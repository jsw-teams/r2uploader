package storage

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type R2 struct {
	client *s3.Client
	bucket string
}

// NewR2 使用 accountID + AK/SK + bucket 创建 R2 客户端
func NewR2(accountID, accessKeyID, secretAccessKey, bucket string) (*R2, error) {
	if accountID == "" || accessKeyID == "" || secretAccessKey == "" || bucket == "" {
		return nil, fmt.Errorf("missing R2 config")
	}

	cfg := aws.Config{
		Region: "auto", // R2 推荐 auto 区域
		Credentials: aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
		),
	}

	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return &R2{
		client: client,
		bucket: bucket,
	}, nil
}

// PutObject 上传对象
func (r *R2) PutObject(ctx context.Context, key string, body io.Reader, contentType string, contentLength int64) error {
	_, err := r.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(r.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentType:   aws.String(contentType),
		ContentLength: aws.Int64(contentLength),
	})
	return err
}

type ObjectReader struct {
	Body        io.ReadCloser
	ContentType string
}

var ErrNotFound = errors.New("object not found")

// GetObject 读取对象
func (r *R2) GetObject(ctx context.Context, key string) (*ObjectReader, error) {
	out, err := r.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	ct := ""
	if out.ContentType != nil {
		ct = *out.ContentType
	}
	return &ObjectReader{
		Body:        out.Body,
		ContentType: ct,
	}, nil
}

// TotalSize 计算桶内所有对象大小总和（用于限额）
func (r *R2) TotalSize(ctx context.Context) (int64, error) {
	var total int64
	var token *string

	for {
		out, err := r.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(r.bucket),
			ContinuationToken: token,
		})
		if err != nil {
			return 0, err
		}
		for _, obj := range out.Contents {
			total += obj.Size
		}
		if !out.IsTruncated || out.NextContinuationToken == nil {
			break
		}
		token = out.NextContinuationToken
	}

	return total, nil
}
