package config

import (
	"encoding/json"
	"errors"
	"os"
)

const DefaultMaxTotalSizeBytes int64 = 5 * 1024 * 1024 * 1024 // 5GB

type Config struct {
	// 是否已经完成初始化安装
	Installed bool `json:"installed"`

	// Cloudflare R2 配置
	AccountID       string `json:"account_id"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Bucket          string `json:"bucket"`

	// Turnstile 配置
	TurnstileSiteKey   string `json:"turnstile_site_key"`
	TurnstileSecretKey string `json:"turnstile_secret_key"`

	// 总容量限制（字节）
	MaxTotalSizeBytes int64 `json:"max_total_size_bytes"`
}

// Load 从指定路径加载配置文件；不存在则返回默认配置（未安装，默认 5GB）
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{
			MaxTotalSizeBytes: DefaultMaxTotalSizeBytes,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.MaxTotalSizeBytes <= 0 {
		cfg.MaxTotalSizeBytes = DefaultMaxTotalSizeBytes
	}
	return &cfg, nil
}

// Save 以原子方式保存配置
func Save(path string, cfg *Config) error {
	if cfg.MaxTotalSizeBytes <= 0 {
		cfg.MaxTotalSizeBytes = DefaultMaxTotalSizeBytes
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
