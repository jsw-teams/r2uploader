package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	assets "github.com/jsw-teams/r2uploader"
	"github.com/jsw-teams/r2uploader/internal/config"
	"github.com/jsw-teams/r2uploader/internal/storage"
)

const maxUploadSize = 10 * 1024 * 1024 // 单文件最大 10MB

type Server struct {
	cfgPath string
	cfg     *config.Config

	storage *storage.R2

	templates *template.Template
	mux       *http.ServeMux

	mu        sync.Mutex
	usedBytes int64
}

// New 创建服务实例，加载配置并初始化 R2 客户端
func New(cfgPath string) (*Server, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// 👇 用内嵌模板而不是本地文件
	tmpl, err := assets.LoadTemplates()
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	s := &Server{
		cfgPath:   cfgPath,
		cfg:       cfg,
		templates: tmpl,
		mux:       http.NewServeMux(),
	}

	if cfg.Installed {
		if err := s.initStorageFromConfig(); err != nil {
			return nil, fmt.Errorf("init storage: %w", err)
		}
	}

	s.routes()
	return s, nil
}

// ListenAndServe 启动 HTTP 服务
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

func (s *Server) routes() {
	// 👇 静态文件改为从内嵌 FS 读取
	s.mux.Handle(
		"/static/",
		http.StripPrefix("/static/", http.FileServer(assets.StaticFileSystem())),
	)

	// 路由
	s.mux.HandleFunc("/setup", s.handleSetup)
	s.mux.HandleFunc("/upload", s.handleUpload)
	s.mux.HandleFunc("/i/", s.handleServeImage)
	s.mux.HandleFunc("/", s.handleIndex)
}

// 根据现有配置初始化 R2 客户端并计算已用空间
func (s *Server) initStorageFromConfig() error {
	r2, err := storage.NewR2(s.cfg.AccountID, s.cfg.AccessKeyID, s.cfg.SecretAccessKey, s.cfg.Bucket)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	used, err := r2.TotalSize(ctx)
	if err != nil {
		return err
	}

	s.storage = r2
	s.mu.Lock()
	s.usedBytes = used
	s.mu.Unlock()
	return nil
}

// 根路径：上传页（未安装则跳转到 /setup）
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.cfg.Installed {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	data := map[string]any{
		"TurnstileSiteKey": s.cfg.TurnstileSiteKey,
		"MaxTotalGB":       float64(s.cfg.MaxTotalSizeBytes) / (1024 * 1024 * 1024),
		"UsedGB":           s.currentUsedGB(),
	}

	if err := s.templates.ExecuteTemplate(w, "upload.html", data); err != nil {
		log.Printf("render upload.html: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

// /setup 初始化向导
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Installed {
		// 安装完成后禁止再次访问
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data := map[string]any{
			"MaxTotalGB": float64(s.cfg.MaxTotalSizeBytes) / (1024 * 1024 * 1024),
		}
		if err := s.templates.ExecuteTemplate(w, "setup.html", data); err != nil {
			log.Printf("render setup.html: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		accountID := strings.TrimSpace(r.FormValue("account_id"))
		accessKey := strings.TrimSpace(r.FormValue("access_key_id"))
		secretKey := strings.TrimSpace(r.FormValue("secret_access_key"))
		bucket := strings.TrimSpace(r.FormValue("bucket"))
		tsSite := strings.TrimSpace(r.FormValue("turnstile_site_key"))
		tsSecret := strings.TrimSpace(r.FormValue("turnstile_secret_key"))

		if accountID == "" || accessKey == "" || secretKey == "" || bucket == "" || tsSite == "" || tsSecret == "" {
			http.Error(w, "所有字段都是必填的", http.StatusBadRequest)
			return
		}

		// 先尝试连接 R2 并读取已用空间，防止填错
		r2, err := storage.NewR2(accountID, accessKey, secretKey, bucket)
		if err != nil {
			log.Printf("init R2: %v", err)
			http.Error(w, "无法连接 R2，请检查配置", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		used, err := r2.TotalSize(ctx)
		if err != nil {
			log.Printf("list R2 objects: %v", err)
			http.Error(w, "无法读取 R2 桶，请检查权限和名称", http.StatusBadRequest)
			return
		}

		s.storage = r2
		s.mu.Lock()
		s.usedBytes = used
		s.mu.Unlock()

		s.cfg.AccountID = accountID
		s.cfg.AccessKeyID = accessKey
		s.cfg.SecretAccessKey = secretKey
		s.cfg.Bucket = bucket
		s.cfg.TurnstileSiteKey = tsSite
		s.cfg.TurnstileSecretKey = tsSecret
		if s.cfg.MaxTotalSizeBytes <= 0 {
			s.cfg.MaxTotalSizeBytes = config.DefaultMaxTotalSizeBytes
		}
		s.cfg.Installed = true

		if err := config.Save(s.cfgPath, s.cfg); err != nil {
			log.Printf("save config: %v", err)
			http.Error(w, "保存配置失败", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

// verifyTurnstile 调用 Cloudflare Turnstile 服务端验证
func (s *Server) verifyTurnstile(ctx context.Context, r *http.Request) (bool, string) {
	if s.cfg.TurnstileSecretKey == "" {
		return false, "服务端未配置 Turnstile Secret Key"
	}

	token := r.FormValue("cf-turnstile-response")
	if token == "" {
		return false, "缺少人机验证"
	}

	form := url.Values{}
	form.Set("secret", s.cfg.TurnstileSecretKey)
	form.Set("response", token)

	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		form.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		log.Printf("build turnstile request: %v", err)
		return false, "人机验证失败，请稍后再试"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("call turnstile: %v", err)
		return false, "人机验证失败，请稍后再试"
	}
	defer resp.Body.Close()

	var tr turnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		log.Printf("decode turnstile: %v", err)
		return false, "人机验证失败，请稍后再试"
	}

	if !tr.Success {
		return false, "人机验证未通过"
	}
	return true, ""
}

// /upload 上传接口：验证 Turnstile -> 检查大小与配额 -> 上传到 R2
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.Installed || s.storage == nil {
		http.Error(w, "service not initialized", http.StatusBadRequest)
		return
	}

	// 限制 body 大小
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+1024*1024)
	if err := r.ParseMultipartForm(maxUploadSize + 1024*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "文件过大或表单解析失败",
		})
		return
	}

	ok, msg := s.verifyTurnstile(r.Context(), r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": msg,
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "请选择要上传的图片",
		})
		return
	}
	file.Close() // 稍后通过 header.Open 重新打开

	size := header.Size
	if size <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "无法获取文件大小",
		})
		return
	}
	if size > maxUploadSize {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "单个文件最大 10MB",
		})
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !isAllowedExt(ext) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "仅允许上传常见图片格式",
		})
		return
	}

	s.mu.Lock()
	used := s.usedBytes
	limit := s.cfg.MaxTotalSizeBytes
	s.mu.Unlock()

	if used+size > limit {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "空间已满，无法继续上传",
		})
		return
	}

	f, err := header.Open()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "读取文件失败",
		})
		return
	}
	defer f.Close()

	// 读取前 512 字节做 MIME 检测
	buf := make([]byte, 512)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "读取文件失败",
		})
		return
	}
	contentType := http.DetectContentType(buf[:n])
	if !strings.HasPrefix(contentType, "image/") {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "只允许上传图片文件",
		})
		return
	}

	reader := io.MultiReader(bytes.NewReader(buf[:n]), f)

	id, err := randomID()
	if err != nil {
		log.Printf("randomID: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "生成文件名失败",
		})
		return
	}
	fileName := id + ext
	key := "images/" + fileName

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if err := s.storage.PutObject(ctx, key, reader, contentType, size); err != nil {
		log.Printf("PutObject: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "上传到存储失败",
		})
		return
	}

	s.mu.Lock()
	s.usedBytes += size
	s.mu.Unlock()

	url := baseURL(r) + "/i/" + fileName
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":  true,
		"url": url,
	})
}

// /i/{file} 读取并回源图片（不暴露 R2 直链）
func (s *Server) handleServeImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.Installed || s.storage == nil {
		http.NotFound(w, r)
		return
	}

	fileName := strings.TrimPrefix(r.URL.Path, "/i/")
	fileName = path.Clean(fileName)
	if fileName == "" || fileName == "." || strings.Contains(fileName, "/") {
		http.NotFound(w, r)
		return
	}

	key := "images/" + fileName

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	obj, err := s.storage.GetObject(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("GetObject: %v", err)
		http.Error(w, "读取图片失败", http.StatusInternalServerError)
		return
	}
	defer obj.Body.Close()

	ct := obj.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=31536000")

	if _, err := io.Copy(w, obj.Body); err != nil {
		log.Printf("write image: %v", err)
	}
}

func (s *Server) currentUsedGB() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return float64(s.usedBytes) / (1024 * 1024 * 1024)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func isAllowedExt(ext string) bool {
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg":
		return true
	default:
		return false
	}
}

// randomID 生成 16 字节随机 ID（32 位 hex）
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// baseURL 根据当前请求主机 + 协议生成 base URL，不依赖配置
func baseURL(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if host == "" {
		host = "localhost"
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}
