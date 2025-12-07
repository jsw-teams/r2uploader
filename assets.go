// assets.go（放在项目根目录）

package assets

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed web/templates/*.html web/static/*
var embeddedFiles embed.FS

// LoadTemplates 从内置资源中加载所有 HTML 模板
func LoadTemplates() (*template.Template, error) {
	return template.ParseFS(embeddedFiles, "web/templates/*.html")
}

// StaticFileSystem 返回一个 http.FileSystem，用于服务静态资源
func StaticFileSystem() http.FileSystem {
	sub, err := fs.Sub(embeddedFiles, "web/static")
	if err != nil {
		// 这里如果错了说明编译阶段就有问题，直接 panic 即可
		panic(err)
	}
	return http.FS(sub)
}
