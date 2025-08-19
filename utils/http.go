package utils

import (
	"bytes"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// cloneRequest 克隆HTTP请求对象，用于创建未授权请求副本
func CloneRequest(r *proxy.Request) *http.Request {
	if r == nil || r.URL == nil {
		return nil
	}

	// 创建原始URL的副本
	targetURL, err := url.Parse(r.URL.String())
	if err != nil {
		return nil
	}

	// 创建请求体的副本（如果有）
	var bodyReader io.Reader
	if r.Body != nil && len(r.Body) > 0 {
		bodyReader = bytes.NewReader(r.Body)
	}

	// 创建新的HTTP请求
	req, err := http.NewRequest(r.Method, targetURL.String(), bodyReader)
	if err != nil {
		return nil
	}

	// 完全复制所有请求头，保持原始顺序
	for key, values := range r.Header {
		// 跳过一些不需要复制的头部
		if key == "Connection" || key == "Content-Length" {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 使用URL的主机名作为Host头
	if targetURL.Host != "" {
		req.Host = targetURL.Host
	}

	return req
}

// containsExcludeKeywords 检查是否包含需要排除的关键词
func ContainsExcludeKeywords(path string, keywords []string) bool {
	lowerPath := strings.ToLower(path)
	for _, keyword := range keywords {
		if strings.Contains(lowerPath, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// isExcludedPath 检查是否为需要排除的路径
func IsExcludedPath(url string, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		if strings.Contains(strings.ToLower(url), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

//// fixBrokenJSON 尝试修复可能被破坏的JSON数据
//func FixBrokenJSON(data []byte, contentType string) ([]byte, bool) {
//	// 如果内容类型不是JSON，直接返回
//	if !strings.Contains(contentType, "application/json") {
//		return data, false
//	}
//
//	// 简单的JSON修复逻辑
//	// 这里可以添加更复杂的修复逻辑
//	return data, false
//}
