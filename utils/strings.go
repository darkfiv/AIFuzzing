package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// TruncateString 截断字符串到指定长度
func TruncateString(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// TruncateRequestBody 截断请求体以防止过大
func TruncateRequestBody(body string, maxSize int) string {
	if maxSize <= 0 || len(body) <= maxSize {
		return body
	}

	halfSize := maxSize / 2
	prefix := body[:halfSize]
	suffix := body[len(body)-halfSize:]
	
	return prefix + "\n... [内容过长已截断] ...\n" + suffix
}

// FormatHeaders 格式化HTTP头
func FormatHeaders(headers map[string][]string) string {
	var result strings.Builder

	headerOrder := []string{
		"Host", "Content-Type", "Accept", "Accept-Language", 
		"Accept-Encoding", "Connection", "Origin", "Referer",
		"User-Agent", "X-App-Token-M", "X-App-Token-D", 
		"X-Request-Fp", "X-Track-Page", "Cookie", "Authorization",
		"Content-Length",
	}

	for _, key := range headerOrder {
		if values := headers[key]; len(values) > 0 {
			result.WriteString(fmt.Sprintf("%s: %s\n", key, values[0]))
		}
	}

	for key, values := range headers {
		if Contains(headerOrder, key) {
			continue
		}
		if strings.HasPrefix(key, "X-") && !Contains([]string{"X-App-Token-M", "X-App-Token-D", "X-Request-Fp", "X-Track-Page"}, key) {
			continue
		}
		if Contains([]string{"Server", "Date", "Set-Cookie", "Etag", "Content-Length", "Vary", "P3p", "X-Download-Options", "X-Permitted-Cross-Domain-Policies", "X-Dns-Prefetch-Control", "X-Tefe-Action", "X-Tefe-Result", "Strict-Transport-Security", "Janus-Addr", "Janus-Configid", "Origin-Agent-Cluster"}, key) {
			continue
		}
		result.WriteString(fmt.Sprintf("%s: %s\n", key, values[0]))
	}

	return result.String()
}

// Contains 检查字符串切片是否包含特定字符串
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CleanupResponse 清理AI响应中可能导致JSON解析失败的字符
func CleanupResponse(response string) string {
	response = strings.Replace(response, "`", "", -1)
	response = strings.Replace(response, "\"\"", "\"", -1)
	
	if strings.HasPrefix(strings.TrimSpace(response), "json") {
		if jsonStartIndex := strings.Index(response, "{"); jsonStartIndex > 0 {
			response = response[jsonStartIndex:]
		}
	}
	
	if strings.Contains(response, "```json") && strings.Contains(response, "```") {
		start := strings.Index(response, "```json") + 7
		end := strings.LastIndex(response, "```")
		if start > 7 && end > start {
			response = strings.TrimSpace(response[start:end])
		}
	}
	
	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "{") {
		if jsonStartIndex := strings.Index(response, "{"); jsonStartIndex >= 0 {
			response = response[jsonStartIndex:]
		}
	}
	
	return response
}

// ExtractTopLevelDomain 从hostname中提取顶级域名
func ExtractTopLevelDomain(hostname string) string {
	if i := strings.LastIndex(hostname, ":"); i != -1 {
		hostname = hostname[:i]
	}

	if IsIPAddress(hostname) {
		return hostname
	}

	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}

	if len(parts) > 2 {
		lastTwo := parts[len(parts)-2:]
		if lastTwo[1] == "uk" || lastTwo[1] == "cn" {
			return strings.Join(lastTwo, ".")
		}
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

// IsIPAddress 检查字符串是否为IP地址
func IsIPAddress(hostname string) bool {
	parts := strings.Split(hostname, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}
