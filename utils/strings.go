package utils

import (
    "fmt"
)

// TruncateString 截断字符串到指定长度，避免过长
func TruncateString(s string, maxLen int) string {
    if len(s) <= maxLen {
        return s
    }
    return s[:maxLen] + "..."
}

// ParseResponse 解析API响应
func ParseResponse(response string) (string, error) {
    return response, nil
}

// PrintYuequan 格式化越权漏洞输出
func PrintYuequan(result string, method string, url string, reason string) string {
    return fmt.Sprintf("[%s] %s %s - %s", result, method, url, reason)
} 