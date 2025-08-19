package utils

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

var (
	whitelistDomains = make(map[string]bool)
	whitelistIPs     = make(map[string]bool)
	whitelistMutex   sync.RWMutex
)

// LoadWhitelist 从whitelist.txt加载白名单域名和IP
func LoadWhitelist() error {
	// 获取当前工作目录
	_, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("获取当前工作目录失败: %v", err)
	}

	// 尝试加载白名单文件
	whitelistPath := "whitelist.txt"
	data, err := os.ReadFile(whitelistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取白名单文件失败: %v", err)
	}

	whitelistMutex.Lock()
	defer whitelistMutex.Unlock()

	whitelistDomains = make(map[string]bool)
	whitelistIPs = make(map[string]bool)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			// 检查是否为IP地址
			if ip := net.ParseIP(line); ip != nil {
				whitelistIPs[line] = true
			} else {
			whitelistDomains[line] = true
			}
		}
	}
	return nil
}

// IsWhitelisted 检查域名或IP是否在白名单中
func IsWhitelisted(hostname string) bool {
	whitelistMutex.RLock()
	defer whitelistMutex.RUnlock()

	if len(whitelistDomains) == 0 && len(whitelistIPs) == 0 {
		return true // 如果白名单为空，则处理所有请求
	}

	// 检查是否为IP地址
	if ip := net.ParseIP(hostname); ip != nil {
		return whitelistIPs[hostname]
	}

	// 提取顶级域名
	topLevelDomain := ExtractTopLevelDomain(hostname)
	return whitelistDomains[topLevelDomain]
}

