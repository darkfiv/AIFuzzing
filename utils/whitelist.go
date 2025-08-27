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
	whitelistCIDRs   = make([]*net.IPNet, 0)
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
	whitelistCIDRs = make([]*net.IPNet, 0)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			// 优先尝试解析为CIDR网段
			if _, ipnet, err := net.ParseCIDR(line); err == nil && ipnet != nil {
				whitelistCIDRs = append(whitelistCIDRs, ipnet)
				continue
			}

			// 检查是否为IP地址
			if ip := net.ParseIP(line); ip != nil {
				whitelistIPs[line] = true
				continue
			}

			// 其他按域名记录
			whitelistDomains[line] = true
		}
	}
	return nil
}

// IsWhitelisted 检查域名或IP是否在白名单中
func IsWhitelisted(hostname string) bool {
	whitelistMutex.RLock()
	defer whitelistMutex.RUnlock()

	if len(whitelistDomains) == 0 && len(whitelistIPs) == 0 && len(whitelistCIDRs) == 0 {
		return true // 如果白名单为空，则处理所有请求
	}

	// 先移除端口（host:port）再判断
	hostOnly := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil && h != "" {
		hostOnly = h
	} else {
		// 处理简单的 host:port 场景
		if i := strings.LastIndex(hostname, ":"); i > -1 {
			possibleHost := hostname[:i]
			if net.ParseIP(possibleHost) != nil {
				hostOnly = possibleHost
			}
		}
	}

	// 检查是否为IP地址（含CIDR匹配）
	if ip := net.ParseIP(hostOnly); ip != nil {
		if whitelistIPs[hostOnly] {
			return true
		}
		for _, ipnet := range whitelistCIDRs {
			if ipnet.Contains(ip) {
				return true
			}
		}
		return false
	}

	// 提取顶级域名或完整域名匹配
	topLevelDomain := ExtractTopLevelDomain(hostOnly)
	if whitelistDomains[topLevelDomain] {
		return true
	}
	return whitelistDomains[hostOnly]
}

