package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"yuequanScan/AIAPIS"
	"yuequanScan/config"
	_ "yuequanScan/similarity"
	"yuequanScan/utils"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	_ "golang.org/x/text/encoding"
	_ "golang.org/x/text/encoding/charmap"
	_ "golang.org/x/text/encoding/japanese"
	_ "golang.org/x/text/encoding/korean"
	_ "golang.org/x/text/encoding/simplifiedchinese"
	_ "golang.org/x/text/transform"
)

// 漏洞类型
type VulnType string

const (
	VulnPrivilegeEscalation VulnType = "privilege_escalation" // 越权漏洞
	VulnUnauthorizedAccess  VulnType = "unauthorized_access"  // 未授权访问漏洞
	VulnSensitiveDataLeak   VulnType = "sensitive_data_leak"  // 敏感数据泄露漏洞
)

// 扫描结果
type ScanResult struct {
	Res    string `json:"res"`
	Reason string `json:"reason"`
}

// 全局变量
var (
	// 已在main.go中定义的变量，不需要重复声明
	// workerPool, reportGenerator, logs 已在其他文件声明

	// 外部变量声明，这些变量在main.go中定义
	// Resp和reportGenerator需要在这里声明为外部引用，以便在scan.go中使用

	// 需要全局声明这两个变量
	req1 string
	req2 string

	// 请求处理状态跟踪
	retryCounters   sync.Map // 存储请求重试次数
	lastAttempts    sync.Map // 存储上次尝试处理的时间
	pendingRequests sync.Map // 存储等待处理的请求
	processingFlag  sync.Map // 标记正在处理的请求
	requestStatuses sync.Map // 请求状态: "pending", "processing", "completed", "failed"

	// 创建停止通道
	stopChan = make(chan struct{})

	// 配置对象
	conf = config.GetConfig()

	// 敏感数据检测的正则表达式
	idCardPattern   *regexp.Regexp
	namePattern     *regexp.Regexp
	phonePattern    *regexp.Regexp
	addressPattern  *regexp.Regexp
	emailPattern    *regexp.Regexp
	bankCardPattern *regexp.Regexp

	// ... existing variables ...
	whitelistDomains       = make(map[string]bool)
	whitelistMutex         sync.RWMutex
	completedRequestsMap   = make(map[string]*RequestResponseLog)
	completedRequestsMutex sync.RWMutex
)

// 状态常量
const (
	StatusPending    = "pending"
	StatusProcessing = "processing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

// 定义请求状态常量（数字类型），使用不同名称避免冲突
const (
	StatusNumInitialized = iota
	StatusNumProcessing  // 实际处理中
	StatusNumCompleted   // 处理完成
	StatusNumError       // 处理出错
)

// 请求处理失败原因
type FailReason struct {
	Reason    string    // 失败原因
	Timestamp time.Time // 失败时间
	Count     int       // 失败次数
}

// LoadWhitelist 从whitelist.txt加载白名单域名
func LoadWhitelist() error {
	// 获取当前工作目录
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("获取当前工作目录失败: %v", err)
	}
	utils.Debug("当前工作目录: %s", currentDir)

	// 尝试加载白名单文件
	whitelistPath := "whitelist.txt"
	data, err := os.ReadFile(whitelistPath)
	if err != nil {
		if os.IsNotExist(err) {
			utils.Warning("白名单文件不存在: %s，将处理所有域名", whitelistPath)
			return nil
		}
		return fmt.Errorf("读取白名单文件失败: %v", err)
	}

	whitelistMutex.Lock()
	defer whitelistMutex.Unlock()

	whitelistDomains = make(map[string]bool)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			whitelistDomains[line] = true
		}
	}
	utils.Info("已加载 %d 个白名单域名", len(whitelistDomains))
	return nil
}

// extractTopLevelDomain 从hostname中提取顶级域名
func extractTopLevelDomain(hostname string) string {
	// 移除端口号
	if i := strings.LastIndex(hostname, ":"); i != -1 {
		hostname = hostname[:i]
	}

	// 如果是IP地址，直接返回
	if isIPAddress(hostname) {
		return hostname
	}

	// 分割域名部分
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}

	// 处理特殊域名（如 .co.uk, .com.cn 等）
	if len(parts) > 2 {
		lastTwo := parts[len(parts)-2:]
		if lastTwo[1] == "uk" || lastTwo[1] == "cn" {
			return strings.Join(lastTwo, ".")
		}
	}

	// 返回最后两部分作为顶级域名
	return strings.Join(parts[len(parts)-2:], ".")
}

// isIPAddress 检查字符串是否为IP地址
func isIPAddress(hostname string) bool {
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

// IsWhitelisted 检查域名是否在白名单中
func IsWhitelisted(hostname string) bool {
	whitelistMutex.RLock()
	defer whitelistMutex.RUnlock()

	if len(whitelistDomains) == 0 {
		utils.Debug("白名单为空，处理所有域名")
		return true // 如果白名单为空，则处理所有域名
	}

	// 提取顶级域名
	topLevelDomain := extractTopLevelDomain(hostname)
	utils.Debug("白名单检查 - 原始域名: %s, 顶级域名: %s, 是否在白名单中: %v",
		hostname,
		topLevelDomain,
		whitelistDomains[topLevelDomain])

	// 打印当前白名单内容
	utils.Debug("当前白名单内容:")
	for domain := range whitelistDomains {
		utils.Debug("  - %s", domain)
	}

	return whitelistDomains[topLevelDomain]
}

// 初始化扫描服务
func InitScanService() {
	// 初始化敏感数据检测的模式
	setupPatterns()

	// 加载白名单
	if err := LoadWhitelist(); err != nil {
		utils.Error("加载白名单失败: %v", err)
	} else {
		utils.Info("成功加载白名单，包含 %d 个域名", len(whitelistDomains))
		// 打印白名单内容
		utils.Debug("白名单内容:")
		for domain := range whitelistDomains {
			utils.Debug("  - %s", domain)
		}
	}

	utils.Info("[扫描服务] 初始化完成")
}

// 清理扫描服务
func CleanupScanService() {
	utils.Info("[扫描服务] 工作池已停止")

	// 关闭停止通道
	close(stopChan)

	utils.Info("[扫描服务] 清理完成")
}

// ScanImpl 扫描实现
func ScanImpl() {
	// 初始化计数器
	processedCount := 0
	skippedCount := 0
	filteredCount := 0
	staticCount := 0
	currentlyProcessingCount := 0

	// 上次统计时间
	lastStatsTime := time.Now()

	// 添加定时器，定期处理完成的请求
	completedTicker := time.NewTicker(1000 * time.Millisecond)
	defer completedTicker.Stop()

	// 高优先级请求处理定时器
	highPriorityTicker := time.NewTicker(2000 * time.Millisecond) // 减少频率
	defer highPriorityTicker.Stop()

	// 低优先级请求处理定时器
	lowPriorityTicker := time.NewTicker(5000 * time.Millisecond) // 减少频率
	defer lowPriorityTicker.Stop()

	// 定期清理旧请求定时器 - 增加频率以更快清理
	cleanupTicker := time.NewTicker(15 * time.Second)
	defer cleanupTicker.Stop()

	// CONNECT请求处理定时器
	connectTicker := time.NewTicker(20 * time.Second) // 减少频率
	defer connectTicker.Stop()

	// 每分钟输出请求处理统计信息 - 可以减少为每3分钟一次
	statsTicker := time.NewTicker(180 * time.Second)
	defer statsTicker.Stop()

	// 主循环
	for {
		select {
		case <-completedTicker.C:
			// 处理完成的请求
			currentlyProcessingCount = 0
			logs.Range(func(key, value interface{}) bool {
				if isProcessing, ok := processingFlag.Load(key); ok && isProcessing.(bool) {
					currentlyProcessingCount++
				}
				return true
			})
			newProcessed, newSkipped, newFiltered, newStatic := processCompletedRequests()
			processedCount += newProcessed
			skippedCount += newSkipped
			filteredCount += newFiltered
			staticCount += newStatic

		case <-statsTicker.C:
			// 计算每分钟的请求统计
			now := time.Now()
			duration := now.Sub(lastStatsTime).Minutes()

			// 获取当前请求数量
			var totalRequests int
			logs.Range(func(_, _ interface{}) bool {
				totalRequests++
				return true
			})

			processedPerMinute := float64(processedCount) / duration
			skippedPerMinute := float64(skippedCount) / duration

			utils.Info("[请求统计] 过去 %.1f 分钟内: 总处理=%d (%.1f/分), 跳过=%d (%.1f/分), 过滤=%d, 静态=%d, 当前处理中=%d, 等待中=%d",
				duration, processedCount, processedPerMinute,
				skippedCount, skippedPerMinute,
				filteredCount, staticCount,
				currentlyProcessingCount, totalRequests-currentlyProcessingCount)

			// 重置统计数据
			processedCount = 0
			skippedCount = 0
			filteredCount = 0
			staticCount = 0
			lastStatsTime = now

			// 输出内存中的请求分布信息
			countByPath := make(map[string]int)
			countByHost := make(map[string]int)
			logs.Range(func(_, value interface{}) bool {
				if req, ok := value.(*RequestResponseLog); ok && req.Request != nil && req.Request.URL != nil {
					path := req.Request.URL.Path
					host := req.Request.URL.Host
					countByPath[path]++
					countByHost[host]++
				}
				return true
			})

			// 找出请求最多的路径和域名
			type pathCount struct {
				path  string
				count int
			}
			pathCounts := make([]pathCount, 0, len(countByPath))
			for p, c := range countByPath {
				pathCounts = append(pathCounts, pathCount{p, c})
			}

			// 按请求数量排序
			sort.Slice(pathCounts, func(i, j int) bool {
				return pathCounts[i].count > pathCounts[j].count
			})

			// 输出前5个请求最多的路径
			if len(pathCounts) > 0 {
				utils.Info("[请求分布] 请求最多的路径:")
				for i := 0; i < 5 && i < len(pathCounts); i++ {
					utils.Info(" - %s: %d 个请求", pathCounts[i].path, pathCounts[i].count)
				}
			}

			// 输出当前域名分布
			utils.Info("[请求分布] 域名分布:")
			for host, count := range countByHost {
				utils.Info(" - %s: %d 个请求", host, count)
			}

		case <-highPriorityTicker.C:
			// 优先处理需要先认证的请求
			processHighPriorityRequests()

		case <-lowPriorityTicker.C:
			// 处理低优先级请求
			processLowPriorityRequests()

		case <-cleanupTicker.C:
			// 清理过期请求
			cleanupStaleRequests()

		case <-connectTicker.C:
			// 处理CONNECT请求
			handleConnectRequests()

		case <-stopChan:
			utils.Info("扫描服务停止")
			return
		}
	}
}

// processCompletedRequests 处理完成的请求-响应对
func processCompletedRequests() (processed int, skipped int, filtered int, static int) {
	utils.Info("[请求处理] 开始处理已完成的请求...")

	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		utils.Error("[请求处理] 配置未初始化")
		return
	}

	// 遍历所有请求
	logs.Range(func(key, value interface{}) bool {
		rr, ok := value.(*RequestResponseLog)
		if !ok {
			utils.Warning("[请求处理] 无效的请求日志类型: %v", key)
			return true
		}

		// 跳过已处理的请求
		if rr.Processed {
			return true
		}

		// 检查请求是否有效
		if rr.Request == nil || rr.Request.URL == nil {
			utils.Warning("[请求处理] 无效的请求对象: %v", key)
			return true
		}

		// 获取hostname
		hostname := rr.Request.URL.Host
		if hostname == "" {
			utils.Warning("[请求处理] 无法获取hostname: %v", key)
			return true
		}

		// 白名单检查
		utils.Info("[白名单检查] 检查域名: %s", hostname)
		if !IsWhitelisted(hostname) {
			utils.Info("[白名单检查] 域名 %s 不在白名单中，跳过处理", hostname)
			skipped++
			rr.Processed = true
			return true
		}

		// 检查是否为静态资源
		if !isNotSuffix(rr.Request.URL.Path, conf.Suffixes) {
			utils.Info("命中静态资源文件，不处理")
			skipped++
			static++
			rr.Processed = true
			return true
		}

		// 检查是否在排除路径中
		if isExcludedPath(rr.Request.URL.Path, conf.UnauthorizedScan.ExcludePatterns) {
			utils.Info("命中排出路径，不处理")
			skipped++
			rr.Processed = true
			return true
		}

		// 检查响应头
		if rr.Response != nil {
			contentType := rr.Response.Header.Get("Content-Type")
			if contains(conf.AllowedRespHeaders, contentType) {
				utils.Info("命中不允许的响应类型，不处理")
				skipped++
				rr.Processed = true
				return true
			}
		}

		processed++
		return true
	})

	utils.Info("[请求处理] 处理完成 - 已处理: %d, 已跳过: %d", processed, skipped)
	return processed, skipped, 0, 0
}

// 检查是否为需要排除的路径
func isExcludedPath(url string, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		if strings.Contains(strings.ToLower(url), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// 克隆HTTP请求对象，用于创建未授权请求副本
func cloneRequest(r *proxy.Request) *http.Request {
	if r == nil || r.URL == nil {
		utils.Error("[请求克隆] 无法克隆空请求")
		return nil
	}

	// 创建原始URL的副本
	targetURL, err := url.Parse(r.URL.String())
	if err != nil {
		utils.Error("[请求克隆] 解析URL失败: %v", err)
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
		utils.Error("[请求克隆] 创建请求对象失败: %v", err)
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

	// 记录原始请求头的详细信息
	utils.Debug("[请求克隆] 原始请求详情:")
	utils.Debug("  - 方法: %s", r.Method)
	utils.Debug("  - URL: %s", r.URL.String())
	utils.Debug("  - 协议: %s", r.Proto)
	utils.Debug("  - 请求头数量: %d", len(r.Header))

	// 记录所有请求头，用于调试
	for key, values := range r.Header {
		utils.Debug("[请求克隆] 原始请求头: %s = %v", key, values)
	}

	// 记录克隆后的请求头
	utils.Debug("[请求克隆] 克隆后请求头数量: %d", len(req.Header))
	for key, values := range req.Header {
		utils.Debug("[请求克隆] 克隆后请求头: %s = %v", key, values)
	}

	return req
}

// 检测未授权访问
func detectUnauthorizedAccess(r *RequestResponseLog) (*Result, error) {
	if r == nil || r.Request == nil || r.Response == nil {
		return nil, fmt.Errorf("无效的请求或响应")
	}

	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		return nil, fmt.Errorf("配置未初始化")
	}

	// 记录请求URL和相关信息
	utils.Info("[未授权检测] 开始检测请求: %s %s", r.Request.Method, r.Request.URL.String())

	// 创建结果对象
	vulnResult := &Result{
		Method:   r.Request.Method,
		Url:      r.Request.URL.String(),
		VulnType: string(VulnUnauthorizedAccess),
		Result:   "unknown",
	}

	// 获取完整的原始请求协议版本
	proto := r.Request.Proto
	if proto == "" {
		proto = "2" // 默认使用HTTP/2
	}

	// 获取Host值，这是关键
	host := ""
	if hostValues := r.Request.Header["Host"]; len(hostValues) > 0 {
		host = hostValues[0]
	} else if r.Request.URL != nil && r.Request.URL.Host != "" {
		host = r.Request.URL.Host
	}

	// 构建完整的请求行，确保使用确切的HTTP方法
	requestLine := fmt.Sprintf("%s %s HTTP/%s",
		r.Request.Method,
		r.Request.URL.Path+r.Request.URL.RawQuery,
		proto)

	// 设置原始请求详情 - 全部重新构建确保格式一致
	vulnResult.RequestA = requestLine + "\n"

	// 如果Host不在请求头中，手动添加
	reqHeader := formatHeaders(r.Request.Header)
	if !strings.Contains(reqHeader, "Host: ") && host != "" {
		vulnResult.RequestA += fmt.Sprintf("Host: %s\n", host)
	}

	// 添加其他请求头
	vulnResult.RequestA += reqHeader

	// 如果有请求体，添加空行后添加请求体
	if len(r.Request.Body) > 0 {
		vulnResult.RequestA += "\n" + string(r.Request.Body)
	} else {
		// 即使没有请求体，也添加空行表示请求头结束
		vulnResult.RequestA += "\n"
	}

	// 记录原始请求的详细信息
	utils.Debug("[未授权检测] 原始请求详情:")
	utils.Debug("  - 方法: %s", r.Request.Method)
	utils.Debug("  - URL: %s", r.Request.URL.String())
	utils.Debug("  - 协议: %s", proto)
	utils.Debug("  - Host: %s", host)
	utils.Debug("  - 请求头数量: %d", len(r.Request.Header))

	// 创建未授权请求
	req2 := cloneRequest(r.Request)
	if req2 == nil {
		utils.Warning("[未授权检测] 无法克隆请求，跳过检测")
		return nil, fmt.Errorf("无法克隆请求")
	}

	// 移除授权相关头部
	// 安全地访问配置
	if conf != nil {
		// 从配置中获取要移除的头部
		if len(conf.UnauthorizedScan.RemoveHeaders) > 0 {
			for _, header := range conf.UnauthorizedScan.RemoveHeaders {
				req2.Header.Del(header)
			}
		} else {
			// 如果配置中没有定义要删除的头部，使用默认的授权头
			defaultAuthHeaders := []string{"Authorization", "Cookie", "X-Auth-Token", "X-API-Key", "Bearer"}
			for _, header := range defaultAuthHeaders {
				req2.Header.Del(header)
			}
			utils.Debug("[未授权检测] 配置中未定义RemoveHeaders，使用默认授权头列表")
		}
	} else {
		// 如果配置不可用，使用默认的授权头
		defaultAuthHeaders := []string{"Authorization", "Cookie", "X-Auth-Token", "X-API-Key", "Bearer"}
		for _, header := range defaultAuthHeaders {
			req2.Header.Del(header)
		}
		utils.Debug("[未授权检测] 配置对象为空，使用默认授权头列表")
	}

	// 设置未授权请求详情 - 使用与原始请求相同的格式进行构建
	vulnResult.RequestB = requestLine + "\n" // 使用相同的请求行

	// 如果Host不在请求头中，手动添加
	reqHeader2 := formatHeaders(req2.Header)
	if !strings.Contains(reqHeader2, "Host: ") && host != "" {
		vulnResult.RequestB += fmt.Sprintf("Host: %s\n", host)
	}

	// 添加其他请求头
	vulnResult.RequestB += reqHeader2

	// 如果有请求体，添加空行后添加请求体
	if len(r.Request.Body) > 0 {
		vulnResult.RequestB += "\n" + string(r.Request.Body)
	} else {
		// 即使没有请求体，也添加空行表示请求头结束
		vulnResult.RequestB += "\n"
	}

	// 记录未授权请求的详细信息
	utils.Debug("[未授权检测] 未授权请求详情:")
	utils.Debug("  - 方法: %s", req2.Method)
	utils.Debug("  - URL: %s", req2.URL.String())
	utils.Debug("  - 协议: %s", req2.Proto)
	utils.Debug("  - 请求头数量: %d", len(req2.Header))

	// 设置原始响应头
	if r.Response != nil && r.Response.Header != nil {
		vulnResult.HeaderA = formatHeaders(r.Response.Header)
	}

	// 设置原始响应体
	if r.Response != nil && r.Response.Body != nil {
		vulnResult.RespBodyA = string(r.Response.Body)
	}

	// 发送未授权请求
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 增强发送未授权请求前的调试输出
	utils.Debug("[未授权检测] 准备发送未授权请求:")
	utils.Debug("  - 方法: %s", req2.Method)
	utils.Debug("  - URL: %s", req2.URL.String())
	utils.Debug("  - 请求头数量: %d", len(req2.Header))

	// 记录所有请求头
	for key, values := range req2.Header {
		utils.Debug("[未授权检测] 请求头: %s = %v", key, values)
	}

	// 发送请求并获取响应
	resp, err := client.Do(req2)
	if err != nil {
		utils.Warning("[未授权检测] 发送未授权请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Warning("[未授权检测] 读取响应体失败: %v", err)
		return nil, err
	}

	// 设置未授权响应头
	vulnResult.HeaderB = formatHeaders(resp.Header)

	// 设置未授权响应体
	vulnResult.RespBodyB = string(respBody)

	// 计算置信度分数
	score, reasons := calculateConfidenceScore(r, respBody, resp)

	// 检测敏感数据并添加到结果
	if conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
		sensitivePatterns := make(map[string]string)
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.Patterns {
			sensitivePatterns[pattern.Name] = pattern.Pattern
		}

		// 检测未授权响应中的敏感数据
		sensitiveMatches := detectSensitiveDataWithDetails(string(respBody), sensitivePatterns)
		if len(sensitiveMatches) > 0 {
			// 确保结果中包含完整的敏感数据信息
			vulnResult.SensitiveData = sensitiveMatches
			utils.Info("[未授权检测] 在未授权响应中发现敏感数据: %d 处", len(sensitiveMatches))
		}
	}

	// 根据置信度分数设置结果
	if score >= 80 {
		vulnResult.Result = "true"
		vulnResult.Reason = fmt.Sprintf("高置信度未授权访问 (分数: %d, 原因: %v)", score, reasons)
	} else if score >= 60 {
		vulnResult.Result = "unknown"
		vulnResult.Reason = fmt.Sprintf("中等置信度未授权访问 (分数: %d, 原因: %v)", score, reasons)
	} else {
		vulnResult.Result = "false"
		vulnResult.Reason = fmt.Sprintf("低置信度未授权访问 (分数: %d, 原因: %v)", score, reasons)
	}

	// 记录检测结果
	utils.Info("[未授权检测] 检测完成: URL=%s, 结果=%s, 分数=%d, 原因=%v",
		r.Request.URL.String(), vulnResult.Result, score, reasons)

	return vulnResult, nil
}

func formatHeaders(headers http.Header) string {
	var result strings.Builder

	// 定义请求头的标准顺序
	headerOrder := []string{
		"Host",
		"Content-Type",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
		"Origin",
		"Referer",
		"User-Agent",
		"X-App-Token-M",
		"X-App-Token-D",
		"X-Request-Fp",
		"X-Track-Page",
		"Cookie",
		"Authorization",
		"Content-Length",
	}

	// 先添加有序的请求头
	for _, key := range headerOrder {
		if values := headers[key]; len(values) > 0 {
			result.WriteString(fmt.Sprintf("%s: %s\n", key, values[0]))
		}
	}

	// 添加其他请求头（排除响应头）
	for key, values := range headers {
		// 跳过已经在有序列表中的头部
		if contains(headerOrder, key) {
			continue
		}

		// 跳过响应头
		if strings.HasPrefix(key, "X-") && !contains([]string{"X-App-Token-M", "X-App-Token-D", "X-Request-Fp", "X-Track-Page"}, key) {
			continue
		}

		// 跳过服务器相关头部
		if contains([]string{"Server", "Date", "Set-Cookie", "Etag", "Content-Length", "Vary", "P3p", "X-Download-Options", "X-Permitted-Cross-Domain-Policies", "X-Dns-Prefetch-Control", "X-Tefe-Action", "X-Tefe-Result", "Strict-Transport-Security", "Janus-Addr", "Janus-Configid", "Origin-Agent-Cluster"}, key) {
			continue
		}

		// 记录所有请求头
		result.WriteString(fmt.Sprintf("%s: %s\n", key, values[0]))
	}

	// 记录格式化后的头部信息
	utils.Debug("[头部格式化] 格式化后的头部:\n%s", result.String())

	return result.String()
}

// contains 检查字符串是否在切片中
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// 比较两个响应并提取差异
func compareResponses(respA, respB string) []string {
	// 简单的情况：两个响应完全相同
	if respA == respB {
		return nil
	}

	differences := []string{}

	// 尝试解析为JSON进行结构化比较
	var jsonA, jsonB interface{}
	jsonAErr := json.Unmarshal([]byte(respA), &jsonA)
	jsonBErr := json.Unmarshal([]byte(respB), &jsonB)

	if jsonAErr == nil && jsonBErr == nil {
		// 两者都是有效的JSON，进行结构化比较
		diffs := compareJSON(jsonA, jsonB, "")
		if len(diffs) > 0 {
			differences = append(differences, diffs...)
		}
	} else {
		// 至少一个不是有效的JSON，执行文本比较
		// 按行分割并比较
		linesA := strings.Split(respA, "\n")
		linesB := strings.Split(respB, "\n")

		// 长度差异
		if len(linesA) != len(linesB) {
			differences = append(differences, fmt.Sprintf("响应行数不同: 原始=%d行, The unauthorized request returned a response with %d lines of content.", len(linesA), len(linesB)))
		}

		// 逐行比较(限制比较的行数，避免过多的差异)
		maxLines := min(len(linesA), len(linesB))
		maxLinesToCheck := min(maxLines, 10) // 最多检查10行

		for i := 0; i < maxLinesToCheck; i++ {
			if linesA[i] != linesB[i] {
				differences = append(differences, fmt.Sprintf("第%d行不同:\n  原始: %s\n  未授权: %s",
					i+1, truncateString(linesA[i], 100), truncateString(linesB[i], 100)))
			}
		}

		// 如果有太多的差异，只显示摘要
		if maxLines > maxLinesToCheck {
			differences = append(differences, fmt.Sprintf("（为简洁起见，只显示前%d行的差异）", maxLinesToCheck))
		}
	}

	return differences
}

// 比较两个JSON对象并返回差异
func compareJSON(a, b interface{}, path string) []string {
	differences := []string{}

	// 根据类型进行比较
	switch aTyped := a.(type) {
	case map[string]interface{}:
		// 如果a是对象
		if bTyped, ok := b.(map[string]interface{}); ok {
			// b也是对象，逐个比较键
			for k, aVal := range aTyped {
				newPath := path
				if path != "" {
					newPath += "."
				}
				newPath += k

				if bVal, exists := bTyped[k]; exists {
					// 键在两个对象中都存在，递归比较值
					diffs := compareJSON(aVal, bVal, newPath)
					differences = append(differences, diffs...)
				} else {
					// 键在b中不存在
					differences = append(differences, fmt.Sprintf("键 '%s' 在未授权响应中不存在", newPath))
				}
			}

			// 检查b中有而a中没有的键
			for k := range bTyped {
				newPath := path
				if path != "" {
					newPath += "."
				}
				newPath += k

				if _, exists := aTyped[k]; !exists {
					differences = append(differences, fmt.Sprintf("键 '%s' 在未授权响应中新增", newPath))
				}
			}
		} else {
			// 类型不匹配
			differences = append(differences, fmt.Sprintf("路径 '%s' 类型不匹配: 原始=对象, 未授权=%T", path, b))
		}

	case []interface{}:
		// 如果a是数组
		if bTyped, ok := b.([]interface{}); ok {
			// b也是数组
			if len(aTyped) != len(bTyped) {
				differences = append(differences, fmt.Sprintf("数组 '%s' 长度不同: 原始=%d, 未授权=%d",
					path, len(aTyped), len(bTyped)))
			}

			// 比较数组元素，最多比较10个以避免太多差异
			minLen := min(len(aTyped), len(bTyped))
			maxCheck := min(minLen, 10)

			for i := 0; i < maxCheck; i++ {
				itemPath := fmt.Sprintf("%s[%d]", path, i)
				diffs := compareJSON(aTyped[i], bTyped[i], itemPath)
				differences = append(differences, diffs...)
			}

			if minLen > maxCheck {
				differences = append(differences, fmt.Sprintf("（为简洁起见，只检查数组 '%s' 的前%d个元素）", path, maxCheck))
			}
		} else {
			// 类型不匹配
			differences = append(differences, fmt.Sprintf("路径 '%s' 类型不匹配: 原始=数组, 未授权=%T", path, b))
		}

	default:
		// 基本类型直接比较
		if a != b {
			// 限制值的长度，避免差异过长
			aStr := fmt.Sprintf("%v", a)
			bStr := fmt.Sprintf("%v", b)

			aDisplay := truncateString(aStr, 50)
			bDisplay := truncateString(bStr, 50)

			differences = append(differences, fmt.Sprintf("值 '%s' 不同: 原始=%s, 未授权=%s",
				path, aDisplay, bDisplay))
		}
	}

	return differences
}

// 截断字符串，添加省略号
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// min函数返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max函数实现
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// 从响应体中检测敏感数据，返回详细的匹配情况
func detectSensitiveDataWithDetails(respBody string, patterns map[string]string) []string {
	result := []string{}

	// 性能保护：如果内容超过10MB，截断内容
	if len(respBody) > 10*1024*1024 {
		utils.Warning("[敏感数据检测] 内容超过10MB，截断为前10MB")
		respBody = respBody[:10*1024*1024]
	} else {
		utils.Warning("[敏感数据检测] 内容大小正常，总长度: %d 字节", len(respBody))
	}

	utils.Warning("[敏感数据检测] 开始检测敏感数据，内容长度: %d 字节", len(respBody))

	// 记录响应体摘要，帮助调试
	if len(respBody) > 200 {
		utils.Debug("[敏感数据检测] 响应体摘要: %s...", respBody[:200])
	} else {
		utils.Debug("[敏感数据检测] 响应体摘要: %s", respBody)
	}

	// 用于记录每个类型的匹配数
	typeCounts := make(map[string]int)

	// 遍历所有正则表达式模式
	for name, patternStr := range patterns {
		// 错误恢复，确保一个正则表达式的问题不会影响整体检测
		func() {
			defer func() {
				if r := recover(); r != nil {
					utils.Warning("[敏感数据检测] 处理模式 %s 时发生错误: %v", name, r)
				}
			}()

			// 编译正则表达式
			pattern, err := regexp.Compile(patternStr)
			if err != nil {
				utils.Warning("[敏感数据检测] 编译正则表达式 %s 失败: %v", name, err)
				return
			}

			// 查找匹配项
			matches := pattern.FindAllString(respBody, -1)

			// 过滤无效匹配
			validMatches := []string{}
			for _, match := range matches {
				if isValidMatch(name, match) {
					validMatches = append(validMatches, match)
				}
			}

			// 去重
			uniqueMatches := make(map[string]bool)
			for _, match := range validMatches {
				if !uniqueMatches[match] {
					uniqueMatches[match] = true
				}
			}

			// 限制匹配项数量，避免过多输出
			var matchList []string
			count := 0
			for match := range uniqueMatches {
				// 不再遮掩敏感数据，直接展示完整内容
				matchList = append(matchList, match)
				count++
				if count >= 10 {
					break
				}
			}

			// 如果找到匹配项，添加到结果
			if count > 0 {
				typeCounts[name] = count
				patternDesc := getPatternDescription(name)

				result = append(result, fmt.Sprintf("发现%s: %s", patternDesc, strings.Join(matchList, ", ")))
				utils.Warning("[敏感数据检测] 检测到 %s: %d 处", patternDesc, count)
			}
		}()
	}

	utils.Warning("[敏感数据检测] 检测完成，发现 %d 种类型的敏感数据", len(result))
	return result
}

// 对敏感值进行掩码处理 - 现在仅返回原始值，不进行掩码
func maskSensitiveValue(value string, dataType string) string {
	// 直接返回原始值，不进行任何掩码处理
	return value
}

// isValidMatch 额外验证匹配结果是否有效，减少误报
func isValidMatch(name string, value string) bool {
	switch name {
	case "idCard":
		// 身份证号码需要符合特定格式
		if len(value) != 18 && len(value) != 15 {
			return false
		}

		// 检查是否是订单号等误报情况
		if strings.HasPrefix(value, "PC") || strings.HasPrefix(value, "OD") {
			return false
		}

		// 检查身份证前6位是否是有效的行政区划码
		if len(value) == 18 {
			// 简单验证前两位是否在合理范围内(11-65之间的省级行政区划码)
			prefix, _ := strconv.Atoi(value[:2])
			if prefix < 11 || prefix > 65 {
				return false
			}
		}

		return true

	case "phone":
		// 放宽手机号验证 - 支持不同格式

		// 移除所有非数字字符，以便检查格式化的号码
		cleanValue := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, value)

		// 快速检查：如果在时间相关字段中或直接是时间戳格式，直接拒绝
		if containsTimeFieldName(value) || isTimestampFormat(cleanValue) {
			return false
		}

		// 数字过长的情况，通常是ID或时间戳，而非手机号
		if len(cleanValue) > 11 {
			return false
		}

		// 中国大陆手机号：11位，以1开头
		if len(cleanValue) == 11 && strings.HasPrefix(cleanValue, "1") {
			// 如果是11位且第一位是1，很可能是中国手机号
			utils.Debug("[验证] 可能是中国手机号: %s -> %s", value, cleanValue)

			// 检查剩余数字是否都在合理范围内
			secondDigit := cleanValue[1:2]
			if secondDigit >= "3" && secondDigit <= "9" {
				// 再次检查是否可能是时间戳
				// 以17开头的手机号很可能是时间戳,当前时间戳17开头
				if strings.HasPrefix(cleanValue, "17") && !strings.Contains(strings.ToLower(value), "phone") {
					return false
				}
				return true
			}
		}

		// 避免误报：不太可能是纯数字的手机号
		if strings.Count(value, "0") > 7 ||
			strings.Count(value, "1") > 7 ||
			strings.Count(value, "9") > 7 {
			return false
		}

		// 如果是getImBase API或包含phone字段，更宽松地验证
		if strings.Contains(value, "getImBase") || strings.Contains(strings.ToLower(value), "phone") {
			// 如果长度在10-13之间，更有可能是电话号码
			if len(cleanValue) >= 10 && len(cleanValue) <= 13 {
				utils.Debug("[验证] 特殊API中的可能电话号码: %s", cleanValue)
				return true
			}
		}

		return false

	case "bankCard":
		// 银行卡号通常为16-19位
		if len(value) < 16 || len(value) > 19 {
			return false
		}

		// 避免误报：检查是否是页面ID、时间戳等
		if strings.Contains(value, "-") || strings.Contains(value, ":") {
			return false
		}

		return true

	case "email":
		// 电子邮箱必须包含@和.
		return strings.Contains(value, "@") && strings.Contains(value, ".")

	default:
		return true
	}
}

// 计算未授权访问的置信度评分
func calculateConfidenceScore(r *RequestResponseLog, respBody []byte, resp *http.Response) (int, []string) {
	totalScore := 0
	appliedRules := []string{}

	// 检查参数是否为空
	if r == nil || r.Response == nil || resp == nil || respBody == nil {
		utils.Warning("[未授权检测] calculateConfidenceScore调用参数异常: r=%v, respBody长度=%d, resp=%v",
			r != nil, len(respBody), resp != nil)
		return 0, []string{"参数检查失败"}
	}

	// 确保r.Response.Body不为空
	if r.Response.Body == nil {
		utils.Warning("[未授权检测] 原始响应体为空")
		return 0, []string{"原始响应体为空"}
	}

	// 获取配置
	conf := config.GetConfig()

	// 获取配置的规则列表
	if conf == nil {
		utils.Error("[未授权检测] 配置对象为空")
		return 0, []string{"配置对象为空"}
	}

	rules := conf.UnauthorizedScan.ConfidenceRules

	// 如果没有配置规则，使用默认规则
	if len(rules) == 0 {
		rules = getDefaultConfidenceRules()
	}

	// 检查响应体中的敏感数据，并根据命中条数计算分数
	var sensitiveDataCount int
	var sensitiveDetails []string
	var sensitiveMatches []string // 保存完整的敏感数据匹配结果

	if conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
		sensitivePatterns := make(map[string]string)
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.Patterns {
			sensitivePatterns[pattern.Name] = pattern.Pattern
		}

		// 获取所有敏感数据匹配项
		sensitiveMatches = detectSensitiveDataWithDetails(string(respBody), sensitivePatterns)
		sensitiveDataCount = len(sensitiveMatches)

		// 分类汇总敏感数据类型及数量
		sensitiveTypeCounts := make(map[string]int)
		for _, match := range sensitiveMatches {
			parts := strings.SplitN(match, ": ", 2)
			if len(parts) > 0 {
				dataType := strings.TrimPrefix(parts[0], "发现")
				sensitiveTypeCounts[dataType]++
			}
		}

		// 将类型计数转换为详细信息
		for dataType, count := range sensitiveTypeCounts {
			sensitiveDetails = append(sensitiveDetails, fmt.Sprintf("%s(%d处)", dataType, count))
		}
	}

	// 遍历规则并评分
	for _, rule := range rules {
		switch rule.Name {
		case "contains_sensitive_data":
			// 根据敏感数据命中数量计算分数
			if sensitiveDataCount > 0 {
				// 基础分 + 命中条数加分（最高不超过规则权重）
				baseScore := rule.Weight / 2                       // 基础分为权重的一半
				extraScore := min(baseScore, sensitiveDataCount*5) // 每条敏感数据加5分，但不超过基础分
				earnedScore := baseScore + extraScore

				totalScore += earnedScore
				if len(sensitiveDetails) > 0 {
					appliedRules = append(appliedRules, fmt.Sprintf("发现敏感数据: %s", strings.Join(sensitiveDetails, "、")))
				} else {
					appliedRules = append(appliedRules, fmt.Sprintf("发现敏感数据(%d处)", sensitiveDataCount))
				}

				utils.Debug("[未授权检测] 敏感数据评分: 基础分=%d, 额外分=%d, 总计=%d, 敏感数据数量=%d",
					baseScore, extraScore, earnedScore, sensitiveDataCount)
			}

		case "successful_status_code":
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "成功状态码")
			}

		case "json_response":
			var js interface{}
			if json.Unmarshal(respBody, &js) == nil {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "JSON响应")
			}

		case "non_empty_response":
			if len(respBody) > 20 {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "非空响应")
			}

		case "error_keywords_absent":
			errorKeywords := []string{
				"权限不足", "无权限", "未授权", "请先登录", "会话已过期",
				"unauthorized", "access denied", "forbidden", "permission denied",
				"login required", "not authorized", "invalid token",
			}
			hasErrorKeyword := false
			respStr := strings.ToLower(string(respBody))
			for _, keyword := range errorKeywords {
				if strings.Contains(respStr, strings.ToLower(keyword)) {
					hasErrorKeyword = true
					break
				}
			}
			if !hasErrorKeyword {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "无错误关键词")
			}

		case "same_content_type":
			// 安全地获取Content-Type
			origCT := ""
			if r.Response != nil && r.Response.Header != nil {
				origCT = r.Response.Header.Get("Content-Type")
			}

			newCT := ""
			if resp != nil && resp.Header != nil {
				newCT = resp.Header.Get("Content-Type")
			}

			if origCT != "" && origCT == newCT {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "相同内容类型")
			}

		case "similar_content_length":
			// 安全地比较长度
			origLen := 0
			if r.Response != nil && r.Response.Body != nil {
				origLen = len(r.Response.Body)
			}

			newLen := len(respBody)
			// 长度相差不超过10%
			if origLen > 0 && math.Abs(float64(origLen-newLen))/float64(origLen) <= 0.1 {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "相似响应长度")
			}

		case "api_endpoint":
			// 判断是否为API端点
			if r.Request != nil && r.Request.URL != nil {
				urlPath := r.Request.URL.Path
				apiPatterns := []string{"/api/", "/v1/", "/v2/", "/rest/", "/service/"}
				for _, pattern := range apiPatterns {
					if strings.Contains(urlPath, pattern) {
						totalScore += rule.Weight
						appliedRules = append(appliedRules, "API端点")
						break
					}
				}
			}
		}
	}

	utils.Debug("[未授权检测] 置信度评分计算完成: %d分, 应用规则: %v", totalScore, appliedRules)
	return totalScore, appliedRules
}

// 获取默认置信度规则
func getDefaultConfidenceRules() []config.ConfidenceRule {
	return []config.ConfidenceRule{
		{
			Name:        "contains_sensitive_data",
			Description: "响应中包含敏感数据（如手机号、身份证等）",
			Weight:      40, // 敏感数据权重最高
		},
		{
			Name:        "successful_status_code",
			Description: "响应状态码为2xx",
			Weight:      15,
		},
		{
			Name:        "json_response",
			Description: "响应为有效的JSON格式",
			Weight:      10,
		},
		{
			Name:        "non_empty_response",
			Description: "响应内容非空",
			Weight:      10,
		},
		{
			Name:        "error_keywords_absent",
			Description: "响应中不包含错误关键词",
			Weight:      15,
		},
		{
			Name:        "same_content_type",
			Description: "与原始响应具有相同的Content-Type",
			Weight:      5,
		},
		{
			Name:        "similar_content_length",
			Description: "与原始响应长度相似",
			Weight:      5,
		},
		{
			Name:        "api_endpoint",
			Description: "请求URL是典型的API端点",
			Weight:      10,
		},
	}
}

// isNotSuffix 检查路径是否以特定后缀结尾
func isNotSuffix(path string, suffixes []string) bool {
	lowerPath := strings.ToLower(path)

	// 优先检查常见文件类型
	for _, commonExt := range []string{".js", ".css", ".jpg", ".png", ".gif", ".ico"} {
		if strings.HasSuffix(lowerPath, commonExt) {
			utils.Debug("[路径检查] 快速检测到静态文件: %s, 后缀=%s", path, commonExt)
			return false
		}
	}

	// 详细检查所有配置的后缀
	for _, suffix := range suffixes {
		suffix = strings.ToLower(suffix)
		if strings.HasSuffix(lowerPath, suffix) {
			utils.Debug("[路径检查] 路径匹配静态文件后缀: %s, 后缀=%s", path, suffix)
			return false
		}
	}

	// 对于没有后缀的路径，检查它们是否可能是API路径
	if !strings.Contains(lowerPath, ".") {
		if strings.Contains(lowerPath, "/api/") ||
			strings.Contains(lowerPath, "/v1/") ||
			strings.Contains(lowerPath, "/v2/") {
			utils.Debug("[路径检查] 检测到潜在API路径: %s", path)
		}
	}

	return true
}

// containsString 检查字符串是否包含指定子串
func containsString(s string, substrings []string) bool {
	if s == "" {
		return false
	}

	lowerS := strings.ToLower(s)

	for _, substring := range substrings {
		substring = strings.ToLower(substring)
		if strings.Contains(lowerS, substring) {
			utils.Debug("[内容检查] Content-Type匹配过滤规则: %s, 规则=%s", s, substring)
			return true
		}
	}

	return false
}

// processHighPriorityRequests 处理高优先级请求
func processHighPriorityRequests() {
	// 优先处理需要先认证的请求
	logs.Range(func(key, value interface{}) bool {
		// 跳过正在处理的请求
		if isProcessing, ok := processingFlag.Load(key); ok && isProcessing.(bool) {
			return true
		}

		r, ok := value.(*RequestResponseLog)
		if !ok || r == nil || r.Request == nil || r.Request.URL == nil {
			return true
		}

		// 跳过已处理的请求
		if r.Processed {
			return true
		}

		// 判断是否是高优先级请求
		// 例如：登录、认证、重要API等
		path := strings.ToLower(r.Request.URL.Path)
		isHighPriority := strings.Contains(path, "/login") ||
			strings.Contains(path, "/auth") ||
			strings.Contains(path, "/token") ||
			strings.Contains(path, "/user") ||
			strings.Contains(path, "/signin") ||
			r.Request.Method == "POST"

		if isHighPriority && r.Response != nil && r.Response.StatusCode == 200 {
			utils.Debug("[优先处理] 发现高优先级请求: %s %s", r.Request.Method, r.Request.URL.String())

			// 标记为正在处理
			processingFlag.Store(key, true)
			requestStatuses.Store(key, StatusProcessing)

			// 直接使用goroutine处理
			go func() {
				defer func() {
					processingFlag.Delete(key)
					// 不在这里设置Processed标志，改为在扫描完成后设置
				}()

				// 进行特殊处理，例如存储令牌、Cookie等
				if strings.Contains(path, "/login") || strings.Contains(path, "/auth") {
					utils.Debug("[认证请求] 处理可能包含认证信息的请求: %s", r.Request.URL.String())

					// 检查响应头，可能包含认证信息
					authHeaders := []string{"Set-Cookie", "Authorization", "Token", "JWT"}
					for _, header := range authHeaders {
						if value := r.Response.Header.Get(header); value != "" {
							utils.Debug("[认证信息] 发现可能的认证头: %s = %s", header, utils.TruncateString(value, 30))
						}
					}

					// 检查响应体，可能包含认证信息
					if r.Response.Body != nil {
						utils.Debug("[认证信息] 响应体长度: %d 字节", len(r.Response.Body))
					}
				}

				//// 使用统一过滤函数判断是否需要进行安全扫描
				//shouldScan, skipReason := shouldScanRequest(r)
				//if !shouldScan {
				//	utils.Debug("[优先处理] 跳过扫描: %s, 原因: %s", r.Request.URL.String(), skipReason)
				//	r.Processed = true
				//	return
				//}

				// 获取配置
				conf := config.GetConfig()

				// 执行未授权访问检测 (如果已启用)
				var unauthorizedResult *Result
				var unauthorizedErr error

				if conf.UnauthorizedScan.Enabled {
					utils.Debug("[优先处理] 执行未授权访问检测: URL=%s", r.Request.URL.String())
					unauthorizedResult, unauthorizedErr = detectUnauthorizedAccess(r)

					// 如果检测成功且发现未授权漏洞
					if unauthorizedErr == nil && unauthorizedResult != nil {
						// 检查是否包含敏感数据，如果包含则直接使用未授权结果
						if len(unauthorizedResult.SensitiveData) > 0 {
							utils.Warning("[漏洞确认] 未授权检测发现敏感数据，无论结果状态，优先处理为未授权漏洞: %s", r.Request.URL.String())

							// 确保结果为true，因为包含敏感数据
							unauthorizedResult.Result = "true"
							unauthorizedResult.Reason = "包含敏感数据的未授权访问: " + unauthorizedResult.Reason

							// 添加扫描时间
							unauthorizedResult.ScanTime = time.Now().Format("2006-01-02 15:04:05")

							// 添加到Resp数组
							Resp = append(Resp, *unauthorizedResult)

							// 同时添加到报告生成器
							if reportGenerator != nil {
								reportGenerator.AddResult(*unauthorizedResult)
							}

							utils.Warning("[漏洞确认详情] 敏感数据数组长度=%d, 原始Result=%s, URL=%s",
								len(unauthorizedResult.SensitiveData), unauthorizedResult.Result, r.Request.URL.String())

							// 打印前10条敏感数据内容
							maxCount := 10
							if len(unauthorizedResult.SensitiveData) < maxCount {
								maxCount = len(unauthorizedResult.SensitiveData)
							}
							for i := 0; i < maxCount; i++ {
								utils.Warning("[漏洞确认敏感数据] #%d: %s", i+1, unauthorizedResult.SensitiveData[i])
							}

							r.Processed = true
							return
						}

						// 原有逻辑：如果检测成功且发现未授权漏洞 (结果为true)
						if unauthorizedResult.Result == "true" {
							utils.Info("[漏洞发现] 检测到未授权访问漏洞: %s %s", r.Request.Method, r.Request.URL.String())

							// 添加扫描时间
							unauthorizedResult.ScanTime = time.Now().Format("2006-01-02 15:04:05")

							// 添加到Resp数组
							Resp = append(Resp, *unauthorizedResult)

							// 同时添加到报告生成器
							if reportGenerator != nil {
								reportGenerator.AddResult(*unauthorizedResult)
							}

							// 只有当发现的未授权漏洞包含敏感数据时，才直接返回，不执行越权检测
							if len(unauthorizedResult.SensitiveData) > 0 {
								utils.Info("[漏洞确认] 未授权漏洞包含敏感数据，确认存在漏洞，跳过后续检测: %s", r.Request.URL.String())
								utils.Warning("[漏洞确认详情] 敏感数据数组长度=%d, Result=%s, URL=%s",
									len(unauthorizedResult.SensitiveData), unauthorizedResult.Result, r.Request.URL.String())

								// 打印前10条敏感数据内容
								maxCount := 10
								if len(unauthorizedResult.SensitiveData) < maxCount {
									maxCount = len(unauthorizedResult.SensitiveData)
								}
								for i := 0; i < maxCount; i++ {
									utils.Warning("[漏洞确认敏感数据] #%d: %s", i+1, unauthorizedResult.SensitiveData[i])
								}

								r.Processed = true
								return
							}

							utils.Warning("[漏洞分析警告] 未授权漏洞不包含敏感数据，敏感数据长度=%d，继续执行越权检测, URL=%s",
								len(unauthorizedResult.SensitiveData), r.Request.URL.String())
						}
					}
				}

				// 如果未授权扫描未发现漏洞或未启用，继续执行越权检测 (如果已启用)
				if conf.PrivilegeEscalationScan.Enabled {
					utils.Debug("[优先处理] 执行越权检测: URL=%s", r.Request.URL.String())
					privilegeResult, privilegeErr := detectPrivilegeEscalation(r)

					if privilegeErr == nil && privilegeResult != nil {
						utils.Info("[漏洞发现] 检测到潜在越权访问: %s %s", r.Request.Method, r.Request.URL.String())

						// 添加扫描时间
						privilegeResult.ScanTime = time.Now().Format("2006-01-02 15:04:05")

						// 添加到Resp数组
						Resp = append(Resp, *privilegeResult)

						// 同时添加到报告生成器
						if reportGenerator != nil {
							reportGenerator.AddResult(*privilegeResult)
						}
					}
				}

				// 在所有扫描完成后才标记为已处理
				r.Processed = true
			}()
		}

		return true
	})
}

// processLowPriorityRequests 处理低优先级请求
func processLowPriorityRequests() {
	// 获取当前正在处理的请求数
	processingCount := 0
	logs.Range(func(key, value interface{}) bool {
		if isProcessing, ok := processingFlag.Load(key); ok && isProcessing.(bool) {
			processingCount++
		}
		return true
	})

	// 如果正在处理的请求过多，则暂停处理低优先级请求
	maxConcurrent := config.GetConfig().Performance.MaxConcurrentScans
	if maxConcurrent <= 0 {
		maxConcurrent = 5 // 默认值
	}

	if processingCount >= maxConcurrent {
		utils.Debug("[处理控制] 当前处理请求数 %d 已达到最大并发数 %d，暂停处理低优先级请求",
			processingCount, maxConcurrent)
		return
	}

	// 处理低优先级的请求
	remainingSlots := maxConcurrent - processingCount
	processedCount := 0

	logs.Range(func(key, value interface{}) bool {
		// 如果已达到本次可处理的请求数，则停止遍历
		if processedCount >= remainingSlots {
			return false
		}

		// 跳过正在处理的请求
		if isProcessing, ok := processingFlag.Load(key); ok && isProcessing.(bool) {
			return true
		}

		r, ok := value.(*RequestResponseLog)
		if !ok || r == nil || r.Request == nil || r.Request.URL == nil {
			return true
		}

		// 跳过已处理的请求
		if r.Processed {
			return true
		}

		// 判断是否是低优先级请求
		path := strings.ToLower(r.Request.URL.Path)
		isLowPriority := !strings.Contains(path, "/login") &&
			!strings.Contains(path, "/auth") &&
			!strings.Contains(path, "/token") &&
			!strings.Contains(path, "/user") &&
			!strings.Contains(path, "/signin") &&
			r.Request.Method == "GET"

		if isLowPriority && r.Response != nil && r.Response.StatusCode == 200 {
			utils.Debug("[低优先处理] 处理低优先级请求: %s %s", r.Request.Method, r.Request.URL.String())

			// 标记为正在处理
			processingFlag.Store(key, true)
			requestStatuses.Store(key, StatusProcessing)
			processedCount++

			// 直接使用goroutine处理
			go func() {
				defer func() {
					processingFlag.Delete(key)
					// 不在这里设置Processed标志，改为在扫描完成后设置
				}()

				// 记录处理时间
				startTime := time.Now()
				defer func() {
					duration := time.Since(startTime)
					utils.Debug("[低优先处理] 请求处理完成: %s, 耗时=%s", r.Request.URL.String(), duration)
				}()

				//// 使用统一过滤函数判断是否需要进行安全扫描
				//shouldScan, skipReason := shouldScanRequest(r)
				//if !shouldScan {
				//	utils.Debug("[低优先处理] 跳过扫描: %s, 原因: %s", r.Request.URL.String(), skipReason)
				//	r.Processed = true
				//	return
				//}

				// 获取配置
				conf := config.GetConfig()

				// 执行未授权访问检测 (如果已启用)
				var unauthorizedResult *Result
				var unauthorizedErr error

				if conf.UnauthorizedScan.Enabled {
					utils.Debug("[低优先处理] 执行未授权访问检测: URL=%s", r.Request.URL.String())
					unauthorizedResult, unauthorizedErr = detectUnauthorizedAccess(r)

					// 如果检测成功并且获取到结果
					if unauthorizedErr == nil && unauthorizedResult != nil {
						// 检查是否包含敏感数据，如果包含则直接使用未授权结果，不管Result是什么值
						if len(unauthorizedResult.SensitiveData) > 0 {
							utils.Warning("[漏洞确认] 未授权检测发现敏感数据，无论结果状态，优先处理为未授权漏洞: %s", r.Request.URL.String())

							// 确保结果为true，因为包含敏感数据
							unauthorizedResult.Result = "true"
							unauthorizedResult.Reason = "包含敏感数据的未授权访问: " + unauthorizedResult.Reason

							// 添加扫描时间
							unauthorizedResult.ScanTime = time.Now().Format("2006-01-02 15:04:05")

							// 添加到Resp数组
							Resp = append(Resp, *unauthorizedResult)

							// 同时添加到报告生成器
							if reportGenerator != nil {
								reportGenerator.AddResult(*unauthorizedResult)
							}

							utils.Warning("[漏洞确认详情] 敏感数据数组长度=%d, 原始Result=%s, URL=%s",
								len(unauthorizedResult.SensitiveData), unauthorizedResult.Result, r.Request.URL.String())

							// 打印前10条敏感数据内容
							maxCount := 10
							if len(unauthorizedResult.SensitiveData) < maxCount {
								maxCount = len(unauthorizedResult.SensitiveData)
							}
							for i := 0; i < maxCount; i++ {
								utils.Warning("[漏洞确认敏感数据] #%d: %s", i+1, unauthorizedResult.SensitiveData[i])
							}

							r.Processed = true
							return
						}

						// 原有逻辑：检查Result是否为true
						if unauthorizedResult.Result == "true" {
							utils.Info("[漏洞发现] 检测到未授权访问漏洞: %s %s", r.Request.Method, r.Request.URL.String())

							// 添加扫描时间
							unauthorizedResult.ScanTime = time.Now().Format("2006-01-02 15:04:05")

							// 添加到Resp数组
							Resp = append(Resp, *unauthorizedResult)

							// 同时添加到报告生成器
							if reportGenerator != nil {
								reportGenerator.AddResult(*unauthorizedResult)
							}

							// 只有当发现的未授权漏洞包含敏感数据时，才直接返回，不执行越权检测
							if len(unauthorizedResult.SensitiveData) > 0 {
								utils.Info("[漏洞确认] 未授权漏洞包含敏感数据，确认存在漏洞，跳过后续检测: %s", r.Request.URL.String())
								utils.Warning("[漏洞确认详情] 敏感数据数组长度=%d, Result=%s, URL=%s",
									len(unauthorizedResult.SensitiveData), unauthorizedResult.Result, r.Request.URL.String())

								// 打印前10条敏感数据内容
								maxCount := 10
								if len(unauthorizedResult.SensitiveData) < maxCount {
									maxCount = len(unauthorizedResult.SensitiveData)
								}
								for i := 0; i < maxCount; i++ {
									utils.Warning("[漏洞确认敏感数据] #%d: %s", i+1, unauthorizedResult.SensitiveData[i])
								}

								r.Processed = true
								return
							}

							utils.Warning("[漏洞分析警告] 未授权漏洞不包含敏感数据，敏感数据长度=%d，继续执行越权检测, URL=%s",
								len(unauthorizedResult.SensitiveData), r.Request.URL.String())
						}
					}
				}

				// 如果未授权扫描未发现漏洞或未启用，或者未授权漏洞不包含敏感数据，继续执行越权检测 (如果已启用)
				if conf.PrivilegeEscalationScan.Enabled {
					utils.Debug("[低优先处理] 执行越权检测: URL=%s", r.Request.URL.String())
					privilegeResult, privilegeErr := detectPrivilegeEscalation(r)

					if privilegeErr == nil && privilegeResult != nil {
						utils.Info("[漏洞发现] 检测到潜在越权访问: %s %s", r.Request.Method, r.Request.URL.String())

						// 添加扫描时间
						privilegeResult.ScanTime = time.Now().Format("2006-01-02 15:04:05")

						// 添加到Resp数组
						Resp = append(Resp, *privilegeResult)

						// 同时添加到报告生成器
						if reportGenerator != nil {
							reportGenerator.AddResult(*privilegeResult)
						}
					}
				}

				// 在所有扫描完成后才标记为已处理
				r.Processed = true
			}()
		}

		return true
	})

	if processedCount > 0 {
		utils.Debug("[低优先处理] 本轮处理了 %d 个低优先级请求", processedCount)
	}
}

// cleanupStaleRequests 清理过期的请求
func cleanupStaleRequests() {
	now := time.Now()
	staleCount := 0
	noResponseCount := 0
	connectRequestCount := 0
	processedCount := 0

	// 记录问题请求的域名统计
	problemDomains := make(map[string]int)

	// 搜索长时间没有完成的请求
	logs.Range(func(key any, value any) bool {
		r, ok := value.(*RequestResponseLog)
		if !ok || r == nil || r.Request == nil || r.Request.URL == nil {
			// 无效记录，直接删除
			logs.Delete(key)
			staleCount++
			return true
		}

		// 计算请求年龄
		age := now.Sub(r.ReceivedAt)
		host := r.Request.URL.Host

		// 已处理请求清理 - 更激进的清理策略
		if r.Processed {
			processedCount++
			// 已处理的请求仅保留2分钟
			if age > 2*time.Minute {
				logs.Delete(key)
				staleCount++
			}
			return true
		}

		// 处理CONNECT请求
		if r.ConnectRequest {
			if age > 5*time.Minute {
				// 5分钟以上的CONNECT请求可以清理
				logs.Delete(key)
				connectRequestCount++
			}
			return true
		}

		// 检查长时间无响应的请求
		if r.Response == nil {
			// 无响应请求统计
			noResponseCount++

			// 记录域名统计
			problemDomains[host]++

			// 标记已知问题域名的请求，减少后续处理
			if strings.Contains(host, "wx.17u.cn") ||
				strings.Contains(host, "problematic-domain.com") {
				if !r.Processed && age > 30*time.Second {
					utils.Debug("[特殊域名处理] 标记问题域名请求为已处理: %s", r.Request.URL.String())
					r.Processed = true
					logs.Store(key, r)
				}
			}

			// 超过5分钟的无响应请求直接清理
			if age > 5*time.Minute {
				utils.Debug("[清理] 清理长时间无响应请求: %s, 年龄=%s",
					r.Request.URL.String(), age)
				logs.Delete(key)
				staleCount++
			}
			return true
		}

		return true
	})

	// 减少统计输出频率，避免日志爆炸
	if staleCount > 10 || noResponseCount > 20 {
		utils.Info("[清理统计] 已清理 %d 个过期请求，发现 %d 个无响应请求，%d 个已处理请求",
			staleCount, noResponseCount, processedCount)

		// 仅当问题域名数超过阈值时才输出详细统计
		if len(problemDomains) > 0 && noResponseCount > 10 {
			utils.Info("[无响应域名统计]")
			for domain, count := range problemDomains {
				if count > 5 {
					utils.Info(" - %s: %d 个无响应请求", domain, count)
				}
			}
		}
	}
}

// 处理CONNECT请求，尝试匹配和标记相关请求
func handleConnectRequests() {
	connectCount := 0

	logs.Range(func(key any, value any) bool {
		r, ok := value.(*RequestResponseLog)
		if !ok || r == nil || r.Request == nil {
			return true
		}

		// 识别CONNECT请求并标记
		if r.Request.Method == "CONNECT" && !r.ConnectRequest {
			r.ConnectRequest = true
			r.Processed = true
			logs.Store(key, r)
			connectCount++
			utils.Debug("[CONNECT处理] 标记CONNECT请求: %s", r.Request.URL.String())
		}

		return true
	})

	if connectCount > 0 {
		utils.Debug("[CONNECT处理] 已标记 %d 个CONNECT请求", connectCount)
	}
}

// setupPatterns 初始化敏感数据检测的正则表达式
func setupPatterns() {
	var err error

	// 使用双引号替代反引号，避免Unicode转义问题
	// 中文姓名模式 - 2-4个汉字
	namePattern, err = regexp.Compile("[\\x{4e00}-\\x{9fa5}]{2,4}(先生|女士|小姐|同学|老师|教授|医生|博士)?")
	if err != nil {
		utils.Warning("[敏感数据检测] 编译姓名正则表达式失败: %v", err)
	}

	// 身份证号模式 - 更精确的身份证匹配，检查省份编码规则
	idCardPattern, err = regexp.Compile(`(([1-9]\d{5})(18|19|20)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\d{3}[0-9Xx]))|(([1-9]\d{5})(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\d{3}))`)
	if err != nil {
		utils.Warning("[敏感数据检测] 编译身份证正则表达式失败: %v", err)
	}

	// 手机号模式 - 更精确的手机号匹配模式，避免误报
	// 使用断言确保前后不是数字，避免匹配长数字序列中的子串
	phonePattern, err = regexp.Compile(`(?<!\d)1[3-9]\d{9}(?!\d)`)
	if err != nil {
		utils.Warning("[敏感数据检测] 编译手机号正则表达式失败: %v", err)
	}

	// 地址模式 - 包含省市县区路街号的地址
	addressPattern, err = regexp.Compile("[\\x{4e00}-\\x{9fa5}]{2,}(省|市|县|区|路|街|号)")
	if err != nil {
		utils.Warning("[敏感数据检测] 编译地址正则表达式失败: %v", err)
	}

	// 电子邮件模式
	emailPattern, err = regexp.Compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
	if err != nil {
		utils.Warning("[敏感数据检测] 编译电子邮件正则表达式失败: %v", err)
	}

	// 银行卡号模式 - 16到19位数字
	bankCardPattern, err = regexp.Compile("\\b\\d{16,19}\\b")
	if err != nil {
		utils.Warning("[敏感数据检测] 编译银行卡正则表达式失败: %v", err)
	}
}

// 计算字符串中可能的乱码率
func calculateContaminationRate(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	invalidCount := 0
	totalCount := 0

	// 遍历字符串中的每个符文（Unicode字符）
	for _, r := range s {
		totalCount++

		// 检查是否是控制字符（除了常见的如换行、制表符外）
		if unicode.IsControl(r) &&
			r != '\n' && r != '\r' && r != '\t' {
			invalidCount++
			continue
		}

		// 检查是否是不可打印字符或私有使用区域字符
		if !unicode.IsPrint(r) ||
			(r >= 0xE000 && r <= 0xF8FF) || // 私有使用区
			(r >= 0xF0000 && r <= 0x10FFFF) { // 补充私有使用区
			invalidCount++
			continue
		}

		// 检查是否是替换字符（通常表示解码失败）
		if r == unicode.ReplacementChar {
			invalidCount++
			continue
		}
	}

	return float64(invalidCount) / float64(totalCount)
}

// 递归提取JSON中的所有字符串值
func extractJSONStringValues(data interface{}) []string {
	var result []string

	// 添加更多调试输出
	utils.Debug("[敏感数据检测-JSON] 提取字符串值，数据类型: %T", data)

	switch v := data.(type) {
	case string:
		// 找到字符串值
		result = append(result, v)
		utils.Debug("[敏感数据检测-JSON] 提取到字符串值: %s", v)
	case map[string]interface{}:
		// 对象，递归处理所有值
		utils.Debug("[敏感数据检测-JSON] 处理对象，键数量: %d", len(v))
		for key, value := range v {
			utils.Debug("[敏感数据检测-JSON] 处理对象字段: %s", key)
			stringValues := extractJSONStringValues(value)
			result = append(result, stringValues...)

			// 直接也将键考虑为可能的字符串值
			result = append(result, key)
		}
	case []interface{}:
		// 数组，递归处理所有元素
		utils.Debug("[敏感数据检测-JSON] 处理数组，元素数量: %d", len(v))
		for i, item := range v {
			utils.Debug("[敏感数据检测-JSON] 处理数组元素 #%d", i)
			stringValues := extractJSONStringValues(item)
			result = append(result, stringValues...)
		}
	case float64:
		// 将数值转换为字符串也检查（可能有些数值看起来像电话号码）
		strVal := fmt.Sprintf("%v", v)
		result = append(result, strVal)
		utils.Debug("[敏感数据检测-JSON] 将数值转换为字符串: %s", strVal)
	case bool:
		// 将布尔值转换为字符串
		strVal := fmt.Sprintf("%v", v)
		result = append(result, strVal)
	case nil:
		// 忽略空值
		utils.Debug("[敏感数据检测-JSON] 忽略空值")
	default:
		// 处理其他类型，转换为字符串
		strVal := fmt.Sprintf("%v", v)
		result = append(result, strVal)
		utils.Debug("[敏感数据检测-JSON] 转换未知类型为字符串: %s (%T)", strVal, v)
	}

	return result
}

// 从JSON响应中提取并检测敏感数据
func detectSensitiveDataInJSON(jsonStr string, patterns map[string]string) []string {
	var result []string

	utils.Warning("[敏感数据检测-JSON] 开始检测敏感数据，内容长度: %d", len(jsonStr))

	// 记录JSON内容摘要，帮助调试
	if len(jsonStr) > 200 {
		utils.Debug("[敏感数据检测-JSON] JSON内容摘要: %s...", jsonStr[:200])
	} else {
		utils.Debug("[敏感数据检测-JSON] JSON内容: %s", jsonStr)
	}

	// 获取JSON专用的正则表达式
	conf := config.GetConfig()
	jsonPatterns := make(map[string]string)
	if conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns != nil {
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
			jsonPatterns[pattern.Name] = pattern.Pattern
			utils.Debug("[敏感数据检测-JSON] 使用JSON专用正则: %s = %s", pattern.Name, pattern.Pattern)
		}
	} else {
		// 如果没有JSON专用正则，使用普通正则
		jsonPatterns = patterns
	}

	// 预先检测常见时间戳字段，建立排除列表
	timeFieldValues := extractTimeFieldValues(jsonStr)
	utils.Debug("[敏感数据检测-JSON] 识别到 %d 个时间字段值用于排除", len(timeFieldValues))

	// 用于记录每个类型的匹配数
	typeCounts := make(map[string]int)

	// 在字符串值中检测敏感信息
	for name, patternStr := range jsonPatterns {
		// 错误恢复，确保一个正则表达式的问题不会影响整体检测
		func() {
			defer func() {
				if r := recover(); r != nil {
					utils.Warning("[敏感数据检测-JSON] 处理模式 %s 时发生错误: %v", name, r)
				}
			}()

			pattern, err := regexp.Compile(patternStr)
			if err != nil {
				utils.Warning("[敏感数据检测-JSON] 编译正则表达式失败: %v", err)
				return
			}

			utils.Debug("[敏感数据检测-JSON] 使用正则表达式 %s: %s", name, patternStr)

			// 直接在整个JSON字符串中查找匹配项
			matches := pattern.FindAllString(jsonStr, -1)

			// 去重处理匹配项
			uniqueMatches := make(map[string]bool)
			for _, match := range matches {
				// 如果是JSON模式中的匹配，去掉引号
				if strings.HasPrefix(match, "\"") && strings.HasSuffix(match, "\"") {
					// 去掉引号
					cleanMatch := match[1 : len(match)-1]

					// 排除误报：时间戳和其他常见的长数字字段
					if name == "phone" {
						// 检查是否是时间戳（13位或更长数字，且不符合手机号格式）
						if len(cleanMatch) >= 13 && !isValidPhoneNumber(cleanMatch) {
							utils.Debug("[敏感数据检测-JSON] 排除疑似时间戳数据: %s", cleanMatch)
							continue
						}

						// 检查是否在预先提取的时间字段值列表中
						if isInTimeValues(cleanMatch, timeFieldValues) {
							utils.Debug("[敏感数据检测-JSON] 排除时间值列表中的数据: %s", cleanMatch)
							continue
						}

						// 检查是否在一个常见的时间戳字段中
						contextBefore := extractContext(jsonStr, match, 30, true)
						if containsTimeFieldName(contextBefore) {
							utils.Debug("[敏感数据检测-JSON] 排除时间字段中的数值: %s (上下文: %s)", cleanMatch, contextBefore)
							continue
						}

						// 额外检查：时间戳格式检测
						if isTimestampFormat(cleanMatch) {
							utils.Debug("[敏感数据检测-JSON] 排除标准时间戳格式: %s", cleanMatch)
							continue
						}
					}

					uniqueMatches[cleanMatch] = true
				} else {
					// 非JSON匹配的情况，也需要检查是否为误报
					if name == "phone" {
						if len(match) >= 13 && !isValidPhoneNumber(match) {
							utils.Debug("[敏感数据检测-JSON] 排除疑似时间戳数据: %s", match)
							continue
						}

						// 检查是否在预先提取的时间字段值列表中
						if isInTimeValues(match, timeFieldValues) {
							utils.Debug("[敏感数据检测-JSON] 排除时间值列表中的数据: %s", match)
							continue
						}

						// 额外检查：时间戳格式检测
						if isTimestampFormat(match) {
							utils.Debug("[敏感数据检测-JSON] 排除标准时间戳格式: %s", match)
							continue
						}
					}
					uniqueMatches[match] = true
				}
			}

			// 记录匹配数量及样例
			matchCount := len(uniqueMatches)
			var matchSamples []string

			for match := range uniqueMatches {
				if len(matchSamples) < 5 {
					matchSamples = append(matchSamples, match)
				}
			}

			if matchCount > 0 {
				typeCounts[name] = matchCount
				patternDesc := getPatternDescription(name)
				matchSummary := fmt.Sprintf("发现%s: %d处", patternDesc, matchCount)
				if len(matchSamples) > 0 {
					matchSummary += fmt.Sprintf("，样例: %s", strings.Join(matchSamples, ", "))
				}
				result = append(result, matchSummary)
				utils.Warning("[敏感数据检测-JSON] 检测到 %s: %d 处", patternDesc, matchCount)
			} else {
				utils.Debug("[敏感数据检测-JSON] 未检测到 %s", name)
			}
		}()
	}

	utils.Warning("[敏感数据检测-JSON] 检测完成，发现 %d 种类型的敏感数据", len(result))
	return result
}

// 预先提取所有时间相关字段的值
func extractTimeFieldValues(jsonStr string) []string {
	var timeValues []string

	// 尝试解析JSON对象
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		utils.Debug("[敏感数据检测-JSON] 提取时间字段值时解析JSON失败: %v", err)
		return timeValues
	}

	// 提取所有字段及其值
	fields := getJSONFields(data)

	// 检查每个字段名是否为时间相关字段
	for field, value := range fields {
		if containsTimeFieldName(field) {
			// 提取时间字段的值
			switch v := value.(type) {
			case string:
				timeValues = append(timeValues, v)
			case float64:
				timeValues = append(timeValues, strconv.FormatFloat(v, 'f', 0, 64))
			case int:
				timeValues = append(timeValues, strconv.Itoa(v))
			case int64:
				timeValues = append(timeValues, strconv.FormatInt(v, 10))
			}
		}
	}

	return timeValues
}

// 检查值是否在时间字段值列表中
func isInTimeValues(value string, timeValues []string) bool {
	for _, tv := range timeValues {
		if tv == value {
			return true
		}
	}
	return false
}

// 判断是否符合时间戳格式
func isTimestampFormat(s string) bool {
	// 检查UNIX时间戳格式 (10位或13位数字)
	if len(s) >= 10 && len(s) <= 16 {
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			// 13位是毫秒级时间戳，非常常见
			if len(s) == 13 {
				return true
			}

			// 10位是秒级时间戳，也很常见
			if len(s) == 10 {
				return true
			}

			// 14-16位可能是带有微秒/纳秒的时间戳
			if len(s) >= 14 && len(s) <= 16 {
				return true
			}

			// 如果以174开头的数字大概率为时间戳（2025年前后的时间戳都是17开头）
			if strings.HasPrefix(s, "17") {
				return true
			}

			// 如果以16开头的数字大概率为时间戳（2020年左右的时间戳都是16开头）
			if strings.HasPrefix(s, "16") {
				return true
			}

			// 验证是否在合理的时间范围内 (2000年~2099年)
			timestamp, _ := strconv.ParseInt(s, 10, 64)
			if len(s) >= 13 { // 毫秒级时间戳
				timestamp = timestamp / 1000
			}

			// 检查是否在合理的时间范围
			if timestamp >= 946684800 && timestamp <= 4102444800 {
				return true
			}
		}
	}

	// 检查ISO 8601日期时间格式
	isoPatterns := []string{
		`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`,
		`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`,
		`^\d{4}-\d{2}-\d{2}$`,
		`^\d{4}/\d{2}/\d{2}$`,
	}

	for _, pattern := range isoPatterns {
		if matched, _ := regexp.MatchString(pattern, s); matched {
			return true
		}
	}

	return false
}

// 从字符串中提取匹配项前后的上下文
func extractContext(text string, match string, contextSize int, before bool) string {
	matchIndex := strings.Index(text, match)
	if matchIndex == -1 {
		return ""
	}

	if before {
		// 提取匹配项前的上下文
		startIndex := matchIndex - contextSize
		if startIndex < 0 {
			startIndex = 0
		}
		return text[startIndex:matchIndex]
	} else {
		// 提取匹配项后的上下文
		endIndex := matchIndex + len(match) + contextSize
		if endIndex > len(text) {
			endIndex = len(text)
		}
		return text[matchIndex+len(match) : endIndex]
	}
}

// 检查字符串是否包含时间相关的字段名
func containsTimeFieldName(s string) bool {
	timeFields := []string{
		"time", "Time", "TIME",
		"timestamp", "Timestamp", "TIMESTAMP",
		"date", "Date", "DATE",
		"createTime", "CreateTime", "createAt", "CreateAt",
		"updateTime", "UpdateTime", "updateAt", "UpdateAt",
		"start", "Start", "end", "End",
		"rspTime", "RspTime", "reqTime", "ReqTime",
		"lastTime", "LastTime", "beginTime", "BeginTime",
		"endTime", "EndTime", "startTime", "StartTime",
		"modifyTime", "ModifyTime", "modified", "Modified",
		"created", "Created", "uptime", "Uptime",
		"lastModified", "LastModified", "responseTime", "ResponseTime",
		"ts", "TS", "millis", "Millis", "ms", "MS",
		"nanos", "Nanos", "seconds", "Seconds",
		"unix", "Unix", "utc", "UTC", "gmt", "GMT",
		"lastUpdated", "LastUpdated", "expiry", "Expiry",
		"ttl", "TTL", "expire", "Expire", "pubTime", "PubTime",
		"timeStamp", "TimeStamp", "timespan", "Timespan",
	}

	for _, field := range timeFields {
		if strings.Contains(s, field) {
			return true
		}
	}
	return false
}

// 获取模式描述
func getPatternDescription(name string) string {
	switch name {
	case "phone":
		return "手机号码"
	case "email":
		return "电子邮箱"
	case "idCard":
		return "身份证号"
	case "bankCard":
		return "银行卡号"
	case "address":
		return "地址信息"
	case "name":
		return "姓名信息"
	default:
		return name
	}
}

// 获取JSON对象中的所有字段名和值
func getJSONFields(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	var extractFields func(data interface{}, prefix string)
	extractFields = func(data interface{}, prefix string) {
		switch v := data.(type) {
		case map[string]interface{}:
			for key, value := range v {
				fieldName := key
				if prefix != "" {
					fieldName = prefix + "." + key
				}
				result[fieldName] = value
				extractFields(value, fieldName)
			}
		case []interface{}:
			for i, item := range v {
				fieldName := fmt.Sprintf("%s[%d]", prefix, i)
				extractFields(item, fieldName)
			}
		}
	}

	extractFields(data, "")
	return result
}

// 判断是否是有效的手机号（对于中国手机号，必须是1开头的11位数字）
func isValidPhoneNumber(s string) bool {
	if len(s) != 11 {
		return false
	}
	if s[0] != '1' {
		return false
	}
	// 确保全部是数字
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// shouldScanRequest 统一过滤函数，判断请求是否需要进行安全扫描
// 返回值: (是否应该扫描, 跳过原因)
//func shouldScanRequest(r *RequestResponseLog) (bool, string) {
//	if r == nil || r.Request == nil || r.Request.URL == nil {
//		return false, "无效的请求对象"
//	}
//
//	// 获取配置
//	conf := config.GetConfig()
//	if conf == nil {
//		return false, "配置未初始化"
//	}
//
//	// 检查是否为静态资源
//	if !isNotSuffix(r.Request.URL.Path, conf.Suffixes) {
//		return false, "静态资源文件"
//	}
//
//	// 检查是否在排除路径中
//	if isExcludedPath(r.Request.URL.Path, conf.UnauthorizedScan.ExcludePatterns) {
//		return false, "排除路径"
//	}
//
//	// 检查响应头
//	if r.Response != nil {
//		contentType := r.Response.Header.Get("Content-Type")
//		if !contains(conf.AllowedRespHeaders, contentType) {
//			return false, "不允许的响应类型"
//		}
//	}
//
//	return true, ""
//}

// detectPrivilegeEscalation 执行越权检测
func detectPrivilegeEscalation(r *RequestResponseLog) (*Result, error) {
	if r == nil || r.Request == nil || r.Response == nil {
		utils.Warning("[越权检测] 请求/响应为空, 跳过越权检测")
		return nil, fmt.Errorf("请求或响应为空")
	}

	// 获取配置
	conf := config.GetConfig()
	if conf == nil || !conf.PrivilegeEscalationScan.Enabled {
		return nil, fmt.Errorf("越权扫描未启用或配置不存在")
	}

	// 创建结果对象
	vulnResult := &Result{
		Method:   r.Request.Method,
		Url:      r.Request.URL.String(),
		VulnType: string(VulnPrivilegeEscalation),
		Result:   "unknown",
	}

	// 提取请求方法、路径和协议版本
	proto := r.Request.Proto
	if proto == "" {
		proto = "2" // 默认使用HTTP/2
	}

	// 获取Host值
	host := ""
	if hostValues := r.Request.Header["Host"]; len(hostValues) > 0 {
		host = hostValues[0]
	} else if r.Request.URL != nil && r.Request.URL.Host != "" {
		host = r.Request.URL.Host
	}

	// 构建完整的请求行
	requestLine := fmt.Sprintf("%s %s HTTP/%s",
		r.Request.Method,
		r.Request.URL.Path+"?"+r.Request.URL.RawQuery,
		proto)

	// 设置原始请求详情
	vulnResult.RequestA = requestLine + "\n"
	if !strings.Contains(formatHeaders(r.Request.Header), "Host: ") && host != "" {
		vulnResult.RequestA += fmt.Sprintf("Host: %s\n", host)
	}
	vulnResult.RequestA += formatHeaders(r.Request.Header)

	// 如果有请求体，添加空行后添加请求体
	if len(r.Request.Body) > 0 {
		vulnResult.RequestA += "\n" + string(r.Request.Body)
	} else {
		// 即使没有请求体，也添加空行表示请求头结束
		vulnResult.RequestA += "\n"
	}

	// 检查请求是否包含需要进行越权测试的参数模式
	hasPrivilegePattern := false
	matchedParam := ""

	// 检查URL参数
	for _, pattern := range conf.PrivilegeEscalationScan.ParamPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			utils.Warning("[越权检测] 编译参数模式失败: %v, 模式=%s", err, pattern)
			continue
		}

		// 检查URL中是否匹配
		if re.MatchString(r.Request.URL.String()) {
			hasPrivilegePattern = true
			matchedParam = re.FindString(r.Request.URL.String())
			utils.Debug("[越权检测] 在URL中匹配到越权参数: %s", matchedParam)
			break
		}

		// 检查请求体中是否匹配
		if len(r.Request.Body) > 0 {
			if re.MatchString(string(r.Request.Body)) {
				hasPrivilegePattern = true
				matchedParam = re.FindString(string(r.Request.Body))
				utils.Debug("[越权检测] 在请求体中匹配到越权参数: %s", matchedParam)
				break
			}
		}
	}

	// 如果请求中不包含越权测试需要的参数模式，则跳过测试
	if !hasPrivilegePattern {
		utils.Debug("[越权检测] 请求不包含需要检测的越权参数模式: %s", r.Request.URL.String())
		return nil, fmt.Errorf("请求不包含需要检测的越权参数模式")
	}

	// 保存原始响应
	respA := r.Response

	// 设置原始响应详情
	vulnResult.RespBodyA = string(respA.Body)
	vulnResult.HeaderA = formatHeaders(respA.Header)

	// 创建替换请求进行越权测试
	newReq := cloneRequest(r.Request)
	if newReq == nil {
		utils.Warning("[越权检测] 无法克隆请求")
		return nil, fmt.Errorf("无法克隆请求")
	}

	// 使用headers2替换原始请求头
	// 替换前先保存原始请求头
	originalHeaders := make(http.Header)
	for key, values := range newReq.Header {
		originalHeaders[key] = values
	}

	// 清除原有授权相关头信息
	for _, header := range conf.UnauthorizedScan.RemoveHeaders {
		if len(newReq.Header[header]) > 0 {
			utils.Debug("[越权检测] 移除原始请求中的认证头: %s", header)
			delete(newReq.Header, header)
		}
	}

	// 使用配置中的headers2替换
	for key, value := range conf.Headers2 {
		newReq.Header.Set(key, value)
		utils.Debug("[越权检测] 设置headers2中的头: %s = %s", key, value)
	}

	utils.Info("[越权检测] 准备发送替换请求: %s %s", newReq.Method, newReq.URL.String())

	// 发送请求
	client := &http.Client{
		Timeout: time.Duration(conf.Performance.ScanTimeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不自动跟随重定向
		},
	}

	respB, err := client.Do(newReq)
	if err != nil {
		utils.Warning("[越权检测] 发送替换请求失败: %v", err)
		return nil, fmt.Errorf("发送替换请求失败: %v", err)
	}
	defer respB.Body.Close()

	// 读取响应体
	respBBody, err := io.ReadAll(respB.Body)
	if err != nil {
		utils.Warning("[越权检测] 读取替换请求响应体失败: %v", err)
		return nil, fmt.Errorf("读取替换请求响应体失败: %v", err)
	}

	// 保存替换请求详情
	vulnResult.RequestB = formatRequest(newReq)
	vulnResult.RespBodyB = string(respBBody)
	vulnResult.HeaderB = formatHeaders(respB.Header)

	// 替换请求行
	replacementRequestLine := fmt.Sprintf("%s %s HTTP/%s",
		newReq.Method,
		newReq.URL.Path+"?"+newReq.URL.RawQuery,
		proto)

	// 构建完整的替换请求
	requestB := replacementRequestLine + "\n"
	if !strings.Contains(formatHeaders(newReq.Header), "Host: ") && host != "" {
		requestB += fmt.Sprintf("Host: %s\n", host)
	}
	requestB += formatHeaders(newReq.Header)

	// 如果有请求体，添加空行后添加请求体
	if newReq.Body != nil {
		// 读取请求体
		bodyBytes, _ := io.ReadAll(newReq.Body)
		if len(bodyBytes) > 0 {
			requestB += "\n" + string(bodyBytes)
		} else {
			// 即使没有请求体，也添加空行表示请求头结束
			requestB += "\n"
		}
	} else {
		requestB += "\n"
	}

	// 设置最终的替换请求
	vulnResult.RequestB = requestB

	// 用于检测响应异常的状态码
	statusCodes := map[int]string{
		401: "未授权",
		403: "禁止访问",
		404: "资源不存在",
		500: "服务器错误",
	}

	// 检查状态码是否表明授权失败
	if errMsg, ok := statusCodes[respB.StatusCode]; ok {
		utils.Info("[越权检测] 替换请求返回错误状态码: %d (%s)", respB.StatusCode, errMsg)
		vulnResult.Result = "false"
		vulnResult.Reason = fmt.Sprintf("替换请求返回错误状态码: %d (%s)", respB.StatusCode, errMsg)
		return vulnResult, nil
	}

	// 如果替换请求状态码成功(2xx)，进一步分析响应内容
	if respB.StatusCode >= 200 && respB.StatusCode < 300 {
		// 准备检测敏感数据的工具
		sensitivePatternsMap := make(map[string]*regexp.Regexp)

		// 编译敏感数据正则表达式
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.Patterns {
			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				utils.Warning("[越权检测] 编译敏感数据模式失败: %v, 模式=%s", err, pattern.Pattern)
				continue
			}
			sensitivePatternsMap[pattern.Name] = re
		}

		// 检查JSON格式的敏感数据
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				utils.Warning("[越权检测] 编译JSON敏感数据模式失败: %v, 模式=%s", err, pattern.Pattern)
				continue
			}
			sensitivePatternsMap[pattern.Name+"_json"] = re
		}

		// 检测原始响应中的敏感数据
		respAStr := string(respA.Body)
		originalSensitiveData := []string{}

		for name, re := range sensitivePatternsMap {
			if re.MatchString(respAStr) {
				matches := re.FindAllString(respAStr, -1)
				if len(matches) > 0 {
					for _, match := range matches {
						originalSensitiveData = append(originalSensitiveData, fmt.Sprintf("%s: %s", name, match))
						if len(originalSensitiveData) >= 5 {
							break
						}
					}
				}
				if len(originalSensitiveData) >= 5 {
					break
				}
			}
		}

		// 检测替换请求响应中的敏感数据
		respBStr := string(respBBody)
		sensitivePatternsFound := []string{}

		for name, re := range sensitivePatternsMap {
			if re.MatchString(respBStr) {
				matches := re.FindAllString(respBStr, -1)
				if len(matches) > 0 {
					for _, match := range matches {
						sensitivePatternsFound = append(sensitivePatternsFound, fmt.Sprintf("%s: %s", name, match))
						if len(sensitivePatternsFound) >= 5 {
							break
						}
					}
				}
				if len(sensitivePatternsFound) >= 5 {
					break
				}
			}
		}

		// 保存敏感数据检测结果
		vulnResult.SensitiveData = sensitivePatternsFound

		// 1. 如果替换响应中包含敏感数据，分析是否是真正的越权
		if len(sensitivePatternsFound) > 0 {
			// 检查敏感数据是否在原始响应和替换响应中都存在
			if len(originalSensitiveData) > 0 {
				// 计算两个敏感数据集的交集
				commonSensitiveData := 0
				sensitiveDiffs := []string{}

				// 简单比较：检查替换响应中的每个敏感数据是否存在于原始响应中
				for _, replacement := range sensitivePatternsFound {
					found := false
					for _, original := range originalSensitiveData {
						if replacement == original {
							found = true
							commonSensitiveData++
							break
						}
					}
					if !found {
						sensitiveDiffs = append(sensitiveDiffs, replacement)
					}
				}

				//// 如果有不同的敏感数据 - 这是真正的越权
				//if len(sensitiveDiffs) == 0 {
				//	utils.Info("[越权检测] 检测到替换请求获取了相同的敏感数据: %v", sensitiveDiffs)
				//	vulnResult.Result = "true"
				//	vulnResult.Reason = fmt.Sprintf("替换请求获取了相同的敏感数据: %s", strings.Join(sensitiveDiffs[:min(3, len(sensitiveDiffs))], ", "))
				//	return vulnResult, nil
				//}

				// 如果两者完全相同，可能是公开数据
				if len(sensitivePatternsFound) > 0 && commonSensitiveData == len(sensitivePatternsFound) && commonSensitiveData == len(originalSensitiveData) {
					utils.Info("[越权检测] 替换请求获取到与原始响应完全相同的敏感数据，可能是公开数据")

					// 继续使用相似度判断
					similarityScore := calculateResponseSimilarity(respAStr, respBStr)
					utils.Info("[越权检测] 响应体相似度: %.2f", similarityScore)

					if similarityScore >= conf.PrivilegeEscalationScan.SimilarityThreshold {
						// 标记为需人工确认，因为敏感数据完全相同
						vulnResult.Result = "true"
						vulnResult.Reason = fmt.Sprintf("替换请求返回相同敏感数据且响应相似度高 (%.2f >= %.2f)，可能是公开API或存在越权，请人工确认",
							similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold)
					} else {
						vulnResult.Result = "unknown"
						vulnResult.Reason = "替换请求获取了相同的敏感数据，但响应整体不相似，请人工确认"
					}
					return vulnResult, nil
				}
			} else {
				// 原始响应中没有敏感数据，但替换响应有 - 很可能是不同的数据
				utils.Info("[越权检测] 原始响应无敏感数据，替换请求获取了敏感数据: %v", sensitivePatternsFound)
				vulnResult.Result = "unknown"
				vulnResult.Reason = fmt.Sprintf("替换请求获取了敏感数据，而原始请求没有: %s", strings.Join(sensitivePatternsFound[:min(3, len(sensitivePatternsFound))], ", "))
				return vulnResult, nil
			}
		}

		// 2. 使用AI分析两个响应的异同，判断是否存在越权[对于特殊情况进行兜底，包括越权删除、修改、添加等，不基于敏感数据评定的越权]
		utils.Info("[越权检测] 使用AI分析两个响应是否存在越权")

		// 获取AI分析配置
		aiType := conf.AI
		var apiUrl string
		var apiKey string

		// 设置API URL和Key
		switch aiType {
		case "deepseek":
			apiUrl = "https://api.deepseek.com/v1/chat/completions"
			apiKey = conf.APIKeys.DeepSeek
		case "kimi":
			apiUrl = "https://api.moonshot.cn/v1/chat/completions"
			apiKey = conf.APIKeys.Kimi
		case "qianwen":
			apiUrl = "https://api.qianwen.com/v1/chat/completions"
			apiKey = conf.APIKeys.Qianwen
		case "gpt":
			apiUrl = "https://api.openai.com/v1/chat/completions"
			apiKey = conf.APIKeys.Gpt
		case "glm":
			apiUrl = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
			apiKey = conf.APIKeys.Glm
		default:
			// 默认使用 deepseek
			apiUrl = "https://api.deepseek.com/v1/chat/completions"
			apiKey = conf.APIKeys.DeepSeek
			aiType = "deepseek"
		}

		// 获取模型名称
		modelName := aiapis.GetModelNameByAIType(aiType)

		// 调用AI分析
		aiResult, err := aiapis.AIScan(
			modelName,
			apiUrl,
			apiKey,
			vulnResult.RequestA,
			vulnResult.RespBodyA,
			vulnResult.RespBodyB,
			fmt.Sprintf("%d", respB.StatusCode),
		)

		if err != nil {
			utils.Warning("[越权检测] AI分析失败: %v", err)
			// AI分析失败，使用备选方法：检查响应体相似度
			similarityScore := calculateResponseSimilarity(string(respA.Body), string(respBBody))
			utils.Info("[越权检测] 响应体相似度: %.2f", similarityScore)

			if similarityScore >= conf.PrivilegeEscalationScan.SimilarityThreshold {
				// 检查是否有敏感数据
				hasSensitiveData := len(vulnResult.SensitiveData) > 0

				if hasSensitiveData {
					// 有敏感数据，直接判定为真
					vulnResult.Result = "true"
					vulnResult.Reason = fmt.Sprintf("替换请求响应与原始响应相似度较高 (%.2f >= %.2f)且包含敏感数据，可能存在越权访问",
						similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold)
				} else {
					// 没有敏感数据，标记为需人工确认
					vulnResult.Result = "unknown"
					vulnResult.Reason = fmt.Sprintf("替换请求响应与原始响应相似度较高 (%.2f >= %.2f)但未发现敏感数据，请人工确认",
						similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold)
				}
			} else {
				vulnResult.Result = "unknown"
				vulnResult.Reason = fmt.Sprintf("AI分析失败，响应体相似度不足以确定: %.2f < %.2f",
					similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold)
			}
		} else {
			// 解析AI返回的结果
			var aiResponse struct {
				Res    string `json:"res"`
				Reason string `json:"reason"`
			}

			// 首先尝试直接解析
			err = json.Unmarshal([]byte(aiResult), &aiResponse)
			if err != nil {
				utils.Warning("[越权检测] 解析AI返回结果失败: %v, 原始数据: %s", err, aiResult)
				// 为了调试，记录更详细的AI响应内容
				utils.Error("[越权检测] AI响应详细内容 (前500字符): %s", trimString(aiResult, 500))
				utils.Error("[越权检测] 字符代码检查 (前100字符):")
				for i, c := range aiResult {
					if i >= 100 {
						break
					}
					utils.Error("  字符位置[%d]: '%c' (ASCII: %d, 十六进制: %X)", i, c, c, c)
					if c == '`' || c == '"' || c == '\\' {
						utils.Error("  *** 可能问题字符 at %d: '%c' ***", i, c)
					}
				}

				// 尝试手动解析
				success := false

				// 方法1: 尝试以"json"开头的情况
				if strings.HasPrefix(strings.TrimSpace(aiResult), "json") {
					jsonStartIndex := strings.Index(aiResult, "{")
					if jsonStartIndex > 0 {
						utils.Debug("[越权检测] 检测到json前缀，尝试从位置%d开始解析", jsonStartIndex)
						jsonPart := aiResult[jsonStartIndex:]

						err2 := json.Unmarshal([]byte(jsonPart), &aiResponse)
						if err2 == nil {
							utils.Info("[越权检测] JSON前缀处理后解析成功")
							success = true
						} else {
							utils.Warning("[越权检测] JSON前缀处理后仍解析失败: %v", err2)
						}
					}
				}

				// 方法2: 使用正则表达式提取关键信息
				if !success {
					resPattern := regexp.MustCompile(`"res"\s*:\s*"([^"]+)"`)
					reasonPattern := regexp.MustCompile(`"reason"\s*:\s*"([^"]+)"`)

					resMatches := resPattern.FindStringSubmatch(aiResult)
					reasonMatches := reasonPattern.FindStringSubmatch(aiResult)

					if len(resMatches) > 1 && len(reasonMatches) > 1 {
						utils.Debug("[越权检测] 通过正则表达式提取结果")
						aiResponse.Res = resMatches[1]
						aiResponse.Reason = reasonMatches[1]
						success = true
					}
				}

				// 方法3: 尝试去除特殊字符后重新解析
				if !success {
					utils.Debug("[越权检测] 尝试清理特殊字符后重新解析")
					cleanedResult := strings.Replace(aiResult, "`", "", -1)
					cleanedResult = strings.Replace(cleanedResult, "\"\"", "\"", -1)

					// 尝试找到并只保留JSON对象部分
					jsonStartIndex := strings.Index(cleanedResult, "{")
					jsonEndIndex := strings.LastIndex(cleanedResult, "}")

					if jsonStartIndex >= 0 && jsonEndIndex > jsonStartIndex {
						jsonPart := cleanedResult[jsonStartIndex : jsonEndIndex+1]
						utils.Debug("[越权检测] 提取JSON部分: %s", trimString(jsonPart, 100))

						err2 := json.Unmarshal([]byte(jsonPart), &aiResponse)
						if err2 == nil {
							utils.Info("[越权检测] 清理后成功解析JSON部分")
							success = true
						}
					}
				}

				if success {
					utils.Info("[越权检测] 通过替代方法解析AI结果: %s, 原因: %s", aiResponse.Res, aiResponse.Reason)
					vulnResult.Result = aiResponse.Res
					vulnResult.Reason = aiResponse.Reason
				} else {
					vulnResult.Result = "unknown"
					vulnResult.Reason = "AI分析结果解析失败: " + err.Error()
				}
			} else {
				utils.Info("[越权检测] AI分析结果: %s, 原因: %s", aiResponse.Res, aiResponse.Reason)
				vulnResult.Result = aiResponse.Res
				vulnResult.Reason = aiResponse.Reason
			}
		}
	} else {
		// 处理非2xx状态码
		vulnResult.Result = "unknown"
		vulnResult.Reason = fmt.Sprintf("替换请求返回非标准状态码: %d", respB.StatusCode)
	}

	// 记录检测结果
	utils.Info("[越权检测] 完成检测: URL=%s, 结果=%s, 原因=%s",
		r.Request.URL.String(), vulnResult.Result, vulnResult.Reason)

	return vulnResult, nil
}

// 计算响应体相似度的辅助函数
func calculateResponseSimilarity(respA, respB string) float64 {
	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		utils.Warning("[相似度计算] 配置对象为空")
		return 0.0
	}

	// 首先检查respB是否包含错误信息的特征
	for _, errorPattern := range conf.RespBodyBWhiteList {
		if strings.Contains(respB, errorPattern) {
			utils.Info("[相似度计算] 替换请求响应包含错误信息: %s", errorPattern)
			return 0.0 // 如果响应包含错误信息，直接返回低相似度
		}
	}

	// 检查JSON结构中的错误标志
	var jsonB interface{}
	if err := json.Unmarshal([]byte(respB), &jsonB); err == nil {
		// 成功解析为JSON
		if mapB, ok := jsonB.(map[string]interface{}); ok {
			// 检查常见的错误指示字段
			if isSuccess, exists := mapB["isSuccess"]; exists {
				if success, ok := isSuccess.(bool); ok && !success {
					utils.Info("[相似度计算] 响应JSON包含失败标志: isSuccess=false")
					return 0.0
				}
			}

			// 检查空数组或空对象
			if passengerList, exists := mapB["passengerList"]; exists {
				if list, ok := passengerList.([]interface{}); ok && len(list) == 0 {
					utils.Info("[相似度计算] 响应包含空数组: passengerList=[]")
					return 0.0
				}
			}

			// 检查error相关字段
			for key := range mapB {
				if strings.Contains(strings.ToLower(key), "error") ||
					strings.Contains(strings.ToLower(key), "err") ||
					strings.Contains(strings.ToLower(key), "msg") ||
					strings.Contains(strings.ToLower(key), "message") {
					utils.Info("[相似度计算] 响应JSON包含错误相关字段: %s", key)
					return 0.0
				}
			}
		}
	}

	// 检查respB是否与respA有显著不同的长度 (如果差异超过80%，视为不相似)
	if math.Abs(float64(len(respA)-len(respB)))/float64(max(len(respA), len(respB))) > 0.8 {
		utils.Info("[相似度计算] 响应长度差异显著: 原始=%d, 替换=%d", len(respA), len(respB))
		return 0.0
	}

	// 使用编辑距离计算相似度
	// 简单实现：计算编辑距离的归一化相似度
	maxLen := max(len(respA), len(respB))
	if maxLen == 0 {
		return 1.0 // 两个都是空字符串
	}

	// 计算编辑距离
	distance := levenshteinDistance(respA, respB)

	// 归一化为相似度 (1 - 距离/最大长度)
	similarity := 1.0 - float64(distance)/float64(maxLen)
	return similarity
}

// 计算Levenshtein距离的函数
func levenshteinDistance(s1, s2 string) int {
	// 如果某个字符串长度过长，使用子串进行计算
	// 这主要是为了性能考虑
	maxLength := 1000
	if len(s1) > maxLength || len(s2) > maxLength {
		s1 = s1[:min(len(s1), maxLength)]
		s2 = s2[:min(len(s2), maxLength)]
	}

	// 常规的动态规划算法计算编辑距离
	m, n := len(s1), len(s2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 0; i <= m; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = j
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			dp[i][j] = min(
				dp[i-1][j]+1, // 删除
				min(dp[i][j-1]+1, // 插入
					dp[i-1][j-1]+cost), // 替换
			)
		}
	}

	return dp[m][n]
}

// 添加formatRequest函数，用于格式化请求
func formatRequest(req *http.Request) string {
	if req == nil {
		return ""
	}

	// 格式化请求行
	requestLine := fmt.Sprintf("%s %s HTTP/%s",
		req.Method,
		req.URL.String(),
		req.Proto)

	// 添加请求头
	headers := formatHeaders(req.Header)

	// 完整的请求
	fullRequest := requestLine + "\n" + headers

	// 如果有请求体，添加
	if req.Body != nil {
		// 由于Body可能已经被读取，这里不尝试读取Body
		fullRequest += "\n<请求体已被读取，无法显示>"
	}

	return fullRequest
}

// trimString 截取字符串到指定长度并添加省略号
func trimString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength] + "..."
}
