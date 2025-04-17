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
	"unicode/utf8"
	"yuequanScan/AIAPIS"
	"yuequanScan/config"
	"yuequanScan/utils"
	"yuequanScan/types"
	_ "yuequanScan/similarity"
	

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// 漏洞类型
type VulnType string

const (
	VulnPrivilegeEscalation VulnType = "privilege_escalation" // 越权漏洞
	VulnUnauthorizedAccess  VulnType = "unauthorized_access"  // 未授权访问漏洞
	VulnSensitiveDataLeak   VulnType = "sensitive_data_leak"  // 敏感数据泄露漏洞
	VulnSqlInjection        VulnType = "sql_injection"        // SQL注入漏洞
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
	// ... existing variables ...
	whitelistDomains       = make(map[string]bool)
	whitelistMutex         sync.RWMutex
	completedRequestsMap   = make(map[string]*types.RequestResponseLog)
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
				if req, ok := value.(*types.RequestResponseLog); ok && req.Request != nil && req.Request.URL != nil {
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
		rr, ok := value.(*types.RequestResponseLog)
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

		// 获取主机名
		hostname := rr.Request.URL.Host
		if hostname == "" {
			utils.Warning("[请求处理] 无法获取hostname: %v", key)
			return true
		}

		// 检查是否在白名单中
		utils.Info("[白名单检查] 检查域名: %s", hostname)
		if !IsWhitelisted(hostname) {
			utils.Info("[白名单检查] 域名 %s 不在白名单中，跳过处理", hostname)
			skipped++
			rr.Processed = true
			return true
		}

		// 检查是否是静态资源
		if !isNotSuffix(rr.Request.URL.Path, conf.Suffixes) {
			utils.Info("命中静态资源文件，不处理")
			static++
			rr.Processed = true
			return true
		}

		// 检查是否在排除路径中
		if isExcludedPath(rr.Request.URL.String(), conf.UnauthorizedScan.ExcludePatterns) {
			utils.Info("命中排出路径，不处理")
			filtered++
			rr.Processed = true
			return true
		}

		// 检查响应内容类型是否在允许处理的类型列表中
		if rr.Response != nil && rr.Response.Header != nil {
			contentType := rr.Response.Header.Get("Content-Type")
			for _, allowedType := range conf.AllowedRespHeaders {
				if strings.Contains(contentType, allowedType) {
					utils.Info("命中不允许的响应类型，不处理")
					filtered++
					rr.Processed = true
					return true
				}
			}
		}

		processed++
		return true
	})

	utils.Info("[请求处理] 处理完成 - 已处理: %d, 已跳过: %d", processed, skipped)
	return processed, skipped, filtered, static
}

// isExcludedPath 检查URL是否在排除列表中
func isExcludedPath(url string, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		if strings.Contains(strings.ToLower(url), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// cloneRequest 克隆请求
func cloneRequest(r *proxy.Request) (*http.Request, error) {
	if r == nil {
		utils.Error("[请求克隆] 无法克隆空请求")
		return nil, fmt.Errorf("无法克隆空请求")
	}

	// 解析URL
	parsedURL, err := url.Parse(r.URL.String())
	if err != nil {
		utils.Error("[请求克隆] 解析URL失败: %v", err)
		return nil, err
	}

	// 创建新的请求体
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}

	// 创建新的请求
	req, err := http.NewRequest(r.Method, parsedURL.String(), body)
	if err != nil {
		utils.Error("[请求克隆] 创建请求对象失败: %v", err)
		return nil, err
	}

	// 复制头部
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 设置Host和协议
	req.Host = r.URL.Host
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	// 打印调试信息
	utils.Debug("[请求克隆] 原始请求详情:")
	utils.Debug("  - 方法: %s", r.Method)
	utils.Debug("  - URL: %s", r.URL.String())
	utils.Debug("  - 协议: %s", r.Proto)
	utils.Debug("  - 请求头数量: %d", len(r.Header))

	for key, values := range r.Header {
		utils.Debug("[请求克隆] 原始请求头: %s = %v", key, values)
	}

	utils.Debug("[请求克隆] 克隆后请求头数量: %d", len(req.Header))
	for key, values := range req.Header {
		utils.Debug("[请求克隆] 克隆后请求头: %s = %v", key, values)
	}

	return req, nil
}

// detectUnauthorizedAccess 检测未授权访问漏洞
func detectUnauthorizedAccess(r *types.RequestResponseLog) (*types.Result, error) {
	// 如果配置不存在，跳过检测
	if conf == nil {
		return nil, fmt.Errorf("配置不存在")
	}

	// 如果未启用未授权扫描，则跳过
	if !conf.UnauthorizedScan.Enabled {
		return nil, fmt.Errorf("未启用未授权扫描")
	}

	utils.Info("[未授权检测] 开始检测请求: %s %s", r.Request.Method, r.Request.URL.String())

	// 记录请求开始时间
	startTime := time.Now()

	// 检查请求是否为GET/HEAD/OPTIONS/POST等方法
	// 其他方法如PUT/DELETE等可能会修改数据，不检测
	allowedMethods := []string{"GET", "HEAD", "OPTIONS", "POST"}
	if !contains(allowedMethods, r.Request.Method) {
		return nil, fmt.Errorf("不支持的HTTP方法: %s", r.Request.Method)
	}

	// 如果原始请求没有授权相关头部，跳过检测
	hasAuthHeader := false
	for _, key := range conf.UnauthorizedScan.RemoveHeaders {
		if len(r.Request.Header.Values(key)) > 0 {
			hasAuthHeader = true
			break
		}
	}

	if !hasAuthHeader {
		return nil, fmt.Errorf("请求没有包含授权头，跳过检测")
	}

	// 获取请求的主机、协议等信息
	proto := "HTTP/1.1"
	host := r.Request.URL.Host

	utils.Debug("[未授权检测] 原始请求详情:")
	utils.Debug("  - 方法: %s", r.Request.Method)
	utils.Debug("  - URL: %s", r.Request.URL.String())
	utils.Debug("  - 协议: %s", proto)
	utils.Debug("  - Host: %s", host)
	utils.Debug("  - 请求头数量: %d", len(r.Request.Header))

	// 克隆原始请求，移除授权头
	req2, err := cloneRequest(r.Request)
	if err != nil {
		utils.Warning("[未授权检测] 无法克隆请求，跳过检测")
		return nil, fmt.Errorf("无法克隆请求: %v", err)
	}

	// 从请求头中移除授权相关的头部
	for _, header := range conf.UnauthorizedScan.RemoveHeaders {
		if header == "" {
			continue
		}
		
		if len(req2.Header.Values(header)) > 0 {
			req2.Header.Del(header)
		}
	}

	// 如果未在配置中定义RemoveHeaders，使用默认的授权头
	if len(conf.UnauthorizedScan.RemoveHeaders) == 0 {
		utils.Debug("[未授权检测] 配置中未定义RemoveHeaders，使用默认授权头列表")

		defaultAuthHeaders := []string{
			"Authorization", "Cookie", "Token", "Jwt", 
			"X-Auth-Token", "X-Csrf-Token", "Sectoken",
			"Usertoken", "X-Api-Key",
		}

		for _, header := range defaultAuthHeaders {
			if len(req2.Header.Values(header)) > 0 {
				req2.Header.Del(header)
			}
		}
	} else if conf == nil {
		utils.Debug("[未授权检测] 配置对象为空，使用默认授权头列表")

		// 默认的授权头列表
		defaultAuthHeaders := []string{
			"Authorization", "Cookie", "Token", "Jwt", 
			"X-Auth-Token", "X-Csrf-Token",
		}

		for _, header := range defaultAuthHeaders {
			if len(req2.Header.Values(header)) > 0 {
				req2.Header.Del(header)
			}
		}
	}

	// 记录生成的请求信息
	req1 = r.Request.URL.String()
	utils.Debug("[未授权检测] 未授权请求详情:")
	utils.Debug("  - 方法: %s", req2.Method)
	utils.Debug("  - URL: %s", req2.URL.String())
	utils.Debug("  - 协议: %s", req2.Proto)
	utils.Debug("  - 请求头数量: %d", len(req2.Header))

	// 创建HTTP客户端对象
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过证书验证，用于测试
			},
		},
		Timeout: time.Duration(conf.Performance.RequestTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 限制重定向次数
			if len(via) >= 10 {
				return fmt.Errorf("停止跟随重定向，重定向次数超过10次")
			}
			return nil
		},
	}

	// 输出更多调试信息
	utils.Debug("[未授权检测] 准备发送未授权请求:")
	utils.Debug("  - 方法: %s", req2.Method)
	utils.Debug("  - URL: %s", req2.URL.String())
	utils.Debug("  - 请求头数量: %d", len(req2.Header))

	// 打印请求头
	for key, values := range req2.Header {
		utils.Debug("[未授权检测] 请求头: %s = %v", key, values)
	}

	// 发送未授权请求
	resp, err := client.Do(req2)
	if err != nil {
		utils.Warning("[未授权检测] 发送未授权请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应体
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Warning("[未授权检测] 读取响应体失败: %v", err)
		return nil, err
	}

	// 处理可能的编码问题
	respBodyStr := string(respBodyBytes)
	contentType := resp.Header.Get("Content-Type")

	// 特殊处理: 如果请求是application/x-www-form-urlencoded但响应是JSON
	if strings.Contains(contentType, "application/json") {
		utils.Debug("[未授权检测] 检测到application/x-www-form-urlencoded请求但返回JSON响应，处理编码")
	}

	// 检测和转换非UTF-8编码（如GBK）
	if !utf8.ValidString(respBodyStr) {
		utils.Warning("[未授权检测] 检测到非UTF-8编码的JSON响应，尝试转换")
		// 尝试GBK转UTF-8
		gbkDecoder := simplifiedchinese.GBK.NewDecoder()
		utf8Bytes, err := gbkDecoder.Bytes(respBodyBytes)
		if err == nil {
			respBodyStr = string(utf8Bytes)
			utils.Info("[未授权检测] 成功将响应体从GBK转换为UTF-8")
		}
	}

	// 创建结果对象
	result := &types.Result{
		Method:     r.Request.Method,
		Url:        r.Request.URL.String(),
		RequestA:   formatRequest(req2),
		HeaderA:    formatHeaders(r.Request.Header),
		HeaderB:    formatHeaders(req2.Header),
		RespBodyB:  respBodyStr,
		Result:     "false", // 默认结果为false，后面会根据分析修改
		VulnType:   string(types.VulnUnauthorizedAccess),
		ScanTime:   time.Now().Format("2006-01-02 15:04:05"),
		Similarity: 0.0,
	}

	// 检查响应体是否包含敏感数据
	var sensitiveMatches []string
	
	// 寻找敏感数据
	if conf != nil && conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
		sensitiveMatches = detectSensitiveDataWithDetails(respBodyStr, conf.UnauthorizedScan.SensitiveDataPatterns.PatternMap)
		if len(sensitiveMatches) > 0 {
			result.SensitiveData = sensitiveMatches
			utils.Info("[未授权检测] 在未授权响应中发现敏感数据: %d 处", len(sensitiveMatches))
		}
	}

	// 计算置信度分数
	confidenceScore, appliedRules := calculateConfidenceScore(r, respBodyBytes, resp)
	
	// 修改结果
	if confidenceScore >= conf.UnauthorizedScan.HighConfidenceScore {
		result.Result = "true"
		result.Reason = fmt.Sprintf("高可信度未授权访问，分数: %d", confidenceScore)
	} else if confidenceScore >= conf.UnauthorizedScan.MediumConfidenceScore {
		result.Result = "true"
		result.Reason = fmt.Sprintf("中等可信度未授权访问，分数: %d", confidenceScore)
	} else if confidenceScore >= conf.UnauthorizedScan.LowConfidenceScore {
		result.Result = "unknown"
		result.Reason = fmt.Sprintf("低可信度未授权访问，分数: %d", confidenceScore)
	} else {
		result.Result = "false"
		result.Reason = fmt.Sprintf("未检测到未授权访问，分数: %d", confidenceScore)
	}

	utils.Info("[未授权检测] 检测完成: URL=%s, 结果=%s, 分数=%d, 原因=%v",
		r.Request.URL.String(), result.Result, confidenceScore, appliedRules)

	return result, nil
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
		utils.Warning("[正则调试输出] name : %s -> pattern : %s", name, patternStr)
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
func calculateConfidenceScore(r *types.RequestResponseLog, respBody []byte, resp *http.Response) (int, []string) {
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
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
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

// processHighPriorityRequests 处理高优先级请求
func processHighPriorityRequests() {
	// 优先处理需要先认证的请求
	logs.Range(func(key, value interface{}) bool {
		// 跳过正在处理的请求
		if isProcessing, ok := processingFlag.Load(key); ok && isProcessing.(bool) {
			return true
		}

		r, ok := value.(*types.RequestResponseLog)
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
		isHighPriority := strings.Contains(path, "/auth") ||
			strings.Contains(path, "/token") ||
			strings.Contains(path, "/user") ||
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

				// 获取配置
				conf := config.GetConfig()

				// 执行未授权访问检测 (如果已启用)
				var unauthorizedResult *types.Result
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

		r, ok := value.(*types.RequestResponseLog)
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
				var unauthorizedResult *types.Result
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
		r, ok := value.(*types.RequestResponseLog)
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
		r, ok := value.(*types.RequestResponseLog)
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

// detectPrivilegeEscalation 执行越权检测
func detectPrivilegeEscalation(r *types.RequestResponseLog) (*types.Result, error) {
	if r == nil || r.Request == nil || r.Response == nil {
		utils.Warning("[越权检测] 请求/响应为空, 跳过越权检测")
		return nil, fmt.Errorf("请求或响应为空")
	}

	// 创建结果对象
	vulnResult := &types.Result{
		Method:   r.Request.Method,
		Url:      r.Request.URL.String(),
		VulnType: string(types.VulnPrivilegeEscalation),
		Result:   "unknown",
	}

	// 检查配置是否已加载
	if conf == nil {
		utils.Warning("[越权检测] 配置为空, 跳过检测")
		return nil, fmt.Errorf("配置为空")
	}

	// 检查是否启用越权扫描
	if !conf.PrivilegeEscalationScan.Enabled {
		utils.Warning("[越权检测] 越权扫描未启用，跳过检测")
		return nil, fmt.Errorf("越权扫描未启用")
	}

	// 检查请求路径是否包含潜在参数模式
	hasPrivilegePattern := false
	matchedParam := ""

	// 如果配置了参数模式且启用了参数匹配
	if len(conf.PrivilegeEscalationScan.ParamPatterns) > 0 {
		for _, pattern := range conf.PrivilegeEscalationScan.ParamPatterns {
			re, err := regexp.Compile(pattern)
			utils.Debug("[越权检测] 正则表达式：%s", pattern)
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

		// 如果配置了参数模式但请求中不包含匹配的参数，则跳过测试
		if !hasPrivilegePattern {
			utils.Debug("[越权检测] 请求不包含需要检测的越权参数模式: %s", r.Request.URL.String())
			return nil, fmt.Errorf("请求不包含需要检测的越权参数模式")
		}
	} else {
		utils.Debug("[越权检测] 未配置参数模式，将检测所有请求")
	}

	// 使用AI分析越权
	aiResult := ""
	
	// 获取AI模型
	modelName := AIAPIS.GetModelNameByAIType(conf.AI)
	aiURL := GetAPIURLByAIType(conf.AI) // 根据AI类型获取API URL
	apiKey := conf.APIKeys[conf.AI]     // 从配置中获取API密钥

	// 格式化请求数据
	reqA := formatRequest(r.Request)
	respA := string(r.Response.Body)
	respBStr := respA // 初始化为相同值，后续会修改

	respStatusB := "200 OK" // 默认状态码

	if respA == "" {
		utils.Warning("[越权检测] 原始响应体为空")
		vulnResult.Result = "unknown"
		vulnResult.Reason = "原始响应体为空，无法进行分析"
		return vulnResult, nil
	}

	// 开始AI分析
	if modelName != "" && aiURL != "" && apiKey != "" {
		// 调用AI进行分析
		aiResult, err := AIAPIS.AIScan(modelName, aiURL, apiKey, reqA, respA, respBStr, respStatusB)
		if err != nil {
			utils.Warning("[越权检测] AI分析失败: %v", err)
			vulnResult.Result = "unknown"
			vulnResult.Reason = fmt.Sprintf("AI分析失败: %v", err)
			return vulnResult, nil
		}

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
				// 查找是否有"true"或"false"的结果
				resultRe := regexp.MustCompile(`"res"\s*:\s*"(true|false|unknown)"`)
				reasonRe := regexp.MustCompile(`"reason"\s*:\s*"([^"]*)"`)

				resultMatches := resultRe.FindStringSubmatch(aiResult)
				reasonMatches := reasonRe.FindStringSubmatch(aiResult)

				if len(resultMatches) > 1 {
					aiResponse.Res = resultMatches[1]
					if len(reasonMatches) > 1 {
						aiResponse.Reason = reasonMatches[1]
					} else {
						aiResponse.Reason = "无法解析原因"
					}
					utils.Info("[越权检测] 使用正则表达式成功提取结果: %s", aiResponse.Res)
					success = true
				}
			}

			// 方法3: 使用简单字符串检查
			if !success {
				if strings.Contains(aiResult, `"res":"true"`) || strings.Contains(aiResult, `"res": "true"`) {
					aiResponse.Res = "true"
					utils.Info("[越权检测] 使用字符串匹配提取到结果: true")
					success = true
				} else if strings.Contains(aiResult, `"res":"false"`) || strings.Contains(aiResult, `"res": "false"`) {
					aiResponse.Res = "false"
					utils.Info("[越权检测] 使用字符串匹配提取到结果: false")
					success = true
				} else if strings.Contains(aiResult, `"res":"unknown"`) || strings.Contains(aiResult, `"res": "unknown"`) {
					aiResponse.Res = "unknown"
					utils.Info("[越权检测] 使用字符串匹配提取到结果: unknown")
					success = true
				}

				// 尝试提取原因
				if success {
					reasonStart := strings.Index(aiResult, `"reason":"`)
					if reasonStart > 0 {
						reasonStart += 10 // 跳过 "reason":"
						reasonEnd := strings.Index(aiResult[reasonStart:], `"`)
						if reasonEnd > 0 {
							aiResponse.Reason = aiResult[reasonStart : reasonStart+reasonEnd]
							utils.Info("[越权检测] 使用字符串匹配提取到原因: %s", aiResponse.Reason)
						}
					}
				}
			}

			// 如果仍然无法解析，使用默认值
			if !success {
				utils.Warning("[越权检测] 所有解析方法均失败，使用默认值")
				aiResponse.Res = "unknown"
				aiResponse.Reason = "AI响应解析失败"
			}
		}

		// 设置结果
		vulnResult.Result = aiResponse.Res
		vulnResult.Reason = aiResponse.Reason

		// 添加详细说明
		utils.Info("[越权检测] AI分析结果: %s, 原因: %s", aiResponse.Res, aiResponse.Reason)
	} else {
		// AI分析不可用，执行本地规则判断
		utils.Warning("[越权检测] AI分析未启用或配置不完整，使用本地规则")

		// 本地规则逻辑...
		if len(matchedParam) > 0 {
			vulnResult.Result = "unknown"
			vulnResult.Reason = fmt.Sprintf("找到可能的越权参数 %s，但无法确定是否存在漏洞", matchedParam)
		} else {
			vulnResult.Result = "false"
			vulnResult.Reason = "未找到可能的越权参数"
		}
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
// detectSqlInjection 执行SQL注入检测
func detectSqlInjection(r *types.RequestResponseLog) (*types.Result, error) {
	// 创建结果对象
	vulnResult := &types.Result{
		VulnType: string(types.VulnSqlInjection),
		Result:   "false", // 默认为未发现漏洞
	}

	if r == nil || r.Request == nil || r.Response == nil {
		utils.Warning("[SQL注入检测] 请求或响应为空，跳过检测")
		return nil, fmt.Errorf("请求或响应为空")
	}

	// 设置基本信息
	vulnResult.Method = r.Request.Method
	vulnResult.Url = r.Request.URL.String()

	// 检查是否启用SQL注入扫描
	if conf == nil || !conf.SqlInjectionScan.Enabled {
		utils.Warning("[SQL注入检测] SQL注入扫描未启用，跳过检测")
		return nil, fmt.Errorf("SQL注入扫描未启用")
	}

	// 敏感响应特征
	sqlErrorPatterns := []string{
		`SQL syntax.*?MySQL`, `Warning.*?\\Wmysqli?_`, `MySQLSyntaxErrorException`,
		`valid MySQL result`, `check the manual that (corresponds to|fits) your MySQL server version`,
		`Unknown column '[^']+' in 'field list'`, `MySqlClient\\.", "MySQL server version for the right syntax to use`,
		`com\\.mysql\\.jdbc`, `Zend_Db_(Adapter|Statement)_Mysqli_Exception`,
		`Syntax error or access violation`, `Unclosed quotation mark after the character string`,
		`Incorrect syntax near`, `ODBC SQL Server Driver`, `SQLServer JDBC Driver`, `getConnection`,
		`SQLServerException`, `Unclosed quotation mark after the character string`,
		`ODBC SQL Server Driver`, `Microsoft SQL Native Client`, `Microsoft OLE DB Provider for SQL Server`,
		`Microsoft OLE DB Provider for Oracle`, `Oracle error`, `ORA-[0-9][0-9][0-9][0-9]`,
		`quoted string not properly terminated`, `DG4ODBC`, `Error ORA-`, `SQL ERROR`,
		`Syntax error:.*?at line`, `Incorrect syntax near`, `Syntax error.*?in query expression`,
		`PostgreSQL.*?ERROR`, `Warning.*?\\Wpg_`, `valid PostgreSQL result`,
		`Npgsql\\.`, `PG::SyntaxError:`, `org\\.postgresql\\.util\\.PSQLException`,
		`ERROR:\\s\\ssyntax error at or near`, `ERROR: parser: parse error at or near`,
		`SQLite/JDBCDriver`, `SQLite\\.Exception`, `System\\.Data\\.SQLite\\.SQLiteException`,
		`Warning.*?\\W(sqlite_|SQLite3::)`, `\\[SQLITE_ERROR\\]`,
		`SQL error.*?ORA-[0-9]+`, `Oracle error`, `Oracle.*?Driver`, `Warning.*?\\Woci_`,
		`Warning.*?\\Wora_`, `DB2 SQL error`, `Syntax error.*?DB2`,
		`Warning.*?IBM_DB2`, `Warning.*?DB2`, `Ingres SQLSTATE`, `Ingres\\W.*?Driver`,
		`Warning.*?ingres_`, `Syntax error.*?Ingres`, `Microsoft Access Driver`,
		`Access Database Engine`, `Microsoft JET Database Engine`,
		`ODBC Microsoft Access`, `Syntax error \\(missing operator\\) in query expression`}

	// 匹配是否包含SQL错误
	originalRespBody := string(r.Response.Body)
	originalStatusCode := r.Response.StatusCode

	// 记录原始响应信息(用于调试)
	utils.Debug("[SQL注入检测] 原始响应状态码: %d, 内容长度: %d", originalStatusCode, len(originalRespBody))

	// 检查原始响应是否已经包含SQL错误信息
	for _, pattern := range sqlErrorPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			utils.Warning("[SQL注入检测] 编译SQL错误模式失败: %v", err)
			continue
		}

		if re.MatchString(originalRespBody) {
			utils.Warning("[SQL注入检测] 原始响应已包含SQL错误信息，跳过测试: %s", pattern)
			vulnResult.Result = "unknown"
			vulnResult.Reason = "原始响应已包含SQL错误信息，请人工确认是否存在SQL注入"
			return vulnResult, nil
		}
	}

	// 获取要测试的参数
	paramsToTest := make(map[string]string)
	valueToTest := []string{"'", "\"", "\\", "--", "#", "1=1", "1=2", "' OR '1'='1", "' AND '1'='2", "'; --", "\" OR \"1\"=\"1", "\" AND \"1\"=\"2", "\"; --"}

	// 提取URL查询参数
	querys := r.Request.URL.Query()
	for key, values := range querys {
		if len(values) > 0 {
			paramsToTest[key] = values[0]
		}
	}

	// 提取请求体参数
	if len(r.Request.Body) > 0 {
		// 尝试解析不同格式的请求体
		requestBody := string(r.Request.Body)

		// 解析JSON格式
		var jsonMap map[string]interface{}
		if err := json.Unmarshal([]byte(requestBody), &jsonMap); err == nil {
			// 成功解析为JSON，提取参数
			for key, value := range jsonMap {
				switch v := value.(type) {
				case string:
					paramsToTest[key] = v
				case float64, int, bool:
					paramsToTest[key] = fmt.Sprintf("%v", v)
				}
			}
		} else {
			// 尝试解析为表单格式
			values, err := url.ParseQuery(requestBody)
			if err == nil {
				for key, vals := range values {
					if len(vals) > 0 {
						paramsToTest[key] = vals[0]
					}
				}
			} else {
				// 无法解析，直接记录整个请求体
				utils.Debug("[SQL注入检测] 无法解析请求体: %s", requestBody)
			}
		}
	}

	// 没有参数可测试，跳过
	if len(paramsToTest) == 0 {
		utils.Info("[SQL注入检测] 未找到可测试的参数，跳过: %s", r.Request.URL.String())
		return nil, fmt.Errorf("未找到可测试的参数")
	}

	utils.Info("[SQL注入检测] 找到 %d 个参数可测试", len(paramsToTest))

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: time.Duration(conf.Performance.ScanTimeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不自动跟随重定向
		},
	}

	// 实际测试开始
	for paramKey, paramValue := range paramsToTest {
		utils.Debug("[SQL注入检测] 测试参数 %s=%s", paramKey, paramValue)

		// 对每个参数测试不同的SQL注入载荷
		for _, payload := range valueToTest {
			// 创建新的请求，替换参数值
			newReq := cloneRequest(r.Request)
			if newReq == nil {
				utils.Warning("[SQL注入检测] 无法克隆请求")
				continue
			}

			// 注入点：URL参数
			if r.Request.URL.Query().Has(paramKey) {
				q := newReq.URL.Query()
				q.Set(paramKey, payload)
				newReq.URL.RawQuery = q.Encode()
				utils.Debug("[SQL注入检测] 在URL参数中注入: %s=%s", paramKey, payload)
			}

			// 注入点：请求体
			if len(r.Request.Body) > 0 {
				requestBody := string(r.Request.Body)

				// JSON格式请求体
				var jsonMap map[string]interface{}
				if err := json.Unmarshal([]byte(requestBody), &jsonMap); err == nil {
					// 当参数存在于JSON中时进行替换
					if _, exists := jsonMap[paramKey]; exists {
						jsonMap[paramKey] = payload
						modifiedJson, err := json.Marshal(jsonMap)
						if err == nil {
							newReq.Body = io.NopCloser(bytes.NewReader(modifiedJson))
							newReq.ContentLength = int64(len(modifiedJson))
							utils.Debug("[SQL注入检测] 在JSON请求体中注入: %s=%s", paramKey, payload)
						}
					}
				} else {
					// 表单格式请求体
					values, err := url.ParseQuery(requestBody)
					if err == nil && values.Has(paramKey) {
						values.Set(paramKey, payload)
						formData := values.Encode()
						newReq.Body = io.NopCloser(strings.NewReader(formData))
						newReq.ContentLength = int64(len(formData))
						utils.Debug("[SQL注入检测] 在表单请求体中注入: %s=%s", paramKey, payload)
					}
				}
			}

			// 发送请求
			resp, err := client.Do(newReq)
			if err != nil {
				utils.Warning("[SQL注入检测] 发送请求失败: %v", err)
				continue
			}

			// 读取响应体
			respBody, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				utils.Warning("[SQL注入检测] 读取响应失败: %v", err)
				continue
			}

			respBodyStr := string(respBody)
			utils.Debug("[SQL注入检测] 测试参数 %s=%s, 响应状态码: %d, 内容长度: %d", 
				paramKey, payload, resp.StatusCode, len(respBodyStr))

			// 检查响应中是否包含SQL错误特征
			for _, pattern := range sqlErrorPatterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					utils.Warning("[SQL注入检测] 编译模式失败: %v", err)
					continue
				}

				if re.MatchString(respBodyStr) {
					matches := re.FindStringSubmatch(respBodyStr)
					matchText := ""
					if len(matches) > 0 {
						matchText = matches[0]
						if len(matchText) > 50 {
							matchText = matchText[:50] + "..."
						}
					}

					utils.Info("[SQL注入检测] 检测到SQL注入点 - 参数: %s, 载荷: %s, 匹配模式: %s, 匹配内容: %s",
						paramKey, payload, pattern, matchText)

					vulnResult.Result = "true"
					vulnResult.Reason = fmt.Sprintf("在参数 %s 使用载荷 '%s' 时检测到SQL错误信息: %s",
						paramKey, payload, matchText)
					vulnResult.Parameter = paramKey
					vulnResult.Payload = payload

					// 添加详细说明
					vulnResult.Description = fmt.Sprintf(
						"SQL注入漏洞存在于参数: %s\n"+
							"使用的载荷: %s\n"+
							"匹配的错误模式: %s\n"+
							"响应中的错误信息: %s\n"+
							"请检查应用程序对用户输入的验证和清理机制。",
						paramKey, payload, pattern, matchText)

					return vulnResult, nil
				}
			}

			// 如果响应状态码有显著变化，也可能是SQL注入
			if (originalStatusCode >= 200 && originalStatusCode < 300) && (resp.StatusCode >= 500) {
				utils.Info("[SQL注入检测] 检测到状态码异常变化 - 参数: %s, 载荷: %s, 原始状态码: %d, 当前状态码: %d",
					paramKey, payload, originalStatusCode, resp.StatusCode)

				vulnResult.Result = "true"
				vulnResult.Reason = fmt.Sprintf("在参数 %s 使用载荷 '%s' 时服务器返回错误状态码: %d (原始状态码: %d)",
					paramKey, payload, resp.StatusCode, originalStatusCode)
				vulnResult.Parameter = paramKey
				vulnResult.Payload = payload

				return vulnResult, nil
			}

			// 避免发送请求过快
			time.Sleep(time.Duration(conf.Performance.RequestInterval) * time.Millisecond)
		}
	}

	// 未检测到SQL注入
	vulnResult.Result = "false"
	vulnResult.Reason = "未发现SQL注入漏洞"

	utils.Info("[SQL注入检测] 未发现SQL注入漏洞: %s", r.Request.URL.String())
	return vulnResult, nil
}

