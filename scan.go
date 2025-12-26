package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
	"yuequanScan/AICheck"

	"github.com/klauspost/pgzip"
	"yuequanScan/config"
	"yuequanScan/similarity"
	"yuequanScan/utils"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
)

var hexDataPreview string

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

	// 白名单域名
	whitelistDomains = make(map[string]bool)

	// 其他变量
	completedRequestsMap   = make(map[string]*RequestResponseLog)
	completedRequestsMutex sync.RWMutex

	//enc = mahonia.NewEncoder("utf-8")
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

// LoadWhitelist 加载白名单，使用utils包中的实现
func LoadWhitelist() error {
	return utils.LoadWhitelist()
}

// IsWhitelisted 检查域名是否在白名单中，使用utils包中的实现
func IsWhitelisted(hostname string) bool {
	return utils.IsWhitelisted(hostname)
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
	utils.Info("[扫描服务] 开始主循环，等待请求...")
	for {
		select {
		case <-stopChan:
			utils.Info("[扫描服务] 收到停止信号，退出主循环")
			return
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

			// 持续运行，无请求时仅记录日志

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
			utils.Info("命中公共接口排除路径，不处理")
			skipped++
			rr.Processed = true
			return true
		}

		// 检查是否包含需要排除的关键词
		if len(conf.UnauthorizedScan.ExcludeKeywords) > 0 && containsExcludeKeywords(rr.Request.URL.Path, conf.UnauthorizedScan.ExcludeKeywords) {
			utils.Info("命中公共接口排除关键词，不处理")
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

// containsExcludeKeywords 检查是否包含需要排除的关键词
func containsExcludeKeywords(path string, keywords []string) bool {
	return utils.ContainsExcludeKeywords(path, keywords)
}

// isExcludedPath 检查是否为需要排除的路径
func isExcludedPath(url string, excludePatterns []string) bool {
	return utils.IsExcludedPath(url, excludePatterns)
}

// cloneRequest 克隆HTTP请求对象，使用utils包中的实现
func cloneRequest(r *proxy.Request) *http.Request {
	return utils.CloneRequest(r)
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
		ScanTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// 处理原始请求的响应体
	originalRespBody := r.Response.Body
	if originalRespBody == nil {
		utils.Warning("[未授权检测] 原始响应体为空")
		return nil, fmt.Errorf("原始响应体为空")
	}

	// 处理原始响应体编码
	processedOrigBody, err := processResponseBody(originalRespBody, r.Response.Header.Get("Content-Type"))
	if err != nil {
		utils.Warning("[未授权检测] 处理原始响应体失败: %v，使用原始响应体", err)
		processedOrigBody = originalRespBody
	}

	// 设置原始请求信息
	vulnResult.RequestA = formatRequest(r.Request)
	vulnResult.HeaderA = formatHeaders(r.Response.Header)
	vulnResult.RespBodyA = string(processedOrigBody)

	// 创建未授权请求
	req2 := cloneRequest(r.Request)
	if req2 == nil {
		utils.Warning("[未授权检测] 无法克隆请求，跳过检测")
		return nil, fmt.Errorf("无法克隆请求")
	}

	// 移除授权相关头部
	for _, header := range conf.UnauthorizedScan.RemoveHeaders {
		req2.Header.Del(header)
	}

	// 设置未授权请求信息
	vulnResult.RequestB = formatRequest(req2)

	// 发送未授权请求
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 发送请求并获取响应
	resp, err := client.Do(req2)
	if err != nil {
		utils.Warning("[未授权检测] 发送未授权请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 读取未授权请求的响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Warning("[未授权检测] 读取未授权响应体失败: %v", err)
		return nil, err
	}

	// 设置响应头
	vulnResult.HeaderB = formatHeaders(resp.Header)

	// 处理响应体编码
	processedBody, err := processResponseBody(respBody, resp.Header.Get("Content-Type"))
	if err != nil {
		utils.Warning("[未授权检测] 处理未授权响应体失败: %v，使用原始响应体", err)
		processedBody = respBody
	}

	// 保存处理后的响应体
	vulnResult.RespBodyB = string(processedBody)

	// 如果状态码是2xx，进行进一步分析
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 检测敏感数据
		if conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
			sensitivePatterns := make(map[string]string)
			for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
				sensitivePatterns[pattern.Name] = pattern.Pattern
			}
			vulnResult.SensitiveData = detectSensitiveDataWithDetails(string(processedBody), sensitivePatterns)

			if len(vulnResult.SensitiveData) > 0 {
				utils.Info("[未授权检测] 发现敏感数据: %d 处", len(vulnResult.SensitiveData))
			}
		}

		// 计算响应相似度
		similarityScore, reason, vulnStatus := calculateResponseSimilarity(
			vulnResult.RespBodyA,
			string(processedBody),
			vulnResult.RequestA,
			resp.StatusCode,
		)

		utils.Info("[未授权检测] 字符级别响应体相似度: %.4f", similarityScore)

		// 处理相似度结果
		if similarityScore >= conf.UnauthorizedScan.SimilarityThreshold {
			hasSensitiveData := len(vulnResult.SensitiveData) > 0
			if hasSensitiveData && vulnStatus {
				vulnResult.Result = "true"
				vulnResult.Reason = fmt.Sprintf("【重要】替换请求响应与原始响应相似度较高 %s (%.2f >= %.2f)且包含敏感数据",
					reason, similarityScore, conf.UnauthorizedScan.SimilarityThreshold)
			} else if !vulnStatus {
				vulnResult.Result = "false"
				vulnResult.Reason = fmt.Sprintf("%s", reason)
			} else {
				vulnResult.Result = "unknown"
				vulnResult.Reason = fmt.Sprintf("替换请求响应与原始响应相似度较高 %s (%.2f >= %.2f)但未检测到敏感数据，建议人工复查",
					reason, similarityScore, conf.UnauthorizedScan.SimilarityThreshold)
			}
		} else {
			vulnResult.Result = "false"
			vulnResult.Reason = fmt.Sprintf("替换请求响应与原始响应相似度较低 %s (%.2f < %.2f)",
				reason, similarityScore, conf.UnauthorizedScan.SimilarityThreshold)
		}
	} else {
		vulnResult.Result = "false"
		vulnResult.Reason = fmt.Sprintf("替换请求返回非标准状态码: %d", resp.StatusCode)
	}

	// 记录检测结果
	utils.Info("[未授权检测] 检测完成: URL=%s, 结果=%s, 敏感数据数量=%d",
		vulnResult.Url, vulnResult.Result, len(vulnResult.SensitiveData))

	return vulnResult, nil
}

// 处理响应体的辅助函数
func processResponseBody(body []byte, contentType string) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	utils.Debug("[响应处理] 开始处理响应体，原始长度=%d字节, Content-Type=%s", len(body), contentType)

	// 记录原始数据的前32字节（十六进制）用于调试
	hexPreview := ""
	for i := 0; i < min(len(body), 32); i++ {
		hexPreview += fmt.Sprintf("%02x ", body[i])
	}
	utils.Debug("[响应处理] 原始数据前32字节: %s", hexPreview)

	// 1. 首先处理 gzip 压缩
	if isGzipCompressed(body) {
		utils.Debug("[响应处理] 检测到 gzip 压缩，尝试解压")
		reader, err := pgzip.NewReader(bytes.NewReader(body))
		if err != nil {
			utils.Warning("[响应处理] gzip 解压失败: %v", err)
			return body, fmt.Errorf("gzip 解压失败: %v", err)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			utils.Warning("[响应处理] 读取解压数据失败: %v", err)
			return body, fmt.Errorf("读取解压数据失败: %v", err)
		}
		utils.Debug("[响应处理] gzip解压成功，解压后长度=%d字节", len(decompressed))
		body = decompressed
	}

	// 2. 检查并移除 BOM
	if len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF {
		utils.Debug("[响应处理] 检测到并移除 UTF-8 BOM")
		body = body[3:]
	}

	// 3. 检查是否已经是有效的 UTF-8
	if utf8.Valid(body) {
		utils.Debug("[响应处理] 响应体是有效的 UTF-8 编码")
		// 记录一小段预览
		preview := string(body)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		utils.Debug("[响应处理] 响应体预览: %s", preview)
		return body, nil
	}

	// 4. 尝试从 Content-Type 获取字符集
	charset := getCharset(contentType)
	if charset == "" {
		// 5. 如果没有指定字符集，尝试检测
		charset = detectCharset(body)
	}
	utils.Debug("[响应处理] 检测到字符集: %s", charset)

	// 6. 转换编码
	if charset != "" && !strings.EqualFold(charset, "utf-8") {
		utils.Debug("[响应处理] 尝试将编码从 %s 转换为 UTF-8", charset)
		converted, err := convertToUTF8(body, charset)
		if err != nil {
			utils.Warning("[响应处理] 编码转换失败: %v", err)
			// 尝试其他编码
			for _, tryCharset := range []string{"gbk", "gb18030", "big5"} {
				if tryCharset != charset {
					utils.Debug("[响应处理] 尝试使用 %s 编码转换", tryCharset)
					if converted, err = convertToUTF8(body, tryCharset); err == nil {
						utils.Debug("[响应处理] 使用 %s 编码转换成功", tryCharset)
						body = converted
						break
					}
				}
			}
			if err != nil {
				return body, fmt.Errorf("编码转换失败: %v", err)
			}
		}
		body = converted
	}

	// 7. 最终验证
	if !utf8.Valid(body) {
		utils.Warning("[响应处理] 处理后的响应体不是有效的 UTF-8 编码")
		return body, fmt.Errorf("处理后的响应体不是有效的 UTF-8 编码")
	}

	// 记录处理后的预览
	preview := string(body)
	if len(preview) > 100 {
		preview = preview[:100] + "..."
	}
	utils.Debug("[响应处理] 最终处理结果预览: %s", preview)

	return body, nil
}

// 检测数据是否是 gzip 压缩的
func isGzipCompressed(data []byte) bool {
	return len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b
}

// 检测字符集
func detectCharset(data []byte) string {
	// 这里可以使用更复杂的字符集检测算法
	// 目前先实现一个简单的检测
	if isGBK(data) {
		return "gbk"
	}
	return ""
}

// 简单的 GBK 检测
func isGBK(data []byte) bool {
	length := len(data)
	var i int = 0
	for i < length {
		if data[i] <= 0x7f {
			//编码0~127,只有一个字节的编码，兼容ASCII码
			i++
			continue
		} else {
			//大于127的使用双字节编码
			if i+1 >= length {
				return false
			}
			if data[i] >= 0x81 &&
				data[i] <= 0xfe &&
				data[i+1] >= 0x40 &&
				data[i+1] <= 0xfe &&
				data[i+1] != 0x7f {
				i += 2
				continue
			} else {
				return false
			}
		}
	}
	return true
}

// 转换到 UTF-8
func convertToUTF8(data []byte, charset string) ([]byte, error) {
	if strings.EqualFold(charset, "gbk") || strings.EqualFold(charset, "gb2312") || strings.EqualFold(charset, "gb18030") {
		return simplifiedchinese.GBK.NewDecoder().Bytes(data)
	}
	// 如果需要支持其他编码，在这里添加
	return data, fmt.Errorf("不支持的字符集: %s", charset)
}

// 从 Content-Type 提取字符集
func getCharset(contentType string) string {
	if contentType == "" {
		return ""
	}

	// 解析 Content-Type
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		utils.Warning("[响应处理] 解析 Content-Type 失败: %v", err)
		return ""
	}

	// 获取字符集
	charset := params["charset"]
	if charset == "" && (strings.Contains(mediaType, "text") || strings.Contains(mediaType, "json")) {
		// 对于文本类型，如果没有指定字符集，默认尝试 UTF-8
		charset = "utf-8"
	}

	return strings.ToLower(charset)
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

// fixBrokenJSON 尝试修复可能被破坏的JSON数据
func fixBrokenJSON(data []byte, contentType string) ([]byte, bool) {

	// 生成数据的十六进制预览
	hexDataPreview = ""
	for i, b := range data {
		if i < 16 { // 只显示前16字节的十六进制
			hexDataPreview += fmt.Sprintf("%02x ", b)
		} else {
			break
		}
	}
	utils.Info("[JSON修复] 原始数据十六进制预览: %s", hexDataPreview)

	// 检测并移除BOM头
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		utils.Info("[JSON修复] 检测到UTF-8 BOM头，移除中...")
		data = data[3:]
	}

	// 检查数据是否已经是有效的JSON
	if json.Valid(data) {
		utils.Info("[JSON修复] 数据已经是有效的JSON，无需修复")
		return data, false
	}

	// 尝试将数据转换为字符串进行处理
	strData := string(data)

	// 判断是否为UTF-8编码
	isUTF8 := utf8.ValidString(strData)
	utils.Info("[JSON修复] 数据是否为有效UTF-8: %v", isUTF8)

	// 尝试检测并处理常见的非UTF-8编码，特别是如果Content-Type声明是UTF-8但实际不是
	if !isUTF8 && (strings.Contains(contentType, "utf-8") || strings.Contains(contentType, "json")) {
		utils.Info("[JSON修复] Content-Type声明是UTF-8或JSON，但数据不是有效UTF-8，尝试其他编码")

		// 尝试GBK编码解码
		gbkDecoder := simplifiedchinese.GBK.NewDecoder()
		gbkStr, err := gbkDecoder.String(strData)
		if err == nil {
			utils.Info("[JSON修复] 尝试GBK解码，解码成功")
			strData = gbkStr
			if json.Valid([]byte(strData)) {
				utils.Info("[JSON修复] GBK解码后数据是有效JSON")
				return []byte(strData), true
			}
		} else {
			utils.Info("[JSON修复] GBK解码失败: %s", err.Error())
		}

		// 尝试GB18030编码解码
		gb18030Decoder := simplifiedchinese.GB18030.NewDecoder()
		gb18030Str, err := gb18030Decoder.String(strData)
		if err == nil {
			utils.Info("[JSON修复] 尝试GB18030解码，解码成功")
			strData = gb18030Str
			if json.Valid([]byte(strData)) {
				utils.Info("[JSON修复] GB18030解码后数据是有效JSON")
				return []byte(strData), true
			}
		} else {
			utils.Info("[JSON修复] GB18030解码失败: %s", err.Error())
		}
	}

	// 检查是否包含常见的乱码字符模式
	if containsCommonGarbledCharacters(strData) {
		utils.Info("[JSON修复] 检测到常见乱码字符模式")
	}

	// 尝试修复常见的JSON格式错误
	fixedStr, changed := fixCommonJSONFormatErrors(strData)
	if changed {
		utils.Info("[JSON修复] 修复常见JSON格式错误后，尝试解析")

		// 检查修复后的字符串是否为有效JSON
		if json.Valid([]byte(fixedStr)) {
			utils.Info("[JSON修复] 修复成功，返回有效JSON")
			return []byte(fixedStr), true
		} else {
			utils.Info("[JSON修复] 修复后仍然不是有效JSON")
		}
	}

	// 最后尝试进行更积极的修复
	cleanStr := strData

	// 移除所有控制字符
	re := regexp.MustCompile(`[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]`)
	cleanStr = re.ReplaceAllString(cleanStr, "")

	// 如果字符串太长且包含大量重复内容，可能是乱码，尝试截断
	if len(cleanStr) > 10000 && hasManyRepeatingPatterns(cleanStr) {
		utils.Info("[JSON修复] 检测到大量重复内容，可能是乱码，尝试截断")
		cleanStr = cleanStr[:2000] // 截取前2000个字符
	}

	// 再次尝试修复格式错误
	fixedStr, _ = fixCommonJSONFormatErrors(cleanStr)

	// 检查是否有效JSON
	if json.Valid([]byte(fixedStr)) {
		utils.Info("[JSON修复] 积极修复后得到有效JSON")
		return []byte(fixedStr), true
	}

	// 如果仍然无法修复，记录失败并返回原始数据
	utils.Info("[JSON修复] 所有修复尝试失败，返回原始数据")
	return data, false
}

// 检查字符串是否包含常见的乱码字符模式
func containsCommonGarbledCharacters(s string) bool {
	// 检查是否包含中文乱码的常见特征
	if regexp.MustCompile(`[\xef\xbf\xbd]{3,}`).MatchString(s) {
		utils.Info("[乱码检测] 发现连续的UTF-8替换字符，可能是编码问题")
		return true
	}

	// 检查是否有不成对的Unicode代理对
	if regexp.MustCompile(`[\xd8-\xdb][\x00-\xff](?![\xdc-\xdf][\x00-\xff])`).MatchString(s) ||
		regexp.MustCompile(`(?<![\xd8-\xdb][\x00-\xff])[\xdc-\xdf][\x00-\xff]`).MatchString(s) {
		utils.Info("[乱码检测] 发现不成对的Unicode代理对，可能是编码问题")
		return true
	}

	// 检查是否包含大量无效的UTF-8序列
	invalidCount := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			invalidCount++
		}
		i += size
	}

	// 如果无效字符比例超过5%，认为有乱码
	invalidRatio := float64(invalidCount) / float64(len(s))
	if invalidRatio > 0.05 {
		utils.Info("[乱码检测] 无效UTF-8序列比例为%.2f%%，超过阈值", invalidRatio*100)
		return true
	}

	return false
}

// 检测字符串中是否有大量重复模式
func hasManyRepeatingPatterns(s string) bool {
	if len(s) < 100 {
		return false
	}

	// 选择一些样本进行检查
	samples := []string{
		s[:10], s[10:20], s[20:30], s[30:40], s[40:50],
	}

	// 计算每个样本在全文中的出现次数
	totalCount := 0
	for _, sample := range samples {
		if len(sample) < 3 {
			continue
		}
		count := strings.Count(s, sample)
		totalCount += count
	}

	// 如果平均每个样本出现次数超过预期，认为有大量重复
	avgCount := float64(totalCount) / float64(len(samples))
	utils.Info("[重复模式检测] 样本平均重复次数: %.2f", avgCount)
	return avgCount > 10
}

// 修复常见的JSON格式错误
func fixCommonJSONFormatErrors(jsonStr string) (string, bool) {
	original := jsonStr
	changed := false

	// 打印原始字符串长度和前100个字符
	preview := ""
	if len(jsonStr) <= 100 {
		preview = jsonStr
	} else {
		preview = jsonStr[:100] + "..."
	}
	utils.Info("[JSON格式修复] 原始字符串长度=%d，预览: %s", len(jsonStr), preview)

	// 修复常见的格式错误：单引号替换成双引号
	if strings.Contains(jsonStr, "'") && strings.Count(jsonStr, "'") > strings.Count(jsonStr, "\"")*2 {
		jsonStr = strings.Replace(jsonStr, "'", "\"", -1)
		changed = true
	}

	// 修复未闭合的字符串
	if strings.Count(jsonStr, "\"")%2 != 0 {
		utils.Info("[JSON格式修复] 发现未闭合的引号")
		jsonStr = strings.TrimRight(jsonStr, "\"")
		changed = true
	}

	// 修复未闭合的大括号
	if strings.Count(jsonStr, "{") > strings.Count(jsonStr, "}") {
		utils.Info("[JSON格式修复] 发现未闭合的大括号")
		jsonStr += "}"
		changed = true
	}

	// 修复未闭合的中括号
	if strings.Count(jsonStr, "[") > strings.Count(jsonStr, "]") {
		utils.Info("[JSON格式修复] 发现未闭合的中括号")
		jsonStr += "]"
		changed = true
	}

	// 修复常见的转义字符错误
	jsonStr = strings.Replace(jsonStr, "\\\"", "\"", -1)

	// 检查修复后的字符串是否与原始字符串不同
	if jsonStr != original {
		changed = true
	}

	// 修复缺少引号的键名
	re := regexp.MustCompile(`([{,]\s*)([a-zA-Z0-9_]+)(\s*:)`)
	if re.MatchString(jsonStr) {
		jsonStr = re.ReplaceAllString(jsonStr, "$1\"$2\"$3")
		changed = true
		utils.Info("[JSON格式修复] 为缺少引号的键名添加引号")
	}

	// 修复常见的转义字符问题
	if strings.Contains(jsonStr, "\\x") {
		// 将\x转义序列转换为Unicode
		re := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
		jsonStr = re.ReplaceAllStringFunc(jsonStr, func(s string) string {
			hex := s[2:]
			code, _ := strconv.ParseInt(hex, 16, 32)
			return string(rune(code))
		})
		changed = true
		utils.Info("[JSON格式修复] 修复转义字符")
	}

	// 处理错误的布尔值写法
	reTrue := regexp.MustCompile(`(?i):\s*TRUE\b`)
	reFalse := regexp.MustCompile(`(?i):\s*FALSE\b`)

	if reTrue.MatchString(jsonStr) {
		jsonStr = reTrue.ReplaceAllString(jsonStr, ": true")
		changed = true
		utils.Info("[JSON格式修复] 修复TRUE为true")
	}

	if reFalse.MatchString(jsonStr) {
		jsonStr = reFalse.ReplaceAllString(jsonStr, ": false")
		changed = true
		utils.Info("[JSON格式修复] 修复FALSE为false")
	}

	// 处理缺少引号的值
	reNoQuoteValue := regexp.MustCompile(`:\s*([a-zA-Z][a-zA-Z0-9_]*)(\s*[,}])`)
	if reNoQuoteValue.MatchString(jsonStr) {
		jsonStr = reNoQuoteValue.ReplaceAllStringFunc(jsonStr, func(s string) string {
			// 不处理true, false, null
			if strings.Contains(s, "true") || strings.Contains(s, "false") || strings.Contains(s, "null") {
				return s
			}

			re := regexp.MustCompile(`:\s*([a-zA-Z][a-zA-Z0-9_]*)(\s*[,}])`)
			return re.ReplaceAllString(s, ": \"$1\"$2")
		})
		changed = true
		utils.Info("[JSON格式修复] 为缺少引号的值添加引号")
	}

	// 处理尾部多余的逗号
	reTrailingComma := regexp.MustCompile(`,(\s*})`)
	if reTrailingComma.MatchString(jsonStr) {
		jsonStr = reTrailingComma.ReplaceAllString(jsonStr, "$1")
		changed = true
		utils.Info("[JSON格式修复] 移除对象尾部多余的逗号")
	}

	// 处理数组中的尾部逗号
	reArrayTrailingComma := regexp.MustCompile(`,(\s*\])`)
	if reArrayTrailingComma.MatchString(jsonStr) {
		jsonStr = reArrayTrailingComma.ReplaceAllString(jsonStr, "$1")
		changed = true
		utils.Info("[JSON格式修复] 移除数组尾部多余的逗号")
	}

	// 如果有修改,打印修改后的前100个字符
	if changed {
		preview = ""
		if len(jsonStr) <= 100 {
			preview = jsonStr
		} else {
			preview = jsonStr[:100] + "..."
		}
		utils.Info("[JSON格式修复] 修改后字符串预览: %s", preview)

		// 检查修改后是否为有效JSON
		valid := json.Valid([]byte(jsonStr))
		utils.Info("[JSON格式修复] 修改后是否为有效JSON: %v", valid)
	}

	return jsonStr, changed && jsonStr != original
}

// 去除JSON前后的非JSON字符
func trimNonJSONChars(jsonStr string) string {
	// 查找第一个可能的JSON开始字符
	startIdx := strings.IndexAny(jsonStr, "{[")
	if startIdx == -1 {
		return jsonStr
	}

	// 从后向前查找可能的JSON结束字符
	endIdx := strings.LastIndexAny(jsonStr, "}]")
	if endIdx == -1 || endIdx < startIdx {
		return jsonStr
	}

	// 提取可能的JSON部分
	trimmed := jsonStr[startIdx : endIdx+1]

	// 进一步尝试平衡大括号和方括号
	openBraces := 0
	openBrackets := 0
	bestEndPos := -1

	for i, ch := range trimmed {
		if ch == '{' {
			openBraces++
		} else if ch == '}' {
			openBraces--
			if openBraces == 0 && openBrackets == 0 {
				bestEndPos = i
			}
		} else if ch == '[' {
			openBrackets++
		} else if ch == ']' {
			openBrackets--
			if openBraces == 0 && openBrackets == 0 {
				bestEndPos = i
			}
		}
	}

	if bestEndPos != -1 {
		return trimmed[:bestEndPos+1]
	}

	return trimmed
}

// 从文本中提取JSON
func extractJSONFromText(text string) string {
	// 尝试查找最外层的JSON对象或数组
	objectMatches := regexp.MustCompile(`\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\}`).FindAllString(text, -1)
	arrayMatches := regexp.MustCompile(`\[(?:[^\[\]]|(?:\[(?:[^\[\]]|(?:\[[^\[\]]*\]))*\]))*\]`).FindAllString(text, -1)

	// 组合所有可能的JSON
	candidates := append(objectMatches, arrayMatches...)

	// 按长度排序，优先考虑更长的匹配（可能包含更多信息）
	sort.Slice(candidates, func(i, j int) bool {
		return len(candidates[i]) > len(candidates[j])
	})

	// 返回第一个有效的JSON
	for _, candidate := range candidates {
		if json.Valid([]byte(candidate)) {
			return candidate
		}
	}

	return ""
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
	var result []string
	var matchList []string
	// 使用map追踪每种模式的匹配计数
	matchCounts := make(map[string]int)

	// 添加调试信息
	utils.Debug("[敏感数据检测] 开始检测敏感数据，响应体长度: %d 字节, 模式数量: %d",
		len(respBody), len(patterns))

	// 检查响应体是否为空或无效
	if len(respBody) < 5 {
		utils.Debug("[敏感数据检测] 响应体太短，跳过检测")
		return result
	}

	// 记录响应体前100字符
	previewLen := 100
	if len(respBody) < previewLen {
		previewLen = len(respBody)
	}
	respPreview := respBody[:previewLen]
	utils.Debug("[敏感数据检测] 响应体预览: %s", respPreview)

	// 检查各种敏感数据模式
	for name, pattern := range patterns {
		utils.Debug("[敏感数据检测] 检查模式: %s, 正则: %s", name, pattern)

		re, err := regexp.Compile(pattern)
		if err != nil {
			utils.Warning("[敏感数据检测] 正则表达式编译失败: %s, 错误: %v", pattern, err)
			continue
		}

		// 查找所有匹配
		matches := re.FindAllString(respBody, -1)
		if matches == nil || len(matches) == 0 {
			utils.Debug("[敏感数据检测] 没有找到匹配: %s", name)
			continue
		}

		// 处理匹配结果
		matchCount := 0
		matchList = []string{}
		uniqueMatches := map[string]bool{}

		for _, match := range matches {
			// 验证匹配结果是否有效
			if !isValidMatch(name, match) {
				continue
			}

			// 去重并记录匹配
			if _, exists := uniqueMatches[match]; !exists {
				uniqueMatches[match] = true

				// 脱敏处理，根据匹配类型进行适当展示
				displayMatch := getMaskedValue(name, match)
				matchList = append(matchList, displayMatch)
				matchCount++

				// 限制匹配数量，防止结果过大
				if matchCount >= 10 {
					matchList = append(matchList, fmt.Sprintf("... 还有 %d 项匹配", len(matches)-10))
					break
				}
			}
		}

		// 记录匹配计数
		matchCounts[name] = matchCount

		// 如果找到匹配，添加到结果
		if len(matchList) > 0 {
			// 获取模式描述
			patternDesc := getPatternDescription(name)
			resultStr := fmt.Sprintf("发现%s: %s", patternDesc, strings.Join(matchList, ", "))
			result = append(result, resultStr)

			// 详细记录匹配情况
			utils.Info("[敏感数据检测] 发现模式 %s (%s) 的匹配: %d 项",
				name, patternDesc, matchCount)

			// 如果匹配数量较多，记录统计信息
			if matchCount > 3 {
				utils.Info("[敏感数据检测] %s 匹配统计: 共 %d 项，展示前 %d 项",
					name, matchCount, min(matchCount, 10))
			}
		}
	}

	// 总结检测结果
	if len(result) > 0 {
		utils.Info("[敏感数据检测] 总计发现 %d 种敏感数据模式", len(result))

		// 按匹配数量排序并显示统计
		type matchStat struct {
			name  string
			count int
		}
		stats := []matchStat{}
		for name, count := range matchCounts {
			if count > 0 {
				stats = append(stats, matchStat{name, count})
			}
		}

		// 按匹配数量排序
		sort.Slice(stats, func(i, j int) bool {
			return stats[i].count > stats[j].count
		})

		// 打印排序后的匹配统计
		for _, stat := range stats {
			utils.Debug("[敏感数据统计] 模式: %s, 匹配数: %d", stat.name, stat.count)
		}
	} else {
		utils.Debug("[敏感数据检测] 未发现任何敏感数据")
	}

	return result
}

// 根据匹配类型获取脱敏后的值
func getMaskedValue(patternName string, value string) string {
	// 直接返回原始值，不进行脱敏
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
func calculateConfidenceScore(r *RequestResponseLog, respBody []byte, resp *http.Response) (int, []string, string) {
	totalScore := 0
	appliedRules := []string{}
	detailedScoring := "" // 用于记录详细的打分细则

	// 检查参数是否为空
	if r == nil || r.Response == nil || resp == nil || respBody == nil {
		utils.Warning("[未授权检测] calculateConfidenceScore调用参数异常: r=%v, respBody长度=%d, resp=%v",
			r != nil, len(respBody), resp != nil)
		return 0, []string{"参数检查失败"}, "参数检查失败"
	}

	// 确保r.Response.Body不为空
	if r.Response.Body == nil {
		utils.Warning("[未授权检测] 原始响应体为空")
		return 0, []string{"原始响应体为空"}, "原始响应体为空"
	}

	// 获取配置
	conf := config.GetConfig()

	// 获取配置的规则列表
	if conf == nil {
		utils.Error("[未授权检测] 配置对象为空")
		return 0, []string{"配置对象为空"}, "配置对象为空"
	}

	rules := conf.UnauthorizedScan.ConfidenceRules

	// 如果没有配置规则，使用默认规则
	if len(rules) == 0 {
		rules = getDefaultConfidenceRules()
	}

	// 计算所有规则的总权重，用于后续的归一化处理
	totalWeight := 0
	for _, rule := range rules {
		totalWeight += rule.Weight
	}

	detailedScoring += fmt.Sprintf("置信度评分规则总权重：%d分\n", totalWeight)

	// 检查响应体中的敏感数据，并根据命中条数计算分数
	var sensitiveDataCount int
	var sensitiveDetails []string
	var sensitiveMatches []string // 保存完整的敏感数据匹配结果
	var sensitiveTypeCounts map[string]int = make(map[string]int)

	if conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
		sensitivePatterns := make(map[string]string)
		for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
			sensitivePatterns[pattern.Name] = pattern.Pattern
		}

		// 获取所有敏感数据匹配项
		sensitiveMatches = detectSensitiveDataWithDetails(string(respBody), sensitivePatterns)
		sensitiveDataCount = len(sensitiveMatches)

		// 分类汇总敏感数据类型及数量
		sensitiveTypeCounts = make(map[string]int)
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
	detailedScoring += "规则评分明细：\n"
	for _, rule := range rules {
		switch rule.Name {
		case "contains_sensitive_data":
			// 根据敏感数据命中数量计算分数，保持在权重范围内
			if sensitiveDataCount > 0 {
				// 基础分为权重的60%
				baseScore := rule.Weight * 60 / 100

				// 根据敏感数据数量计算额外加分，但不超过权重的40%
				extraScoreMax := rule.Weight * 40 / 100
				extraScore := min(extraScoreMax, sensitiveDataCount*5)

				// 对于高价值敏感数据类型（如身份证号、手机号），在不超过权重的情况下额外加分
				highValueBonus := 0
				for dataType := range sensitiveTypeCounts {
					if (strings.Contains(dataType, "身份证") || strings.Contains(dataType, "手机号")) &&
						(baseScore+extraScore+highValueBonus < rule.Weight) {
						highValueBonus += 3
					}
				}

				// 确保总分不超过规则权重
				earnedScore := min(rule.Weight, baseScore+extraScore+highValueBonus)

				totalScore += earnedScore
				if len(sensitiveDetails) > 0 {
					appliedRules = append(appliedRules, fmt.Sprintf("发现高价值敏感数据: %s", strings.Join(sensitiveDetails, "、")))
				} else {
					appliedRules = append(appliedRules, fmt.Sprintf("发现敏感数据(%d处)", sensitiveDataCount))
				}

				detailedScoring += fmt.Sprintf("- %s: +%d分 (基础分:%d分, 数量加成:%d分, 高价值加成:%d分)\n  敏感数据: %s\n",
					rule.Description, earnedScore, baseScore, extraScore, highValueBonus,
					strings.Join(sensitiveDetails, "、"))

				utils.Debug("[未授权检测] 敏感数据评分: 基础分=%d, 额外分=%d, 高价值数据加分=%d, 总计=%d, 敏感数据数量=%d",
					baseScore, extraScore, highValueBonus, earnedScore, sensitiveDataCount)
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (未检测到敏感数据)\n", rule.Description)
			}

		case "successful_status_code":
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "成功状态码")
				detailedScoring += fmt.Sprintf("- %s: +%d分 (状态码:%d)\n", rule.Description, rule.Weight, resp.StatusCode)
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (状态码:%d, 非2xx)\n", rule.Description, resp.StatusCode)
			}

		case "json_response":
			var js interface{}
			if json.Unmarshal(respBody, &js) == nil {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "JSON响应")
				detailedScoring += fmt.Sprintf("- %s: +%d分 (响应是有效的JSON格式)\n", rule.Description, rule.Weight)
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (响应不是有效的JSON格式)\n", rule.Description)
			}

		case "non_empty_response":
			if len(respBody) > 20 {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "非空响应")
				detailedScoring += fmt.Sprintf("- %s: +%d分 (响应长度:%d字节)\n", rule.Description, rule.Weight, len(respBody))
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (响应长度:%d字节, 小于20字节)\n", rule.Description, len(respBody))
			}

		case "error_keywords_absent":
			errorKeywords := []string{
				"权限不足", "无权限", "未授权", "请先登录", "会话已过期",
				"unauthorized", "access denied", "forbidden", "permission denied",
				"login required", "not authorized", "invalid token",
			}
			hasErrorKeyword := false
			foundKeywords := []string{}
			respStr := strings.ToLower(string(respBody))
			for _, keyword := range errorKeywords {
				if strings.Contains(respStr, strings.ToLower(keyword)) {
					hasErrorKeyword = true
					foundKeywords = append(foundKeywords, keyword)
				}
			}
			if !hasErrorKeyword {
				totalScore += rule.Weight
				appliedRules = append(appliedRules, "无错误关键词")
				detailedScoring += fmt.Sprintf("- %s: +%d分 (未发现错误关键词)\n", rule.Description, rule.Weight)
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (发现错误关键词: %s)\n", rule.Description, strings.Join(foundKeywords, ", "))
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
				detailedScoring += fmt.Sprintf("- %s: +%d分 (Content-Type匹配: %s)\n", rule.Description, rule.Weight, origCT)
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (Content-Type不匹配: 原始=%s, 当前=%s)\n", rule.Description, origCT, newCT)
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
				detailedScoring += fmt.Sprintf("- %s: +%d分 (长度相似度: 原始=%d字节, 当前=%d字节, 差异:%.2f%%)\n",
					rule.Description, rule.Weight, origLen, newLen, math.Abs(float64(origLen-newLen))/float64(origLen)*100)
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (长度差异过大: 原始=%d字节, 当前=%d字节, 差异:%.2f%%)\n",
					rule.Description, origLen, newLen,
					calculateDiffPercentage(origLen, newLen))
			}

		case "api_endpoint":
			// 判断是否为API端点
			if r.Request != nil && r.Request.URL != nil {
				urlPath := r.Request.URL.Path
				apiPatterns := []string{"/api/", "/v1/", "/v2/", "/rest/", "/service/"}
				matched := false
				matchedPattern := ""
				for _, pattern := range apiPatterns {
					if strings.Contains(urlPath, pattern) {
						totalScore += rule.Weight
						appliedRules = append(appliedRules, "API端点")
						matched = true
						matchedPattern = pattern
						break
					}
				}
				if matched {
					detailedScoring += fmt.Sprintf("- %s: +%d分 (匹配API路径模式: %s)\n", rule.Description, rule.Weight, matchedPattern)
				} else {
					detailedScoring += fmt.Sprintf("- %s: +0分 (未匹配任何API路径模式: %s)\n", rule.Description, urlPath)
				}
			} else {
				detailedScoring += fmt.Sprintf("- %s: +0分 (无法获取请求URL)\n", rule.Description)
			}
		}
	}

	// 如果包含敏感数据但总分仍低于高置信度阈值，适当提升分数，但确保不超过100分
	if sensitiveDataCount > 0 && totalScore < conf.UnauthorizedScan.HighConfidenceScore {
		// 根据敏感数据数量和类型计算额外加分，但最多加到高置信度阈值
		additionalScoreMax := min(15, conf.UnauthorizedScan.HighConfidenceScore-totalScore)
		additionalScore := min(additionalScoreMax, sensitiveDataCount*3)

		// 如果存在身份证或手机号等高价值数据，确保至少达到高置信度阈值的80%
		highValueBoost := false
		for dataType := range sensitiveTypeCounts {
			if strings.Contains(dataType, "身份证") || strings.Contains(dataType, "手机号") {
				minScore := conf.UnauthorizedScan.HighConfidenceScore * 80 / 100
				if totalScore+additionalScore < minScore {
					additionalScore = minScore - totalScore
					highValueBoost = true
				}
				break
			}
		}

		// 确保最终分数不超过100
		if totalScore+additionalScore > 100 {
			additionalScore = 100 - totalScore
		}

		if additionalScore > 0 {
			oldScore := totalScore
			totalScore += additionalScore
			appliedRules = append(appliedRules, fmt.Sprintf("敏感数据加成(+%d分)", additionalScore))

			if highValueBoost {
				detailedScoring += fmt.Sprintf("\n敏感数据加成: +%d分 (原始分数:%d分 → 加成后:%d分)\n原因: 发现高价值敏感数据(身份证/手机号)但总分低于高置信度阈值\n",
					additionalScore, oldScore, totalScore)
			} else {
				detailedScoring += fmt.Sprintf("\n敏感数据加成: +%d分 (原始分数:%d分 → 加成后:%d分)\n原因: 发现敏感数据但总分低于高置信度阈值\n",
					additionalScore, oldScore, totalScore)
			}

			utils.Debug("[未授权检测] 发现敏感数据但分数不足，额外加分: +%d分", additionalScore)
		}
	}

	// 最终确保分数不超过100
	if totalScore > 100 {
		utils.Warning("[未授权检测] 计算的分数(%d)超过100，将被限制为100", totalScore)
		totalScore = 100
		detailedScoring += "\n注意: 计算的分数超过100，已限制为100分\n"
	}

	// 添加总分和阈值信息
	detailedScoring += fmt.Sprintf("\n总得分: %d分 (高置信度阈值:%d分, 中置信度阈值:%d分, 低置信度阈值:%d分)",
		totalScore, conf.UnauthorizedScan.HighConfidenceScore,
		conf.UnauthorizedScan.MediumConfidenceScore, conf.UnauthorizedScan.LowConfidenceScore)

	utils.Debug("[未授权检测] 置信度评分计算完成: %d分, 应用规则: %v", totalScore, appliedRules)
	return totalScore, appliedRules, detailedScoring
}

// 计算差异百分比的辅助函数
func calculateDiffPercentage(origLen int, newLen int) float64 {
	if origLen > 0 {
		return math.Abs(float64(origLen-newLen)) / float64(origLen) * 100
	}
	return 100.0
}

// 获取默认置信度规则
func getDefaultConfidenceRules() []config.ConfidenceRule {
	return []config.ConfidenceRule{
		{
			Name:        "contains_sensitive_data",
			Description: "响应中包含敏感数据（如手机号、身份证等）",
			Weight:      45, // 保持与配置文件中相同的权重
		},
		{
			Name:        "successful_status_code",
			Description: "响应状态码为2xx",
			Weight:      10,
		},
		{
			Name:        "json_response",
			Description: "响应为有效的JSON格式",
			Weight:      5,
		},
		{
			Name:        "non_empty_response",
			Description: "响应内容非空",
			Weight:      5,
		},
		{
			Name:        "error_keywords_absent",
			Description: "响应中不包含错误关键词",
			Weight:      10,
		},
		{
			Name:        "same_content_type",
			Description: "与原始响应具有相同的Content-Type",
			Weight:      5,
		},
		{
			Name:        "similar_content_length",
			Description: "与原始响应长度相似",
			Weight:      10,
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
				var unauthorizedResult *Result
				var unauthorizedErr error

				if conf.UnauthorizedScan.Enabled {
					utils.Debug("[优先处理] 执行未授权访问检测: URL=%s", r.Request.URL.String())
					unauthorizedResult, unauthorizedErr = detectUnauthorizedAccess(r)

					// 如果检测成功且发现未授权漏洞
					if unauthorizedErr == nil && unauthorizedResult != nil {
						// 检查是否包含敏感数据，如果包含则直接使用未授权结果
						if len(unauthorizedResult.SensitiveData) > 0 && unauthorizedResult.Result == "true" {
							utils.Warning("[漏洞确认] 未授权检测发现敏感数据，无论结果状态，优先处理为未授权漏洞: %s", r.Request.URL.String())

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
func detectPrivilegeEscalation(r *RequestResponseLog) (*Result, error) {
	if r == nil || r.Request == nil || r.Response == nil {
		return nil, fmt.Errorf("无效的请求或响应")
	}

	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		return nil, fmt.Errorf("配置未初始化")
	}

	utils.Info("[越权检测] 开始检测请求: %s %s", r.Request.Method, r.Request.URL.String())

	// 创建结果对象
	vulnResult := &Result{
		Method:   r.Request.Method,
		Url:      r.Request.URL.String(),
		VulnType: string(VulnPrivilegeEscalation),
		Result:   "unknown",
		ScanTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// 处理原始请求的响应体
	originalRespBody := r.Response.Body
	if originalRespBody == nil {
		utils.Warning("[越权检测] 原始响应体为空")
		return nil, fmt.Errorf("原始响应体为空")
	}

	// 处理原始响应体编码
	processedOrigBody, err := processResponseBody(originalRespBody, r.Response.Header.Get("Content-Type"))
	if err != nil {
		utils.Warning("[越权检测] 处理原始响应体失败: %v，使用原始响应体", err)
		processedOrigBody = originalRespBody
	}

	// 设置原始请求信息
	vulnResult.RequestA = formatRequest(r.Request)
	vulnResult.HeaderA = formatHeaders(r.Response.Header)
	vulnResult.RespBodyA = string(processedOrigBody)

	// 创建越权测试请求
	req2 := cloneRequest(r.Request)
	if req2 == nil {
		utils.Warning("[越权检测] 无法克隆请求，跳过测试")
		return nil, fmt.Errorf("无法克隆请求")
	}

	// 移除授权相关头部
	for _, header := range conf.UnauthorizedScan.RemoveHeaders {
		req2.Header.Del(header)
	}

	// 使用配置中的headers2替换
	for key, value := range conf.Headers2 {
		req2.Header.Set(key, value)
		utils.Debug("[越权检测] 设置headers2中的头: %s = %s", key, value)
	}

	// 设置越权测试请求信息
	vulnResult.RequestB = formatRequest(req2)

	// 发送越权测试请求
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req2)
	if err != nil {
		utils.Warning("[越权检测] 发送越权测试请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 读取越权测试请求的响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		utils.Warning("[越权检测] 读取越权测试响应体失败: %v", err)
		return nil, err
	}

	// 设置响应头
	vulnResult.HeaderB = formatHeaders(resp.Header)

	// 处理响应体编码
	processedBody, err := processResponseBody(respBody, resp.Header.Get("Content-Type"))
	if err != nil {
		utils.Warning("[越权检测] 处理越权测试响应体失败: %v，使用原始响应体", err)
		processedBody = respBody
	}

	// 保存处理后的响应体
	vulnResult.RespBodyB = string(processedBody)

	// 如果状态码是2xx，进行进一步分析
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 检测敏感数据
		if conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
			sensitivePatterns := make(map[string]string)
			for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
				sensitivePatterns[pattern.Name] = pattern.Pattern
			}
			vulnResult.SensitiveData = detectSensitiveDataWithDetails(string(processedBody), sensitivePatterns)

			if len(vulnResult.SensitiveData) > 0 {
				utils.Info("[越权检测] 发现敏感数据: %d 处", len(vulnResult.SensitiveData))
			}
		}

		// 计算响应相似度
		similarityScore, reason, vulnStatus := calculateResponseSimilarity(
			vulnResult.RespBodyA,
			string(processedBody),
			vulnResult.RequestA,
			resp.StatusCode,
		)

		utils.Info("[越权检测] 字符级别响应体相似度: %.4f", similarityScore)

		// 处理相似度结果
		if similarityScore >= conf.PrivilegeEscalationScan.SimilarityThreshold {
			hasSensitiveData := len(vulnResult.SensitiveData) > 0
			if hasSensitiveData && vulnStatus {
				vulnResult.Result = "true"
				vulnResult.Reason = fmt.Sprintf("【重要】%s (%.2f >= %.2f)且包含敏感数据",
					reason, similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold)
			} else if !vulnStatus {
				vulnResult.Result = "false"
				vulnResult.Reason = fmt.Sprintf("%s", reason)
			} else {
				// 计算响应相似度
				similarityScore, reason, vulnStatus := calculateAIResponseSimilarity(
					vulnResult.RespBodyA,
					string(processedBody),
					vulnResult.RequestA,
					resp.StatusCode,
				)

				vulnResult.Result = strconv.FormatBool(vulnStatus)
				vulnResult.Reason = fmt.Sprintf("【复测--->相似度：%.2f】%s ", similarityScore, reason)
			}
		} else {
			vulnResult.Result = "false"
			vulnResult.Reason = fmt.Sprintf("越权请求响应与原始响应相似度较低 %s (%.2f < %.2f)",
				reason, similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold)
		}
	} else {
		vulnResult.Result = "false"
		vulnResult.Reason = fmt.Sprintf("越权请求返回非标准状态码: %d", resp.StatusCode)
	}

	// 记录检测结果
	utils.Info("[越权检测] 检测完成: URL=%s, 结果=%s, 敏感数据数量=%d",
		vulnResult.Url, vulnResult.Result, len(vulnResult.SensitiveData))

	return vulnResult, nil
}

// calculateResponseSimilarity 计算响应相似度并在需要时使用AI分析
func calculateAIResponseSimilarity(respA, respB string, reqA string, respBStatus int) (float64, string, bool) {
	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		utils.Warning("[相似度计算] 配置对象为空")
		return 0.0, "[相似度计算] 配置对象为空", false
	}

	// 首先检查respB是否包含错误信息的特征
	for _, errorPattern := range conf.RespBodyBWhiteList {
		if strings.Contains(respB, errorPattern) {
			return 0.0, fmt.Sprintf("响应包含白名单错误信息: %s", errorPattern), false
		}
	}

	// 计算相似度 - 使用字符级别的 Levenshtein 距离算法
	similarityScore := similarity.CalculateSimilarity(respA, respB)
	utils.Debug("[AI相似度计算] 字符级别相似度计算结果: %.4f", similarityScore)
	utils.Debug("[AI相似度计算] 响应A长度: %d 字符, 响应B长度: %d 字符", len(respA), len(respB))

	// 如果相似度较低，提供更多调试信息
	if similarityScore < 0.5 {
		utils.Info("[AI相似度计算] 检测到显著差异，相似度: %.4f (< 0.5)", similarityScore)
		if len(respA) > 100 {
			utils.Debug("[AI相似度计算] 响应A前100字符: %s", respA[:100])
		} else {
			utils.Debug("[AI相似度计算] 响应A完整内容: %s", respA)
		}
		if len(respB) > 100 {
			utils.Debug("[AI相似度计算] 响应B前100字符: %s", respB[:100])
		} else {
			utils.Debug("[AI相似度计算] 响应B完整内容: %s", respB)
		}
	}

	// 检查是否包含敏感数据
	hasSensitiveData := hasSensitiveData(respB)

	// 如果相似度为1且没有敏感数据，尝试使用AI分析
	if similarityScore >= conf.PrivilegeEscalationScan.SimilarityThreshold && !hasSensitiveData && conf.EnableAI {
		utils.Info("[相似度计算] 相似度达到阈值且无敏感数据，尝试使用AI分析")
		// 越权检测的AI分析，传递越权漏洞类型
		result, err := AIAnalyzeResponse(reqA, respA, respB, respBStatus, similarityScore, false, string(VulnPrivilegeEscalation))
		if err == nil && result != nil {
			return similarityScore, result.Reason, result.Result == "true"
		} else {
			utils.Warning("[相似度计算] AI分析失败: %v", err)
		}
	}

	// AI没开的时候做个备用
	if similarityScore >= conf.PrivilegeEscalationScan.SimilarityThreshold {
		return similarityScore, fmt.Sprintf("响应相似度较高 (%.2f >= %.2f)",
			similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold), true
	}

	return similarityScore, fmt.Sprintf("响应相似度较低 (%.2f < %.2f)",
		similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold), false
}

func calculateResponseSimilarity(respA, respB string, reqA string, respBStatus int) (float64, string, bool) {
	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		utils.Warning("[相似度计算] 配置对象为空")
		return 0.0, "[相似度计算] 配置对象为空", false
	}

	// 首先检查respB是否包含错误信息的特征
	for _, errorPattern := range conf.RespBodyBWhiteList {
		if strings.Contains(respB, errorPattern) {
			return 0.0, fmt.Sprintf("响应包含白名单错误信息: %s", errorPattern), false
		}
	}

	// 计算相似度 - 使用字符级别的 Levenshtein 距离算法
	similarityScore := similarity.CalculateSimilarity(respA, respB)
	utils.Debug("[标准相似度计算] 字符级别相似度计算结果: %.4f", similarityScore)
	utils.Debug("[标准相似度计算] 响应A长度: %d 字符, 响应B长度: %d 字符", len(respA), len(respB))

	// 如果相似度较低，提供更多调试信息
	if similarityScore < 0.5 {
		utils.Info("[标准相似度计算] 检测到显著差异，相似度: %.4f (< 0.5)", similarityScore)
		if len(respA) > 100 {
			utils.Debug("[标准相似度计算] 响应A前100字符: %s", respA[:100])
		} else {
			utils.Debug("[标准相似度计算] 响应A完整内容: %s", respA)
		}
		if len(respB) > 100 {
			utils.Debug("[标准相似度计算] 响应B前100字符: %s", respB[:100])
		} else {
			utils.Debug("[标准相似度计算] 响应B完整内容: %s", respB)
		}
	}

	// 检查是否包含敏感数据
	// hasSensitiveData := hasSensitiveData(respB)

	// // 如果相似度为1且没有敏感数据，尝试使用AI分析
	// if similarityScore == 1.0 && !hasSensitiveData && conf.EnableAI {
	// 	utils.Info("[相似度计算] 相似度为1且无敏感数据，尝试使用AI分析")
	// 	result, err := AIAnalyzeResponse(reqA, respA, respB, respBStatus, similarityScore, false)
	// 	if err == nil && result != nil {
	// 		return similarityScore, result.Reason, result.Result == "true"
	// 	} else {
	// 		utils.Warning("[相似度计算] AI分析失败: %v", err)
	// 	}
	// }

	// 返回原始相似度结果
	if similarityScore >= conf.PrivilegeEscalationScan.SimilarityThreshold {
		return similarityScore, fmt.Sprintf("响应相似度较高 (%.2f >= %.2f)",
			similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold), true
	}

	return similarityScore, fmt.Sprintf("响应相似度较低 (%.2f < %.2f)",
		similarityScore, conf.PrivilegeEscalationScan.SimilarityThreshold), false
}

// hasSensitiveData 检查响应中是否包含敏感数据
func hasSensitiveData(response string) bool {
	conf := config.GetConfig()
	if conf == nil || !conf.UnauthorizedScan.SensitiveDataPatterns.Enabled {
		return false
	}

	// 检查JSON模式
	for _, pattern := range conf.UnauthorizedScan.SensitiveDataPatterns.JsonPatterns {
		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			utils.Warning("[敏感数据检测] 正则表达式编译失败: %v", err)
			continue
		}

		if re.MatchString(response) {
			return true
		}
	}

	return false
}

// 添加formatRequest函数，用于格式化请求
func formatRequest(req interface{}) string {
	switch r := req.(type) {
	case *http.Request:
		if r == nil {
			return ""
		}
		// 格式化HTTP请求，分离hostname和path
		var fullURL string
		if r.URL.RawQuery != "" {
			fullURL = r.URL.Path + "?" + r.URL.RawQuery
		} else {
			fullURL = r.URL.Path
		}
		requestLine := fmt.Sprintf("%s %s %s",
			r.Method,
			fullURL,
			r.Proto)

		// 创建一个新的Header来包含hostname
		headers := r.Header.Clone()
		if r.URL.Host != "" {
			headers.Set("Host", r.URL.Host)
		}

		// 添加请求头
		headersStr := formatHeaders(headers)

		// 完整的请求
		fullRequest := requestLine + "\n" + headersStr

		// 如果是POST/PUT/PATCH等方法，尝试读取并显示请求体
		if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
			// 读取请求体
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				fullRequest += "\n<读取请求体失败>"
			} else {
				// 重新设置请求体，这样后续处理还可以读取
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				// 添加请求体到输出
				fullRequest += "\n\n" + string(bodyBytes)
			}
		}

		return fullRequest

	case *proxy.Request:
		if r == nil {
			return ""
		}
		// 格式化代理请求，分离hostname和path
		var path string
		if r.URL != nil {
			parsedURL, err := url.Parse(r.URL.String())
			if err == nil {
				path = parsedURL.Path
				if parsedURL.RawQuery != "" {
					path += "?" + parsedURL.RawQuery
				}
			} else {
				path = r.URL.String()
			}
		}

		requestLine := fmt.Sprintf("%s %s %s",
			r.Method,
			path,
			r.Proto)

		// 创建一个新的Header来包含hostname
		headers := r.Header.Clone()
		if r.URL != nil {
			parsedURL, err := url.Parse(r.URL.String())
			if err == nil && parsedURL.Host != "" {
				headers.Set("Host", parsedURL.Host)
			}
		}

		// 添加请求头
		headersStr := formatHeaders(headers)

		// 完整的请求
		fullRequest := requestLine + "\n" + headersStr

		// 如果是POST/PUT/PATCH等方法，显示请求体
		if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
			fullRequest += "\n\n" + string(r.Body)
		}

		return fullRequest

	default:
		return ""
	}
}

// trimString 截取字符串到指定长度并添加省略号
func trimString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength] + "..."
}

// 优化响应体读取和处理函数
func readAndProcessResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("响应或响应体为空")
	}

	// 1. 首先读取整个响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	defer resp.Body.Close()

	// 记录原始响应信息
	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	contentType := resp.Header.Get("Content-Type")
	utils.Debug("[响应处理] Content-Type: %s, Content-Encoding: %s", contentType, contentEncoding)
	utils.Debug("[响应处理] 原始响应体长度: %d 字节", len(respBody))

	// 记录原始数据的前32字节（十六进制）
	hexPreview := ""
	for i := 0; i < min(len(respBody), 32); i++ {
		hexPreview += fmt.Sprintf("%02x ", respBody[i])
	}
	utils.Debug("[响应处理] 原始数据前32字节: %s", hexPreview)

	// 2. 处理压缩响应
	var decompressedBody []byte
	switch contentEncoding {
	case "gzip":
		reader, err := pgzip.NewReader(bytes.NewReader(respBody))
		if err != nil {
			utils.Warning("[响应处理] gzip解压失败: %v，尝试使用原始数据", err)
			decompressedBody = respBody
		} else {
			decompressedBody, err = io.ReadAll(reader)
			reader.Close()
			if err != nil {
				utils.Warning("[响应处理] 读取gzip解压数据失败: %v，使用原始数据", err)
				decompressedBody = respBody
			} else {
				utils.Debug("[响应处理] gzip解压成功，解压后长度=%d字节", len(decompressedBody))
			}
		}
	case "br":
		utils.Warning("[响应处理] 检测到br压缩，目前不支持br解压，将使用原始数据")
		decompressedBody = respBody
	case "zstd":
		utils.Warning("[响应处理] 检测到zstd压缩，目前不支持zstd解压，将使用原始数据")
		decompressedBody = respBody
	case "deflate":
		utils.Warning("[响应处理] 检测到deflate压缩，目前使用原始数据处理")
		decompressedBody = respBody
	default:
		utils.Debug("[响应处理] 未使用压缩或使用未知压缩方式")
		decompressedBody = respBody
	}

	// 3. 检查并处理BOM
	if len(decompressedBody) >= 3 && decompressedBody[0] == 0xEF && decompressedBody[1] == 0xBB && decompressedBody[2] == 0xBF {
		utils.Debug("[响应处理] 检测到并移除UTF-8 BOM")
		decompressedBody = decompressedBody[3:]
	}

	// 4. 处理字符集
	charset := extractCharset(contentType)
	utils.Debug("[响应处理] 检测到字符集: %s", charset)

	// 如果已经是有效的UTF-8，直接返回
	if utf8.Valid(decompressedBody) {
		utils.Debug("[响应处理] 响应体是有效的UTF-8编码")
		preview := string(decompressedBody)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		utils.Debug("[响应处理] 响应体预览: %s", preview)
		return decompressedBody, nil
	}

	// 5. 尝试转换编码
	decodedBody, err := tryDecodeBody(decompressedBody, charset)
	if err != nil {
		utils.Warning("[响应处理] 编码转换失败: %v，尝试其他编码方式", err)
		// 尝试其他常见编码
		for _, tryCharset := range []string{"gbk", "gb18030", "big5", "shift-jis", "euc-jp"} {
			if tryCharset != charset {
				utils.Debug("[响应处理] 尝试使用 %s 编码", tryCharset)
				if decoded, err := tryDecodeBody(decompressedBody, tryCharset); err == nil {
					utils.Debug("[响应处理] 使用 %s 编码成功", tryCharset)
					decodedBody = decoded
					break
				}
			}
		}

		// 如果所有编码都失败了，使用原始数据
		if decodedBody == nil {
			utils.Warning("[响应处理] 所有编码转换都失败，使用原始数据")
			decodedBody = decompressedBody
		}
	}

	// 6. 验证处理后的响应体
	if len(decodedBody) > 0 {
		utils.Debug("[响应处理] 处理后响应体长度: %d 字节", len(decodedBody))
		if utf8.Valid(decodedBody) {
			utils.Debug("[响应处理] 处理后响应体是有效的UTF-8编码")
			preview := string(decodedBody)
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}
			utils.Debug("[响应处理] 最终响应体预览: %s", preview)
		} else {
			utils.Warning("[响应处理] 处理后响应体不是有效的UTF-8编码")
			// 记录一些十六进制数据以供调试
			hexPreview = ""
			for i := 0; i < min(len(decodedBody), 32); i++ {
				hexPreview += fmt.Sprintf("%02x ", decodedBody[i])
			}
			utils.Debug("[响应处理] 处理后数据前32字节: %s", hexPreview)
		}
	}

	return decodedBody, nil
}

// 提取字符集信息
func extractCharset(contentType string) string {
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "charset=") {
		charsetParts := strings.Split(contentType, "charset=")
		if len(charsetParts) > 1 {
			charset := strings.Split(charsetParts[1], ";")[0]
			return strings.TrimSpace(charset)
		}
	}
	return "utf-8"
}

// 尝试解码响应体
func tryDecodeBody(body []byte, charset string) ([]byte, error) {
	// 检查并移除BOM
	if len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF {
		utils.Debug("[编码转换] 检测到并移除UTF-8 BOM")
		body = body[3:]
	}

	// 如果已经是UTF-8且有效，直接返回
	if charset == "utf-8" && utf8.Valid(body) {
		utils.Debug("[编码转换] 已经是有效的UTF-8编码，无需转换")
		return body, nil
	}

	// 记录原始数据信息
	utils.Debug("[编码转换] 开始转换编码，原始长度=%d字节，目标字符集=%s", len(body), charset)
	hexPreview := ""
	for i := 0; i < min(len(body), 32); i++ {
		hexPreview += fmt.Sprintf("%02x ", body[i])
	}
	utils.Debug("[编码转换] 原始数据前32字节: %s", hexPreview)

	// 尝试常见编码
	var decodedBody []byte
	var err error

	// 规范化字符集名称
	charset = strings.ToLower(charset)
	charset = strings.ReplaceAll(charset, "-", "")
	charset = strings.ReplaceAll(charset, "_", "")

	// 根据字符集选择解码器
	switch charset {
	case "gbk", "gb2312", "gb18030":
		utils.Debug("[编码转换] 使用GBK/GB18030解码器")
		if decodedBody, err = simplifiedchinese.GBK.NewDecoder().Bytes(body); err == nil {
			utils.Debug("[编码转换] GBK解码成功")
			return decodedBody, nil
		}
		utils.Warning("[编码转换] GBK解码失败: %v", err)

		// 尝试GB18030
		if decodedBody, err = simplifiedchinese.GB18030.NewDecoder().Bytes(body); err == nil {
			utils.Debug("[编码转换] GB18030解码成功")
			return decodedBody, nil
		}
		utils.Warning("[编码转换] GB18030解码失败: %v", err)

	case "big5", "big5hkscs":
		utils.Debug("[编码转换] 使用Big5解码器")
		if decodedBody, err = traditionalchinese.Big5.NewDecoder().Bytes(body); err == nil {
			utils.Debug("[编码转换] Big5解码成功")
			return decodedBody, nil
		}
		utils.Warning("[编码转换] Big5解码失败: %v", err)

	case "shiftjis", "sjis":
		utils.Debug("[编码转换] 使用Shift-JIS解码器")
		if decodedBody, err = japanese.ShiftJIS.NewDecoder().Bytes(body); err == nil {
			utils.Debug("[编码转换] Shift-JIS解码成功")
			return decodedBody, nil
		}
		utils.Warning("[编码转换] Shift-JIS解码失败: %v", err)

	case "eucjp":
		utils.Debug("[编码转换] 使用EUC-JP解码器")
		if decodedBody, err = japanese.EUCJP.NewDecoder().Bytes(body); err == nil {
			utils.Debug("[编码转换] EUC-JP解码成功")
			return decodedBody, nil
		}
		utils.Warning("[编码转换] EUC-JP解码失败: %v", err)

	case "euckr":
		utils.Debug("[编码转换] 使用EUC-KR解码器")
		if decodedBody, err = korean.EUCKR.NewDecoder().Bytes(body); err == nil {
			utils.Debug("[编码转换] EUC-KR解码成功")
			return decodedBody, nil
		}
		utils.Warning("[编码转换] EUC-KR解码失败: %v", err)

	case "", "utf8", "utf-8":
		utils.Debug("[编码转换] 尝试UTF-8编码")
		if utf8.Valid(body) {
			utils.Debug("[编码转换] 有效的UTF-8编码")
			return body, nil
		}
		utils.Warning("[编码转换] 无效的UTF-8编码")

	default:
		utils.Warning("[编码转换] 未知或不支持的字符集: %s", charset)
	}

	// 如果指定的编码转换失败，尝试自动检测
	if !utf8.Valid(body) {
		utils.Debug("[编码转换] 尝试自动检测编码")

		// 尝试检测中文编码
		if isGBK(body) {
			utils.Debug("[编码转换] 检测到可能是GBK编码，尝试转换")
			if decodedBody, err = simplifiedchinese.GBK.NewDecoder().Bytes(body); err == nil {
				utils.Debug("[编码转换] GBK自动检测转换成功")
				return decodedBody, nil
			}
		}

		// 可以添加更多的编码检测逻辑
	}

	return body, fmt.Errorf("无法找到合适的编码方式")
}

// AIAnalyzeResponse 封装AI分析响应的逻辑
func AIAnalyzeResponse(reqA, respA, respB string, respBStatus int, similarityScore float64, hasSensitiveData bool, vulnType string) (*Result, error) {
	// 获取配置
	conf := config.GetConfig()
	if conf == nil {
		return nil, fmt.Errorf("配置对象为空")
	}

	// 检查AI是否启用
	if !conf.EnableAI {
		return nil, fmt.Errorf("AI功能未启用")
	}

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
	case "other":
		apiUrl = conf.AIAPI
		apiKey = conf.APIKeys.Other
	default:
		apiUrl = "https://api.deepseek.com/v1/chat/completions"
		apiKey = conf.APIKeys.DeepSeek
		aiType = "deepseek"
	}

	// 获取模型名称
	modelName := conf.AIMODEL
	if modelName == "" {
		modelName = AICheck.GetModelNameByAIType(aiType)
	}

	// 调用AI分析
	aiResult, err := AICheck.AIScan(
		modelName,
		apiUrl,
		apiKey,
		reqA,
		respA,
		respB,
		fmt.Sprintf("%d", respBStatus),
	)

	if err != nil {
		utils.Warning("[AI分析] 分析失败: %v", err)
		return nil, err
	}

	// 解析AI返回的结果
	var aiResponse struct {
		Res    string `json:"res"`
		Reason string `json:"reason"`
	}

	// 解析AI响应
	err = json.Unmarshal([]byte(aiResult), &aiResponse)
	if err != nil {
		utils.Warning("[AI分析] 解析结果失败: %v", err)
		return nil, err
	}

	// 创建结果对象，确保继承原始检测的VulnType
	result := &Result{
		Result:   aiResponse.Res,
		Reason:   fmt.Sprintf("[AI分析] %s", aiResponse.Reason),
		VulnType: vulnType, // ✅ 继承原始检测的漏洞类型
	}

	utils.Debug("[AI分析] 分析完成，VulnType: %s, Result: %s", vulnType, aiResponse.Res)
	return result, nil
}
