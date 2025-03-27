package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"yuequanScan/config"
	"yuequanScan/utils"

	"github.com/gin-gonic/gin"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
)

// 确保 Result 类型在全局范围内可用
type Result struct {
	Method        string   `json:"method"`
	Url           string   `json:"url"`
	RequestA      string   `json:"requestA"`
	RequestB      string   `json:"requestB"`
	HeaderA       string   `json:"headerA"`
	HeaderB       string   `json:"headerB"`
	RespBodyA     string   `json:"respBodyA"`
	RespBodyB     string   `json:"respBodyB"`
	Result        string   `json:"result"`
	Reason        string   `json:"reason"`
	VulnType      string   `json:"vulnType"`
	Similarity    float64  `json:"similarity"`
	Differences   []string `json:"differences"`
	SensitiveData []string `json:"sensitiveData,omitempty"` // 检测到的敏感数据类型
	ScanTime      string   `json:"scanTime"`                // 添加扫描时间字段
}

// 全局变量，用于存储请求日志
var logs sync.Map
var logCount int64 // 添加计数器

// 报告生成器
var reportGenerator *utils.ReportGenerator

// 工作池
var workerPool *utils.WorkerPool

// Resp 数据存储
var Resp = []Result{} // 初始化为空数组，而不是nil

// RequestResponseLog 存储请求和响应日志
type RequestResponseLog struct {
	Request            *proxy.Request
	Response           *proxy.Response
	ReceivedAt         time.Time
	Processed          bool
	ConnectRequest     bool
	ResponseReceivedAt time.Time
	ResponseReceived   bool
	ResponseTime       int64
}

// 生成请求的唯一ID
func getRequestId(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}

	// 采用更可靠的ID生成方式: 时间戳 + URL + 随机数
	timestamp := time.Now().UnixNano()
	randomPart := rand.Intn(1000)

	// 构建包含更多信息的ID
	fullUrl := fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path)
	method := r.Method

	// 计算哈希值作为请求ID
	idStr := fmt.Sprintf("%s-%s-%d-%d", method, fullUrl, timestamp, randomPart)

	// 长度限制可能导致哈希碰撞，这里保留足够长度
	return idStr
}

// main 启动程序的主函数
func main() {
	// 解析命令行参数
	args := utils.ParseCommandLine()

	// 初始化配置
	if err := config.InitConfig(args.ConfigFile); err != nil {
		fmt.Printf("初始化配置失败: %v\n", err)
		os.Exit(1)
	}

	conf := config.GetConfig()

	// 初始化日志系统
	logLevel := conf.Log.Level
	if args.LogLevel != "" {
		logLevel = args.LogLevel
	}

	if err := utils.InitLogger(logLevel, conf.Log.EnableFile || args.LogToFile); err != nil {
		fmt.Printf("初始化日志系统失败: %v\n", err)
		os.Exit(1)
	}
	defer utils.Close()

	utils.Info("AIFuzzing 启动中...")

	// 检查golang.org/x/text包是否已安装
	checkDependencies()

	// 初始化工作池
	workerPool = utils.NewWorkerPool(conf.Performance.MaxConcurrentScans)
	workerPool.Start()

	// 初始化报告生成器
	reportGenerator = utils.NewReportGenerator(conf.Output.ReportDirectory)

	// 设置信号处理，优雅关闭
	setupSignalHandler()

	// 启动各个组件
	utils.Info("启动各组件...")

	// 如果启用了Web界面
	if conf.Output.EnableWebUI && !args.DisableWebUI {
		go index(conf.Output.WebUIPort) // Web界面
	}

	go mitmproxy(conf.Proxy.Port, conf.Proxy.StreamLargeBodies) // 代理服务

	scan() // 扫描功能
}

// 检查依赖是否已安装
func checkDependencies() {
	textVersion := "v0.3.8" // 适合的版本

	// 仅在开发环境下检查并安装依赖，避免在生产环境中执行
	if _, err := os.Stat("go.mod"); err == nil {
		utils.Info("检测到go.mod文件，检查所需依赖...")

		// 检查是否已安装golang.org/x/text
		cmd := exec.Command("go", "list", "-m", "golang.org/x/text")
		output, err := cmd.CombinedOutput()

		if err != nil || !strings.Contains(string(output), "golang.org/x/text") {
			utils.Warning("未检测到golang.org/x/text，正在自动安装...")
			installCmd := exec.Command("go", "get", "golang.org/x/text@"+textVersion)
			if installErr := installCmd.Run(); installErr != nil {
				utils.Error("安装golang.org/x/text失败: %v", installErr)
			} else {
				utils.Info("golang.org/x/text安装成功")
			}
		} else {
			utils.Info("已安装golang.org/x/text")
		}
	}
}

// 设置信号处理，优雅关闭
func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		utils.Info("接收到中断信号，开始优雅关闭...")

		// 停止工作池
		if workerPool != nil {
			workerPool.Stop()
		}

		// 生成报告
		if reportGenerator != nil && config.GetConfig().Output.EnableReportFile {
			format := config.GetConfig().Output.ReportFormat
			utils.Info("正在生成最终报告，格式: %s", format)
			if filepath, err := reportGenerator.GenerateReport(format); err != nil {
				utils.Error("生成报告失败: %v", err)
			} else {
				utils.Info("报告已保存至: %s", filepath)
			}
		}

		utils.Info("AIFuzzing 已安全关闭")
		os.Exit(0)
	}()
}

// index 启动Web界面服务
func index(port int) {
	webPort := 8222 // 默认端口
	if port > 0 {
		webPort = port
	}

	utils.Info("启动Web界面服务, 端口: %d", webPort)

	// 设置为发布模式，减少日志输出
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	// 提供前端静态文件服务
	r.LoadHTMLFiles("index.html") // 加载前端页面
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// 提供 API 接口
	r.GET("/data", func(c *gin.Context) {
		utils.Warning("[Web接口] 接收到/data请求，当前结果数: %d", len(Resp))

		// 获取分页参数
		pageStr := c.DefaultQuery("page", "1")
		pageSizeStr := c.DefaultQuery("pageSize", "10")
		
		page, err := strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			page = 1
		}
		
		pageSize, err := strconv.Atoi(pageSizeStr)
		if err != nil || pageSize < 1 || pageSize > 100 {
			pageSize = 10
		}

		// 确保永远返回数组
		if len(Resp) == 0 {
			c.JSON(http.StatusOK, []Result{})
			return
		}

		// 对结果进行去重
		deduplicatedResults := deduplicateResults(Resp)
		utils.Info("[Web接口] 原始结果数: %d, 去重后结果数: %d", len(Resp), len(deduplicatedResults))

		c.JSON(http.StatusOK, deduplicatedResults)
	})

	r.POST("/update", func(c *gin.Context) {
		var newData Result
		if err := c.ShouldBindJSON(&newData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		Resp = append(Resp, newData)

		// 同时添加到报告生成器
		if reportGenerator != nil {
			reportGenerator.AddResult(newData)
		}

		c.JSON(http.StatusOK, gin.H{"message": "数据更新成功"})
	})

	r.POST("/filter", func(c *gin.Context) {
		var filterData struct {
			Result   string `json:"result"`
			VulnType string `json:"vulnType"`
		}
		if err := c.ShouldBindJSON(&filterData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		filteredData := []Result{}
		for _, item := range Resp {
			// 根据结果和漏洞类型进行过滤
			if (filterData.Result == "" || item.Result == filterData.Result) &&
				(filterData.VulnType == "" || string(item.VulnType) == filterData.VulnType) {
				filteredData = append(filteredData, item)
			}
		}
		c.JSON(http.StatusOK, filteredData)
	})

	// 添加按漏洞类型过滤的API
	r.GET("/vulntypes", func(c *gin.Context) {
		vulnTypes := map[string]string{
			"privilege_escalation": "越权漏洞",
			"unauthorized_access":  "未授权访问",
		}
		c.JSON(http.StatusOK, vulnTypes)
	})

	// 添加扫描统计API
	r.GET("/stats", func(c *gin.Context) {
		// 计算统计数据
		var totalVulnerabilities, totalUnknown, totalSafe int
		for _, item := range Resp {
			switch item.Result {
			case "true":
				totalVulnerabilities++
			case "unknown":
				totalUnknown++
			case "false":
				totalSafe++
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"total":      len(Resp),
			"vulnerable": totalVulnerabilities,
			"unknown":    totalUnknown,
			"safe":       totalSafe,
		})
	})

	// 添加生成报告API
	r.GET("/report/:format", func(c *gin.Context) {
		if reportGenerator == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "报告生成器未初始化"})
			return
		}

		format := c.Param("format")
		if format == "" {
			format = "HTML"
		}

		filepath, err := reportGenerator.GenerateReport(format)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "报告生成成功",
			"filepath": filepath,
		})
	})

	// 添加清除数据API
	r.POST("/clear", func(c *gin.Context) {
		Resp = []Result{}
		c.JSON(http.StatusOK, gin.H{"message": "数据已清除"})
	})

	// 添加直接下载报告的接口
	r.GET("/download-report", func(c *gin.Context) {
		filepath := c.Query("file")
		if filepath == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "未指定文件"})
			return
		}

		// 安全检查：确保文件路径在reports目录下
		if !strings.HasPrefix(filepath, "./reports/") && !strings.HasPrefix(filepath, "reports/") {
			c.JSON(http.StatusForbidden, gin.H{"error": "非法的文件路径"})
			return
		}

		// 检查文件是否存在
		if _, err := os.Stat(filepath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "文件不存在"})
			return
		}

		// 获取文件名
		_, filename := path.Split(filepath)
		if filename == "" {
			filename = "vulnerability_report.html"
		}

		// 设置文件类型和下载标志
		c.Header("Content-Description", "File Transfer")
		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Transfer-Encoding", "binary")
		c.Header("Cache-Control", "no-cache")

		// 提供文件下载
		c.File(filepath)
	})

	// 启动服务
	portStr := ":" + strconv.Itoa(webPort)
	utils.Info("Web界面服务运行中，访问 http://127.0.0.1%s", portStr)
	if err := r.Run(portStr); err != nil {
		utils.Error("Web界面服务启动失败: %v", err)
	}
}

// MyAddon 继承了 proxy.BaseAddon
type MyAddon struct {
	proxy.BaseAddon
	requestCount int // 添加请求计数器
}

// Request 方法处理 HTTP 请求
func (a *MyAddon) Request(f *proxy.Flow) {
	// 创建并记录请求日志
	logEntry := &RequestResponseLog{
		Request:    f.Request,
		Processed:  false,      // 初始化为未处理
		ReceivedAt: time.Now(), // 记录接收时间
	}
	// 使用 Flow ID 作为键，将请求日志存入 sync.Map
	logs.Store(f.Id, logEntry)
	utils.Debug("[请求跟踪] 存储请求 ID=%s, 方法=%s, URL=%s, 时间=%s",
		f.Id, f.Request.Method, f.Request.URL, logEntry.ReceivedAt.Format("15:04:05.000"))
}

// Response 方法处理 HTTP 响应
func (a *MyAddon) Response(flow *proxy.Flow) {
	// 使用flow.Id作为键，确保与Request方法使用相同的键
	reqID := flow.Id

	// 从日志映射中获取请求记录
	value, ok := logs.Load(reqID)
	if !ok {
		// 如果找不到对应的请求记录，输出警告
		utils.Warning("[响应处理] 找不到对应的请求记录: %s", reqID)
		return
	}

	// 获取RequestResponseLog对象
	rr, ok := value.(*RequestResponseLog)
	if !ok {
		utils.Warning("[响应处理] 值类型不是RequestResponseLog: %s", reqID)
		return
	}

	// 检查是否已处理过此响应
	if rr.ResponseReceived {
		// 已接收过响应，避免重复处理
		return
	}

	// 设置响应标志，避免重复处理
	rr.ResponseReceived = true
	rr.ResponseReceivedAt = time.Now()

	// 处理CONNECT响应
	if flow.Request.Method == "CONNECT" {
		rr.ConnectRequest = true
		rr.Processed = true
		logs.Store(reqID, rr)
		return
	}

	// 设置响应
	rr.Response = flow.Response

	// 计算响应时间
	if !rr.ReceivedAt.IsZero() {
		rr.ResponseTime = time.Since(rr.ReceivedAt).Milliseconds()
	}

	// 检查是否为静态资源或被过滤的内容类型
	isFiltered := false
	if flow.Response != nil && flow.Response.Header != nil {
		contentType := flow.Response.Header.Get("Content-Type")

		// 只在详细日志模式下记录详细的响应信息
		if contentType != "" {
			// 使用utils.Debug函数本身的日志级别判断
			// 每1000个请求只记录1个普通请求的类型，减少日志量
			if rand.Intn(1000) == 0 {
				utils.Debug("[响应] 请求ID=%s, URL=%s, ContentType=%s",
					reqID, flow.Request.URL.String(), contentType)
			}

			// 对于特殊请求，仍然保持较高的日志频率
			if strings.Contains(flow.Request.URL.Path, "/admin") ||
				strings.Contains(flow.Request.URL.Path, "/api") {
				utils.Debug("[重要响应] 请求ID=%s, URL=%s, ContentType=%s",
					reqID, flow.Request.URL.String(), contentType)
			}
		}

		// 检查是否为静态资源
		conf := config.GetConfig()
		for _, ext := range conf.Suffixes {
			if strings.HasSuffix(flow.Request.URL.Path, ext) {
				rr.Processed = true
				isFiltered = true
				// 每1000个静态资源只记录1个，降低日志量
				if rand.Intn(1000) == 0 {
					utils.Debug("[响应] 检测到静态资源: %s", flow.Request.URL.Path)
				}
				break
			}
		}

		// 检查是否为过滤的内容类型
		if !isFiltered {
			for _, ct := range conf.AllowedRespHeaders {
				if strings.Contains(contentType, ct) {
					rr.Processed = true
					isFiltered = true
					break
				}
			}
		}
	}

	// 保存更新后的记录，但不删除
	utils.Debug("[响应处理] 成功关联请求和响应: ID=%s, URL=%s",
		reqID, flow.Request.URL.String())
	logs.Store(reqID, rr)
}

// Error 方法处理代理过程中的错误
func (a *MyAddon) Error(f *proxy.Flow) {
	// 增强错误日志，特别是TLS相关错误
	utils.Error("代理请求处理发生错误, ID=%s, URL=%s", f.Id, f.Request.URL)

	// 检查证书路径
	certPath := os.ExpandEnv("${HOME}/.mitmproxy/mitmproxy-ca-cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		utils.Error("证书文件异常: %v, 路径: %s", err, certPath)
	} else {
		utils.Debug("证书文件存在: %s", certPath)
	}

	// 提示常见的TLS错误解决方案
	utils.Info("如果您看到TLS证书错误，请尝试以下步骤:")
	utils.Info("1. 确保已经正确下载并安装了证书")
	utils.Info("2. 对于macOS，确保已将证书添加到钥匙串并信任")
	utils.Info("3. 对于iOS/Android设备，确保已在设备设置中信任该证书")
	utils.Info("4. 某些应用可能使用证书锁定(SSL Pinning)技术，可能需要额外的配置")
}

// mitmproxy 启动代理服务
func mitmproxy(port int, streamLargeBodies int) {
	portStr := ":9080" // 默认端口
	if port > 0 {
		portStr = ":" + strconv.Itoa(port)
	}

	utils.Info("启动mitmproxy代理服务, 端口: %s", portStr)
	utils.Info("当前工作目录: %s", getCwd())

	// 增强调试信息，打印当前系统信息
	utils.Info("系统信息: %s", getSystemInfo())

	// 增加更多调试选项
	opts := &proxy.Options{
		Addr:              portStr,
		StreamLargeBodies: int64(streamLargeBodies),
		Debug:             1,
	}

	utils.Info("代理服务配置已完成")

	p, err := proxy.NewProxy(opts)
	if err != nil {
		utils.Error("创建代理服务失败: %v", err)
		return
	}

	// 检查证书路径和权限
	certPath := os.ExpandEnv("${HOME}/.mitmproxy/mitmproxy-ca-cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		utils.Error("证书文件问题: %v", err)
		utils.Error("请确保证书存在于路径: %s", certPath)
		utils.Info("您可能需要手动创建证书，或先运行一次标准的mitmproxy来生成证书")
	} else {
		utils.Info("证书文件已找到: %s", certPath)
		// 尝试读取证书内容以验证权限
		if certData, err := os.ReadFile(certPath); err != nil {
			utils.Error("无法读取证书文件: %v", err)
		} else {
			utils.Info("证书文件可读，长度: %d bytes", len(certData))
		}
	}

	// 添加多个实例进行调试
	p.AddAddon(&MyAddon{})             // 添加 MyAddon
	p.AddAddon(&DebugAddon{})          // 添加调试专用Addon
	p.AddAddon(&NetworkMonitorAddon{}) // 添加网络监视Addon

	utils.Info("代理服务运行中...")
	utils.Info("要拦截HTTPS流量，请下载并安装证书:")
	utils.Info("1. 设置设备代理为 127.0.0.1%s", portStr)
	utils.Info("2. 访问 http://mitm.it 或 http://127.0.0.1%s/cert 下载证书", portStr)
	utils.Info("3. 按照提示安装证书到您的设备")
	utils.Info("4. 对于macOS，请确保在钥匙串中将证书设置为\"始终信任\"")
	utils.Info("5. 请确保您的设备或浏览器已正确配置代理设置")

	// 启动代理前再次检查代理状态
	checkProxyStatus(portStr)

	// 启动一个监视线程，监视网络连接
	go monitorNetworkConnections(portStr)

	if err := p.Start(); err != nil {
		utils.Error("代理服务启动失败: %v", err)
		return
	}
}

// 获取当前工作目录
func getCwd() string {
	dir, err := os.Getwd()
	if err != nil {
		return "未知"
	}
	return dir
}

// 获取系统信息
func getSystemInfo() string {
	return fmt.Sprintf("OS: %s, ARCH: %s", runtime.GOOS, runtime.GOARCH)
}

// 检查代理状态
func checkProxyStatus(port string) {
	utils.Info("正在检查代理端口 %s 状态...", port)

	// 检查端口是否被占用
	l, err := net.Listen("tcp", port)
	if err != nil {
		utils.Warning("端口%s已被占用: %v", port, err)
		utils.Info("建议检查是否有其他代理程序正在运行")
	} else {
		utils.Info("端口%s可用，代理将正常启动", port)
		l.Close()
	}

	// 打印当前系统代理设置
	utils.Info("请确保您的系统或浏览器代理设置为 127.0.0.1%s", port)
}

// DebugAddon 专用于调试的Addon
type DebugAddon struct {
	proxy.BaseAddon
}

// 在每个阶段都添加调试日志
func (a *DebugAddon) Requestheaders(f *proxy.Flow) {
	utils.Debug("DebugAddon: 接收到请求头 - %s %s", f.Request.Method, f.Request.URL)
}

func (a *DebugAddon) Request(f *proxy.Flow) {
	utils.Debug("DebugAddon: 完整请求已处理 - %s %s", f.Request.Method, f.Request.URL)
}

func (a *DebugAddon) Responseheaders(f *proxy.Flow) {
	utils.Debug("DebugAddon: 接收到响应头 - %s %s, 状态码: %d",
		f.Request.Method, f.Request.URL, f.Response.StatusCode)
}

func (a *DebugAddon) Response(f *proxy.Flow) {
	utils.Debug("DebugAddon: 完整响应已处理 - %s %s, 状态码: %d",
		f.Request.Method, f.Request.URL, f.Response.StatusCode)
}

func (a *DebugAddon) Error(f *proxy.Flow) {
	utils.Error("DebugAddon: 处理错误 - %s %s", f.Request.Method, f.Request.URL)
}

// NetworkMonitorAddon 专用于监控网络连接的Addon
type NetworkMonitorAddon struct {
	proxy.BaseAddon
	lastActiveTime time.Time
}

func (a *NetworkMonitorAddon) Request(f *proxy.Flow) {
	a.lastActiveTime = time.Now()
	utils.Info("NetworkMonitor: 收到请求 - %s %s", f.Request.Method, f.Request.URL)
}

func (a *NetworkMonitorAddon) Response(f *proxy.Flow) {
	a.lastActiveTime = time.Now()
	utils.Info("NetworkMonitor: 收到响应 - %s %s, 状态码: %d",
		f.Request.Method, f.Request.URL, f.Response.StatusCode)
}

func (a *NetworkMonitorAddon) Error(f *proxy.Flow) {
	utils.Info("NetworkMonitor: 处理错误 - %s %s", f.Request.Method, f.Request.URL)
}

// 监视网络连接状态
func monitorNetworkConnections(portStr string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// 检查当前连接数量
		conns, err := getNetConnections(portStr)
		if err != nil {
			utils.Warning("无法获取网络连接信息: %v", err)
			continue
		}

		utils.Info("当前代理端口%s的活动连接数: %d", portStr, len(conns))

		// 如果没有连接，提示用户
		if len(conns) == 0 {
			utils.Warning("当前没有活动连接到代理，请检查客户端配置")
			utils.Info("请尝试以下命令测试代理: curl -v --proxy 127.0.0.1%s http://example.com", portStr)
		}
	}
}

// 获取网络连接信息
func getNetConnections(portStr string) ([]string, error) {
	// 这里只是一个简化实现，实际上我们应该使用系统命令或库来获取连接信息
	// 但为了简单，我们只返回一个空列表
	return []string{}, nil
}

// scan 启动扫描服务，此为主入口
func scan() {
	InitScanService()
	// 调用scan.go中的实际实现
	ScanImpl()
}

// Response 处理响应
func (a *MyAddon) ResponseProcessor(r *http.Response) error {
	// 获取响应对应的请求ID
	reqId := getRequestId(r.Request)
	if reqId == "" {
		utils.Debug("[响应处理] 无法获取请求ID，可能是内部请求")
		return nil
	}

	// 从日志映射中获取请求日志
	value, ok := logs.Load(reqId)
	if !ok {
		utils.Warning("[响应处理] 找不到请求日志: %s", reqId)
		return nil
	}

	// 获取请求日志
	reqLog, ok := value.(*RequestResponseLog)
	if !ok {
		utils.Warning("[响应处理] 值类型不是RequestResponseLog: %s", reqId)
		return nil
	}

	// 计算请求和响应之间的时间差
	responseTime := time.Since(reqLog.ReceivedAt)

	// 处理响应头
	respHeaders := make(http.Header)
	for k, v := range r.Header {
		respHeaders[k] = v
	}

	// 生成响应结构体
	var respBody []byte
	var err error

	// 读取响应体
	if r.Body != nil {
		respBody, err = io.ReadAll(r.Body)
		if err != nil {
			utils.Warning("[响应处理] 读取响应体失败: %v", err)
		}

		// 重置响应体，以便其他处理器使用
		r.Body = io.NopCloser(bytes.NewBuffer(respBody))
	}

	// 更新请求日志
	reqLog.Response = &proxy.Response{
		StatusCode: r.StatusCode,
		Header:     respHeaders,
		Body:       respBody,
	}

	// 记录状态码和响应时间
	utils.Debug("[响应处理] 处理响应: URL=%s, 方法=%s, 状态码=%d, 响应时间=%s",
		r.Request.URL.String(), r.Request.Method, r.StatusCode, responseTime)

	// 记录头部信息
	contentType := r.Header.Get("Content-Type")
	contentLength := r.Header.Get("Content-Length")
	utils.Debug("[响应处理] 响应头信息: Content-Type=%s, Content-Length=%s",
		contentType, contentLength)

	// 检查响应体长度
	if respBody != nil {
		utils.Debug("[响应处理] 响应体长度: %d 字节", len(respBody))
	} else {
		utils.Debug("[响应处理] 响应体为空")
	}

	// 判断是否是静态资源
	path := r.Request.URL.Path
	conf := config.GetConfig()
	isStatic := false
	for _, suffix := range conf.Suffixes {
		if strings.HasSuffix(strings.ToLower(path), strings.ToLower(suffix)) {
			isStatic = true
			break
		}
	}

	// 判断是否是过滤的内容类型
	isFilteredContent := false
	if contentType != "" {
		for _, allowedType := range conf.AllowedRespHeaders {
			if strings.Contains(strings.ToLower(contentType), strings.ToLower(allowedType)) {
				isFilteredContent = true
				break
			}
		}
	}

	// 记录请求分类
	if isStatic {
		utils.Debug("[响应处理] 静态资源: %s", path)
	} else if isFilteredContent {
		utils.Debug("[响应处理] 过滤内容类型: %s, Content-Type=%s", path, contentType)
	} else {
		utils.Debug("[响应处理] 潜在API请求: %s, Content-Type=%s", path, contentType)
	}

	// 仅标记静态资源和过滤内容类型为已处理，但不删除
	if isStatic || isFilteredContent {
		reqLog.Processed = true
		utils.Debug("[响应处理] 标记为已处理 (静态=%v, 过滤=%v): %s",
			isStatic, isFilteredContent, r.Request.URL.String())
	}

	// 重要：不再删除日志条目，让scan.go中的清理机制来处理
	// 原有代码: logs.Delete(reqId)

	return nil
}

// Request 处理请求
func (a *MyAddon) RequestProcessor(r *http.Request) error {
	// 记录请求计数
	a.requestCount++

	// 获取请求ID
	reqId := getRequestId(r)
	if reqId == "" {
		utils.Debug("[请求处理] 无法获取请求ID，可能是内部请求")
		return nil
	}

	// 处理请求头
	reqHeaders := make(http.Header)
	for k, v := range r.Header {
		reqHeaders[k] = v
	}

	// 读取请求体
	var reqBody []byte
	var err error
	if r.Body != nil {
		reqBody, err = io.ReadAll(r.Body)
		if err != nil {
			utils.Warning("[请求处理] 读取请求体失败: %v", err)
		}

		// 重置请求体，以便其他处理器使用
		r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	}

	// 创建请求日志
	reqLog := &RequestResponseLog{
		Request: &proxy.Request{
			Method: r.Method,
			URL:    r.URL,
			Header: reqHeaders,
			Body:   reqBody,
		},
		ReceivedAt: time.Now(),
		Processed:  false,
	}

	// 存储请求日志
	logs.Store(reqId, reqLog)

	// 记录请求信息
	contentType := r.Header.Get("Content-Type")
	contentLength := r.Header.Get("Content-Length")
	utils.Debug("[请求处理] 新请求 #%d: %s %s, Content-Type=%s, Content-Length=%s, ID=%s",
		a.requestCount, r.Method, r.URL.String(), contentType, contentLength, reqId)

	// 检查是否有认证信息
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// 记录认证头但截断以保护敏感信息
		utils.Debug("[请求处理] 包含认证信息: Authorization=%s", TruncateString(authHeader, 20))
	}

	// 检查Cookie
	cookie := r.Header.Get("Cookie")
	if cookie != "" {
		utils.Debug("[请求处理] 包含Cookie: %s", TruncateString(cookie, 30))
	}

	return nil
}

// TruncateString 截断字符串到指定长度，并添加省略号
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// deduplicateResults 去重函数
func deduplicateResults(results []Result) []Result {
	// 第一步：按Method+URL+VulnType分组
	groupedResults := make(map[string][]Result)

	for _, result := range results {
		// 使用Method、URL和漏洞类型作为分组键
		key := fmt.Sprintf("%s-%s-%s", result.Method, result.Url, result.VulnType)
		groupedResults[key] = append(groupedResults[key], result)
	}

	// 第二步：对每组结果选择最优结果
	deduplicatedResults := []Result{}

	for _, group := range groupedResults {
		if len(group) == 0 {
			continue
		}

		// 按结果优先级排序：true > unknown > false
		var bestResult Result
		bestPriority := -1 // -1表示尚未分配

		for _, result := range group {
			var priority int
			switch result.Result {
			case "true":
				priority = 2 // 最高优先级
			case "unknown":
				priority = 1 // 中等优先级
			case "false":
				priority = 0 // 最低优先级
			default:
				priority = -1
			}

			// 如果当前结果优先级更高或尚未设置最佳结果
			if priority > bestPriority || bestPriority == -1 {
				bestResult = result
				bestPriority = priority
			} else if priority == bestPriority {
				// 如果优先级相同，优先选择有敏感数据的结果
				if len(result.SensitiveData) > len(bestResult.SensitiveData) {
					bestResult = result
				} else if len(result.SensitiveData) == len(bestResult.SensitiveData) && result.ScanTime > bestResult.ScanTime {
					// 时间相同时，选择最新的结果
					bestResult = result
				}
			}
		}

		deduplicatedResults = append(deduplicatedResults, bestResult)
		utils.Debug("[结果去重] URL=%s, 原始结果数=%d, 选择结果=%s",
			bestResult.Url, len(group), bestResult.Result)
	}

	return deduplicatedResults
}
