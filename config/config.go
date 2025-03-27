package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// 请求过滤规则结构
type RequestFilter struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Description string   `json:"description"`
	Methods     []string `json:"methods,omitempty"`     // 指定适用的HTTP方法，为空则匹配所有方法
	ContentType []string `json:"contentType,omitempty"` // 指定适用的Content-Type，为空则匹配所有类型
}

// 敏感数据模式
type SensitiveDataPattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// 敏感数据配置
type SensitiveDataConfig struct {
	Enabled      bool                   `json:"enabled"`
	Patterns     []SensitiveDataPattern `json:"patterns"`
	JsonPatterns []SensitiveDataPattern `json:"jsonPatterns,omitempty"` // JSON响应专用的敏感数据模式
}

// 置信度规则
type ConfidenceRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Weight      int    `json:"weight"` // 权重，用于计算最终置信度
}

// 未授权检测配置
type UnauthorizedScanConfig struct {
	Enabled               bool                `json:"enabled"`
	RemoveHeaders         []string            `json:"removeHeaders"`
	SimilarityThreshold   float64             `json:"similarityThreshold"`
	ExcludePatterns       []string            `json:"excludePatterns"`
	SensitiveDataPatterns SensitiveDataConfig `json:"sensitiveDataPatterns"`
	// 新增置信度相关配置
	UseConfidenceScore    bool             `json:"useConfidenceScore"`    // 是否使用置信度评分而非相似度
	ConfidenceRules       []ConfidenceRule `json:"confidenceRules"`       // 置信度评分规则
	HighConfidenceScore   int              `json:"highConfidenceScore"`   // 高置信度阈值
	MediumConfidenceScore int              `json:"mediumConfidenceScore"` // 中置信度阈值
	LowConfidenceScore    int              `json:"lowConfidenceScore"`    // 低置信度阈值
}

// 越权检测配置
type PrivilegeEscalationScanConfig struct {
	Enabled             bool     `json:"enabled"`             // 是否启用越权检测
	SimilarityThreshold float64  `json:"similarityThreshold"` // 相似度阈值
	ParamPatterns       []string `json:"paramPatterns"`       // 参数模式
	ExcludePatterns     []string `json:"excludePatterns"`     // 排除模式
}

// 性能配置
type PerformanceConfig struct {
	MaxConcurrentScans int   `json:"maxConcurrentScans"` // 最大并发扫描数
	ScanTimeout        int64 `json:"scanTimeout"`        // 扫描超时时间(秒)
	MaxRetries         int   `json:"maxRetries"`         // 最大重试次数
	RetryInterval      int   `json:"retryInterval"`      // 重试间隔(秒)
	MaxRequestSize     int   `json:"maxRequestSize"`     // 最大请求大小(字节)
}

// 日志配置
type LogConfig struct {
	Level      string `json:"level"`      // 日志级别: DEBUG, INFO, WARNING, ERROR
	EnableFile bool   `json:"enableFile"` // 是否启用文件日志
	Directory  string `json:"directory"`  // 日志目录
}

// 输出配置
type OutputConfig struct {
	EnableWebUI      bool   `json:"enableWebUI"`      // 是否启用Web界面
	WebUIPort        int    `json:"webUIPort"`        // Web界面端口
	EnableReportFile bool   `json:"enableReportFile"` // 是否输出报告文件
	ReportFormat     string `json:"reportFormat"`     // 报告格式: JSON, HTML, CSV
	ReportDirectory  string `json:"reportDirectory"`  // 报告目录
}

// 代理配置
type ProxyConfig struct {
	Port               int  `json:"port"`               // 代理端口
	StreamLargeBodies  int  `json:"streamLargeBodies"`  // 大请求体流式处理限制
	EnableCertVerifier bool `json:"enableCertVerifier"` // 是否启用证书验证
}

// 配置结构
type Config struct {
	AI                 string            `json:"AI"`
	Headers2           map[string]string `json:"headers2"`
	Suffixes           []string          `json:"suffixes"`
	AllowedRespHeaders []string          `json:"allowedRespHeaders"`
	APIKeys            struct {
		Kimi     string `json:"kimi"`
		DeepSeek string `json:"deepseek"`
		Qianwen  string `json:"qianwen"`
		HunYuan  string `json:"hunyuan"`
		Gpt      string `json:"gpt"`
		Glm      string `json:"glm"`
	} `json:"apiKeys"`
	RespBodyBWhiteList []string `json:"respBodyBWhiteList"`
	// 新增配置项
	RequestFilters struct {
		ParamPatterns []RequestFilter `json:"paramPatterns"`
		Enabled       bool            `json:"enabled"`
	} `json:"requestFilters"`
	UnauthorizedScan        UnauthorizedScanConfig        `json:"unauthorizedScan"`
	PrivilegeEscalationScan PrivilegeEscalationScanConfig `json:"privilegeEscalationScan"`
	Performance             PerformanceConfig             `json:"performance"`
	Log                     LogConfig                     `json:"log"`
	Output                  OutputConfig                  `json:"output"`
	Proxy                   ProxyConfig                   `json:"proxy"`
}

// 全局配置变量和锁，用于线程安全访问
var (
	conf        *Config
	configLock  sync.RWMutex
	configPath  string    = "./config.json" // 默认配置文件路径
	lastModTime time.Time                   // 配置文件最后修改时间
)

var Prompt = `{
  "role": "你是一个AI，负责通过比较两个HTTP响应数据包来检测潜在的越权行为，并自行做出判断。",
  "inputs": {
    "reqA": "原始请求A",
    "responseA": "账号A请求URL的响应。",
    "responseB": "使用账号B的Cookie（也可能是token等其他参数）重放请求的响应。",
    "statusB": "账号B重放请求的请求状态码。",
    "dynamicFields": ["timestamp", "nonce", "session_id", "uuid", "request_id"]
  },
  "analysisRequirements": {
    "structureAndContentComparison": {
      "urlAnalysis": "结合原始请求A和响应A分析，判断是否可能是无需数据鉴权的公共接口（不作为主要判断依据）。",
      "responseComparison": "比较响应A和响应B的结构和内容，忽略动态字段（如时间戳、随机数、会话ID、X-Request-ID等），并进行语义匹配。",
      "httpStatusCode": "对比HTTP状态码：403/401直接判定越权失败（false），500标记为未知（unknown），200需进一步分析。",
      "similarityAnalysis": "使用字段对比和文本相似度计算（Levenshtein/Jaccard）评估内容相似度。",
      "errorKeywords": "检查responseB是否包含 'Access Denied'、'Permission Denied'、'403 Forbidden' 等错误信息，若有，则判定越权失败。",
      "emptyResponseHandling": "如果responseB返回null、[]、{}或HTTP 204，且responseA有数据，判定为权限受限（false）。",
      "sensitiveDataDetection": "如果responseB包含敏感数据（如手机号、身份证号、邮箱、中文姓名、银行卡号等），判定为越权成功（true）。",
      "consistencyCheck": "如果responseB和responseA结构一致但关键数据不同，判定可能是权限控制正确（false）。"
    },
    "judgmentCriteria": {
      "authorizationSuccess (true)": "如果不是公共接口，且responseB的结构和非动态字段内容与responseA高度相似，或者responseB包含敏感数据，则判定为越权成功。",
      "authorizationFailure (false)": "如果是公共接口，或者responseB的结构和responseA不相似，或者responseB明确定义权限错误（403/401/Access Denied），或者responseB为空，则判定为越权失败。",
      "unknown": "如果responseB返回500，或者responseA和responseB结构不同但没有权限相关信息，或者responseB只是部分字段匹配但无法确定影响，则判定为unknown。"
    }
  },
  "outputFormat": {
    "json": {
      "res": "\"true\", \"false\" 或 \"unknown\"",
      "reason": "清晰的判断原因，总体不超过50字。"
    }
  },
  "notes": [
    "仅输出 JSON 格式的结果，不添加任何额外文本或解释。",
    "确保 JSON 格式正确，便于后续处理。",
    "保持客观，仅根据响应内容进行分析。",
    "优先使用 HTTP 状态码、错误信息和数据结构匹配进行判断。",
    "重点关注敏感数据检测，如手机号、身份证号、邮箱、银行卡号等。",
    "支持用户提供额外的动态字段，提高匹配准确性。"
  ],
  "process": [
    "接收并理解原始请求A、responseA和responseB。",
    "分析原始请求A，判断是否是无需鉴权的公共接口。",
    "提取并忽略动态字段（时间戳、随机数、会话ID）。",
    "对比HTTP状态码，403/401直接判定为false，500标记为unknown。",
    "检查responseB是否包含敏感数据（如手机号、身份证号、邮箱、银行卡号），如果有，则判定为true。",
    "检查responseB是否返回错误信息（Access Denied / Forbidden），如果有，则判定为false。",
    "计算responseA和responseB的结构相似度，并使用Levenshtein编辑距离计算文本相似度，计算时忽略动态字段（如时间戳、随机数、会话ID、X-Request-ID等）。",
    "如果responseB内容为空（null、{}、[]），判断可能是权限受限，判定为false。",
    "根据分析结果，返回JSON结果。"
  ]
}
  `

// 初始化配置
func InitConfig(configFile string) error {
	if configFile != "" {
		configPath = configFile
	}

	// 加载配置
	if err := loadConfig(); err != nil {
		return fmt.Errorf("加载配置文件失败: %v", err)
	}

	// 设置默认值
	setDefaults()

	// 开启配置文件监控，实现热重载
	go watchConfig()

	return nil
}

// 设置配置默认值
func setDefaults() {
	configLock.Lock()
	defer configLock.Unlock()

	// 代理配置默认值
	if conf.Proxy.Port == 0 {
		conf.Proxy.Port = 9080
	}
	if conf.Proxy.StreamLargeBodies == 0 {
		conf.Proxy.StreamLargeBodies = 1024 * 1024 * 5 // 5MB
	}

	// 性能配置默认值
	if conf.Performance.MaxConcurrentScans == 0 {
		conf.Performance.MaxConcurrentScans = 10
	}
	if conf.Performance.ScanTimeout == 0 {
		conf.Performance.ScanTimeout = 60 // 60秒
	}
	if conf.Performance.MaxRetries == 0 {
		conf.Performance.MaxRetries = 3
	}
	if conf.Performance.RetryInterval == 0 {
		conf.Performance.RetryInterval = 10 // 10秒
	}
	if conf.Performance.MaxRequestSize == 0 {
		conf.Performance.MaxRequestSize = 1024 * 1024 * 2 // 2MB
	}

	// 日志配置默认值
	if conf.Log.Level == "" {
		conf.Log.Level = "INFO"
	}
	if conf.Log.Directory == "" {
		conf.Log.Directory = "logs"
	}

	// 输出配置默认值
	if conf.Output.WebUIPort == 0 {
		conf.Output.WebUIPort = 8222
	}
	if conf.Output.ReportFormat == "" {
		conf.Output.ReportFormat = "JSON"
	}
	if conf.Output.ReportDirectory == "" {
		conf.Output.ReportDirectory = "reports"
	}
}

// 监控配置文件变化
func watchConfig() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fileInfo, err := os.Stat(configPath)
		if err != nil {
			continue
		}

		modTime := fileInfo.ModTime()
		if modTime.After(lastModTime) {
			if err := loadConfig(); err == nil {
				setDefaults()
				lastModTime = modTime
				fmt.Println("配置文件已重新加载")
			}
		}
	}
}

// 加载配置文件
func loadConfig() error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	configLock.Lock()
	defer configLock.Unlock()

	if err := json.Unmarshal(data, &conf); err != nil {
		return err
	}

	// 记录文件修改时间
	fileInfo, _ := os.Stat(configPath)
	lastModTime = fileInfo.ModTime()

	return nil
}

// 获取配置，线程安全
func GetConfig() *Config {
	configLock.RLock()
	defer configLock.RUnlock()
	return conf
}

// 获取配置的JSON字符串
func GetConfigJSON() (string, error) {
	configLock.RLock()
	defer configLock.RUnlock()

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// 更新配置文件
func UpdateConfig(newConfig *Config) error {
	configLock.Lock()
	defer configLock.Unlock()

	// 更新内存中的配置
	conf = newConfig

	// 序列化为JSON
	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return err
	}

	return nil
}

// GetAPIKey 根据AI类型获取对应的API密钥
func GetAPIKey(ai string) string {
	configLock.RLock()
	defer configLock.RUnlock()

	switch ai {
	case "kimi":
		return conf.APIKeys.Kimi
	case "deepseek":
		return conf.APIKeys.DeepSeek
	case "qianwen":
		return conf.APIKeys.Qianwen
	case "hunyuan":
		return conf.APIKeys.HunYuan
	case "gpt":
		return conf.APIKeys.Gpt
	case "glm":
		return conf.APIKeys.Glm
	default:
		return ""
	}
}

// GetAPIURL 根据AI类型获取对应的API URL
func GetAPIURL(ai string) string {
	switch ai {
	case "kimi":
		return "https://api.moonshot.cn/v1/chat/completions"
	case "deepseek":
		return "https://api.deepseek.com/v1/chat/completions"
	case "qianwen":
		return "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
	case "hunyuan":
		return "https://hunyuan.tencent.com/hyllm/v1/chat/completions"
	case "gpt":
		return "https://api.openai.com/v1/chat/completions"
	case "glm":
		return "https://open.bigmodel.cn/api/paas/v4/chat/completions"
	default:
		return ""
	}
}

// 替代原来的init函数
// 新的init函数将在InitConfig中调用
func init() {
	// 此处不进行实际初始化，而是由main函数调用InitConfig完成初始化
}
