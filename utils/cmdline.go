package utils

import (
	"flag"
	"fmt"
	"os"
)

// CommandLineArgs 命令行参数结构
type CommandLineArgs struct {
	ConfigFile   string // 配置文件路径
	LogLevel     string // 日志级别
	LogToFile    bool   // 是否记录日志到文件
	ProxyPort    int    // 代理端口
	WebUIPort    int    // Web界面端口
	DisableWebUI bool   // 禁用Web界面
	AIType       string // AI类型
	APIKey       string // AI API密钥
	Version      bool   // 显示版本信息
	Help         bool   // 显示帮助信息
}

// VERSION 版本号
const VERSION = "1.0.0"

// ParseCommandLine 解析命令行参数
func ParseCommandLine() CommandLineArgs {
	args := CommandLineArgs{}

	// 定义命令行参数
	flag.StringVar(&args.ConfigFile, "config", "./config.json", "配置文件路径")
	flag.StringVar(&args.LogLevel, "log-level", "", "日志级别 (DEBUG, INFO, WARNING, ERROR)")
	flag.BoolVar(&args.LogToFile, "log-file", false, "是否记录日志到文件")
	flag.IntVar(&args.ProxyPort, "proxy-port", 0, "代理端口")
	flag.IntVar(&args.WebUIPort, "web-port", 0, "Web界面端口")
	flag.BoolVar(&args.DisableWebUI, "no-web", false, "禁用Web界面")
	flag.StringVar(&args.AIType, "ai", "", "AI类型 (kimi, deepseek, qianwen, hunyuan, gpt, glm)")
	flag.StringVar(&args.APIKey, "api-key", "", "AI API密钥")
	flag.BoolVar(&args.Version, "version", false, "显示版本信息")
	flag.BoolVar(&args.Help, "help", false, "显示帮助信息")

	// 解析命令行参数
	flag.Parse()

	// 如果需要显示版本信息
	if args.Version {
		fmt.Printf("PrivHunterAI 版本 %s\n", VERSION)
		os.Exit(0)
	}

	// 如果需要显示帮助信息
	if args.Help {
		fmt.Println("PrivHunterAI - 一款通过被动代理方式，利用主流AI检测越权漏洞的工具")
		fmt.Println("\n使用方法: privhunter [选项]")
		fmt.Println("\n选项:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	return args
}

// ApplyCommandLineArgs 应用命令行参数到配置
func ApplyCommandLineArgs(args CommandLineArgs, conf *map[string]interface{}) {
	// 检查是否提供了日志级别
	if args.LogLevel != "" {
		logConfig := (*conf)["log"].(map[string]interface{})
		logConfig["level"] = args.LogLevel
	}

	// 检查是否提供了日志文件标志
	if args.LogToFile {
		logConfig := (*conf)["log"].(map[string]interface{})
		logConfig["enableFile"] = true
	}

	// 检查是否提供了代理端口
	if args.ProxyPort != 0 {
		proxyConfig := (*conf)["proxy"].(map[string]interface{})
		proxyConfig["port"] = args.ProxyPort
	}

	// 检查是否提供了Web界面端口
	if args.WebUIPort != 0 {
		outputConfig := (*conf)["output"].(map[string]interface{})
		outputConfig["webUIPort"] = args.WebUIPort
	}

	// 检查是否禁用Web界面
	if args.DisableWebUI {
		outputConfig := (*conf)["output"].(map[string]interface{})
		outputConfig["enableWebUI"] = false
	}

	// 检查是否提供了AI类型
	if args.AIType != "" {
		(*conf)["AI"] = args.AIType
	}

	// 检查是否提供了API密钥
	if args.APIKey != "" {
		apiKeys := (*conf)["apiKeys"].(map[string]interface{})
		// 检查当前AI类型
		aiType := (*conf)["AI"].(string)
		// 设置对应的API密钥
		apiKeys[aiType] = args.APIKey
	}
} 