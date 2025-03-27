package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 日志级别常量
const (
	LogDebug   = "DEBUG"   // 调试
	LogInfo    = "INFO"    // 信息
	LogWarning = "WARNING" // 警告
	LogError   = "ERROR"   // 错误
)

// 日志颜色
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

var (
	logger       *log.Logger
	logFile      *os.File
	logLevel     string = LogDebug // 默认为调试级别
	logDirectory       = "logs"    // 日志目录
	logFilePath  = ""                 // 日志文件路径
	colorMap     = map[string]string{ // 日志级别对应的颜色
		LogDebug:   ColorBlue,
		LogInfo:    ColorGreen,
		LogWarning: ColorYellow,
		LogError:   ColorRed,
	}
)

// InitLogger 初始化日志系统
func InitLogger(level string, enableFile bool) error {
	// 默认设置为调试级别以获取更多信息
	if level == "" {
		level = LogDebug
	}
	
	level = strings.ToUpper(level)
	
	// 设置日志级别
	switch level {
	case LogDebug:
		logLevel = LogDebug
	case LogInfo:
		logLevel = LogInfo
	case LogWarning:
		logLevel = LogWarning
	case LogError:
		logLevel = LogError
	default:
		logLevel = LogDebug // 默认为调试级别
	}

	// 设置标准输出的日志记录器
	logger = log.New(os.Stdout, "", 0)

	// 如果需要记录到文件
	if enableFile {
		// 创建日志目录
		if err := os.MkdirAll(logDirectory, 0755); err != nil {
			return fmt.Errorf("创建日志目录失败: %v", err)
		}

		// 创建当天的日志文件
		currentTime := time.Now().Format("2006-01-02")
		logFilePath = filepath.Join(logDirectory, fmt.Sprintf("privhunter-%s.log", currentTime))
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("打开日志文件失败: %v", err)
		}

		logFile = file
		// 同时输出到标准输出和文件
		logger = log.New(os.Stdout, "", 0)
	}

	return nil
}

// Log 记录指定级别的日志
func Log(level string, format string, v ...interface{}) {
	// 检查是否应该记录这个级别的日志
	if !shouldLog(level) {
		return
	}
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, v...)
	// 带颜色的日志级别
	coloredLevel := fmt.Sprintf("%s[%s]%s", colorMap[level], level, ColorReset)
	
	// 输出到标准输出
	logMsg := fmt.Sprintf("%s %s %s", timestamp, coloredLevel, msg)
	logger.Println(logMsg)
	
	// 如果日志文件打开，记录到文件
	if logFile != nil {
		// 文件中不要颜色代码
		fileMsg := fmt.Sprintf("%s [%s] %s", timestamp, level, msg)
		fmt.Fprintln(logFile, fileMsg)
	}
}

// Debug 记录调试信息
func Debug(format string, v ...interface{}) {
	Log(LogDebug, format, v...)
}

// Info 记录普通信息
func Info(format string, v ...interface{}) {
	Log(LogInfo, format, v...)
}

// Warning 记录警告信息
func Warning(format string, v ...interface{}) {
	Log(LogWarning, format, v...)
}

// Error 记录错误信息
func Error(format string, v ...interface{}) {
	Log(LogError, format, v...)
}

// shouldLog 判断当前日志级别是否应该记录
func shouldLog(level string) bool {
	levelMap := map[string]int{
		LogDebug:   0,
		LogInfo:    1,
		LogWarning: 2,
		LogError:   3,
	}

	return levelMap[level] >= levelMap[logLevel]
}

// Close 关闭日志文件
func Close() {
	if logFile != nil {
		logFile.Close()
	}
} 