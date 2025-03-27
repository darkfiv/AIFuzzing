package aiapis

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	
	"strings"
	"time"
	"yuequanScan/config"
	"yuequanScan/utils"
)

const (
	apiTimeout = 30 * time.Second
)

type ChatCompletionRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
	Error   struct {
		Message string `json:"message"`
	} `json:"error"`
}

type Choice struct {
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

var (
	client = &http.Client{
		Timeout: time.Second * 30,
	}
)

// CreateChatCompletion 发送请求到 AI API
func CreateChatCompletion(request ChatCompletionRequest, aiurl string, aiapikey string) (*ChatCompletionResponse, error) {
	// 创建安全的HTTP传输配置，跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	client := &http.Client{
		Timeout: apiTimeout,
		Transport: tr,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	req, err := http.NewRequest("POST", aiurl, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+aiapikey)

	utils.Debug("发送请求到 AI API: %s (已禁用证书验证)", aiurl)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API返回状态码 %d: %s", resp.StatusCode, body)
	}

	// 读取响应体原始内容以便调试
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	
	// 调试输出原始响应内容
	utils.Debug("AI API原始响应 (前500字符): %s", truncateString(string(rawBody), 500))
	
	// 检查原始响应中是否包含可能导致JSON解析失败的特殊字符
	for i, c := range string(rawBody) {
		if i < 200 && (c == '`' || (c < 32 && c != '\n' && c != '\r' && c != '\t')) {
			utils.Warning("API响应包含特殊字符 位置[%d]: '%c' (ASCII: %d, 十六进制: %X)", i, c, c, c)
		}
	}

	// 创建新的Reader用于解析JSON
	bodyReader := bytes.NewReader(rawBody)
	
	var response ChatCompletionResponse
	if err := json.NewDecoder(bodyReader).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	if response.Error.Message != "" {
		return nil, fmt.Errorf("API错误: %s", response.Error.Message)
	}

	return &response, nil
}

// AIScan 使用AI分析请求和响应，检测越权
func AIScan(model, aiurl, apikey, reqA, respA, respB, statusB string) (string, error) {
	// 获取配置
	conf := config.GetConfig()
	maxSize := conf.Performance.MaxRequestSize
	
	// 截断过大的请求和响应内容
	reqA = TruncateRequestBody(reqA, maxSize)
	respA = TruncateRequestBody(respA, maxSize)
	respB = TruncateRequestBody(respB, maxSize)
	
	// 构建更详细的提示，包含请求头和响应的对比分析
	request := ChatCompletionRequest{
		Model: model, // 根据实际模型名称修改
		Messages: []Message{
			{
				Role:    "system",
				Content: config.Prompt,
			},
			{
				Role:    "user",
				Content: "reqA:" + reqA + "\n" + 
				         "responseA:" + respA + "\n" + 
				         "responseB:" + respB + "\n" + 
				         "statusB:" + statusB + "\n" +
				         "请特别注意分析请求中的认证头部差异，以及响应中的权限相关内容差异",
			},
		},
		Temperature: 0.7,
		MaxTokens:   500,
	}

	// 设置重试参数
	maxRetries := conf.Performance.MaxRetries
	retryInterval := time.Duration(conf.Performance.RetryInterval) * time.Second
	
	var result string
	var lastErr error
	
	// 重试循环
	for retry := 0; retry <= maxRetries; retry++ {
		if retry > 0 {
			utils.Warning("AI分析异常，第 %d 次重试，异常原因: %v", retry, lastErr)
			time.Sleep(retryInterval)
		}
		
		response, err := CreateChatCompletion(request, aiurl, apikey)
		if err != nil {
			lastErr = err
			continue
		}
		
		if len(response.Choices) > 0 {
			result = response.Choices[0].Message.Content
			utils.Debug("AI分析完成，结果长度: %d", len(result))
			
			// 检查结果是否包含可能导致JSON解析失败的字符
			for i, c := range result {
				if i < 100 && (c == '`' || (c < 32 && c != '\n' && c != '\r' && c != '\t')) {
					utils.Warning("AI结果包含特殊字符 位置[%d]: '%c' (ASCII: %d, 十六进制: %X)", i, c, c, c)
				}
			}
			
			// 尝试预处理响应，清理可能导致解析失败的字符
			result = cleanupResponse(result)
			
			return result, nil
		} else {
			lastErr = errors.New("未收到响应")
		}
	}
	
	utils.Error("AI分析失败，最大重试次数已用尽，最后错误: %v", lastErr)
	return "", lastErr
}

// TruncateRequestBody 截断请求体以防止过大
func TruncateRequestBody(body string, maxSize int) string {
	if maxSize <= 0 || len(body) <= maxSize {
		return body
	}

	// 保留前后部分
	halfSize := maxSize / 2
	prefix := body[:halfSize]
	suffix := body[len(body)-halfSize:]
	
	return prefix + "\n... [内容过长已截断] ...\n" + suffix
}

// GetModelNameByAIType 根据AI类型获取对应的模型名称
func GetModelNameByAIType(aiType string) string {
	switch aiType {
	case "kimi":
		return "moonshot-v1-8k"
	case "deepseek":
		return "deepseek-chat"
	case "qianwen":
		return "qwen-plus"
	case "hunyuan":
		return "hunyuan-lite"
	case "gpt":
		return "gpt-3.5-turbo"
	case "glm":
		return "glm-4"
	default:
		return "gpt-3.5-turbo" // 默认使用GPT
	}
}

// truncateString 截断字符串到指定长度
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// cleanupResponse 清理AI响应中可能导致JSON解析失败的字符
func cleanupResponse(response string) string {
	// 显示清理前的原始响应内容（调试用）
	utils.Debug("清理前响应内容: %s", truncateString(response, 100))
	
	// 移除反引号，这些字符可能导致JSON解析失败
	response = strings.Replace(response, "`", "", -1)
	
	// 处理多余的引号
	response = strings.Replace(response, "\"\"", "\"", -1)
	
	// 处理以"json"开头的情况（重要修复）
	if strings.HasPrefix(strings.TrimSpace(response), "json") {
		jsonStartIndex := strings.Index(response, "{")
		if jsonStartIndex > 0 {
			utils.Debug("检测到以json开头的响应，从位置%d开始截取JSON部分", jsonStartIndex)
			response = response[jsonStartIndex:]
		}
	}
	
	// 如果响应像是ChatGPT风格的Markdown代码块
	if strings.Contains(response, "```json") && strings.Contains(response, "```") {
		// 提取代码块内容
		start := strings.Index(response, "```json") + 7
		end := strings.LastIndex(response, "```")
		if start > 7 && end > start {
			jsonPart := response[start:end]
			jsonPart = strings.TrimSpace(jsonPart)
			utils.Debug("从Markdown代码块中提取JSON: %s", truncateString(jsonPart, 200))
			response = jsonPart
		}
	}
	
	// 确保响应是有效的JSON对象
	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "{") {
		// 尝试找到JSON对象开始的位置
		jsonStartIndex := strings.Index(response, "{")
		if jsonStartIndex >= 0 {
			utils.Debug("响应不是以{开头，从位置%d开始截取", jsonStartIndex)
			response = response[jsonStartIndex:]
		}
	}
	
	// 显示清理后的最终响应内容（调试用）
	utils.Debug("清理后响应内容: %s", truncateString(response, 100))
	
	return response
}
