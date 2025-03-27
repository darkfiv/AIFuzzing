Quick Suggestionspackage report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"text/template"
	"time"
)

// Result 表示一个漏洞结果
type Result struct {
	Method       string    `json:"method"`
	Url          string    `json:"url"`
	RequestA     string    `json:"requestA"`
	RequestB     string    `json:"requestB"`
	HeaderA      string    `json:"headerA"`
	HeaderB      string    `json:"headerB"`
	RespBodyA    string    `json:"respBodyA"`
	RespBodyB    string    `json:"respBodyB"`
	Result       string    `json:"result"`
	Reason       string    `json:"reason"`
	VulnType     string    `json:"vulnType"`
	Similarity   float64   `json:"similarity"`
	Differences  []string  `json:"differences"`
	SensitiveData []string `json:"sensitiveData,omitempty"`
}

// Generator 报告生成器
type Generator struct {
	reportDir   string
	reportFormat string
	results     []Result
	mu          sync.Mutex
}

// NewGenerator 创建新的报告生成器
func NewGenerator(reportDir, reportFormat string) (*Generator, error) {
	// 确保报告目录存在
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return nil, fmt.Errorf("创建报告目录失败: %v", err)
	}

	// 检查目录是否可写
	testFile := filepath.Join(reportDir, ".test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return nil, fmt.Errorf("报告目录不可写: %v", err)
	}
	os.Remove(testFile)

	return &Generator{
		reportDir:   reportDir,
		reportFormat: reportFormat,
		results:     make([]Result, 0),
	}, nil
}

// AddResult 添加一个漏洞结果
func (g *Generator) AddResult(result Result) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.results = append(g.results, result)
}

// GenerateReport 生成报告
func (g *Generator) GenerateReport(format string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// 如果没有使用传入的格式，则使用默认格式
	if format == "" {
		format = g.reportFormat
	}

	// 根据格式生成不同类型的报告
	switch format {
	case "json":
		return g.generateJSONReport()
	case "html":
		return g.generateHTMLReport()
	default:
		return g.generateHTMLReport() // 默认HTML格式
	}
}

// generateJSONReport 生成JSON格式报告
func (g *Generator) generateJSONReport() (string, error) {
	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(g.reportDir, fmt.Sprintf("report-%s.json", timestamp))

	// 将结果序列化为JSON
	data, err := json.MarshalIndent(g.results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化报告数据失败: %v", err)
	}

	// 写入文件
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", fmt.Errorf("写入报告文件失败: %v", err)
	}

	return filename, nil
}

// generateHTMLReport 生成HTML格式报告
func (g *Generator) generateHTMLReport() (string, error) {
	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(g.reportDir, fmt.Sprintf("report-%s.html", timestamp))

	// 创建HTML模板
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("解析HTML模板失败: %v", err)
	}

	// 创建报告文件
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("创建HTML报告文件失败: %v", err)
	}
	defer file.Close()

	// 准备报告数据
	data := struct {
		Timestamp     string
		TotalVulns    int
		Results       []Result
		UnauthorizedCount int
		EscalationCount   int
	}{
		Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
		TotalVulns: len(g.results),
		Results:    g.results,
	}

	// 计算各种漏洞类型的数量
	for _, result := range g.results {
		switch result.VulnType {
		case "unauthorized_access":
			data.UnauthorizedCount++
		case "privilege_escalation":
			data.EscalationCount++
		}
	}

	// 执行模板渲染
	if err := tmpl.Execute(file, data); err != nil {
		return "", fmt.Errorf("渲染HTML模板失败: %v", err)
	}

	return filename, nil
}

// Close 关闭报告生成器
func (g *Generator) Close() error {
	// 没有需要特别清理的资源，但保留方法以符合接口
	return nil
}

// htmlTemplate HTML报告模板
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            background-color: #f8f9fa;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .summary-item {
            text-align: center;
            padding: 10px;
        }
        .summary-item .count {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .summary-item .label {
            font-size: 14px;
            color: #666;
        }
        .vulnerability {
            background-color: #fff;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .vulnerability h3 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .vuln-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        .detail-item {
            margin-bottom: 10px;
        }
        .detail-label {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .detail-value {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            word-break: break-all;
            font-family: monospace;
            font-size: 13px;
            max-height: 200px;
            overflow-y: auto;
        }
        .unauthorized {
            border-left: 4px solid #e74c3c;
        }
        .escalation {
            border-left: 4px solid #f39c12;
        }
        .timestamp {
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>安全扫描报告</h1>
            <p class="timestamp">生成时间: {{.Timestamp}}</p>
        </header>
        
        <div class="summary">
            <div class="summary-item">
                <div class="count">{{.TotalVulns}}</div>
                <div class="label">发现漏洞总数</div>
            </div>
            <div class="summary-item">
                <div class="count">{{.UnauthorizedCount}}</div>
                <div class="label">未授权访问</div>
            </div>
            <div class="summary-item">
                <div class="count">{{.EscalationCount}}</div>
                <div class="label">越权漏洞</div>
            </div>
        </div>
        
        <h2>漏洞详情</h2>
        
        {{range .Results}}
        <div class="vulnerability {{if eq .VulnType "unauthorized_access"}}unauthorized{{else if eq .VulnType "privilege_escalation"}}escalation{{end}}">
            <h3>{{if eq .VulnType "unauthorized_access"}}未授权访问{{else if eq .VulnType "privilege_escalation"}}越权漏洞{{else}}{{.VulnType}}{{end}}</h3>
            <div class="vuln-details">
                <div class="detail-item">
                    <div class="detail-label">URL</div>
                    <div class="detail-value">{{.Url}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">HTTP方法</div>
                    <div class="detail-value">{{.Method}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">漏洞原因</div>
                    <div class="detail-value">{{.Reason}}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">相似度</div>
                    <div class="detail-value">{{.Similarity}}</div>
                </div>
                {{if .SensitiveData}}
                <div class="detail-item">
                    <div class="detail-label">敏感数据类型</div>
                    <div class="detail-value">{{range .SensitiveData}}{{.}}<br>{{end}}</div>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}
    </div>
</body>
</html>` 