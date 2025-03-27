package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

// Report 报告信息结构
type Report struct {
	GeneratedTime     string        `json:"generatedTime"`
	ScanDuration      string        `json:"scanDuration"`
	TotalScanned      int           `json:"totalScanned"`
	TotalVulnerable   int           `json:"totalVulnerable"`
	TotalUnknown      int           `json:"totalUnknown"`
	TotalSafe         int           `json:"totalSafe"`
	VulnerableResults []interface{} `json:"vulnerableResults"`
	UnknownResults    []interface{} `json:"unknownResults"`
}

// ReportGenerator 报告生成器
type ReportGenerator struct {
	StartTime time.Time
	Results   []interface{}
	OutputDir string
}

// NewReportGenerator 创建一个新的报告生成器
func NewReportGenerator(outputDir string) *ReportGenerator {
	return &ReportGenerator{
		StartTime: time.Now(),
		Results:   make([]interface{}, 0),
		OutputDir: outputDir,
	}
}

// AddResult 添加一个扫描结果
func (rg *ReportGenerator) AddResult(result interface{}) {
	rg.Results = append(rg.Results, result)
}

// GenerateReport 生成报告
func (rg *ReportGenerator) GenerateReport(format string) (string, error) {
	// 确保输出目录存在
	if err := os.MkdirAll(rg.OutputDir, 0755); err != nil {
		return "", fmt.Errorf("创建报告目录失败: %v", err)
	}

	// 根据格式生成报告
	switch format {
	case "JSON":
		return rg.generateJSONReport()
	case "HTML":
		return rg.generateHTMLReport()
	case "CSV":
		return rg.generateCSVReport()
	default:
		return "", fmt.Errorf("不支持的报告格式: %s", format)
	}
}

// generateJSONReport 生成JSON格式报告
func (rg *ReportGenerator) generateJSONReport() (string, error) {
	report := rg.prepareReportData()

	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(rg.OutputDir, fmt.Sprintf("privhunter-report-%s.json", timestamp))

	// 序列化为JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}

	// 写入文件
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", fmt.Errorf("写入报告文件失败: %v", err)
	}

	return filename, nil
}

// generateHTMLReport 生成HTML格式报告
func (rg *ReportGenerator) generateHTMLReport() (string, error) {
	report := rg.prepareReportData()

	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(rg.OutputDir, fmt.Sprintf("privhunter-report-%s.html", timestamp))

	// HTML模板
	htmlTemplate := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIFuzzing 扫描报告</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism-tomorrow.min.css">
    <style>
        :root {
            --primary-color: #4a90e2;
            --secondary-color: #5cb85c;
            --danger-color: #d9534f;
            --warning-color: #f0ad4e;
            --info-color: #5bc0de;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background: #f8f9fa;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            padding: 30px;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        
        h1 {
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 5px;
        }
        
        .subtitle {
            color: #6c757d;
            font-size: 1rem;
        }
        
        .summary {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-bottom: 30px;
            gap: 15px;
        }
        
        .summary-box {
            flex: 1;
            min-width: 200px;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .summary-box:hover {
            transform: translateY(-5px);
        }
        
        .summary-box h3 {
            margin-bottom: 10px;
            font-size: 1.25rem;
        }
        
        .summary-box p {
            font-size: 2rem;
            font-weight: 700;
            margin: 0;
        }
        
        .vulnerable {
            background: linear-gradient(135deg, #fff, #ffebee);
            border-left: 5px solid var(--danger-color);
            color: var(--danger-color);
        }
        
        .unknown {
            background: linear-gradient(135deg, #fff, #fff8e1);
            border-left: 5px solid var(--warning-color);
            color: var(--warning-color);
        }
        
        .safe {
            background: linear-gradient(135deg, #fff, #e8f5e9);
            border-left: 5px solid var(--secondary-color);
            color: var(--secondary-color);
        }
        
        .total {
            background: linear-gradient(135deg, #fff, #e3f2fd);
            border-left: 5px solid var(--primary-color);
            color: var(--primary-color);
        }
        
        .section {
            margin-top: 40px;
            position: relative;
        }
        
        .section-title {
            font-size: 1.5rem;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .results-table {
            width: 100%;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .results-table th {
            background-color: #f8f9fa;
            color: #495057;
            font-weight: 600;
            padding: 12px 15px;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
        }
        
        .results-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .results-table tbody tr:hover {
            background-color: #f8f9fa;
        }
        
        .detail-btn {
            background-color: #e7f5ff;
            color: var(--primary-color);
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
            transition: all 0.2s;
        }
        
        .detail-btn:hover {
            background-color: var(--primary-color);
            color: white;
        }
        
        .result-detail {
            margin-top: 15px;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            display: none;
        }
        
        .detail-header {
            font-weight: 600;
            margin-bottom: 10px;
            color: #333;
        }
        
        .detail-content {
            background: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Consolas', monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        
        .request-wrapper, .response-wrapper {
            display: flex;
            margin-bottom: 15px;
            gap: 20px;
        }
        
        .request-original, .request-modified,
        .response-original, .response-modified {
            flex: 1;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .request-title, .response-title {
            background: #e9ecef;
            padding: 8px 15px;
            font-weight: 600;
            color: #495057;
        }
        
        .diff-highlight {
            background-color: #ffecb3;
            padding: 2px 0;
            border-radius: 2px;
        }
        
        .empty-message {
            text-align: center;
            color: #6c757d;
            padding: 20px;
        }
        
        .footer {
            margin-top: 40px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        /* 新增：请求/响应比较样式 */
        .comparison-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .comparison-panel {
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .comparison-header {
            background: #f5f5f5;
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
            font-weight: 600;
        }
        
        .comparison-content {
            padding: 0;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .code-block {
            margin: 0;
            border-radius: 0;
        }
        
        /* 差异高亮 */
        .diff-added {
            background-color: #e6ffed;
        }
        
        .diff-removed {
            background-color: #ffeef0;
        }
        
        .similarity-badge {
            font-size: 0.8rem;
            padding: 3px 8px;
            border-radius: 10px;
            background-color: #e9ecef;
        }
        
        .similarity-high {
            background-color: #d4edda;
            color: #155724;
        }
        
        .similarity-medium {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .similarity-low {
            background-color: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AIFuzzing 扫描报告</h1>
            <p class="subtitle">生成时间: {{.GeneratedTime}} | 扫描用时: {{.ScanDuration}}</p>
        </header>
        
        <div class="summary">
            <div class="summary-box total">
                <h3>总扫描</h3>
                <p>{{.TotalScanned}}</p>
            </div>
            <div class="summary-box vulnerable">
                <h3>存在漏洞</h3>
                <p>{{.TotalVulnerable}}</p>
            </div>
            <div class="summary-box unknown">
                <h3>未知状态</h3>
                <p>{{.TotalUnknown}}</p>
            </div>
            <div class="summary-box safe">
                <h3>安全</h3>
                <p>{{.TotalSafe}}</p>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">存在漏洞的请求 ({{.TotalVulnerable}})</h2>
        {{if gt .TotalVulnerable 0}}
            <table class="results-table">
            <thead>
                <tr>
                        <th>#</th>
                    <th>方法</th>
                    <th>URL</th>
                    <th>漏洞类型</th>
                    <th>相似度</th>
                        <th>详情</th>
                </tr>
            </thead>
            <tbody>
                {{range $index, $result := .VulnerableResults}}
                <tr>
                    <td>{{add $index 1}}</td>
                    <td>{{$result.Method}}</td>
                        <td class="text-truncate" style="max-width: 300px;">{{$result.Url}}</td>
                        <td>
                            {{if eq $result.VulnType "未授权访问"}}
                                <span class="badge bg-danger">未授权访问</span>
                            {{else if eq $result.VulnType "越权访问"}}
                                <span class="badge bg-warning text-dark">越权访问</span>
                            {{else}}
                                <span class="badge bg-secondary">{{$result.VulnType}}</span>
                            {{end}}
                        </td>
                        <td>
                            {{if gt $result.Similarity 0.8}}
                                <span class="similarity-badge similarity-high">{{$result.Similarity}}</span>
                            {{else if gt $result.Similarity 0.5}}
                                <span class="similarity-badge similarity-medium">{{$result.Similarity}}</span>
                            {{else}}
                                <span class="similarity-badge similarity-low">{{$result.Similarity}}</span>
                            {{end}}
                        </td>
                        <td>
                            <button class="detail-btn" onclick="toggleDetail('vuln-{{$index}}')">查看详情</button>
                        </td>
                    </tr>
                    <tr id="vuln-{{$index}}" style="display: none;">
                        <td colspan="6">
                            <div class="result-detail">
                                <div class="detail-header">原因：{{$result.Reason}}</div>
                                
                                <div class="accordion" id="accordionVuln{{$index}}">
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" 
                                                    data-bs-target="#collapseRequest{{$index}}" aria-expanded="false">
                                                请求对比
                                            </button>
                                        </h2>
                                        <div id="collapseRequest{{$index}}" class="accordion-collapse collapse" data-bs-parent="#accordionVuln{{$index}}">
                                            <div class="accordion-body p-0">
                                                <div class="comparison-container">
                                                    <div class="comparison-panel">
                                                        <div class="comparison-header">原始请求</div>
                                                        <div class="comparison-content">
                                                            <pre class="language-http"><code>{{$result.Method}} {{$result.Url}}
{{$result.HeaderA}}

{{$result.RequestA}}</code></pre>
                                                        </div>
                                                    </div>
                                                    <div class="comparison-panel">
                                                        <div class="comparison-header">未授权请求</div>
                                                        <div class="comparison-content">
                                                            <pre class="language-http"><code>{{$result.Method}} {{$result.Url}}
{{$result.HeaderB}}

{{$result.RequestB}}</code></pre>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" 
                                                    data-bs-target="#collapseResponse{{$index}}" aria-expanded="false">
                                                响应对比
                                            </button>
                                        </h2>
                                        <div id="collapseResponse{{$index}}" class="accordion-collapse collapse" data-bs-parent="#accordionVuln{{$index}}">
                                            <div class="accordion-body p-0">
                                                <div class="comparison-container">
                                                    <div class="comparison-panel">
                                                        <div class="comparison-header">原始响应</div>
                                                        <div class="comparison-content">
                                                            <pre class="language-json"><code>{{$result.RespBodyA}}</code></pre>
                                                        </div>
                                                    </div>
                                                    <div class="comparison-panel">
                                                        <div class="comparison-header">未授权响应</div>
                                                        <div class="comparison-content">
                                                            <pre class="language-json"><code>{{$result.RespBodyB}}</code></pre>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    {{if $result.Differences}}
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" 
                                                    data-bs-target="#collapseDiff{{$index}}" aria-expanded="false">
                                                差异分析
                                            </button>
                                        </h2>
                                        <div id="collapseDiff{{$index}}" class="accordion-collapse collapse" data-bs-parent="#accordionVuln{{$index}}">
                                            <div class="accordion-body">
                                                <ul>
                                                    {{range $diff := $result.Differences}}
                                                    <li>{{$diff}}</li>
                                                    {{end}}
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                    {{end}}
                                    
                                    {{if $result.SensitiveData}}
                                    <div class="accordion-item">
                                        <h2 class="accordion-header">
                                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" 
                                                    data-bs-target="#collapseSensitive{{$index}}" aria-expanded="false">
                                                敏感信息泄露
                                            </button>
                                        </h2>
                                        <div id="collapseSensitive{{$index}}" class="accordion-collapse collapse" data-bs-parent="#accordionVuln{{$index}}">
                                            <div class="accordion-body">
                                                <ul>
                                                    {{range $data := $result.SensitiveData}}
                                                    <li>{{$data}}</li>
                                                    {{end}}
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                    {{end}}
                                </div>
                            </div>
                        </td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
            <div class="empty-message">未发现漏洞</div>
        {{end}}
        </div>
        
        <div class="section">
            <h2 class="section-title">未知状态的请求 ({{.TotalUnknown}})</h2>
        {{if gt .TotalUnknown 0}}
            <table class="results-table">
            <thead>
                <tr>
                        <th>#</th>
                    <th>方法</th>
                    <th>URL</th>
                    <th>相似度</th>
                        <th>详情</th>
                </tr>
            </thead>
            <tbody>
                {{range $index, $result := .UnknownResults}}
                <tr>
                    <td>{{add $index 1}}</td>
                    <td>{{$result.Method}}</td>
                        <td class="text-truncate" style="max-width: 300px;">{{$result.Url}}</td>
                        <td>
                            {{if gt $result.Similarity 0.8}}
                                <span class="similarity-badge similarity-high">{{$result.Similarity}}</span>
                            {{else if gt $result.Similarity 0.5}}
                                <span class="similarity-badge similarity-medium">{{$result.Similarity}}</span>
                            {{else}}
                                <span class="similarity-badge similarity-low">{{$result.Similarity}}</span>
                            {{end}}
                        </td>
                        <td>
                            <button class="detail-btn" onclick="toggleDetail('unknown-{{$index}}')">查看详情</button>
                        </td>
                    </tr>
                    <tr id="unknown-{{$index}}" style="display: none;">
                        <td colspan="5">
                            <div class="result-detail">
                                <!-- 与漏洞详情类似的结构 -->
                                <div class="detail-header">原因：{{$result.Reason}}</div>
                                
                                <!-- 请求/响应信息 -->
                                <div class="accordion" id="accordionUnknown{{$index}}">
                                    <!-- 与上面相同的手风琴结构 -->
                                </div>
                            </div>
                        </td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
            <div class="empty-message">没有未知状态的请求</div>
        {{end}}
        </div>
        
        <div class="footer">
            <p>由 AIFuzzing 生成 | 版本: 1.0.0</p>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/prism.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-http.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/components/prism-json.min.js"></script>
    <script>
        function toggleDetail(id) {
            const element = document.getElementById(id);
            if (element.style.display === 'none') {
                element.style.display = 'table-row';
            } else {
                element.style.display = 'none';
            }
        }
        
        // 初始化语法高亮
        document.addEventListener('DOMContentLoaded', (event) => {
            Prism.highlightAll();
        });
    </script>
</body>
</html>`

	// 解析模板
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("解析HTML模板失败: %v", err)
	}

	// 创建文件
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("创建报告文件失败: %v", err)
	}
	defer file.Close()

	// 执行模板
	if err := tmpl.Execute(file, report); err != nil {
		return "", fmt.Errorf("生成HTML报告失败: %v", err)
	}

	return filename, nil
}

// generateCSVReport 生成CSV格式报告
func (rg *ReportGenerator) generateCSVReport() (string, error) {
	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(rg.OutputDir, fmt.Sprintf("privhunter-report-%s.csv", timestamp))

	// 创建文件
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("创建CSV文件失败: %v", err)
	}
	defer file.Close()

	// 创建CSV写入器
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{"结果", "方法", "URL", "漏洞类型", "相似度", "原因"}
	if err := writer.Write(headers); err != nil {
		return "", fmt.Errorf("写入CSV表头失败: %v", err)
	}

	// 写入数据
	for _, r := range rg.Results {
		result := r.(map[string]interface{})
		
		var vulnType string
		if vt, ok := result["vulnType"].(string); ok {
			vulnType = vt
		}
		
		var similarity string
		if sim, ok := result["similarity"].(float64); ok {
			similarity = fmt.Sprintf("%.2f", sim)
		}
		
		row := []string{
			result["result"].(string),
			result["method"].(string),
			result["url"].(string),
			vulnType,
			similarity,
			result["reason"].(string),
		}
		
		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("写入CSV行失败: %v", err)
		}
	}

	return filename, nil
}

// prepareReportData 准备报告数据
func (rg *ReportGenerator) prepareReportData() Report {
	// 统计结果
	var vulnerableResults []interface{}
	var unknownResults []interface{}
	var totalSafe int

	for _, result := range rg.Results {
		r := result.(map[string]interface{})
		
		switch r["result"].(string) {
		case "true":
			vulnerableResults = append(vulnerableResults, r)
		case "unknown":
			unknownResults = append(unknownResults, r)
		case "false":
			totalSafe++
		}
	}

	// 准备报告数据
	return Report{
		GeneratedTime:     time.Now().Format("2006-01-02 15:04:05"),
		ScanDuration:      time.Since(rg.StartTime).String(),
		TotalScanned:      len(rg.Results),
		TotalVulnerable:   len(vulnerableResults),
		TotalUnknown:      len(unknownResults),
		TotalSafe:         totalSafe,
		VulnerableResults: vulnerableResults,
		UnknownResults:    unknownResults,
	}
} 