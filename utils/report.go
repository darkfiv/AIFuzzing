package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	
	"github.com/xuri/excelize/v2"
)

// Report 报告信息结构
type Report struct {
	GeneratedTime     string        `json:"generatedTime"`
	ScanDuration      string        `json:"scanDuration"`
	TotalScanned      int           `json:"totalScanned"`
	TotalVulnerable   int           `json:"totalVulnerable"`
	TotalUnknown      int           `json:"totalUnknown"`
	TotalSafe         int           `json:"totalSafe"`
	TotalFalsePositive int          `json:"totalFalsePositive"`
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
	case "json":
		return rg.generateJSONReport()
	case "csv":
		return rg.generateCSVReport()
	case "xlsx":
		return rg.generateExcelReport()
	default:
		return "", fmt.Errorf("不支持的报告格式: %s", format)
	}
}

// generateJSONReport 生成JSON格式报告
func (rg *ReportGenerator) generateJSONReport() (string, error) {
	report := rg.prepareReportData()

	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(rg.OutputDir, fmt.Sprintf("AIFuzzing-report-%s.json", timestamp))

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

// generateCSVReport 生成CSV格式报告
func (rg *ReportGenerator) generateCSVReport() (string, error) {
	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(rg.OutputDir, fmt.Sprintf("AIFuzzing-report-%s.csv", timestamp))

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

// generateExcelReport 生成Excel格式报告
func (rg *ReportGenerator) generateExcelReport() (string, error) {
	// 创建Excel文件
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Println("关闭Excel文件时出错:", err)
		}
	}()

	// 获取报告数据
	report := rg.prepareReportData()

	// 创建"概要"工作表
	summarySheet := "概要"
	f.SetSheetName("Sheet1", summarySheet) // 重命名默认工作表

	// 设置概要标题
	f.SetCellValue(summarySheet, "A1", "AIFuzzing 扫描报告")
	f.SetCellValue(summarySheet, "A2", fmt.Sprintf("生成时间: %s", report.GeneratedTime))
	f.SetCellValue(summarySheet, "A3", fmt.Sprintf("扫描用时: %s", report.ScanDuration))

	// 设置概要统计
	f.SetCellValue(summarySheet, "A5", "统计信息")
	f.SetCellValue(summarySheet, "A6", "总扫描")
	f.SetCellValue(summarySheet, "B6", report.TotalScanned)
	f.SetCellValue(summarySheet, "A7", "存在漏洞")
	f.SetCellValue(summarySheet, "B7", report.TotalVulnerable)
	f.SetCellValue(summarySheet, "A8", "未知状态")
	f.SetCellValue(summarySheet, "B8", report.TotalUnknown)
	f.SetCellValue(summarySheet, "A9", "安全")
	f.SetCellValue(summarySheet, "B9", report.TotalSafe)

	// 设置单元格样式
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold:   true,
			Size:   16,
			Color:  "#4a90e2",
		},
	})
	f.SetCellStyle(summarySheet, "A1", "A1", titleStyle)

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold:   true,
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#f8f9fa"},
			Pattern: 1,
		},
		Border: []excelize.Border{
			{Type: "bottom", Color: "#dee2e6", Style: 1},
		},
	})

	// 创建漏洞工作表
	if report.TotalVulnerable > 0 {
		vulnSheet := "存在漏洞"
		f.NewSheet(vulnSheet)

		// 设置表头
		headers := []string{"#", "方法", "URL", "漏洞类型", "相似度", "原因", "误报标记", "详细信息"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(vulnSheet, cell, header)
		}
		f.SetCellStyle(vulnSheet, "A1", "H1", headerStyle)

		// 写入数据
		for i, result := range report.VulnerableResults {
			r := result.(map[string]interface{})
			row := i + 2 // 从第2行开始

			f.SetCellValue(vulnSheet, fmt.Sprintf("A%d", row), i+1)
			f.SetCellValue(vulnSheet, fmt.Sprintf("B%d", row), r["method"])
			f.SetCellValue(vulnSheet, fmt.Sprintf("C%d", row), r["url"])
			f.SetCellValue(vulnSheet, fmt.Sprintf("D%d", row), r["vulnType"])
			f.SetCellValue(vulnSheet, fmt.Sprintf("E%d", row), r["similarity"])
			f.SetCellValue(vulnSheet, fmt.Sprintf("F%d", row), r["reason"])
			
			// 添加误报标记
			isFalsePositive, _ := r["isFalsePositive"].(bool)
			falsePositiveText := "否"
			if isFalsePositive {
				falsePositiveText = "是"
			}
			f.SetCellValue(vulnSheet, fmt.Sprintf("G%d", row), falsePositiveText)

			// 详细信息
			details := fmt.Sprintf("原始请求头: %s\n\n原始请求体: %s\n\n未授权请求头: %s\n\n未授权请求体: %s\n\n"+
				"原始响应: %s\n\n未授权响应: %s",
				r["headerA"], r["requestA"], r["headerB"], r["requestB"], r["respBodyA"], r["respBodyB"])
			f.SetCellValue(vulnSheet, fmt.Sprintf("H%d", row), details)
		}

		// 设置列宽
		f.SetColWidth(vulnSheet, "A", "A", 5)
		f.SetColWidth(vulnSheet, "B", "B", 10)
		f.SetColWidth(vulnSheet, "C", "C", 50)
		f.SetColWidth(vulnSheet, "D", "D", 15)
		f.SetColWidth(vulnSheet, "E", "E", 10)
		f.SetColWidth(vulnSheet, "F", "F", 30)
		f.SetColWidth(vulnSheet, "G", "G", 10)
		f.SetColWidth(vulnSheet, "H", "H", 50)
	}

	// 创建未知状态工作表
	if report.TotalUnknown > 0 {
		unknownSheet := "未知状态"
		f.NewSheet(unknownSheet)

		// 设置表头
		headers := []string{"#", "方法", "URL", "相似度", "原因", "详细信息"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(unknownSheet, cell, header)
		}
		f.SetCellStyle(unknownSheet, "A1", "F1", headerStyle)

		// 写入数据
		for i, result := range report.UnknownResults {
			r := result.(map[string]interface{})
			row := i + 2 // 从第2行开始

			f.SetCellValue(unknownSheet, fmt.Sprintf("A%d", row), i+1)
			f.SetCellValue(unknownSheet, fmt.Sprintf("B%d", row), r["method"])
			f.SetCellValue(unknownSheet, fmt.Sprintf("C%d", row), r["url"])
			f.SetCellValue(unknownSheet, fmt.Sprintf("D%d", row), r["similarity"])
			f.SetCellValue(unknownSheet, fmt.Sprintf("E%d", row), r["reason"])

			// 详细信息
			details := fmt.Sprintf("原始请求头: %s\n\n原始请求体: %s\n\n未授权请求头: %s\n\n未授权请求体: %s\n\n"+
				"原始响应: %s\n\n未授权响应: %s",
				r["headerA"], r["requestA"], r["headerB"], r["requestB"], r["respBodyA"], r["respBodyB"])
			f.SetCellValue(unknownSheet, fmt.Sprintf("F%d", row), details)
		}

		// 设置列宽
		f.SetColWidth(unknownSheet, "A", "A", 5)
		f.SetColWidth(unknownSheet, "B", "B", 10)
		f.SetColWidth(unknownSheet, "C", "C", 50)
		f.SetColWidth(unknownSheet, "D", "D", 10)
		f.SetColWidth(unknownSheet, "E", "E", 30)
		f.SetColWidth(unknownSheet, "F", "F", 50)
	}

	// 将默认活动表设置为概要
	f.SetActiveSheet(0)

	// 生成文件名
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(rg.OutputDir, fmt.Sprintf("AIFuzzing-report-%s.xlsx", timestamp))

	// 保存文件
	if err := f.SaveAs(filename); err != nil {
		return "", fmt.Errorf("保存Excel报告失败: %v", err)
	}

	return filename, nil
}

// prepareReportData 准备报告数据
func (rg *ReportGenerator) prepareReportData() Report {
	// 统计结果
	var vulnerableResults []interface{}
	var unknownResults []interface{}
	var totalSafe int
	var totalFalsePositive int

	for _, result := range rg.Results {
		// 确保结果是一个有效的 map[string]interface{}
		r, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		// 确保所有必需的字段都存在
		resultStr, ok := r["result"].(string)
		if !ok {
			continue
		}

		// 初始化必需的字段（如果不存在）
		if _, ok := r["method"]; !ok {
			r["method"] = ""
		}
		if _, ok := r["url"]; !ok {
			r["url"] = ""
		}
		if _, ok := r["requestA"]; !ok {
			r["requestA"] = ""
		}
		if _, ok := r["requestB"]; !ok {
			r["requestB"] = ""
		}
		if _, ok := r["headerA"]; !ok {
			r["headerA"] = ""
		}
		if _, ok := r["headerB"]; !ok {
			r["headerB"] = ""
		}
		if _, ok := r["respBodyA"]; !ok {
			r["respBodyA"] = ""
		}
		if _, ok := r["respBodyB"]; !ok {
			r["respBodyB"] = ""
		}
		if _, ok := r["reason"]; !ok {
			r["reason"] = ""
		}
		if _, ok := r["vulnType"]; !ok {
			r["vulnType"] = ""
		}
		if _, ok := r["isFalsePositive"]; !ok {
			r["isFalsePositive"] = false
		}
		
		// 确保similarity字段一定是float64类型
		simValue, ok := r["similarity"].(float64)
		if !ok {
			// 如果不是float64，尝试转换
			switch v := r["similarity"].(type) {
			case int:
				simValue = float64(v)
			case int32:
				simValue = float64(v)
			case int64:
				simValue = float64(v)
			case float32:
				simValue = float64(v)
			case string:
				// 尝试将字符串转换为float64
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					simValue = f
				} else {
					simValue = 0.0
				}
			default:
				simValue = 0.0
			}
			r["similarity"] = simValue
		}
		
		if _, ok := r["differences"]; !ok {
			r["differences"] = []string{}
		}
		if _, ok := r["sensitiveData"]; !ok {
			r["sensitiveData"] = []string{}
		}
		if _, ok := r["scanTime"]; !ok {
			r["scanTime"] = time.Now().Format("2006-01-02 15:04:05")
		}

		// 检查是否为误报
		if isFalsePositive, ok := r["isFalsePositive"].(bool); ok && isFalsePositive {
			totalFalsePositive++
		}

		switch resultStr {
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
		TotalFalsePositive: totalFalsePositive,
		VulnerableResults: vulnerableResults,
		UnknownResults:    unknownResults,
	}
}

// UpdateFalsePositive 更新报告中指定结果的误报状态
func (rg *ReportGenerator) UpdateFalsePositive(index int, isFalsePositive bool) {
	if index < 0 || index >= len(rg.Results) {
		return
	}

	// 将结果转换为map以便更新
	if result, ok := rg.Results[index].(map[string]interface{}); ok {
		result["isFalsePositive"] = isFalsePositive
		rg.Results[index] = result
	}
}
