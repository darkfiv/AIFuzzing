package similarity

import (
	"encoding/json"
	"math"
	"strings"
)

// CalculateSimilarity 计算两个字符串的相似度（返回0.0-1.0之间的值）
func CalculateSimilarity(str1, str2 string) float64 {
	// 如果任一字符串为空，返回0
	if str1 == "" || str2 == "" {
		return 0.0
	}
	
	// 如果两个字符串完全相同，返回1
	if str1 == str2 {
		return 1.0
	}

	// 尝试解析JSON并比较结构
	similarity, jsonValid := compareJSON(str1, str2)
	if jsonValid {
		return similarity
	}

	// 如果不是有效的JSON或JSON比较得分较低，使用文本相似度算法
	return calculateJaccardSimilarity(str1, str2)
}

// compareJSON 尝试将字符串解析为JSON并比较结构
func compareJSON(str1, str2 string) (float64, bool) {
	var jsonObj1 interface{}
	var jsonObj2 interface{}

	// 尝试解析第一个字符串
	err1 := json.Unmarshal([]byte(str1), &jsonObj1)
	if err1 != nil {
		return 0.0, false
	}

	// 尝试解析第二个字符串
	err2 := json.Unmarshal([]byte(str2), &jsonObj2)
	if err2 != nil {
		return 0.0, false
	}

	// 两个字符串都是有效的JSON，比较它们的结构
	return compareJSONStructure(jsonObj1, jsonObj2), true
}

// compareJSONStructure 比较两个JSON对象的结构
func compareJSONStructure(obj1, obj2 interface{}) float64 {
	// 处理不同类型的情况
	switch v1 := obj1.(type) {
	case map[string]interface{}: // JSON对象
		v2, ok := obj2.(map[string]interface{})
		if !ok {
			return 0.0 // 类型不同
		}
		return compareJSONObjects(v1, v2)
		
	case []interface{}: // JSON数组
		v2, ok := obj2.([]interface{})
		if !ok {
			return 0.0 // 类型不同
		}
		return compareJSONArrays(v1, v2)
		
	default: // 简单值
		if obj1 == obj2 {
			return 1.0
		}
		
		// 字符串类型的简单值做进一步比较
		str1, ok1 := obj1.(string)
		str2, ok2 := obj2.(string)
		if ok1 && ok2 {
			return calculateLevenshteinSimilarity(str1, str2)
		}
		
		// 其他类型的值不相等，返回0
		return 0.0
	}
}

// compareJSONObjects 比较两个JSON对象
func compareJSONObjects(obj1, obj2 map[string]interface{}) float64 {
	// 如果两个对象中的一个为空，而另一个不为空
	if (len(obj1) == 0) != (len(obj2) == 0) {
		return 0.0
	}
	
	// 如果两个对象都为空，认为它们相似
	if len(obj1) == 0 && len(obj2) == 0 {
		return 1.0
	}
	
	// 计算键的交集和并集
	commonKeys := 0
	allKeys := make(map[string]bool)
	
	// 统计所有键
	for k := range obj1 {
		allKeys[k] = true
	}
	for k := range obj2 {
		allKeys[k] = true
	}
	
	// 计算相似度总和
	totalSimilarity := 0.0
	
	// 比较每个键的值
	for k := range allKeys {
		val1, ok1 := obj1[k]
		val2, ok2 := obj2[k]
		
		if ok1 && ok2 {
			// 两个对象都有这个键，比较它们的值
			commonKeys++
			totalSimilarity += compareJSONStructure(val1, val2)
		}
	}
	
	// 如果没有共同的键，返回0
	if commonKeys == 0 {
		return 0.0
	}
	
	// 计算平均相似度
	return totalSimilarity / float64(commonKeys) * (float64(commonKeys) / float64(len(allKeys)))
}

// compareJSONArrays 比较两个JSON数组
func compareJSONArrays(arr1, arr2 []interface{}) float64 {
	len1 := len(arr1)
	len2 := len(arr2)
	
	// 如果两个数组中的一个为空，而另一个不为空
	if (len1 == 0) != (len2 == 0) {
		return 0.0
	}
	
	// 如果两个数组都为空，认为它们相似
	if len1 == 0 && len2 == 0 {
		return 1.0
	}
	
	// 计算数组元素的最大匹配相似度
	maxLen := int(math.Max(float64(len1), float64(len2)))
	totalSimilarity := 0.0
	
	// 对于较小长度的数组，只比较到它的长度
	minLen := int(math.Min(float64(len1), float64(len2)))
	
	for i := 0; i < minLen; i++ {
		totalSimilarity += compareJSONStructure(arr1[i], arr2[i])
	}
	
	// 返回平均相似度，考虑长度差异
	return totalSimilarity / float64(maxLen)
}

// calculateJaccardSimilarity 计算两个字符串的Jaccard相似度
func calculateJaccardSimilarity(str1, str2 string) float64 {
	// 将字符串拆分为单词
	words1 := splitIntoWords(str1)
	words2 := splitIntoWords(str2)
	
	// 如果两个都是空集，返回1
	if len(words1) == 0 && len(words2) == 0 {
		return 1.0
	}
	
	// 计算交集大小
	intersection := 0
	for word := range words1 {
		if words2[word] {
			intersection++
		}
	}
	
	// 计算并集大小
	union := len(words1) + len(words2) - intersection
	
	// 计算Jaccard系数
	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

// calculateLevenshteinSimilarity 计算基于Levenshtein距离的相似度
func calculateLevenshteinSimilarity(str1, str2 string) float64 {
	len1 := len(str1)
	len2 := len(str2)
	
	// 如果其中一个字符串为空，相似度取决于另一个字符串的长度
	if len1 == 0 {
		return 0.0
	}
	if len2 == 0 {
		return 0.0
	}
	
	// 如果两个字符串相同，相似度为1
	if str1 == str2 {
		return 1.0
	}
	
	// 创建距离矩阵
	matrix := make([][]int, len1+1)
	for i := range matrix {
		matrix[i] = make([]int, len2+1)
	}
	
	// 初始化矩阵
	for i := 0; i <= len1; i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}
	
	// 填充矩阵
	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 1
			if str1[i-1] == str2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,     // 删除
				matrix[i][j-1]+1,     // 插入
				matrix[i-1][j-1]+cost, // 替换
			)
		}
	}
	
	// 计算距离
	distance := matrix[len1][len2]
	
	// 计算相似度
	maxLen := int(math.Max(float64(len1), float64(len2)))
	if maxLen == 0 {
		return 1.0
	}
	
	// 返回基于距离的相似度
	return 1.0 - float64(distance)/float64(maxLen)
}

// splitIntoWords 将字符串拆分为单词集合
func splitIntoWords(str string) map[string]bool {
	words := make(map[string]bool)
	
	// 简单拆分为单词（可以根据需要使用更复杂的分词方法）
	for _, word := range strings.Fields(strings.ToLower(str)) {
		// 去除标点符号
		word = strings.Trim(word, ".,?!:;-_\"'()[]{}\u3002\uff0c\uff1f\uff01\uff1a\uff1b\u201c\u201d\u2018\u2019\uff08\uff09\u3010\u3011")
		if word != "" {
			words[word] = true
		}
	}
	
	return words
}

// min 返回三个整数中的最小值
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// 中文符号
func isChinese(char rune) bool {
	if (char >= '\u4e00' && char <= '\u9fa5') || // 中文
		(char >= '\u3400' && char <= '\u4db5') || // 扩展A
		(char >= '\uf900' && char <= '\ufa6a') || // 兼容
		(char >= '\u2e80' && char <= '\u9fff') { // 其他CJK
		return true
	}
	
	// 常见标点符号 - 使用Unicode编码
	chinesePunct := []rune{
		'\uff0c', // ，
		'\u3002', // 。
		'\u3001', // 、
		'\uff1b', // ；
		'\uff1a', // ：
		'\uff1f', // ？
		'\uff01', // ！
		'\u201c', // "
		'\u201d', // "
		'\u2018', // '
		'\u2019', // '
		'\uff08', // （
		'\uff09', // ）
		'\u3010', // 【
		'\u3011', // 】
		'\u300a', // 《
		'\u300b', // 》
		'\u3008', // 〈
		'\u3009', // 〉
	}
	
	for _, p := range chinesePunct {
		if char == p {
			return true
		}
	}
	
	return false
}