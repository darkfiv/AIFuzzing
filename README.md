# AIFuzzing

AIFuzzing是一款基于人工智能的Web安全漏洞自动化检测工具，专注于被动式检测未授权访问与越权漏洞。通过智能分析HTTP请求和响应，AIFuzzing可以自动发现应用程序中潜在的安全问题，帮助开发人员和安全研究人员提前识别并修复漏洞。

## 核心功能

- **被动式漏洞检测**：无需主动发起扫描，通过代理服务器捕获真实流量进行分析
- **未授权访问检测**：自动识别API接口的访问控制缺陷
- **水平/垂直越权检测**：通过请求差异对比识别越权漏洞
- **敏感数据泄露检测**：使用正则表达式识别响应中的敏感信息（手机号、邮箱、身份证等）
- **AI辅助分析**：利用大语言模型分析请求和响应差异，提高检测准确性
- **实时Web界面**：直观展示检测结果并支持筛选
- **详细报告生成**：支持多种格式的安全报告导出

## 技术特点

### 智能噪音过滤

AIFuzzing采用多重策略过滤噪音数据，提高检测准确率：

1. **静态资源过滤**：自动识别并忽略JS、CSS、图片等静态资源请求
2. **响应内容过滤**：过滤常见的401/403错误页面、验证码页面等
3. **业务错误识别**：智能识别JSON响应中的业务错误码，避免将正常业务响应误判为漏洞
4. **相似度比对**：使用文本相似度算法分析响应内容差异，降低误报率
5. **白名单机制**：支持URL和响应内容白名单，忽略已知安全的接口

### 智能优先级处理

AIFuzzing实现了智能的请求处理优先级系统：

1. **高优先级请求处理**：登录、认证、Token相关请求优先处理，确保授权信息能及时获取
2. **低优先级并发处理**：常规API请求在资源允许的条件下并发处理
3. **自动资源清理**：过期和已处理请求自动清理，防止内存泄漏

### 未授权访问检测技术

针对未授权访问漏洞的智能检测：

1. **置信度评分系统**：采用多维度规则评估未授权访问可能性，减少误报
2. **认证头部移除**：自动移除认证相关头部后重放请求
3. **状态码分析**：根据不同状态码进行初步判断，如200与401/403的差异
4. **敏感数据检测**：自动识别响应中的敏感信息（手机号、身份证等）
5. **错误关键词分析**：检测响应中是否包含权限错误相关词汇

### 基于敏感数据的越权漏洞检测

AIFuzzing创新性地将敏感数据检测作为越权判定的核心指标：

1. **多方位分析**：对比原始请求和伪造请求响应中的敏感数据差异
2. **双重判定机制**：
   - 若替换请求响应中包含敏感数据但原始响应中没有 → 极可能存在越权
   - 若两者都包含敏感数据但内容不同 → 确认存在越权
   - 若两者包含相同敏感数据 → 结合相似度和AI分析进行判断

3. **人工智能辅助**：当敏感数据和相似度判断不明确时，调用大语言模型进行深度分析

### 置信度评分系统

AIFuzzing的置信度评分系统用于评估未授权访问漏洞的可能性：

1. **多规则评分**：综合8种不同规则进行评分：
   - 敏感数据存在（40分）
   - 成功状态码（15分）
   - 无错误关键词（15分）
   - JSON响应（10分）
   - 非空响应（10分）
   - API端点（10分）
   - 相同内容类型（5分）
   - 相似响应长度（5分）
   
2. **置信度等级**：
   - 高置信度（≥60分）：极有可能存在未授权访问
   - 中置信度（40-59分）：可能存在未授权访问
   - 低置信度（20-39分）：潜在未授权访问，需进一步验证
   - 不可信（<20分）：很可能不存在漏洞

3. **自定义规则**：支持自定义评分规则和权重，适应不同业务场景

### 敏感数据识别

内置多种敏感数据模式识别能力：

- 手机号码
- 电子邮箱
- 身份证号
- 中文姓名
- 银行卡号
- 用户ID
- 地址信息

## 安装与使用

### 系统要求

- Go 1.18+
- 支持Windows, macOS, Linux

### 安装方法

#### 从源码编译[源码暂不开源]

1. 克隆仓库
```bash
git clone https://github.com/yourusername/AIFuzzing.git
cd AIFuzzing
```

2. 不同环境下编译

**macOS**
```bash
# 对于Intel芯片
GOOS=darwin GOARCH=amd64 go build -o aifuzz

# 对于M1/M2/M3芯片
GOOS=darwin GOARCH=arm64 go build -o aifuzz
```

**Linux**
```bash
GOOS=linux GOARCH=amd64 go build -o aifuzz
```

**Windows**
```bash
GOOS=windows GOARCH=amd64 go build -o aifuzz.exe
```

### 快速开始

1. 配置代理：
```bash
./aifuzz -port 9080 【需要下载index.html、config.json、whitelist.txt至同一目录下】
```

2. 配置浏览器代理：
   - 设置HTTP/HTTPS代理为127.0.0.1:9080
   - 访问mitm.it安装HTTPS证书

3. 访问Web界面查看结果：
   - 打开浏览器访问http://127.0.0.1:8222

### 配置说明

工具的核心配置存储在`config.json`文件中，主要包括以下部分：

#### 代理配置

```json
"proxy": {
  "port": 9080,
  "streamLargeBodies": 1024
}
```

#### 未授权访问扫描配置

```json
"unauthorizedScan": {
  "enabled": true,
  "removeHeaders": [
    "Authorization",
    "Cookie",
    "Token",
    "Jwt",
    "X-Auth-Token",
    "X-Csrf-Token",
    "X-Api-Key"
  ],
  "sensitiveDataPatterns": {
    "enabled": true,
    "patterns": [
      {
        "name": "phone",
        "pattern": "1[3-9]\\d{9}",
        "description": "中国手机号码"
      }
    ]
  },
  "useConfidenceScore": true,
  "highConfidenceScore": 60,
  "mediumConfidenceScore": 40,
  "lowConfidenceScore": 20
}
```

#### 越权检测配置

```json
"privilegeEscalationScan": {
  "enabled": true,
  "similarityThreshold": 0.6,
  "paramPatterns": [
    "id=\\d+",
    "userId=\\d+",
    "user_id=\\d+",
    "memberId=\\d+"
  ]
}
```

#### AI辅助分析配置

```json
"AI": "deepseek",
"apiKeys": {
  "deepseek": "sk-xxxxxxx",
  "kimi": "sk-xxxxxxx",
  "qianwen": "sk-xxxxxxx",
  "gpt": "sk-xxxxxxx"
}
```


<b> whitelist.txt【注意：放顶级域名】</b>
  白名单，只对符合白名单顶级域名内的目标测试，一定存放的事顶级域名，不然会错误。
例如：
<img width="114" alt="image" src="https://github.com/user-attachments/assets/248faea0-d8ab-42f1-8ae7-7c0b0caaaa4b" />


## 检测原理

### 未授权访问检测

1. 移除原始请求中的认证相关头部（Cookie、Authorization等）
2. 发送修改后的请求并获取响应
3. 分析响应内容，通过置信度评分系统评估未授权访问可能性
4. 检测响应中的敏感数据，如存在则提高风险等级
5. 返回检测结果和详细信息

### 越权漏洞检测

1. 识别请求中的敏感参数（如ID、用户标识符等）
2. 替换请求中的认证信息为其他用户的身份
3. 发送修改后的请求并获取响应
4. 比较原始响应和修改后响应的敏感数据差异
5. 调用AI模型分析响应内容差异，识别潜在越权问题
6. 返回检测结果和详细信息

## 结果解读

### 未授权访问结果

- **true**：高可能性未授权访问漏洞，包含敏感数据或置信度分数高
- **unknown**：中等可能性，需要人工确认
- **false**：低可能性，可能是正常行为

### 越权漏洞结果

- **true**：高可能性越权漏洞，不同身份可访问相同敏感数据
- **unknown**：需要人工确认，AI分析结果不确定
- **false**：低可能性，不存在越权问题

## 最佳实践

1. 在测试环境中使用，减少对生产环境的影响
2. 使用独立的测试账户，避免实际用户数据泄露
3. 优先关注高置信度的漏洞报告
4. 结合人工分析，确认漏洞的实际影响
5. 定期更新配置文件中的敏感数据模式，提高检测准确率

## 常见问题

### HTTPS证书问题

- 确保正确安装了mitmproxy证书
- 对于Chrome，可启用`chrome://flags`中的`Allow invalid certificates for resources loaded from localhost`
- 对于Android设备，需要将证书安装到系统证书存储区

### 检测灵敏度调整

- 调整置信度阈值和规则权重
- 添加特定URL到`excludePatterns`排除不需要检测的端点
- 优化`sensitiveDataPatterns`适应业务数据特征

## 贡献与支持

欢迎提交Issues和Pull Requests来完善本工具。详情请参阅[贡献指南](CONTRIBUTING.md)。

## 许可证

本项目采用MIT许可证 - 查看[LICENSE](LICENSE)文件了解详情。
