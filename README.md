# AIFuzzing

<div align="center">
  <p>
    <img src="https://img.shields.io/github/stars/darkfiv/AIFuzzing?style=social" alt="GitHub stars">
  </p>
  <p><strong>智能越权与未授权访问检测工具</strong></p>
  <p>
    <a href="#核心功能">功能</a> •
    <a href="#安装指南">安装</a> •
    <a href="#快速开始">快速开始</a> •
    <a href="#配置详解">配置</a> •
    <a href="#web-界面使用">使用</a> •
    <a href="#入门使用教程">入门使用教程</a> •
    <a href="#更新日志">更新日志</a>
  </p>
</div>

AIFuzzing 是一款基于代理的被动式 Web 安全扫描工具，专注于检测未授权访问和越权漏洞。它通过拦截和分析应用程序流量，自动发现潜在的安全问题，帮助开发人员和安全研究人员提前识别并修复漏洞。

## 核心功能

- **被动式漏洞扫描**：无需主动发起扫描，通过代理服务器捕获真实流量进行分析
- **未授权访问检测**：自动移除授权头部并重放请求，检测缺乏访问控制的 API 接口
- **越权漏洞检测**：识别并替换请求中的敏感参数，检测水平和垂直越权问题
- **敏感数据识别**：使用正则表达式识别响应中的敏感信息（手机号、邮箱、身份证等）
- **智能置信度评分**：多维度评估漏洞可能性，减少误报
- **流式响应处理**：高效处理大型响应体，确保扫描性能
- **Web UI 界面**：实时查看扫描结果，支持结果筛选和报告导出
- **AI 辅助分析**：利用大语言模型分析复杂场景，提高检测准确性

## 人工规则+AI检测
1、AI 开启模式下，会先基于内置规则，对请求进行未授权/越权测试，若内置规则已发现漏洞，则不调用AI，减少token消耗。<br>
2、AI 模式未开启状态下，使用内置规则进行测试，内置规则先测试未授权【融合了Xia Yue】，若测试出未授权漏洞且包含敏感数据，跳出不再进行后续检测；若未检测出漏洞，或者存在未授权但是响应不包含敏感数据，会下发给越权模块检测，越权模块基于相似度+敏感数据匹配多维度去关联是否存在越权漏洞。<br>

## 安装指南

### 系统要求

- 支持 Windows、macOS 和 Linux
- 足够的内存处理并发请求（建议至少 4GB RAM）
- Go 1.18+ (仅源码编译需要)

### 下载与安装

#### 预编译二进制文件（推荐）

直接从 [Releases](https://github.com/darkfiv/AIFuzzing/releases) 页面下载对应平台的二进制文件:

- Windows: `AIFuzzing_windows_amd64.zip`
- macOS: `AIFuzzing_macos_arm64.zip` (Apple Silicon) / `AIFuzzing_macos_amd64.zip` (Intel)
- Linux: `AIFuzzing_linux_amd64.zip`

下载后解压，包含以下文件：
- 可执行文件 (`AIFuzzing` 或 `AIFuzzing.exe`)
- 配置文件 (`config.json`)
- Web界面文件 (`index.html`)

## 快速开始

1. **启动代理服务**

```bash
# Windows
AIFuzzing.exe

# macOS/Linux
./AIFuzzing
```

默认使用配置文件 `config.json`，也可指定配置文件：

```bash
./AIFuzzing -config my-config.json
```

2. **配置浏览器或应用程序代理**

设置代理地址为 `127.0.0.1:9080`（默认端口）

3. **安装 HTTPS 证书**

首次使用时需安装 HTTPS 证书：
怎么安装mitmproxy证书大家自行百度吧，教程太多不细说了。

对于 macOS 用户，可执行以下命令信任证书：
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

4. **访问 Web 界面查看结果**

浏览器访问 `http://127.0.0.1:8222` 查看实时扫描结果

## 配置详解

AIFuzzing 使用 JSON 格式的配置文件，主要配置项如下：

### 代理配置

```json
"proxy": {
  "port": 9080,
  "streamLargeBodies": 102400
}
```

- `port`: 代理服务器监听端口
- `streamLargeBodies`: 以字节为单位的大响应体阈值，超过此值使用流式处理（默认 100KB）

### 未授权访问扫描配置

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
    "Sectoken",
    "X-Api-Key"
  ],
  "similarityThreshold": 0.5,
  "excludePatterns": [
    "/static/",
    "/login",
    "/logout"
  ],
  "sensitiveDataPatterns": {
    "enabled": true,
    "jsonPatterns": [
      {
        "name": "phone",
        "pattern": "(?:[^\\w]|^)((?:(?:\\+|00)86)?1(?:(?:3[\\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\\d])|(?:9[189]))\\d{8})(?:[^\\w]|$)",
        "description": "中国手机号码"
      }
    ]
  },
  "useConfidenceScore": true,
  "highConfidenceScore": 60,
  "mediumConfidenceScore": 45,
  "lowConfidenceScore": 35
}
```

- `enabled`: 是否启用未授权访问扫描
- `removeHeaders`: 重放请求时要移除的鉴权头部列表
- `similarityThreshold`: 响应相似度阈值，用于比较原始响应和未授权响应
- `excludePatterns`: 排除的 URL 路径模式列表
- `sensitiveDataPatterns`: 敏感数据检测配置，包含 JSON 响应中的敏感数据模式
- `useConfidenceScore`: 是否启用置信度评分系统
- `highConfidenceScore`: 高置信度分数阈值（≥此值视为高可能性漏洞）
- `mediumConfidenceScore`: 中置信度分数阈值
- `lowConfidenceScore`: 低置信度分数阈值

### 若要退出程序，ctrl+c即可

### 越权漏洞扫描配置

```json
"privilegeEscalationScan": {
  "enabled": true,
  "similarityThreshold": 0.6,
  "paramPatterns": [
    "id=\\d+",
    "userId=\\d+",
    "user_id=\\d+",
    "accountId=\\d+",
    "memberId=\\d+"
  ]
}
```

- `enabled`: 是否启用越权漏洞扫描
- `similarityThreshold`: 响应相似度阈值
- `paramPatterns`: 用于识别可能触发越权漏洞的参数模式列表

### AI 辅助分析配置

```json
"AI": "deepseek",
"apiKeys": {
  "deepseek": "sk-xxx",
  "kimi": "sk-xxx",
  "qianwen": "sk-xxx",
  "hunyuan": "sk-xxx",
  "glm": "sk-xxx",
  "gpt": "sk-xxx"
}
```

- `AI`: 默认使用的 AI 模型
- `apiKeys`: 各 AI 模型的 API 密钥配置


## 大响应处理机制

AIFuzzing 内置了高效的大响应处理机制：

1. 通过 `proxy.streamLargeBodies` 设置大响应流式处理阈值（默认 100KB）
2. 使用 go-mitmproxy 提供的流式处理能力，避免一次性加载整个响应体
3. 敏感数据检测时，对于超过 10MB 的响应体会进行截断处理以保护性能
4. 在比较响应相似度时，仅处理合理长度的数据段

这些机制确保了工具在处理大型响应时的性能和稳定性。

## Web 界面使用

访问 `http://127.0.0.1:8222` 可使用 Web 界面：

1. **实时结果查看**：查看检测到的漏洞详情
2. **结果筛选**：按漏洞类型、检测结果进行筛选
3. **统计概览**：查看漏洞统计数据
4. **报告生成**：生成并下载安全报告

## 命令行参数

```
Usage: AIFuzzing [options]

Options:
  -config string
        配置文件路径 (默认 "config.json")
  -disableWebUI
        禁用Web界面
  -log string
        日志级别：debug, info, warning, error (默认 使用配置文件设置)
  -logFile
        启用文件日志
  -port int
        代理服务器端口 (默认 使用配置文件设置)
```

## 结果解读

### 漏洞严重程度

- **高危险**：置信度分数 ≥ 60，极有可能存在漏洞
- **中危险**：置信度分数 45-59，可能存在漏洞
- **低危险**：置信度分数 35-44，存在潜在风险
- **信息**：置信度分数 < 35, 可能是误报

### 置信度评分规则

评分由以下规则组成：

1. **包含敏感数据**：+65 分（例如手机号、身份证等）
2. **成功状态码**：+10 分（状态码为 2xx）
3. **JSON 响应**：+5 分（响应为有效的 JSON 格式）
4. **相似响应长度**：+10 分（与原始响应长度相近）
5. **API 端点**：+10 分（URL 为典型的 API 端点）

## 常见问题

### 无法截获 HTTPS 请求

- 确认已正确安装并信任 HTTPS 证书
- 对于 macOS，确保在钥匙串中将证书设置为"始终信任"
- 对于 iOS/Android 设备，确保已在设备设置中信任该证书

### 响应体过大导致内存问题

- 调整配置文件中的 `proxy.streamLargeBodies` 值
- 默认配置为 100KB，可根据系统内存适当调整

### 误报太多

- 调整 `unauthorizedScan.highConfidenceScore` 提高置信度要求
- 编辑 `unauthorizedScan.sensitiveDataPatterns` 优化敏感数据识别规则
- 将特定 URL 添加到 `unauthorizedScan.excludePatterns` 中排除

### 检测不到敏感数据

- 检查 `sensitiveDataPatterns` 配置，确保模式匹配目标敏感数据
- 使用更准确的正则表达式模式
- 对于大响应，检查是否启用了流式处理和适当的截断策略

## 入门使用教程

我们提供了详细的入门使用教程，帮助您快速上手 AIFuzzing：

- [中文教程](https://github.com/darkfiv/AIFuzzing/blob/main/AIFuzzing%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E.pdf)

## 更新日志

### v1.0.0 (2025-04-20)
- 首次发布
- 支持未授权访问检测
- 支持越权漏洞检测
- 支持敏感数据识别
- 支持AI辅助分析
- 支持Web界面查看结果
- url扫描去重，防止对同一个目标多次扫描

### v1.0.1 (2025-04-22)
- 结果展示界面添加搜索框，支持url模糊搜索
- 添加置信度打分细则，方便用户调试
- 支持json/csv/xlsx结果导出，默认导出为.json格式

### v1.0.2 (2025-04-24)
- 优化内置越权漏洞扫描逻辑
- 添加公共接口模糊过滤规则，路径包含关键字的请求均过滤【降误报，按个人需求开启】
- 优化内置AI prompt提示，提高越权场景识别精准度


## 免责声明

AIFuzzing 仅用于合法的安全测试和研究目的。用户必须获得测试目标系统的授权，且需遵守当地法律法规。开发者对因滥用本工具导致的任何损失不承担责任。

---

<div align="center">
  <sub>Built with ❤️ DarkFi5</sub>
</div>
