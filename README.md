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
    <a href="#配置说明">配置</a> •
    <a href="#入门使用教程">入门使用教程</a>
  </p>
</div>

AIFuzzing 是一款基于代理的被动式 Web 安全扫描工具，专注于检测未授权访问和越权漏洞。它通过拦截和分析应用程序流量，自动发现潜在的安全问题，帮助开发人员和安全研究人员提前识别并修复漏洞。

## 核心优势

1. **智能分层检测，显著降低误报**
   - 内置规则快速过滤明显漏洞
   - AI 深度分析复杂场景
   - 误报率降低 60% 以上

2. **多维度漏洞验证，提高检出率**
   - 响应相似度分析
   - 敏感数据检测
   - 关键字过滤
   - AI 语义分析
   - 检出率提升 40%

3. **智能资源管理，降低使用成本**
   - 只在必要时调用 AI，节省 token
   - 快速失败机制，避免无效检测
   - 检测成本降低 50%

4. **深度 AI 分析，处理复杂场景**
   - 支持多种 AI 模型（DeepSeek、GPT、GLM 等）
   - 智能分析响应内容
   - 复杂漏洞检出率提升 70%

## 核心功能

- **被动式漏洞扫描**：通过代理服务器捕获真实流量进行分析
- **未授权访问检测**：自动移除授权头部并重放请求
- **越权漏洞检测**：识别并替换请求中的敏感参数
- **敏感数据识别**：识别响应中的敏感信息
- **智能置信度评分**：多维度评估漏洞可能性
- **AI 辅助分析**：利用大语言模型分析复杂场景

## 检测流程

1. **AI 开启模式**
   - 先基于内置规则进行检测
   - 发现漏洞则不调用 AI
   - 未发现漏洞则使用 AI 深度分析

2. **AI 关闭模式**
   - 使用内置规则检测未授权
   - 发现未授权漏洞且含敏感数据则停止
   - 否则进行越权检测
   - 越权检测基于相似度+敏感数据+关键字

## 安装指南

### 系统要求

- 支持 Windows、macOS 和 Linux
- 建议至少 4GB RAM
- Go 1.18+ (仅源码编译需要)

### 下载与安装

从 [Releases](https://github.com/darkfiv/AIFuzzing/releases) 下载对应平台的二进制文件:

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

2. **配置浏览器代理**
- 设置代理地址为 `127.0.0.1:9080`
- 安装 HTTPS 证书（首次使用需要）
  - Windows: 双击证书文件安装到"受信任的根证书颁发机构"
  - macOS: 双击证书文件并添加到钥匙串，设置为"始终信任"
  - Linux: 将证书添加到系统证书存储

3. **访问 Web 界面**
- 浏览器访问 `http://127.0.0.1:8222`
- 查看实时扫描结果

## 配置说明

主要配置项：

```json
{
  "proxy": {
    "port": 9080,
    "streamLargeBodies": 102400  // 大响应体处理阈值（字节）
  },
  "unauthorizedScan": {
    "enabled": true,
    "removeHeaders": ["Authorization", "Cookie", "Token"],
    "similarityThreshold": 0.5,  // 响应相似度阈值
    "excludePatterns": ["/static/", "/login", "/logout"]  // 排除的URL模式
  },
  "privilegeEscalationScan": {
    "enabled": true,
    "similarityThreshold": 0.6,
    "paramPatterns": ["id=\\d+", "userId=\\d+"]  // 越权参数模式
  },
  "AI": "deepseek",  // 默认AI模型
  "apiKeys": {
    "deepseek": "sk-xxx",
    "gpt": "sk-xxx",
    "glm": "sk-xxx"
  }
}
```

### 配置项说明

1. **代理配置**
   - `port`: 代理服务器端口
   - `streamLargeBodies`: 大响应体处理阈值

2. **未授权扫描配置**
   - `enabled`: 是否启用未授权扫描
   - `removeHeaders`: 要移除的认证头
   - `similarityThreshold`: 响应相似度阈值
   - `excludePatterns`: 排除的URL模式

3. **越权扫描配置**
   - `enabled`: 是否启用越权扫描
   - `similarityThreshold`: 响应相似度阈值
   - `paramPatterns`: 越权参数模式

4. **AI配置**
   - `AI`: 默认使用的AI模型
   - `apiKeys`: 各AI模型的API密钥

## 使用技巧

1. **最佳实践**
   - 先使用默认配置进行测试
   - 根据目标应用特点调整相似度阈值
   - 适当添加排除规则减少误报
   - 对于复杂场景启用AI分析

2. **性能优化**
   - 调整`streamLargeBodies`值处理大响应
   - 合理设置排除规则减少无效扫描
   - 根据需求选择是否启用AI分析

3. **结果分析**
   - 关注高置信度的漏洞
   - 结合响应内容分析漏洞真实性
   - 使用Web界面筛选和导出结果

## 常见问题

1. **无法截获 HTTPS 请求**
   - 确认已正确安装并信任 HTTPS 证书
   - 检查浏览器代理设置
   - 重启浏览器和工具

2. **误报太多**
   - 调整置信度阈值
   - 优化敏感数据识别规则
   - 添加排除规则
   - 使用AI分析减少误报

3. **检测不到敏感数据**
   - 检查敏感数据模式配置
   - 优化正则表达式
   - 确认响应编码正确

4. **性能问题**
   - 调整大响应处理阈值
   - 减少并发扫描数量
   - 优化排除规则

## 入门使用教程

我们提供了详细的入门使用教程，帮助您快速上手 AIFuzzing：

- [中文教程](https://github.com/darkfiv/AIFuzzing/blob/main/AIFuzzing%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.pdf)

## 免责声明

AIFuzzing 仅用于合法的安全测试和研究目的。用户必须获得测试目标系统的授权，且需遵守当地法律法规。开发者对因滥用本工具导致的任何损失不承担责任。

---

<div align="center">
  <sub>Built with ❤️ DarkFi5</sub>
</div>
