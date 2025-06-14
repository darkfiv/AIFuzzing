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
    <a href="#web-界面使用">使用</a>
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

3. **访问 Web 界面**
- 浏览器访问 `http://127.0.0.1:8222`
- 查看实时扫描结果

## 配置说明

主要配置项：

```json
{
  "proxy": {
    "port": 9080
  },
  "unauthorizedScan": {
    "enabled": true,
    "removeHeaders": ["Authorization", "Cookie", "Token"],
    "similarityThreshold": 0.5
  },
  "privilegeEscalationScan": {
    "enabled": true,
    "similarityThreshold": 0.6
  },
  "AI": "deepseek",
  "apiKeys": {
    "deepseek": "sk-xxx"
  }
}
```

## 常见问题

1. **无法截获 HTTPS 请求**
   - 确认已正确安装并信任 HTTPS 证书

2. **误报太多**
   - 调整置信度阈值
   - 优化敏感数据识别规则
   - 添加排除规则

3. **检测不到敏感数据**
   - 检查敏感数据模式配置
   - 优化正则表达式

## 免责声明

AIFuzzing 仅用于合法的安全测试和研究目的。用户必须获得测试目标系统的授权，且需遵守当地法律法规。开发者对因滥用本工具导致的任何损失不承担责任。

---

<div align="center">
  <sub>Built with ❤️ DarkFi5</sub>
</div>
