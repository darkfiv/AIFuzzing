# 贡献指南

感谢您考虑为 AIFuzzing 项目做出贡献！您的参与对于改进这个工具非常重要。

## 贡献流程

1. 先 Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的修改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建一个新的 Pull Request

## 代码规范

- 遵循Go语言的官方代码规范
- 使用有意义的变量名和函数名
- 为所有公开的函数、类型和变量添加文档注释
- 添加单元测试和功能测试覆盖您的代码

## 提交bug或功能请求

如果您发现了bug或有新功能建议，请创建一个issue并提供以下信息：

**对于bug**:
- 描述问题和预期行为
- 如何重现问题的步骤
- 运行环境(操作系统、Go版本等)
- 错误日志或截图(如果有)

**对于功能请求**:
- 对新功能的清晰描述
- 解释为什么这个功能对项目有益
- 提供可能的实现方案(可选)

## 开发环境设置

1. 确保您已安装Go 1.16+
2. 克隆仓库并安装依赖
```bash
git clone https://github.com/yourusername/AIFuzzing.git
cd AIFuzzing
go mod download
```

3. 运行测试确保一切正常
```bash
go test ./...
```

## 构建和测试

- 使用提供的构建脚本进行跨平台编译
```bash
# Linux/macOS
./scripts/build.sh

# Windows
scripts\build.bat
```

- 编译单个平台版本
```bash
# 例如仅编译当前平台版本
go build -o aifuzzing main.go scan.go
```

## 分支策略

- `main`: 稳定版本分支
- `develop`: 开发分支，所有功能分支合并到此
- `feature/*`: 新功能开发分支
- `bugfix/*`: bug修复分支
- `release/*`: 发布准备分支

## 版本发布

我们使用[语义化版本](https://semver.org/)进行版本管理:

- 主版本号(x.0.0): 不兼容的API变更
- 次版本号(0.x.0): 向后兼容的功能性新增
- 修订号(0.0.x): 向后兼容的问题修正

## 行为准则

请尊重所有项目参与者，创建一个开放和友好的环境。禁止任何形式的骚扰或冒犯性行为。

## 许可证

通过贡献代码，您同意您的贡献将在与项目相同的[MIT许可证](LICENSE)下发布。

感谢您的贡献！ 