#!/bin/bash

# 设置输出颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 创建输出目录
OUTPUT_DIR="./dist"
mkdir -p $OUTPUT_DIR

echo -e "${YELLOW}开始编译 AIFuzzing...${NC}"

# 标记版本
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date "+%Y-%m-%d %H:%M:%S")
BUILD_INFO="-X 'main.Version=$VERSION' -X 'main.Commit=$COMMIT' -X 'main.BuildDate=$BUILD_DATE'"

# 编译macOS版本 (Intel)
echo -e "${BLUE}编译 macOS/amd64 版本...${NC}"
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$BUILD_INFO" -o "$OUTPUT_DIR/aifuzzing_macos_amd64" main.go scan.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ macOS/amd64 编译成功${NC}"
else
    echo -e "${RED}× macOS/amd64 编译失败${NC}"
fi

# 编译macOS版本 (Apple Silicon)
echo -e "${BLUE}编译 macOS/arm64 版本...${NC}"
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$BUILD_INFO" -o "$OUTPUT_DIR/aifuzzing_macos_arm64" main.go scan.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ macOS/arm64 编译成功${NC}"
else
    echo -e "${RED}× macOS/arm64 编译失败${NC}"
fi

# 编译Linux版本
echo -e "${BLUE}编译 Linux/amd64 版本...${NC}"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$BUILD_INFO" -o "$OUTPUT_DIR/aifuzzing_linux_amd64" main.go scan.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Linux/amd64 编译成功${NC}"
else
    echo -e "${RED}× Linux/amd64 编译失败${NC}"
fi

# 编译Windows版本
echo -e "${BLUE}编译 Windows/amd64 版本...${NC}"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$BUILD_INFO" -o "$OUTPUT_DIR/aifuzzing_windows_amd64.exe" main.go scan.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Windows/amd64 编译成功${NC}"
else
    echo -e "${RED}× Windows/amd64 编译失败${NC}"
fi

echo -e "${YELLOW}编译完成. 二进制文件在 $OUTPUT_DIR 目录中${NC}"
ls -lh $OUTPUT_DIR 