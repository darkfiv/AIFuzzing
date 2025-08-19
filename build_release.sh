#!/bin/bash

# AIFuzzing 打包发布脚本
# 作者: AIFuzzing Team
# 用途: 编译并打包AIFuzzing工具用于GitHub发布

# 显示彩色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}==== AIFuzzing 打包脚本开始执行 ====${NC}"

# 设置变量
VERSION="v1.0.5"  # 固定版本号
BUILD_DIR="build"
RELEASE_DIR="release"
BINARY_NAME="AIFuzzing"
REQUIRED_FILES=("index.html" "config.json" "whitelist.txt" "static")

# 检查必要的文件是否存在
echo -e "${YELLOW}检查必要文件...${NC}"
for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$file" ] && [ ! -d "$file" ]; then
    echo -e "${RED}错误: 未找到必要文件或目录 $file${NC}"
    exit 1
  else
    echo -e "${GREEN}✓ 找到文件或目录: $file${NC}"
  fi
done

# 创建构建目录
mkdir -p "$BUILD_DIR"
mkdir -p "$RELEASE_DIR"

# 清理旧文件
echo -e "${YELLOW}清理旧构建文件...${NC}"
rm -rf "$BUILD_DIR"/*
rm -rf "$RELEASE_DIR"/*

# 检测系统架构
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then
  ARCH="amd64"
elif [ "$ARCH" == "arm64" ]; then
  ARCH="arm64"
else
  echo -e "${YELLOW}未知架构 $ARCH, 使用默认值 amd64${NC}"
  ARCH="amd64"
fi

# 检测系统类型
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "darwin" ]; then
  echo -e "${YELLOW}警告: 当前系统不是macOS (检测到: $OS)${NC}"
else
  echo -e "${GREEN}检测到macOS系统${NC}"
fi

# 编译不同平台的二进制文件
echo -e "${YELLOW}开始编译...${NC}"

# macOS (当前平台)
echo -e "${YELLOW}编译macOS ($ARCH) 版本...${NC}"
go build -o "$BUILD_DIR/${BINARY_NAME}_${OS}_${ARCH}" .
if [ $? -ne 0 ]; then
  echo -e "${RED}macOS 编译失败!${NC}"
  exit 1
else
  echo -e "${GREEN}✓ macOS 编译成功: ${BINARY_NAME}_${OS}_${ARCH}${NC}"
fi

# macOS x86(amd64) 版本，如果当前不是amd64架构则交叉编译
if [ "$ARCH" != "amd64" ]; then
  echo -e "${YELLOW}交叉编译 macOS (amd64) 版本...${NC}"
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/${BINARY_NAME}_darwin_amd64" .
  if [ $? -ne 0 ]; then
    echo -e "${RED}macOS amd64 编译失败!${NC}"
  else
    echo -e "${GREEN}✓ macOS amd64 编译成功: ${BINARY_NAME}_darwin_amd64${NC}"
  fi
fi

# Linux amd64
echo -e "${YELLOW}交叉编译 Linux (amd64) 版本...${NC}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/${BINARY_NAME}_linux_amd64" .
if [ $? -ne 0 ]; then
  echo -e "${RED}Linux amd64 编译失败!${NC}"
else
  echo -e "${GREEN}✓ Linux 编译成功: ${BINARY_NAME}_linux_amd64${NC}"
fi

# Linux arm64
echo -e "${YELLOW}交叉编译 Linux (arm64) 版本...${NC}"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o "$BUILD_DIR/${BINARY_NAME}_linux_arm64" .
if [ $? -ne 0 ]; then
  echo -e "${RED}Linux arm64 编译失败!${NC}"
else
  echo -e "${GREEN}✓ Linux 编译成功: ${BINARY_NAME}_linux_arm64${NC}"
fi

# Windows amd64
echo -e "${YELLOW}交叉编译 Windows (amd64) 版本...${NC}"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/${BINARY_NAME}_windows_amd64.exe" .
if [ $? -ne 0 ]; then
  echo -e "${RED}Windows 编译失败!${NC}"
else
  echo -e "${GREEN}✓ Windows 编译成功: ${BINARY_NAME}_windows_amd64.exe${NC}"
fi

# 复制必要文件到构建目录
echo -e "${YELLOW}复制必要文件到构建目录...${NC}"
for file in "${REQUIRED_FILES[@]}"; do
  cp "$file" "$BUILD_DIR/"
  echo -e "${GREEN}✓ 复制: $file${NC}"
done

# 创建各平台的发布包
echo -e "${YELLOW}创建发布包...${NC}"

# macOS 当前架构版本
echo -e "${YELLOW}打包 macOS ($ARCH) 版本...${NC}"
mkdir -p "$BUILD_DIR/macos_${ARCH}"
cp "$BUILD_DIR/${BINARY_NAME}_${OS}_${ARCH}" "$BUILD_DIR/macos_${ARCH}/${BINARY_NAME}"
for file in "${REQUIRED_FILES[@]}"; do
  cp "$file" "$BUILD_DIR/macos_${ARCH}/"
done
(cd "$BUILD_DIR" && zip -r "../$RELEASE_DIR/AIFuzzing_${VERSION}_macos_${ARCH}.zip" "macos_${ARCH}")
echo -e "${GREEN}✓ macOS ${ARCH} 打包完成: AIFuzzing_${VERSION}_macos_${ARCH}.zip${NC}"

# macOS x86(amd64) 版本，如果当前不是amd64架构
if [ "$ARCH" != "amd64" ] && [ -f "$BUILD_DIR/${BINARY_NAME}_darwin_amd64" ]; then
  echo -e "${YELLOW}打包 macOS (amd64) 版本...${NC}"
  mkdir -p "$BUILD_DIR/macos_amd64"
  cp "$BUILD_DIR/${BINARY_NAME}_darwin_amd64" "$BUILD_DIR/macos_amd64/${BINARY_NAME}"
  for file in "${REQUIRED_FILES[@]}"; do
    cp "$file" "$BUILD_DIR/macos_amd64/"
  done
  (cd "$BUILD_DIR" && zip -r "../$RELEASE_DIR/AIFuzzing_${VERSION}_macos_amd64.zip" "macos_amd64")
  echo -e "${GREEN}✓ macOS amd64 打包完成: AIFuzzing_${VERSION}_macos_amd64.zip${NC}"
fi

# Linux amd64 版本
echo -e "${YELLOW}打包 Linux amd64 版本...${NC}"
mkdir -p "$BUILD_DIR/linux_amd64"
cp "$BUILD_DIR/${BINARY_NAME}_linux_amd64" "$BUILD_DIR/linux_amd64/${BINARY_NAME}"
for file in "${REQUIRED_FILES[@]}"; do
  cp "$file" "$BUILD_DIR/linux_amd64/"
done
(cd "$BUILD_DIR" && zip -r "../$RELEASE_DIR/AIFuzzing_${VERSION}_linux_amd64.zip" "linux_amd64")
echo -e "${GREEN}✓ Linux amd64 打包完成: AIFuzzing_${VERSION}_linux_amd64.zip${NC}"

# Linux arm64 版本
echo -e "${YELLOW}打包 Linux arm64 版本...${NC}"
mkdir -p "$BUILD_DIR/linux_arm64"
cp "$BUILD_DIR/${BINARY_NAME}_linux_arm64" "$BUILD_DIR/linux_arm64/${BINARY_NAME}"
for file in "${REQUIRED_FILES[@]}"; do
  cp "$file" "$BUILD_DIR/linux_arm64/"
done
(cd "$BUILD_DIR" && zip -r "../$RELEASE_DIR/AIFuzzing_${VERSION}_linux_arm64.zip" "linux_arm64")
echo -e "${GREEN}✓ Linux arm64 打包完成: AIFuzzing_${VERSION}_linux_arm64.zip${NC}"

# Windows 版本
echo -e "${YELLOW}打包 Windows 版本...${NC}"
mkdir -p "$BUILD_DIR/windows"
cp "$BUILD_DIR/${BINARY_NAME}_windows_amd64.exe" "$BUILD_DIR/windows/${BINARY_NAME}.exe"
for file in "${REQUIRED_FILES[@]}"; do
  cp "$file" "$BUILD_DIR/windows/"
done
(cd "$BUILD_DIR" && zip -r "../$RELEASE_DIR/AIFuzzing_${VERSION}_windows_amd64.zip" "windows")
echo -e "${GREEN}✓ Windows 打包完成: AIFuzzing_${VERSION}_windows_amd64.zip${NC}"

# 计算发布包的 SHA256 哈希值
echo -e "${YELLOW}计算发布包的 SHA256 哈希值...${NC}"
cd "$RELEASE_DIR"
shasum -a 256 *.zip > SHA256SUMS.txt
echo -e "${GREEN}✓ SHA256 哈希值已保存到: release/SHA256SUMS.txt${NC}"
cd ..

echo -e "${GREEN}==== 构建完成! ====${NC}"
echo -e "${GREEN}发布文件位于: ${RELEASE_DIR}/ 目录${NC}"
echo -e "${YELLOW}提示: 您可以将这些文件上传到 GitHub 发布页面${NC}"
echo -e "${YELLOW}GitHub CLI 命令示例:${NC}"
echo -e "${YELLOW}gh release create ${VERSION} --title \"AIFuzzing ${VERSION}\" --notes \"AIFuzzing ${VERSION} 发布\" ${RELEASE_DIR}/*.zip ${RELEASE_DIR}/SHA256SUMS.txt${NC}"

# 显示发布文件
echo -e "${YELLOW}发布文件列表:${NC}"
ls -lh "$RELEASE_DIR"
