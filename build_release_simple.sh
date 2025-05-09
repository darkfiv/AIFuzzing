#!/bin/bash

# AIFuzzing 简易打包发布脚本
# 作者: AIFuzzing Team
# 用途: 打包AIFuzzing工具用于GitHub发布

# 显示彩色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}==== AIFuzzing 打包脚本开始执行 ====${NC}"

# 设置变量
VERSION="v1.0.0"
RELEASE_DIR="release"
REQUIRED_FILES=("index.html" "config.json" "whitelist.txt" "AIFuzzing")

# 创建发布目录
mkdir -p "$RELEASE_DIR"

# 清理旧文件
echo -e "${YELLOW}清理旧发布文件...${NC}"
rm -rf "$RELEASE_DIR"/*

# 检查必要的文件是否存在
echo -e "${YELLOW}检查必要文件...${NC}"
for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo -e "${RED}错误: 未找到必要文件 $file${NC}"
    echo -e "${YELLOW}注意: 如果可执行文件名不是'AIFuzzing'，请修改脚本中的REQUIRED_FILES变量${NC}"
    exit 1
  else
    echo -e "${GREEN}✓ 找到文件: $file${NC}"
  fi
done

# 确保可执行文件有执行权限
echo -e "${YELLOW}确保可执行文件有执行权限...${NC}"
chmod +x AIFuzzing
echo -e "${GREEN}✓ 已设置可执行权限${NC}"

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

# 创建临时目录用于打包
TEMP_DIR="temp_package"
echo -e "${YELLOW}创建临时打包目录...${NC}"
mkdir -p "$TEMP_DIR"

# 复制文件到临时目录
echo -e "${YELLOW}复制文件到打包目录...${NC}"
for file in "${REQUIRED_FILES[@]}"; do
  cp "$file" "$TEMP_DIR/"
  echo -e "${GREEN}✓ 复制: $file${NC}"
done

# 创建ZIP压缩包
echo -e "${YELLOW}创建ZIP压缩包...${NC}"
(cd "$TEMP_DIR" && zip -r "../$RELEASE_DIR/AIFuzzing_${VERSION}_${OS}_${ARCH}.zip" *)
echo -e "${GREEN}✓ 打包完成: AIFuzzing_${VERSION}_${OS}_${ARCH}.zip${NC}"

# 计算SHA256哈希值
echo -e "${YELLOW}计算SHA256哈希值...${NC}"
cd "$RELEASE_DIR"
shasum -a 256 *.zip > SHA256SUMS.txt
cd ..
echo -e "${GREEN}✓ SHA256哈希值已保存到: $RELEASE_DIR/SHA256SUMS.txt${NC}"

# 清理临时目录
echo -e "${YELLOW}清理临时文件...${NC}"
rm -rf "$TEMP_DIR"
echo -e "${GREEN}✓ 临时文件已清理${NC}"

echo -e "${GREEN}==== 打包完成! ====${NC}"
echo -e "${GREEN}发布文件位于: $RELEASE_DIR/ 目录${NC}"
echo -e "${YELLOW}发布文件列表:${NC}"
ls -lh "$RELEASE_DIR"

echo -e "${YELLOW}提示: 您可以将这些文件上传到GitHub发布页面${NC}" 