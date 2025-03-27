@echo off
SETLOCAL

:: 创建输出目录
SET OUTPUT_DIR=.\dist
IF NOT EXIST %OUTPUT_DIR% mkdir %OUTPUT_DIR%

echo 开始编译 AIFuzzing...

:: 编译 Windows 版本
echo 编译 Windows/amd64 版本...
SET GOOS=windows
SET GOARCH=amd64
SET CGO_ENABLED=0
go build -o "%OUTPUT_DIR%\aifuzzing_windows_amd64.exe" main.go scan.go
IF %ERRORLEVEL% EQU 0 (
    echo Windows/amd64 编译成功
) ELSE (
    echo Windows/amd64 编译失败
)

:: 编译 macOS Intel 版本
echo 编译 macOS/amd64 版本...
SET GOOS=darwin
SET GOARCH=amd64
go build -o "%OUTPUT_DIR%\aifuzzing_macos_amd64" main.go scan.go
IF %ERRORLEVEL% EQU 0 (
    echo macOS/amd64 编译成功
) ELSE (
    echo macOS/amd64 编译失败
)

:: 编译 macOS Apple Silicon 版本
echo 编译 macOS/arm64 版本...
SET GOOS=darwin
SET GOARCH=arm64
go build -o "%OUTPUT_DIR%\aifuzzing_macos_arm64" main.go scan.go
IF %ERRORLEVEL% EQU 0 (
    echo macOS/arm64 编译成功
) ELSE (
    echo macOS/arm64 编译失败
)

:: 编译 Linux 版本
echo 编译 Linux/amd64 版本...
SET GOOS=linux
SET GOARCH=amd64
go build -o "%OUTPUT_DIR%\aifuzzing_linux_amd64" main.go scan.go
IF %ERRORLEVEL% EQU 0 (
    echo Linux/amd64 编译成功
) ELSE (
    echo Linux/amd64 编译失败
)

echo 编译完成. 二进制文件在 %OUTPUT_DIR% 目录中
dir /b %OUTPUT_DIR%

ENDLOCAL 