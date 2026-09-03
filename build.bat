@echo off
chcp 65001 > nul
echo 正在编译 pumc-net-auth (Windows GUI 无黑框模式)...
go build -ldflags="-H windowsgui -s -w" -o pumc-net-auth.exe .
if %ERRORLEVEL% equ 0 (
    echo 编译成功：pumc-net-auth.exe
) else (
    echo 编译失败，请检查 Go 编译环境。
)
pause
