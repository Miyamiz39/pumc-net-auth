//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
)

func trimMemory() {
	debug.FreeOSMemory()
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setWorkingSet := kernel32.NewProc("SetProcessWorkingSetSize")
	handle, _, _ := kernel32.NewProc("GetCurrentProcess").Call()
	_, _, _ = setWorkingSet.Call(handle, ^uintptr(0), ^uintptr(0))
}

func init() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attachConsole := kernel32.NewProc("AttachConsole")
	// 尝试附加到父进程控制台（若从终端运行则能看到输出，若双击/自启则保持无窗口）
	_, _, _ = attachConsole.Call(uintptr(0xFFFFFFFF))
}

func killProcess(pid int) error {
	cmd := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))
	return cmd.Run()
}

func isProcessRunning(pid int) bool {
	pidStr := strconv.Itoa(pid)
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid))
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), pidStr)
}
