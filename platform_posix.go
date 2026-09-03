//go:build !windows

package main

import (
	"syscall"
)

func killProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

func isProcessRunning(pid int) bool {
	// Signal 0 探测进程是否存在
	err := syscall.Kill(pid, 0)
	return err == nil
}
