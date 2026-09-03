package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config 配置结构
type Config struct {
	Username             string `json:"username"`
	Password             string `json:"password"`
	PortalHost           string `json:"portal_host"`
	AcID                 int    `json:"ac_id"`
	KeepaliveTarget      string `json:"keepalive_target"`
	IntervalSeconds      int    `json:"interval_seconds"`
	TCPHoldSeconds       int    `json:"tcp_hold_seconds"`
	FailThresholdRelogin int    `json:"fail_threshold_relogin"`
	FailThresholdBackoff int    `json:"fail_threshold_backoff"`
	BackoffMinutes       int    `json:"backoff_minutes"`
}

var defaultConfig = Config{
	PortalHost:           "go.pumc.edu.cn",
	AcID:                 1,
	KeepaliveTarget:      "www.baidu.com",
	IntervalSeconds:      30,
	TCPHoldSeconds:       10,
	FailThresholdRelogin: 2,
	FailThresholdBackoff: 5,
	BackoffMinutes:       5,
}

var (
	pidFile = filepath.Join(os.TempDir(), "pumc_net_auth.pid")
	logFile = filepath.Join(os.TempDir(), "pumc_net_auth.log")
)

func findConfig() string {
	exe, err := os.Executable()
	var exeDir string
	if err == nil {
		exeDir = filepath.Dir(exe)
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(exeDir, "config.json"),
		filepath.Join(home, ".pumc-net-auth", "config.json"),
		"config.json",
		filepath.Join("..", "scripts", "config.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return filepath.Join(exeDir, "config.json")
}

func loadConfig() Config {
	cfgPath := findConfig()
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		cfg := defaultConfig
		b, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile(cfgPath, b, 0644)
		fmt.Printf("已生成默认配置: %s\n请在其中填入 username 与 password 后重试。\n", cfgPath)
		os.Exit(1)
	}
	cfg := defaultConfig
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

func logMsg(msg string) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	fmt.Print(line)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(line)
	}
}

func checkHTTP(target string) (bool, string) {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Head("http://" + target + "/")
	if err != nil {
		return false, fmt.Sprintf("HTTP 失败: %v", err)
	}
	defer resp.Body.Close()
	return true, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func checkTCPHold(target string, holdSeconds int) (bool, string) {
	conn, err := net.DialTimeout("tcp", target+":80", 8*time.Second)
	if err != nil {
		return false, fmt.Sprintf("TCP 失败: %v", err)
	}
	defer conn.Close()
	time.Sleep(time.Duration(holdSeconds) * time.Second)
	return true, fmt.Sprintf("TCP hold %ds OK", holdSeconds)
}

func doKeepalive(cfg Config) (bool, bool, string) {
	httpOk, httpMsg := checkHTTP(cfg.KeepaliveTarget)
	tcpOk, tcpMsg := checkTCPHold(cfg.KeepaliveTarget, cfg.TCPHoldSeconds)
	return httpOk, tcpOk, fmt.Sprintf("%s | %s", httpMsg, tcpMsg)
}

func daemonLoop(cfg Config) {
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	defer os.Remove(pidFile)

	logMsg(fmt.Sprintf("=== 启动 (Go 原生无黑框模式) === pid=%d", os.Getpid()))
	logMsg(fmt.Sprintf("  username=%s  host=%s  ac_id=%d", cfg.Username, cfg.PortalHost, cfg.AcID))
	logMsg(fmt.Sprintf("  间隔 %ds / TCP hold %ds / 失败 %d 次重登 / %d 次退避 %dmin",
		cfg.IntervalSeconds, cfg.TCPHoldSeconds, cfg.FailThresholdRelogin, cfg.FailThresholdBackoff, cfg.BackoffMinutes))

	failCount := 0
	var backoffUntil time.Time
	cycle := 0

	for {
		cycle++
		now := time.Now()

		if now.Before(backoffUntil) {
			if cycle%10 == 0 {
				remain := int(backoffUntil.Sub(now).Seconds())
				logMsg(fmt.Sprintf("[退避中] 剩余 %ds", remain))
			}
			time.Sleep(time.Duration(cfg.IntervalSeconds) * time.Second)
			continue
		}

		httpOk, tcpOk, detail := doKeepalive(cfg)
		cycleOk := httpOk || tcpOk
		status := "FAIL"
		if cycleOk {
			status = "OK"
		}
		logMsg(fmt.Sprintf("[循环 %d] %s  http=%v  tcp=%v  %s", cycle, status, httpOk, tcpOk, detail))

		if cycleOk {
			if failCount > 0 {
				logMsg(fmt.Sprintf("  → 网络恢复，fail_count 清零（前值=%d）", failCount))
			}
			failCount = 0
			time.Sleep(time.Duration(cfg.IntervalSeconds) * time.Second)
			continue
		}

		failCount++
		logMsg(fmt.Sprintf("  → 失败 #%d", failCount))

		if failCount < cfg.FailThresholdRelogin {
			time.Sleep(time.Duration(cfg.IntervalSeconds) * time.Second)
			continue
		}

		logMsg(fmt.Sprintf("  → 触发重登（已连续失败 %d 次）", failCount))
		if checkOnline(cfg.PortalHost) {
			logMsg("  → rad_user_info 显示已在线（网络临时波动），清零")
			failCount = 0
			time.Sleep(time.Duration(cfg.IntervalSeconds) * time.Second)
			continue
		}

		logMsg(fmt.Sprintf("  → 未在线，开始登录 %s ...", cfg.PortalHost))
		success, msg := login(cfg.PortalHost, cfg.Username, cfg.Password, cfg.AcID, "")
		logMsg(fmt.Sprintf("  → 登录结果：%s", msg))

		if success {
			logMsg("  → 重登成功，回到保活模式")
			failCount = 0
		} else {
			failCount++
			if failCount >= cfg.FailThresholdBackoff {
				logMsg(fmt.Sprintf("  → 连续 %d 次失败，进入退避 %d 分钟", failCount, cfg.BackoffMinutes))
				backoffUntil = time.Now().Add(time.Duration(cfg.BackoffMinutes) * time.Minute)
				failCount = 0
			}
		}
		time.Sleep(time.Duration(cfg.IntervalSeconds) * time.Second)
	}
}

func cmdLoginOnce(cfg Config) {
	logMsg(fmt.Sprintf("=== 单次登录 === host=%s user=%s", cfg.PortalHost, cfg.Username))
	if checkOnline(cfg.PortalHost) {
		logMsg("已经在线，无需登录")
		return
	}
	success, msg := login(cfg.PortalHost, cfg.Username, cfg.Password, cfg.AcID, "")
	logMsg(fmt.Sprintf("结果：%s", msg))
	if !success {
		os.Exit(1)
	}
}

func cmdProbe(cfg Config) {
	logMsg(fmt.Sprintf("=== 探测 === host=%s user=%s", cfg.PortalHost, cfg.Username))
	logMsg("1) get_challenge ...")
	token, ip, err := getToken(cfg.PortalHost, cfg.Username, "0.0.0.0")
	tokenPreview := "None"
	if len(token) > 16 {
		tokenPreview = token[:16] + "..."
	}
	logMsg(fmt.Sprintf("  token=%s  ip=%s  err=%v", tokenPreview, ip, err))

	logMsg("2) rad_user_info ...")
	online := checkOnline(cfg.PortalHost)
	logMsg(fmt.Sprintf("  online=%v", online))

	if token != "" {
		logMsg("3) hmd5 (HMAC-MD5) 试算 ...")
		h := hmd5("test_password", token)
		logMsg(fmt.Sprintf("  hmd5=%s", h))

		logMsg("4) build_info 试算 ...")
		clientIP := ip
		if clientIP == "" {
			clientIP = "0.0.0.0"
		}
		info := buildInfo(cfg.Username, "test", clientIP, cfg.AcID, token)
		if len(info) > 60 {
			logMsg(fmt.Sprintf("  info=%s...", info[:60]))
		}

		logMsg("5) build_chksum 试算 ...")
		chk := buildChksum(token, cfg.Username, h, cfg.AcID, clientIP, 200, 1, info)
		logMsg(fmt.Sprintf("  chksum=%s", chk))
	}
	logMsg("=== 探测完成 ===")
}

func cmdStop() {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Println("没有后台实例在跑 (PID 文件不存在)")
		return
	}
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		fmt.Printf("无效的 PID: %s\n", pidStr)
		return
	}
	_ = killProcess(pid)
	_ = os.Remove(pidFile)
	fmt.Printf("已终止后台进程 pid=%d\n", pid)
}

func cmdStatus() {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Println("无后台实例在跑")
		return
	}
	pidStr := strings.TrimSpace(string(data))
	pid, _ := strconv.Atoi(pidStr)
	if isProcessRunning(pid) {
		fmt.Printf("后台实例运行中: PID=%d\n", pid)
	} else {
		fmt.Printf("PID 文件存在 (%d) 但进程已不在（可能异常退出）\n", pid)
	}
}

func main() {
	loginOnce := flag.Bool("login-once", false, "单次登录")
	probe := flag.Bool("probe", false, "探测模式（不发登录）")
	stop := flag.Bool("stop", false, "停止后台实例")
	status := flag.Bool("status", false, "查看运行状态")
	flag.Parse()

	if *stop {
		cmdStop()
		return
	}
	if *status {
		cmdStatus()
		return
	}

	cfg := loadConfig()

	if *loginOnce {
		cmdLoginOnce(cfg)
	} else if *probe {
		cmdProbe(cfg)
	} else {
		daemonLoop(cfg)
	}
}
