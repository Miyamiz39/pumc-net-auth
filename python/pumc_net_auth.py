"""
pumc-net-auth · 协和校园网自动保活 + 掉线重登

用法：
    python pumc_net_auth.py                   # 前台（调试）
    pythonw pumc_net_auth.py                  # 后台（无窗口，按需启动）
    python pumc_net_auth.py --login-once      # 单次登录（断网时手动恢复）
    python pumc_net_auth.py --probe           # 探测模式（不真登录）
    python pumc_net_auth.py --stop            # 停止后台实例
    python pumc_net_auth.py --status          # 查看运行状态
"""
from __future__ import annotations
import argparse
import json
import os
import socket
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# 确保在 Windows 控制台下正常输出 UTF-8 中文字符
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# 同目录的协议库
sys.path.insert(0, str(Path(__file__).parent))
import pumc_login_lib as auth


# ========================================================================
# 配置 + 日志
# ========================================================================

DEFAULT_CONFIG = {
    "username": "",
    "password": "",
    "portal_host": "go.pumc.edu.cn",
    "ac_id": 1,
    "keepalive_target": "www.baidu.com",
    "interval_seconds": 30,
    "tcp_hold_seconds": 10,
    "fail_threshold_relogin": 2,
    "fail_threshold_backoff": 5,
    "backoff_minutes": 5,
}

PID_FILE = Path(os.environ.get("TEMP", "/tmp")) / "pumc_net_auth.pid"
LOG_FILE = Path(os.environ.get("TEMP", "/tmp")) / "pumc_net_auth.log"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_KEEP_FILES = 5


def _find_config() -> Path:
    """查找 config.json：脚本同目录 > ~/.pumc-net-auth/ > 当前目录"""
    candidates = [
        Path(__file__).parent / "config.json",
        Path.home() / ".pumc-net-auth" / "config.json",
        Path.cwd() / "config.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    # 都没有就用脚本同目录（让用户填）
    return candidates[0]


def _strip_comments(text: str) -> str:
    lines = text.splitlines()
    clean = []
    for line in lines:
        in_str = False
        idx = -1
        for i, ch in enumerate(line):
            if ch == '"' and (i == 0 or line[i - 1] != '\\'):
                in_str = not in_str
            elif not in_str and i + 1 < len(line) and line[i:i + 2] == "//":
                idx = i
                break
        clean.append(line[:idx] if idx != -1 else line)
    return "\n".join(clean)


def load_config() -> dict:
    cfg_path = _find_config()
    if not cfg_path.exists():
        # 自动生成默认 config 提示用户填
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        raise SystemExit(
            f"已创建默认 config.json：{cfg_path}\n"
            f"请填入 username + password 后再运行。"
        )
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.loads(_strip_comments(f.read()))
    # 补缺失字段
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


def _rotate_log():
    """日志滚动：>10MB 时 .log → .1 → .2 ... → .5"""
    if not LOG_FILE.exists():
        return
    if LOG_FILE.stat().st_size < LOG_MAX_BYTES:
        return
    # 倒序移动
    for i in range(LOG_KEEP_FILES - 1, 0, -1):
        src = LOG_FILE.with_suffix(LOG_FILE.suffix + f".{i}")
        dst = LOG_FILE.with_suffix(LOG_FILE.suffix + f".{i + 1}")
        if src.exists():
            if i + 1 >= LOG_KEEP_FILES:
                src.unlink()
            else:
                src.rename(dst)
    LOG_FILE.rename(LOG_FILE.with_suffix(LOG_FILE.suffix + ".1"))


def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        _rotate_log()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ========================================================================
# 保活监测：HTTP HEAD + TCP hold
# ========================================================================

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_http(url: str, timeout: int = 5) -> tuple[bool, str]:
    """HEAD 请求检查 URL 可达性，拦截 302 劫持跳转"""
    try:
        req = urllib.request.Request(url, method="HEAD")
        opener = urllib.request.build_opener(NoRedirectHandler)
        with opener.open(req, timeout=timeout) as resp:
            code = resp.status
            if 300 <= code < 400:
                return False, f"HTTP 遭遇网关跳转 ({code})"
            if code not in (200, 204):
                return False, f"HTTP 状态异常: {code}"
            return True, f"HTTP {code}"
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return False, f"HTTP 遭遇网关跳转 ({e.code})"
        return False, f"HTTP 错误：{e.code}"
    except Exception as e:
        return False, f"HTTP 失败：{type(e).__name__}: {e}"


def check_tcp_hold(host: str, port: int, hold_seconds: float, timeout: int = 5) -> tuple[bool, str]:
    """建立 TCP 连接并 hold 住指定秒数进行会话保活"""
    if hold_seconds <= 0:
        return True, "TCP hold 跳过"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        time.sleep(hold_seconds)
        sock.close()
        return True, f"TCP hold {hold_seconds}s OK"
    except Exception as e:
        return False, f"TCP 失败：{type(e).__name__}: {e}"


def do_keepalive_check(cfg: dict) -> tuple[bool, str]:
    """执行一次保活检查：仅公网 HTTP 成功时才判定在线，并执行 TCP hold"""
    target = cfg["keepalive_target"]
    http_ok, http_msg = check_http(f"http://{target}/", timeout=5)
    if not http_ok:
        return False, http_msg
    _, tcp_msg = check_tcp_hold(target, 80, cfg["tcp_hold_seconds"], timeout=5)
    return True, f"{http_msg} | {tcp_msg}"


# ========================================================================
# 主循环：监测 + 重登
# ========================================================================

def daemon_loop(cfg: dict):
    """守护主循环"""
    # 写 PID
    PID_FILE.write_text(str(os.getpid()))

    interval = cfg["interval_seconds"]
    fail_threshold = cfg["fail_threshold_relogin"]
    backoff_threshold = cfg["fail_threshold_backoff"]
    backoff_sec = cfg["backoff_minutes"] * 60

    log(f"=== 启动 === pid={os.getpid()}")
    log(f"  username={cfg['username']}  host={cfg['portal_host']}  ac_id={cfg['ac_id']}")
    log(f"  间隔 {interval}s / TCP hold {cfg['tcp_hold_seconds']}s / 失败 {fail_threshold} 次重登 / {backoff_threshold} 次退避 {cfg['backoff_minutes']}min")

    # [冷启动检查] 开机或启动立刻检查，离线立刻登录
    log("[启动检查] 探测当前校园网在线状态...")
    if auth.check_online(cfg["portal_host"]):
        log("  → 当前已在线，直接进入后台保活")
    else:
        log("  → 当前未在线，立即发起登录认证...")
        logged = False
        for attempt in range(1, 4):
            success, msg = auth.login(
                cfg["portal_host"],
                cfg["username"],
                cfg["password"],
                ac_id=cfg["ac_id"],
                client_ip=cfg.get("client_ip", "0.0.0.0"),
            )
            log(f"  → 启动登录结果 (尝试 {attempt}/3): {msg}")
            if success:
                logged = True
                break
            time.sleep(2)
        if not logged:
            log("  → 启动快速登录暂未成功，转入后台状态机持续重试")

    fail_count = 0
    backoff_until = 0.0
    cycle = 0

    try:
        while True:
            cycle += 1
            now = time.time()

            # 退避期
            if now < backoff_until:
                if cycle % 10 == 0:
                    remain = int(backoff_until - now)
                    log(f"[退避中] 剩余 {remain}s")
                time.sleep(interval)
                continue

            # 保活检查
            cycle_ok, detail = do_keepalive_check(cfg)
            status = "OK" if cycle_ok else "FAIL"
            log(f"[循环 {cycle}] {status}  {detail}")

            if cycle_ok:
                if fail_count > 0:
                    log(f"  → 网络正常，fail_count 清零（前值={fail_count}）")
                fail_count = 0
                time.sleep(interval)
                continue

            # 失败了
            fail_count += 1
            log(f"  → 失败 #{fail_count}")

            # 首次失败快速 3 秒复查
            if fail_count < fail_threshold:
                log("  → 探测失败，等待 3s 快速复检...")
                time.sleep(3)
                recheck_ok, recheck_detail = do_keepalive_check(cfg)
                if recheck_ok:
                    log(f"  → 快速复检通过 ({recheck_detail})，判定为瞬时抖动，清零")
                    fail_count = 0
                    time.sleep(interval)
                    continue
                fail_count += 1
                log(f"  → 快速复检依然失败 ({recheck_detail})，确认掉线 (#{fail_count})")

            # 确认掉线：先查在线状态，避免重复登录
            log(f"  → 触发重登（已确认掉线）")
            is_online = auth.check_online(cfg["portal_host"])
            if is_online:
                log(f"  → rad_user_info 显示已在线（公网临时故障），清零")
                fail_count = 0
                time.sleep(interval)
                continue

            # 不在线 → 真登录
            log(f"  → 不在线，开始登录 {cfg['portal_host']} ...")
            success, msg = auth.login(
                cfg["portal_host"],
                cfg["username"],
                cfg["password"],
                cfg["ac_id"],
            )
            log(f"  → 登录结果：{msg}")

            if success:
                log(f"  → 重登成功，回到保活模式")
                fail_count = 0
                time.sleep(interval)
            else:
                fail_count += 1
                if fail_count >= backoff_threshold:
                    log(f"  → 连续 {fail_count} 次失败，进入退避 {cfg['backoff_minutes']} 分钟")
                    backoff_until = time.time() + backoff_sec
                    fail_count = 0  # 退避后清零
                time.sleep(interval)

    except KeyboardInterrupt:
        log("=== 用户中断退出 ===")
    finally:
        try:
            PID_FILE.unlink()
        except Exception:
            pass


# ========================================================================
# 单次命令
# ========================================================================

def cmd_login_once(cfg: dict):
    """单次登录（断网时手动恢复）"""
    log(f"=== 单次登录 === host={cfg['portal_host']} user={cfg['username']}")
    is_online = auth.check_online(cfg["portal_host"])
    if is_online:
        log("已经在线，无需登录")
        return
    success, msg = auth.login(
        cfg["portal_host"],
        cfg["username"],
        cfg["password"],
        cfg["ac_id"],
    )
    log(f"结果：{msg}")
    sys.exit(0 if success else 1)


def cmd_probe(cfg: dict):
    """探测模式：只检查 token/在线状态，不真发登录"""
    log(f"=== 探测 === host={cfg['portal_host']} user={cfg['username']}")
    log("1) get_challenge ...")
    token, ip = auth.get_token(cfg["portal_host"], cfg["username"], "0.0.0.0")
    log(f"  token={token[:16] + '...' if token else 'None'}  ip={ip}")

    log("2) rad_user_info ...")
    online = auth.check_online(cfg["portal_host"])
    log(f"  online={online}")

    if token:
        log("3) hmd5 (HMAC-MD5) 试算 ...")
        h = auth.hmd5("test_password", token)
        log(f"  hmd5={h}")

        log("4) build_info 试算 ...")
        info = auth.build_info(cfg["username"], "test", ip or "0.0.0.0", cfg["ac_id"], token)
        log(f"  info={info[:60]}...")

        log("5) build_chksum 试算 ...")
        chk = auth.build_chksum(token, cfg["username"], h, cfg["ac_id"], ip or "0.0.0.0", 200, 1, info)
        log(f"  chksum={chk}")

    log("=== 探测完成 ===")


def cmd_stop():
    if not PID_FILE.exists():
        print("没有后台实例在跑")
        return
    try:
        pid = int(PID_FILE.read_text().strip())
        import subprocess
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=False)
        print(f"已发送终止信号到 pid={pid}")
        try:
            PID_FILE.unlink()
        except Exception:
            pass
    except Exception as e:
        print(f"停止失败：{e}")


def cmd_status():
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            print(f"后台实例 pid={pid}（PID 文件存在）")
            # 简单检查进程是否真在
            import subprocess
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
            if str(pid) in r.stdout:
                print("进程在跑")
            else:
                print("PID 文件存在但进程已不在（可能崩溃）")
        except Exception as e:
            print(f"读取 PID 失败：{e}")
    else:
        print("无后台实例在跑")


# ========================================================================
# 入口
# ========================================================================

def main():
    parser = argparse.ArgumentParser(description="协和校园网自动保活 + 掉线重登")
    parser.add_argument("--login-once", action="store_true", help="单次登录（断网恢复用）")
    parser.add_argument("--probe", action="store_true", help="探测协议（不发登录）")
    parser.add_argument("--stop", action="store_true", help="停止后台实例")
    parser.add_argument("--status", action="store_true", help="查看运行状态")
    args = parser.parse_args()

    if args.stop:
        cmd_stop()
        return
    if args.status:
        cmd_status()
        return

    cfg = load_config()

    if args.login_once:
        cmd_login_once(cfg)
    elif args.probe:
        cmd_probe(cfg)
    else:
        daemon_loop(cfg)


if __name__ == "__main__":
    main()
