"""
diag.py · 协和校园网 srun 算法自测与诊断工具

用法：
  python diag.py                # 默认运行基准测试（离线校验算法与官方 Portal.js 一致性）
  python diag.py --self-test    # 同上，算法单元测试
  python diag.py --probe        # 联网探测在线状态与 token（不发登录）
  python diag.py '<cURL 命令>'  # 解析浏览器登录 cURL，分析参数
"""
from __future__ import annotations
import json
import re
import sys
import urllib.parse
from pathlib import Path

# 确保在 Windows GBK 控制台下也能正常输出 UTF-8
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).parent))
import pumc_login_lib as auth


# 基于官方 Portal.js v2.00.20211105 运行验证的基准测试向量（公开脱敏测试数据）
TEST_VECTOR = {
    "username": "202401001",
    "password": "TestPassword123",
    "ip": "10.61.34.79",
    "ac_id": 1,
    "token": "3c20ef0d07611994b7effdab1a0a4e45523ad94d68f22bc008f7b1762aa99048",
    # 官方 Portal.js 在此明文与 token 下的加密输出
    "expected_info": "{SRBX1}Ql6APrLvdePYvDZz7WPxEn6BSt6qlzp0VBaeqv1trAnMOiUzWNBQ5AweH+lJ1L5DGXFuEyvQqUv9M2UkoQSSd4uAINvY6Cv//6l+esZXP9f9JAfvhQ1aFq/2cU6YkRNt06p8LegNKScp7W2O",
    "expected_hmd5": "52163b2e4ccac5a00a57c54f3d77fa83",
    "expected_chksum": "47661ff70e5dbdf22dcc1144023a9c5ae78c528d",
}


def run_self_test() -> bool:
    """离线自测：验证本地 Python 实现是否与官方 Portal.js 字节级一致"""
    print("=" * 60)
    print(" 协和 Srun 协议层自测 (对比 Portal.js v2.00.20211105)")
    print("=" * 60)

    # 1. 验证 hmd5 (HMAC-MD5)
    calc_hmd5 = auth.hmd5(TEST_VECTOR["password"], TEST_VECTOR["token"])
    hmd5_ok = (calc_hmd5 == TEST_VECTOR["expected_hmd5"])
    print(f"1. HMAC-MD5 (hmd5):       {'[PASS]' if hmd5_ok else '[FAIL]'}")
    if not hmd5_ok:
        print(f"   预期: {TEST_VECTOR['expected_hmd5']}")
        print(f"   实际: {calc_hmd5}")

    # 2. 验证 info (XXTEA + 自定义 Base64)
    calc_info = auth.build_info(
        TEST_VECTOR["username"],
        TEST_VECTOR["password"],
        TEST_VECTOR["ip"],
        TEST_VECTOR["ac_id"],
        TEST_VECTOR["token"],
    )
    info_ok = (calc_info == TEST_VECTOR["expected_info"])
    print(f"2. XXTEA + Base64 (info): {'[PASS]' if info_ok else '[FAIL]'}")
    if not info_ok:
        print(f"   预期: {TEST_VECTOR['expected_info']}")
        print(f"   实际: {calc_info}")
        print(f"   长度: 预期={len(TEST_VECTOR['expected_info'])}, 实际={len(calc_info)}")

    # 3. 验证 chksum (SHA1 拼接)
    calc_chksum = auth.build_chksum(
        TEST_VECTOR["token"],
        TEST_VECTOR["username"],
        calc_hmd5,
        TEST_VECTOR["ac_id"],
        TEST_VECTOR["ip"],
        200,
        1,
        calc_info,
    )
    chksum_ok = (calc_chksum == TEST_VECTOR["expected_chksum"])
    print(f"3. SHA1 Checksum (chksum):{'[PASS]' if chksum_ok else '[FAIL]'}")
    if not chksum_ok:
        print(f"   预期: {TEST_VECTOR['expected_chksum']}")
        print(f"   实际: {calc_chksum}")

    print("-" * 60)
    all_ok = hmd5_ok and info_ok and chksum_ok
    if all_ok:
        print("全部算法自测通过！本地代码与官方 Portal.js 完全一致。")
    else:
        print("自测失败，请排查相关加密移植。")
    print("=" * 60)
    return all_ok


def parse_curl(curl_cmd: str):
    """解析浏览器抓包获得的 cURL 命令"""
    print("=" * 60)
    print(" 解析浏览器 cURL 请求")
    print("=" * 60)

    # 提取 URL
    m_url = re.search(r'https?://[^\s\'"]+', curl_cmd)
    if not m_url:
        print("未在输入中找到 URL")
        return
    url = m_url.group(0)
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    print(f"Host:     {parsed.netloc}")
    print(f"Endpoint: {parsed.path}")
    print("\n关键参数：")
    for k in ["action", "username", "password", "ac_id", "ip", "chksum", "info"]:
        val = params.get(k, [""])[0]
        if k == "info":
            print(f"  {k:10}: {val[:50]}... (len={len(val)})")
        else:
            print(f"  {k:10}: {val}")


def main():
    if len(sys.argv) == 1 or sys.argv[1] in ("--self-test", "-t"):
        ok = run_self_test()
        sys.exit(0 if ok else 1)

    arg = sys.argv[1]
    if arg == "--probe":
        from pumc_net_auth import cmd_probe, load_config
        cmd_probe(load_config())
    elif "curl" in arg.lower() or "http" in arg:
        parse_curl(arg)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
