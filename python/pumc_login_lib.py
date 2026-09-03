"""
协和校园网 srun 协议实现（北京协和医学院 go.pumc.edu.cn）

已对照 Portal.js v2.00.20211105 验证：
- HMAC-MD5 密码
- XXTEA 用户信息加密（注意末尾块索引是 n 不是 n-1）
- 自定义 base64 字母表
- SHA1 chksum

零依赖，纯标准库：urllib + hashlib + hmac + struct
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import struct
import urllib.parse
import urllib.request
from typing import Optional, Tuple


# ========================================================================
# 核心加密函数
# ========================================================================

# 自定义 base64 字母表（Portal.js 第 688 行）
SBOX = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def hmd5(password: str, token: str) -> str:
    """HMAC-MD5(password, token) hex —— Portal.js 第 1018 行 md5(password, token) 等价"""
    return hmac.new(
        token.encode('utf-8'),
        password.encode('utf-8'),
        hashlib.md5
    ).hexdigest()


def _str_to_uint32_le(s: str, with_len: bool) -> list[int]:
    """Portal.js s() 函数：把字符串转 uint32 数组（little-endian）
    with_len=True 时末尾 push 字符数（加密路径）"""
    v = []
    c = len(s)
    for i in range(0, c, 4):
        b0 = ord(s[i]) if i < c else 0
        b1 = ord(s[i + 1]) if i + 1 < c else 0
        b2 = ord(s[i + 2]) if i + 2 < c else 0
        b3 = ord(s[i + 3]) if i + 3 < c else 0
        v.append(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    if with_len:
        v.append(c)
    return v


def _uint32_to_str(v: list[int], with_len: bool) -> Optional[str]:
    """Portal.js l() 函数：uint32 数组转回字符串（little-endian 输出）"""
    d = len(v)
    c = (d - 1) << 2
    if with_len:
        m = v[d - 1]
        if m < c - 3 or m > c:
            return None
        c = m
    parts = []
    for x in v:
        parts.append(chr(x & 0xff))
        parts.append(chr((x >> 8) & 0xff))
        parts.append(chr((x >> 16) & 0xff))
        parts.append(chr((x >> 24) & 0xff))
    full = ''.join(parts)
    return full[:c] if with_len else full


def xxtea_encrypt(plaintext: str, key: str) -> str:
    """XXTEA 加密 —— Portal.js encode() 函数
    严格按 JS 优先级（>>> > << > ^ > & > +）+ JS 32 位无符号语义移植
    """
    v = _str_to_uint32_le(plaintext, True)
    k = _str_to_uint32_le(key, False)
    if len(k) < 4:
        k.extend([0] * (4 - len(k)))

    n = len(v) - 1
    if n < 1:
        return ''
    z = v[n]
    y = v[0]
    c = (0x86014019 | 0x183639A0) & 0xFFFFFFFF  # JS 中 | 操作结果当 32 位用

    SUM_MASK = (0x8CE0D9BF | 0x731F2640) & 0xFFFFFFFF
    ADD_MASK = (0xEFB8D130 | 0x10472ECF) & 0xFFFFFFFF
    LAST_MASK = (0xBB390742 | 0x44C6F8BD) & 0xFFFFFFFF

    def u32(x): return x & 0xFFFFFFFF  # JS 32位无符号截断

    q = int(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        # JS: d = d + c & SUM_MASK  →  d + (c & SUM_MASK)
        d = u32(d + (c & SUM_MASK))
        e = (d >> 2) & 3

        for p in range(n):
            y = v[p + 1]
            # JS: m = z >>> 5 ^ y << 2  →  (z >>> 5) ^ (y << 2)
            #     >>> 与 << 都是 32 位无符号
            m = u32((z >> 5) ^ (y << 2))
            # JS: m += y >>> 3 ^ z << 4 ^ (d ^ y)
            #     ^ 优先级相同，从右往左：((y >>> 3) ^ (z << 4)) ^ (d ^ y)
            m = u32(m + (u32(y >> 3) ^ u32(z << 4) ^ (d ^ y)))
            # JS: m += k[p & 3 ^ e] ^ z  →  m + ((k[(p&3)^e]) ^ z)
            m = u32(m + (k[(p & 3) ^ e] ^ z))
            # JS: z = v[p] = v[p] + m & ADD_MASK  →  v[p] + (m & ADD_MASK)
            z = u32(v[p] + (m & ADD_MASK))
            v[p] = z

        y = v[0]
        m = u32((z >> 5) ^ (y << 2))
        m = u32(m + (u32(y >> 3) ^ u32(z << 4) ^ (d ^ y)))
        # 关键：JS 原版 var 循环结束后 p === n；Python 的 range(n) 循环结束后 p == n-1，此处必须显式用 n 索引！
        m = u32(m + (k[(n & 3) ^ e] ^ z))
        # JS: z = v[n] = v[n] + m & LAST_MASK  →  v[n] + (m & LAST_MASK)
        z = u32(v[n] + (m & LAST_MASK))
        v[n] = z
        q -= 1

    return _uint32_to_str(v, False)


def custom_base64_encode(s: str) -> str:
    """自定义字母表 base64（保留 = padding）—— Portal.js base64.setAlpha()"""
    std_b64 = _manual_base64_encode(s)
    # 字母表映射：索引 i 的字符 → SBOX[i]
    trans = str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        SBOX
    )
    return std_b64.translate(trans)


def _manual_base64_encode(s: str) -> str:
    """标准 base64 编码（手写避免依赖）"""
    import base64
    return base64.b64encode(s.encode('latin-1')).decode('ascii')


def build_info(username: str, password: str, ip: str, ac_id: int, token: str) -> str:
    """构造 info 字段："{SRBX1}" + custom_base64(XXTEA(json, token))"""
    info_dict = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": str(ac_id),
        "enc_ver": "srun_bx1",
    }
    plaintext = json.dumps(info_dict, separators=(',', ':'))
    encrypted = xxtea_encrypt(plaintext, token)
    return "{SRBX1}" + custom_base64_encode(encrypted)


def build_chksum(token: str, username: str, hmd: str, ac_id: int, ip: str, n: int, type_: int, info: str) -> str:
    """chksum = sha1(token+username+token+hmd5+token+ac_id+token+ip+token+n+token+type+token+info)"""
    parts = [token, username, token, hmd, token, str(ac_id), token, ip, token, str(n), token, str(type_), token, info]
    s = ''.join(parts)
    return hashlib.sha1(s.encode('utf-8')).hexdigest()


# ========================================================================
# HTTP 调用层
# ========================================================================

def _http_get(url: str, timeout: int = 10) -> str:
    """带 User-Agent 的 GET，返回 body 文本"""
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit/537.36',
        'Referer': 'https://go.pumc.edu.cn/srun_portal_pc?ac_id=1&theme=pro',
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def get_token(host: str, username: str, ip: str) -> Tuple[Optional[str], Optional[str]]:
    """GET /cgi-bin/get_challenge → 拿 token
    返回 (token, client_ip) —— Portal.js 用 callback 包装 JSONP，解析 jQueryxxx({...})"""
    url = f"https://{host}/cgi-bin/get_challenge?callback=jQuery&username={urllib.parse.quote(username)}&ip={urllib.parse.quote(ip)}"
    try:
        body = _http_get(url)
    except Exception as e:
        return None, None
    # JSONP: jQuery123456({...})
    m = re.search(r'\((.+)\)', body, re.DOTALL)
    if not m:
        return None, None
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None, None
    return data.get('challenge'), data.get('client_ip') or data.get('ip')


def login(host: str, username: str, password: str, ac_id: int = 1, ip: str = '') -> Tuple[bool, str]:
    """执行完整登录流程
    返回 (success, message) —— success=True 表示上线成功（含 ip_already_online_error）
    message 是服务器响应（成功/失败详细）"""
    if not ip:
        ip = '0.0.0.0'  # 占位，srun 一般不校验

    token, client_ip = get_token(host, username, ip)
    if not token:
        return False, "get_challenge 失败（无法拿 token）"
    if client_ip:
        ip = client_ip

    h = hmd5(password, token)
    info = build_info(username, password, ip, ac_id, token)
    chksum = build_chksum(token, username, h, ac_id, ip, 200, 1, info)

    params = {
        'callback': 'jQuery',
        'action': 'login',
        'username': username,
        'password': '{MD5}' + h,
        'ac_id': str(ac_id),
        'ip': ip,
        'n': '200',
        'type': '1',
        'os': 'Windows',
        'name': 'Windows',
        'double_stack': '0',
        'chksum': chksum,
        'info': info,
    }
    query = urllib.parse.urlencode(params)
    url = f"https://{host}/cgi-bin/srun_portal?{query}"
    try:
        body = _http_get(url)
    except Exception as e:
        return False, f"login 请求异常：{e}"

    m = re.search(r'\((.+)\)', body, re.DOTALL)
    if not m:
        return False, f"login 响应解析失败：{body[:200]}"
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return False, f"login JSON 解析失败：{body[:200]}"

    suc_msg = data.get('suc_msg', '')
    error = data.get('error', '')

    # ip_already_online_error 视为成功（账号实际已在线）
    if suc_msg == 'ip_already_online_error':
        return True, "ip_already_online_error（实际已在线）"
    if error == 'ok':
        return True, "登录成功"
    # 其他 error 视为失败
    return False, f"login 失败: error={error}, suc_msg={suc_msg}, res={data.get('res', '')}"


def check_online(host: str) -> bool:
    """GET /cgi-bin/rad_user_info → 是否在线
    返回 True/False"""
    url = f"https://{host}/cgi-bin/rad_user_info?callback=jQuery"
    try:
        body = _http_get(url)
    except Exception:
        return False
    m = re.search(r'"error"\s*:\s*"([^"]+)"', body)
    if not m:
        return False
    return m.group(1) == 'ok'


def logout(host: str) -> bool:
    """GET /cgi-bin/srun_portal?action=logout"""
    url = f"https://{host}/cgi-bin/srun_portal?callback=jQuery&action=logout"
    try:
        _http_get(url)
        return True
    except Exception:
        return False
