package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SBOX      = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	STD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// strToUint32LE 将字符串以小端序装入 uint32 数组，withLen 为 true 时末尾 push 字符数
func strToUint32LE(s string, withLen bool) []uint32 {
	c := len(s)
	v := make([]uint32, 0, (c+3)/4+1)
	for i := 0; i < c; i += 4 {
		var b0, b1, b2, b3 uint32
		if i < c {
			b0 = uint32(s[i])
		}
		if i+1 < c {
			b1 = uint32(s[i+1])
		}
		if i+2 < c {
			b2 = uint32(s[i+2])
		}
		if i+3 < c {
			b3 = uint32(s[i+3])
		}
		v = append(v, b0|(b1<<8)|(b2<<16)|(b3<<24))
	}
	if withLen {
		v = append(v, uint32(c))
	}
	return v
}

// uint32ToStr 将 uint32 数组以小端序转回字符串
func uint32ToStr(v []uint32, withLen bool) string {
	d := len(v)
	c := (d - 1) << 2
	if withLen {
		m := int(v[d-1])
		if m < c-3 || m > c {
			return ""
		}
		c = m
	}
	buf := make([]byte, 0, d*4)
	for _, x := range v {
		buf = append(buf, byte(x&0xff), byte((x>>8)&0xff), byte((x>>16)&0xff), byte((x>>24)&0xff))
	}
	if withLen && c <= len(buf) {
		return string(buf[:c])
	}
	return string(buf)
}

// xxteaEncrypt 严格按 Portal.js 逻辑移植的 XXTEA 加密
func xxteaEncrypt(plaintext, key string) string {
	if plaintext == "" {
		return ""
	}
	v := strToUint32LE(plaintext, true)
	k := strToUint32LE(key, false)
	for len(k) < 4 {
		k = append(k, 0)
	}
	n := len(v) - 1
	if n < 1 {
		return ""
	}
	z := v[n]
	y := v[0]
	c := uint32(0x9E3779B9)
	q := 6 + 52/(n+1)
	d := uint32(0)

	for q > 0 {
		d += c
		e := (d >> 2) & 3
		for p := 0; p < n; p++ {
			y = v[p+1]
			m := (z >> 5) ^ (y << 2)
			m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
			m += k[(p&3)^int(e)] ^ z
			z = v[p] + m
			v[p] = z
		}
		y = v[0]
		m := (z >> 5) ^ (y << 2)
		m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
		// 显式使用 n，避免循环索引错位
		m += k[(n&3)^int(e)] ^ z
		z = v[n] + m
		v[n] = z
		q--
	}
	return uint32ToStr(v, false)
}

// customBase64 换表 Base64 编码
func customBase64(s string) string {
	std := base64.StdEncoding.EncodeToString([]byte(s))
	out := make([]byte, len(std))
	for i := 0; i < len(std); i++ {
		idx := strings.IndexByte(STD_ALPHA, std[i])
		if idx != -1 {
			out[i] = SBOX[idx]
		} else {
			out[i] = std[i]
		}
	}
	return string(out)
}

// hmd5 计算 HMAC-MD5 字符串
func hmd5(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// buildInfo 组装并加密 info 字段
func buildInfo(username, password, ip string, acId int, token string) string {
	infoJSON := fmt.Sprintf(`{"username":"%s","password":"%s","ip":"%s","acid":"%d","enc_ver":"srun_bx1"}`,
		strings.ReplaceAll(strings.ReplaceAll(username, `\`, `\\`), `"`, `\"`),
		strings.ReplaceAll(strings.ReplaceAll(password, `\`, `\\`), `"`, `\"`),
		ip, acId)
	enc := xxteaEncrypt(infoJSON, token)
	return "{SRBX1}" + customBase64(enc)
}

// buildChksum 计算 SHA1 校验和
func buildChksum(token, username, hmd5Str string, acId int, ip string, n, type_ int, info string) string {
	parts := []string{
		token, username,
		token, hmd5Str,
		token, strconv.Itoa(acId),
		token, ip,
		token, strconv.Itoa(n),
		token, strconv.Itoa(type_),
		token, info,
	}
	joined := strings.Join(parts, "")
	h := sha1.Sum([]byte(joined))
	return hex.EncodeToString(h[:])
}

// httpClient 统一 HTTP 请求客户端
var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	Timeout: 10 * time.Second,
}

func httpGet(reqURL string) (string, error) {
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Referer", "https://go.pumc.edu.cn/srun_portal_pc?ac_id=1&theme=pro")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getToken 获取 challenge token
func getToken(host, username, ip string) (string, string, error) {
	urlStr := fmt.Sprintf("https://%s/cgi-bin/get_challenge?callback=jQuery&username=%s&ip=%s",
		host, url.QueryEscape(username), url.QueryEscape(ip))
	body, err := httpGet(urlStr)
	if err != nil {
		return "", "", err
	}
	re := regexp.MustCompile(`\((.+)\)`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return "", "", fmt.Errorf("未能解析 JSONP: %s", body)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(m[1]), &data); err != nil {
		return "", "", err
	}
	token, _ := data["challenge"].(string)
	clientIP, _ := data["client_ip"].(string)
	if clientIP == "" {
		clientIP, _ = data["ip"].(string)
	}
	return token, clientIP, nil
}

// checkOnline 检查当前是否在线
func checkOnline(host string) bool {
	urlStr := fmt.Sprintf("https://%s/cgi-bin/rad_user_info?callback=jQuery", host)
	body, err := httpGet(urlStr)
	if err != nil {
		return false
	}
	return strings.Contains(body, `"error":"ok"`) || strings.Contains(body, `"error": "ok"`)
}

// login 执行一次登录认证
func login(host, username, password string, acId int, ip string) (bool, string) {
	if ip == "" {
		ip = "0.0.0.0"
	}
	token, clientIP, err := getToken(host, username, ip)
	if err != nil || token == "" {
		return false, fmt.Sprintf("get_challenge 失败: %v", err)
	}
	if clientIP != "" {
		ip = clientIP
	}

	h := hmd5(password, token)
	info := buildInfo(username, password, ip, acId, token)
	chksum := buildChksum(token, username, h, acId, ip, 200, 1, info)

	params := url.Values{}
	params.Set("callback", "jQuery")
	params.Set("action", "login")
	params.Set("username", username)
	params.Set("password", "{MD5}"+h)
	params.Set("ac_id", strconv.Itoa(acId))
	params.Set("ip", ip)
	params.Set("n", "200")
	params.Set("type", "1")
	params.Set("os", "Windows")
	params.Set("name", "Windows")
	params.Set("double_stack", "0")
	params.Set("chksum", chksum)
	params.Set("info", info)

	loginURL := fmt.Sprintf("https://%s/cgi-bin/srun_portal?%s", host, params.Encode())
	body, err := httpGet(loginURL)
	if err != nil {
		return false, fmt.Sprintf("请求网关异常: %v", err)
	}

	re := regexp.MustCompile(`\((.+)\)`)
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return false, fmt.Sprintf("响应解析失败: %s", body)
	}
	var res map[string]interface{}
	if err := json.Unmarshal([]byte(m[1]), &res); err != nil {
		return false, fmt.Sprintf("JSON 解析失败: %s", body)
	}

	sucMsg, _ := res["suc_msg"].(string)
	errorMsg, _ := res["error"].(string)

	if sucMsg == "ip_already_online_error" {
		return true, "ip_already_online_error（实际已在线）"
	}
	if errorMsg == "ok" {
		return true, "登录成功"
	}
	return false, fmt.Sprintf("登录失败: error=%v, suc_msg=%v, res=%v", errorMsg, sucMsg, res["res"])
}
