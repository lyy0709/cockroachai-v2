package utils

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FixSetCookieHeaders 修复 Set-Cookie 头的 Domain 属性
// 将 Domain=.google.com 等替换为代理域名，以便浏览器接受这些 Cookie
func FixSetCookieHeaders(headers *http.Header, proxyHost string) {
	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}

	// 清除原有的 Set-Cookie 头
	headers.Del("Set-Cookie")

	for _, cookie := range cookies {
		// 移除 Domain 属性（让浏览器使用当前域名）
		// 同时移除 Secure 属性（因为代理可能是 HTTP）
		// 移除 SameSite=none（因为没有 Secure 时会被忽略）
		parts := strings.Split(cookie, ";")
		var newParts []string
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			lowerPart := strings.ToLower(trimmed)
			// 跳过 Domain、Secure 和 SameSite 属性
			if strings.HasPrefix(lowerPart, "domain=") ||
				lowerPart == "secure" ||
				strings.HasPrefix(lowerPart, "samesite=") {
				continue
			}
			newParts = append(newParts, trimmed)
		}
		// 添加修改后的 Cookie
		if len(newParts) > 0 {
			headers.Add("Set-Cookie", strings.Join(newParts, "; "))
		}
	}
}

// HeaderModify modifies the header of the request.
func HeaderModify(headers *http.Header) {
	// 移除一些错误的转发头
	headers.Del("X-Forwarded-For")
	headers.Del("X-Forwarded-Host")
	headers.Del("X-Forwarded-Proto")
	headers.Del("X-Forwarded-Server")
	headers.Del("X-Real-Ip")
	headers.Del("X-Forwarded-Port")
	headers.Del("X-Forwarded-Uri")
	headers.Del("X-Forwarded-Path")
	headers.Del("X-Forwarded-Method")
	headers.Del("X-Forwarded-Protocol")
	headers.Del("X-Forwarded-Scheme")

	// 移除一些CF的头
	headers.Del("Cf-Connecting-Ip")
	headers.Del("Cf-Ipcountry")
	headers.Del("Cf-Ray")
	headers.Del("Cf-Visitor")
	headers.Del("Cf-Request-Id")
	headers.Del("Cf-Worker")
	headers.Del("Cf-Access-Client-Id")
	headers.Del("Cf-Access-Client-Device-Type")
	headers.Del("Cf-Access-Client-Device-Model")
	headers.Del("Cf-Access-Client-Device-Name")
	headers.Del("Cf-Access-Client-Device-Brand")

	// 设置完整的 CORS 头
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
	headers.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-CSRF-Token, X-Same-Domain, X-Goog-Encode-Response-If-Executable, X-Goog-Upload-Header-Content-Encoding, X-Goog-Upload-Header-Content-Type, X-Goog-Upload-Protocol, X-Goog-Upload-Command, X-Goog-Upload-Offset, X-Goog-Upload-Content-Type, X-Goog-Upload-Content-Length, X-Client-Data")
	headers.Set("Access-Control-Allow-Credentials", "true")
	headers.Set("Access-Control-Expose-Headers", "*")

	// 移除安全相关的限制头
	headers.Del("Content-Security-Policy")
	headers.Del("Content-Security-Policy-Report-Only")
	headers.Del("X-Frame-Options")
	headers.Del("X-XSS-Protection")
	headers.Del("X-Content-Type-Options")
	headers.Del("X-Permitted-Cross-Domain-Policies")
	headers.Del("Referrer-Policy")
	headers.Del("Cross-Origin-Opener-Policy")
	headers.Del("Cross-Origin-Embedder-Policy")
	headers.Del("Cross-Origin-Resource-Policy")
	headers.Del("Permissions-Policy")
	headers.Del("access-control-allow-headers")
	headers.Del("access-control-allow-credentials")

	// 删除可能导致内容长度不匹配的头部
	// 注意：不再删除 Set-Cookie，让浏览器可以接收 cookies
	headers.Del("report-to")
	headers.Del("Content-Encoding")
	headers.Del("Content-Length")

	// 删除上游下发的 Set-Cookie，避免透传
	headers.Del("Set-Cookie")
	headers.Del("www-authenticate")

	// 一些奇怪的东西
	headers.Del("x-middleware-prefetch")
}

// GenerateSAPISIDHash 生成 Google API 所需的 Authorization 头
// 格式: SAPISIDHASH <timestamp>_<hash>
// hash = SHA1(timestamp + " " + origin + " " + SAPISID)
func GenerateSAPISIDHash(origin string, cookie string) string {
	// 从 Cookie 中提取 SAPISID
	sapisid := extractCookieValue(cookie, "SAPISID")
	if sapisid == "" {
		// 如果没有 SAPISID，尝试使用 __Secure-3PAPISID
		sapisid = extractCookieValue(cookie, "__Secure-3PAPISID")
	}
	if sapisid == "" {
		return ""
	}

	// 生成时间戳（秒）
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// 生成 hash: SHA1(timestamp + " " + origin + " " + SAPISID)
	data := timestamp + " " + origin + " " + sapisid
	hash := sha1.Sum([]byte(data))
	hashHex := hex.EncodeToString(hash[:])

	// 返回格式: SAPISIDHASH timestamp_hash
	return fmt.Sprintf("SAPISIDHASH %s_%s", timestamp, hashHex)
}

// extractCookieValue 从 Cookie 字符串中提取指定名称的值
func extractCookieValue(cookie string, name string) string {
	// 使用正则表达式匹配 name=value
	pattern := regexp.MustCompile(name + `=([^;]+)`)
	matches := pattern.FindStringSubmatch(cookie)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
