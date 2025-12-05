package reverse

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"reverse/config"
	"strings"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
)

var (
	// 缓存的 access token
	cachedAccessToken string
	// 缓存的 session ID (f.sid)
	cachedSessionID   string
	accessTokenMutex  sync.RWMutex
	lastTokenTime     time.Time
	tokenCacheTTL     = 5 * time.Minute // token 缓存时间
)

func init() {
	// 注册 Cookie 变更回调,当 Cookie 变更时清除 access token 缓存
	config.RegisterCookieChangeCallback(func() {
		ctx := gctx.GetInitCtx()
		g.Log().Info(ctx, "Cookie 已变更,清除 access token 和 session ID 缓存")
		InvalidateAccessToken()
	})
}

// GetAccessToken 获取 access token (带缓存)
func GetAccessToken(ctx context.Context) (string, error) {
	accessTokenMutex.RLock()
	if cachedAccessToken != "" && time.Since(lastTokenTime) < tokenCacheTTL {
		token := cachedAccessToken
		accessTokenMutex.RUnlock()
		return token, nil
	}
	accessTokenMutex.RUnlock()

	// 需要刷新 token
	accessTokenMutex.Lock()
	defer accessTokenMutex.Unlock()

	// 双重检查
	if cachedAccessToken != "" && time.Since(lastTokenTime) < tokenCacheTTL {
		return cachedAccessToken, nil
	}

	// 从 CookieManager 获取完整的会话信息
	sessionInfo, err := config.CookieMgr.GetSessionInfo(ctx)
	if err != nil {
		return "", err
	}

	// 更新 cookie
	config.SetCookie(sessionInfo.CookieStr)

	// 缓存 token 和 session ID
	cachedAccessToken = sessionInfo.AccessToken
	cachedSessionID = sessionInfo.SessionID
	lastTokenTime = time.Now()

	g.Log().Info(ctx, "Access token 已刷新, Session ID:", sessionInfo.SessionID)
	return sessionInfo.AccessToken, nil
}

// InvalidateAccessToken 使 access token 和 session ID 缓存失效
func InvalidateAccessToken() {
	accessTokenMutex.Lock()
	defer accessTokenMutex.Unlock()
	cachedAccessToken = ""
	cachedSessionID = ""
	lastTokenTime = time.Time{}
}

// GetSessionID 获取 session ID
func GetSessionID() string {
	accessTokenMutex.RLock()
	defer accessTokenMutex.RUnlock()
	return cachedSessionID
}

// SetSessionID 设置 session ID
func SetSessionID(sid string) {
	accessTokenMutex.Lock()
	defer accessTokenMutex.Unlock()
	cachedSessionID = sid
}

// ProcessStreamGenerateBody 处理 StreamGenerate 请求体
// 替换请求体中的 at 参数为服务端的 access token
func ProcessStreamGenerateBody(ctx context.Context, body []byte) ([]byte, error) {
	bodyStr := string(body)

	// 获取服务端的 access token
	serverToken, err := GetAccessToken(ctx)
	if err != nil {
		g.Log().Warning(ctx, "获取 access token 失败:", err)
		return body, err
	}

	if serverToken == "" {
		g.Log().Warning(ctx, "获取到的 access token 为空,跳过替换")
		return body, fmt.Errorf("access token 为空")
	}

	// 使用正则表达式替换 at 参数，保持原有编码格式
	// 请求体格式: at=xxx&f.req=xxx 或 f.req=xxx&at=xxx
	// 匹配: at=<任意非&字符>
	re := regexp.MustCompile(`at=([^&]+)`)

	if !re.MatchString(bodyStr) {
		// 如果没有 at 参数，添加一个（在开头）
		// 提取纯token，不添加时间戳（因为原始请求没有at参数，可能不需要时间戳）
		var pureServerToken string
		if strings.Contains(serverToken, ":") {
			parts := strings.Split(serverToken, ":")
			pureServerToken = parts[0]
		} else {
			pureServerToken = serverToken
		}

		encodedToken := url.QueryEscape(pureServerToken)
		newBodyStr := "at=" + encodedToken + "&" + bodyStr
		return []byte(newBodyStr), nil
	}

	// 替换现有的 at 参数
	matches := re.FindStringSubmatch(bodyStr)
	if len(matches) >= 2 {
		oldToken := matches[1] // 这是URL编码的，例如：tokenA%3A1234567890

		// 在URL编码状态下直接操作，避免解码/重新编码导致的格式差异
		// 查找 %3A (URL编码的冒号)
		colonIndex := strings.Index(oldToken, "%3A")

		// 提取服务端的纯token（去掉可能存在的时间戳）
		var pureServerToken string
		if strings.Contains(serverToken, ":") {
			parts := strings.Split(serverToken, ":")
			pureServerToken = parts[0]
		} else {
			pureServerToken = serverToken
		}

		// URL编码纯token
		encodedPureServerToken := url.QueryEscape(pureServerToken)

		var finalEncodedToken string
		if colonIndex >= 0 {
			// 原token有时间戳，保留时间戳部分（保持原始编码）
			timestampPart := oldToken[colonIndex:] // "%3A1234567890"
			finalEncodedToken = encodedPureServerToken + timestampPart
		} else {
			// 原token没有时间戳
			finalEncodedToken = encodedPureServerToken
		}

		newBodyStr := re.ReplaceAllString(bodyStr, "at="+finalEncodedToken)

		return []byte(newBodyStr), nil
	}

	return body, nil
}

// ProcessBatchExecuteBody 处理 batchexecute 请求体
// 替换请求体中的 at 参数 (只有当原始请求包含 at 参数时才替换)
func ProcessBatchExecuteBody(ctx context.Context, body []byte) ([]byte, bool, error) {
	bodyStr := string(body)

	// 检查是否包含 at 参数
	if !strings.Contains(bodyStr, "at=") {
		return body, false, nil
	}

	// 获取服务端的 access token (这会同时刷新 session ID)
	serverToken, err := GetAccessToken(ctx)
	if err != nil {
		g.Log().Warning(ctx, "获取 access token 失败:", err)
		return body, false, err
	}

	if serverToken == "" {
		g.Log().Warning(ctx, "获取到的 access token 为空,跳过替换")
		return body, false, fmt.Errorf("access token 为空")
	}

	// 使用正则表达式替换 at 参数，保持原有编码格式
	// 匹配: at=<任意非&字符>，可能在末尾或&之前
	re := regexp.MustCompile(`at=([^&]+)`)
	matches := re.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return body, false, nil
	}

	oldToken := matches[1] // 这是URL编码的，例如：tokenA%3A1234567890

	// 在URL编码状态下直接操作，避免解码/重新编码导致的格式差异
	// 查找 %3A (URL编码的冒号)
	colonIndex := strings.Index(oldToken, "%3A")

	// 提取服务端的纯token（去掉可能存在的时间戳）
	var pureServerToken string
	if strings.Contains(serverToken, ":") {
		parts := strings.Split(serverToken, ":")
		pureServerToken = parts[0]
	} else {
		pureServerToken = serverToken
	}

	// URL编码纯token
	encodedPureServerToken := url.QueryEscape(pureServerToken)

	var finalEncodedToken string
	if colonIndex >= 0 {
		// 原token有时间戳，保留时间戳部分（保持原始编码）
		timestampPart := oldToken[colonIndex:] // "%3A1234567890"
		finalEncodedToken = encodedPureServerToken + timestampPart
	} else {
		// 原token没有时间戳
		finalEncodedToken = encodedPureServerToken
	}

	// 替换 at 参数值
	newBodyStr := re.ReplaceAllString(bodyStr, "at="+finalEncodedToken)

	return []byte(newBodyStr), true, nil
}

// ProcessBatchExecuteURL 处理 batchexecute 请求 URL
// 替换 URL 中的 f.sid 参数
func ProcessBatchExecuteURL(ctx context.Context, rawURL string) (string, bool) {
	// 获取服务端的 session ID
	serverSID := GetSessionID()
	if serverSID == "" {
		// 尝试刷新获取
		_, _ = GetAccessToken(ctx)
		serverSID = GetSessionID()
	}

	if serverSID == "" {
		return rawURL, false
	}

	// 解析 URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, false
	}

	query := parsedURL.Query()
	oldSID := query.Get("f.sid")
	if oldSID == "" {
		return rawURL, false
	}

	// 替换 f.sid
	query.Set("f.sid", serverSID)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), true
}

// ExtractAccessTokenFromHTML 从 HTML 响应中提取 access token
func ExtractAccessTokenFromHTML(html string) string {
	// 匹配 "SNlM0e":"xxx" 格式
	re := regexp.MustCompile(`"SNlM0e":"([^"]+)"`)
	matches := re.FindStringSubmatch(html)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// IsStreamGenerateRequest 判断是否是 StreamGenerate 请求
func IsStreamGenerateRequest(path string) bool {
	return strings.Contains(path, "StreamGenerate")
}

// IsBatchExecuteRequest 判断是否是 batchexecute 请求
func IsBatchExecuteRequest(path string) bool {
	return strings.Contains(path, "batchexecute")
}

// NeedsTokenReplacement 判断请求是否需要替换 token
func NeedsTokenReplacement(path string) bool {
	return IsStreamGenerateRequest(path) || IsBatchExecuteRequest(path)
}
