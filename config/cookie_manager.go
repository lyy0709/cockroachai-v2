package config

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
)

// CookieManager Cookie 管理器
type CookieManager struct {
	Secure1PSID   string
	Secure1PSIDTS string
	CacheDir      string
	ProxyURL      string
	Verbose       bool
}

// CookieSource Cookie 来源
type CookieSource struct {
	Cookies map[string]string
	Source  string // "base", "cache", "browser"
}

// NewCookieManager 创建 Cookie 管理器
func NewCookieManager(psid, psidts, cacheDir, proxyURL string, verbose bool) *CookieManager {
	if cacheDir == "" {
		// 默认缓存目录
		cacheDir = filepath.Join(os.TempDir(), "gemini_cookies")
		os.MkdirAll(cacheDir, 0755)
	}

	return &CookieManager{
		Secure1PSID:   psid,
		Secure1PSIDTS: psidts,
		CacheDir:      cacheDir,
		ProxyURL:      proxyURL,
		Verbose:       verbose,
	}
}

// GetAccessToken 获取访问令牌和有效的 cookies
// 返回: accessToken, cookieString, error
func (cm *CookieManager) GetAccessToken(ctx context.Context) (string, string, error) {
	info, err := cm.GetSessionInfo(ctx)
	if err != nil {
		return "", "", err
	}
	return info.AccessToken, info.CookieStr, nil
}

// GetSessionInfo 获取完整的会话信息 (包括 access token 和 session ID)
func (cm *CookieManager) GetSessionInfo(ctx context.Context) (*SessionInfo, error) {
	// 1. 先获取 google.com 的额外 cookies
	extraCookies, err := cm.getExtraCookies(ctx)
	if err != nil {
		if cm.Verbose {
			g.Log().Warning(ctx, "获取额外 cookies 失败:", err)
		}
		extraCookies = make(map[string]string)
	}

	// 2. 收集所有可能的 cookie 来源
	cookieSources := cm.collectCookieSources(ctx, extraCookies)

	if len(cookieSources) == 0 {
		return nil, fmt.Errorf("没有可用的 cookies。请提供 __Secure-1PSID 和 __Secure-1PSIDTS")
	}

	// 3. 依次尝试每个 cookie 来源
	for i, source := range cookieSources {
		if cm.Verbose {
			g.Log().Infof(ctx, "尝试第 %d/%d 个 cookie 来源: %s", i+1, len(cookieSources), source.Source)
		}

		sessionInfo, err := cm.validateCookies(ctx, source.Cookies)
		if err != nil {
			if cm.Verbose {
				g.Log().Debugf(ctx, "Cookie 来源 %s 验证失败: %v", source.Source, err)
			}
			continue
		}

		// 验证成功,缓存 __Secure-1PSIDTS
		if psidts, ok := source.Cookies["__Secure-1PSIDTS"]; ok {
			if psid, ok := source.Cookies["__Secure-1PSID"]; ok {
				cm.cachePSIDTS(ctx, psid, psidts)
			}
		}

		if cm.Verbose {
			g.Log().Infof(ctx, "Cookie 来源 %s 验证成功", source.Source)
		}

		return sessionInfo, nil
	}

	return nil, fmt.Errorf("所有 cookie 来源验证失败 (共尝试 %d 个来源)", len(cookieSources))
}

// getExtraCookies 从 google.com 获取额外的 cookies
func (cm *CookieManager) getExtraCookies(ctx context.Context) (map[string]string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // 允许重定向
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://google.com", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	extraCookies := make(map[string]string)
	if resp.StatusCode == 200 {
		for _, cookie := range resp.Cookies() {
			extraCookies[cookie.Name] = cookie.Value
		}
		if cm.Verbose && len(extraCookies) > 0 {
			g.Log().Debugf(ctx, "从 google.com 获取到 %d 个额外 cookies", len(extraCookies))
		}
	}

	return extraCookies, nil
}

// collectCookieSources 收集所有可能的 cookie 来源
func (cm *CookieManager) collectCookieSources(ctx context.Context, extraCookies map[string]string) []CookieSource {
	var sources []CookieSource

	// 来源1: 直接传入的 base cookies
	if cm.Secure1PSID != "" && cm.Secure1PSIDTS != "" {
		cookies := make(map[string]string)
		// 合并额外 cookies
		for k, v := range extraCookies {
			cookies[k] = v
		}
		cookies["__Secure-1PSID"] = cm.Secure1PSID
		cookies["__Secure-1PSIDTS"] = cm.Secure1PSIDTS

		sources = append(sources, CookieSource{
			Cookies: cookies,
			Source:  "base",
		})
	} else if cm.Verbose {
		g.Log().Debug(ctx, "跳过 base cookies: __Secure-1PSID 或 __Secure-1PSIDTS 未提供")
	}

	// 来源2: 缓存的 __Secure-1PSIDTS
	if cm.Secure1PSID != "" {
		cachedPSIDTS := cm.loadCachedPSIDTS(ctx, cm.Secure1PSID)
		if cachedPSIDTS != "" {
			cookies := make(map[string]string)
			for k, v := range extraCookies {
				cookies[k] = v
			}
			cookies["__Secure-1PSID"] = cm.Secure1PSID
			cookies["__Secure-1PSIDTS"] = cachedPSIDTS

			sources = append(sources, CookieSource{
				Cookies: cookies,
				Source:  "cache",
			})
		} else if cm.Verbose {
			g.Log().Debug(ctx, "跳过缓存 cookies: 缓存文件不存在或为空")
		}
	} else {
		// 如果没有提供 PSID,尝试加载所有缓存文件
		cachedSources := cm.loadAllCachedCookies(ctx, extraCookies)
		sources = append(sources, cachedSources...)
	}

	return sources
}

// loadCachedPSIDTS 加载缓存的 __Secure-1PSIDTS
func (cm *CookieManager) loadCachedPSIDTS(ctx context.Context, psid string) string {
	filename := fmt.Sprintf(".cached_1psidts_%s.txt", psid)
	cachePath := filepath.Join(cm.CacheDir, filename)

	data, err := ioutil.ReadFile(cachePath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// loadAllCachedCookies 加载所有缓存的 cookies
func (cm *CookieManager) loadAllCachedCookies(ctx context.Context, extraCookies map[string]string) []CookieSource {
	var sources []CookieSource

	files, err := filepath.Glob(filepath.Join(cm.CacheDir, ".cached_1psidts_*.txt"))
	if err != nil {
		return sources
	}

	validCaches := 0
	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil || len(data) == 0 {
			continue
		}

		// 从文件名提取 PSID
		basename := filepath.Base(file)
		psid := strings.TrimSuffix(strings.TrimPrefix(basename, ".cached_1psidts_"), ".txt")

		cookies := make(map[string]string)
		for k, v := range extraCookies {
			cookies[k] = v
		}
		cookies["__Secure-1PSID"] = psid
		cookies["__Secure-1PSIDTS"] = strings.TrimSpace(string(data))

		sources = append(sources, CookieSource{
			Cookies: cookies,
			Source:  fmt.Sprintf("cache-%d", validCaches),
		})
		validCaches++
	}

	if validCaches == 0 && cm.Verbose {
		g.Log().Debug(ctx, "跳过缓存 cookies: 成功初始化后将缓存 cookies")
	}

	return sources
}

// cachePSIDTS 缓存 __Secure-1PSIDTS
func (cm *CookieManager) cachePSIDTS(ctx context.Context, psid, psidts string) {
	filename := fmt.Sprintf(".cached_1psidts_%s.txt", psid)
	cachePath := filepath.Join(cm.CacheDir, filename)

	err := ioutil.WriteFile(cachePath, []byte(psidts), 0644)
	if err != nil {
		if cm.Verbose {
			g.Log().Warning(ctx, "缓存 __Secure-1PSIDTS 失败:", err)
		}
	} else if cm.Verbose {
		g.Log().Debug(ctx, "已缓存 __Secure-1PSIDTS 到:", cachePath)
	}
}

// SessionInfo 会话信息
type SessionInfo struct {
	AccessToken string // SNlM0e
	SessionID   string // FdrFJe (f.sid)
	CookieStr   string
}

// validateCookies 验证 cookies 是否有效
// 返回: SessionInfo, error
func (cm *CookieManager) validateCookies(ctx context.Context, cookies map[string]string) (*SessionInfo, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://gemini.google.com", nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// 构建 cookie 字符串
	var cookieParts []string
	for k, v := range cookies {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", k, v))
	}
	cookieStr := strings.Join(cookieParts, "; ")
	req.Header.Set("Cookie", cookieStr)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	bodyStr := string(body)

	// 从响应中提取 SNlM0e token (access token)
	reToken := regexp.MustCompile(`"SNlM0e":"([^"]+)"`)
	tokenMatches := reToken.FindStringSubmatch(bodyStr)
	if len(tokenMatches) < 2 {
		return nil, fmt.Errorf("cookies 无效: 未找到 SNlM0e token")
	}

	// 从响应中提取 FdrFJe (session ID / f.sid)
	reSid := regexp.MustCompile(`"FdrFJe":"(-?\d+)"`)
	sidMatches := reSid.FindStringSubmatch(bodyStr)
	sessionID := ""
	if len(sidMatches) >= 2 {
		sessionID = sidMatches[1]
		if cm.Verbose {
			g.Log().Debug(ctx, "提取到 session ID (FdrFJe):", sessionID)
		}
	}

	return &SessionInfo{
		AccessToken: tokenMatches[1],
		SessionID:   sessionID,
		CookieStr:   cookieStr,
	}, nil
}

// RotateCookies 刷新 __Secure-1PSIDTS cookie
// 返回新的 __Secure-1PSIDTS 值
func (cm *CookieManager) RotateCookies(ctx context.Context, cookies map[string]string) (string, error) {
	psid, hasPSID := cookies["__Secure-1PSID"]
	if !hasPSID {
		return "", fmt.Errorf("cookies 中缺少 __Secure-1PSID")
	}

	// 检查缓存文件是否在最近1分钟内被修改过,避免 429 Too Many Requests
	filename := fmt.Sprintf(".cached_1psidts_%s.txt", psid)
	cachePath := filepath.Join(cm.CacheDir, filename)

	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) <= time.Minute {
			// 缓存文件在1分钟内被修改过,直接读取
			data, err := ioutil.ReadFile(cachePath)
			if err == nil && len(data) > 0 {
				if cm.Verbose {
					g.Log().Debug(ctx, "使用最近缓存的 __Secure-1PSIDTS (避免频繁请求)")
				}
				return strings.TrimSpace(string(data)), nil
			}
		}
	}

	// 发送刷新请求
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://accounts.google.com/RotateCookies",
		strings.NewReader(`[000,"-0000000000000000000"]`))
	if err != nil {
		return "", err
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	// 构建 cookie 字符串
	var cookieParts []string
	for k, v := range cookies {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", k, v))
	}
	req.Header.Set("Cookie", strings.Join(cookieParts, "; "))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return "", fmt.Errorf("认证失败: cookies 无效或已过期")
	}

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("刷新 cookies 失败: 状态码 %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 从响应的 Set-Cookie 中提取新的 __Secure-1PSIDTS
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "__Secure-1PSIDTS" {
			newPSIDTS := cookie.Value
			// 缓存新的 __Secure-1PSIDTS
			cm.cachePSIDTS(ctx, psid, newPSIDTS)
			if cm.Verbose {
				g.Log().Info(ctx, "成功刷新 __Secure-1PSIDTS")
			}
			return newPSIDTS, nil
		}
	}

	return "", fmt.Errorf("响应中未找到 __Secure-1PSIDTS cookie")
}
