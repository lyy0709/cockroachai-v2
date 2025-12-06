package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
)

// CookieChangeCallback Cookie 变更回调函数类型
type CookieChangeCallback func()

var (
	PORT     = 8080 // 端口
	BaseUrl  = "https://gemini.google.com"
	ProxyURL = ""

	// 简化的 Cookie 配置 - 只需要这两个关键 cookie
	Secure1PSID   = "g.a0004QjzqA-0CpdTW8IXDXLJLhiYF_AejQLm9tGrngzR3fD1dbYF5xMw7F27LHwc7GNzqN2d_wACgYKAQgSARISFQHGX2MiJLv28pPfjSXJHiRizi_UNhoVAUF8yKrns5sWypcgdiZ8-e41MITl0076"
	Secure1PSIDTS = "sidts-CjIBwQ9iI-_y9yjtNBMTNcJr-R_YBYsszEWcJwigXQ08uoX_xlEyHOsxspPN9lAL5M2TNhAA"

	// Cookie 字符串 (由 CookieManager 生成)
	Cookie = ""

	// Cookie 管理器实例
	CookieMgr *CookieManager

	// Cookie 缓存目录
	CookieCacheDir = "./cookies"

	// 是否启用详细日志
	Verbose = true

	// Cookie 锁,用于并发安全
	cookieMutex sync.RWMutex

	// Cookie 变更回调列表
	cookieChangeCallbacks []CookieChangeCallback
	callbackMutex         sync.RWMutex

	// Cookie 旋转节流
	lastCookieRotate time.Time
	rotateMutex      sync.Mutex
)

func init() {
	ctx := gctx.GetInitCtx()

	// 读取端口
	port := g.Cfg().MustGetWithEnv(ctx, "PORT").Int()
	if port > 0 {
		PORT = port
	}
	g.Log().Info(ctx, "PORT:", PORT)

	// 读取缓存目录
	cacheDir := g.Cfg().MustGetWithEnv(ctx, "COOKIE_CACHE_DIR").String()
	if cacheDir != "" {
		CookieCacheDir = cacheDir
	}

	// 读取代理 URL
	proxyURL := g.Cfg().MustGetWithEnv(ctx, "PROXY_URL").String()
	if proxyURL != "" {
		ProxyURL = proxyURL
	}

	// 读取详细日志开关
	verbose := g.Cfg().MustGetWithEnv(ctx, "VERBOSE").Bool()
	Verbose = verbose

	// 初始化 Cookie 存储 (默认使用文件存储)
	cookieConfigPath := g.Cfg().MustGetWithEnv(ctx, "COOKIE_CONFIG_PATH").String()
	if cookieConfigPath == "" {
		cookieConfigPath = "./cookies/cookie_config.json"
	}
	InitCookieStorage(NewFileCookieStorage(cookieConfigPath))

	// 尝试从存储加载 Cookie
	if err := LoadCookieFromStorage(ctx); err != nil {
		g.Log().Debug(ctx, "从存储加载 Cookie 失败:", err)
	}

	// 如果存储中没有,从环境变量/配置文件读取
	psid := g.Cfg().MustGetWithEnv(ctx, "SECURE_1PSID").String()
	if psid != "" {
		Secure1PSID = psid
	}

	psidts := g.Cfg().MustGetWithEnv(ctx, "SECURE_1PSIDTS").String()
	if psidts != "" {
		Secure1PSIDTS = psidts
	}

	// 初始化 Cookie 管理器
	CookieMgr = NewCookieManager(Secure1PSID, Secure1PSIDTS, CookieCacheDir, ProxyURL, Verbose)

	// 尝试获取有效的 Cookie
	if Secure1PSID != "" {
		accessToken, cookieStr, err := CookieMgr.GetAccessToken(ctx)
		if err != nil {
			g.Log().Warning(ctx, "初始化 Cookie 失败:", err)
			// 如果有 PSID 和 PSIDTS,构建基本的 cookie 字符串
			if Secure1PSID != "" && Secure1PSIDTS != "" {
				Cookie = "__Secure-1PSID=" + Secure1PSID + "; __Secure-1PSIDTS=" + Secure1PSIDTS
				g.Log().Info(ctx, "使用基本 Cookie 配置")
			}
		} else {
			Cookie = cookieStr
			g.Log().Info(ctx, "Cookie 初始化成功, AccessToken:", accessToken[:20]+"...")
		}
	} else {
		g.Log().Warning(ctx, "未配置 SECURE_1PSID,请设置环境变量或配置文件")
	}

	g.Log().Info(ctx, "Cookie 配置完成")
}

// GetCookie 获取当前 Cookie (线程安全)
func GetCookie() string {
	cookieMutex.RLock()
	defer cookieMutex.RUnlock()
	return Cookie
}

// SetCookie 设置 Cookie (线程安全)
func SetCookie(cookie string) {
	cookieMutex.Lock()
	defer cookieMutex.Unlock()
	Cookie = cookie
}

// RefreshCookie 刷新 Cookie
func RefreshCookie() error {
	ctx := gctx.GetInitCtx()

	rotateMutex.Lock()
	defer rotateMutex.Unlock()

	// 最小间隔 1 分钟，避免频繁刷新导致签名会话错位
	if !lastCookieRotate.IsZero() && time.Since(lastCookieRotate) < time.Minute {
		g.Log().Debug(ctx, "跳过刷新: 距上次刷新不足 1 分钟")
		return nil
	}

	// 读取当前主 Cookie（保持 __Secure-1PSID 不变）
	cookieMutex.RLock()
	psid := Secure1PSID
	psidts := Secure1PSIDTS
	cookieMutex.RUnlock()
	if psid == "" {
		return fmt.Errorf("缺少 __Secure-1PSID，无法刷新")
	}

	cookies := map[string]string{
		"__Secure-1PSID":   psid,
		"__Secure-1PSIDTS": psidts,
	}

	newPSIDTS, err := CookieMgr.RotateCookies(ctx, cookies)
	if err != nil {
		return err
	}

	// 更新内存中的 TS 与 CookieManager
	cookieMutex.Lock()
	Secure1PSIDTS = newPSIDTS
	cookieMutex.Unlock()
	CookieMgr.Secure1PSIDTS = newPSIDTS

	// 重新获取完整的 Cookie（保持主 PSID 不变，只刷新 TS）
	if _, cookieStr, err := CookieMgr.GetAccessToken(ctx); err != nil {
		// 获取失败则回退到基础串
		SetCookie("__Secure-1PSID=" + psid + "; __Secure-1PSIDTS=" + newPSIDTS)
		g.Log().Warning(ctx, "获取 AccessToken 失败，使用基础 Cookie:", err)
	} else {
		SetCookie(cookieStr)
	}

	lastCookieRotate = time.Now()

	// 保存到存储 (文件或数据库)
	if err := SaveCookieToStorage(ctx); err != nil {
		g.Log().Warning(ctx, "保存 Cookie 到存储失败:", err)
	}

	g.Log().Info(ctx, "Cookie 刷新成功")
	return nil
}

// UpdateSecure1PSID 更新 Secure1PSID 并保存
func UpdateSecure1PSID(ctx context.Context, psid string) error {
	cookieMutex.Lock()
	Secure1PSID = psid
	cookieMutex.Unlock()

	// 更新 CookieManager
	CookieMgr.Secure1PSID = psid

	// 触发 Cookie 变更回调
	triggerCookieChangeCallbacks()

	// 保存到存储
	return SaveCookieToStorage(ctx)
}

// UpdateSecure1PSIDTS 更新 Secure1PSIDTS 并保存
func UpdateSecure1PSIDTS(ctx context.Context, psidts string) error {
	cookieMutex.Lock()
	Secure1PSIDTS = psidts
	cookieMutex.Unlock()

	// 更新 CookieManager
	CookieMgr.Secure1PSIDTS = psidts

	// 触发 Cookie 变更回调
	triggerCookieChangeCallbacks()

	// 保存到存储
	return SaveCookieToStorage(ctx)
}

// UpdateCookies 同时更新 PSID 和 PSIDTS 并保存
func UpdateCookies(ctx context.Context, psid, psidts string) error {
	cookieMutex.Lock()
	Secure1PSID = psid
	Secure1PSIDTS = psidts
	cookieMutex.Unlock()

	// 更新 CookieManager
	CookieMgr.Secure1PSID = psid
	CookieMgr.Secure1PSIDTS = psidts

	// 重新构建 Cookie 字符串
	Cookie = "__Secure-1PSID=" + psid + "; __Secure-1PSIDTS=" + psidts

	// 触发 Cookie 变更回调
	triggerCookieChangeCallbacks()

	// 保存到存储
	return SaveCookieToStorage(ctx)
}

// RegisterCookieChangeCallback 注册 Cookie 变更回调
func RegisterCookieChangeCallback(callback CookieChangeCallback) {
	callbackMutex.Lock()
	defer callbackMutex.Unlock()
	cookieChangeCallbacks = append(cookieChangeCallbacks, callback)
}

// triggerCookieChangeCallbacks 触发所有 Cookie 变更回调
func triggerCookieChangeCallbacks() {
	callbackMutex.RLock()
	defer callbackMutex.RUnlock()
	for _, callback := range cookieChangeCallbacks {
		go callback() // 异步执行回调
	}
}
