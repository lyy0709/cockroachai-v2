package utils

import (
	"strings"
)

// URL_PATH_DOMAIN_MAP 路径前缀到域名的映射表
// 根据实际抓取的URL列表建立映射关系
// 格式：路径前缀 -> 域名
var URL_PATH_DOMAIN_MAP = map[string]string{
	// gemini.google.com 的路径
	"/_/BardChatUi": "gemini.google.com",
	"/_/bscframe":   "gemini.google.com",
	"/app":          "gemini.google.com",
	"/gem":          "gemini.google.com",
	"/generate_204": "gemini.google.com",

	// accounts.google.com 的路径
	"/RotateCookiesPage": "accounts.google.com",
	"/RotateCookies":     "accounts.google.com",

	// www.gstatic.com 的路径
	"/_/mss/boq-bard-web":   "www.gstatic.com",
	"/_/mss/boq-identity":   "www.gstatic.com",
	"/_/mss/boq-one-google": "www.gstatic.com",
	"/_/boq-bard-web":       "www.gstatic.com",
	"/og/_/js":              "www.gstatic.com",
	"/og/_/ss":              "www.gstatic.com",
	"/feedback/js":          "www.gstatic.com",
	"/lamda/images":         "www.gstatic.com",
	"/images/branding":      "www.gstatic.com",

	// fonts.gstatic.com 的路径
	"/icon/font": "fonts.gstatic.com",
	"/s/":        "fonts.gstatic.com",

	// waa-pa.clients6.google.com 的路径
	"/$rpc/google.internal.waa": "waa-pa.clients6.google.com",

	// signaler-pa.clients6.google.com 的路径
	"/punctual": "signaler-pa.clients6.google.com",

	// ogads-pa.clients6.google.com 的路径
	"/$rpc/google.internal.onegoogle": "ogads-pa.clients6.google.com",

	// push.clients6.google.com 的路径
	"/upload": "push.clients6.google.com",

	// apis.google.com 的路径
	"/_/scs/abc-static": "apis.google.com",

	// www.google.com 的路径
	"/ccm/collect": "www.google.com",
	"/js/bg":       "www.google.com",

	// www.googletagmanager.com 的路径
	"/gtm.js":  "www.googletagmanager.com",
	"/gtag/js": "www.googletagmanager.com",
	"/gtag/":   "www.googletagmanager.com",
	"/static/": "www.googletagmanager.com",

	// region1.google-analytics.com 和 region1.analytics.google.com 的路径
	"/g/collect": "region1.google-analytics.com",

	// www.google.co.uk 的路径
	"/ads/ga-audiences": "www.google.co.uk",

	// lh3.googleusercontent.com 和 lh3.google.com 的路径
	"/ogw/":  "lh3.googleusercontent.com",
	"/a/":    "lh3.googleusercontent.com",
	"/gg/":   "lh3.googleusercontent.com",
	"/gg-dl/": "lh3.googleusercontent.com",
	"/rd-gg": "lh3.google.com",

	// drive-thirdparty.googleusercontent.com 的路径
	"/32/type": "drive-thirdparty.googleusercontent.com",

	// play.google.com 的路径
	"/log": "play.google.com",

	// ogs.google.com 的路径
	"/u/":      "ogs.google.com",
	"/widget/": "ogs.google.com",

	// contribution.usercontent.google.com 的路径
	"/download": "contribution.usercontent.google.com",
}

// GetDomainFromPath 根据路径获取对应的域名
// 优先使用精确的路径前缀匹配
func GetDomainFromPath(path string) string {
	// 首先尝试从路径中直接提取域名（如果路径包含域名）
	domainFromPath := ExtractOriginalDomainFromPath(path)
	if domainFromPath != "" {
		return domainFromPath
	}

	// 如果路径不包含域名，使用路径映射表
	// 按路径长度降序排序匹配（更长的路径优先匹配）
	longestMatch := ""
	matchedDomain := ""

	for prefix, domain := range URL_PATH_DOMAIN_MAP {
		if strings.HasPrefix(path, prefix) {
			if len(prefix) > len(longestMatch) {
				longestMatch = prefix
				matchedDomain = domain
			}
		}
	}

	if matchedDomain != "" {
		return matchedDomain
	}

	// 默认返回 gemini.google.com
	return "gemini.google.com"
}

// ExtractDomainFromReferer 从Referer中提取原始域名
// referer格式: http://127.0.0.1:9315/gemini.google.com/path
// 返回: gemini.google.com
func ExtractDomainFromReferer(referer string, proxyHost string) string {
	if referer == "" {
		return ""
	}

	// 移除协议和代理host
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(referer, scheme+proxyHost) {
			path := strings.TrimPrefix(referer, scheme+proxyHost)
			return ExtractOriginalDomainFromPath(path)
		}
	}

	return ""
}
