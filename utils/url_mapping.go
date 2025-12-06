package utils

import (
	"strings"
)

// URL_PATH_DOMAIN_MAP 路径前缀到域名的映射表
// 用于客户端 JavaScript 拦截器判断相对路径应该请求哪个域名
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

	// region1.google-analytics.com 的路径
	"/g/collect": "region1.google-analytics.com",

	// www.google.co.uk 的路径
	"/ads/ga-audiences": "www.google.co.uk",

	// 移除所有通用的图片路径，避免误判：
	// "/gg/", "/a/", "/ogw/", "/gg-dl/", "/rd-gg" - 这些路径太通用
	// 图片请求应该依赖当前页面的域名，而不是路径映射

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

// ExtractDomainAndPathFromProxyPath 从代理路径中提取原始域名和真实路径
// 输入: /gemini.google.com/app/chat?q=test
// 输出: domain="gemini.google.com", path="/app/chat"
// 新方案：路径格式为 /domain/path，域名嵌入在路径的第一段
// 兼容旧格式：当路径未携带域名时，尝试通过 URL_PATH_DOMAIN_MAP 最长前缀匹配推断域名
func ExtractDomainAndPathFromProxyPath(proxyPath string) (domain string, realPath string) {
	// 移除开头的斜杠
	trimmedPath := strings.TrimPrefix(proxyPath, "/")

	if trimmedPath == "" {
		return "", "/"
	}

	// 查找第一个斜杠的位置（域名和路径的分隔符）
	slashIndex := strings.Index(trimmedPath, "/")

	var possibleDomain string
	if slashIndex == -1 {
		// 没有找到斜杠，整个字符串可能是域名
		possibleDomain = trimmedPath
		realPath = "/"
	} else {
		// 找到斜杠，分割域名和路径
		possibleDomain = trimmedPath[:slashIndex]
		realPath = "/" + trimmedPath[slashIndex+1:]
	}

	// 验证是否在已知域名列表中
	for _, knownDomain := range DOMAIN_LIST {
		if possibleDomain == knownDomain {
			return possibleDomain, realPath
		}
	}

	// 兼容旧格式：根据路径前缀映射推断域名（最长前缀优先）
	longestMatch := ""
	matchedDomain := ""
	for prefix, mappedDomain := range URL_PATH_DOMAIN_MAP {
		if strings.HasPrefix(proxyPath, prefix) {
			if len(prefix) > len(longestMatch) {
				longestMatch = prefix
				matchedDomain = mappedDomain
			}
		}
	}
	if matchedDomain != "" {
		return matchedDomain, proxyPath
	}

	// 如果第一部分不是有效域名，返回空域名（表示这不是新格式的路径）
	return "", proxyPath
}
