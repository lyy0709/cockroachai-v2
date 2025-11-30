package utils

import (
	"regexp"
	"sort"
	"strings"
)

// DOMAIN_LIST 从实际URL中提取的所有唯一域名，按长度降序排列（避免包含关系导致的错误匹配）
var DOMAIN_LIST = []string{
	"drive-thirdparty.googleusercontent.com", // 38
	"signaler-pa.clients6.google.com",        // 32
	"region1.google-analytics.com",           // 29
	"region1.analytics.google.com",           // 29
	"ogads-pa.clients6.google.com",           // 28
	"waa-pa.clients6.google.com",             // 26
	"lh3.googleusercontent.com",              // 25
	"push.clients6.google.com",               // 24
	"www.googletagmanager.com",               // 24
	"accounts.google.com",                    // 19
	"gemini.google.com",                      // 18
	"fonts.gstatic.com",                      // 18
	"play.google.com",                        // 16
	"www.google.co.uk",                       // 16
	"www.gstatic.com",                        // 16
	"apis.google.com",                        // 15
	"lh3.google.com",                         // 14
	"www.google.com",                         // 14
	"ogs.google.com",                         // 14 新增
}

// ExtractDomainFromURL 从完整URL中提取域名
func ExtractDomainFromURL(urlStr string) string {
	// 移除协议前缀
	urlStr = regexp.MustCompile(`^https?://`).ReplaceAllString(urlStr, "")

	// 提取域名部分（到第一个/或结尾）
	parts := strings.SplitN(urlStr, "/", 2)
	if len(parts) > 0 {
		// 移除端口号（如果有）
		domain := strings.Split(parts[0], ":")[0]
		return domain
	}
	return ""
}

// ParseDomainsFromURLList 从URL列表中提取所有唯一域名并排序
// 按域名长度降序排列，避免短域名误匹配长域名
func ParseDomainsFromURLList(urls []string) []string {
	domainMap := make(map[string]bool)

	for _, url := range urls {
		if url == "" {
			continue
		}
		domain := ExtractDomainFromURL(url)
		if domain != "" {
			domainMap[domain] = true
		}
	}

	// 转换为切片
	domains := make([]string, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, domain)
	}

	// 按长度降序排序（长的在前，避免包含关系）
	sort.Slice(domains, func(i, j int) bool {
		if len(domains[i]) == len(domains[j]) {
			return domains[i] > domains[j] // 长度相同时按字母降序
		}
		return len(domains[i]) > len(domains[j])
	})

	return domains
}

// ExtractOriginalDomainFromPath 从代理后的路径中提取原始域名
// 例如："/gemini.google.com/app" -> "gemini.google.com"
// 注意：使用DOMAIN_LIST按顺序匹配，优先匹配最长的域名
func ExtractOriginalDomainFromPath(path string) string {
	// 移除开头的斜杠
	path = strings.TrimPrefix(path, "/")

	// 按顺序匹配域名列表（长的在前）
	for _, domain := range DOMAIN_LIST {
		if strings.HasPrefix(path, domain) {
			// 确保匹配的是完整域名（后面是/或结尾）
			if len(path) == len(domain) || (len(path) > len(domain) && path[len(domain)] == '/') {
				return domain
			}
		}
	}

	return ""
}

// GetOriginalURL 从代理请求中重建原始URL
// path: 请求路径，如 "/gemini.google.com/app"
// rawQuery: 原始查询字符串
// 返回: 完整的原始URL，如 "https://gemini.google.com/app?query=xxx"
func GetOriginalURL(path string, rawQuery string) (string, string) {
	domain := ExtractOriginalDomainFromPath(path)
	if domain == "" {
		// 如果无法从路径提取域名，返回空字符串
		return "", ""
	}

	// 从路径中移除域名部分
	pathWithoutDomain := strings.TrimPrefix(path, "/"+domain)
	if pathWithoutDomain == "" {
		pathWithoutDomain = "/"
	}

	// 构建原始URL
	originalURL := "https://" + domain + pathWithoutDomain
	if rawQuery != "" {
		originalURL += "?" + rawQuery
	}

	return originalURL, domain
}
