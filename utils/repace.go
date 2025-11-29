package utils

import (
	"regexp"
	"strings"

	"github.com/gogf/gf/v2/os/gctx"
)

// Replace 替换内容中的所有目标域名为代理域名
// 格式：https://original-domain.com/path -> https://proxy-host/path
// 不再在URL中包含原始域名，通过路径映射表确定目标域名
func Replace(ctx gctx.Ctx, content string, scheme string, host string) string {
	result := content

	// 按顺序处理每个域名（长的在前，避免误匹配）
	for _, domain := range DOMAIN_LIST {
		// 转义域名中的特殊字符（主要是点号和连字符）
		escapedDomain := regexp.QuoteMeta(domain)

		// 1. 匹配带协议的完整URL：https?://domain[/path][?query]
		// 使用更精确的正则，分别捕获路径和查询参数
		pattern1 := regexp.MustCompile(`(https?://)` + escapedDomain + `(/[^\s"'<>?]*)?(\?[^\s"'<>]*)?`)
		result = pattern1.ReplaceAllStringFunc(result, func(match string) string {
			// 检查是否已经被替换过
			if strings.Contains(match, host) {
				return match
			}

			// 提取路径部分（包括查询字符串）
			pathPart := strings.TrimPrefix(match, "https://"+domain)
			pathPart = strings.TrimPrefix(pathPart, "http://"+domain)

			// 如果为空，设置为 /
			if pathPart == "" {
				pathPart = "/"
			}
			// 如果以 ? 开头，添加 /
			if strings.HasPrefix(pathPart, "?") {
				pathPart = "/" + pathPart
			}
			// 确保只有一个开头的 /
			if strings.HasPrefix(pathPart, "//") {
				pathPart = strings.TrimPrefix(pathPart, "/")
			}

			return scheme + "://" + host + pathPart
		})

		// 2. 匹配协议相对URL：//domain/path（常见于HTML/JS中）
		pattern1b := regexp.MustCompile(`(//)` + escapedDomain + `(/[^\s"'<>?]*)?(\?[^\s"'<>]*)?`)
		result = pattern1b.ReplaceAllStringFunc(result, func(match string) string {
			// 检查是否已经被替换过
			if strings.Contains(match, host) {
				return match
			}
			// 提取路径部分
			pathPart := strings.TrimPrefix(match, "//"+domain)

			if pathPart == "" {
				pathPart = "/"
			}
			if strings.HasPrefix(pathPart, "?") {
				pathPart = "/" + pathPart
			}
			if strings.HasPrefix(pathPart, "//") {
				pathPart = strings.TrimPrefix(pathPart, "/")
			}

			return "//" + host + pathPart
		})

		// 3. 匹配不带协议的相对URL（如在JS或CSS中）
		pattern2 := regexp.MustCompile(`(["\s=:])` + escapedDomain + `(/[^\s"'<>?]*)?(\?[^\s"'<>]*)?`)
		result = pattern2.ReplaceAllStringFunc(result, func(match string) string {
			// 获取前缀字符（引号、空格等）
			prefix := match[:1]
			restMatch := match[1:]

			// 检查是否已经被替换过（避免重复替换）
			if strings.Contains(restMatch, host) {
				return match
			}

			// 提取路径部分
			pathPart := strings.TrimPrefix(restMatch, domain)

			if pathPart == "" {
				pathPart = "/"
			}
			if strings.HasPrefix(pathPart, "?") {
				pathPart = "/" + pathPart
			}
			if strings.HasPrefix(pathPart, "//") {
				pathPart = strings.TrimPrefix(pathPart, "/")
			}

			return prefix + host + pathPart
		})
	}

	return result
}

// ExtractDomainFromPath 从URL路径中提取域名（使用新的域名列表）
// 例如："/gemini.google.com/path/to/file" -> "gemini.google.com"
// 已被 domains.go 中的 ExtractOriginalDomainFromPath 替代，保留此函数以兼容
func ExtractDomainFromPath(path string) string {
	return ExtractOriginalDomainFromPath(path)
}
