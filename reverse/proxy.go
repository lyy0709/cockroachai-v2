package reverse

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"reverse/config"
	"reverse/utils"
	"strings"

	"github.com/andybalholm/brotli"
	http "github.com/bogdanfinn/fhttp"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

func Proxy(r *ghttp.Request) {
	ctx := r.Context()
	scheme, host := utils.GetInfo(r)

	// 处理 CORS 预检请求
	if r.Method == "OPTIONS" {
		r.Response.Header().Set("Access-Control-Allow-Origin", "*")
		r.Response.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		r.Response.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-CSRF-Token, X-Same-Domain, X-Goog-Encode-Response-If-Executable, X-Goog-Upload-Header-Content-Encoding, X-Goog-Upload-Header-Content-Type, X-Goog-Upload-Protocol, X-Goog-Upload-Command, X-Goog-Upload-Offset, X-Goog-Upload-Content-Type, X-Goog-Upload-Content-Length, X-Client-Data")
		r.Response.Header().Set("Access-Control-Allow-Credentials", "true")
		r.Response.Header().Set("Access-Control-Max-Age", "86400")
		r.Response.WriteStatus(http.StatusNoContent)
		return
	}

	// 新方案：从路径中提取域名和真实路径
	// 路径格式：/gemini.google.com/app/chat
	originalDomain, realPath := utils.ExtractDomainAndPathFromProxyPath(r.URL.Path)

	// 如果无法提取域名（不是新格式），说明路径格式错误
	if originalDomain == "" {
		g.Log().Error(ctx, "无法从路径中提取域名", "path", r.URL.Path)
		r.Response.WriteStatus(http.StatusBadRequest, "Invalid path format. Expected: /domain.com/path")
		return
	}

	// 拦截并忽略不重要的第三方请求（Google Analytics, Ads, 图片等）
	// 这些请求对核心功能没有影响，直接返回 200 避免报错
	if shouldIgnoreRequest(originalDomain, realPath) {
		r.Response.Header().Set("Access-Control-Allow-Origin", "*")
		r.Response.WriteStatus(http.StatusOK)
		return
	}

	// 构建目标URL（使用提取的真实路径）
	targetURL := "https://" + originalDomain + realPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// 处理特殊的查询参数（如origin）
	if r.URL.RawQuery != "" && strings.Contains(r.URL.RawQuery, "origin=") {
		queryParams := r.URL.Query()
		originParam := queryParams.Get("origin")
		if originParam != "" {
			// 检查是否包含代理域名
			if strings.Contains(originParam, host) {
				// 格式: http://127.0.0.1:9315/domain.com/path
				originPath := strings.TrimPrefix(originParam, "http://"+host)
				originPath = strings.TrimPrefix(originPath, "https://"+host)

				if originPath != "" && strings.HasPrefix(originPath, "/") {
					// 从路径中提取域名
					originDomainFromParam, _ := utils.ExtractDomainAndPathFromProxyPath(originPath)
					if originDomainFromParam != "" {
						queryParams.Set("origin", "https://"+originDomainFromParam)
					} else {
						// 如果无法提取，使用当前请求的目标域名
						queryParams.Set("origin", "https://"+originalDomain)
					}
				} else {
					// 没有路径，使用当前请求的目标域名
					queryParams.Set("origin", "https://"+originalDomain)
				}
			}
		}
		// 重新构建URL（使用提取的真实路径）
		targetURL = "https://" + originalDomain + realPath + "?" + queryParams.Encode()
	}
	// 读取请求体用于调试和可能的修改
	var reqBodyBytes []byte
	if r.Body != nil {
		reqBodyBytes, _ = ioutil.ReadAll(r.Body)
	}

	// StreamGenerate 和 batchexecute 请求：完全透传at和f.sid参数
	// 只替换Cookie，不替换at和f.sid（因为它们可能与f.req等其他数据深度绑定）

	// 创建新请求
	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, bytes.NewReader(reqBodyBytes))
	if err != nil {
		g.Log().Error(ctx, "创建请求失败", err)
		r.Response.WriteStatus(http.StatusInternalServerError, err.Error())
		return
	}

	for k, v := range r.Header {
		if len(v) > 0 {
			req.Header.Set(k, v[0])
		}
	}

	// 设置固定请求头（仅在缺失时补齐，避免覆盖浏览器头）
	for key, value := range utils.DEFAULT_HEADERS {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// 只修改必须修改的头
	// Host 必须设置为实际的目标域名（HTTP 协议要求）
	req.Header.Set("Host", originalDomain)

	// 优先使用浏览器的 Accept-Encoding；若为空则补常见值，避免破坏上游压缩/分块
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// 统一修正 Origin/Referer：如果来自代理域，映射回真实域，保持同源校验通过
	if refer := r.Referer(); refer != "" && strings.Contains(refer, host) {
		relative := strings.TrimPrefix(refer, scheme+"://"+host)
		if refDomain, refPath := utils.ExtractDomainAndPathFromProxyPath(relative); refDomain != "" {
			req.Header.Set("Referer", "https://"+refDomain+refPath)
			req.Header.Set("Origin", "https://"+refDomain)
		} else {
			// 无法解析时，回退到目标域，确保 Origin/Referer 一致
			req.Header.Set("Referer", "https://"+originalDomain+realPath)
			req.Header.Set("Origin", "https://"+originalDomain)
		}
	}

	// 所有请求都使用服务端 Cookie（部分资源可根据域名选择去掉）
	req.Header.Set("Cookie", config.GetCookie())
	if req.Header.Get("Origin") == "" {
		req.Header.Set("Origin", "https://"+originalDomain)
	}
	if req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", "https://"+originalDomain)
	}

	// 其他请求保持统一来源与 CSRF 保护
	if req.Header.Get("X-Same-Domain") == "" {
		req.Header.Set("X-Same-Domain", "1")
	}

	// 根据请求路径选择合适的客户端
	client := utils.GetClientForPath(r.URL.Path)
	resp, err := client.Do(req)
	if err != nil {
		g.Log().Error(ctx, "发送请求失败", err)
		r.Response.WriteStatus(http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	// 检查是否是 StreamGenerate 流式请求（使用真实路径）
	isStreamGenerate := IsStreamGenerateRequest(realPath)

	// 如果是流式请求，使用流式转发模式
	if isStreamGenerate {
		g.Log().Info(ctx, "使用流式转发模式")
		// 复制响应头
		for k, v := range resp.Header {
			if len(v) > 0 {
				r.Response.Header().Set(k, v[0])
			}
		}
		header := r.Response.Header()
		utils.HeaderModify(&header)
		r.Response.Status = resp.StatusCode

		// 按行读取并流式输出
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Bytes()
			r.Response.Write(line)
			r.Response.Write([]byte("\n"))
			r.Response.Flush() // 每行立即刷新到客户端
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			g.Log().Error(ctx, "流式读取失败", err)
		}
		return
	}

	// 非流式请求：读取响应体
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	// 获取 Content-Type 判断是否需要替换
	contentType := resp.Header.Get("Content-Type")
	shouldReplace := shouldReplaceContent(contentType)

	// 检查是否需要解压缩
	contentEncoding := resp.Header.Get("Content-Encoding")
	var bodyReader io.Reader = bytes.NewReader(bodyBytes)

	if shouldReplace {
		if contentEncoding == "gzip" {
			gzReader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
			if err == nil {
				defer gzReader.Close()
				decompressed, err := ioutil.ReadAll(gzReader)
				if err == nil {
					bodyBytes = decompressed
				}
			}
		} else if contentEncoding == "br" {
			brReader := brotli.NewReader(bytes.NewReader(bodyBytes))
			decompressed, err := ioutil.ReadAll(brReader)
			if err == nil {
				bodyBytes = decompressed
			}
		}
	}
	_ = bodyReader // 避免未使用警告

	// 图片请求（googleusercontent）非 2xx/3xx 时记录详细日志
	if strings.Contains(originalDomain, "googleusercontent.com") {
		if resp.StatusCode >= 400 {
			snippet := bodyBytes
			if len(snippet) > 512 {
				snippet = snippet[:512]
			}
			g.Log().Error(ctx, "图片请求失败",
				"status", resp.StatusCode,
				"url", targetURL,
				"domain", originalDomain,
				"path", realPath,
				"req_headers", req.Header,
				"cookie_set", req.Header.Get("Cookie") != "",
				"auth_set", req.Header.Get("Authorization") != "",
				"referer", req.Header.Get("Referer"),
				"origin", req.Header.Get("Origin"),
				"resp_headers", resp.Header,
				"body_snippet", string(snippet),
			)
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// 成功时记录调试日志
			g.Log().Debug(ctx, "图片请求成功",
				"status", resp.StatusCode,
				"url", targetURL,
				"content_type", resp.Header.Get("Content-Type"),
			)
		}
	}

	// 复制响应头
	for k, v := range resp.Header {
		if len(v) > 0 {
			// 跳过 Content-Encoding 和 Content-Length，因为内容可能已被修改
			if shouldReplace && (k == "Content-Encoding" || k == "Content-Length") {
				continue
			}
			// 对于不需要替换的内容，保留原始头
			if !shouldReplace && k == "Content-Encoding" {
				r.Response.Header().Set(k, v[0])
				continue
			}
			if !shouldReplace && k == "Content-Length" {
				r.Response.Header().Set(k, v[0])
				continue
			}
			r.Response.Header().Set(k, v[0])
		}
	}
	header := r.Response.Header()
	utils.HeaderModify(&header)
	r.Response.Status = resp.StatusCode

	// 只对文本内容进行替换
	if shouldReplace {
		content := utils.Replace(ctx, string(bodyBytes), scheme, host, originalDomain)
		r.Response.Write(content)
	} else {
		r.Response.Write(bodyBytes)
	}
}

// shouldIgnoreRequest 判断是否应该忽略该请求（直接返回 200）
// 用于拦截 Google Analytics, Ads, 以及某些图片请求
func shouldIgnoreRequest(domain string, path string) bool {
	// 忽略 Google Analytics 请求
	if strings.Contains(domain, "google-analytics.com") ||
		strings.Contains(domain, "analytics.google.com") {
		return true
	}

	// 忽略 Google Ads 和 DoubleClick 请求
	if strings.Contains(domain, "doubleclick.net") ||
		strings.Contains(domain, "googleadservices.com") ||
		strings.Contains(domain, "googlesyndication.com") {
		return true
	}

	// 忽略 Google Tag Manager 的某些请求
	if strings.Contains(domain, "googletagmanager.com") && strings.Contains(path, "/gtag/") {
		return true
	}

	// 注意：移除了图片请求的拦截逻辑，让图片请求正常通过代理
	// 如果某些图片返回 403，可能需要检查 Cookie 或请求头设置

	return false
}

// shouldReplaceContent 判断是否需要对响应内容进行 URL 替换
func shouldReplaceContent(contentType string) bool {
	if contentType == "" {
		return true // 默认进行替换
	}
	contentType = strings.ToLower(contentType)

	// 需要替换的内容类型
	replaceTypes := []string{
		"text/html",
		"text/css",
		// 注意：不包含 application/json，batchexecute 的 JSON 响应中的 URL
		// 必须由客户端 JS 拦截器处理，服务端替换会破坏响应结构
		// 注意：不包含 JavaScript 文件，因为正则替换会破坏 JS 语法
		// JavaScript 的 URL 重写由注入的拦截脚本在运行时处理
		"text/xml",
		"application/xml",
		"text/plain",
		"application/x-www-form-urlencoded",
	}

	for _, t := range replaceTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}

	return false
}

// checkIsImageRequest 综合判断是否是图片请求
// 优先通过域名和路径判断，Accept 头作为辅助判断
func checkIsImageRequest(acceptHeader string, domain string, path string) bool {
	// 1. 通过域名判断（最准确）
	imageDomains := []string{
		"lh3.google.com",
		"lh3.googleusercontent.com",
		"lh4.googleusercontent.com",
		"lh5.googleusercontent.com",
		"lh6.googleusercontent.com",
	}
	for _, imgDomain := range imageDomains {
		if domain == imgDomain {
			return true
		}
	}

	// 2. 通过路径判断
	imagePathPatterns := []string{
		"/rd-gg/", // Google 图片重定向路径
		"/gg/",    // Google 图片路径
		"/a/",     // 头像路径
		"/ogw/",   // 图片路径
		"/gg-dl/", // 图片下载路径
	}
	for _, pattern := range imagePathPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	// 3. 通过文件扩展名判断
	lowerPath := strings.ToLower(path)
	imageExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp"}
	for _, ext := range imageExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}

	// 4. 通过 Accept 请求头判断（仅当 Accept 头以 image/ 开头时）
	// 注意：浏览器的 Accept 头通常包含多种类型，只有当 image/ 是第一个类型时才认为是图片请求
	if acceptHeader != "" {
		lowerAccept := strings.ToLower(strings.TrimSpace(acceptHeader))
		if strings.HasPrefix(lowerAccept, "image/") {
			return true
		}
	}

	return false
}
