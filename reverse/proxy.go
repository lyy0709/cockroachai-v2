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

	// 使用路径映射表确定目标域名
	originalDomain := utils.GetDomainFromPath(r.URL.Path)

	// 拦截并忽略不重要的第三方请求（Google Analytics, Ads, 图片等）
	// 这些请求对核心功能没有影响，直接返回 200 避免报错
	if shouldIgnoreRequest(originalDomain, r.URL.Path) {
		r.Response.Header().Set("Access-Control-Allow-Origin", "*")
		r.Response.WriteStatus(http.StatusOK)
		return
	}

	// 构建目标URL
	targetURL := "https://" + originalDomain + r.URL.Path
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
				// 格式: http://127.0.0.1:9315 或 http://127.0.0.1:9315/path
				originPath := strings.TrimPrefix(originParam, "http://"+host)
				originPath = strings.TrimPrefix(originPath, "https://"+host)

				if originPath != "" && strings.HasPrefix(originPath, "/") {
					// 有路径部分，通过路径映射表确定域名
					originDomainFromParam := utils.GetDomainFromPath(originPath)
					queryParams.Set("origin", "https://"+originDomainFromParam)
				} else {
					// 没有路径，使用当前请求的目标域名
					queryParams.Set("origin", "https://"+originalDomain)
				}
			}
		}
		// 重新构建URL
		targetURL = "https://" + originalDomain + r.URL.Path + "?" + queryParams.Encode()
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

	// 复制所有请求头（透传）
	for k, v := range r.Header {
		if len(v) > 0 {
			req.Header.Set(k, v[0])
		}
	}

	// 设置固定请求头
	for k, v := range utils.DEFAULT_HEADERS {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// 只修改必须修改的头
	req.Header.Set("Host", originalDomain)
	req.Header.Set("Accept-Encoding", "")
	// 所有请求都使用服务端 Cookie
	req.Header.Set("Cookie", config.GetCookie())

	// 确保关键的 CSRF 保护头存在
	if req.Header.Get("X-Same-Domain") == "" {
		req.Header.Set("X-Same-Domain", "1")
	}

	// 修正 Origin 和 Referer（如果它们指向代理域名，改为目标域名）
	if origin := req.Header.Get("Origin"); origin != "" && strings.Contains(origin, host) {
		req.Header.Set("Origin", "https://"+originalDomain)
	}
	if referer := req.Header.Get("Referer"); referer != "" && strings.Contains(referer, host) {
		req.Header.Set("Referer", "https://"+originalDomain+"/")
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

	// 检查是否是 StreamGenerate 流式请求
	isStreamGenerate := IsStreamGenerateRequest(r.URL.Path)

	// 如果是流式请求，使用流式转发模式
	if isStreamGenerate {
		// 复制响应头
		for k, v := range resp.Header {
			if k == "Set-Cookie" {
				for _, cookie := range v {
					r.Response.Header().Add(k, cookie)
				}
				continue
			}
			if len(v) > 0 {
				r.Response.Header().Set(k, v[0])
			}
		}
		header := r.Response.Header()
		utils.FixSetCookieHeaders(&header, host)
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

	// 复制响应头
	for k, v := range resp.Header {
		// Set-Cookie 需要特殊处理，先添加所有值
		if k == "Set-Cookie" {
			for _, cookie := range v {
				r.Response.Header().Add(k, cookie)
			}
			continue
		}
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
	// 修复 Set-Cookie 头的 Domain 属性
	utils.FixSetCookieHeaders(&header, host)
	utils.HeaderModify(&header)
	r.Response.Status = resp.StatusCode

	// 只对文本内容进行替换
	if shouldReplace {
		content := utils.Replace(ctx, string(bodyBytes), scheme, host)
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

	// 忽略用户头像图片请求（这些请求经常返回 403）
	if (strings.Contains(domain, "googleusercontent.com") || strings.Contains(domain, "lh3.google.com")) &&
		strings.Contains(path, "/gg/") {
		return true
	}

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
