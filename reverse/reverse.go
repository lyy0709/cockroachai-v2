package reverse

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"reverse/config"
	"reverse/utils"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	http "github.com/bogdanfinn/fhttp"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

func init() {
	s := g.Server()
	group := s.Group("/")

	group.GET("/app", Index)
	group.ALL("/*", Proxy)
	group.GET("/RotateCookiesPage", RotateCookiesPage)
	group.GET("/RotateCookies", RotateCookiesPage)
}

var (
	cookieRefreshMu   sync.Mutex
	lastCookieRefresh time.Time
)

func Index(r *ghttp.Request) {
	ctx := r.Context()
	scheme, host := utils.GetInfo(r)

	// 首页固定访问 gemini.google.com/app
	targetURL := config.BaseUrl + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}
	originalDomain := "gemini.google.com"

	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
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

	// 先从 Referer 中提取来源域名，用于设置 Origin
	refer := r.Referer()
	refererDomain := ""
	if refer != "" && strings.Contains(refer, host) {
		// 从Referer中提取路径
		relativePath := strings.TrimPrefix(refer, scheme+"://"+host)

		// 使用新方案：从路径中提取域名和真实路径
		// 路径格式：/gemini.google.com/app/chat
		var realPath string
		refererDomain, realPath = utils.ExtractDomainAndPathFromProxyPath(relativePath)

		// 构建原始 Referer（使用提取的真实路径）
		if refererDomain != "" {
			newReferer := "https://" + refererDomain + realPath
			req.Header.Set("Referer", newReferer)
		}
	}

	// 确定要使用的 Origin 域名
	originDomainToUse := refererDomain
	if originDomainToUse == "" {
		originDomainToUse = originalDomain
	}

	// 设置 Origin - 始终设置为与 Referer 匹配的域名
	req.Header.Set("Origin", "https://"+originDomainToUse)

	// 设置所有的默认请求头（但不覆盖已设置的）
	for key, value := range utils.DEFAULT_HEADERS {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// 设置正确的Host和Cookie
	req.Header.Set("Host", originalDomain)
	req.Header.Set("Cookie", config.GetCookie())
	req.Header.Set("Accept-Encoding", "")
	// 使用指纹客户端发送请求
	resp, err := utils.TlsClient.Do(req)
	if err != nil {
		g.Log().Error(ctx, "发送请求失败", err)
		r.Response.WriteStatus(http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	// 检查是否需要解压缩
	contentEncoding := resp.Header.Get("Content-Encoding")

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

	// 替换外部URL
	content := utils.Replace(ctx, string(bodyBytes), scheme, host, originalDomain)

	// 复制响应头
	for k, v := range resp.Header {
		if len(v) > 0 {
			// 跳过 Content-Encoding 和 Content-Length，因为内容已被修改
			if k == "Content-Encoding" || k == "Content-Length" {
				continue
			}
			r.Response.Header().Set(k, v[0])
		}
	}
	header := r.Response.Header()
	utils.HeaderModify(&header)
	r.Response.Status = resp.StatusCode
	r.Response.Write(content)
}

// RotateCookiesPage 处理 Cookie 刷新请求
func RotateCookiesPage(r *ghttp.Request) {
	ctx := r.Context()

	cookieRefreshMu.Lock()
	defer cookieRefreshMu.Unlock()

	// 若 1 小时内已刷新过，则直接返回，避免更换 Cookie 导致会话失效
	if !lastCookieRefresh.IsZero() && time.Since(lastCookieRefresh) < time.Hour {
		r.Response.WriteJsonExit("{}")
		return
	}

	// 调用 Cookie 刷新
	if err := config.RefreshCookie(); err != nil {
		g.Log().Error(ctx, "Cookie 刷新失败:", err)
		r.Response.WriteJsonExit("{}")
		return
	}

	lastCookieRefresh = time.Now()
	r.Response.Write("{}")
}
