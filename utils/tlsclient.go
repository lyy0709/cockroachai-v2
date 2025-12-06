package utils

import (
	"net/url"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"

	UA "github.com/EDDYCJY/fake-useragent"
	http_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// 全局变量
var (
	// TlsClient HTTP/2 客户端,用于正常请求
	TlsClient http_client.HttpClient

	// TlsClientHttp1 HTTP/1.1 客户端,用于 batchexecute 和 StreamGenerate 请求
	TlsClientHttp1 http_client.HttpClient

	DEFAULT_HEADERS = map[string]string{
		"Origin":     "https://gemini.google.com",
		"Host":       "gemini.google.com",
		"User-Agent": UA.Safari(),
	}
)

func init() {
	ctx := gctx.GetInitCtx()
	var err error

	jar := http_client.NewCookieJar()
	// ========== HTTP/2 客户端 (用于正常请求) ==========
	http2Options := []http_client.HttpClientOption{
		http_client.WithTimeoutSeconds(60),
		http_client.WithClientProfile(profiles.Safari_IOS_18_0),
		http_client.WithRandomTLSExtensionOrder(),
		http_client.WithInsecureSkipVerify(),
		// 保存 jar
		http_client.WithCookieJar(jar),
	}

	// 如果配置中有代理URL，则添加代理设置
	proxyURL := g.Cfg().MustGetWithEnv(ctx, "PROXY_URL").String()
	if proxyURL != "" {
		parsed, parseErr := url.Parse(proxyURL)
		if parseErr == nil {
			http2Options = append(http2Options, http_client.WithProxyUrl(parsed.String()))
			g.Log().Info(ctx, "HTTP/2 客户端使用代理", proxyURL)
		} else {
			g.Log().Error(ctx, "解析代理URL失败", parseErr)
		}
	}

	TlsClient, err = http_client.NewHttpClient(http_client.NewNoopLogger(), http2Options...)
	if err != nil {
		g.Log().Error(ctx, "创建 HTTP/2 TLS客户端失败", err)
	}
	g.Log().Info(ctx, "HTTP/2 TLS客户端初始化完成")

	// ========== HTTP/1.1 客户端 (用于 batchexecute/StreamGenerate) ==========
	http1Options := []http_client.HttpClientOption{
		http_client.WithTimeoutSeconds(120), // 更长的超时时间
		http_client.WithClientProfile(profiles.Safari_IOS_18_0),
		http_client.WithRandomTLSExtensionOrder(),
		http_client.WithInsecureSkipVerify(),
		http_client.WithForceHttp1(), // 强制 HTTP/1.1
	}

	// 如果配置中有代理URL，则添加代理设置
	if proxyURL != "" {
		parsed, parseErr := url.Parse(proxyURL)
		if parseErr == nil {
			http1Options = append(http1Options, http_client.WithProxyUrl(parsed.String()))
			g.Log().Info(ctx, "HTTP/1.1 客户端使用代理", proxyURL)
		}
	}

	TlsClientHttp1, err = http_client.NewHttpClient(http_client.NewNoopLogger(), http1Options...)
	if err != nil {
		g.Log().Error(ctx, "创建 HTTP/1.1 TLS客户端失败", err)
	}
	g.Log().Info(ctx, "HTTP/1.1 TLS客户端初始化完成")
}

// GetClientForPath 根据请求路径选择合适的客户端
func GetClientForPath(path string) http_client.HttpClient {
	// batchexecute 和 StreamGenerate 使用 HTTP/1.1 客户端
	if strings.Contains(path, "batchexecute") || strings.Contains(path, "StreamGenerate") {
		return TlsClientHttp1
	}
	// 其他请求使用 HTTP/2 客户端
	return TlsClient
}
