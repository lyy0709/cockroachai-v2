package utils

import (
	"net/url"
	"reverse/config"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"

	UA "github.com/EDDYCJY/fake-useragent"
	http_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// 全局变量
var (
	TlsClient http_client.HttpClient

	DEFAULT_HEADERS = map[string]string{
		"Connection": "keep-alive",
		"Origin":     "https://gemini.google.com",
		"Host":       "gemini.google.com",
		"User-Agent": UA.Safari(),
	}
)

func init() {
	ctx := gctx.GetInitCtx()
	var err error

	// 创建客户端选项列表
	options := []http_client.HttpClientOption{
		http_client.WithTimeoutSeconds(0),
		http_client.WithClientProfile(profiles.Safari_IOS_18_0),
		http_client.WithRandomTLSExtensionOrder(), // 随机TLS扩展顺序
		http_client.WithInsecureSkipVerify(),      // 根据需要可以移除此选项
	}

	// 如果配置中有代理URL，则添加代理设置
	if config.ProxyURL != "" {
		proxyURL, parseErr := url.Parse(config.ProxyURL)
		if parseErr == nil {
			options = append(options, http_client.WithProxyUrl(proxyURL.String()))
			g.Log().Info(ctx, "使用代理", config.ProxyURL)
		} else {
			g.Log().Error(ctx, "解析代理URL失败", parseErr)
		}
	}

	// 创建一个模拟Chrome浏览器的TLS指纹客户端
	TlsClient, err = http_client.NewHttpClient(http_client.NewNoopLogger(), options...)

	if err != nil {
		g.Log().Error(ctx, "创建TLS客户端失败", err)
	}
}
