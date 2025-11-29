package reverse

import (
	"io/ioutil"
	"reverse/config"
	"reverse/utils"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

func Proxy(r *ghttp.Request) {
	ctx := r.Context()
	scheme, host := utils.GetInfo(r)

	// 使用路径映射表确定目标域名
	originalDomain := utils.GetDomainFromPath(r.URL.Path)
	g.Log().Debug(ctx, "请求路径:", r.URL.Path, "目标域名:", originalDomain)

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
		g.Log().Info(ctx, "处理后的 targetURL:", targetURL)
	}
	// 创建新请求
	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
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
	g.Log().Debug(ctx, "原始 Referer:", refer)
	if refer != "" && strings.Contains(refer, host) {
		// 从Referer中提取路径
		relativePath := strings.TrimPrefix(refer, scheme+"://"+host)
		g.Log().Debug(ctx, "Referer 相对路径:", relativePath)

		// 通过路径映射表确定 Referer 的域名
		refererDomain = utils.GetDomainFromPath(relativePath)
		g.Log().Debug(ctx, "Referer 域名:", refererDomain)

		// 构建原始 Referer
		newReferer := "https://" + refererDomain + relativePath
		req.Header.Set("Referer", newReferer)
		g.Log().Info(ctx, "设置 Referer 为:", newReferer)
	}

	// 处理 Origin 头 - Origin 应该与 Referer 的域名匹配
	originHeader := r.Header.Get("Origin")
	g.Log().Debug(ctx, "原始 Origin 头:", originHeader, "Host:", host)

	// 确定要使用的 Origin 域名
	// 优先使用 Referer 中的域名（这样 Origin 和 Referer 会匹配）
	originDomainToUse := refererDomain
	if originDomainToUse == "" {
		// 如果没有 Referer 域名，使用目标域名
		originDomainToUse = originalDomain
	}

	// 设置 Origin - 始终设置为与 Referer 匹配的域名
	newOrigin := "https://" + originDomainToUse
	req.Header.Set("Origin", newOrigin)
	g.Log().Debug(ctx, "设置 Origin 为:", newOrigin)

	// 设置所有的默认请求头（但不覆盖已设置的）
	for key, value := range utils.DEFAULT_HEADERS {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// 设置正确的Host和Cookie
	req.Header.Set("Host", originalDomain)
	req.Header.Set("Cookie", config.Cookie)

	// 使用指纹客户端发送请求
	resp, err := utils.TlsClient.Do(req)
	if err != nil {
		g.Log().Error(ctx, "发送请求失败", err)
		r.Response.WriteStatus(http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	// 替换外部URL
	content := utils.Replace(ctx, string(bodyBytes), scheme, host)

	for k, v := range resp.Header {
		if len(v) > 0 {
			r.Response.Header().Set(k, v[0])
		}
	}
	header := r.Response.Header()
	utils.HeaderModify(&header)
	r.Response.Status = resp.StatusCode

	r.Response.Write(content)
}
