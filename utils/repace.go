package utils

import (
	"regexp"
	"strings"

	"github.com/gogf/gf/v2/os/gctx"
)

// Replace 替换内容中的所有目标域名为代理域名
// 新方案：https://original-domain.com/path -> https://proxy-host/original-domain.com/path
// 同时处理相对路径：/path -> /original-domain.com/path
func Replace(ctx gctx.Ctx, content string, scheme string, host string, originalDomain string) string {
	result := content

	// 首先移除 HTML 中的内嵌 CSP meta 标签
	result = RemoveInlineCSP(result)

	// 检测是否是 HTML 内容，记录下来，但不在这里注入脚本
	// 注入脚本需要在 URL 替换之后进行，否则脚本内容也会被替换
	isHTML := strings.Contains(result, "<html") || strings.Contains(result, "<head") || strings.Contains(result, "<!DOCTYPE")

	// 按顺序处理每个域名（长的在前，避免误匹配）
	for _, domain := range DOMAIN_LIST {
		// 转义域名中的特殊字符（主要是点号和连字符）
		escapedDomain := regexp.QuoteMeta(domain)

		// 1. 匹配带协议的完整URL：https?://domain[/path][?query]
		// 使用更精确的正则，分别捕获路径和查询参数
		// 注意：路径部分可能以多个 / 开头（如 //path），需要处理
		pattern1 := regexp.MustCompile(`(https?://)` + escapedDomain + `(/*[^\s"'<>?]*)?(\\?[^\s"'<>]*)?`)
		result = pattern1.ReplaceAllStringFunc(result, func(match string) string {
			// 检查是否已经被替换过
			if strings.Contains(match, host) {
				return match
			}

			// 提取路径部分（包括查询字符串）
			pathPart := strings.TrimPrefix(match, "https://"+domain)
			pathPart = strings.TrimPrefix(pathPart, "http://"+domain)

			// 移除所有开头的斜杠，然后统一添加一个
			pathPart = strings.TrimLeft(pathPart, "/")
			// 如果为空或以 ? 开头，添加 /
			if pathPart == "" {
				pathPart = "/"
			} else if strings.HasPrefix(pathPart, "?") {
				pathPart = "/" + pathPart
			} else {
				pathPart = "/" + pathPart
			}

			// 关键修改：在路径前添加域名
			return scheme + "://" + host + "/" + domain + pathPart
		})

		// 2. 匹配协议相对URL：//domain/path（常见于HTML/JS中）
		// 注意：路径部分可能以多个 / 开头，需要处理
		pattern1b := regexp.MustCompile(`(//)` + escapedDomain + `(/*[^\s"'<>?]*)?(\\?[^\s"'<>]*)?`)
		result = pattern1b.ReplaceAllStringFunc(result, func(match string) string {
			// 检查是否已经被替换过
			if strings.Contains(match, host) {
				return match
			}
			// 提取路径部分
			pathPart := strings.TrimPrefix(match, "//"+domain)

			// 移除所有开头的斜杠，然后统一添加一个
			pathPart = strings.TrimLeft(pathPart, "/")
			if pathPart == "" {
				pathPart = "/"
			} else if strings.HasPrefix(pathPart, "?") {
				pathPart = "/" + pathPart
			} else {
				pathPart = "/" + pathPart
			}

			// 关键修改：在路径前添加域名
			return "//" + host + "/" + domain + pathPart
		})

		// 3. 匹配不带协议的相对URL（如在JS或CSS中）
		// 注意：这种情况下域名可能是作为字符串变量使用，后续会拼接路径
		// 例如：lg(3) + "/gtag/js"，其中 lg(3) 返回域名
		// 所以当路径为空时，不应该添加 /，否则会导致双斜杠
		pattern2 := regexp.MustCompile(`(["\s=:])` + escapedDomain + `(/*[^\s"'<>?]*)?(\\?[^\s"'<>]*)?`)
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

			// 移除所有开头的斜杠
			pathPart = strings.TrimLeft(pathPart, "/")

			// 如果路径不为空，添加一个开头的 /
			// 如果路径为空，保持为空（不添加 /），因为后续 JS 可能会拼接以 / 开头的路径
			if pathPart != "" {
				if strings.HasPrefix(pathPart, "?") {
					pathPart = "/?" + strings.TrimPrefix(pathPart, "?")
				} else {
					pathPart = "/" + pathPart
				}
			}

			// 关键修改：在路径前添加域名
			return prefix + host + "/" + domain + pathPart
		})
	}

	// 注意：不在服务端替换相对路径（如 /path），因为：
	// 1. 服务端不知道相对路径的正确目标域名（如 /punctual 实际指向 signaler-pa.clients6.google.com）
	// 2. 让 JavaScript 拦截器配合路径映射表来处理所有相对路径

	// 在 URL 替换完成后，再注入代理脚本（这样脚本内容不会被替换）
	if isHTML {
		result = InjectProxyScript(result, scheme, host, originalDomain)
	}

	return result
}

// RemoveInlineCSP 移除 HTML 中的内嵌 CSP meta 标签
func RemoveInlineCSP(content string) string {
	// 移除 <meta http-equiv="Content-Security-Policy" ...>
	cspMetaPattern := regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*>`)
	content = cspMetaPattern.ReplaceAllString(content, "")

	// 移除 <meta http-equiv="Content-Security-Policy-Report-Only" ...>
	cspReportMetaPattern := regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*["']?Content-Security-Policy-Report-Only["']?[^>]*>`)
	content = cspReportMetaPattern.ReplaceAllString(content, "")

	return content
}

// InjectProxyScript 注入 JavaScript 代码来拦截动态生成的 URL
func InjectProxyScript(content string, scheme string, host string, originalDomain string) string {
	// 构建域名映射 JavaScript 对象
	var domainMapParts []string
	for _, domain := range DOMAIN_LIST {
		domainMapParts = append(domainMapParts, `"`+domain+`": true`)
	}
	domainMapJS := "{" + strings.Join(domainMapParts, ", ") + "}"

	// 构建路径到域名的映射 JavaScript 对象
	var pathMapParts []string
	for path, domain := range URL_PATH_DOMAIN_MAP {
		pathMapParts = append(pathMapParts, `"`+path+`": "`+domain+`"`)
	}
	pathMapJS := "{" + strings.Join(pathMapParts, ", ") + "}"

	// 清洁版脚本（临时添加调试日志）
	cleanScript := `
(function() {
    var proxyHost = "PROXY_SCHEME://PROXY_HOST";
    var currentDomain = "CURRENT_DOMAIN";
    var targetDomains = TARGET_DOMAINS_MAP;
    var pathToDomainMap = PATH_TO_DOMAIN_MAP;
    console.log('[Proxy] Interceptor loaded. Proxy:', proxyHost, 'Current domain:', currentDomain, 'Domains:', Object.keys(targetDomains).length, 'Path mappings:', Object.keys(pathToDomainMap).length);

    function shouldIgnoreRequest(url) {
        if (!url || typeof url !== 'string') return false;
        var lowerUrl = url.toLowerCase();
        if (lowerUrl.includes('google-analytics.com') ||
            lowerUrl.includes('analytics.google.com')) {
            return true;
        }
        if (lowerUrl.includes('doubleclick.net') ||
            lowerUrl.includes('googleadservices.com') ||
            lowerUrl.includes('googlesyndication.com')) {
            return true;
        }
        return false;
    }

    function rewriteUrl(url) {
        if (!url || typeof url !== 'string') return url;
        if (shouldIgnoreRequest(url)) {
            return null;
        }
        // 处理相对路径：/path -> /targetDomain/path
        if (url.startsWith('/') && !url.startsWith('//')) {
            // 检查是否已经是新格式（/domain.com/path）
            var pathWithoutSlash = url.substring(1);
            var isAlreadyNewFormat = false;
            for (var domain in targetDomains) {
                if (pathWithoutSlash.startsWith(domain + '/') || pathWithoutSlash === domain) {
                    isAlreadyNewFormat = true;
                    break;
                }
            }
            if (isAlreadyNewFormat) {
                return url;
            }

            // 使用路径映射表查找目标域名（最长前缀匹配）
            var targetDomain = null;
            var longestMatch = '';
            for (var pathPrefix in pathToDomainMap) {
                if (url.startsWith(pathPrefix) && pathPrefix.length > longestMatch.length) {
                    longestMatch = pathPrefix;
                    targetDomain = pathToDomainMap[pathPrefix];
                }
            }

            // 如果找到匹配，使用映射的域名；否则使用当前域名
            if (!targetDomain) {
                targetDomain = currentDomain;
            }

            if (targetDomain) {
                var rewritten = '/' + targetDomain + url;
                console.log('[Proxy] Relative path rewrite:', url, '->', rewritten, '(target:', targetDomain + ')');
                return rewritten;
            }
            return url;
        }
        try {
            var urlObj = new URL(url, window.location.href);
            if (targetDomains[urlObj.hostname]) {
                // 关键修改：在路径前添加域名
                var rewritten = proxyHost + '/' + urlObj.hostname + urlObj.pathname + urlObj.search + urlObj.hash;
                console.log('[Proxy] URL rewrite:', urlObj.hostname, url, '->', rewritten);
                return rewritten;
            }
            if (urlObj.hostname === window.location.hostname) {
                return url;
            }
        } catch (e) {
            console.error('[Proxy] URL parse error:', e, url);
        }
        return url;
    }

    // 从 fetch 参数中提取 URL，支持 string / URL / Request
    function extractUrlFromFetchInput(input) {
        if (typeof input === 'string') {
            return input;
        }
        if (input instanceof URL) {
            return input.href;
        }
        if (input instanceof Request && input.url) {
            return input.url;
        }
        return null;
    }

    // 拦截 Response 对象，替换响应体中的 URL
    function wrapResponse(response, url) {
        var isBatchExecute = url && url.includes && url.includes('batchexecute');
        var isStreamGenerate = url && url.includes && url.includes('StreamGenerate');

        // 仅在 batchexecute 或 StreamGenerate 时处理
        if (!isBatchExecute && !isStreamGenerate) {
            return response;
        }

        console.log('[Proxy] Wrapping response for URL:', url);

        // 替换文本中的 URL
        function replaceUrlsInText(text) {
            var modified = text;
            var count = 0;

            Object.keys(targetDomains).forEach(function(domain) {
                // 匹配 https://domain/path 或 http://domain/path，包括转义的版本
                var escapedDomain = domain.replace(/\./g, '\\.');
                // 匹配正常的 URL (包括路径)
                var regex1 = new RegExp('(https?://)' + escapedDomain + '(/[^\\s"\'<>]*)?', 'g');
                // 匹配 JSON 转义的 URL (\u003d, \u0026 等)
                var regex2 = new RegExp('(https?:\\\\/\\\\/)' + escapedDomain + '(\\\\/[^\\s"\'<>]*)?', 'g');
                // 匹配协议相对的 //domain/path
                var regex3 = new RegExp('(//)' + escapedDomain + '(/[^\\s"\'<>]*)?', 'g');
                // 匹配转义的协议相对 URL
                var regex4 = new RegExp('(\\\\/\\\\/)' + escapedDomain + '(\\\\/[^\\s"\'<>]*)?', 'g');

                var beforeCount = (modified.match(regex1) || []).length +
                    (modified.match(regex2) || []).length +
                    (modified.match(regex3) || []).length +
                    (modified.match(regex4) || []).length;

                // 关键修改：保留域名和路径
                modified = modified.replace(regex1, function(match, protocol, path) {
                    var finalPath = path || '/';
                    var finalDomain = domain;

                    // 特殊处理：lh3.googleusercontent.com 的 /gg/ 路径
                    // 保持 /gg/ 原路径，不做额外重写，避免签名失效

                    return proxyHost + '/' + finalDomain + finalPath;
                });
                modified = modified.replace(regex2, function(match, protocol, path) {
                    var finalPath = path ? path.replace(/\\\\/g, '/') : '/';
                    var finalDomain = domain;

                    // 特殊处理：lh3.googleusercontent.com 的 /gg/ 路径
                    // 保持 /gg/ 原路径，不做额外重写，避免签名失效

                    var escapedProxyHost = proxyHost.replace(/:/g, '\\u003a').replace(/\//g, '\\/');
                    var escapedPath = finalPath.replace(/\//g, '\\/');
                    return escapedProxyHost + '\\/' + finalDomain.replace(/\./g, '\\.') + escapedPath;
                });
                modified = modified.replace(regex3, function(match, protocol, path) {
                    var finalPath = path || '/';
                    return '//' + host + '/' + domain + finalPath;
                });
                modified = modified.replace(regex4, function(match, protocol, path) {
                    var finalPath = path ? path.replace(/\\\\/g, '/') : '/';
                    var escapedPath = finalPath.replace(/\//g, '\\/');
                    return '\\/\\/' + host.replace(/\./g, '\\.') + '\\/' + domain.replace(/\./g, '\\.') + escapedPath;
                });

                var afterCount = (modified.match(new RegExp(proxyHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length +
                    (modified.match(new RegExp('\/\/' + host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\/' + escapedDomain, 'g')) || []).length;
                count += (afterCount - beforeCount);
            });
            if (count > 0) {
                console.log('[Proxy] Replaced', count, 'URLs in batchexecute response');
            }
            return modified;
        }

        // 先读取响应体
        var originalClone = response.clone();
        return originalClone.text().then(function(originalText) {
            var modifiedText = replaceUrlsInText(originalText);

            // 创建新的 Response 对象，使用修改后的文本
            var newResponse = new Response(modifiedText, {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers
            });

            console.log('[Proxy] Created new Response with modified body');
            return newResponse;
        }).catch(function(err) {
            console.error('[Proxy] Failed to wrap response:', err);
            return response;
        });
    }

    var originalFetch = window.fetch;
    window.fetch = function(input, init) {
        var url = extractUrlFromFetchInput(input);
        var isBatchExecute = url && url.includes && url.includes('batchexecute');
        var isStreamGenerate = url && url.includes && url.includes('StreamGenerate');

        if (url) {
            var rewrittenUrl = rewriteUrl(url);
            if (rewrittenUrl === null) {
                return Promise.resolve(new Response('', { status: 200, statusText: 'OK' }));
            }
            if (rewrittenUrl !== url) {
                console.log('[Proxy] fetch rewrite:', url, '->', rewrittenUrl);
                if (typeof input === 'string' || input instanceof URL) {
                    input = rewrittenUrl;
                } else if (input instanceof Request) {
                    input = new Request(rewrittenUrl, input);
                }
            }
        }

        if (isBatchExecute || isStreamGenerate) {
            init = init || {};
            init.headers = init.headers || {};

            if (init.headers instanceof Headers) {
                var headersObj = {};
                init.headers.forEach(function(value, key) {
                    headersObj[key] = value;
                });
                init.headers = headersObj;
            }

            if (!init.headers['X-Same-Domain'] && !init.headers['x-same-domain']) {
                init.headers['X-Same-Domain'] = '1';
            }
        }

        // 拦截响应
        return originalFetch.call(this, input, init).then(function(response) {
            return wrapResponse(response, url);
        });
    };

    var originalXHROpen = XMLHttpRequest.prototype.open;
    var originalXHRSend = XMLHttpRequest.prototype.send;
    var originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

    // 替换响应文本中的 URL
    function replaceUrlsInXHRResponse(text) {
        if (!text || typeof text !== 'string') return text;

        var modified = text;
        var count = 0;
        Object.keys(targetDomains).forEach(function(domain) {
            var escapedDomain = domain.replace(/\./g, '\\.');
            // 匹配正常的 URL (包括路径)
            var regex1 = new RegExp('(https?://)' + escapedDomain + '(/[^\\s"\'<>]*)?', 'g');
            // 匹配 JSON 转义的 URL
            var regex2 = new RegExp('(https?:\\\\/\\\\/)' + escapedDomain + '(\\\\/[^\\s"\'<>]*)?', 'g');
            // 匹配协议相对 URL
            var regex3 = new RegExp('(//)' + escapedDomain + '(/[^\\s"\'<>]*)?', 'g');
            // 匹配转义的协议相对 URL
            var regex4 = new RegExp('(\\\\/\\\\/)' + escapedDomain + '(\\\\/[^\\s"\'<>]*)?', 'g');

            var matches = (modified.match(regex1) || []).length +
                (modified.match(regex2) || []).length +
                (modified.match(regex3) || []).length +
                (modified.match(regex4) || []).length;
            if (matches > 0) {
                // 关键修改：保留域名和路径
                modified = modified.replace(regex1, function(match, protocol, path) {
                    var finalPath = path || '/';
                    return proxyHost + '/' + domain + finalPath;
                });
                modified = modified.replace(regex2, function(match, protocol, path) {
                    var finalPath = path ? path.replace(/\\\\/g, '/') : '/';
                    var escapedProxyHost = proxyHost.replace(/:/g, '\\u003a').replace(/\//g, '\\/');
                    var escapedPath = finalPath.replace(/\//g, '\\/');
                    return escapedProxyHost + '\\/' + domain.replace(/\./g, '\\.') + escapedPath;
                });
                modified = modified.replace(regex3, function(match, protocol, path) {
                    var finalPath = path || '/';
                    return '//' + host + '/' + domain + finalPath;
                });
                modified = modified.replace(regex4, function(match, protocol, path) {
                    var finalPath = path ? path.replace(/\\\\/g, '/') : '/';
                    var escapedPath = finalPath.replace(/\//g, '\\/');
                    return '\\/\\/' + host.replace(/\./g, '\\.') + '\\/' + domain.replace(/\./g, '\\.') + escapedPath;
                });
                count += matches;
            }
        });

        if (count > 0) {
            console.log('[Proxy] XHR response rewritten:', count, 'URLs replaced');
        }
        return modified;
    }

    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
        var rewrittenUrl = rewriteUrl(url);
        if (rewrittenUrl === null) {
            this._shouldIgnore = true;
            rewrittenUrl = 'data:text/plain,';
        } else {
            this._shouldIgnore = false;
        }

        this._url = url;
        this._rewrittenUrl = rewrittenUrl;
        this._headers = {};
        this._isBatchExecute = url && url.includes && url.includes('batchexecute');

        if (this._isBatchExecute) {
            console.log('[Proxy] XHR batchexecute detected:', url);
        }

        return originalXHROpen.call(this, method, rewrittenUrl, async, user, password);
    };

    XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
        if (this._headers) {
            this._headers[header] = value;
        }
        return originalXHRSetRequestHeader.call(this, header, value);
    };

    XMLHttpRequest.prototype.send = function(body) {
        if (this._shouldIgnore) {
            var self = this;
            setTimeout(function() {
                Object.defineProperty(self, 'status', { value: 200, writable: false });
                Object.defineProperty(self, 'statusText', { value: 'OK', writable: false });
                Object.defineProperty(self, 'responseText', { value: '', writable: false });
                Object.defineProperty(self, 'readyState', { value: 4, writable: false });
                if (self.onreadystatechange) self.onreadystatechange();
                if (self.onload) self.onload();
            }, 0);
            return;
        }

        if (this._rewrittenUrl && (this._rewrittenUrl.includes('batchexecute') || this._rewrittenUrl.includes('StreamGenerate'))) {
            var hasXSameDomain = false;
            if (this._headers) {
                for (var key in this._headers) {
                    if (key.toLowerCase() === 'x-same-domain') {
                        hasXSameDomain = true;
                        break;
                    }
                }
            }
            if (!hasXSameDomain) {
                originalXHRSetRequestHeader.call(this, 'X-Same-Domain', '1');
            }
        }

        // 拦截 batchexecute 响应
        if (this._isBatchExecute) {
            var self = this;
            var originalOnReadyStateChange = this.onreadystatechange;

            this.onreadystatechange = function() {
                if (self.readyState === 4 && self.status === 200) {
                    try {
                        // 获取原始 responseText 的 getter
                        var originalResponseTextGetter = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, 'responseText').get;
                        var originalResponseText = originalResponseTextGetter.call(self);

                        if (originalResponseText) {
                            var modifiedResponseText = replaceUrlsInXHRResponse(originalResponseText);

                            // 替换 responseText
                            Object.defineProperty(self, 'responseText', {
                                value: modifiedResponseText,
                                writable: false,
                                configurable: true
                            });

                            // 替换 response
                            Object.defineProperty(self, 'response', {
                                value: modifiedResponseText,
                                writable: false,
                                configurable: true
                            });

                            console.log('[Proxy] XHR batchexecute response intercepted and modified');
                        }
                    } catch (e) {
                        console.error('[Proxy] Failed to modify XHR response:', e);
                    }
                }

                if (originalOnReadyStateChange) {
                    return originalOnReadyStateChange.apply(this, arguments);
                }
            };
        }

        return originalXHRSend.call(this, body);
    };

    var originalImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    if (originalImageSrc) {
        Object.defineProperty(HTMLImageElement.prototype, 'src', {
            set: function(value) {
                originalImageSrc.set.call(this, rewriteUrl(value));
            },
            get: function() {
                return originalImageSrc.get.call(this);
            }
        });
    }

    var originalScriptSrc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (originalScriptSrc) {
        Object.defineProperty(HTMLScriptElement.prototype, 'src', {
            set: function(value) {
                originalScriptSrc.set.call(this, rewriteUrl(value));
            },
            get: function() {
                return originalScriptSrc.get.call(this);
            }
        });
    }

    var originalVideoSrc = Object.getOwnPropertyDescriptor(HTMLVideoElement.prototype, 'src');
    if (originalVideoSrc) {
        Object.defineProperty(HTMLVideoElement.prototype, 'src', {
            set: function(value) {
                originalVideoSrc.set.call(this, rewriteUrl(value));
            },
            get: function() {
                return originalVideoSrc.get.call(this);
            }
        });
    }

    var originalAudioSrc = Object.getOwnPropertyDescriptor(HTMLAudioElement.prototype, 'src');
    if (originalAudioSrc) {
        Object.defineProperty(HTMLAudioElement.prototype, 'src', {
            set: function(value) {
                originalAudioSrc.set.call(this, rewriteUrl(value));
            },
            get: function() {
                return originalAudioSrc.get.call(this);
            }
        });
    }

    var originalSourceSrc = Object.getOwnPropertyDescriptor(HTMLSourceElement.prototype, 'src');
    if (originalSourceSrc) {
        Object.defineProperty(HTMLSourceElement.prototype, 'src', {
            set: function(value) {
                originalSourceSrc.set.call(this, rewriteUrl(value));
            },
            get: function() {
                return originalSourceSrc.get.call(this);
            }
        });
    }

    var originalIFrameSrc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (originalIFrameSrc) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
            set: function(value) {
                originalIFrameSrc.set.call(this, rewriteUrl(value));
            },
            get: function() {
                return originalIFrameSrc.get.call(this);
            }
        });
    }

    // 拦截 setAttribute 方法
    var originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (name && name.toLowerCase() === 'src' && typeof value === 'string') {
            var tagName = this.tagName ? this.tagName.toLowerCase() : '';
            if (tagName === 'img' || tagName === 'script' || tagName === 'video' ||
                tagName === 'audio' || tagName === 'source' || tagName === 'iframe') {
                var rewrittenValue = rewriteUrl(value);
                if (rewrittenValue !== value) {
                    console.log('[Proxy] setAttribute rewrite:', tagName, value, '->', rewrittenValue);
                }
                return originalSetAttribute.call(this, name, rewrittenValue);
            }
        }
        return originalSetAttribute.call(this, name, value);
    };

    // 使用 MutationObserver 监听 DOM 变化
    var observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1) { // Element node
                        var tagName = node.tagName ? node.tagName.toLowerCase() : '';
                        if ((tagName === 'img' || tagName === 'script' || tagName === 'video' ||
                             tagName === 'audio' || tagName === 'source' || tagName === 'iframe') && node.src) {
                            var originalSrc = node.getAttribute('src');
                            if (originalSrc) {
                                var rewrittenSrc = rewriteUrl(originalSrc);
                                if (rewrittenSrc !== originalSrc) {
                                    console.log('[Proxy] MutationObserver rewrite:', tagName, originalSrc, '->', rewrittenSrc);
                                    node.src = rewrittenSrc;
                                }
                            }
                        }
                        // 递归处理子节点
                        if (node.querySelectorAll) {
                            var elements = node.querySelectorAll('img[src], script[src], video[src], audio[src], source[src], iframe[src]');
                            elements.forEach(function(el) {
                                var originalSrc = el.getAttribute('src');
                                if (originalSrc) {
                                    var rewrittenSrc = rewriteUrl(originalSrc);
                                    if (rewrittenSrc !== originalSrc) {
                                        console.log('[Proxy] MutationObserver (nested) rewrite:', el.tagName.toLowerCase(), originalSrc, '->', rewrittenSrc);
                                        el.src = rewrittenSrc;
                                    }
                                }
                            });
                        }
                    }
                });
            } else if (mutation.type === 'attributes' && mutation.attributeName === 'src') {
                var target = mutation.target;
                if (target && target.nodeType === 1) {
                    var tagName = target.tagName ? target.tagName.toLowerCase() : '';
                    if (tagName === 'img' || tagName === 'script' || tagName === 'video' ||
                        tagName === 'audio' || tagName === 'source' || tagName === 'iframe') {
                        var currentSrc = target.getAttribute('src');
                        if (currentSrc) {
                            var rewrittenSrc = rewriteUrl(currentSrc);
                            if (rewrittenSrc !== currentSrc && target.src !== rewrittenSrc) {
                                console.log('[Proxy] Attribute change rewrite:', tagName, currentSrc, '->', rewrittenSrc);
                                target.src = rewrittenSrc;
                            }
                        }
                    }
                }
            }
        });
    });

    // 开始观察
    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['src']
    });

    console.log('[Proxy] MutationObserver and setAttribute interceptor installed');
})();
`

	// 替换占位符
	proxyScript := strings.ReplaceAll(cleanScript, "PROXY_SCHEME://PROXY_HOST", scheme+"://"+host)
	proxyScript = strings.ReplaceAll(proxyScript, "CURRENT_DOMAIN", originalDomain)
	proxyScript = strings.ReplaceAll(proxyScript, "TARGET_DOMAINS_MAP", domainMapJS)
	proxyScript = strings.ReplaceAll(proxyScript, "PATH_TO_DOMAIN_MAP", pathMapJS)

	proxyScript = "<script>" + proxyScript + "</script>"

	// 在 <head> 标签后注入脚本（确保最早执行）
	headPattern := regexp.MustCompile(`(?i)(<head[^>]*>)`)
	if headPattern.MatchString(content) {
		content = headPattern.ReplaceAllString(content, "$1"+proxyScript)
	} else {
		// 如果没有 head 标签，在 html 标签后注入
		htmlPattern := regexp.MustCompile(`(?i)(<html[^>]*>)`)
		if htmlPattern.MatchString(content) {
			content = htmlPattern.ReplaceAllString(content, "$1"+proxyScript)
		}
	}

	return content
}
