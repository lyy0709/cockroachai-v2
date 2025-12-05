(function() {
    var proxyHost = "PROXY_SCHEME://PROXY_HOST";
    var targetDomains = TARGET_DOMAINS_MAP;

    // 检查是否应该忽略该请求（Google Analytics, Ads 等）
    function shouldIgnoreRequest(url) {
        if (!url || typeof url !== 'string') return false;

        var lowerUrl = url.toLowerCase();
        // 忽略 Google Analytics
        if (lowerUrl.includes('google-analytics.com') ||
            lowerUrl.includes('analytics.google.com')) {
            return true;
        }
        // 忽略 Google Ads
        if (lowerUrl.includes('doubleclick.net') ||
            lowerUrl.includes('googleadservices.com') ||
            lowerUrl.includes('googlesyndication.com')) {
            return true;
        }
        return false;
    }

    // 重写 URL 的辅助函数
    function rewriteUrl(url) {
        if (!url || typeof url !== 'string') return url;

        // 检查是否应该忽略该请求
        if (shouldIgnoreRequest(url)) {
            console.log('[Proxy] Ignore tracking request:', url);
            return null; // 返回 null 表示应该忽略
        }

        // 处理相对路径（以 / 开头但不是 // 开头的）
        if (url.startsWith('/') && !url.startsWith('//')) {
            // 相对路径直接保持不变，让代理服务器处理
            // 因为代理服务器会根据路径映射表确定目标域名
            console.log('[Proxy] Relative path (keep):', url);
            return url;
        }

        // 处理完整URL或协议相对URL
        try {
            var urlObj = new URL(url, window.location.href);
            // 如果是目标域名，重写为代理路径
            if (targetDomains[urlObj.hostname]) {
                var rewritten = proxyHost + urlObj.pathname + urlObj.search + urlObj.hash;
                console.log('[Proxy] Rewrite:', url, '->', rewritten);
                return rewritten;
            }
            // 如果是代理域名本身，保持不变
            if (urlObj.hostname === window.location.hostname) {
                return url;
            }
        } catch (e) {
            console.warn('[Proxy] Failed to parse URL:', url, e);
        }
        return url;
    }

    // 拦截 fetch
    var originalFetch = window.fetch;
    window.fetch = function(input, init) {
        var url = typeof input === 'string' ? input : (input.url || input);
        var isBatchExecute = url && url.includes && url.includes('batchexecute');
        var isStreamGenerate = url && url.includes && url.includes('StreamGenerate');

        if (typeof input === 'string') {
            var rewrittenUrl = rewriteUrl(input);
            // 如果返回 null，表示应该忽略该请求，返回一个空的成功响应
            if (rewrittenUrl === null) {
                return Promise.resolve(new Response('', { status: 200, statusText: 'OK' }));
            }
            if (rewrittenUrl !== input) {
                console.log('[Proxy] Fetch rewrite:', input, '->', rewrittenUrl);
            }
            input = rewrittenUrl;
        } else if (input instanceof Request) {
            var rewrittenUrl = rewriteUrl(input.url);
            // 如果返回 null，表示应该忽略该请求
            if (rewrittenUrl === null) {
                return Promise.resolve(new Response('', { status: 200, statusText: 'OK' }));
            }
            if (rewrittenUrl !== input.url) {
                console.log('[Proxy] Fetch Request rewrite:', input.url, '->', rewrittenUrl);
                input = new Request(rewrittenUrl, input);
            }
        }

        // 确保关键请求包含 X-Same-Domain 头（Google 的 CSRF 保护）
        if (isBatchExecute || isStreamGenerate) {
            init = init || {};
            init.headers = init.headers || {};

            // 如果 headers 是 Headers 对象，转换为普通对象
            if (init.headers instanceof Headers) {
                var headersObj = {};
                init.headers.forEach(function(value, key) {
                    headersObj[key] = value;
                });
                init.headers = headersObj;
            }

            // 添加 X-Same-Domain 头（如果还没有）
            if (!init.headers['X-Same-Domain'] && !init.headers['x-same-domain']) {
                init.headers['X-Same-Domain'] = '1';
                console.log('[Proxy] Added X-Same-Domain header to', isStreamGenerate ? 'StreamGenerate' : 'batchexecute', 'request');
            }
        }

        // 如果是 batchexecute 或 StreamGenerate 请求，记录请求和响应
        if (isBatchExecute || isStreamGenerate) {
            var finalUrl = typeof input === 'string' ? input : (input.url || url);
            var requestType = isStreamGenerate ? 'StreamGenerate' : 'batchexecute';
            console.log('[Proxy] 📤 Sending ' + requestType + ' request:', finalUrl);
            return originalFetch.call(this, input, init).then(function(response) {
                console.log('[Proxy] 📥 Received ' + requestType + ' response:', finalUrl, 'Status:', response.status);

                // 克隆响应以便读取内容
                var clonedResponse = response.clone();
                clonedResponse.text().then(function(text) {
                    console.log('[Proxy] ' + requestType + ' response preview:', text.substring(0, 200));
                }).catch(function(err) {
                    console.error('[Proxy] Failed to read ' + requestType + ' response:', err);
                });

                return response;
            }).catch(function(error) {
                console.error('[Proxy] ❌ ' + requestType + ' request failed:', finalUrl, error);
                throw error;
            });
        }

        return originalFetch.call(this, input, init);
    };

    // 拦截 XMLHttpRequest
    var originalXHROpen = XMLHttpRequest.prototype.open;
    var originalXHRSend = XMLHttpRequest.prototype.send;
    var originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
        var rewrittenUrl = rewriteUrl(url);
        // 如果返回 null，标记为应该忽略的请求
        if (rewrittenUrl === null) {
            this._shouldIgnore = true;
            // 使用一个虚拟 URL，避免实际发送请求
            rewrittenUrl = 'data:text/plain,';
        } else {
            this._shouldIgnore = false;
            if (rewrittenUrl !== url) {
                console.log('[Proxy] XHR rewrite:', url, '->', rewrittenUrl);
            }
        }

        // 保存 URL 信息用于后续判断
        this._url = url;
        this._rewrittenUrl = rewrittenUrl;
        this._headers = {};

        return originalXHROpen.call(this, method, rewrittenUrl, async, user, password);
    };

    XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
        // 记录设置的头
        if (this._headers) {
            this._headers[header] = value;
        }
        return originalXHRSetRequestHeader.call(this, header, value);
    };

    XMLHttpRequest.prototype.send = function(body) {
        // 如果是应该忽略的请求，不发送
        if (this._shouldIgnore) {
            // 模拟成功响应
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

        // 如果是 batchexecute 或 StreamGenerate 请求，确保有 X-Same-Domain 头
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
                console.log('[Proxy] Added X-Same-Domain header to XHR', this._rewrittenUrl.includes('StreamGenerate') ? 'StreamGenerate' : 'batchexecute', 'request');
            }
        }

        return originalXHRSend.call(this, body);
    };

    // 拦截 Image src
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

    // 拦截 script src
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

    console.log('[Proxy] URL interception initialized');
})();
