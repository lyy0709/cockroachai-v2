(function() {
    var proxyHost = "PROXY_SCHEME://PROXY_HOST";
    var targetDomains = TARGET_DOMAINS_MAP;

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
        if (url.startsWith('/') && !url.startsWith('//')) {
            return url;
        }
        try {
            var urlObj = new URL(url, window.location.href);
            if (targetDomains[urlObj.hostname]) {
                var rewritten = proxyHost + urlObj.pathname + urlObj.search + urlObj.hash;
                return rewritten;
            }
            if (urlObj.hostname === window.location.hostname) {
                return url;
            }
        } catch (e) {
        }
        return url;
    }

    var originalFetch = window.fetch;
    window.fetch = function(input, init) {
        var url = typeof input === 'string' ? input : (input.url || input);
        var isBatchExecute = url && url.includes && url.includes('batchexecute');
        var isStreamGenerate = url && url.includes && url.includes('StreamGenerate');

        if (typeof input === 'string') {
            var rewrittenUrl = rewriteUrl(input);
            if (rewrittenUrl === null) {
                return Promise.resolve(new Response('', { status: 200, statusText: 'OK' }));
            }
            input = rewrittenUrl;
        } else if (input instanceof Request) {
            var rewrittenUrl = rewriteUrl(input.url);
            if (rewrittenUrl === null) {
                return Promise.resolve(new Response('', { status: 200, statusText: 'OK' }));
            }
            if (rewrittenUrl !== input.url) {
                input = new Request(rewrittenUrl, input);
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

        return originalFetch.call(this, input, init);
    };

    var originalXHROpen = XMLHttpRequest.prototype.open;
    var originalXHRSend = XMLHttpRequest.prototype.send;
    var originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

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
})();
