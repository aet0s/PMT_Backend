// server/src/scripts/permcheck/browserClient.js
// Emulates a browser client with strict cookie jar, Origin headers, and CSRF compliance.

class BrowserClient {
  constructor({ apiBaseUrl, frontendUrl, userAgent = 'Permcheck-E2E-Runner/1.0', xForwardedFor = null }) {
    this.apiBaseUrl = apiBaseUrl.replace(/\/+$/, '');
    this.frontendUrl = frontendUrl.replace(/\/+$/, '');
    this.cookies = new Map();
    this.token = null;
    this.userAgent = userAgent;
    const isLocal = this.apiBaseUrl.includes('localhost') || this.apiBaseUrl.includes('127.0.0.1') || this.frontendUrl.includes('localhost') || this.frontendUrl.includes('127.0.0.1');
    this.xForwardedFor = xForwardedFor || (isLocal ? `192.168.${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 250) + 1}` : null);
  }

  setCookie(name, value) {
    this.cookies.set(name, value);
    if (name === 'token') {
      this.token = value;
    }
  }

  getCookie(name) {
    return this.cookies.get(name);
  }

  getCookieString() {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  parseSetCookie(setCookieHeaders) {
    if (!setCookieHeaders) return;
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const header of headers) {
      const parts = header.split(';')[0].split('=');
      if (parts.length >= 2) {
        const name = parts[0].trim();
        const value = parts.slice(1).join('=').trim();
        this.setCookie(name, value);
      }
    }
  }

  async request(path, options = {}) {
    const url = path.startsWith('http') ? path : `${this.apiBaseUrl}${path.startsWith('/') ? path : '/' + path}`;
    const method = options.method || 'GET';
    const headers = {
      'Origin': this.frontendUrl,
      'Referer': `${this.frontendUrl}/`,
      'User-Agent': this.userAgent,
      'Accept': 'application/json, text/plain, */*',
      ...options.headers
    };

    if (this.xForwardedFor) {
      headers['X-Forwarded-For'] = this.xForwardedFor;
    }

    const cookieStr = this.getCookieString();
    if (cookieStr) {
      headers['Cookie'] = cookieStr;
    }

    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    let body = options.body;
    if (body && typeof body === 'object' && !(body instanceof Buffer) && !(body instanceof FormData)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }

    const startTime = performance.now();
    let res;
    let error = null;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: ['GET', 'HEAD'].includes(method) ? undefined : body,
        redirect: 'manual'
      });
    } catch (err) {
      error = err;
    }
    const durationMs = Math.round(performance.now() - startTime);

    if (error) {
      return {
        ok: false,
        status: 0,
        headers: {},
        data: null,
        error: error.message,
        durationMs,
        evidence: {
          method,
          url,
          status: 0,
          durationMs,
          error: error.message
        }
      };
    }

    // Extract set-cookie
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : res.headers.get('set-cookie');
    this.parseSetCookie(setCookie);

    const contentType = res.headers.get('content-type') || '';
    let data = null;
    const rawText = await res.text();
    if (contentType.includes('application/json')) {
      try {
        data = JSON.parse(rawText);
      } catch (e) {
        data = rawText;
      }
    } else {
      data = rawText;
    }

    const sanitizedBody = typeof body === 'string' ? body : JSON.stringify(body || null);
    // Sanitize any password or tokens from evidence
    const cleanReqBody = sanitizedBody
      ? sanitizedBody.replace(/"(password|token|refreshToken)":\s*"[^"]+"/g, '"$1":"[REDACTED]"')
      : null;

    const evidence = {
      method,
      url,
      status: res.status,
      durationMs,
      reqBody: cleanReqBody,
      resBody: typeof data === 'object' ? data : (rawText.length > 500 ? rawText.slice(0, 500) + '...' : rawText),
      requestId: res.headers.get('x-request-id') || null
    };

    return {
      ok: res.ok,
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      data,
      durationMs,
      evidence
    };
  }

  get(path, options = {}) {
    return this.request(path, { ...options, method: 'GET' });
  }

  post(path, body, options = {}) {
    return this.request(path, { ...options, method: 'POST', body });
  }

  patch(path, body, options = {}) {
    return this.request(path, { ...options, method: 'PATCH', body });
  }

  put(path, body, options = {}) {
    return this.request(path, { ...options, method: 'PUT', body });
  }

  delete(path, body = null, options = {}) {
    return this.request(path, { ...options, method: 'DELETE', body });
  }

  options(path, reqMethod, reqHeaders = 'Content-Type,Authorization') {
    return this.request(path, {
      method: 'OPTIONS',
      headers: {
        'Origin': this.frontendUrl,
        'Access-Control-Request-Method': reqMethod,
        'Access-Control-Request-Headers': reqHeaders
      }
    });
  }
}

module.exports = { BrowserClient };
