// server/src/scripts/permtest/client.js
// Native fetch client (Node 18+, no browser automation / Playwright / Puppeteer).
// Connects to the application through the frontend proxy (http://localhost:5173/api)
// or directly in production with strict Origin / Referer / CORS / Cookie jar / CSRF handling.

class PermtestClient {
  constructor({
    frontendUrl = process.env.PERMTEST_FRONTEND_URL || 'http://localhost:5173',
    apiUrl = process.env.PERMTEST_API_URL || null,
    allowProd = false,
    userAgent = 'Permtest-Runner/2.0'
  } = {}) {
    this.frontendUrl = frontendUrl.replace(/\/+$/, '');
    this.apiUrl = apiUrl ? apiUrl.replace(/\/+$/, '') : null;
    this.allowProd = allowProd || process.argv.includes('--allow-prod');
    this.userAgent = userAgent;

    // In dev mode (default), API routes go through Vite proxy: ${FRONTEND_URL}/api
    // In prod mode, API routes go to ${apiUrl} with Origin: ${FRONTEND_URL}
    this.isProd = Boolean(this.apiUrl && !this.apiUrl.includes('localhost') && !this.apiUrl.includes('127.0.0.1'));
    this.apiBaseUrl = this.apiUrl || `${this.frontendUrl}/api`;

    // Safety guard
    if (this.isProd && !this.allowProd) {
      throw new Error('[SECURITY FATAL] Permtest client refused: Target looks like production but --allow-prod was not specified.');
    }

    this.cookies = new Map();
    this.token = null;
    this.csrfToken = null;
  }

  setCookie(name, value) {
    this.cookies.set(name, value);
    if (name === 'token') {
      this.token = value;
    }
    if (name === 'csrfToken' || name === 'x-csrf-token') {
      this.csrfToken = value;
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
      if (typeof header !== 'string') continue;
      const parts = header.split(';')[0].split('=');
      if (parts.length >= 2) {
        const name = parts[0].trim();
        const value = parts.slice(1).join('=').trim();
        this.setCookie(name, value);
      }
    }
  }

  async request(path, options = {}) {
    // Normalise path
    let url;
    if (path.startsWith('http://') || path.startsWith('https://')) {
      url = path;
    } else {
      const cleanPath = path.startsWith('/') ? path : `/${path}`;
      if (this.apiBaseUrl.endsWith('/api') && cleanPath.startsWith('/api/')) {
        url = `${this.apiBaseUrl}${cleanPath.slice(4)}`;
      } else {
        url = `${this.apiBaseUrl}${cleanPath}`;
      }
    }

    const method = (options.method || 'GET').toUpperCase();
    const headers = {
      'Origin': this.frontendUrl,
      'Referer': `${this.frontendUrl}/`,
      'User-Agent': this.userAgent,
      'Accept': 'application/json, text/plain, */*',
      ...options.headers
    };

    const cookieStr = this.getCookieString();
    if (cookieStr) {
      headers['Cookie'] = cookieStr;
    }

    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    if (this.csrfToken && !headers['x-csrf-token']) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    let body = options.body;
    if (body && typeof body === 'object' && !(body instanceof Buffer) && !(body instanceof FormData)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }

    let res;
    let error = null;
    let attempts = 0;
    const maxAttempts = 3;

    while (attempts < maxAttempts) {
      attempts++;
      error = null;
      try {
        res = await fetch(url, {
          method,
          headers,
          body: ['GET', 'HEAD'].includes(method) ? undefined : body,
          redirect: 'manual'
        });

        // Handle 429 rate limit backoff
        if (res.status === 429 && attempts < maxAttempts) {
          const retryAfter = Number(res.headers.get('retry-after') || 1);
          console.warn(`[PERMTEST] 429 Rate limited on ${url}, backing off for ${retryAfter}s (attempt ${attempts}/${maxAttempts})...`);
          await new Promise((r) => setTimeout(r, retryAfter * 1000 + 200));
          continue;
        }

        break;
      } catch (err) {
        error = err;
        console.error('[PERMTEST CLIENT FETCH ERROR]:', err.code, err.message, err.cause);
        if (attempts >= maxAttempts) break;
        await new Promise((r) => setTimeout(r, 500));
      }
    }

    if (error) {
      return {
        ok: false,
        status: 0,
        headers: {},
        data: null,
        error: error.message,
        url,
        method
      };
    }

    // Extract set-cookie
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : res.headers.get('set-cookie');
    this.parseSetCookie(setCookie);

    // Extract potential csrf token from header
    const csrfHeader = res.headers.get('x-csrf-token');
    if (csrfHeader) {
      this.csrfToken = csrfHeader;
    }

    const contentType = res.headers.get('content-type') || '';
    const rawText = await res.text();
    let data = null;

    if (contentType.includes('application/json')) {
      try {
        data = JSON.parse(rawText);
      } catch {
        data = rawText;
      }
    } else {
      data = rawText;
    }

    return {
      ok: res.ok,
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      data,
      rawText,
      url,
      method
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

  /**
   * Preflight validation: ensures frontend URL serves SPA HTML and /api/health proxies to backend.
   */
  async preflightCheck() {
    console.log(`[PREFLIGHT] Checking Frontend URL: ${this.frontendUrl}`);
    const rRoot = await this.get(this.frontendUrl);
    if (!rRoot.rawText || !rRoot.rawText.includes('<html')) {
      throw new Error(`[PREFLIGHT FAILED] Frontend root ${this.frontendUrl} did not return SPA HTML (status: ${rRoot.status})`);
    }

    console.log(`[PREFLIGHT] Checking API Health Proxy: ${this.apiBaseUrl}/health`);
    const rHealth = await this.get(`${this.apiBaseUrl}/health`);
    if (rHealth.status !== 200 || !rHealth.data || rHealth.data.status !== 'ok') {
      throw new Error(`[PREFLIGHT FAILED] API health check failed via ${this.apiBaseUrl}/health. Status: ${rHealth.status}, Data: ${JSON.stringify(rHealth.data)}`);
    }

    console.log('✓ Preflight verified: Frontend SPA HTML & /api proxy health check OK.');
    return true;
  }
}

module.exports = { PermtestClient };
