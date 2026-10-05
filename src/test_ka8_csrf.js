// server/src/test_ka8_csrf.js
const assert = require('assert');
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const { csrfProtection } = require('./middleware/csrf');

async function runTests() {
  console.log('--- Testing K-A.8.4: CSRF Exact-Match Origin & Cookie Protection ---');

  const allowedOrigins = [
    'https://pmt.solarman.in',
    'https://pmtmgmt.solarman.in'
  ];

  const app = express();
  app.use(cookieParser());
  app.use(csrfProtection(() => allowedOrigins));

  app.get('/api/test', (req, res) => res.json({ ok: true, method: 'GET' }));
  app.head('/api/test', (req, res) => res.status(200).end());
  app.post('/api/test', (req, res) => res.json({ ok: true, method: 'POST' }));
  app.delete('/api/test', (req, res) => res.json({ ok: true, method: 'DELETE' }));

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Exact match origin should pass
    const passRes = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Origin: 'https://pmt.solarman.in' }
    });
    assert.strictEqual(passRes.status, 200, 'Legitimate origin should be allowed');
    const passBody = await passRes.json();
    assert.strictEqual(passBody.ok, true);
    console.log('✓ Pass: Exact match origin https://pmt.solarman.in allowed (200)');

    // 2. Subdomain suffix attack: https://pmt.solarman.in.evil.com -> 403
    const evilSuffix = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Origin: 'https://pmt.solarman.in.evil.com' }
    });
    assert.strictEqual(evilSuffix.status, 403, 'Suffix attack must be rejected');
    const evilSuffixBody = await evilSuffix.json();
    assert.strictEqual(evilSuffixBody.error.code, 'CSRF_REJECTED');
    console.log('✓ Pass: Suffix attack https://pmt.solarman.in.evil.com rejected (403 CSRF_REJECTED)');

    // 3. Prefix attack: https://evilpmt.solarman.in -> 403
    const evilPrefix = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Origin: 'https://evilpmt.solarman.in' }
    });
    assert.strictEqual(evilPrefix.status, 403, 'Prefix attack must be rejected');
    const evilPrefixBody = await evilPrefix.json();
    assert.strictEqual(evilPrefixBody.error.code, 'CSRF_REJECTED');
    console.log('✓ Pass: Prefix attack https://evilpmt.solarman.in rejected (403 CSRF_REJECTED)');

    // 4. Insecure HTTP scheme: http://pmt.solarman.in -> 403
    const httpScheme = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Origin: 'http://pmt.solarman.in' }
    });
    assert.strictEqual(httpScheme.status, 403, 'HTTP scheme must be rejected when HTTPS expected');
    const httpBody = await httpScheme.json();
    assert.strictEqual(httpBody.error.code, 'CSRF_REJECTED');
    console.log('✓ Pass: Insecure HTTP scheme http://pmt.solarman.in rejected (403 CSRF_REJECTED)');

    // 5. Origin "null" -> 403
    const nullOrigin = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Origin: 'null' }
    });
    assert.strictEqual(nullOrigin.status, 403, 'Origin "null" must be rejected');
    const nullBody = await nullOrigin.json();
    assert.strictEqual(nullBody.error.code, 'CSRF_REJECTED');
    console.log('✓ Pass: Origin "null" rejected (403 CSRF_REJECTED)');

    // 6. Missing Origin with cookie-authenticated mutating request -> 403
    const missingOriginWithCookie = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Cookie: 'token=valid_session_jwt_xyz' }
    });
    assert.strictEqual(missingOriginWithCookie.status, 403, 'Missing Origin on cookie-auth mutating request must be rejected');
    const missingCookieBody = await missingOriginWithCookie.json();
    assert.strictEqual(missingCookieBody.error.code, 'CSRF_ORIGIN_MISSING');
    console.log('✓ Pass: Missing Origin with cookie-auth rejected (403 CSRF_ORIGIN_MISSING)');

    // 7. GET / HEAD unaffected by missing Origin even with cookie
    const getWithCookie = await fetch(`${baseUrl}/api/test`, {
      method: 'GET',
      headers: { Cookie: 'token=valid_session_jwt_xyz' }
    });
    assert.strictEqual(getWithCookie.status, 200, 'GET must be unaffected by CSRF checks');
    console.log('✓ Pass: GET unaffected by missing Origin with cookie (200)');

    const headWithCookie = await fetch(`${baseUrl}/api/test`, {
      method: 'HEAD',
      headers: { Cookie: 'token=valid_session_jwt_xyz' }
    });
    assert.strictEqual(headWithCookie.status, 200, 'HEAD must be unaffected by CSRF checks');
    console.log('✓ Pass: HEAD unaffected by missing Origin with cookie (200)');

    // 8. Missing Origin on non-cookie mutating request (e.g. Bearer auth or server-to-server) -> 200
    const missingOriginNoCookie = await fetch(`${baseUrl}/api/test`, {
      method: 'POST',
      headers: { Authorization: 'Bearer token_abc' }
    });
    assert.strictEqual(missingOriginNoCookie.status, 200, 'Non-cookie mutating request without Origin allowed');
    console.log('✓ Pass: Non-cookie mutating request without Origin allowed (200)');

    console.log('\nAll 8 CSRF tests passed successfully!');
  } finally {
    server.close();
  }
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
