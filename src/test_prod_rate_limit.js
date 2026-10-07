// server/src/test_prod_rate_limit.js
// Verifies that POST /api/dev/reset-rate-limit is ONLY available in NODE_ENV=test
// and strictly returns 404 in NODE_ENV=production.

const assert = require('assert');
const http = require('http');

function clearServerCache() {
  for (const k of Object.keys(require.cache)) {
    if (k.startsWith(__dirname) || k.includes('server')) {
      delete require.cache[k];
    }
  }
}

async function runTest() {
  console.log('--- Testing POST /api/dev/reset-rate-limit environment isolation ---');

  // 1. Boot in production mode
  process.env.NODE_ENV = 'production';
  process.env.JWT_SECRET = 'secret123456789012345678901234567890';
  process.env.SESSION_SECRET = 'secret123456789012345678901234567890';
  process.env.TOTP_ENC_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  clearServerCache();

  const prodApp = require('./index').app;
  const prodServer = http.createServer(prodApp);
  await new Promise((resolve) => prodServer.listen(0, resolve));
  const prodPort = prodServer.address().port;

  try {
    const prodRes = await fetch(`http://localhost:${prodPort}/api/dev/reset-rate-limit`, {
      method: 'POST'
    });
    console.log(`[Production] POST /api/dev/reset-rate-limit status: ${prodRes.status}`);
    assert.strictEqual(prodRes.status, 404, 'Expected 404 in production mode');
    console.log('✓ PASS: Production server returns 404 for /api/dev/reset-rate-limit');
  } finally {
    await new Promise((resolve) => prodServer.close(resolve));
  }

  // 2. Boot in test mode
  process.env.NODE_ENV = 'test';
  clearServerCache();

  const testApp = require('./index').app;
  const testServer = http.createServer(testApp);
  await new Promise((resolve) => testServer.listen(0, resolve));
  const testPort = testServer.address().port;

  try {
    const testRes = await fetch(`http://localhost:${testPort}/api/dev/reset-rate-limit`, {
      method: 'POST'
    });
    console.log(`[Test] POST /api/dev/reset-rate-limit status: ${testRes.status}`);
    assert.strictEqual(testRes.status, 200, 'Expected 200 in test mode');
    const data = await testRes.json();
    assert.strictEqual(data.ok, true, 'Expected { ok: true }');
    console.log('✓ PASS: Test server returns 200 { ok: true } for /api/dev/reset-rate-limit');
  } finally {
    await new Promise((resolve) => testServer.close(resolve));
  }

  console.log('\nAll rate limit endpoint environment isolation tests PASSED!\n');
}

if (require.main === module) {
  runTest().catch((err) => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = { runTest };
