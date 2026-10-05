// server/src/test_ka_cross_origin_checklist.js
const assert = require('assert');
const http = require('http');

process.env.CORS_ORIGINS = 'https://pmt.solarman.in';
process.env.CLIENT_URL = 'https://pmt.solarman.in';

async function runTests() {
  console.log('=== Running K-A.6: Cross-Origin Production Configuration Checklist Tests ===\n');

  const { app } = require('./index');
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. CORS Preflight & Credentials
    console.log('1. Testing CORS preflight and credentials from https://pmt.solarman.in...');
    const preflightRes = await fetch(`${baseUrl}/api/boards/1`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://pmt.solarman.in',
        'Access-Control-Request-Method': 'DELETE',
        'Access-Control-Request-Headers': 'x-origin-id,Content-Type'
      }
    });

    assert.strictEqual(preflightRes.status, 204);
    assert.strictEqual(preflightRes.headers.get('access-control-allow-origin'), 'https://pmt.solarman.in');
    assert.strictEqual(preflightRes.headers.get('access-control-allow-credentials'), 'true');
    assert.notStrictEqual(preflightRes.headers.get('access-control-allow-origin'), '*', 'Wildcard origin must NOT be returned with credentials: true');
    assert.strictEqual(preflightRes.headers.get('access-control-max-age'), '86400');
    console.log('✓ CORS preflight and credentials assertions passed.');

    // 2. Disallowed Origin CORS Rejection
    console.log('2. Testing CORS rejection for disallowed origin https://evil-attacker.com...');
    const disallowedPreflight = await fetch(`${baseUrl}/api/boards/1`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'DELETE'
      }
    });

    assert.strictEqual(disallowedPreflight.headers.get('access-control-allow-origin'), null, 'Disallowed origin must not have access-control-allow-origin');
    console.log('✓ Disallowed origin correctly rejected.');

    // 3. CSRF Protection for state-changing endpoints
    console.log('3. Testing CSRF blocking of state-changing request from unauthorized origin...');
    const csrfRes = await fetch(`${baseUrl}/api/workspaces`, {
      method: 'POST',
      headers: {
        'Origin': 'https://evil-attacker.com',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ name: 'Malicious Workspace' })
    });

    assert.strictEqual(csrfRes.status, 403);
    const csrfBody = await csrfRes.json();
    assert.strictEqual(csrfBody?.error?.code, 'CSRF_REJECTED');
    console.log('✓ Cross-origin mutating request blocked with 403 CSRF_REJECTED.');

    // 4. Allowed Origin CSRF Pass-through
    console.log('4. Testing CSRF pass-through from legitimate origin https://pmt.solarman.in...');
    const validCsrfRes = await fetch(`${baseUrl}/api/workspaces`, {
      method: 'POST',
      headers: {
        'Origin': 'https://pmt.solarman.in',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ name: 'Valid Workspace' })
    });

    // Should pass CSRF and reach authentication layer (401)
    assert.strictEqual(validCsrfRes.status, 401);
    console.log('✓ Allowed origin correctly passed CSRF layer into auth layer (401).');

    // 5. Trust proxy configuration
    console.log('5. Testing trust proxy setting on Express app...');
    assert.ok(app.get('trust proxy'), 'app.set("trust proxy") must be enabled');
    console.log('✓ app.get("trust proxy") is enabled.');

    // 6. Cross-Origin-Resource-Policy on files vs general
    console.log('6. Testing Helmet CORP settings (/api/files vs general)...');
    const filesCorpRes = await fetch(`${baseUrl}/api/files/test.png`);
    assert.strictEqual(filesCorpRes.headers.get('cross-origin-resource-policy'), 'cross-origin');

    const generalCorpRes = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(generalCorpRes.headers.get('cross-origin-resource-policy'), 'same-origin');
    console.log('✓ CORP is cross-origin for files/uploads and same-origin for general routes.');

    // 7. Unknown /api route returns JSON 404
    console.log('7. Testing unknown /api routes return JSON 404...');
    const unknownRouteRes = await fetch(`${baseUrl}/api/nonexistent-route-xyz`);
    assert.strictEqual(unknownRouteRes.status, 404);
    assert.strictEqual(unknownRouteRes.headers.get('content-type')?.includes('application/json'), true);
    const unknownBody = await unknownRouteRes.json();
    assert.strictEqual(unknownBody?.error?.code, 'NOT_FOUND');
    console.log('✓ Unknown /api routes correctly return JSON 404.');

    // 8. Dev routes absent in non-test mode
    console.log('8. Testing dev routes absent...');
    const devRouteRes = await fetch(`${baseUrl}/api/dev/reset-rate-limit`, { method: 'POST' });
    assert.strictEqual(devRouteRes.status, 404);
    console.log('✓ Dev routes return 404 JSON.');

    console.log('\n===============================================');
    console.log('K-A.6 CROSS-ORIGIN CHECKLIST TESTS PASSED!');
    console.log('===============================================\n');
  } finally {
    server.close();
  }
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Test failed:', err);
    process.exit(1);
  });
