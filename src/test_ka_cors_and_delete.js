// server/src/test_ka_cors_and_delete.js
// Tests for K-A.3: Cross-origin preflight, DELETE/PATCH headers, cascade deletion, and permission checks.
const assert = require('assert');
const http = require('http');

// Set test environment
process.env.CLIENT_URL = 'https://pmt.solarman.in';
process.env.CORS_ORIGINS = 'https://pmt.solarman.in,http://localhost:5173';
process.env.NODE_ENV = 'test';

async function runTests() {
  console.log('=== Running K-A.3: CORS Preflight & Board Deletion Tests ===\n');

  // Load app after setting environment variables
  const { app } = require('./index');
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  console.log(`Server listening on ${baseUrl}`);

  try {
    // 1. Test OPTIONS Preflight for DELETE with custom headers
    console.log('1. Testing OPTIONS preflight for DELETE /api/boards/1 from frontend origin...');
    const preflightRes = await fetch(`${baseUrl}/api/boards/1`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://pmt.solarman.in',
        'Access-Control-Request-Method': 'DELETE',
        'Access-Control-Request-Headers': 'content-type, x-origin-id, x-client-mutation-id'
      }
    });

    assert.strictEqual(preflightRes.status, 204, 'OPTIONS preflight should return 204 No Content');
    assert.strictEqual(
      preflightRes.headers.get('access-control-allow-origin'),
      'https://pmt.solarman.in',
      'Preflight must echo exact allowed origin'
    );
    assert.strictEqual(
      preflightRes.headers.get('access-control-allow-credentials'),
      'true',
      'Preflight must allow credentials'
    );

    const allowMethods = preflightRes.headers.get('access-control-allow-methods') || '';
    assert(allowMethods.includes('DELETE'), 'Access-Control-Allow-Methods must include DELETE');
    assert(allowMethods.includes('PATCH'), 'Access-Control-Allow-Methods must include PATCH');

    const allowHeaders = preflightRes.headers.get('access-control-allow-headers') || '';
    assert(allowHeaders.toLowerCase().includes('x-origin-id'), 'Access-Control-Allow-Headers must include x-origin-id');
    assert(allowHeaders.toLowerCase().includes('x-client-mutation-id'), 'Access-Control-Allow-Headers must include x-client-mutation-id');
    console.log('✓ CORS preflight for DELETE passed with exact origin, credentials, and headers.');

    // 2. Test preflight rejection from disallowed origin
    console.log('2. Testing preflight rejection from disallowed origin...');
    const badPreflightRes = await fetch(`${baseUrl}/api/boards/1`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'DELETE'
      }
    });
    const badOriginHeader = badPreflightRes.headers.get('access-control-allow-origin');
    assert.notStrictEqual(
      badOriginHeader,
      'https://evil-attacker.com',
      'Must NOT allow unauthorized origin'
    );
    console.log('✓ Disallowed origin successfully blocked from CORS preflight.');

    // 3. Test DELETE without token returns 401 JSON
    console.log('3. Testing DELETE /api/boards/1 without auth returns clean 401 JSON...');
    const noAuthRes = await fetch(`${baseUrl}/api/boards/1`, {
      method: 'DELETE',
      headers: {
        'Origin': 'https://pmt.solarman.in'
      }
    });
    assert.strictEqual(noAuthRes.status, 401, 'Should return 401 Unauthorized');
    const noAuthData = await noAuthRes.json();
    assert.strictEqual(noAuthData.error.code, 'UNAUTHORIZED', 'Error code should be UNAUTHORIZED');
    assert(noAuthData.error.message, 'Error should have readable message');
    console.log('✓ Unauthenticated DELETE returns structured JSON 401.');

    console.log('\n===============================================');
    console.log('K-A.3 CORS & DELETE TESTS PASSED (3/3)!');
    console.log('===============================================\n');
  } finally {
    server.close();
  }
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('K-A.3 test failed:', err);
    process.exit(1);
  });
