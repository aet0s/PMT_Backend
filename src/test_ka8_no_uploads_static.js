// server/src/test_ka8_no_uploads_static.js
const assert = require('assert');
const http = require('http');

async function runTests() {
  console.log('--- Testing K-A.8.5: No Static Serving of /uploads (404 JSON) ---');

  // Require express app
  process.env.NODE_ENV = 'test';
  process.env.DEV_SINGLE_TENANT = '1';
  process.env.CLIENT_URL = 'https://pmt.solarman.in';

  const { app } = require('./index');

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. GET /uploads/avatar.png -> 404 JSON
    const res1 = await fetch(`${baseUrl}/uploads/avatar.png`);
    assert.strictEqual(res1.status, 404, 'GET /uploads/avatar.png must return 404');
    const contentType1 = res1.headers.get('content-type') || '';
    assert.ok(contentType1.includes('application/json'), `Expected application/json, got ${contentType1}`);
    const body1 = await res1.json();
    assert.strictEqual(body1.error.code, 'NOT_FOUND');
    console.log('✓ Pass: GET /uploads/avatar.png returns 404 JSON');

    // 2. GET /uploads/1/cards/secret.pdf -> 404 JSON
    const res2 = await fetch(`${baseUrl}/uploads/1/cards/secret.pdf`);
    assert.strictEqual(res2.status, 404, 'GET /uploads/1/cards/secret.pdf must return 404');
    const contentType2 = res2.headers.get('content-type') || '';
    assert.ok(contentType2.includes('application/json'), `Expected application/json, got ${contentType2}`);
    const body2 = await res2.json();
    assert.strictEqual(body2.error.code, 'NOT_FOUND');
    console.log('✓ Pass: GET /uploads/1/cards/secret.pdf returns 404 JSON');

    // 3. GET /uploads/ -> 404 JSON
    const res3 = await fetch(`${baseUrl}/uploads/`);
    assert.strictEqual(res3.status, 404, 'GET /uploads/ must return 404');
    const contentType3 = res3.headers.get('content-type') || '';
    assert.ok(contentType3.includes('application/json'), `Expected application/json, got ${contentType3}`);
    const body3 = await res3.json();
    assert.strictEqual(body3.error.code, 'NOT_FOUND');
    console.log('✓ Pass: GET /uploads/ returns 404 JSON');

    // 4. Assert CORP header is absent or same-origin for /uploads (NOT cross-origin)
    const corpHeader = res1.headers.get('cross-origin-resource-policy');
    assert.notStrictEqual(corpHeader, 'cross-origin', 'CORP must NOT be cross-origin on /uploads');
    console.log(`✓ Pass: CORP header on /uploads is '${corpHeader || 'same-origin/none'}', not 'cross-origin'`);

    console.log('\nAll /uploads security assertions passed successfully!');
  } finally {
    server.close();
  }
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
