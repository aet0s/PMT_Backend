// server/src/test_ka_auth_activity.js
// Tests for K-A.4: GET /api/auth/activity endpoint, pagination, authentication, and response shape.
const assert = require('assert');
const http = require('http');

process.env.CLIENT_URL = 'https://pmt.solarman.in';
process.env.CORS_ORIGINS = 'https://pmt.solarman.in,http://localhost:5173';
process.env.NODE_ENV = 'test';
process.env.DEV_SINGLE_TENANT = '1';
process.env.MYSQL_DATABASE = 'pm_dev_single';

async function runTests() {
  console.log('=== Running K-A.4: Auth Activity Tests ===\n');

  const { app } = require('./index');
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Unauthenticated request to /api/auth/activity should return 401 (NOT 404!)
    console.log('1. Testing GET /api/auth/activity without auth...');
    const noAuthRes = await fetch(`${baseUrl}/api/auth/activity`);
    assert.strictEqual(
      noAuthRes.status,
      401,
      `Should return 401 Unauthorized, but got ${noAuthRes.status}`
    );
    const noAuthData = await noAuthRes.json();
    assert.strictEqual(noAuthData.error?.code, 'UNAUTHORIZED');
    console.log('✓ Unauthenticated request correctly returns 401.');

    // 2. Login or create user and call /api/auth/activity
    console.log('2. Testing GET /api/auth/activity with authenticated user...');
    const email = `activity_test_${Date.now()}@example.com`;
    const password = 'Password123!@#';

    // Register user
    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Activity Tester', email, password })
    });
    assert(regRes.ok, `Registration failed with status ${regRes.status}`);

    const cookieHeader = regRes.headers.get('set-cookie');
    assert(cookieHeader, 'Registration should return auth cookie');

    // Extract token cookie
    const tokenMatch = cookieHeader.match(/token=([^;]+)/);
    const cookie = tokenMatch ? `token=${tokenMatch[1]}` : cookieHeader;

    // Call /api/auth/activity
    const actRes = await fetch(`${baseUrl}/api/auth/activity?page=1&limit=10`, {
      headers: {
        Cookie: cookie
      }
    });

    assert.strictEqual(
      actRes.status,
      200,
      `GET /api/auth/activity should return 200, but got ${actRes.status}`
    );

    const actData = await actRes.json();
    assert(Array.isArray(actData.events), 'Response must contain events array');
    assert(actData.pagination, 'Response must contain pagination metadata');
    assert.strictEqual(actData.pagination.page, 1, 'Pagination page should be 1');
    assert.strictEqual(actData.pagination.limit, 10, 'Pagination limit should be 10');
    assert(typeof actData.pagination.total === 'number', 'Pagination total should be a number');

    console.log(`✓ Authenticated request succeeded. Found ${actData.events.length} event(s), total: ${actData.pagination.total}`);

    if (actData.events.length > 0) {
      const first = actData.events[0];
      assert(first.id, 'Event must have id');
      assert(first.action, 'Event must have action description');
      assert(first.created_at, 'Event must have ISO created_at date');
      // Verify date is valid ISO-8601
      const parsedDate = new Date(first.created_at);
      assert(!isNaN(parsedDate.getTime()), 'created_at must be valid date');
      console.log('✓ Event shape assertions passed:', first);
    }

    console.log('\n===============================================');
    console.log('K-A.4 AUTH ACTIVITY TESTS PASSED!');
    console.log('===============================================\n');
  } finally {
    server.close();
  }
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('K-A.4 test failed:', err);
    process.exit(1);
  });
