// server/src/test_kb1_public_routes.js
// Tests public route security rules:
// 1. All public routes MUST be in the explicit ALLOWED_PUBLIC_ROUTES allow-list with category & justification.
// 2. No public route may write to the database except login/session/registration flows.
// 3. Rejection of unlisted public routes and unauthorized mutating public routes.
// 4. Runtime assertion that non-auth public endpoints perform 0 DB write queries.

const assert = require('assert');
const http = require('http');
const { ROUTE_PERMISSIONS } = require('./rbac/routePermissions');
const { ALLOWED_PUBLIC_ROUTES, DB_WRITE_ALLOWED_PUBLIC_CATEGORIES } = require('./scripts/rbacAudit');
const db = require('./db');

process.env.NODE_ENV = 'test';
process.env.DEV_SINGLE_TENANT = '1';
process.env.JWT_SECRET = 'secret123456789012345678901234567890';
process.env.SESSION_SECRET = 'secret123456789012345678901234567890';

const { app } = require('./index');

async function runTests() {
  console.log('\n================================================================');
  console.log('       K-B.1 PUBLIC ROUTE & DB WRITE RESTRICTION TEST SUITE     ');
  console.log('================================================================\n');

  let passedAssertions = 0;

  // Test 1: Every route declared with publicReason is in ALLOWED_PUBLIC_ROUTES
  console.log('1. Verifying every publicReason route matches explicit ALLOWED_PUBLIC_ROUTES...');
  for (const [key, decl] of ROUTE_PERMISSIONS.entries()) {
    if (decl.publicReason) {
      const allowed = ALLOWED_PUBLIC_ROUTES.get(key);
      assert(allowed, `Route ${key} has publicReason but is missing from ALLOWED_PUBLIC_ROUTES`);
      assert(allowed.justification && allowed.justification.length > 5, `Route ${key} lacks an adequate justification`);
      assert(allowed.category, `Route ${key} lacks an explicit category`);
      passedAssertions += 3;
    }
  }
  console.log(`✓ All publicReason routes in ROUTE_PERMISSIONS exist in ALLOWED_PUBLIC_ROUTES (${passedAssertions} checks).`);

  // Test 2: Database write rule - only registration & login/session may write to DB
  console.log('\n2. Verifying public route database write category constraints...');
  for (const [key, info] of ALLOWED_PUBLIC_ROUTES.entries()) {
    const [method] = key.split(' ');
    if (!DB_WRITE_ALLOWED_PUBLIC_CATEGORIES.has(info.category)) {
      // Non-auth public routes must not be mutating methods (unless test-only helper)
      if (info.category !== 'test-only') {
        assert.strictEqual(method, 'GET', `Public non-auth route ${key} has mutating method ${method}`);
        passedAssertions++;
      } else {
        assert.strictEqual(key, 'POST /api/dev/reset-rate-limit', `Unexpected mutating test route: ${key}`);
        passedAssertions++;
      }
    }
  }
  console.log(`✓ No public route outside registration/session has unapproved mutating methods.`);

  // Test 3: Simulated violation: unapproved public route fails validation
  console.log('\n3. Testing rejection of unapproved public routes...');
  const fakeRouteMap = new Map(ROUTE_PERMISSIONS);
  fakeRouteMap.set('POST /api/unapproved/public', { publicReason: 'Hacker backdoor', scope: 'company' });
  
  let rejectedUnapproved = false;
  for (const [key, decl] of fakeRouteMap.entries()) {
    if (decl.publicReason && !ALLOWED_PUBLIC_ROUTES.has(key)) {
      rejectedUnapproved = true;
      break;
    }
  }
  assert.strictEqual(rejectedUnapproved, true, 'Audit failed to reject unapproved public route');
  passedAssertions++;
  console.log('✓ Audit rule successfully catches and rejects unapproved public routes.');

  // Test 4: Simulated violation: public route outside auth attempting DB write
  console.log('\n4. Testing rejection of unauthorized public mutating routes...');
  const unauthorizedMutating = { method: 'POST', path: '/api/config/public', category: 'public-config' };
  const wouldFailDbWriteRule = !DB_WRITE_ALLOWED_PUBLIC_CATEGORIES.has(unauthorizedMutating.category) &&
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(unauthorizedMutating.method);
  assert.strictEqual(wouldFailDbWriteRule, true, 'Audit rule failed to catch unauthorized public write attempt');
  passedAssertions++;
  console.log('✓ Audit rule strictly forbids mutating methods on public non-auth routes.');

  // Test 5: Runtime verification - GET /api/health performs 0 DB writes
  console.log('\n5. Verifying GET /api/health executes 0 database writes...');
  let writeQueriesCount = 0;
  const originalExecute = db.execute;
  const originalQuery = db.query;

  const writeRegex = /^\s*(INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|CREATE|TRUNCATE)/i;

  const interceptor = (sql) => {
    if (typeof sql === 'string' && writeRegex.test(sql.trim())) {
      writeQueriesCount++;
      console.error(`[UNEXPECTED DB WRITE]: ${sql}`);
    }
  };

  db.execute = async function(sql, ...args) {
    interceptor(sql);
    return originalExecute.apply(this, [sql, ...args]);
  };
  db.query = async function(sql, ...args) {
    interceptor(sql);
    return originalQuery.apply(this, [sql, ...args]);
  };

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(healthRes.status, 200);
    const healthBody = await healthRes.json();
    assert.strictEqual(healthBody.status, 'ok');
    assert.strictEqual(writeQueriesCount, 0, 'GET /api/health triggered database writes!');
    passedAssertions += 3;
    console.log('✓ GET /api/health returned 200 with exactly 0 database write queries.');

    // Test 6: Runtime verification - GET /api/invitations/verify performs 0 DB writes
    console.log('\n6. Verifying GET /api/invitations/verify executes 0 database writes...');
    writeQueriesCount = 0;
    const verifyRes = await fetch(`${baseUrl}/api/invitations/verify?token=invalid_test_token`);
    assert.strictEqual(verifyRes.status, 404); // Non-existent token returns 404
    assert.strictEqual(writeQueriesCount, 0, 'GET /api/invitations/verify triggered database writes!');
    passedAssertions += 2;
    console.log('✓ GET /api/invitations/verify rejected invalid token with exactly 0 database write queries.');

    // Test 7: Runtime verification - POST /api/dev/reset-rate-limit performs 0 DB writes
    console.log('\n7. Verifying POST /api/dev/reset-rate-limit executes 0 database writes...');
    writeQueriesCount = 0;
    const resetRes = await fetch(`${baseUrl}/api/dev/reset-rate-limit`, { method: 'POST' });
    assert.strictEqual(resetRes.status, 200);
    const resetBody = await resetRes.json();
    assert.strictEqual(resetBody.ok, true);
    assert.strictEqual(writeQueriesCount, 0, 'POST /api/dev/reset-rate-limit triggered database writes!');
    passedAssertions += 3;
    console.log('✓ POST /api/dev/reset-rate-limit completed with exactly 0 database write queries.');

  } finally {
    server.close();
    db.execute = originalExecute;
    db.query = originalQuery;
  }

  console.log('\n================================================================');
  console.log(`✓ K-B.1 TEST SUITE PASSED: ${passedAssertions} assertions verified cleanly.`);
  console.log('================================================================\n');
  process.exit(0);
}

runTests().catch((err) => {
  console.error('\n❌ K-B.1 TEST SUITE FAILED:', err);
  process.exit(1);
});
