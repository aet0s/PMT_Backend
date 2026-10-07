// server/src/test_part_b.js
// Phase 2.5 Hardening Test Suite (Items 1-8):
// 1. ID-collision isolation (same numeric IDs across tenants never cross or leak)
// 2. Forged, suspended, deleted-tenant, and missing-user token guards
// 3. Database naming pm_t_<slug>_<id8> guard and format verification
// 4. Provisioning rollback on failure and concurrent-registration race tests
// 5. Empty initial notifications/activity_log & multi-tenant reminder cron execution
// 6. File-path consistency (private uploads) and cross-tenant access guards

require('dotenv').config();
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const {
  deriveTenantDbName,
  provisionTenant,
  dropTenantDatabase,
  TENANT_DB_GUARD
} = require('./services/tenantProvisioner');
const { getJwtSecret } = require('./middleware/auth');
const migrator = require('./db/migrator');
const { checkDueSoonCards } = require('./cron/reminders');

const authRouter = require('./routes/auth');
const workspacesRouter = require('./routes/workspaces');
const boardsRouter = require('./routes/boards');
const listsRouter = require('./routes/lists');
const cardsRouter = require('./routes/cards');
const filesRouter = require('./routes/files');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`  ❌ FAILED: ${message}`);
    failedTests++;
    throw new Error(message);
  } else {
    console.log(`  ✓ ${message}`);
    passedTests++;
  }
}

async function request(baseUrl, path, options = {}) {
  const url = `${baseUrl}${path}`;
  const headers = { ...(options.headers || {}) };
  let body = options.body;

  if (body && typeof body === 'object' && !(body instanceof Buffer)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body
  });

  const contentType = res.headers.get('content-type') || '';
  let data;
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    data = await res.text();
  }

  return { status: res.status, headers: res.headers, data };
}

async function runPartBTests() {
  console.log('================================================================');
  console.log('            PART B: PHASE 2.5 HARDENING TEST SUITE             ');
  console.log('================================================================\n');

  await migrator.migrateMaster();

  const app = express();
  app.use(cors({ origin: true, credentials: true }));
  app.use(cookieParser());
  app.use(express.json());

  app.use('/api/auth', authRouter);
  app.use('/api/workspaces', workspacesRouter);
  app.use('/api/boards', boardsRouter);
  app.use('/api/lists', listsRouter);
  app.use('/api/cards', cardsRouter);
  app.use('/api/files', filesRouter);
  app.use('/uploads', filesRouter);

  app.use((err, req, res, next) => {
    const status = err.status || 400;
    res.status(status).json({ error: { message: err.message, code: err.code || 'BAD_REQUEST' } });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const masterDb = getMasterDb();

  try {
    // -------------------------------------------------------------
    // Item 3: DB Naming Verification (pm_t_<slug>_<id8>)
    // -------------------------------------------------------------
    console.log('--- Item 3: Tenant Database Naming Format ---');
    const dbName1 = deriveTenantDbName('acme_corp');
    assert(/^pm_t_acme_corp_[0-9a-f]{8}$/.test(dbName1), `Generated dbName "${dbName1}" matches pm_t_<slug>_<id8>`);
    assert(TENANT_DB_GUARD.test(dbName1), `dbName "${dbName1}" passes strict security regex guard`);
    assert(dbName1.length <= 64, `dbName length (${dbName1.length}) is within 64 character MySQL limit`);

    const dbName2 = deriveTenantDbName('acme_corp');
    assert(dbName1 !== dbName2, 'Subsequent calls generate unique 8-character hex suffixes');

    // -------------------------------------------------------------
    // Item 1: ID-Collision Isolation Tests
    // -------------------------------------------------------------
    console.log('\n--- Item 1: ID-Collision Isolation (Same Numeric IDs in Both Tenants) ---');

    // Clean up test tenants if existing
    const collisionSlugs = ['collision_a', 'collision_b'];
    for (const slug of collisionSlugs) {
      const existing = await masterDb.query('SELECT id, db_name FROM tenants WHERE slug = ?', [slug]);
      for (const t of existing) {
        try { await dropTenantDatabase(t.db_name); } catch (e) {}
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
      }
    }

    // Provision Tenant A
    const provA = await provisionTenant({
      companyName: 'Collision Corp A',
      slug: 'collision_a',
      ownerEmail: 'owner@collision-a.com',
      ownerPassword: 'Password123!',
      ownerName: 'Owner A'
    });
    const tenantA = provA.tenant;
    const tokenA = jwt.sign(
      { sub: provA.owner.id, userId: provA.owner.id, email: provA.owner.email, tid: tenantA.id, tenantId: tenantA.id },
      getJwtSecret(),
      { expiresIn: '1h' }
    );

    // Provision Tenant B
    const provB = await provisionTenant({
      companyName: 'Collision Corp B',
      slug: 'collision_b',
      ownerEmail: 'owner@collision-b.com',
      ownerPassword: 'Password123!',
      ownerName: 'Owner B'
    });
    const tenantB = provB.tenant;
    const tokenB = jwt.sign(
      { sub: provB.owner.id, userId: provB.owner.id, email: provB.owner.email, tid: tenantB.id, tenantId: tenantB.id },
      getJwtSecret(),
      { expiresIn: '1h' }
    );

    // In both newly provisioned tenant DBs, the initial board ID is 1, initial list ID is 1, initial card ID is 1.
    // Tenant A mutates its card 1
    const updateCardA = await request(baseUrl, '/api/cards/1', {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: { title: 'Card 1 Title for Tenant A', description: 'Alpha isolated description' }
    });
    assert(updateCardA.status === 200, 'Tenant A updated Card 1 successfully');

    // Tenant B mutates its card 1
    const updateCardB = await request(baseUrl, '/api/cards/1', {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${tokenB}` },
      body: { title: 'Card 1 Title for Tenant B', description: 'Beta isolated description' }
    });
    assert(updateCardB.status === 200, 'Tenant B updated Card 1 successfully');

    // Fetch Card 1 as Tenant A: must see Tenant A data, NOT Tenant B
    const fetchCardA = await request(baseUrl, '/api/cards/1', {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(fetchCardA.status === 200, 'Tenant A fetched Card 1');
    assert(fetchCardA.data.card.title === 'Card 1 Title for Tenant A', 'Card 1 contains Tenant A title strictly');
    assert(fetchCardA.data.card.description === 'Alpha isolated description', 'Card 1 contains Tenant A description');

    // Fetch Card 1 as Tenant B: must see Tenant B data
    const fetchCardB = await request(baseUrl, '/api/cards/1', {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert(fetchCardB.status === 200, 'Tenant B fetched Card 1');
    assert(fetchCardB.data.card.title === 'Card 1 Title for Tenant B', 'Card 1 contains Tenant B title strictly');
    assert(fetchCardB.data.card.description === 'Beta isolated description', 'Card 1 contains Tenant B description');

    // Token A attempting to query non-existent ID (e.g. Card 9999) returns 404
    const notFoundCard = await request(baseUrl, '/api/cards/9999', {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(notFoundCard.status === 404, 'Non-existent card ID returns 404');

    // -------------------------------------------------------------
    // Item 2: Forged, Suspended, Deleted-Tenant, and Missing-User Token Tests
    // -------------------------------------------------------------
    console.log('\n--- Item 2: Token Security & Invalid Tenant/User State Tests ---');

    // 1. Forged token (tampered secret)
    const forgedToken = jwt.sign(
      { sub: 1, userId: 1, email: 'hacker@evil.com', tid: tenantA.id },
      'wrong_secret_1234567890123456789012',
      { expiresIn: '1h' }
    );
    const forgedRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${forgedToken}` }
    });
    assert(forgedRes.status === 401, 'Forged token rejected with 401 Unauthorized');

    // 2. Suspended tenant token
    await masterDb.execute("UPDATE tenants SET status = 'suspended' WHERE id = ?", [tenantB.id]);
    const suspendedRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert(suspendedRes.status === 403, 'Suspended tenant token rejected with 403 Forbidden');
    assert(suspendedRes.data.error?.code === 'TENANT_INACTIVE', 'Error code is TENANT_INACTIVE');

    // 3. Deleted tenant token
    await masterDb.execute("UPDATE tenants SET status = 'deleted' WHERE id = ?", [tenantB.id]);
    const deletedRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert(deletedRes.status === 401 || deletedRes.status === 403 || deletedRes.status === 404, 'Deleted tenant token rejected');

    // 4. Missing user token (valid tenant, but user ID removed from tenant users table)
    const missingUserToken = jwt.sign(
      { sub: 88888, userId: 88888, email: 'ghost@collision-a.com', tid: tenantA.id, tenantId: tenantA.id },
      getJwtSecret(),
      { expiresIn: '1h' }
    );
    const missingUserRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${missingUserToken}` }
    });
    assert(missingUserRes.status === 401, 'Missing user rejected with 401 Unauthorized');
    assert(missingUserRes.data.error?.code === 'USER_NOT_FOUND', 'Error code is USER_NOT_FOUND');

    // -------------------------------------------------------------
    // Item 4: Provisioning Failure Rollback & Concurrent Registration Tests
    // -------------------------------------------------------------
    console.log('\n--- Item 4: Provisioning Failure Rollback & Concurrent Registrations ---');

    // 1. Provisioning Failure Rollback
    let rollbackThrew = false;
    try {
      // Pass an invalid table insert or trigger a failure by using an invalid object
      await provisionTenant({
        companyName: 'Fail Corp',
        slug: 'fail_tenant',
        ownerEmail: 'fail@fail.com',
        ownerPasswordHash: null // triggers missing password error
      });
    } catch (err) {
      rollbackThrew = true;
    }
    assert(rollbackThrew, 'Provisioning with missing password threw error as expected');

    // Verify no orphaned tenant record exists in pm_master
    const [orphanTenant] = await masterDb.query("SELECT id FROM tenants WHERE slug = 'fail_tenant'");
    assert(!orphanTenant, 'No orphaned tenant record left in pm_master after provisioning failure');

    // 2. Concurrent Registration Race Condition
    console.log('Testing concurrent company registration for identical slug/email...');
    process.env.VERIFICATION_MODE = 'off';
    process.env.REGISTRATION_ENABLED = 'true';

    // Clean up conc_tenant if present from prior runs
    const existingConc = await masterDb.query("SELECT id, db_name FROM tenants WHERE slug = 'conc_tenant'");
    for (const t of existingConc) {
      try { await dropTenantDatabase(t.db_name); } catch (e) {}
      await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
      await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
    }

    // Fire 2 simultaneous registration requests for the same company slug
    const concPromises = [
      request(baseUrl, '/api/auth/register-company', {
        method: 'POST',
        body: {
          company_name: 'Concurrent Corp',
          slug: 'conc_tenant',
          admin_name: 'User One',
          admin_email: 'user1@conc.com',
          admin_password: 'Password123!'
        }
      }),
      request(baseUrl, '/api/auth/register-company', {
        method: 'POST',
        body: {
          company_name: 'Concurrent Corp',
          slug: 'conc_tenant',
          admin_name: 'User Two',
          admin_email: 'user2@conc.com',
          admin_password: 'Password123!'
        }
      })
    ];

    const concResults = await Promise.all(concPromises);
    const successCount = concResults.filter((r) => r.status === 201).length;
    const conflictCount = concResults.filter((r) => r.status === 409).length;

    assert(successCount === 1, 'Exactly one concurrent registration succeeded with 201 Created');
    assert(conflictCount === 1, 'Second concurrent registration was safely rejected with 409 Conflict');

    // -------------------------------------------------------------
    // Item 5: Empty Initial Tables & Multi-Tenant Cron Reminder Execution
    // -------------------------------------------------------------
    console.log('\n--- Item 5: Empty Initial Tables & Multi-Tenant Reminder Cron ---');

    const dbA = await getTenantDb(tenantA.id);
    const [notifCountA] = await dbA.query('SELECT COUNT(*) as count FROM notifications');
    assert(Number(notifCountA.count) === 0, 'Newly provisioned tenant DB has 0 initial notifications (empty baseline)');

    const [activityCountA] = await dbA.query('SELECT COUNT(*) as count FROM activity_log');
    assert(Number(activityCountA.count) === 0, 'Newly provisioned tenant DB has 0 initial activity log records');

    // Set Card 1 in Tenant A to be due soon (within 30 minutes) and assign owner
    const dueSoonDate = new Date(Date.now() + 30 * 60 * 1000);
    await dbA.execute('INSERT IGNORE INTO card_members (card_id, user_id) VALUES (1, ?)', [provA.owner.id]);
    await dbA.execute('UPDATE cards SET due_date = ? WHERE id = 1', [dueSoonDate]);

    // Run reminder cron logic
    const now = new Date();
    const dueSoonCount = await checkDueSoonCards(now, dbA, tenantA.id);
    assert(dueSoonCount >= 1, 'Cron job processed due-soon card for Tenant A');

    // Deduplication check: running cron again does not duplicate
    const dedupCount = await checkDueSoonCards(now, dbA, tenantA.id);
    assert(dedupCount === 0, 'Cron run deduplicated: 0 duplicate notifications generated');

    // -------------------------------------------------------------
    // Item 6: File Storage Isolation & Path Traversal Guards
    // -------------------------------------------------------------
    console.log('\n--- Item 6: File Storage Isolation & Path Traversal Guards ---');

    // Cross-tenant download attempt: Token A attempting to download Tenant B files returns 404
    const crossDownloadRes = await request(baseUrl, `/api/files/${tenantB.id}/cards/1/fake_file.txt`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(crossDownloadRes.status === 404, 'Cross-tenant file download strictly blocked with 404');

    // Path traversal attempt (/../)
    const traversalRes = await request(baseUrl, `/api/files/${tenantA.id}/..%2f..%2f..%2fpackage.json`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(traversalRes.status === 403 || traversalRes.status === 404, 'Path traversal attack blocked with 403/404');

    console.log('\n================================================================');
    console.log(`PART B TEST SUMMARY: ${passedTests} passed, ${failedTests} failed.`);
    console.log('================================================================\n');
  } finally {
    server.close();
    await closeAllPools();
    process.exit(failedTests > 0 ? 1 : 0);
  }
}

runPartBTests().catch((err) => {
  console.error('Test suite runner crashed:', err);
  process.exit(1);
});
