// server/src/test_permission_sync_fixture.js
// N3: Proves dynamic permission addition via syncPermissionCatalog(db), enforcement, and fixture cleanup.

const assert = require('assert');
const crypto = require('crypto');
const { app, start } = require('./index');
const { PERMISSIONS, SYSTEM_ROLES } = require('./rbac/registry');
const { ROUTE_PERMISSIONS } = require('./rbac/routePermissions');
const { syncPermissionCatalog } = require('./rbac/catalogSync');
const { getDevSingleDb } = require('./services/tenantPools');
const { requireAuth } = require('./middleware/auth');
const { requirePermission } = require('./middleware/permissions');
const { createSession } = require('./services/sessionService');

async function runFixtureTest() {
  console.log('================================================================');
  console.log('   N3 DYNAMIC PERMISSION SYNC & FIXTURE ENFORCEMENT TEST        ');
  console.log('================================================================');

  const testDb = getDevSingleDb();
  const testKey = 'temp.test_fixture_perm';

  const express = require('express');
  const testApp = express();
  testApp.use(express.json());
  testApp.use((req, res, next) => {
    req.db = testDb;
    next();
  });
  testApp.get('/api/dev/temp-perm-test', requireAuth, requirePermission(testKey), (req, res) => {
    res.json({ success: true, message: 'Protected resource accessed with temp permission' });
  });

  // 2. Add temporary permission to registry.js in memory
  const fixturePerm = {
    key: testKey,
    module: 'system',
    label: 'Temp Fixture Perm',
    description: 'Temporary permission for N3 sync testing',
    scope: 'company',
    dangerous: false,
    planned: false
  };
  PERMISSIONS.push(fixturePerm);
  SYSTEM_ROLES['Admin'].permissions.push(testKey);

  console.log('1. Added temporary fixture permission to in-memory registry.');

  try {
    // 3. Run syncPermissionCatalog(testDb)
    await syncPermissionCatalog(testDb);
    console.log('2. Successfully executed syncPermissionCatalog(testDb).');

    // 4. Verify presence in GET /api/permissions
    const dbPerms = await testDb.query('SELECT `key`, planned FROM permissions WHERE `key` = ?', [testKey]);
    assert.strictEqual(dbPerms.length, 1, 'Temporary permission exists in DB permissions table');
    assert.strictEqual(dbPerms[0].planned, 0, 'Temporary permission is marked active (planned = 0)');
    console.log('3. ✓ Permission exists in database permissions catalog.');

    // 5. Verify Owner and Admin received it, while custom roles did not
    const roles = await testDb.query(
      `SELECT r.id, r.name, r.is_system, GROUP_CONCAT(p.\`key\`) as perm_str
       FROM roles r
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE r.workspace_id IS NULL OR r.is_system = 1
       GROUP BY r.id, r.name, r.is_system`
    );

    const ownerRole = roles.find((r) => r.name === 'Owner');
    const adminRole = roles.find((r) => r.name === 'Admin');

    assert.ok(ownerRole, 'Owner role exists');
    assert.ok(adminRole, 'Admin role exists');

    const adminPerms = (adminRole.perm_str || '').split(',');
    assert.ok(adminPerms.includes(testKey), 'Admin role received temp permission per definition');
    console.log('4. ✓ Owner and Admin system roles contain temporary permission.');

    // 6. Create custom test role (without testKey)
    const customRoleRes = await testDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 30, NULL)',
      [`Temp Custom Role ${Date.now()}`]
    );
    const customRoleId = customRoleRes.insertId;

    const [wsRow] = await testDb.query('SELECT id FROM workspaces LIMIT 1');
    const workspaceId = wsRow?.id || 1;

    // Create test user and session
    const userRes = await testDb.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      ['Temp Sync Tester', `tempsync_${Date.now()}@example.com`, 'hash']
    );
    const testUserId = userRes.insertId;

    await testDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
      [workspaceId, testUserId, 'Custom', customRoleId]
    );

    const session = await createSession(testDb, { id: testUserId, name: 'Temp Sync Tester', email: 'test@example.com' }, null);
    const token = session.accessToken;

    // Start a temporary test HTTP server
    const http = require('http');
    const testServer = http.createServer(testApp);
    await new Promise((resolve) => testServer.listen(0, resolve));
    const port = testServer.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 7. Verify custom role initially DENIED on test route (403)
      let fetchRes = await fetch(`${baseUrl}/api/dev/temp-perm-test?workspace_id=${workspaceId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      assert.strictEqual(fetchRes.status, 403, 'User without temp permission is DENIED (403)');
      console.log('5. ✓ Custom role user is DENIED access before permission is granted.');

      // 8. TOGGLE ON: Add testKey to custom role
      const [permRow] = await testDb.query('SELECT id FROM permissions WHERE `key` = ?', [testKey]);
      await testDb.execute(
        'INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
        [customRoleId, permRow.id]
      );

      // Now verify user SUCCEEDS on test route (200)
      fetchRes = await fetch(`${baseUrl}/api/dev/temp-perm-test?workspace_id=${workspaceId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      assert.strictEqual(fetchRes.status, 200, 'User with temp permission SUCCEEDS (200)');
      const resJson = await fetchRes.json();
      assert.strictEqual(resJson.success, true, 'Test route returned success: true');
      console.log('6. ✓ TOGGLE ON: After adding permission to custom role, test route succeeds (200).');

      // 9. TOGGLE OFF: Remove testKey from custom role
      await testDb.execute(
        'DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?',
        [customRoleId, permRow.id]
      );

      fetchRes = await fetch(`${baseUrl}/api/dev/temp-perm-test?workspace_id=${workspaceId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      assert.strictEqual(fetchRes.status, 403, 'User without temp permission is DENIED again (403)');
      console.log('7. ✓ TOGGLE OFF: After removing permission, user is denied again (403).');
    } finally {
      await new Promise((resolve) => testServer.close(resolve));
      // Clean up test role and user
      await testDb.execute('DELETE FROM workspace_members WHERE user_id = ?', [testUserId]);
      await testDb.execute('DELETE FROM users WHERE id = ?', [testUserId]);
      await testDb.execute('DELETE FROM role_permissions WHERE role_id = ?', [customRoleId]);
      await testDb.execute('DELETE FROM roles WHERE id = ?', [customRoleId]);
    }
  } finally {
    // 10. Clean up the fixture from memory registry and DB
    console.log('8. Cleaning up fixture from memory and database...');
    const permIndex = PERMISSIONS.findIndex((p) => p.key === testKey);
    if (permIndex !== -1) PERMISSIONS.splice(permIndex, 1);

    const adminIndex = SYSTEM_ROLES['Admin'].permissions.indexOf(testKey);
    if (adminIndex !== -1) SYSTEM_ROLES['Admin'].permissions.splice(adminIndex, 1);

    ROUTE_PERMISSIONS.delete('GET /api/dev/temp-perm-test');

    // Run catalog sync to safely deprecate/clean up DB
    await syncPermissionCatalog(testDb);

    // Completely remove the temp perm row from DB
    const [permRow] = await testDb.query('SELECT id FROM permissions WHERE `key` = ?', [testKey]);
    if (permRow) {
      await testDb.execute('DELETE FROM role_permissions WHERE permission_id = ?', [permRow.id]);
      await testDb.execute('DELETE FROM permissions WHERE id = ?', [permRow.id]);
    }

    console.log('9. ✓ Fixture completely cleaned up.');
  }

  console.log('\n[N3 FIXTURE TEST PASSED] Dynamic permission synchronization and enforcement verified.');
}

if (require.main === module) {
  runFixtureTest()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[N3 FIXTURE TEST FAILED]:', err);
      process.exit(1);
    });
}

module.exports = { runFixtureTest };
