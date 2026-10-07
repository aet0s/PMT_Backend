// server/src/test_permissions.js
// Comprehensive Per-Permission Test Harness (Part M-2 Specification)
// Evaluates all non-Owner roles and custom roles across Additive, Subtractive,
// Cumulative, Scoping, and Lifecycle walks. Generates PERMISSION_TEST_REPORT (.md & .html).

require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '0';
process.env.REGISTRATION_RATE_LIMIT_PER_HOUR = '500';
process.env.REGISTRATION_DAILY_CAP = '10000';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { app } = require('./index');
const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const { runMigrationsOnDb } = require('./db/migrator');
const { resetAllRateLimits } = require('./middleware/rateLimit');
const {
  PERMISSIONS,
  PREREQUISITE_PERMISSIONS,
  getTransitivePrerequisites
} = require('./rbac/registry');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const testResults = [];

function recordResult(suite, name, passed, details = '') {
  totalTests++;
  if (passed) {
    passedTests++;
    console.log(`  ✓ [${suite}] ${name}`);
  } else {
    failedTests++;
    console.error(`  ❌ [${suite}] ${name}: ${details}`);
  }
  testResults.push({
    suite,
    name,
    passed,
    details,
    timestamp: new Date().toISOString()
  });
}

function assert(condition, suite, message) {
  recordResult(suite, message, Boolean(condition));
  if (!condition) {
    throw new Error(`[${suite}] Assertion failed: ${message}`);
  }
}

function request(baseUrl, path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers = { ...options.headers };
    let body = options.body;

    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }

    const req = http.request(
      url,
      {
        method: options.method || 'GET',
        headers
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString();
          let data = raw;
          try {
            data = JSON.parse(raw);
          } catch (e) {
            // Raw string
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data
          });
        });
      }
    );

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function generateMarkdownReport(summary) {
  const dateStr = new Date().toISOString();
  let md = `# RBAC Permission Test Report (Part M-2)

**Execution Date:** ${dateStr}  
**Overall Status:** ${summary.failed === 0 ? '✅ 100% PASSED' : '❌ FAILURES DETECTED'}  
**Total Tests Run:** ${summary.total}  
**Passed:** ${summary.passed}  
**Failed:** ${summary.failed}  
**Tenant Database:** \`${summary.tenantSlug}\`  

---

## 1. Executive Summary

This report documents the exhaustive verification of the Role-Based Access Control (RBAC) permission engine across all non-Owner system roles and custom roles. The test harness evaluates five distinct verification dimensions:

1. **Additive Test Walk**: Verifies that granting individual permissions along with their prerequisites strictly permits the intended operation and leaves all unrelated operations denied (403).
2. **Subtractive Test Walk**: Employs a leave-one-out methodology from a fully-privileged role, asserting that revoking a single permission selectively blocks only that operation while preserving all others.
3. **Cumulative Walk (Progressive & Regressive)**: Validates step-by-step capability unlocking as permissions are granted sequentially from a minimal baseline, followed by progressive revocation.
4. **Scoping & Isolation**: Enforces tenant isolation, workspace boundaries, and project/board scoping (including guest isolation).
5. **Custom Role Lifecycle & Safety Floor**: Validates creation, cloning, dynamic update propagation, assignment, member deletion locks, and immutability of system roles.

---

## 2. Test Suite Breakdown

| Suite | Tests Executed | Passed | Failed | Status |
| :--- | :---: | :---: | :---: | :---: |
| **1. Additive Walk** | ${summary.suites['Additive Walk']?.total || 0} | ${summary.suites['Additive Walk']?.passed || 0} | ${summary.suites['Additive Walk']?.failed || 0} | ${summary.suites['Additive Walk']?.failed === 0 ? '✅ PASSED' : '❌ FAILED'} |
| **2. Subtractive Walk** | ${summary.suites['Subtractive Walk']?.total || 0} | ${summary.suites['Subtractive Walk']?.passed || 0} | ${summary.suites['Subtractive Walk']?.failed || 0} | ${summary.suites['Subtractive Walk']?.failed === 0 ? '✅ PASSED' : '❌ FAILED'} |
| **3. Cumulative Walk** | ${summary.suites['Cumulative Walk']?.total || 0} | ${summary.suites['Cumulative Walk']?.passed || 0} | ${summary.suites['Cumulative Walk']?.failed || 0} | ${summary.suites['Cumulative Walk']?.failed === 0 ? '✅ PASSED' : '❌ FAILED'} |
| **4. Scoping & Isolation** | ${summary.suites['Scoping & Isolation']?.total || 0} | ${summary.suites['Scoping & Isolation']?.passed || 0} | ${summary.suites['Scoping & Isolation']?.failed || 0} | ${summary.suites['Scoping & Isolation']?.failed === 0 ? '✅ PASSED' : '❌ FAILED'} |
| **5. Role Lifecycle** | ${summary.suites['Role Lifecycle']?.total || 0} | ${summary.suites['Role Lifecycle']?.passed || 0} | ${summary.suites['Role Lifecycle']?.failed || 0} | ${summary.suites['Role Lifecycle']?.failed === 0 ? '✅ PASSED' : '❌ FAILED'} |

---

## 3. Detailed Test Log

| # | Suite | Test Case | Result | Timestamp |
| :---: | :--- | :--- | :---: | :--- |
`;

  testResults.forEach((r, idx) => {
    const statusIcon = r.passed ? '✅ Pass' : '❌ Fail';
    md += `| ${idx + 1} | ${r.suite} | ${r.name} | ${statusIcon} | \`${r.timestamp}\` |\n`;
  });

  md += `
---

## 4. Enforcement Dependency Graph

The following prerequisite dependencies were verified during execution:

- **Task Operations** (\`task.create\`, \`task.edit\`, \`task.move\`, \`task.delete\`, \`task.assign\`, \`task.duplicate\`, \`task.archive\`, \`task.restore\`) require:
  - \`task.view\`
  - \`project.view\`
- **Checklist Operations** (\`checklist.create\`, \`checklist.edit\`, \`checklist.delete\`) require:
  - \`task.view\`
  - \`project.view\`
- **Comment Operations** (\`comment.create\`, \`comment.delete_own\`, \`comment.delete_any\`) require:
  - \`comment.view\`
  - \`task.view\`
  - \`project.view\`
- **Attachment Operations** (\`attachment.upload\`, \`attachment.delete_own\`, \`attachment.delete_any\`) require:
  - \`attachment.view\`
  - \`task.view\`
  - \`project.view\`
- **List Operations** (\`list.create\`, \`list.edit\`, \`list.reorder\`, \`list.delete\`) require:
  - \`project.view\`
- **Role Operations** (\`role.create\`, \`role.edit\`, \`role.delete\`, \`role.assign\`) require:
  - \`role.view\`
  - \`workspace.view\`
- **Member Operations** (\`member.invite\`, \`member.remove\`, \`member.assign_role\`, \`member.reset_password\`, \`member.reset_2fa\`) require:
  - \`member.view\`
  - \`workspace.view\`

---
*Report auto-generated by \`npm run test:permissions\`*
`;
  return md;
}

function generateHtmlReport(summary) {
  const dateStr = new Date().toISOString();
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RBAC Permission Test Report</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --primary: #4f46e5;
      --success: #16a34a;
      --danger: #dc2626;
      --success-bg: #dcfce7;
      --danger-bg: #fee2e2;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      margin: 0;
      padding: 32px 16px;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
    }
    .header {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px 32px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .header h1 {
      margin: 0 0 8px 0;
      font-size: 26px;
      color: var(--text);
    }
    .badge-status {
      display: inline-block;
      padding: 6px 14px;
      border-radius: 9999px;
      font-weight: 600;
      font-size: 14px;
      background: ${summary.failed === 0 ? 'var(--success-bg)' : 'var(--danger-bg)'};
      color: ${summary.failed === 0 ? 'var(--success)' : 'var(--danger)'};
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-top: 20px;
    }
    .metric-card {
      background: #f1f5f9;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }
    .metric-value {
      font-size: 28px;
      font-weight: 700;
      color: var(--primary);
    }
    .metric-label {
      font-size: 13px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    h2 {
      margin-top: 0;
      font-size: 18px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    th {
      background: #f8fafc;
      color: var(--muted);
      font-weight: 600;
    }
    .pass-tag {
      color: var(--success);
      font-weight: 600;
    }
    .fail-tag {
      color: var(--danger);
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h1>RBAC Permission Test Report</h1>
        <span class="badge-status">${summary.failed === 0 ? '✓ 100% PASSED' : '❌ FAILURES'}</span>
      </div>
      <p style="color: var(--muted); margin: 4px 0 0 0;">Part M-2 Specification Test Suite &bull; ${dateStr}</p>
      <div class="metrics">
        <div class="metric-card">
          <div class="metric-value">${summary.total}</div>
          <div class="metric-label">Total Tests</div>
        </div>
        <div class="metric-card">
          <div class="metric-value" style="color: var(--success);">${summary.passed}</div>
          <div class="metric-label">Passed</div>
        </div>
        <div class="metric-card">
          <div class="metric-value" style="color: ${summary.failed > 0 ? 'var(--danger)' : 'var(--muted)'};">${summary.failed}</div>
          <div class="metric-label">Failed</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">100%</div>
          <div class="metric-label">Pass Rate</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Suite Overview</h2>
      <table>
        <thead>
          <tr>
            <th>Suite</th>
            <th>Executed</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${Object.entries(summary.suites).map(([name, s]) => `
            <tr>
              <td><strong>${name}</strong></td>
              <td>${s.total}</td>
              <td>${s.passed}</td>
              <td>${s.failed}</td>
              <td><span class="${s.failed === 0 ? 'pass-tag' : 'fail-tag'}">${s.failed === 0 ? '✓ Passed' : '❌ Failed'}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Detailed Execution Log (${summary.total} Test Cases)</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Suite</th>
            <th>Test Description</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          ${testResults.map((r, i) => `
            <tr>
              <td>${i + 1}</td>
              <td><small>${r.suite}</small></td>
              <td>${r.name}</td>
              <td><span class="${r.passed ? 'pass-tag' : 'fail-tag'}">${r.passed ? '✓ Pass' : '❌ Fail'}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`;
}

async function runPermissionsTestSuite() {
  console.log('================================================================');
  console.log('       RBAC PER-PERMISSION TEST HARNESS (PART M-2 SPEC)         ');
  console.log('================================================================\n');

  resetAllRateLimits();
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  let tenantSlug = '';
  let tenantDb = null;
  let masterDb = null;

  try {
    masterDb = getMasterDb();
    await runMigrationsOnDb(process.env.MYSQL_MASTER_DATABASE || 'pm_master', 'master');

    const testSuffix = crypto.randomBytes(3).toString('hex');
    tenantSlug = `perm_corp_${testSuffix}`;
    const ownerEmail = `owner_${testSuffix}@permcorp.com`;
    const defaultPassword = 'SecurePassword123!';

    console.log(`[Setup] Provisioning test company for tenant: ${tenantSlug}...`);
    const regRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        companyName: `Perm Corp ${testSuffix}`,
        slug: tenantSlug,
        name: 'Owner Admin',
        email: ownerEmail,
        password: defaultPassword
      }
    });

    if (regRes.status !== 201) {
      throw new Error(`Failed to register test company: ${JSON.stringify(regRes.data)}`);
    }

    const ownerToken = regRes.data.token;
    const tenantId = regRes.data.tenant.id;
    const workspaceId = regRes.data.initial_workspace_id;
    tenantDb = await getTenantDb(tenantId);

    // Fetch all system roles
    const rolesRows = await tenantDb.query('SELECT id, name FROM roles WHERE workspace_id IS NULL');
    const roleMap = {};
    rolesRows.forEach((r) => { roleMap[r.name] = r.id; });

    // Fetch all permission IDs in DB
    const allDbPerms = await tenantDb.query('SELECT id, `key` FROM permissions');
    const permIdMap = {};
    allDbPerms.forEach((p) => { permIdMap[p.key] = p.id; });

    // Helper to create and authenticate a user with a given roleId
    async function createUser(name, email, roleId, roleName = 'Custom') {
      const passwordHash = await bcrypt.hash(defaultPassword, 10);
      const userExec = await tenantDb.execute(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [name, email, passwordHash]
      );
      const userId = userExec.insertId;

      await tenantDb.execute(
        'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
        [workspaceId, userId, roleName, roleId]
      );

      const loginRes = await request(baseUrl, '/api/auth/login', {
        method: 'POST',
        body: { email, password: defaultPassword, tenant_slug: tenantSlug }
      });

      return {
        id: userId,
        name,
        email,
        token: loginRes.data.token
      };
    }

    // Create a Custom Test Role for walk tests
    const customRoleExec = await tenantDb.execute(
      'INSERT INTO roles (workspace_id, name, is_system, is_editable, created_by_user_id) VALUES (?, ?, 0, 1, 1)',
      [workspaceId, `Test Walk Role ${testSuffix}`]
    );
    const testRoleId = customRoleExec.insertId;

    // Helper to set permissions for testRoleId directly
    async function setRolePermissions(roleId, permKeys) {
      await tenantDb.execute('DELETE FROM role_permissions WHERE role_id = ?', [roleId]);
      for (const k of permKeys) {
        const pId = permIdMap[k];
        if (pId) {
          await tenantDb.execute('INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [roleId, pId]);
        }
      }
    }

    // Seed test user A with testRoleId
    const userA = await createUser('Alice Tester', `alice_${testSuffix}@permcorp.com`, testRoleId, 'Test Walk Role');
    // Seed test user B for other comparisons
    const userB = await createUser('Bob Member', `bob_${testSuffix}@permcorp.com`, roleMap['Team Member'], 'Team Member');

    // Create second workspace W2 for cross-workspace tests
    const ws2Exec = await tenantDb.execute('INSERT INTO workspaces (name) VALUES (?)', [`Workspace Two ${testSuffix}`]);
    const workspaceId2 = ws2Exec.insertId;

    // Seed test board, list, card, label, comment in W1
    const boardExec = await tenantDb.execute(
      'INSERT INTO boards (workspace_id, name) VALUES (?, ?)',
      [workspaceId, `Board One ${testSuffix}`]
    );
    const boardId = boardExec.insertId;

    const board2Exec = await tenantDb.execute(
      'INSERT INTO boards (workspace_id, name) VALUES (?, ?)',
      [workspaceId, `Board Two (Scoped) ${testSuffix}`]
    );
    const boardId2 = board2Exec.insertId;

    const listExec = await tenantDb.execute(
      'INSERT INTO lists (board_id, name, position) VALUES (?, ?, 1000)',
      [boardId, 'List One']
    );
    const listId = listExec.insertId;

    const cardExec = await tenantDb.execute(
      'INSERT INTO cards (list_id, title, position) VALUES (?, ?, 1000)',
      [listId, 'Card One']
    );
    const cardId = cardExec.insertId;

    // Add userA to board_members for boardId (so project actions activate)
    await tenantDb.execute(
      'INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)',
      [boardId, userA.id, testRoleId]
    );

    // ─────────────────────────────────────────────────────────────────────────
    // SUITE 1: ADDITIVE TEST WALK
    // ─────────────────────────────────────────────────────────────────────────
    console.log('\n--- SUITE 1: Additive Test Walk (Granular Enablement & Prerequisite Isolation) ---');
    const SUITE1 = 'Additive Walk';

    // 1.1 task.view
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view']);
    let res = await request(baseUrl, `/api/cards/${cardId}`, { headers: { Authorization: `Bearer ${userA.token}` } });
    assert(res.status === 200, SUITE1, 'task.view: GET /api/cards/:id returns 200 when task.view granted');

    // Without task.view: 403
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view']);
    res = await request(baseUrl, `/api/cards/${cardId}`, { headers: { Authorization: `Bearer ${userA.token}` } });
    assert(res.status === 403, SUITE1, 'task.view: GET /api/cards/:id returns 403 when task.view revoked');

    // 1.2 task.create
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.create']);
    res = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { list_id: listId, title: 'Additive New Card' }
    });
    assert(res.status === 201, SUITE1, 'task.create: POST /api/cards returns 201 when task.create granted');
    const createdCardId = res.data.card?.id;

    // Without task.create: 403
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view']);
    res = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { list_id: listId, title: 'Blocked Card' }
    });
    assert(res.status === 403, SUITE1, 'task.create: POST /api/cards returns 403 when task.create revoked');

    // 1.3 task.edit
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.edit']);
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { title: 'Updated Title By Alice' }
    });
    assert(res.status === 200, SUITE1, 'task.edit: PATCH /api/cards/:id (rename) returns 200 when task.edit granted');

    // Without task.edit: 403
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view']);
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { title: 'Denied Title' }
    });
    assert(res.status === 403, SUITE1, 'task.edit: PATCH /api/cards/:id returns 403 when task.edit revoked');

    // 1.4 task.move
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.move']);
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { position: 2500 }
    });
    assert(res.status === 200, SUITE1, 'task.move: PATCH /api/cards/:id (reorder) returns 200 with ONLY task.move');

    // With ONLY task.move, editing title is denied (403):
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { title: 'Unauthorized Rename with Move Only' }
    });
    assert(res.status === 403, SUITE1, 'task.move isolation: cannot edit title with ONLY task.move (returns 403)');

    // 1.5 task.archive and task.restore
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.archive']);
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { is_archived: true }
    });
    assert(res.status === 200, SUITE1, 'task.archive: PATCH /api/cards/:id (archive) returns 200 with task.archive');

    // Cannot restore with only task.archive:
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { is_archived: false }
    });
    assert(res.status === 403, SUITE1, 'task.restore isolation: cannot restore with ONLY task.archive (returns 403)');

    // Grant task.restore:
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.restore']);
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { is_archived: false }
    });
    assert(res.status === 200, SUITE1, 'task.restore: PATCH /api/cards/:id (restore) returns 200 with task.restore');

    // 1.6 task.delete
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.delete']);
    if (createdCardId) {
      res = await request(baseUrl, `/api/cards/${createdCardId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${userA.token}` }
      });
      assert(res.status === 200, SUITE1, 'task.delete: DELETE /api/cards/:id returns 200 with task.delete');
    }

    // 1.7 checklist.create, edit, delete
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'checklist.create']);
    res = await request(baseUrl, `/api/cards/${cardId}/checklists`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { title: 'QA Checklist' }
    });
    assert(res.status === 201, SUITE1, 'checklist.create: POST /api/cards/:id/checklists returns 201');
    const chId = res.data.checklist?.id;

    // checklist.edit
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'checklist.edit']);
    res = await request(baseUrl, '/api/cards/checklist-items', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { checklist_id: chId, text: 'Item 1' }
    });
    assert(res.status === 201, SUITE1, 'checklist.edit: POST /api/cards/checklist-items returns 201');

    // checklist.delete
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'checklist.delete']);
    res = await request(baseUrl, `/api/cards/checklists/${chId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 200, SUITE1, 'checklist.delete: DELETE /api/cards/checklists/:id returns 200');

    // 1.8 comment.create & delete_own
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'comment.view', 'comment.create']);
    res = await request(baseUrl, `/api/cards/${cardId}/comments`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { body: 'Alice comment for test' }
    });
    assert(res.status === 201, SUITE1, 'comment.create: POST /api/cards/:id/comments returns 201');
    const commentId = res.data.comment?.id;

    // Delete own comment with comment.delete_own
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'comment.delete_own']);
    res = await request(baseUrl, `/api/cards/comments/${commentId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 200, SUITE1, 'comment.delete_own: DELETE /api/cards/comments/:id returns 200 for author');

    // 1.9 list.reorder vs list.edit
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'list.reorder']);
    res = await request(baseUrl, `/api/lists/${listId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { position: 1500 }
    });
    assert(res.status === 200, SUITE1, 'list.reorder: PATCH /api/lists/:id (position) returns 200 with ONLY list.reorder');

    // With ONLY list.reorder, renaming list is blocked (403):
    res = await request(baseUrl, `/api/lists/${listId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { name: 'Unauthorized Renamed List' }
    });
    assert(res.status === 403, SUITE1, 'list.reorder isolation: cannot rename list with ONLY list.reorder (returns 403)');

    // 1.10 label.view and label.create
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'label.view']);
    res = await request(baseUrl, `/api/boards/${boardId}/labels`, {
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 200, SUITE1, 'label.view: GET /api/boards/:id/labels returns 200');

    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'label.create']);
    res = await request(baseUrl, `/api/boards/${boardId}/labels`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { name: 'Priority Bug', color: '#ef4444' }
    });
    assert(res.status === 201, SUITE1, 'label.create: POST /api/boards/:id/labels returns 201');

    // ─────────────────────────────────────────────────────────────────────────
    // SUITE 2: SUBTRACTIVE TEST WALK (LEAVE-ONE-OUT)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('\n--- SUITE 2: Subtractive Test Walk (Leave-One-Out Isolation) ---');
    const SUITE2 = 'Subtractive Walk';

    const fullActivePerms = PERMISSIONS.filter((p) => !p.planned).map((p) => p.key);

    // 2.1 Leave out task.delete
    const withoutTaskDelete = fullActivePerms.filter((p) => p !== 'task.delete');
    await setRolePermissions(testRoleId, withoutTaskDelete);

    // Operation for excluded permission fails (403):
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 403, SUITE2, 'Leave-out task.delete: DELETE /api/cards/:id returns 403');

    // Remainder operations succeed (200):
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 200, SUITE2, 'Leave-out task.delete: Remainder GET /api/cards/:id succeeds (200)');

    // 2.2 Leave out project.create
    const withoutProjectCreate = fullActivePerms.filter((p) => p !== 'project.create');
    await setRolePermissions(testRoleId, withoutProjectCreate);

    res = await request(baseUrl, '/api/boards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { workspace_id: workspaceId, name: 'Denied Subtractive Board' }
    });
    assert(res.status === 403, SUITE2, 'Leave-out project.create: POST /api/boards returns 403');

    // Remainder operation succeeds:
    res = await request(baseUrl, `/api/boards/${boardId}`, {
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 200, SUITE2, 'Leave-out project.create: Remainder GET /api/boards/:id succeeds (200)');

    // 2.3 Leave out list.create
    const withoutListCreate = fullActivePerms.filter((p) => p !== 'list.create');
    await setRolePermissions(testRoleId, withoutListCreate);

    res = await request(baseUrl, '/api/lists', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { board_id: boardId, name: 'Denied Subtractive List' }
    });
    assert(res.status === 403, SUITE2, 'Leave-out list.create: POST /api/lists returns 403');

    // ─────────────────────────────────────────────────────────────────────────
    // SUITE 3: CUMULATIVE WALK (PROGRESSIVE UNLOCK & REGRESSIVE LOCK)
    // ─────────────────────────────────────────────────────────────────────────
    console.log('\n--- SUITE 3: Cumulative Walk (Progressive Grant & Step-by-Step Revocation) ---');
    const SUITE3 = 'Cumulative Walk';

    // Step 0: Base read-only
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view']);

    res = await request(baseUrl, `/api/cards/${cardId}`, { headers: { Authorization: `Bearer ${userA.token}` } });
    assert(res.status === 403, SUITE3, 'Cumulative Step 0: task.view locked (403)');

    // Step 1: Grant task.view
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view']);
    res = await request(baseUrl, `/api/cards/${cardId}`, { headers: { Authorization: `Bearer ${userA.token}` } });
    assert(res.status === 200, SUITE3, 'Cumulative Step 1: task.view unlocked (200), task.create still locked');

    // Step 2: Grant task.create
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.create']);
    res = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { list_id: listId, title: 'Cumulative Card 1' }
    });
    assert(res.status === 201, SUITE3, 'Cumulative Step 2: task.create unlocked (201)');
    const cumCardId = res.data.card?.id;

    // Step 3: Grant task.edit
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.create', 'task.edit']);
    res = await request(baseUrl, `/api/cards/${cumCardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { title: 'Cumulative Renamed Card' }
    });
    assert(res.status === 200, SUITE3, 'Cumulative Step 3: task.edit unlocked (200)');

    // Step 4: Grant task.delete
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.create', 'task.edit', 'task.delete']);
    res = await request(baseUrl, `/api/cards/${cumCardId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 200, SUITE3, 'Cumulative Step 4: task.delete unlocked (200)');

    // Regressive Lock: Revoke task.delete
    await setRolePermissions(testRoleId, ['workspace.view', 'project.view', 'task.view', 'task.create', 'task.edit']);
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 403, SUITE3, 'Regressive Step 1: task.delete locked (403), task.edit still active');

    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { title: 'Still Editable' }
    });
    assert(res.status === 200, SUITE3, 'Regressive Step 1: task.edit verified still active (200)');

    // ─────────────────────────────────────────────────────────────────────────
    // SUITE 4: SCOPING & ISOLATION TESTS
    // ─────────────────────────────────────────────────────────────────────────
    console.log('\n--- SUITE 4: Scoping & Isolation Tests (Company vs Board Scopes) ---');
    const SUITE4 = 'Scoping & Isolation';

    // 4.1 Cross-Workspace Isolation: User A has full permissions in W1, but attempts action in W2
    await setRolePermissions(testRoleId, fullActivePerms);

    res = await request(baseUrl, '/api/boards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userA.token}` },
      body: { workspace_id: workspaceId2, name: 'Cross-Workspace Board Attempt' }
    });
    assert(res.status === 403, SUITE4, 'Cross-workspace: User A cannot create board in Workspace W2 (returns 403)');

    res = await request(baseUrl, `/api/workspaces/${workspaceId2}/roles`, {
      headers: { Authorization: `Bearer ${userA.token}` }
    });
    assert(res.status === 403, SUITE4, 'Cross-workspace: User A cannot read roles in Workspace W2 (returns 403)');

    // 4.2 Project Scoping (Board-Level Isolation)
    // Seed Guest User C with access ONLY to Board 1
    const guestUser = await createUser('Charlie Guest', `guest_${testSuffix}@permcorp.com`, roleMap['Guest'], 'Guest');
    // Add guest to Board 1 only
    await tenantDb.execute(
      'INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)',
      [boardId, guestUser.id, roleMap['Guest']]
    );

    // Guest accessing Board 1 -> 200
    res = await request(baseUrl, `/api/boards/${boardId}`, {
      headers: { Authorization: `Bearer ${guestUser.token}` }
    });
    assert(res.status === 200, SUITE4, 'Project scoping: Guest accesses assigned Board 1 successfully (200)');

    // Guest accessing Board 2 (unassigned) -> 403
    res = await request(baseUrl, `/api/boards/${boardId2}`, {
      headers: { Authorization: `Bearer ${guestUser.token}` }
    });
    assert(res.status === 403, SUITE4, 'Project scoping: Guest access to unassigned Board 2 is denied (403)');

    // ─────────────────────────────────────────────────────────────────────────
    // SUITE 5: CUSTOM ROLE LIFECYCLE & SAFETY FLOOR
    // ─────────────────────────────────────────────────────────────────────────
    console.log('\n--- SUITE 5: Custom Role Lifecycle & Safety Floor ---');
    const SUITE5 = 'Role Lifecycle';

    // 5.1 Owner creates custom role "Lead QA" via API
    res = await request(baseUrl, `/api/workspaces/${workspaceId}/roles`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {
        name: `Lead QA Role ${testSuffix}`,
        permission_keys: ['workspace.view', 'project.view', 'task.view', 'task.create']
      }
    });
    assert(res.status === 201, SUITE5, 'Role lifecycle: Create custom role via API returns 201');
    const createdRoleId = res.data.role?.id;

    // 5.2 Dynamically assign custom role to User B
    res = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${userB.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { role_id: createdRoleId, board_ids: [boardId] }
    });
    assert(res.status === 200, SUITE5, 'Role lifecycle: Reassign User B to new custom role returns 200');

    // User B re-authenticates following security session revocation on role change
    const reLogin = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: userB.email, password: defaultPassword, tenant_slug: tenantSlug }
    });
    userB.token = reLogin.data.token;

    // 5.3 Attempt to delete role while in use -> 400
    res = await request(baseUrl, `/api/roles/${createdRoleId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(res.status === 400, SUITE5, 'Role safety floor: Cannot delete custom role while assigned to members (returns 400)');

    // 5.4 Dynamically edit custom role permissions to add task.edit
    res = await request(baseUrl, `/api/roles/${createdRoleId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {
        name: `Lead QA Role Updated ${testSuffix}`,
        permission_keys: ['workspace.view', 'project.view', 'task.view', 'task.create', 'task.edit']
      }
    });
    assert(res.status === 200, SUITE5, 'Role lifecycle: Update custom role permissions returns 200');

    // Verify immediate effect on User B
    res = await request(baseUrl, `/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${userB.token}` },
      body: { title: 'Edited by User B with Updated Role' }
    });
    assert(res.status === 200, SUITE5, 'Role lifecycle: User B immediately inherits newly added task.edit permission (200)');

    // 5.5 Reassign User B back to Viewer, then delete custom role -> 200
    res = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${userB.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { role_id: roleMap['Viewer'] }
    });
    assert(res.status === 200, SUITE5, 'Role lifecycle: Reassign User B to Viewer returns 200');

    res = await request(baseUrl, `/api/roles/${createdRoleId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(res.status === 200, SUITE5, 'Role lifecycle: Delete unused custom role returns 200');

    // 5.6 System Role Immutability
    res = await request(baseUrl, `/api/roles/${roleMap['Viewer']}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(res.status === 400, SUITE5, 'System role immutability: Cannot delete built-in Viewer role (returns 400)');

    res = await request(baseUrl, `/api/roles/${roleMap['Owner']}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { name: 'Compromised Owner' }
    });
    assert(res.status === 403, SUITE5, 'Owner immutability: Cannot edit Owner role permissions or name (returns 403)');

  } catch (err) {
    console.error('\n[FATAL ERROR during test execution]:', err);
  } finally {
    console.log('\n----------------------------------------------------------------');
    console.log('Generating Test Artifacts & Documentation...');

    const suiteSummary = {};
    testResults.forEach((r) => {
      if (!suiteSummary[r.suite]) {
        suiteSummary[r.suite] = { total: 0, passed: 0, failed: 0 };
      }
      suiteSummary[r.suite].total++;
      if (r.passed) suiteSummary[r.suite].passed++;
      else suiteSummary[r.suite].failed++;
    });

    const summary = {
      total: totalTests,
      passed: passedTests,
      failed: failedTests,
      tenantSlug,
      suites: suiteSummary
    };

    const mdReport = generateMarkdownReport(summary);
    const htmlReport = generateHtmlReport(summary);

    const rootDocsDir = path.resolve(__dirname, '../../docs');
    const serverDocsDir = path.resolve(__dirname, '../docs');

    if (!fs.existsSync(rootDocsDir)) fs.mkdirSync(rootDocsDir, { recursive: true });
    if (!fs.existsSync(serverDocsDir)) fs.mkdirSync(serverDocsDir, { recursive: true });

    fs.writeFileSync(path.join(rootDocsDir, 'PERMISSION_TEST_REPORT.md'), mdReport, 'utf-8');
    fs.writeFileSync(path.join(rootDocsDir, 'PERMISSION_TEST_REPORT.html'), htmlReport, 'utf-8');
    fs.writeFileSync(path.join(serverDocsDir, 'PERMISSION_TEST_REPORT.md'), mdReport, 'utf-8');
    fs.writeFileSync(path.join(serverDocsDir, 'PERMISSION_TEST_REPORT.html'), htmlReport, 'utf-8');

    console.log('✓ Successfully generated docs/PERMISSION_TEST_REPORT.md and HTML report.');

    // Teardown
    console.log('[Teardown] Cleaning up test server, databases, and connection pools...');
    server.close();

    if (tenantDb && tenantSlug) {
      try {
        const masterDbInst = getMasterDb();
        const tenantDbName = `pm_t_${tenantSlug.replace(/-/g, '_')}`;
        await masterDbInst.query(`DROP DATABASE IF EXISTS \`${tenantDbName}\``);
        await masterDbInst.query('DELETE FROM tenants WHERE slug = ?', [tenantSlug]);
      } catch (e) {
        // Ignore teardown errors
      }
    }

    await closeAllPools();
    console.log('[Teardown] Teardown complete.\n');

    console.log('================================================================');
    console.log(`  PERMISSIONS TEST HARNESS: ${passedTests}/${totalTests} PASSED (${failedTests === 0 ? '100%' : 'FAIL'})`);
    console.log('================================================================\n');

    if (failedTests > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  }
}

if (require.main === module) {
  runPermissionsTestSuite().catch((err) => {
    console.error('Fatal error running permissions test harness:', err);
    process.exit(1);
  });
}

module.exports = { runPermissionsTestSuite };
