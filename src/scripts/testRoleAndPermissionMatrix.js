// server/src/scripts/testRoleAndPermissionMatrix.js
// Exhaustive verification of all 6 system roles and granular permission matrix toggles.

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '0';
process.env.REGISTRATION_RATE_LIMIT_PER_HOUR = '500';
process.env.REGISTRATION_DAILY_CAP = '10000';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const { app } = require('../index');
const { getTenantDb, closeAllPools } = require('../services/tenantPools');

let server;
let baseUrl;
let tenantDb;
let tenantSlug;

function request(urlPath, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const headers = { ...options.headers };
    let body = options.body;

    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
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
          } catch (e) {}
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

async function main() {
  console.log('========================================================================');
  console.log('  EXHAUSTIVE RBAC ROLES & PERMISSION MATRIX VERIFICATION (SCRATCH RUN)  ');
  console.log('========================================================================\n');

  // Start HTTP server on dynamic port
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });

  const testSuffix = crypto.randomBytes(3).toString('hex');
  tenantSlug = `matrix_corp_${testSuffix}`;
  const ownerEmail = `owner_${testSuffix}@example.com`;
  const defaultPassword = 'SecurePassword123!';

  console.log(`[1] Provisioning test company: ${tenantSlug}...`);
  const regRes = await request('/api/auth/register-company', {
    method: 'POST',
    body: {
      companyName: `Matrix Corp ${testSuffix}`,
      slug: tenantSlug,
      name: 'Corporate Owner',
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

  // Create initial Board & List for task testing
  const boardRes = await request('/api/boards', {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { workspace_id: workspaceId, name: 'Core Board' }
  });
  const coreBoardId = boardRes.data.board.id;

  const listRes = await request('/api/lists', {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { board_id: coreBoardId, name: 'To Do' }
  });
  const coreListId = listRes.data.list.id;

  // Fetch all system roles
  const rolesRows = await tenantDb.query('SELECT id, name FROM roles WHERE workspace_id IS NULL');
  const roleMap = {};
  rolesRows.forEach((r) => { roleMap[r.name] = r.id; });

  // Create member helper
  async function createMember(name, email, roleName) {
    const roleId = roleMap[roleName];
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

    // Also add to core board
    await tenantDb.execute(
      'INSERT INTO board_members (board_id, user_id) VALUES (?, ?)',
      [coreBoardId, userId]
    );

    const loginRes = await request('/api/auth/login', {
      method: 'POST',
      body: { email, password: defaultPassword, tenant_slug: tenantSlug }
    });

    return {
      id: userId,
      name,
      email,
      token: loginRes.data.token,
      roleId,
      roleName
    };
  }

  // Create target member
  const memberEmail = `member_${testSuffix}@example.com`;
  console.log(`[2] Creating test member: ${memberEmail}...`);
  const member = await createMember('Test Target Member', memberEmail, 'Team Member');

  const summary = [];
  function record(section, testName, expected, actual, passed, details = '') {
    summary.push({ section, testName, expected, actual, passed, details });
    const mark = passed ? '✓' : '❌';
    console.log(`  ${mark} [${section}] ${testName} -> Expected: ${expected}, Got: ${actual} (${passed ? 'PASS' : 'FAIL'})`);
  }

  // --------------------------------------------------------------------------
  // SECTION 1: TEST EACH SYSTEM ROLE ASSIGNMENT & CAPABILITIES
  // --------------------------------------------------------------------------
  console.log('\n========================================================================');
  console.log('  SECTION 1: SYSTEM ROLES ASSIGNMENT & BEHAVIOR CHECK (6 ROLES)');
  console.log('========================================================================');

  const rolesToTest = [
    {
      name: 'Guest',
      canViewActivity: false,
      canCreateBoard: false,
      canDeleteTask: false,
      canInvite: false,
      canCreateRole: false
    },
    {
      name: 'Viewer',
      canViewActivity: true,
      canCreateBoard: false,
      canDeleteTask: false,
      canInvite: false,
      canCreateRole: false
    },
    {
      name: 'Team Member',
      canViewActivity: true, // Specifically tested!
      canCreateBoard: false,
      canDeleteTask: false,
      canInvite: false,
      canCreateRole: false
    },
    {
      name: 'Project Manager',
      canViewActivity: true,
      canCreateBoard: true,
      canDeleteTask: true,
      canInvite: true,
      canCreateRole: false
    },
    {
      name: 'Admin',
      canViewActivity: true,
      canCreateBoard: true,
      canDeleteTask: true,
      canInvite: true,
      canCreateRole: true
    }
  ];

  for (const r of rolesToTest) {
    console.log(`\n--- Assigning Role: ${r.name} ---`);
    // Assign role
    const assignRes = await request(`/api/workspaces/${workspaceId}/members/${member.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { role_id: roleMap[r.name] }
    });
    record('System Roles', `Assign ${r.name}`, 200, assignRes.status, assignRes.status === 200);

    // Check my-permissions endpoint
    const permRes = await request(`/api/workspaces/${workspaceId}/my-permissions`, {
      headers: { Authorization: `Bearer ${member.token}` }
    });
    const assignedRoleName = permRes.data.role?.name || permRes.data.role;
    record('System Roles', `${r.name} my-permissions returns role name`, r.name, assignedRoleName, assignedRoleName === r.name);

    // 1. Activity Feed (GET /api/workspaces/:id/activity)
    const actRes = await request(`/api/workspaces/${workspaceId}/activity?page=1&limit=20`, {
      headers: { Authorization: `Bearer ${member.token}` }
    });
    const expectedActStatus = r.canViewActivity ? 200 : 403;
    record(
      'System Roles',
      `${r.name} activity feed access (GET /activity)`,
      expectedActStatus,
      actRes.status,
      actRes.status === expectedActStatus,
      r.canViewActivity ? 'Allowed' : 'Forbidden'
    );

    // 2. Project Creation (POST /api/boards)
    const createBoardRes = await request('/api/boards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${member.token}` },
      body: { workspace_id: workspaceId, name: `Board by ${r.name}` }
    });
    const expectedBoardStatus = r.canCreateBoard ? 201 : 403;
    record(
      'System Roles',
      `${r.name} create project (POST /boards)`,
      expectedBoardStatus,
      createBoardRes.status,
      createBoardRes.status === expectedBoardStatus
    );
    if (createBoardRes.status === 201) {
      await request(`/api/boards/${createBoardRes.data.board.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${ownerToken}` }
      });
    }

    // 3. Task Deletion (DELETE /api/cards/:id)
    const cardRes = await request('/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { list_id: coreListId, title: `Test Card for ${r.name}` }
    });
    const cardId = cardRes.data.card.id;

    const delCardRes = await request(`/api/cards/${cardId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${member.token}` }
    });
    const expectedDelStatus = r.canDeleteTask ? 200 : 403;
    record(
      'System Roles',
      `${r.name} delete task (DELETE /cards/:id)`,
      expectedDelStatus,
      delCardRes.status,
      delCardRes.status === expectedDelStatus
    );
    if (delCardRes.status !== 200) {
      await request(`/api/cards/${cardId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${ownerToken}` }
      });
    }

    // 4. Member Invite (POST /api/invitations)
    const invRes = await request('/api/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${member.token}` },
      body: { workspace_id: workspaceId, email: `test_${crypto.randomBytes(3).toString('hex')}@test.com` }
    });
    const passedInv = r.canInvite ? [200, 201, 202].includes(invRes.status) : (invRes.status === 403);
    record(
      'System Roles',
      `${r.name} invite member (POST /invitations)`,
      r.canInvite ? '200/201' : 403,
      invRes.status,
      passedInv
    );

    // 5. Create Custom Role (POST /api/workspaces/:id/roles)
    const roleCreateRes = await request(`/api/workspaces/${workspaceId}/roles`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${member.token}` },
      body: { name: `Role by ${r.name}`, permission_keys: ['project.view'] }
    });
    const expectedRoleStatus = r.canCreateRole ? 201 : 403;
    record(
      'System Roles',
      `${r.name} create role (POST /roles)`,
      expectedRoleStatus,
      roleCreateRes.status,
      roleCreateRes.status === expectedRoleStatus
    );
    if (roleCreateRes.status === 201) {
      await request(`/api/roles/${roleCreateRes.data.role.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${ownerToken}` }
      });
    }
  }

  // Also verify Owner on Owner token
  console.log('\n--- Checking Owner Capabilities ---');
  const ownerPermRes = await request(`/api/workspaces/${workspaceId}/my-permissions`, {
    headers: { Authorization: `Bearer ${ownerToken}` }
  });
  record('System Roles', 'Owner my-permissions returns Owner', 'Owner', ownerPermRes.data.role?.name, ownerPermRes.data.role?.name === 'Owner');
  const ownerActRes = await request(`/api/workspaces/${workspaceId}/activity?page=1&limit=20`, {
    headers: { Authorization: `Bearer ${ownerToken}` }
  });
  record('System Roles', 'Owner activity feed access', 200, ownerActRes.status, ownerActRes.status === 200);

  // --------------------------------------------------------------------------
  // SECTION 2: PERMISSION MATRIX TOGGLES (EACH PERMISSION ONE BY ONE)
  // --------------------------------------------------------------------------
  console.log('\n========================================================================');
  console.log('  SECTION 2: PERMISSION MATRIX TOGGLE VERIFICATION (ONE BY ONE)');
  console.log('========================================================================');

  // Create a Custom Role for toggle testing
  const customRoleRes = await request(`/api/workspaces/${workspaceId}/roles`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: {
      name: `Toggle Matrix Role ${testSuffix}`,
      permission_keys: ['project.view', 'task.view'] // Baseline read permissions
    }
  });

  if (customRoleRes.status !== 201) {
    throw new Error(`Failed to create custom role: ${JSON.stringify(customRoleRes.data)}`);
  }
  const customRoleId = customRoleRes.data.role.id;

  // Assign target member to this Custom Role
  await request(`/api/workspaces/${workspaceId}/members/${member.id}/role`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { role_id: customRoleId }
  });

  // Matrix capabilities to test with discrete endpoint execution
  const matrixCapabilities = [
    {
      key: 'activity.view',
      label: 'Activity Feed Viewing',
      execute: async () => {
        return request(`/api/workspaces/${workspaceId}/activity?page=1&limit=20`, {
          headers: { Authorization: `Bearer ${member.token}` }
        });
      },
      successStatus: [200]
    },
    {
      key: 'project.create',
      label: 'Create Project/Board',
      execute: async () => {
        const res = await request('/api/boards', {
          method: 'POST',
          headers: { Authorization: `Bearer ${member.token}` },
          body: { workspace_id: workspaceId, name: `Toggle Board ${Date.now()}` }
        });
        if (res.status === 201) {
          // Cleanup
          await request(`/api/boards/${res.data.board.id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${ownerToken}` }
          });
        }
        return res;
      },
      successStatus: [201]
    },
    {
      key: 'task.create',
      label: 'Create Task/Card',
      execute: async () => {
        const res = await request('/api/cards', {
          method: 'POST',
          headers: { Authorization: `Bearer ${member.token}` },
          body: { list_id: coreListId, title: `Toggle Card ${Date.now()}` }
        });
        if (res.status === 201) {
          // Cleanup
          await request(`/api/cards/${res.data.card.id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${ownerToken}` }
          });
        }
        return res;
      },
      successStatus: [201]
    },
    {
      key: 'task.delete',
      label: 'Delete Task/Card',
      execute: async () => {
        // Create card with owner first
        const cRes = await request('/api/cards', {
          method: 'POST',
          headers: { Authorization: `Bearer ${ownerToken}` },
          body: { list_id: coreListId, title: `Delete Card ${Date.now()}` }
        });
        const cId = cRes.data.card.id;
        const res = await request(`/api/cards/${cId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${member.token}` }
        });
        if (res.status !== 200) {
          await request(`/api/cards/${cId}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${ownerToken}` }
          });
        }
        return res;
      },
      successStatus: [200]
    },
    {
      key: 'member.view',
      label: 'View Workspace Members',
      execute: async () => {
        return request(`/api/workspaces/${workspaceId}/members`, {
          headers: { Authorization: `Bearer ${member.token}` }
        });
      },
      successStatus: [200]
    },
    {
      key: 'member.invite',
      label: 'Invite Workspace Member',
      execute: async () => {
        return request('/api/invitations', {
          method: 'POST',
          headers: { Authorization: `Bearer ${member.token}` },
          body: { workspace_id: workspaceId, email: `toggle_inv_${crypto.randomBytes(3).toString('hex')}@test.com` }
        });
      },
      successStatus: [200, 201, 202]
    },
    {
      key: 'role.create',
      label: 'Create Custom Role',
      execute: async () => {
        const res = await request(`/api/workspaces/${workspaceId}/roles`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${member.token}` },
          body: { name: `Sub Role ${Date.now()}`, permission_keys: ['project.view'] }
        });
        if (res.status === 201) {
          await request(`/api/roles/${res.data.role.id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${ownerToken}` }
          });
        }
        return res;
      },
      successStatus: [201]
    },
    {
      key: 'comment.create',
      label: 'Post Task Comment',
      execute: async () => {
        const cRes = await request('/api/cards', {
          method: 'POST',
          headers: { Authorization: `Bearer ${ownerToken}` },
          body: { list_id: coreListId, title: `Comment Target ${Date.now()}` }
        });
        const cId = cRes.data.card.id;
        const res = await request(`/api/cards/${cId}/comments`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${member.token}` },
          body: { body: 'Test comment' }
        });
        await request(`/api/cards/${cId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${ownerToken}` }
        });
        return res;
      },
      successStatus: [201]
    },
    {
      key: 'checklist.create',
      label: 'Create Card Checklist',
      execute: async () => {
        const cRes = await request('/api/cards', {
          method: 'POST',
          headers: { Authorization: `Bearer ${ownerToken}` },
          body: { list_id: coreListId, title: `Checklist Target ${Date.now()}` }
        });
        const cId = cRes.data.card.id;
        const res = await request(`/api/cards/${cId}/checklists`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${member.token}` },
          body: { title: 'Test Checklist' }
        });
        await request(`/api/cards/${cId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${ownerToken}` }
        });
        return res;
      },
      successStatus: [201]
    },
    {
      key: 'archive.view',
      label: 'View Archived Resources',
      execute: async () => {
        return request(`/api/workspaces/${workspaceId}/archived`, {
          headers: { Authorization: `Bearer ${member.token}` }
        });
      },
      successStatus: [200]
    }
  ];

  for (const cap of matrixCapabilities) {
    console.log(`\nTesting Matrix Toggle for: ${cap.key} (${cap.label})...`);

    // STEP A: TOGGLE PERMISSION ON
    const permsWithCap = Array.from(new Set(['project.view', 'task.view', cap.key]));
    const patchOnRes = await request(`/api/roles/${customRoleId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { permission_keys: permsWithCap, workspace_id: workspaceId }
    });
    record('Permission Matrix', `Toggle ON: ${cap.key} (PATCH /api/roles/:id)`, 200, patchOnRes.status, patchOnRes.status === 200);

    // Verify /my-permissions has the key
    const myPermsOn = await request(`/api/workspaces/${workspaceId}/my-permissions`, {
      headers: { Authorization: `Bearer ${member.token}` }
    });
    const hasKeyOn = (myPermsOn.data.permissions || []).includes(cap.key);
    record('Permission Matrix', `Check /my-permissions includes ${cap.key} when ON`, true, hasKeyOn, hasKeyOn === true);

    // Test API call when ON -> MUST SUCCEED (200/201/202)
    const execOnRes = await cap.execute();
    const isAllowedOn = cap.successStatus.includes(execOnRes.status);
    record(
      'Permission Matrix',
      `Execute ${cap.label} when ${cap.key} is ON`,
      cap.successStatus.join('/'),
      execOnRes.status,
      isAllowedOn,
      `Received ${execOnRes.status}`
    );

    // STEP B: TOGGLE PERMISSION OFF
    const permsWithoutCap = ['project.view', 'task.view'].filter((k) => k !== cap.key);
    const patchOffRes = await request(`/api/roles/${customRoleId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { permission_keys: permsWithoutCap, workspace_id: workspaceId }
    });
    record('Permission Matrix', `Toggle OFF: ${cap.key} (PATCH /api/roles/:id)`, 200, patchOffRes.status, patchOffRes.status === 200);

    // Verify /my-permissions NO LONGER has the key
    const myPermsOff = await request(`/api/workspaces/${workspaceId}/my-permissions`, {
      headers: { Authorization: `Bearer ${member.token}` }
    });
    const hasKeyOff = (myPermsOff.data.permissions || []).includes(cap.key);
    record('Permission Matrix', `Check /my-permissions excludes ${cap.key} when OFF`, false, hasKeyOff, hasKeyOff === false);

    // Test API call when OFF -> MUST BE REJECTED WITH 403 FORBIDDEN
    const execOffRes = await cap.execute();
    const isDeniedOff = execOffRes.status === 403;
    record(
      'Permission Matrix',
      `Execute ${cap.label} when ${cap.key} is OFF (403 Enforcement)`,
      403,
      execOffRes.status,
      isDeniedOff,
      isDeniedOff ? 'Denied (403 Forbidden)' : `FAILED with ${execOffRes.status}`
    );
  }

  // Close resources
  server.close();
  await closeAllPools();

  console.log('\n========================================================================');
  console.log('                          FINAL TEST SUMMARY                            ');
  console.log('========================================================================');
  const total = summary.length;
  const passed = summary.filter((s) => s.passed).length;
  const failed = summary.filter((s) => !s.passed).length;

  console.log(`Total Assertions Run: ${total}`);
  console.log(`Passed:               ${passed}`);
  console.log(`Failed:               ${failed}`);

  if (failed > 0) {
    console.error('\nFAILURES DETECTED:');
    summary.filter((s) => !s.passed).forEach((s) => {
      console.error(`- [${s.section}] ${s.testName}: Expected ${s.expected}, Got ${s.actual} (${s.details})`);
    });
    process.exit(1);
  } else {
    console.log('\nALL ROLE & PERMISSION MATRIX TESTS PASSED WITH 100% SUCCESS!');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Test execution error:', err);
  if (server) server.close();
  closeAllPools().then(() => process.exit(1));
});
