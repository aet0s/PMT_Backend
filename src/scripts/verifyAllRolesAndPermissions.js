const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '0';
process.env.REGISTRATION_RATE_LIMIT_PER_HOUR = '500';
process.env.REGISTRATION_DAILY_CAP = '10000';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const { app } = require('../index');
const { getTenantDb, closeAllPools } = require('../services/tenantPools');
const { PERMISSIONS, SYSTEM_ROLES } = require('../rbac/registry');

let server;
let baseUrl;
let tenantDb;
let tenantSlug;

const testResults = [];

function recordResult(category, testCase, moduleName, roleOrContext, expected, actual, passed, notes = '') {
  const item = {
    id: testResults.length + 1,
    category,
    testCase,
    moduleName,
    roleOrContext,
    expected,
    actual,
    passed,
    notes,
    timestamp: new Date().toISOString()
  };
  testResults.push(item);
  const statusIcon = passed ? '✓' : '❌';
  console.log(`  ${statusIcon} [${category}] ${testCase}: ${passed ? 'PASSED' : 'FAILED'} (Got ${actual}, Expected ${expected})`);
}

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

async function runVerification() {
  console.log('================================================================');
  console.log('   FULL END-TO-END RBAC & ROLE-PERMISSION VERIFICATION ENGINE    ');
  console.log('================================================================\n');

  // Start test server
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });

  const testSuffix = crypto.randomBytes(3).toString('hex');
  tenantSlug = `verify_corp_${testSuffix}`;
  const ownerEmail = `owner_${testSuffix}@example.com`;
  const defaultPassword = 'SecurePassword123!';

  console.log(`[Provisioning] Registering test company: ${tenantSlug}...`);
  const regRes = await request('/api/auth/register-company', {
    method: 'POST',
    body: {
      companyName: `Verify Corp ${testSuffix}`,
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
  const ownerUser = regRes.data.user;
  const tenantId = regRes.data.tenant.id;
  const workspaceId = regRes.data.initial_workspace_id;
  tenantDb = await getTenantDb(tenantId);

  // Fetch all system roles
  const rolesRows = await tenantDb.query('SELECT id, name FROM roles WHERE workspace_id IS NULL');
  const roleMap = {};
  rolesRows.forEach((r) => { roleMap[r.name] = r.id; });

  // Helper to create and authenticate a user with a given roleId
  async function createMember(name, email, roleId, roleName) {
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

  // Create admin user and target user
  console.log('[Setup] Provisioning Admin and Test Target Member...');
  const adminMember = await createMember('Admin Alice', `admin_${testSuffix}@example.com`, roleMap['Admin'], 'Admin');
  const targetMember = await createMember('Target Bob', `target_${testSuffix}@example.com`, roleMap['Project Manager'], 'Project Manager');

  // Create board, list, card for testing
  const boardRes = await request('/api/boards', {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { workspace_id: workspaceId, name: 'Main Verification Project' }
  });
  const boardId = boardRes.data.board.id;

  const listRes = await request('/api/lists', {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { board_id: boardId, name: 'To Do', position: 1000 }
  });
  const listId = listRes.data.list.id;

  // Add targetMember to board members so project permissions apply
  await request(`/api/boards/${boardId}/members`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { user_id: targetMember.id }
  });

  async function createTestCard(title = 'Test Task') {
    const cRes = await request('/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { list_id: listId, title, position: 1000 }
    });
    return cRes.data.card.id;
  }

  console.log('\n================================================================');
  console.log('--- 1. SPECIFIC BUG: TASK DELETION PERMISSION ENFORCEMENT ---');
  console.log('================================================================');

  // Step 1: PM initially has task.delete -> Can delete task
  const card1Id = await createTestCard('Task To Delete Initially');
  const del1Res = await request(`/api/cards/${card1Id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${targetMember.token}` }
  });
  recordResult(
    'Task Deletion Enforcement',
    'Project Manager can delete task when task.delete is granted',
    'task',
    'Project Manager',
    200,
    del1Res.status,
    del1Res.status === 200,
    'Initial default permission granted'
  );

  // Step 2: Admin revokes task.delete from Project Manager
  const pmPermsRes = await request(`/api/workspaces/${workspaceId}/roles`, {
    headers: { Authorization: `Bearer ${adminMember.token}` }
  });
  const rolesList = pmPermsRes.data?.roles || [];
  const pmRole = rolesList.find((r) => r.id === roleMap['Project Manager'] || r.name === 'Project Manager') || { permission_keys: SYSTEM_ROLES['Project Manager'].permissions };
  const targetPmRoleId = pmRole.id || roleMap['Project Manager'];
  const pmKeysWithoutTaskDelete = (pmRole.permission_keys || []).filter((k) => k !== 'task.delete' && k !== 'card.delete');

  const updatePmRes = await request(`/api/roles/${targetPmRoleId}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${adminMember.token}` },
    body: {
      name: 'Project Manager',
      permission_keys: pmKeysWithoutTaskDelete,
      workspace_id: workspaceId
    }
  });
  recordResult(
    'Task Deletion Enforcement',
    'Admin revokes task.delete from Project Manager role via PATCH /api/roles/:id',
    'role',
    'Admin',
    200,
    updatePmRes.status,
    updatePmRes.status === 200,
    'Updated system role permission keys'
  );

  // Step 3: PM attempts to delete task -> MUST return 403 Forbidden!
  const card2Id = await createTestCard('Task That PM Must Not Delete');
  const del2Res = await request(`/api/cards/${card2Id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${targetMember.token}` }
  });
  recordResult(
    'Task Deletion Enforcement',
    'Project Manager CANNOT delete task after task.delete revoked (strict 403)',
    'task',
    'Project Manager',
    403,
    del2Res.status,
    del2Res.status === 403,
    del2Res.data?.error?.message || ''
  );

  // Step 4: Admin restores task.delete to Project Manager
  const pmKeysRestored = [...pmKeysWithoutTaskDelete, 'task.delete'];
  const restorePmRes = await request(`/api/roles/${targetPmRoleId}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${adminMember.token}` },
    body: {
      name: 'Project Manager',
      permission_keys: pmKeysRestored,
      workspace_id: workspaceId
    }
  });
  recordResult(
    'Task Deletion Enforcement',
    'Admin restores task.delete to Project Manager role',
    'role',
    'Admin',
    200,
    restorePmRes.status,
    restorePmRes.status === 200,
    'Restored permission key'
  );

  // Step 5: PM can now delete task again
  const del3Res = await request(`/api/cards/${card2Id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${targetMember.token}` }
  });
  recordResult(
    'Task Deletion Enforcement',
    'Project Manager can delete task after task.delete is restored',
    'task',
    'Project Manager',
    200,
    del3Res.status,
    del3Res.status === 200,
    'Permission reinstated successfully'
  );

  console.log('\n================================================================');
  console.log('--- 2. ROLE ASSIGNMENT & PERMISSION MATRIX VERIFICATION (6 ROLES) ---');
  console.log('================================================================');

  // Test roles in ascending rank order so targetMember is progressively promoted
  const rolesToTest = [
    { name: 'Guest', canCreateBoard: false, canDeleteTask: false, canInvite: false },
    { name: 'Viewer', canCreateBoard: false, canDeleteTask: false, canInvite: false },
    { name: 'Team Member', canCreateBoard: false, canDeleteTask: false, canInvite: false },
    { name: 'Project Manager', canCreateBoard: true, canDeleteTask: true, canInvite: true },
    { name: 'Admin', canCreateBoard: true, canDeleteTask: true, canInvite: true }
  ];

  for (const rTest of rolesToTest) {
    console.log(`\nTesting Role Assignment & Enforcement for: ${rTest.name}...`);
    const targetRoleId = roleMap[rTest.name];

    // Assign role via workspace member endpoint
    const assignRes = await request(`/api/workspaces/${workspaceId}/members/${targetMember.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { role_id: targetRoleId }
    });
    recordResult(
      'Role Assignment',
      `Assign role "${rTest.name}" to member via PATCH /api/workspaces/:id/members/:userId/role`,
      'member',
      rTest.name,
      200,
      assignRes.status,
      assignRes.status === 200,
      `Assigned role ${rTest.name}`
    );

    // Verify member permissions endpoint returns correct role
    const myPermsRes = await request(`/api/workspaces/${workspaceId}/my-permissions`, {
      headers: { Authorization: `Bearer ${targetMember.token}` }
    });
    const returnedRoleName = myPermsRes.data.role?.name || myPermsRes.data.role;
    recordResult(
      'Role Verification',
      `Member /my-permissions reflects assigned role "${rTest.name}"`,
      'member',
      rTest.name,
      rTest.name,
      returnedRoleName,
      returnedRoleName === rTest.name,
      `Returned role: ${returnedRoleName}`
    );

    // Test 1: Task Deletion capability
    const testCardId = await createTestCard(`Card For ${rTest.name}`);
    const deleteTestRes = await request(`/api/cards/${testCardId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${targetMember.token}` }
    });
    const expectedDelStatus = rTest.canDeleteTask ? 200 : 403;
    recordResult(
      'Role Permission Matrix',
      `Role "${rTest.name}" task.delete capability check`,
      'task',
      rTest.name,
      expectedDelStatus,
      deleteTestRes.status,
      deleteTestRes.status === expectedDelStatus,
      rTest.canDeleteTask ? 'Allowed (200 OK)' : 'Denied (403 Forbidden)'
    );

    // Test 2: Project Creation capability
    const createBoardRes = await request('/api/boards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${targetMember.token}` },
      body: { workspace_id: workspaceId, name: `Board by ${rTest.name}` }
    });
    const expectedBoardStatus = rTest.canCreateBoard ? 201 : 403;
    recordResult(
      'Role Permission Matrix',
      `Role "${rTest.name}" project.create capability check`,
      'project',
      rTest.name,
      expectedBoardStatus,
      createBoardRes.status,
      createBoardRes.status === expectedBoardStatus,
      rTest.canCreateBoard ? 'Allowed (201 Created)' : 'Denied (403 Forbidden)'
    );

    // Clean up created board if allowed
    if (createBoardRes.status === 201) {
      await request(`/api/boards/${createBoardRes.data.board.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${ownerToken}` }
      });
    }

    // Test 3: Member Invite capability
    const inviteRes = await request('/api/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${targetMember.token}` },
      body: { workspace_id: workspaceId, email: `invite_${crypto.randomBytes(3).toString('hex')}@test.com` }
    });
    const isInviteAllowed = [200, 201, 202].includes(inviteRes.status);
    const passedInvite = rTest.canInvite ? isInviteAllowed : (inviteRes.status === 403);
    recordResult(
      'Role Permission Matrix',
      `Role "${rTest.name}" member.invite capability check`,
      'member',
      rTest.name,
      rTest.canInvite ? '201/202 Allowed' : 403,
      inviteRes.status,
      passedInvite,
      rTest.canInvite ? 'Allowed invitation creation' : 'Denied (403 Forbidden)'
    );

    // Clean up card if not deleted
    if (deleteTestRes.status !== 200) {
      await request(`/api/cards/${testCardId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${ownerToken}` }
      });
    }
  }

  // Also verify Owner role on Owner account
  console.log('\nTesting Role Verification & Capabilities for: Owner...');
  const ownerPermsRes = await request(`/api/workspaces/${workspaceId}/my-permissions`, {
    headers: { Authorization: `Bearer ${ownerToken}` }
  });
  const ownerRoleName = ownerPermsRes.data.role?.name || ownerPermsRes.data.role;
  recordResult(
    'Role Verification',
    'Owner /my-permissions reflects assigned role "Owner"',
    'member',
    'Owner',
    'Owner',
    ownerRoleName,
    ownerRoleName === 'Owner',
    `Returned ${ownerRoleName}`
  );

  const ownerCardId = await createTestCard('Card For Owner');
  const ownerDelRes = await request(`/api/cards/${ownerCardId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerToken}` }
  });
  recordResult(
    'Role Permission Matrix',
    'Role "Owner" task.delete capability check',
    'task',
    'Owner',
    200,
    ownerDelRes.status,
    ownerDelRes.status === 200,
    'Allowed (200 OK)'
  );

  console.log('\n================================================================');
  console.log('--- 3. TOGGLE CHECKBOX ON/OFF FOR ALL MODULES (SINGLE USER) ---');
  console.log('================================================================');

  // Create an editable custom role for toggling
  const customRoleRes = await request(`/api/workspaces/${workspaceId}/roles`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: {
      name: 'Dynamic Toggle Tester Role',
      permission_keys: ['project.view', 'task.view']
    }
  });
  const toggleRoleId = customRoleRes.data.role.id;

  // Create dedicated toggle user to avoid cross-contamination
  const toggleMember = await createMember('Toggle User', `toggle_${testSuffix}@example.com`, toggleRoleId, 'Dynamic Toggle Tester Role');
  await request(`/api/boards/${boardId}/members`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { user_id: toggleMember.id }
  });

  const toggleTestMatrix = [
    {
      module: 'task',
      perm: 'task.delete',
      action: async () => {
        const cId = await createTestCard('Toggle Delete Card');
        return request(`/api/cards/${cId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${toggleMember.token}` }
        });
      },
      expectedSuccessStatus: 200
    },
    {
      module: 'task',
      perm: 'task.create',
      action: () => request('/api/cards', {
        method: 'POST',
        headers: { Authorization: `Bearer ${toggleMember.token}` },
        body: { list_id: listId, title: 'Toggle Create Task', position: 1000 }
      }),
      expectedSuccessStatus: 201
    },
    {
      module: 'task',
      perm: 'task.edit',
      action: async () => {
        const cId = await createTestCard('Toggle Edit Card');
        return request(`/api/cards/${cId}`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${toggleMember.token}` },
          body: { title: 'Renamed Card' }
        });
      },
      expectedSuccessStatus: 200
    },
    {
      module: 'checklist',
      perm: 'checklist.create',
      action: async () => {
        const cId = await createTestCard('Toggle Checklist Card');
        return request(`/api/cards/${cId}/checklists`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${toggleMember.token}` },
          body: { title: 'New Checklist' }
        });
      },
      expectedSuccessStatus: 201
    },
    {
      module: 'comment',
      perm: 'comment.create',
      action: async () => {
        const cId = await createTestCard('Toggle Comment Card');
        return request(`/api/cards/${cId}/comments`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${toggleMember.token}` },
          body: { body: 'Test comment' }
        });
      },
      expectedSuccessStatus: 201
    },
    {
      module: 'list',
      perm: 'list.create',
      action: () => request('/api/lists', {
        method: 'POST',
        headers: { Authorization: `Bearer ${toggleMember.token}` },
        body: { board_id: boardId, name: 'Toggle List', position: 2000 }
      }),
      expectedSuccessStatus: 201
    },
    {
      module: 'label',
      perm: 'label.create',
      action: () => request(`/api/boards/${boardId}/labels`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${toggleMember.token}` },
        body: { name: 'Bug Label', color: '#EF4444' }
      }),
      expectedSuccessStatus: 201
    },
    {
      module: 'project',
      perm: 'project.create',
      action: () => request('/api/boards', {
        method: 'POST',
        headers: { Authorization: `Bearer ${toggleMember.token}` },
        body: { workspace_id: workspaceId, name: 'Toggle Board' }
      }),
      expectedSuccessStatus: 201
    },
    {
      module: 'member',
      perm: 'member.invite',
      action: () => request('/api/invitations', {
        method: 'POST',
        headers: { Authorization: `Bearer ${toggleMember.token}` },
        body: { workspace_id: workspaceId, email: `toggle_inv_${crypto.randomBytes(3).toString('hex')}@test.com` }
      }),
      expectedSuccessStatus: 202
    },
    {
      module: 'role',
      perm: 'role.create',
      action: () => request(`/api/workspaces/${workspaceId}/roles`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${toggleMember.token}` },
        body: { name: `SubRole_${crypto.randomBytes(2).toString('hex')}`, permission_keys: ['project.view'] }
      }),
      expectedSuccessStatus: 201
    }
  ];

  for (const item of toggleTestMatrix) {
    console.log(`\nTesting Toggle ON/OFF for permission [${item.perm}] in module [${item.module}]...`);

    // 1. Toggle OFF: Set permissions without this permission
    const baseKeys = ['project.view', 'task.view'];
    await request(`/api/roles/${toggleRoleId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {
        name: 'Dynamic Toggle Tester Role',
        permission_keys: baseKeys,
        workspace_id: workspaceId
      }
    });

    const offRes = await item.action();
    recordResult(
      'Permission Toggle (OFF)',
      `Toggle OFF [${item.perm}]: Action blocked with 403 Forbidden`,
      item.module,
      'Custom Toggle Role',
      403,
      offRes.status,
      offRes.status === 403,
      `Denied as expected (${offRes.status})`
    );

    // 2. Toggle ON: Add this permission
    const onKeys = Array.from(new Set([...baseKeys, item.perm]));
    await request(`/api/roles/${toggleRoleId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {
        name: 'Dynamic Toggle Tester Role',
        permission_keys: onKeys,
        workspace_id: workspaceId
      }
    });

    const onRes = await item.action();
    const passedOn = (item.perm === 'member.invite')
      ? [200, 201, 202].includes(onRes.status)
      : (onRes.status === item.expectedSuccessStatus);

    recordResult(
      'Permission Toggle (ON)',
      `Toggle ON [${item.perm}]: Action succeeds with ${item.expectedSuccessStatus}`,
      item.module,
      'Custom Toggle Role',
      item.expectedSuccessStatus,
      onRes.status,
      passedOn,
      `Allowed as expected (${onRes.status})`
    );
  }

  console.log('\n================================================================');
  console.log('--- 4. CREATE ROLE FUNCTIONALITY & LIFECYCLE ---');
  console.log('================================================================');

  // Step 1: Create custom role
  const customRoleName = `Quality Lead ${crypto.randomBytes(2).toString('hex')}`;
  const customKeys = ['project.view', 'task.view', 'task.create', 'task.edit', 'comment.create'];
  const newRoleRes = await request(`/api/workspaces/${workspaceId}/roles`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: {
      name: customRoleName,
      permission_keys: customKeys
    }
  });
  recordResult(
    'Custom Role Lifecycle',
    'Create custom role via POST /api/workspaces/:id/roles',
    'role',
    'Owner',
    201,
    newRoleRes.status,
    newRoleRes.status === 201,
    `Created role "${customRoleName}" with ${customKeys.length} permissions`
  );
  const createdRoleId = newRoleRes.data.role.id;

  // Step 2: Create a dedicated member for custom role testing
  const customMember = await createMember('Custom Role Tester', `custom_${testSuffix}@example.com`, roleMap['Team Member'], 'Team Member');
  await request(`/api/boards/${boardId}/members`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { user_id: customMember.id }
  });

  const assignCustomRes = await request(`/api/workspaces/${workspaceId}/members/${customMember.id}/role`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { role_id: createdRoleId }
  });
  recordResult(
    'Custom Role Lifecycle',
    'Assign newly created custom role to member',
    'member',
    'Owner',
    200,
    assignCustomRes.status,
    assignCustomRes.status === 200,
    'Assigned custom role to member'
  );

  // Step 3: Verify member can perform granted actions (e.g. task.create)
  const memberCreateRes = await request('/api/cards', {
    method: 'POST',
    headers: { Authorization: `Bearer ${customMember.token}` },
    body: { list_id: listId, title: 'Card by Custom Role User', position: 1000 }
  });
  recordResult(
    'Custom Role Lifecycle',
    'Member with custom role executes granted action (task.create)',
    'task',
    customRoleName,
    201,
    memberCreateRes.status,
    memberCreateRes.status === 201,
    'Granted capability executes properly'
  );

  // Step 4: Verify member CANNOT perform ungranted action (e.g. task.delete)
  const cardToDelete = await createTestCard('Task To Not Delete');
  const memberDeleteRes = await request(`/api/cards/${cardToDelete}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${customMember.token}` }
  });
  recordResult(
    'Custom Role Lifecycle',
    'Member with custom role blocked on ungranted action (task.delete -> 403)',
    'task',
    customRoleName,
    403,
    memberDeleteRes.status,
    memberDeleteRes.status === 403,
    'Ungranted capability blocked properly'
  );

  // Step 5: Safety floor: Cannot delete custom role while assigned to member
  const deleteAssignedRes = await request(`/api/roles/${createdRoleId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { workspace_id: workspaceId }
  });
  recordResult(
    'Custom Role Lifecycle',
    'Safety floor: Cannot delete custom role while members are assigned (400 ROLE_IN_USE)',
    'role',
    'Owner',
    400,
    deleteAssignedRes.status,
    deleteAssignedRes.status === 400,
    deleteAssignedRes.data?.error?.message || ''
  );

  // Step 6: Reassign member to Team Member, then delete custom role
  const reassignRes = await request(`/api/workspaces/${workspaceId}/members/${customMember.id}/role`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { role_id: roleMap['Team Member'] }
  });
  if (reassignRes.status !== 200) {
    console.log('  [DEBUG reassignRes]:', reassignRes.status, reassignRes.data);
  }

  const deleteRoleRes = await request(`/api/roles/${createdRoleId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { workspace_id: workspaceId }
  });
  if (deleteRoleRes.status !== 200) {
    console.log('  [DEBUG deleteRoleRes data]:', JSON.stringify(deleteRoleRes.data));
  }
  recordResult(
    'Custom Role Lifecycle',
    'Delete unused custom role succeeds (200 OK)',
    'role',
    'Owner',
    200,
    deleteRoleRes.status,
    deleteRoleRes.status === 200,
    'Role deleted cleanly'
  );

  // Clean up toggle role as well
  await request(`/api/workspaces/${workspaceId}/members/${toggleMember.id}/role`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { role_id: roleMap['Team Member'] }
  });

  await request(`/api/roles/${toggleRoleId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { workspace_id: workspaceId }
  });

  // Teardown
  if (closeAllPools) await closeAllPools();
  server.close();

  // Summary calculation
  const total = testResults.length;
  const passed = testResults.filter((r) => r.passed).length;
  const failed = total - passed;

  console.log('\n================================================================');
  console.log(`VERIFICATION COMPLETE: ${passed}/${total} PASSED (${failed} FAILED)`);
  console.log('================================================================\n');

  // Save results to json for the Excel generator
  const outJsonPath = path.join(__dirname, 'rbac_test_results.json');
  fs.writeFileSync(outJsonPath, JSON.stringify({
    summary: { total, passed, failed, passRate: `${Math.round((passed / total) * 100)}%` },
    testResults
  }, null, 2));
  console.log(`Results written to ${outJsonPath}`);

  if (failed > 0) {
    process.exit(1);
  }
}

runVerification().catch((err) => {
  console.error('Fatal error in verification:', err);
  if (server) server.close();
  process.exit(1);
});
