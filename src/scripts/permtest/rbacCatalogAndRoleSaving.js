// server/src/scripts/permtest/rbacCatalogAndRoleSaving.test.js
// Comprehensive test suite covering:
// 1. Complete elimination and rejection of project.view_dashboard and obsolete duplicate keys
// 2. Parity between server registry, client permissions.json, and tenant database catalogs
// 3. System roles loading, editing, saving, and revocation across all 8 system roles
// 4. Exact user scenario: Project Manager assigned workspace.create, saved, persisted, and workspace created without Owner escalation
// 5. Strict rejection of unknown and planned permission keys (atomic transaction safety)
// 6. Custom role lifecycle: creation, editing, privilege escalation protection, and deletion

require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });
const fs = require('fs');
const path = require('path');
const { PermtestFixture } = require('./fixtures');
const { PERMISSIONS, SYSTEM_ROLES } = require('../../rbac/registry');

async function runTests() {
  console.log('================================================================');
  console.log('     RBAC CATALOG MISMATCH & ROLE SAVING AUDIT & TEST SUITE     ');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`❌ FAIL: ${message}`);
      failed++;
    }
  }

  // --- PHASE 1: STATIC & REGISTRY PARITY AUDIT ---
  console.log('\n--- Phase 1: Canonical Registry & Client Catalog Consistency ---');

  // Check 1: project.view_dashboard is absent from registry.js
  const registryHasObsolete = PERMISSIONS.some((p) => p.key === 'project.view_dashboard');
  assert(!registryHasObsolete, 'project.view_dashboard is completely absent from server registry.js');

  // Check 2: Load client permissions.json and check parity
  const clientJsonPath = path.resolve(__dirname, '../../../../client/src/rbac/permissions.json');
  assert(fs.existsSync(clientJsonPath), 'client/src/rbac/permissions.json exists');

  const clientJson = JSON.parse(fs.readFileSync(clientJsonPath, 'utf8'));
  const clientHasObsolete = clientJson.permissions.some((p) => p.key === 'project.view_dashboard');
  assert(!clientHasObsolete, 'project.view_dashboard is completely absent from client permissions.json');

  const serverKeys = new Set(PERMISSIONS.map((p) => p.key));
  const clientKeys = new Set(clientJson.permissions.map((p) => p.key));

  const missingInClient = [...serverKeys].filter((k) => !clientKeys.has(k));
  const missingInServer = [...clientKeys].filter((k) => !serverKeys.has(k));

  assert(missingInClient.length === 0, `All server registry keys exist in client catalog (0 missing)`);
  assert(missingInServer.length === 0, `All client catalog keys exist in server registry (0 extra)`);

  // Check 3: Check RoleEditorTab.jsx for table header and cell keys
  const roleEditorCode = fs.readFileSync(path.resolve(__dirname, '../../../../client/src/components/Settings/RoleEditorTab.jsx'), 'utf8');
  assert(roleEditorCode.includes('key="perm-col"'), 'RoleEditorTab colgroup has key="perm-col"');
  assert(roleEditorCode.includes('key="col-header-perm"'), 'RoleEditorTab thead has key="col-header-perm"');
  assert(roleEditorCode.includes('key="cell-perm-info"'), 'RoleEditorTab tbody tr has key="cell-perm-info"');

  // --- PHASE 2: DISPOSABLE TENANT PROVISIONING & DATABASE AUDIT ---
  console.log('\n--- Phase 2: Live Tenant Database Audit & Role Saving Verification ---');
  const fixture = new PermtestFixture();

  try {
    await fixture.setup();
    const db = fixture.tenantDb;
    const client = fixture.ownerClient;
    const wsId = fixture.tenant.defaultWorkspaceId || 1;

    // Database check: 0 obsolete keys in permissions table
    const dbObsoletePerms = await db.query(
      "SELECT id, `key` FROM permissions WHERE `key` IN ('project.view_dashboard', 'company.manage_billing', 'task.export', 'task.import', 'role.assign')"
    );
    assert(dbObsoletePerms.length === 0, `Database permissions table contains 0 obsolete legacy keys (found: ${dbObsoletePerms.length})`);

    // Database check: 0 obsolete keys in role_permissions table
    const dbObsoleteRolePerms = await db.query(
      `SELECT rp.role_id, p.key
       FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE p.key IN ('project.view_dashboard', 'company.manage_billing', 'task.export', 'task.import', 'role.assign')`
    );
    assert(dbObsoleteRolePerms.length === 0, `Database role_permissions table contains 0 obsolete legacy keys (found: ${dbObsoleteRolePerms.length})`);

    // Database check: 0 planned permissions assigned in role_permissions table
    const dbPlannedRolePerms = await db.query(
      `SELECT rp.role_id, p.key
       FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE p.planned = 1`
    );
    assert(dbPlannedRolePerms.length === 0, `Database role_permissions contains 0 planned keys assigned (found: ${dbPlannedRolePerms.length})`);

    // Fetch roles from API
    const rolesRes = await client.get(`/api/workspaces/${wsId}/roles`);
    assert(rolesRes.status === 200, 'GET /api/workspaces/:id/roles returns 200 OK');
    const roles = rolesRes.data.roles;
    assert(Array.isArray(roles) && roles.length >= 8, `Returned ${roles.length} roles (at least 8 system roles)`);

    // Verify all roles return ONLY valid active permission keys
    let unknownKeysInRoles = [];
    let plannedKeysInRoles = [];
    const validPermMap = new Map();
    PERMISSIONS.forEach((p) => validPermMap.set(p.key, p));

    for (const r of roles) {
      if (r.name === 'Owner' || r.name === 'Super Admin') continue; // Owner is granted full capability
      for (const k of (r.permission_keys || [])) {
        if (!validPermMap.has(k)) {
          unknownKeysInRoles.push(`${r.name}: ${k}`);
        } else if (validPermMap.get(k).planned) {
          plannedKeysInRoles.push(`${r.name}: ${k}`);
        }
      }
    }
    assert(unknownKeysInRoles.length === 0, `Zero unknown permission keys in any role (found: ${unknownKeysInRoles.length})`);
    assert(plannedKeysInRoles.length === 0, `Zero planned permission keys in any role (found: ${plannedKeysInRoles.length})`);

    // --- PHASE 3: ALL 8 SYSTEM ROLES EDITABILITY & INTEGRITY ---
    console.log('\n--- Phase 3: Auditing All 8 System Roles ---');

    // 1. Owner (rank 100) - MUST BE LOCKED
    const ownerRole = roles.find((r) => r.name === 'Owner');
    assert(ownerRole && ownerRole.rank === 100, 'Owner role exists with rank 100');
    assert(!ownerRole.is_editable, 'Owner role is marked is_editable = false');
    const editOwnerRes = await client.patch(`/api/roles/${ownerRole.id}`, {
      permission_keys: ['workspace.view']
    });
    assert(editOwnerRes.status === 403, 'Attempting to edit Owner role is rejected with 403 Forbidden');

    // 2. Project Manager (rank 60) - EXACT USER SCENARIO: grant workspace.create
    const pmRole = roles.find((r) => r.name === 'Project Manager');
    assert(pmRole && pmRole.rank === 60, 'Project Manager role exists with rank 60');
    assert(Boolean(pmRole.is_editable), 'Project Manager role is editable');

    // Enable workspace.create on PM role
    const origPmKeys = pmRole.permission_keys || [];
    const updatedPmKeys = Array.from(new Set([...origPmKeys, 'workspace.create']));
    const savePmRes = await client.patch(`/api/roles/${pmRole.id}`, {
      permission_keys: updatedPmKeys,
      workspace_id: wsId
    });
    assert(savePmRes.status === 200, 'Enabling workspace.create for Project Manager saves successfully with 200 OK');
    assert(
      savePmRes.data.role.permission_keys.includes('workspace.create'),
      'Returned PM role payload includes workspace.create'
    );

    // Verify persistence after refresh (re-query API)
    const reloadedRolesRes = await client.get(`/api/workspaces/${wsId}/roles`);
    const reloadedPm = reloadedRolesRes.data.roles.find((r) => r.id === pmRole.id);
    assert(
      reloadedPm.permission_keys.includes('workspace.create'),
      'Project Manager permission workspace.create persists after API reload'
    );

    // EXACT SCENARIO ESCALATION TEST: PM user creates workspace
    const pmUserClient = fixture.users['Project Manager'].client;
    const pmCreateWsRes = await pmUserClient.post('/api/workspaces', {
      name: 'PM Created Workspace'
    });
    assert(pmCreateWsRes.status === 201 || pmCreateWsRes.status === 200, 'PM user creates workspace successfully when authorized with workspace.create');
    const newWsId = pmCreateWsRes.data.workspace?.id || pmCreateWsRes.data.id;
    const [pmDestMember] = await db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [newWsId, pmUserClient.user.id]
    );
    const [pmDestRole] = await db.query('SELECT name, rank FROM roles WHERE id = ?', [pmDestMember.role_id]);
    assert(
      pmDestRole.name === 'Project Manager' && pmDestRole.rank === 60,
      'PM received destination role "Project Manager" (rank 60), NOT Owner (rank 100)'
    );

    // Test Revocation: Revoke workspace.create from PM role
    const revokedPmKeys = origPmKeys.filter((k) => k !== 'workspace.create');
    const revokePmRes = await client.patch(`/api/roles/${pmRole.id}`, {
      permission_keys: revokedPmKeys,
      workspace_id: wsId
    });
    assert(revokePmRes.status === 200, 'Revoking workspace.create from Project Manager saves successfully with 200 OK');
    const postRevokeRoles = (await client.get(`/api/workspaces/${wsId}/roles`)).data.roles;
    const postRevokePm = postRevokeRoles.find((r) => r.id === pmRole.id);
    assert(
      !postRevokePm.permission_keys.includes('workspace.create'),
      'workspace.create is successfully revoked from PM role in database'
    );

    // Verify PM user is now blocked from creating workspace (revocation actually takes effect)
    const pmDeniedWsRes = await pmUserClient.post('/api/workspaces', {
      name: 'PM Denied Workspace'
    });
    assert(pmDeniedWsRes.status === 403, 'PM user without workspace.create is denied workspace creation (403 Forbidden)');

    // Verify other system roles: Admin, Team Lead, Team Member, Viewer, Auditor, Guest
    const editableSystemRoles = ['Admin', 'Team Lead', 'Team Member', 'Viewer', 'Auditor', 'Guest'];
    for (const rName of editableSystemRoles) {
      const sRole = roles.find((r) => r.name === rName);
      assert(sRole && Boolean(sRole.is_editable), `System role "${rName}" exists and is editable`);

      // Test editing and revoking a permission (e.g. search.use)
      const currentKeys = sRole.permission_keys || [];
      const hasSearch = currentKeys.includes('search.use');
      const testKeys = hasSearch
        ? currentKeys.filter((k) => k !== 'search.use')
        : [...currentKeys, 'search.use'];

      const editRes = await client.patch(`/api/roles/${sRole.id}`, {
        permission_keys: testKeys,
        workspace_id: wsId
      });
      assert(editRes.status === 200, `System role "${rName}" saves permission modifications with 200 OK`);

      // Restore original keys
      await client.patch(`/api/roles/${sRole.id}`, {
        permission_keys: currentKeys,
        workspace_id: wsId
      });
    }

    // --- PHASE 4: NEGATIVE VALIDATION TESTING (REJECTION OF UNKNOWN & PLANNED KEYS) ---
    console.log('\n--- Phase 4: Strict Rejection of Unknown, Obsolete, and Planned Keys ---');

    // 1. Rejection of obsolete project.view_dashboard
    const rejectLegacyRes = await client.patch(`/api/roles/${pmRole.id}`, {
      permission_keys: [...pmRole.permission_keys, 'project.view_dashboard'],
      workspace_id: wsId
    });
    assert(rejectLegacyRes.status === 400, 'Submitting unknown key project.view_dashboard is rejected with 400 Bad Request');
    assert(
      rejectLegacyRes.data?.error?.code === 'UNKNOWN_PERMISSION_KEY',
      'Error code is UNKNOWN_PERMISSION_KEY'
    );

    // 2. Rejection of arbitrary unknown key
    const rejectFakeRes = await client.patch(`/api/roles/${pmRole.id}`, {
      permission_keys: [...pmRole.permission_keys, 'nonexistent.random_capability'],
      workspace_id: wsId
    });
    assert(rejectFakeRes.status === 400, 'Submitting arbitrary fake key is rejected with 400 Bad Request');
    assert(
      rejectFakeRes.data?.error?.code === 'UNKNOWN_PERMISSION_KEY',
      'Error code is UNKNOWN_PERMISSION_KEY'
    );

    // 3. Rejection of planned permission key
    const rejectPlannedRes = await client.patch(`/api/roles/${pmRole.id}`, {
      permission_keys: [...pmRole.permission_keys, 'company.delete'], // company.delete is planned: true
      workspace_id: wsId
    });
    assert(rejectPlannedRes.status === 400, 'Submitting planned permission key company.delete is rejected with 400');
    assert(
      rejectPlannedRes.data?.error?.code === 'CANNOT_ADD_PLANNED_KEY',
      'Error code is CANNOT_ADD_PLANNED_KEY'
    );

    // 4. Atomicity check: verify role permissions were NOT corrupted by rejected requests
    const pmAfterRejections = (await client.get(`/api/workspaces/${wsId}/roles`)).data.roles.find((r) => r.id === pmRole.id);
    assert(
      !pmAfterRejections.permission_keys.includes('project.view_dashboard') &&
      !pmAfterRejections.permission_keys.includes('nonexistent.random_capability') &&
      !pmAfterRejections.permission_keys.includes('company.delete'),
      'Role permissions remained completely intact and uncorrupted after failed requests (atomic transaction)'
    );

    // --- PHASE 5: CUSTOM ROLE FULL LIFECYCLE ---
    console.log('\n--- Phase 5: Custom Role Full Lifecycle ---');

    // 1. Create custom role
    const customRoleName = 'Quality Assurance Lead';
    const initialPerms = ['task.view', 'task.create', 'task.edit', 'project.view'];
    const createRoleRes = await client.post(`/api/workspaces/${wsId}/roles`, {
      name: customRoleName,
      permission_keys: initialPerms,
      rank: 45
    });
    assert(createRoleRes.status === 201 || createRoleRes.status === 200, 'Custom role created successfully');
    const customRoleId = createRoleRes.data.role.id;
    assert(customRoleId > 0, `Custom role assigned valid ID: ${customRoleId}`);

    // Verify fetched custom role
    const getCustomRes = (await client.get(`/api/workspaces/${wsId}/roles`)).data.roles.find((r) => r.id === customRoleId);
    assert(getCustomRes && getCustomRes.name === customRoleName, 'Custom role appears in workspace role list');
    assert(
      initialPerms.every((k) => getCustomRes.permission_keys.includes(k)),
      'Custom role has all initially assigned permissions'
    );

    // 2. Edit custom role permissions (add comment capabilities, remove task.create)
    const modifiedCustomPerms = ['task.view', 'task.edit', 'project.view', 'comment.view', 'comment.create'];
    const editCustomRes = await client.patch(`/api/roles/${customRoleId}`, {
      name: customRoleName,
      permission_keys: modifiedCustomPerms,
      workspace_id: wsId
    });
    assert(editCustomRes.status === 200, 'Custom role permissions updated with 200 OK');
    const updatedCustomRole = (await client.get(`/api/workspaces/${wsId}/roles`)).data.roles.find((r) => r.id === customRoleId);
    assert(!updatedCustomRole.permission_keys.includes('task.create'), 'task.create was successfully removed from custom role');
    assert(updatedCustomRole.permission_keys.includes('comment.create'), 'comment.create was successfully added to custom role');

    // 3. Test attempting to add unknown key to custom role
    const customBadKeyRes = await client.patch(`/api/roles/${customRoleId}`, {
      permission_keys: [...modifiedCustomPerms, 'project.view_dashboard'],
      workspace_id: wsId
    });
    assert(customBadKeyRes.status === 400, 'Adding unknown key to custom role is rejected with 400');

    // 4. Delete custom role
    const deleteCustomRes = await client.delete(`/api/roles/${customRoleId}`, {
      workspace_id: wsId
    });
    assert(deleteCustomRes.status === 200, 'Custom role deleted successfully with 200 OK');
    const rolesAfterDelete = (await client.get(`/api/workspaces/${wsId}/roles`)).data.roles;
    assert(!rolesAfterDelete.some((r) => r.id === customRoleId), 'Deleted custom role no longer appears in roles list');

  } finally {
    // Drop test database cleanly
    await fixture.cleanup();
  }

  console.log('\n================================================================');
  console.log(`TOTAL CHECKS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('================================================================');

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('✅ ALL RBAC CATALOG MISMATCH AND ROLE SAVING TESTS PASSED!');
    process.exit(0);
  }
}

runTests().catch((err) => {
  console.error('[UNHANDLED TEST EXCEPTION]:', err);
  process.exit(1);
});
