// server/src/scripts/permcheck/suiteN2.js
// N2 Suite: Role assignment to users, mid-session dynamic role updates, anti-escalation, name attacks, R1-R8.

const io = require('socket.io-client');
const { createFreshUserViaInvite } = require('./fixtures');
const { SYSTEM_ROLES, PERMISSIONS } = require('../../rbac/registry');
const { OPERATIONS } = require('./operations');

async function runSuiteN2({
  ownerClient,
  apiBaseUrl,
  frontendUrl,
  tenantSlug,
  tenantDb,
  context,
  quick = false,
  reporter
}) {
  console.log('\n================================================================');
  console.log('       RUNNING SUITE N2: ROLE ASSIGNMENT & LIFECYCLE (R1-R8)    ');
  console.log('================================================================\n');

  // ───────────────────────────────────────────────────────────────────────────
  // R1: SYSTEM ROLES EVALUATION (Admin, Project Manager, Team Member, Viewer, Guest)
  // ───────────────────────────────────────────────────────────────────────────
  console.log('--- R1: System Roles Assignment and Catalogue Verification ---');
  const testRoles = ['Admin', 'Project Manager', 'Team Member', 'Viewer', 'Guest'];

  for (const roleName of testRoles) {
    const roleId = context.systemRoleMap[roleName];
    if (!roleId) {
      console.warn(`[WARN] System role ${roleName} not found in map.`);
      continue;
    }

    const { client: rClient, user: rUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId,
      boardIds: [context.boardId]
    });

    // Check my-permissions equals registry definition
    const myPermsRes = await rClient.get(`/api/workspaces/${context.workspaceId}/my-permissions`);
    const actualPerms = new Set(myPermsRes.data?.permissions || []);
    const expectedPerms = SYSTEM_ROLES[roleName]?.permissions || [];

    // Verify all expected permissions are present
    const missingPerms = expectedPerms.filter((p) => !actualPerms.has(p));
    const r1Pass = missingPerms.length === 0;

    reporter.record({
      permission: `role.system.${roleName.toLowerCase().replace(/\s+/g, '_')}`,
      module: 'role_assignment',
      step: `R1: System Role [${roleName}]`,
      status: r1Pass ? 'PASS' : 'FAIL',
      evidence: {
        roleName,
        actualCount: actualPerms.size,
        expectedCount: expectedPerms.length,
        missingPerms
      }
    });

    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${rUser.id}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R2: MID-SESSION ROLE CHANGE ACROSS BOTH ENDPOINTS (UPGRADE & DOWNGRADE)
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R2: Mid-Session Role Change (Workspace & Company Members Endpoints) ---');
  {
    const { client: dynClient, user: dynUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: context.systemRoleMap['Viewer'],
      boardIds: [context.boardId]
    });

    const dynCtx = { ...context, ownUserId: dynUser.id };

    // Baseline as Viewer: task.create is denied (403)
    const baseRes = await OPERATIONS['task.create'].execute(dynClient, dynCtx);
    const viewerDenied = [403, 404, 401].includes(baseRes.status);

    // 1. Upgrade via workspace member route: PATCH /api/workspaces/:id/members/:userId/role
    const upRes = await ownerClient.patch(`/api/workspaces/${context.workspaceId}/members/${dynUser.id}/role`, {
      role_id: context.systemRoleMap['Team Member'],
      board_ids: [context.boardId]
    });
    const upHttpOk = upRes.status === 200;

    // Mid-session test WITHOUT re-login: task.create now succeeds!
    const upOpRes = await OPERATIONS['task.create'].execute(dynClient, dynCtx);
    const teamMemberAllowed = upOpRes.status >= 200 && upOpRes.status < 300;

    // 2. Downgrade via company-members route: PATCH /api/workspaces/:id/company-members/:userId/role
    const downRes = await ownerClient.patch(`/api/workspaces/${context.workspaceId}/company-members/${dynUser.id}/role`, {
      role_id: context.systemRoleMap['Viewer']
    });
    const downHttpOk = downRes.status === 200;

    // Immediate effect: task.create is denied again!
    const downOpRes = await OPERATIONS['task.create'].execute(dynClient, dynCtx);
    const downgradedDenied = [403, 404, 401].includes(downOpRes.status);
    const r2Pass = viewerDenied && upHttpOk && teamMemberAllowed && downHttpOk && downgradedDenied;

    reporter.record({
      permission: 'role.mid_session_change',
      module: 'role_assignment',
      step: 'R2: Mid-Session Upgrade & Downgrade Across Both Endpoints',
      status: r2Pass ? 'PASS' : 'FAIL',
      evidence: {
        viewerDenied,
        upHttpOk,
        teamMemberAllowed,
        downHttpOk,
        downgradedDenied
      }
    });

    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${dynUser.id}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R3: MULTI-USER ROLE EDITS & IN-USE ROLE DELETION LOCK
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R3: Multi-User Role Edits and Role Deletion Safety Lock ---');
  {
    // Create custom role with basic perms
    const r3RoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
      name: `zz-permtest-multi-role-${Date.now()}`,
      permission_keys: ['workspace.view', 'project.view', 'task.view']
    });
    const r3RoleId = r3RoleRes.data?.role?.id || r3RoleRes.data?.id;

    // User 1
    const { client: u1Client, user: u1 } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: r3RoleId,
      boardIds: [context.boardId]
    });

    // User 2
    const { client: u2Client, user: u2 } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: r3RoleId,
      boardIds: [context.boardId]
    });

    // Edit role adding task.create
    await ownerClient.patch(`/api/roles/${r3RoleId}`, {
      permission_keys: ['workspace.view', 'project.view', 'task.view', 'task.create'],
      workspace_id: context.workspaceId
    });

    // Check both users immediately inherit task.create
    const u1Op = await OPERATIONS['task.create'].execute(u1Client, { ...context, ownUserId: u1.id });
    const u2Op = await OPERATIONS['task.create'].execute(u2Client, { ...context, ownUserId: u2.id });
    const bothInherit = (u1Op.status >= 200 && u1Op.status < 300) && (u2Op.status >= 200 && u2Op.status < 300);

    // Delete role while in use -> MUST be blocked (400)
    const delBlockedRes = await ownerClient.delete(`/api/roles/${r3RoleId}`);
    const deleteBlocked = delBlockedRes.status === 400;

    const r3Pass = bothInherit && deleteBlocked;

    reporter.record({
      permission: 'role.multi_user_and_delete_lock',
      module: 'role_assignment',
      step: 'R3: Multi-User Role Edit & Delete Lock while In Use',
      status: r3Pass ? 'PASS' : 'FAIL',
      evidence: {
        bothInherit,
        deleteBlocked,
        deleteStatus: delBlockedRes.status
      }
    });

    // Cleanup
    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${u1.id}`);
    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${u2.id}`);
    await ownerClient.delete(`/api/roles/${r3RoleId}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R4: BOARD-LEVEL MEMBERSHIP & GUEST SCOPING
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R4: Board-Level Membership & Guest Scoping ---');
  {
    const { client: guestClient, user: guestUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: context.systemRoleMap['Guest'],
      boardIds: [context.boardId] // Only on B1
    });

    // Allowed on B1:
    const b1Res = await guestClient.get(`/api/boards/${context.boardId}`);
    const b1Ok = b1Res.status === 200;

    // Denied on B2:
    const b2Res = await guestClient.get(`/api/boards/${context.board2Id}`);
    const b2Denied = [403, 404].includes(b2Res.status);

    // Remove from B1 -> denied immediately on B1
    await ownerClient.delete(`/api/boards/${context.boardId}/members/${guestUser.id}`);
    const b1AfterRemove = await guestClient.get(`/api/boards/${context.boardId}`);
    const b1RemovedDenied = [403, 404].includes(b1AfterRemove.status);

    const r4Pass = b1Ok && b2Denied && b1RemovedDenied;

    reporter.record({
      permission: 'scoping.board_membership',
      module: 'scoping',
      step: 'R4: Board-Level Membership & Dynamic Add/Remove',
      status: r4Pass ? 'PASS' : 'FAIL',
      evidence: { b1Ok, b2Denied, b1RemovedDenied }
    });

    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${guestUser.id}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R5: MULTI-WORKSPACE ISOLATION
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R5: Multi-Workspace Role Isolation ---');
  {
    // User has Admin in W1
    const { client: mwClient, user: mwUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: context.systemRoleMap['Admin'],
      boardIds: [context.boardId]
    });

    // Admin action in W1 succeeds:
    const w1Res = await mwClient.get(`/api/workspaces/${context.workspaceId}/roles`);
    const w1Allowed = w1Res.status === 200;

    // Action in W2 is DENIED (not a member of W2):
    const w2Res = await mwClient.get(`/api/workspaces/${context.workspace2Id}/roles`);
    const w2Denied = [403, 404].includes(w2Res.status);

    const r5Pass = w1Allowed && w2Denied;

    reporter.record({
      permission: 'scoping.multi_workspace',
      module: 'scoping',
      step: 'R5: Cross-Workspace Role Isolation',
      status: r5Pass ? 'PASS' : 'FAIL',
      evidence: { w1Allowed, w2Denied, w2Status: w2Res.status }
    });

    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${mwUser.id}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R6: COMPANY-LEVEL ROUTES PERMISSION ENFORCEMENT
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R6: Company-Level Routes Permission Enforcement ---');
  {
    // User WITH member.view permission
    const { client: permClient, user: permUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: context.systemRoleMap['Admin']
    });

    // User WITHOUT member.view (Guest has no member.view)
    const { client: noPermClient, user: noPermUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: context.systemRoleMap['Guest']
    });

    const cmAllowed = await permClient.get(`/api/workspaces/${context.workspaceId}/company-members`);
    const cmDenied = await noPermClient.get(`/api/workspaces/${context.workspaceId}/company-members`);

    const r6Pass = (cmAllowed.status === 200) && [403, 404, 401].includes(cmDenied.status);

    reporter.record({
      permission: 'member.company_routes',
      module: 'company_routes',
      step: 'R6: Company-Level Members Directory Gating',
      status: r6Pass ? 'PASS' : 'FAIL',
      evidence: {
        allowedStatus: cmAllowed.status,
        deniedStatus: cmDenied.status
      }
    });

    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${permUser.id}`);
    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${noPermUser.id}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R7: ANTI-ESCALATION AND NAME ATTACKS
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R7: Anti-Escalation & Role Name Attacks ---');
  {
    // 1. Role name attacks: attempts to create custom role named "Owner", "Admin ", "admin", "Super Admin"
    const attackNames = ['Owner', 'owner', 'Admin', 'admin', 'Admin ', 'Super Admin', '  Owner  '];
    let allNameAttacksBlocked = true;

    for (const badName of attackNames) {
      const res = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
        name: badName,
        permission_keys: ['workspace.view']
      });

      // Must be rejected with 400 RESERVED_ROLE_NAME
      if (res.status !== 400 || res.data?.error?.code !== 'RESERVED_ROLE_NAME') {
        allNameAttacksBlocked = false;
        console.error(`[FAIL] Role name attack "${badName}" was not blocked! Status: ${res.status}`);
      }
    }

    // 2. Privilege Escalation: Member with role.create cannot grant permissions they do not possess
    const limitedRoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
      name: `zz-permtest-creator-${Date.now()}`,
      permission_keys: ['workspace.view', 'role.view', 'role.create']
    });
    const creatorRoleId = limitedRoleRes.data?.role?.id || limitedRoleRes.data?.id;

    const { client: creatorClient, user: creatorUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: creatorRoleId
    });

    // Attempt to create role granting task.delete (which creator does not have)
    const escalateRes = await creatorClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
      name: `zz-permtest-escalated-${Date.now()}`,
      permission_keys: ['workspace.view', 'project.view', 'task.view', 'task.delete']
    });

    const escalationBlocked = escalateRes.status === 403;

    // 3. Cannot edit own role
    const editOwnRoleRes = await creatorClient.patch(`/api/roles/${creatorRoleId}`, {
      name: 'Hacked Own Role'
    });
    const editOwnBlocked = editOwnRoleRes.status === 403;

    const r7Pass = allNameAttacksBlocked && escalationBlocked && editOwnBlocked;

    reporter.record({
      permission: 'security.anti_escalation_and_name_attacks',
      module: 'security',
      step: 'R7: Name Attacks & Privilege Escalation Prevention',
      status: r7Pass ? 'PASS' : 'FAIL',
      evidence: {
        allNameAttacksBlocked,
        escalationBlocked,
        escalateStatus: escalateRes.status,
        editOwnBlocked,
        editOwnStatus: editOwnRoleRes.status
      }
    });

    await ownerClient.delete(`/api/roles/${creatorRoleId}`);
    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${creatorUser.id}`);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // R8: REALTIME REVOCATION WITH OPEN SOCKET
  // ───────────────────────────────────────────────────────────────────────────
  console.log('\n--- R8: Realtime Permission Revocation with Open Socket ---');
  {
    const r8RoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
      name: `zz-permtest-r8-role-${Date.now()}`,
      permission_keys: ['workspace.view', 'project.view', 'task.view', 'task.create']
    });
    const r8RoleId = r8RoleRes.data?.role?.id || r8RoleRes.data?.id;

    const { client: liveClient, user: liveUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: r8RoleId,
      boardIds: [context.boardId]
    });

    let liveSocketReceived = false;
    const socket = io(apiBaseUrl, {
      path: '/socket.io',
      extraHeaders: {
        Origin: frontendUrl,
        Cookie: liveClient.getCookieString()
      },
      auth: { token: liveClient.token },
      transports: ['websocket', 'polling']
    });

    socket.on('user:permissions_updated', () => {
      liveSocketReceived = true;
    });

    await new Promise((r) => setTimeout(r, 200));

    // Revoke task.create
    await ownerClient.patch(`/api/roles/${r8RoleId}`, {
      permission_keys: ['workspace.view', 'project.view', 'task.view'],
      workspace_id: context.workspaceId
    });

    await new Promise((r) => setTimeout(r, 200));

    // HTTP operation denied immediately
    const httpOp = await OPERATIONS['task.create'].execute(liveClient, { ...context, ownUserId: liveUser.id });
    const httpDenied = [403, 404, 401].includes(httpOp.status);

    const r8Pass = httpDenied && liveSocketReceived;

    reporter.record({
      permission: 'security.realtime_revocation',
      module: 'security',
      step: 'R8: Realtime Permission Revocation & Immediate Denial',
      status: r8Pass ? 'PASS' : 'FAIL',
      evidence: { httpDenied, liveSocketReceived, status: httpOp.status }
    });

    socket.close();
    await ownerClient.delete(`/api/roles/${r8RoleId}`);
    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${liveUser.id}`);
  }

  console.log('\n✓ SUITE N2 COMPLETED.\n');
}

module.exports = { runSuiteN2 };
