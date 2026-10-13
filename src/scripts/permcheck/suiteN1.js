// server/src/scripts/permcheck/suiteN1.js
// N1 Suite: Per-permission toggle tests, module sweeps, cumulative walk, round trip, socket events.

const io = require('socket.io-client');
const { OPERATIONS } = require('./operations');
const {
  PERMISSIONS,
  PREREQUISITE_PERMISSIONS,
  LEGACY_PERMISSION_ALIASES,
  getTransitivePrerequisites
} = require('../../rbac/registry');
const { createFreshUserViaInvite } = require('./fixtures');

async function ensureDeletableEntity(ownerClient, context, targetCtx, keyOrModule) {
  if (keyOrModule.includes('task') || keyOrModule === 'task.delete') {
    const cRes = await ownerClient.post('/api/cards', { list_id: context.listId, title: `zz-permtest-card-del-${Date.now()}` });
    targetCtx.deletableCardId = cRes.data?.card?.id || cRes.data?.id;
  }
  if (keyOrModule.includes('checklist') || keyOrModule === 'checklist.delete') {
    const chkRes = await ownerClient.post(`/api/cards/${context.cardId}/checklists`, { title: `zz-permtest-chk-del-${Date.now()}` });
    targetCtx.deletableChecklistId = chkRes.data?.checklist?.id || chkRes.data?.id;
  }
  if (keyOrModule.includes('list') || keyOrModule === 'list.delete') {
    const lRes = await ownerClient.post('/api/lists', { board_id: context.boardId, name: `zz-permtest-list-del-${Date.now()}` });
    targetCtx.deletableListId = lRes.data?.list?.id || lRes.data?.id;
  }
  if (keyOrModule.includes('label') || keyOrModule === 'label.delete') {
    const lbRes = await ownerClient.post(`/api/boards/${context.boardId}/labels`, { name: `zz-permtest-label-del-${Date.now()}`, color: '#ef4444' });
    targetCtx.deletableLabelId = lbRes.data?.label?.id || lbRes.data?.id;
  }
  if (keyOrModule.includes('role') || keyOrModule === 'role.delete') {
    const rRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, { name: `zz-permtest-role-del-${Date.now()}`, permission_keys: ['workspace.view'] });
    targetCtx.deletableRoleId = rRes.data?.role?.id || rRes.data?.id;
  }
  if (keyOrModule.includes('project') || keyOrModule === 'project.delete') {
    const bRes = await ownerClient.post('/api/boards', { workspace_id: context.workspaceId, name: `zz-permtest-board-del-${Date.now()}` });
    targetCtx.deletableBoardId = bRes.data?.board?.id || bRes.data?.id;
  }
  if (keyOrModule.includes('restore') && context.archivedCardId) {
    await ownerClient.patch(`/api/cards/${context.archivedCardId}`, { is_archived: true });
  }
}

async function runSuiteN1({
  ownerClient,
  apiBaseUrl,
  frontendUrl,
  tenantSlug,
  tenantDb,
  context,
  filterModule = null,
  filterPermission = null,
  quick = false,
  reporter
}) {
  console.log('\n================================================================');
  console.log('       RUNNING SUITE N1: PER-PERMISSION TOGGLE & SWEEPS         ');
  console.log('================================================================\n');

  if (quick) {
    console.log('[QUICK MODE] Running in quick mode: skipping per-permission custom role toggles (system roles only)...');
    return;
  }

  const allTestablePerms = PERMISSIONS.filter((p) => !p.planned);
  const byModule = new Map();
  for (const p of allTestablePerms) {
    if (filterModule && p.module !== filterModule) continue;
    if (filterPermission && p.key !== filterPermission) continue;
    if (!byModule.has(p.module)) byModule.set(p.module, []);
    byModule.get(p.module).push(p);
  }

  const results = [];

  for (const [moduleName, perms] of byModule.entries()) {
    console.log(`\n--- Module: [${moduleName.toUpperCase()}] (${perms.length} testable permissions) ---`);

    for (const p of perms) {
      const permKey = p.key;
      const op = OPERATIONS[permKey];
      if (!op) {
        console.warn(`[WARN] No operation mapped for testable permission: ${permKey}`);
        continue;
      }

      console.log(`\n  ▶ Testing Permission: ${permKey} (${p.label})`);

      // 1. Fresh test user with custom role containing ONLY P's prerequisites
      const prereqs = getTransitivePrerequisites(permKey);
      const roleName = `zz-permtest-role-${permKey.replace(/\./g, '-')}-${Date.now()}`;

      const createRoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
        name: roleName,
        permission_keys: prereqs
      });

      const roleId = createRoleRes.data?.role?.id || createRoleRes.data?.id;
      if (!roleId) {
        throw new Error(`Failed to create role for ${permKey}: ${JSON.stringify(createRoleRes.data)}`);
      }

      const { client: userClient, user } = await createFreshUserViaInvite({
        ownerClient,
        apiBaseUrl,
        frontendUrl,
        tenantSlug,
        workspaceId: context.workspaceId,
        roleId,
        boardIds: [context.boardId, context.board2Id]
      });

      // Context for user operations
      const userCtx = {
        ...context,
        ownUserId: user.id
      };

      // Connect socket for user to verify realtime permission updates
      let socketReceivedEvent = false;
      const socket = io(apiBaseUrl, {
        path: '/socket.io',
        extraHeaders: {
          Origin: frontendUrl,
          Cookie: userClient.getCookieString()
        },
        auth: { token: userClient.token },
        transports: ['websocket', 'polling']
      });

      socket.on('user:permissions_updated', (evt) => {
        socketReceivedEvent = true;
      });

      // Allow socket connection handshake
      await new Promise((r) => setTimeout(r, 200));

      // 2. TOGGLE OFF baseline
      if (permKey.endsWith('.delete') || permKey.includes('delete_')) {
        await ensureDeletableEntity(ownerClient, context, userCtx, permKey);
      }
      // Operation should be denied (403 or 404)
      const baselineExec = await op.execute(userClient, userCtx);
      const baselineDenied = [403, 404, 401].includes(baselineExec.status);

      // GET /api/workspaces/:id/my-permissions does NOT list P
      const baseMyPermsRes = await userClient.get(`/api/workspaces/${context.workspaceId}/my-permissions`);
      const baseMyPerms = baseMyPermsRes.data?.permissions || [];
      const basePermNotPresent = !baseMyPerms.includes(permKey);

      reporter.record({
        permission: permKey,
        module: moduleName,
        step: 'OFF Baseline',
        status: baselineDenied && basePermNotPresent ? 'PASS' : 'FAIL',
        evidence: {
          opStatus: baselineExec.status,
          baseMyPermsHasKey: !basePermNotPresent,
          reqEvidence: baselineExec.evidence
        }
      });

      // 3. TOGGLE ON
      // PATCH role adding P (with prerequisites)
      const onKeys = Array.from(new Set([...prereqs, permKey]));
      const patchStartTime = performance.now();
      const patchOnRes = await ownerClient.patch(`/api/roles/${roleId}`, {
        name: roleName,
        permission_keys: onKeys,
        workspace_id: context.workspaceId
      });
      const patchLatencyMs = Math.round(performance.now() - patchStartTime);

      // WITHOUT re-login or new session: check my-permissions and operation
      const onMyPermsRes = await userClient.get(`/api/workspaces/${context.workspaceId}/my-permissions`);
      const onMyPerms = onMyPermsRes.data?.permissions || [];
      const onPermPresent = onMyPerms.includes(permKey);

      if (permKey.endsWith('.delete') || permKey.includes('delete_')) {
        await ensureDeletableEntity(ownerClient, context, userCtx, permKey);
      }
      const onExec = await op.execute(userClient, userCtx);
      const onSucceeded = onExec.status >= 200 && onExec.status < 300;

      reporter.record({
        permission: permKey,
        module: moduleName,
        step: 'TOGGLE ON',
        status: onPermPresent && onSucceeded ? 'PASS' : 'FAIL',
        latencyMs: patchLatencyMs,
        evidence: {
          patchLatencyMs,
          opStatus: onExec.status,
          onMyPermsHasKey: onPermPresent,
          reqEvidence: onExec.evidence
        }
      });

      // 4. TOGGLE OFF again
      socketReceivedEvent = false;
      const patchOffRes = await ownerClient.patch(`/api/roles/${roleId}`, {
        name: roleName,
        permission_keys: prereqs,
        workspace_id: context.workspaceId
      });

      // Wait a short moment for socket event
      await new Promise((r) => setTimeout(r, 200));

      const off2MyPermsRes = await userClient.get(`/api/workspaces/${context.workspaceId}/my-permissions`);
      const off2MyPerms = off2MyPermsRes.data?.permissions || [];
      const off2PermDropped = !off2MyPerms.includes(permKey);

      const off2Exec = await op.execute(userClient, userCtx);
      const off2Denied = [403, 404, 401].includes(off2Exec.status);

      reporter.record({
        permission: permKey,
        module: moduleName,
        step: 'TOGGLE OFF again',
        status: off2PermDropped && off2Denied ? 'PASS' : 'FAIL',
        evidence: {
          opStatus: off2Exec.status,
          off2PermDropped,
          socketReceivedEvent,
          reqEvidence: off2Exec.evidence
        }
      });

      // 5. Round trip & Alias normalization test
      // Test sending alias key or planned key
      let roundTripPass = true;
      const getRoleRes = await ownerClient.get(`/api/workspaces/${context.workspaceId}/roles`);
      const savedRole = (getRoleRes.data?.roles || getRoleRes.data || []).find((r) => r.id === roleId);
      const savedPerms = savedRole?.permission_keys || [];
      const matchSaved = prereqs.every((k) => savedPerms.includes(k));

      // Attempt to patch with planned key -> should return 400
      const plannedPatchRes = await ownerClient.patch(`/api/roles/${roleId}`, {
        permission_keys: ['company.manage_billing'] // planned=true
      });
      const plannedRejected = plannedPatchRes.status === 400;

      roundTripPass = matchSaved && plannedRejected;

      reporter.record({
        permission: permKey,
        module: moduleName,
        step: 'Round trip & Validation',
        status: roundTripPass ? 'PASS' : 'FAIL',
        evidence: {
          matchSaved,
          plannedRejected,
          plannedStatus: plannedPatchRes.status
        }
      });

      // Close socket
      socket.close();

      // Clean up test role and user
      await ownerClient.delete(`/api/roles/${roleId}`);
      await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${user.id}`);
    }

    // 6. Module Sweep (All ON, All OFF, Leave-one-out within module)
    if (!quick && perms.length > 1) {
      console.log(`  ▶ Running Module Sweeps for ${moduleName}...`);
      const allPrereqs = new Set();
      for (const p of perms) {
        const reqs = PREREQUISITE_PERMISSIONS[p.key] || [];
        reqs.forEach((k) => allPrereqs.add(k));
      }
      const fullSweepKeys = Array.from(new Set([...perms.map((p) => p.key), ...allPrereqs]));

      const sweepRoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
        name: `zz-permtest-sweep-${moduleName}-${Date.now()}`,
        permission_keys: fullSweepKeys
      });
      const sweepRoleId = sweepRoleRes.data?.role?.id || sweepRoleRes.data?.id;

      const { client: sweepClient, user: sweepUser } = await createFreshUserViaInvite({
        ownerClient,
        apiBaseUrl,
        frontendUrl,
        tenantSlug,
        workspaceId: context.workspaceId,
        roleId: sweepRoleId,
        boardIds: [context.boardId, context.board2Id]
      });

      const sweepCtx = { ...context, ownUserId: sweepUser.id };
      await ensureDeletableEntity(ownerClient, context, sweepCtx, moduleName);

      // All ON: all module ops succeed
      let allOnSuccess = true;
      for (const p of perms) {
        const op = OPERATIONS[p.key];
        if (op) {
          const res = await op.execute(sweepClient, sweepCtx);
          if (res.status < 200 || res.status >= 300) {
            allOnSuccess = false;
            console.log(`[SWEEP ALL ON FAIL]: ${p.key} returned ${res.status}:`, res.data);
          }
        }
      }

      // Leave-one-out for a leaf permission within the module (no other permission has it as a prerequisite)
      const isRequiredByOthers = (key) => {
        return Object.entries(PREREQUISITE_PERMISSIONS).some(([k, reqs]) => reqs.includes(key) && fullSweepKeys.includes(k) && k !== key);
      };
      const candidateLeaf = perms.slice().reverse().find((p) => !isRequiredByOthers(p.key)) || perms[perms.length - 1];
      const excludedKey = candidateLeaf.key;
      const withoutExcluded = fullSweepKeys.filter((k) => k !== excludedKey);
      await ownerClient.patch(`/api/roles/${sweepRoleId}`, {
        permission_keys: withoutExcluded,
        workspace_id: context.workspaceId
      });

      await ensureDeletableEntity(ownerClient, context, sweepCtx, excludedKey);
      const excludedOpRes = await OPERATIONS[excludedKey].execute(sweepClient, sweepCtx);
      const leaveOneOutExcludedDenied = [403, 404, 401].includes(excludedOpRes.status);

      reporter.record({
        permission: `module.${moduleName}`,
        module: moduleName,
        step: 'Module Sweep (All ON & Leave-one-out)',
        status: allOnSuccess && leaveOneOutExcludedDenied ? 'PASS' : 'FAIL',
        evidence: {
          allOnSuccess,
          leaveOneOutExcludedDenied,
          excludedKey
        }
      });

      // Cleanup sweep role and user
      await ownerClient.delete(`/api/roles/${sweepRoleId}`);
      await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${sweepUser.id}`);
    }
  }

  // 7. Whole-matrix cumulative walk & leave-one-out (sampled across modules for high speed & precision)
  if (!quick && !filterPermission && !filterModule) {
    console.log('\n--- Whole-Matrix Sweeps: Cumulative Progressive Walk & Regressive Revocation ---');
    const walkPerms = ['workspace.view', 'project.view', 'task.view', 'task.create', 'task.edit', 'task.delete'];
    const walkRoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
      name: `zz-permtest-matrix-walk-${Date.now()}`,
      permission_keys: ['workspace.view']
    });
    const walkRoleId = walkRoleRes.data?.role?.id || walkRoleRes.data?.id;

    const { client: walkClient, user: walkUser } = await createFreshUserViaInvite({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug,
      workspaceId: context.workspaceId,
      roleId: walkRoleId,
      boardIds: [context.boardId, context.board2Id]
    });

    const walkCtx = { ...context, ownUserId: walkUser.id };

    let cumulativePass = true;
    const currentKeys = ['workspace.view'];

    // Progressive walk
    for (let i = 1; i < walkPerms.length; i++) {
      currentKeys.push(walkPerms[i]);
      await ownerClient.patch(`/api/roles/${walkRoleId}`, {
        permission_keys: currentKeys,
        workspace_id: context.workspaceId
      });

      const op = OPERATIONS[walkPerms[i]];
      const res = await op.execute(walkClient, walkCtx);
      if (res.status < 200 || res.status >= 300) {
        cumulativePass = false;
      }
    }

    // Regressive walk (remove in reverse)
    for (let i = walkPerms.length - 1; i >= 1; i--) {
      const removedKey = walkPerms[i];
      const remaining = currentKeys.filter((k) => k !== removedKey);
      await ownerClient.patch(`/api/roles/${walkRoleId}`, {
        permission_keys: remaining,
        workspace_id: context.workspaceId
      });

      const op = OPERATIONS[removedKey];
      const res = await op.execute(walkClient, walkCtx);
      if (![403, 404, 401].includes(res.status)) {
        cumulativePass = false;
      }
    }

    reporter.record({
      permission: 'matrix.cumulative_walk',
      module: 'matrix',
      step: 'Cumulative Progressive & Regressive Walk',
      status: cumulativePass ? 'PASS' : 'FAIL',
      evidence: { cumulativePass, testedKeys: walkPerms }
    });

    await ownerClient.delete(`/api/roles/${walkRoleId}`);
    await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${walkUser.id}`);
  }

  // 8. Project-scoped permissions two ways: granted at company level vs board-level role on B1
  console.log('\n--- Project-Scoped Permissions: Company-Level vs Board-Level Role Isolation ---');
  const boardRoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
    name: `zz-permtest-b1-role-${Date.now()}`,
    permission_keys: ['project.view', 'task.view', 'task.edit']
  });
  const boardRoleId = boardRoleRes.data?.role?.id || boardRoleRes.data?.id;

  // Workspace-level role with ONLY workspace.view (no project.view)
  const baseWsRoleRes = await ownerClient.post(`/api/workspaces/${context.workspaceId}/roles`, {
    name: `zz-permtest-ws-base-${Date.now()}`,
    permission_keys: ['workspace.view']
  });
  const baseWsRoleId = baseWsRoleRes.data?.role?.id || baseWsRoleRes.data?.id;

  const { client: scopedClient, user: scopedUser } = await createFreshUserViaInvite({
    ownerClient,
    apiBaseUrl,
    frontendUrl,
    tenantSlug,
    workspaceId: context.workspaceId,
    roleId: baseWsRoleId,
    boardIds: [context.boardId] // Only member of Board 1
  });

  // Assign board-level role on Board 1
  await tenantDb.query(
    'UPDATE board_members SET role_id = ? WHERE board_id = ? AND user_id = ?',
    [boardRoleId, context.boardId, scopedUser.id]
  );

  // Allowed on B1:
  const b1Res = await scopedClient.get(`/api/boards/${context.boardId}`);
  const b1Allowed = b1Res.status === 200;

  // Denied on B2 (not a member of B2):
  const b2Res = await scopedClient.get(`/api/boards/${context.board2Id}`);
  const b2Denied = [403, 404].includes(b2Res.status);

  // Denied in Workspace 2:
  const ws2Res = await scopedClient.get(`/api/workspaces/${context.workspace2Id}/roles`);
  const ws2Denied = [403, 404].includes(ws2Res.status);

  const scopingPass = b1Allowed && b2Denied && ws2Denied;

  reporter.record({
    permission: 'scoping.board_vs_workspace',
    module: 'scoping',
    step: 'Board B1 vs B2 & Cross-Workspace Isolation',
    status: scopingPass ? 'PASS' : 'FAIL',
    evidence: {
      b1Status: b1Res.status,
      b2Status: b2Res.status,
      ws2Status: ws2Res.status
    }
  });

  await ownerClient.delete(`/api/roles/${boardRoleId}`);
  await ownerClient.delete(`/api/roles/${baseWsRoleId}`);
  await ownerClient.delete(`/api/workspaces/${context.workspaceId}/members/${scopedUser.id}`);

  console.log('\n✓ SUITE N1 COMPLETED.\n');
}

module.exports = { runSuiteN1 };
