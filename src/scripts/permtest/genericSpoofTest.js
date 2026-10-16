// server/src/scripts/permtest/genericSpoofTest.js
// Generic route-driven spoof test (Phase C.5 Item 1).
// For every route in routePermissions.js that has a resource param,
// an Admin of W1 targeting a W2 resource (with W1 ids supplied wherever
// board_id/workspace_id can be sent) must never get 2xx.

const { ROUTE_PERMISSIONS } = require('../../rbac/routePermissions');

async function runGenericSpoofTest(fixture) {
  const adminActor = fixture.users['Admin'];
  const adminClient = adminActor.client;
  const adminUserId = adminActor.user.id;
  const ctx = fixture.context;
  const w1Id = ctx.w1Id;
  const boardAId = ctx.boardAId;
  const w2Id = ctx.w2Id;
  const boardCId = ctx.boardCId;

  console.log('\n================================================================');
  console.log('       RUNNING GENERIC ROUTE-DRIVEN SPOOF TEST (Item 1)         ');
  console.log('================================================================');
  console.log(`Actor: Admin of W1 (User ID: ${adminUserId})`);
  console.log(`Target: Resources belonging to W2 (Workspace ID: ${w2Id}, Board ID: ${boardCId})`);

  // 1. Ensure all W2 resources exist for probing
  // Board C label
  const labelRes = await fixture.ownerClient.post(`/api/boards/${boardCId}/labels`, {
    name: 'W2 Test Label',
    color: '#10b981'
  });
  const labelW2Id = labelRes.data?.label?.id || labelRes.data?.id;

  // W2 Role
  const roleRes = await fixture.ownerClient.post(`/api/workspaces/${w2Id}/roles`, {
    name: 'W2 Custom Role',
    permission_keys: ['project.view']
  });
  const roleW2Id = roleRes.data?.role?.id || roleRes.data?.id;

  // W2 Invitation
  const { getTenantDb } = require('../../services/tenantPools');
  const tenantDb = await getTenantDb(ctx.tenantId);
  await fixture.ownerClient.post('/api/invitations', {
    email: `w2_probe_${Date.now()}@example.com`,
    workspace_id: w2Id,
    role_id: roleW2Id
  });
  const invRows = await tenantDb.query(
    'SELECT id FROM pending_invitations WHERE workspace_id = ? ORDER BY id DESC LIMIT 1',
    [w2Id]
  );
  const invitationW2Id = invRows[0]?.id;

  // W2 Member (Probe user added to W2)
  const probeUserId = fixture.users['Probe'].user.id;
  await fixture.ownerClient.post(`/api/workspaces/${w2Id}/members`, {
    user_id: probeUserId,
    role_id: roleW2Id
  });
  const memberW2UserId = probeUserId;

  const results = [];
  const unprobedRoutes = [];
  let routesCovered = 0;

  for (const [routeKey, meta] of ROUTE_PERMISSIONS.entries()) {
    const [method, pathTemplate] = routeKey.split(' ');

    // Only test routes with resource params
    if (!pathTemplate.includes(':')) continue;

    // Self-scoped routes that are not workspace/board resources
    if (pathTemplate.startsWith('/api/auth/sessions') || 
        pathTemplate.startsWith('/api/notifications') ||
        pathTemplate.startsWith('/api/files/:tenantId')) {
      unprobedRoutes.push({ route: routeKey, reason: 'Self-scoped user session/notification/file route (non-workspace resource)' });
      continue;
    }


    // Substitute params with W2 IDs
    let actualPath = pathTemplate;
    let missingParam = false;

    if (actualPath.includes(':workspaceId')) {
      actualPath = actualPath.replace(':workspaceId', w2Id);
    }
    if (actualPath.includes(':labelId')) {
      actualPath = actualPath.replace(':labelId', labelW2Id);
    }
    if (actualPath.includes(':userId')) {
      actualPath = actualPath.replace(':userId', memberW2UserId);
    }

    // Generic :id replacement based on route prefix
    if (actualPath.includes('/:id')) {
      let replacementId = null;
      if (actualPath.startsWith('/api/workspaces/:id')) replacementId = w2Id;
      else if (actualPath.startsWith('/api/roles/:id')) replacementId = roleW2Id;
      else if (actualPath.startsWith('/api/boards/:id')) replacementId = boardCId;
      else if (actualPath.startsWith('/api/lists/:id')) replacementId = ctx.listW2Id;
      else if (actualPath.startsWith('/api/cards/attachments/:id')) replacementId = ctx.attachmentW2Id;
      else if (actualPath.startsWith('/api/cards/comments/:id') || actualPath.startsWith('/api/comments/:id')) replacementId = ctx.commentW2Id;
      else if (actualPath.startsWith('/api/cards/checklists/:id') || actualPath.startsWith('/api/checklists/:id')) replacementId = ctx.checklistW2Id;
      else if (actualPath.startsWith('/api/cards/checklist-items/:id') || actualPath.startsWith('/api/checklist-items/:id')) replacementId = ctx.checklistItemW2Id;
      else if (actualPath.startsWith('/api/cards/:id')) replacementId = ctx.cardW2Id;
      else if (actualPath.startsWith('/api/attachments/:id')) replacementId = ctx.attachmentW2Id;
      else if (actualPath.startsWith('/api/invitations/:id')) replacementId = invitationW2Id;

      if (replacementId) {
        actualPath = actualPath.replace('/:id', `/${replacementId}`);
      } else {
        missingParam = true;
      }
    }

    if (missingParam || actualPath.includes(':')) {
      unprobedRoutes.push({ route: routeKey, reason: `Unmatched parameter pattern: ${actualPath}` });
      continue;
    }

    // Prepare spoof payload with W1 IDs injected in query and body
    const query = `?workspace_id=${w1Id}&board_id=${boardAId}`;
    const targetUrl = actualPath + query;
    const body = {
      workspace_id: w1Id,
      board_id: boardAId,
      name: 'Spoof Test',
      title: 'Spoof Test',
      description: 'Spoofed description',
      text: 'Spoofed text',
      body: 'Spoofed comment',
      link_url: 'https://example.com/spoof',
      display_name: 'Spoof Link',
      email: `spoof_${Date.now()}@example.com`,
      role: 'member',
      role_id: fixture.users['Team Member'].roleId || 1,
      is_archived: false,
      color: '#3b82f6'
    };

    let response;
    try {
      if (method === 'GET') {
        response = await adminClient.get(targetUrl);
      } else if (method === 'POST') {
        response = await adminClient.post(targetUrl, body);
      } else if (method === 'PATCH') {
        response = await adminClient.patch(targetUrl, body);
      } else if (method === 'DELETE') {
        response = await adminClient.delete(targetUrl, body);
      } else if (method === 'PUT') {
        response = await adminClient.put(targetUrl, body);
      }
    } catch (err) {
      response = { status: 500, error: err.message };
    }

    routesCovered++;
    const isLeak = response.status >= 200 && response.status < 300;
    results.push({
      route: routeKey,
      method,
      actualPath,
      status: response.status,
      passed: !isLeak
    });

    if (isLeak) {
      console.error(`❌ CRITICAL LEAK on ${routeKey}: returned HTTP ${response.status}!`);
    }
  }

  const failedRoutes = results.filter((r) => !r.passed);
  console.log(`\nResults: ${routesCovered} parameterized routes probed.`);
  console.log(`Passed (4xx rejected): ${results.filter((r) => r.passed).length}`);
  console.log(`Failed (2xx leaked):   ${failedRoutes.length}`);
  console.log(`Unprobed routes:       ${unprobedRoutes.length}`);

  if (unprobedRoutes.length > 0) {
    console.log('\nUnprobed Routes List:');
    unprobedRoutes.forEach((u) => console.log(`  - ${u.route} (${u.reason})`));
  }

  if (failedRoutes.length > 0) {
    console.error('\nFAILURES:');
    failedRoutes.forEach((f) => console.error(`  - ${f.route} -> ${f.status}`));
    throw new Error(`Generic Spoof Test FAILED: ${failedRoutes.length} route(s) leaked 2xx!`);
  }

  console.log('\n✅ PASS: Generic route-driven spoof test passed with 100% rejection (0 leaks).');
  return {
    routesCovered,
    unprobedRoutes,
    passedCount: results.length,
    failedCount: failedRoutes.length
  };
}

module.exports = { runGenericSpoofTest };
