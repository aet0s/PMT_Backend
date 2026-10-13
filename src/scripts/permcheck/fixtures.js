// server/src/scripts/permcheck/fixtures.js
// Sets up test entities with prefix "zz-permtest-" and cleans them up.

const crypto = require('crypto');
const { BrowserClient } = require('./browserClient');
const { getTenantDb, getMasterDb } = require('../../services/tenantPools');

async function setupFixtures({ apiBaseUrl, frontendUrl, ownerEmail, ownerPassword, tenantSlug, tenantId }) {
  const { getDevSingleDb, getTenantDb } = require('../../services/tenantPools');
  const ownerClient = new BrowserClient({ apiBaseUrl, frontendUrl });

  // 1. Owner Login
  const loginPayload = { email: ownerEmail, password: ownerPassword };
  if (tenantSlug) loginPayload.tenant_slug = tenantSlug;

  const loginRes = await ownerClient.post('/api/auth/login', loginPayload);

  if (loginRes.status !== 200 || !ownerClient.token) {
    throw new Error(`Owner login failed (${loginRes.status}): ${JSON.stringify(loginRes.data)}`);
  }

  const tenantDb = (tenantId && process.env.DEV_SINGLE_TENANT !== '1') ? await getTenantDb(tenantId) : getDevSingleDb();

  // 2. Fetch or create test workspace W1
  let wsRes = await ownerClient.get('/api/workspaces');
  const wsList = Array.isArray(wsRes.data) ? wsRes.data : (wsRes.data?.workspaces || []);
  let workspace = wsList.find((w) => w.name?.includes('zz-permtest-w1'));
  if (!workspace) {
    const createWsRes = await ownerClient.post('/api/workspaces', {
      name: `zz-permtest-w1-${Date.now()}`
    });
    workspace = createWsRes.data?.workspace || createWsRes.data;
  }
  const workspaceId = workspace.id;

  // 3. Create second workspace W2 for cross-workspace isolation tests
  let workspace2 = wsList.find((w) => w.name?.includes('zz-permtest-w2'));
  if (!workspace2) {
    const createWs2Res = await ownerClient.post('/api/workspaces', {
      name: `zz-permtest-w2-${Date.now()}`
    });
    workspace2 = createWs2Res.data?.workspace || createWs2Res.data;
  }
  const workspace2Id = workspace2.id;

  // 4. Create deletable sub-workspace
  const delWsRes = await ownerClient.post('/api/workspaces', {
    name: `zz-permtest-ws-del-${Date.now()}`
  });
  const deletableWorkspaceId = delWsRes.data?.workspace?.id || delWsRes.data?.id;

  // 5. Fetch system roles in W1
  const rolesRes = await ownerClient.get(`/api/workspaces/${workspaceId}/roles`);
  const roles = rolesRes.data?.roles || rolesRes.data || [];
  const systemRoleMap = {};
  roles.forEach((r) => {
    systemRoleMap[r.name] = r.id;
  });

  // 6. Create board B1 and board B2 (scoped)
  const b1Res = await ownerClient.post('/api/boards', {
    workspace_id: workspaceId,
    name: `zz-permtest-board-b1-${Date.now()}`
  });
  const boardId = b1Res.data?.board?.id || b1Res.data?.id;

  const b2Res = await ownerClient.post('/api/boards', {
    workspace_id: workspaceId,
    name: `zz-permtest-board-b2-${Date.now()}`
  });
  const board2Id = b2Res.data?.board?.id || b2Res.data?.id;

  // Deletable board
  const delBoardRes = await ownerClient.post('/api/boards', {
    workspace_id: workspaceId,
    name: `zz-permtest-board-del-${Date.now()}`
  });
  const deletableBoardId = delBoardRes.data?.board?.id || delBoardRes.data?.id;

  // 7. Create list in B1
  const listRes = await ownerClient.post('/api/lists', {
    board_id: boardId,
    name: `zz-permtest-list-1`
  });
  const listId = listRes.data?.list?.id || listRes.data?.id;

  // Deletable list
  const delListRes = await ownerClient.post('/api/lists', {
    board_id: boardId,
    name: `zz-permtest-list-del`
  });
  const deletableListId = delListRes.data?.list?.id || delListRes.data?.id;

  // 8. Create card in list
  const cardRes = await ownerClient.post('/api/cards', {
    list_id: listId,
    title: `zz-permtest-card-1`
  });
  const cardId = cardRes.data?.card?.id || cardRes.data?.id;

  // Deletable card
  const delCardRes = await ownerClient.post('/api/cards', {
    list_id: listId,
    title: `zz-permtest-card-del`
  });
  const deletableCardId = delCardRes.data?.card?.id || delCardRes.data?.id;

  // Archived card for restore
  const archCardRes = await ownerClient.post('/api/cards', {
    list_id: listId,
    title: `zz-permtest-card-archived`
  });
  const archivedCardId = archCardRes.data?.card?.id || archCardRes.data?.id;
  await ownerClient.patch(`/api/cards/${archivedCardId}`, { is_archived: true });

  // 9. Create checklist in card
  const chkRes = await ownerClient.post(`/api/cards/${cardId}/checklists`, {
    title: `zz-permtest-chk-1`
  });
  const checklistId = chkRes.data?.checklist?.id || chkRes.data?.id;

  const delChkRes = await ownerClient.post(`/api/cards/${cardId}/checklists`, {
    title: `zz-permtest-chk-del`
  });
  const deletableChecklistId = delChkRes.data?.checklist?.id || delChkRes.data?.id;

  // 10. Create comments
  const otherCommRes = await ownerClient.post(`/api/cards/${cardId}/comments`, {
    body: `zz-permtest-other-comment`
  });
  const otherCommentId = otherCommRes.data?.comment?.id || otherCommRes.data?.id;

  // 11. Create label
  const lblRes = await ownerClient.post(`/api/boards/${boardId}/labels`, {
    name: `zz-permtest-lbl-1`,
    color: '#3b82f6'
  });
  const labelId = lblRes.data?.label?.id || lblRes.data?.id;

  const delLblRes = await ownerClient.post(`/api/boards/${boardId}/labels`, {
    name: `zz-permtest-lbl-del`,
    color: '#ef4444'
  });
  const deletableLabelId = delLblRes.data?.label?.id || delLblRes.data?.id;

  // 12. Create deletable custom role
  const delRoleRes = await ownerClient.post(`/api/workspaces/${workspaceId}/roles`, {
    name: `zz-permtest-role-del-${Date.now()}`,
    permission_keys: ['workspace.view']
  });
  const deletableRoleId = delRoleRes.data?.role?.id || delRoleRes.data?.id;

  // 13. Create helper dummy user for member operations
  const targetEmail = `zz-permtest-target-${Date.now()}@example.com`;
  const inviteRes = await ownerClient.post('/api/invitations', {
    email: targetEmail,
    workspace_id: workspaceId,
    board_ids: [boardId],
    role_id: systemRoleMap['Viewer']
  });
  const inviteToken = inviteRes.data?.invite_token || inviteRes.data?.invitation?.token || inviteRes.data?.token;

  const targetClient = new BrowserClient({ apiBaseUrl, frontendUrl });
  const regRes = await targetClient.post('/api/auth/register', {
    name: 'Target Test User',
    email: targetEmail,
    password: 'TargetPass123!@#',
    invite_token: inviteToken
  });
  const targetLogin = { email: targetEmail, password: 'TargetPass123!@#' };
  if (tenantSlug) targetLogin.tenant_slug = tenantSlug;
  await targetClient.post('/api/auth/login', targetLogin);
  const targetUserId = regRes.data?.user?.id || regRes.data?.userId;

  // Removable user
  const remEmail = `zz-permtest-removable-${Date.now()}@example.com`;
  const remInvRes = await ownerClient.post('/api/invitations', {
    email: remEmail,
    workspace_id: workspaceId,
    board_ids: [boardId],
    role_id: systemRoleMap['Viewer']
  });
  const remToken = remInvRes.data?.invite_token || remInvRes.data?.invitation?.token || remInvRes.data?.token;
  const remClient = new BrowserClient({ apiBaseUrl, frontendUrl });
  const remRegRes = await remClient.post('/api/auth/register', {
    name: 'Removable User',
    email: remEmail,
    password: 'TargetPass123!@#',
    invite_token: remToken
  });
  const removableUserId = remRegRes.data?.user?.id || remRegRes.data?.userId;

  // Fetch a session ID for other user
  let otherSessionId = null;
  const targetSessRes = await targetClient.get('/api/auth/sessions');
  if (Array.isArray(targetSessRes.data?.sessions) && targetSessRes.data.sessions.length > 0) {
    otherSessionId = targetSessRes.data.sessions[0].id;
  }

  const context = {
    apiBaseUrl,
    frontendUrl,
    tenantSlug,
    workspaceId,
    workspace2Id,
    deletableWorkspaceId,
    boardId,
    board2Id,
    deletableBoardId,
    listId,
    deletableListId,
    cardId,
    deletableCardId,
    archivedCardId,
    checklistId,
    deletableChecklistId,
    otherCommentId,
    labelId,
    deletableLabelId,
    deletableRoleId,
    targetUserId,
    removableUserId,
    otherSessionId,
    viewerRoleId: systemRoleMap['Viewer'],
    systemRoleMap
  };

  return {
    ownerClient,
    tenantDb,
    context
  };
}

/**
 * Creates a fresh test user through the official invitation & registration flow.
 */
async function createFreshUserViaInvite({
  ownerClient,
  apiBaseUrl,
  frontendUrl,
  tenantSlug,
  workspaceId,
  roleId,
  boardIds = []
}) {
  const email = `zz-permtest-u-${Date.now()}-${crypto.randomBytes(3).toString('hex')}@example.com`;
  const password = 'FreshUserPassword123!@#';

  const invRes = await ownerClient.post('/api/invitations', {
    email,
    workspace_id: workspaceId,
    board_ids: boardIds,
    role_id: roleId
  });

  const inviteToken = invRes.data?.invite_token || invRes.data?.invitation?.token || invRes.data?.token;
  if (!inviteToken) {
    throw new Error(`Failed to create invite token: ${JSON.stringify(invRes.data)}`);
  }

  const client = new BrowserClient({ apiBaseUrl, frontendUrl });
  const regRes = await client.post('/api/auth/register', {
    name: `Test User ${Date.now()}`,
    email,
    password,
    invite_token: inviteToken
  });

  if (regRes.status !== 201 && regRes.status !== 200) {
    throw new Error(`Registration failed: ${JSON.stringify(regRes.data)}`);
  }

  const userLoginPayload = { email, password };
  if (tenantSlug) userLoginPayload.tenant_slug = tenantSlug;
  const loginRes = await client.post('/api/auth/login', userLoginPayload);

  const user = regRes.data?.user || loginRes.data?.user;

  return {
    client,
    user,
    email,
    password
  };
}

async function cleanupFixtures(tenantDb) {
  if (!tenantDb) return;
  console.log('[CLEANUP] Removing test entities starting with "zz-permtest-"...');
  try {
    await tenantDb.query("DELETE FROM cards WHERE title LIKE 'zz-permtest-%'");
    await tenantDb.query("DELETE FROM lists WHERE name LIKE 'zz-permtest-%'");
    await tenantDb.query("DELETE FROM boards WHERE name LIKE 'zz-permtest-%'");
    await tenantDb.query("DELETE FROM roles WHERE name LIKE 'zz-permtest-%' AND is_system = 0");
    await tenantDb.query("DELETE FROM workspaces WHERE name LIKE 'zz-permtest-%'");
    await tenantDb.query("DELETE FROM pending_invitations WHERE email LIKE 'zz-permtest-%'");
    await tenantDb.query("DELETE FROM users WHERE email LIKE 'zz-permtest-%'");
    console.log('[CLEANUP] Successfully cleaned up all zz-permtest- entities.');
  } catch (err) {
    console.warn('[CLEANUP_WARN] Cleanup encountered error:', err.message);
  }
}

module.exports = {
  setupFixtures,
  createFreshUserViaInvite,
  cleanupFixtures
};
