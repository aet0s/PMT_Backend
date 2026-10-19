// server/src/scripts/permtest/fixtures.js
// Provisions a clean, disposable test tenant with workspaces, boards, roles, and test users.
// Strict guard: Slug prefix MUST be "permtest_".

require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });
const crypto = require('crypto');
const { PermtestClient } = require('./client');
const { provisionTenant, slugify, dropTenantDatabase } = require('../../services/tenantProvisioner');
const { getMasterDb, getTenantDb, evictTenantPool, closeAllTenantPools } = require('../../services/tenantPools');
const { generateCompliantPassword } = require('../../utils/passwordPolicy');
const { syncSingleTenant } = require('../rbacMatrixV2Sync');

class PermtestFixture {
  constructor(options = {}) {
    this.options = options;
    this.frontendUrl = options.frontendUrl || 'http://localhost:5173';
    this.apiUrl = options.apiUrl || null;
    this.slug = options.slug || `permtest_${Date.now().toString(36)}_${crypto.randomBytes(3).toString('hex')}`;

    if (!this.slug.startsWith('permtest_')) {
      throw new Error(`[SECURITY VIOLATION] Permtest fixture slug "${this.slug}" must start with "permtest_"`);
    }

    this.ownerEmail = `owner_${this.slug}@permtest.local`;
    this.ownerPassword = generateCompliantPassword(16);
    this.tenant = null;
    this.tenantDb = null;
    this.ownerClient = null;
    this.users = {}; // roleName -> { client, user, email, password }
    this.context = {};
  }

  async setup() {
    console.log(`\n[FIXTURE] Provisioning test tenant "${this.slug}"...`);
    const masterDb = getMasterDb();

    // 1. Provision fresh tenant
    const provisionResult = await provisionTenant({
      companyName: `Permtest Corp ${this.slug}`,
      slug: this.slug,
      ownerEmail: this.ownerEmail,
      ownerPassword: this.ownerPassword,
      ownerName: 'Matrix Owner'
    });

    this.tenant = provisionResult.tenant;
    this.tenantDb = await getTenantDb(this.tenant.id);

    // Apply Phase C RBAC Matrix v2 to fixture tenant
    await syncSingleTenant(this.tenantDb, this.slug, { isApply: true, force: true, silent: true });

    // 2. Owner login via frontend URL
    this.ownerClient = new PermtestClient({
      frontendUrl: this.frontendUrl,
      apiUrl: this.apiUrl
    });

    await new Promise((r) => setTimeout(r, 250));
    console.log('CALLING LOGIN ON URL:', this.ownerClient.apiBaseUrl, this.ownerEmail, this.slug);
    let ownerLoginRes = await this.ownerClient.post('/api/auth/login', {
      email: this.ownerEmail,
      password: this.ownerPassword,
      tenant_slug: this.slug
    });
    console.log('OWNER LOGIN RES STATUS:', ownerLoginRes.status, 'RAW:', ownerLoginRes.rawText);

    let retryCount = 0;
    while ((ownerLoginRes.status !== 200 || !this.ownerClient.token) && retryCount < 6) {
      retryCount++;
      await new Promise((r) => setTimeout(r, 600 * retryCount));
      ownerLoginRes = await this.ownerClient.post('/api/auth/login', {
        email: this.ownerEmail,
        password: this.ownerPassword,
        tenant_slug: this.slug
      });
    }

    if (ownerLoginRes.status !== 200 || !this.ownerClient.token) {
      throw new Error(`[FIXTURE] Owner login failed (${ownerLoginRes.status}): ${JSON.stringify(ownerLoginRes.data)}`);
    }

    this.ownerClient.user = ownerLoginRes.data?.user;
    this.ownerClient.roleName = 'Owner';

    this.users['Owner'] = {
      client: this.ownerClient,
      user: ownerLoginRes.data?.user,
      email: this.ownerEmail,
      password: this.ownerPassword
    };

    // 3. Setup Workspaces W1 and W2
    const wsRes = await this.ownerClient.get('/api/workspaces');
    const wsList = Array.isArray(wsRes.data) ? wsRes.data : (wsRes.data?.workspaces || []);
    let w1 = wsList[0];
    if (!w1) {
      const createW1 = await this.ownerClient.post('/api/workspaces', { name: `W1-${this.slug}` });
      w1 = createW1.data?.workspace || createW1.data;
    }
    const createW2 = await this.ownerClient.post('/api/workspaces', { name: `W2-${this.slug}` });
    const w2 = createW2.data?.workspace || createW2.data;

    const w1Id = w1.id;
    const w2Id = w2.id;

    // 4. Fetch available roles
    const rolesRes = await this.ownerClient.get(`/api/workspaces/${w1Id}/roles`);
    if (!Array.isArray(rolesRes.data?.roles) && !Array.isArray(rolesRes.data)) {
      throw new Error(`[FIXTURE] Failed to get roles: status=${rolesRes.status}, data=${JSON.stringify(rolesRes.data)}`);
    }
    const roles = rolesRes.data?.roles || rolesRes.data || [];
    const roleMap = {};
    roles.forEach((r) => {
      roleMap[r.name] = r.id;
    });

    // 5. Setup Boards: Board A (in W1), Board B (in W1, cross-board boundary), Board C (in W2)
    const bARes = await this.ownerClient.post('/api/boards', {
      workspace_id: w1Id,
      name: `Board A`
    });
    const boardAId = bARes.data?.board?.id || bARes.data?.id;

    const bBRes = await this.ownerClient.post('/api/boards', {
      workspace_id: w1Id,
      name: `Board B`
    });
    const boardBId = bBRes.data?.board?.id || bBRes.data?.id;

    const bCRes = await this.ownerClient.post('/api/boards', {
      workspace_id: w2Id,
      name: `Board C`
    });
    const boardCId = bCRes.data?.board?.id || bCRes.data?.id;

    // Entities on Board B (Workspace 1, non-member board)
    const listBRes = await this.ownerClient.post('/api/lists', {
      board_id: boardBId,
      name: 'List B'
    });
    const listBId = listBRes.data?.list?.id || listBRes.data?.id;

    const cardBRes = await this.ownerClient.post('/api/cards', {
      list_id: listBId,
      title: 'Card B'
    });
    const cardBId = cardBRes.data?.card?.id || cardBRes.data?.id;

    const chkBRes = await this.ownerClient.post(`/api/cards/${cardBId}/checklists`, {
      title: 'Checklist B'
    });
    const checklistBId = chkBRes.data?.checklist?.id || chkBRes.data?.id;

    const chkItemBRes = await this.ownerClient.post('/api/cards/checklist-items', {
      checklist_id: checklistBId,
      text: 'Item B'
    });
    const checklistItemBId = chkItemBRes.data?.item?.id || chkItemBRes.data?.id;

    const comBRes = await this.ownerClient.post(`/api/cards/${cardBId}/comments`, {
      body: 'Comment B'
    });
    const commentBId = comBRes.data?.comment?.id || comBRes.data?.id;

    const attBRes = await this.ownerClient.post(`/api/cards/${cardBId}/attachments/link`, {
      link_url: 'https://example.com/b',
      display_name: 'Attachment B'
    });
    const attachmentBId = attBRes.data?.attachment?.id || attBRes.data?.id;

    const labelBRes = await this.ownerClient.post(`/api/boards/${boardBId}/labels`, {
      name: `Label B`,
      color: '#10b981'
    });
    const labelBId = labelBRes.data?.label?.id || labelBRes.data?.id;

    // 6. Setup entities on Board A
    const listRes = await this.ownerClient.post('/api/lists', {
      board_id: boardAId,
      name: `List 1`
    });
    const list1Id = listRes.data?.list?.id || listRes.data?.id;

    const listDelRes = await this.ownerClient.post('/api/lists', {
      board_id: boardAId,
      name: `List Deletable`
    });
    const listDelId = listDelRes.data?.list?.id || listDelRes.data?.id;

    const cardRes = await this.ownerClient.post('/api/cards', {
      list_id: list1Id,
      title: `Card 1`
    });
    const card1Id = cardRes.data?.card?.id || cardRes.data?.id;

    const cardDelRes = await this.ownerClient.post('/api/cards', {
      list_id: list1Id,
      title: `Card Deletable`
    });
    const cardDelId = cardDelRes.data?.card?.id || cardDelRes.data?.id;

    const cardArchRes = await this.ownerClient.post('/api/cards', {
      list_id: list1Id,
      title: `Card Archived`
    });
    const cardArchId = cardArchRes.data?.card?.id || cardArchRes.data?.id;
    await this.ownerClient.patch(`/api/cards/${cardArchId}`, { is_archived: true });

    const chkRes = await this.ownerClient.post(`/api/cards/${card1Id}/checklists`, {
      title: `Checklist 1`
    });
    const checklist1Id = chkRes.data?.checklist?.id || chkRes.data?.id;

    const commentRes = await this.ownerClient.post(`/api/cards/${card1Id}/comments`, {
      body: `Owner test comment`
    });
    const comment1Id = commentRes.data?.comment?.id || commentRes.data?.id;

    const chkItemRes = await this.ownerClient.post('/api/cards/checklist-items', {
      checklist_id: checklist1Id,
      text: 'Checklist Item 1'
    });
    const checklistItem1Id = chkItemRes.data?.item?.id || chkItemRes.data?.id;

    const attRes = await this.ownerClient.post(`/api/cards/${card1Id}/attachments/link`, {
      link_url: 'https://example.com/attachment1',
      display_name: 'Attachment 1'
    });
    const attachment1Id = attRes.data?.attachment?.id || attRes.data?.id;

    const labelRes = await this.ownerClient.post(`/api/boards/${boardAId}/labels`, {
      name: `Label 1`,
      color: '#3b82f6'
    });
    const label1Id = labelRes.data?.label?.id || labelRes.data?.id;

    // Entities on Board C (Workspace 2) for cross-workspace tests
    const listW2Res = await this.ownerClient.post('/api/lists', {
      board_id: boardCId,
      name: 'List W2'
    });
    const listW2Id = listW2Res.data?.list?.id || listW2Res.data?.id;

    const cardW2Res = await this.ownerClient.post('/api/cards', {
      list_id: listW2Id,
      title: 'Card W2'
    });
    const cardW2Id = cardW2Res.data?.card?.id || cardW2Res.data?.id;

    const chkW2Res = await this.ownerClient.post(`/api/cards/${cardW2Id}/checklists`, {
      title: 'Checklist W2'
    });
    const checklistW2Id = chkW2Res.data?.checklist?.id || chkW2Res.data?.id;

    const chkItemW2Res = await this.ownerClient.post('/api/cards/checklist-items', {
      checklist_id: checklistW2Id,
      text: 'Item W2'
    });
    const checklistItemW2Id = chkItemW2Res.data?.item?.id || chkItemW2Res.data?.id;

    const comW2Res = await this.ownerClient.post(`/api/cards/${cardW2Id}/comments`, {
      body: 'Comment W2'
    });
    const commentW2Id = comW2Res.data?.comment?.id || comW2Res.data?.id;

    const attW2Res = await this.ownerClient.post(`/api/cards/${cardW2Id}/attachments/link`, {
      link_url: 'https://example.com/w2',
      display_name: 'Attachment W2'
    });
    const attachmentW2Id = attW2Res.data?.attachment?.id || attW2Res.data?.id;

    const labelW2Res = await this.ownerClient.post(`/api/boards/${boardCId}/labels`, {
      name: 'Label W2',
      color: '#ef4444'
    });
    const labelW2Id = labelW2Res.data?.label?.id || labelW2Res.data?.id;

    // 7. Create Probe Custom Role in W1
    const probeRoleRes = await this.ownerClient.post(`/api/workspaces/${w1Id}/roles`, {
      name: `Probe Role`,
      permission_keys: ['workspace.view', 'project.view', 'task.view']
    });
    const probeRoleId = probeRoleRes.data?.role?.id || probeRoleRes.data?.id;
    roleMap['Probe'] = probeRoleId;

    // 7b. Create Unprivileged Assignable Roles in W1 and W2 (rank 30, no permissions)
    const assignableW1Res = await this.ownerClient.post(`/api/workspaces/${w1Id}/roles`, {
      name: `Unprivileged Role W1`,
      permission_keys: []
    });
    const assignableRoleW1Id = assignableW1Res.data?.role?.id || assignableW1Res.data?.id;

    const assignableW2Res = await this.ownerClient.post(`/api/workspaces/${w2Id}/roles`, {
      name: `Unprivileged Role W2`,
      permission_keys: []
    });
    const assignableRoleW2Id = assignableW2Res.data?.role?.id || assignableW2Res.data?.id;

    // 8. Provision users for each system role and probe role
    const systemRolesToCreate = [
      'Admin',
      'Project Manager',
      'Team Lead',
      'Team Member',
      'Viewer',
      'Auditor',
      'Guest',
      'Probe'
    ];

    for (const roleName of systemRolesToCreate) {
      const roleId = roleMap[roleName];
      if (!roleId) continue;

      const userEmail = `${roleName.toLowerCase().replace(/\s+/g, '_')}_${this.slug}@permtest.local`;
      const userPassword = 'TestUser123!@#$';

      // Invite user to W1 with membership on Board A ONLY
      const invRes = await this.ownerClient.post('/api/invitations', {
        email: userEmail,
        workspace_id: w1Id,
        board_ids: [boardAId], // Member of Board A ONLY!
        role_id: roleId
      });

      const inviteToken = invRes.data?.invite_token || invRes.data?.invitation?.token || invRes.data?.token;
      if (!inviteToken) {
        throw new Error(`[FIXTURE] Failed to create invite token for ${roleName}: ${JSON.stringify(invRes.data)}`);
      }

      const client = new PermtestClient({
        frontendUrl: this.frontendUrl,
        apiUrl: this.apiUrl
      });

      const regRes = await client.post('/api/auth/register', {
        name: `${roleName} User`,
        email: userEmail,
        password: userPassword,
        invite_token: inviteToken
      });

      if (regRes.status !== 200 && regRes.status !== 201) {
        throw new Error(`[FIXTURE] Register failed for ${roleName}: ${JSON.stringify(regRes.data)}`);
      }

      const loginRes = await client.post('/api/auth/login', {
        email: userEmail,
        password: userPassword,
        tenant_slug: this.slug
      });

      const userObj = regRes.data?.user || loginRes.data?.user;
      client.user = userObj;
      client.roleName = roleName;

      this.users[roleName] = {
        client,
        user: userObj,
        email: userEmail,
        password: userPassword,
        roleId
      };
    }

    // 8b. Provision W2 Member user for member operations in W2
    const w2MemberEmail = `w2member_${this.slug}@permtest.local`;
    const invW2 = await this.ownerClient.post('/api/invitations', {
      email: w2MemberEmail,
      workspace_id: w2Id,
      board_ids: [boardCId],
      role_id: roleMap['Team Member']
    });
    const w2Token = invW2.data?.invite_token || invW2.data?.invitation?.token || invW2.data?.token;
    const w2Client = new PermtestClient({ frontendUrl: this.frontendUrl, apiUrl: this.apiUrl });
    const regW2 = await w2Client.post('/api/auth/register', { name: 'W2 Member User', email: w2MemberEmail, password: 'W2MemberPass123!@#', invite_token: w2Token });
    const w2Login = await w2Client.post('/api/auth/login', { email: w2MemberEmail, password: 'W2MemberPass123!@#', tenant_slug: this.slug });
    const w2UserObj = regW2.data?.user || w2Login.data?.user;

    this.users['W2Member'] = {
      client: w2Client,
      user: w2UserObj,
      email: w2MemberEmail,
      password: 'W2MemberPass123!@#'
    };

    // 8c. Provision Member Target user in W1 for destructive member operations (deactivate, reset password)
    const memTargetEmail = `memtarget_${this.slug}@permtest.local`;
    const invTarget = await this.ownerClient.post('/api/invitations', {
      email: memTargetEmail,
      workspace_id: w1Id,
      board_ids: [boardAId],
      role_id: roleMap['Team Member']
    });
    const tToken = invTarget.data?.invite_token || invTarget.data?.invitation?.token || invTarget.data?.token;
    const tClient = new PermtestClient({ frontendUrl: this.frontendUrl, apiUrl: this.apiUrl });
    const regT = await tClient.post('/api/auth/register', { name: 'Target Member User', email: memTargetEmail, password: 'TargetPass123!@#', invite_token: tToken });
    const tLogin = await tClient.post('/api/auth/login', { email: memTargetEmail, password: 'TargetPass123!@#', tenant_slug: this.slug });
    const tUserObj = regT.data?.user || tLogin.data?.user;

    this.users['MemberTarget'] = {
      client: tClient,
      user: tUserObj,
      email: memTargetEmail,
      password: 'TargetPass123!@#'
    };

    // 9. Provision Creator User and Non-Creator User for ownership tests
    const creatorEmail = `creator_${this.slug}@permtest.local`;
    const nonCreatorEmail = `noncreator_${this.slug}@permtest.local`;
    const userPass = 'OwnershipPass123!@#';

    // Creator user
    const invCreator = await this.ownerClient.post('/api/invitations', {
      email: creatorEmail,
      workspace_id: w1Id,
      board_ids: [boardAId],
      role_id: roleMap['Team Member']
    });
    const cToken = invCreator.data?.invite_token || invCreator.data?.invitation?.token || invCreator.data?.token;
    const creatorClient = new PermtestClient({ frontendUrl: this.frontendUrl, apiUrl: this.apiUrl });
    await creatorClient.post('/api/auth/register', { name: 'Creator User', email: creatorEmail, password: userPass, invite_token: cToken });
    const creatorLogin = await creatorClient.post('/api/auth/login', { email: creatorEmail, password: userPass, tenant_slug: this.slug });

    // Non-creator user
    const invNonCreator = await this.ownerClient.post('/api/invitations', {
      email: nonCreatorEmail,
      workspace_id: w1Id,
      board_ids: [boardAId],
      role_id: roleMap['Team Member']
    });
    const ncToken = invNonCreator.data?.invite_token || invNonCreator.data?.invitation?.token || invNonCreator.data?.token;
    const nonCreatorClient = new PermtestClient({ frontendUrl: this.frontendUrl, apiUrl: this.apiUrl });
    await nonCreatorClient.post('/api/auth/register', { name: 'NonCreator User', email: nonCreatorEmail, password: userPass, invite_token: ncToken });
    const nonCreatorLogin = await nonCreatorClient.post('/api/auth/login', { email: nonCreatorEmail, password: userPass, tenant_slug: this.slug });

    this.users['Creator'] = {
      client: creatorClient,
      user: creatorLogin.data?.user,
      email: creatorEmail,
      password: userPass
    };

    this.users['NonCreator'] = {
      client: nonCreatorClient,
      user: nonCreatorLogin.data?.user,
      email: nonCreatorEmail,
      password: userPass
    };

    // Create a comment authored by Creator
    const creatorCommentRes = await creatorClient.post(`/api/cards/${card1Id}/comments`, {
      body: 'Comment by creator'
    });
    const creatorCommentId = creatorCommentRes.data?.comment?.id || creatorCommentRes.data?.id;

    this.context = {
      tenantSlug: this.slug,
      tenantId: this.tenant.id,
      tenantDbName: this.tenant.db_name,
      w1Id,
      w2Id,
      boardAId,
      boardBId,
      boardCId,
      list1Id,
      listDelId,
      card1Id,
      cardDelId,
      cardArchId,
      checklist1Id,
      checklistItem1Id,
      comment1Id,
      creatorCommentId,
      attachment1Id,
      label1Id,
      listBId,
      cardBId,
      checklistBId,
      checklistItemBId,
      commentBId,
      attachmentBId,
      labelBId,
      listW2Id,
      cardW2Id,
      checklistW2Id,
      checklistItemW2Id,
      commentW2Id,
      attachmentW2Id,
      labelW2Id,
      w2MemberId: w2UserObj?.id,
      memberTargetId: tUserObj?.id,
      assignableRoleW1Id,
      assignableRoleW2Id,
      probeRoleId,
      roleMap,
      ownerClient: this.ownerClient,
      frontendUrl: this.frontendUrl,
      users: this.users,
      tenantDb: this.tenantDb
    };

    console.log(`✓ Fixture setup complete for tenant "${this.slug}" (ID: ${this.tenant.id}).\n`);
    return this;
  }

  async cleanup() {
    console.log(`\n[FIXTURE] Cleaning up disposable test tenant "${this.slug}"...`);
    try {
      if (this.tenant) {
        const masterDb = getMasterDb();
        try {
          await evictTenantPool(this.tenant.id);
        } catch (e) {
          console.warn(`[WARN] evictTenantPool for ${this.tenant.id}:`, e.message);
        }
        try {
          await dropTenantDatabase(this.tenant.db_name);
        } catch (e) {
          console.warn(`[WARN] Could not drop DB ${this.tenant.db_name}:`, e.message);
        }
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [this.tenant.id]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [this.tenant.id]);
      }
      console.log(`✓ Tenant "${this.slug}" cleaned up successfully.`);
    } catch (err) {
      console.warn(`[WARN] Cleanup error for tenant "${this.slug}":`, err.message);
    }
  }
}

/**
 * Sweeps and drops stale disposable test databases older than maxAgeHours (default 1 hour).
 */
async function sweepStaleTestDatabases(maxAgeHours = 1) {
  const masterDb = getMasterDb();
  try {
    const staleTenants = await masterDb.query(
      `SELECT id, slug, db_name, created_at FROM tenants 
       WHERE slug LIKE 'permtest_%' 
         AND created_at < DATE_SUB(NOW(), INTERVAL ? HOUR)`,
      [maxAgeHours]
    );

    if (Array.isArray(staleTenants) && staleTenants.length > 0) {
      console.log(`[SWEEP] Found ${staleTenants.length} stale permtest databases older than ${maxAgeHours} hour(s). Cleaning up...`);
      for (const t of staleTenants) {
        try {
          await evictTenantPool(t.id);
          await dropTenantDatabase(t.db_name);
          await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
          await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
          console.log(`[SWEEP] Cleaned up stale tenant ${t.slug} (${t.db_name})`);
        } catch (sweepErr) {
          console.warn(`[SWEEP WARN] Could not clean stale tenant ${t.slug}:`, sweepErr.message);
        }
      }
    }
  } catch (err) {
    console.warn('[SWEEP] Startup sweep encountered error:', err.message);
  }
}

/**
 * Guarantees leak-proof execution of tests with a disposable fixture via finally-block.
 */
async function withFixture(options, testFn) {
  if (typeof options === 'function') {
    testFn = options;
    options = {};
  }
  await sweepStaleTestDatabases(1);
  const fixture = new PermtestFixture(options);
  await fixture.setup();
  try {
    return await testFn(fixture);
  } finally {
    await fixture.cleanup();
  }
}

module.exports = { PermtestFixture, withFixture, sweepStaleTestDatabases };

