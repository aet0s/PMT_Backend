// server/src/test_company_members_and_invites.js
// Verification suite for:
// 1. GET /api/workspaces/:id/company-members
// 2. PATCH /api/workspaces/:id/company-members/:userId/role
// 3. POST /api/workspaces/:id/company-members/:userId/workspaces
// 4. POST /api/workspaces/:id/company-members/:userId/boards
// 5. DELETE /api/workspaces/:id/company-members/:userId
// 6. Single invitation rule:
//    - Duplicate invite to pending email -> 409 INVITATION_ALREADY_EXISTS
//    - Invite to existing registered user -> 400 USER_ALREADY_MEMBER

require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '1';
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const db = require('./db');
const migrator = require('./db/migrator');

const authRouter = require('./routes/auth');
const workspacesRouter = require('./routes/workspaces');
const boardsRouter = require('./routes/boards');
const listsRouter = require('./routes/lists');
const cardsRouter = require('./routes/cards');
const invitationsRouter = require('./routes/invitations');
const permissionsRouter = require('./routes/permissions');
const rolesRouter = require('./routes/roles');

async function run() {
  console.log('=== Running Company Members & Single Invitation Verification Suite ===\n');

  const testDb = process.env.MYSQL_DATABASE || 'pm_dev_single';
  await migrator.migrateSingleTenant(testDb);

  const app = express();
  app.use(cors({ origin: true, credentials: true }));
  app.use(cookieParser());
  app.use(express.json());

  app.use('/api/auth', authRouter);
  app.use('/api/workspaces', workspacesRouter);
  app.use('/api/boards', boardsRouter);
  app.use('/api/lists', listsRouter);
  app.use('/api/cards', cardsRouter);
  app.use('/api/invitations', invitationsRouter);
  app.use('/api/permissions', permissionsRouter);
  app.use('/api/roles', rolesRouter);

  app.use((err, req, res, next) => {
    const status = err.status || 400;
    res.status(status).json({ error: { message: err.message, code: err.code || 'BAD_REQUEST' } });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`Test server running on ${baseUrl}\n`);

  try {
    // 1. Register Owner
    const ownerEmail = `owner_${Date.now()}@example.com`;
    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Company Owner',
        email: ownerEmail,
        password: 'Password123!'
      })
    });
    const regData = await regRes.json();
    if (!regRes.ok) throw new Error(`Register owner failed: ${JSON.stringify(regData)}`);
    const ownerId = regData.user.id;
    const cookieHeader = regRes.headers.get('set-cookie')?.split(';')[0] || '';
    const ownerHeaders = { 'Content-Type': 'application/json', Cookie: cookieHeader };
    console.log(`1. ✓ Owner registered (${ownerEmail}, id: ${ownerId})`);

    // 2. Fetch default workspace
    const wsRes = await fetch(`${baseUrl}/api/workspaces`, { headers: ownerHeaders }).then((r) => r.json());
    const ws1Id = wsRes.workspaces[0].id;
    console.log(`2. ✓ Found primary workspace (id: ${ws1Id})`);

    // 3. Create a second workspace
    const ws2Res = await fetch(`${baseUrl}/api/workspaces`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ name: 'Engineering Studio' })
    }).then((r) => r.json());
    const ws2Id = ws2Res.workspace?.id || ws2Res.id;
    console.log(`3. ✓ Created second workspace (id: ${ws2Id})`);

    // 4. Create a board in ws1 and a board in ws2
    const board1Res = await fetch(`${baseUrl}/api/boards`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ name: 'Main Project', workspace_id: ws1Id })
    }).then((r) => r.json());
    const board1Id = board1Res.board?.id || board1Res.id;

    const board2Res = await fetch(`${baseUrl}/api/boards`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ name: 'Studio Board', workspace_id: ws2Id })
    }).then((r) => r.json());
    const board2Id = board2Res.board?.id || board2Res.id;
    console.log(`4. ✓ Created boards (board1: ${board1Id}, board2: ${board2Id})`);

    // 5. Register a second user (Developer)
    const devEmail = `dev_${Date.now()}@example.com`;
    const devRegRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Dev One',
        email: devEmail,
        password: 'Password123!'
      })
    });
    const devData = await devRegRes.json();
    const devId = devData.user.id;
    console.log(`5. ✓ Registered second user (${devEmail}, id: ${devId})`);

    // 6. Test GET /api/workspaces/:id/company-members
    const compMembersRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members`, {
      headers: ownerHeaders
    });
    if (!compMembersRes.ok) {
      const errText = await compMembersRes.text();
      throw new Error(`GET company-members failed: ${compMembersRes.status} ${errText}`);
    }
    const compMembersData = await compMembersRes.json();
    if (!Array.isArray(compMembersData.members) || compMembersData.members.length < 2) {
      throw new Error(`Expected at least 2 company members, got ${compMembersData.members?.length}`);
    }
    console.log(`6. ✓ GET /api/workspaces/:id/company-members returned ${compMembersData.members.length} members`);

    // 7. Test POST /api/workspaces/:id/company-members/:userId/workspaces (Assign dev to ws2)
    const assignWsRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${devId}/workspaces`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ workspaceIds: [ws1Id, ws2Id] })
    });
    const assignWsData = await assignWsRes.json();
    if (!assignWsRes.ok || !assignWsData.success) {
      throw new Error(`Assign workspaces failed: ${JSON.stringify(assignWsData)}`);
    }
    console.log(`7. ✓ POST assign workspaces to user ${devId} succeeded`);

    // 8. Test POST /api/workspaces/:id/company-members/:userId/boards (Assign dev to board1 and board2)
    const assignBoardsRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${devId}/boards`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ boardIds: [board1Id, board2Id] })
    });
    const assignBoardsData = await assignBoardsRes.json();
    if (!assignBoardsRes.ok || !assignBoardsData.success) {
      throw new Error(`Assign boards failed: ${JSON.stringify(assignBoardsData)}`);
    }
    console.log(`8. ✓ POST assign boards to user ${devId} succeeded`);

    // 9. Test PATCH /api/workspaces/:id/company-members/:userId/role (Change dev role to Admin)
    const adminRole = compMembersData.roles.find(r => r.name === 'Admin');
    const updateRoleRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${devId}/role`, {
      method: 'PATCH',
      headers: ownerHeaders,
      body: JSON.stringify({ roleId: adminRole.id })
    });
    const updateRoleData = await updateRoleRes.json();
    if (!updateRoleRes.ok || !updateRoleData.success) {
      throw new Error(`Update role failed: ${JSON.stringify(updateRoleData)}`);
    }
    console.log(`9. ✓ PATCH update role to Admin succeeded`);

    // 10. Test Single Invitation Rule:
    // a) Invite existing registered user (devEmail) -> MUST return 400 with code USER_ALREADY_MEMBER
    const inviteExistingRes = await fetch(`${baseUrl}/api/invitations`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        email: devEmail,
        role_id: adminRole.id,
        workspace_id: ws1Id
      })
    });
    const inviteExistingData = await inviteExistingRes.json();
    if (inviteExistingRes.status !== 400 || inviteExistingData.error?.code !== 'USER_ALREADY_MEMBER') {
      throw new Error(`Expected 400 USER_ALREADY_MEMBER, got ${inviteExistingRes.status}: ${JSON.stringify(inviteExistingData)}`);
    }
    console.log(`10a. ✓ Inviting existing user rejected with 400 USER_ALREADY_MEMBER`);

    // b) Invite a new email -> MUST succeed
    const newInviteEmail = `invitee_${Date.now()}@example.com`;
    const newInviteRes = await fetch(`${baseUrl}/api/invitations`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        email: newInviteEmail,
        role_id: adminRole.id,
        workspace_id: ws1Id
      })
    });
    const newInviteData = await newInviteRes.json();
    if (!newInviteRes.ok) {
      throw new Error(`Sending new invite failed: ${JSON.stringify(newInviteData)}`);
    }
    console.log(`10b. ✓ New invitation generated successfully for ${newInviteEmail}`);

    // c) Duplicate invite to same pending email -> MUST return 409 INVITATION_ALREADY_EXISTS
    const dupInviteRes = await fetch(`${baseUrl}/api/invitations`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        email: newInviteEmail,
        role_id: adminRole.id,
        workspace_id: ws1Id
      })
    });
    const dupInviteData = await dupInviteRes.json();
    if (dupInviteRes.status !== 409 || dupInviteData.error?.code !== 'INVITATION_ALREADY_EXISTS') {
      throw new Error(`Expected 409 INVITATION_ALREADY_EXISTS, got ${dupInviteRes.status}: ${JSON.stringify(dupInviteData)}`);
    }
    console.log(`10c. ✓ Duplicate invitation rejected with 409 INVITATION_ALREADY_EXISTS`);

    // 11. Test DELETE /api/workspaces/:id/company-members/:userId (Remove Dev from company)
    const removeRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${devId}`, {
      method: 'DELETE',
      headers: ownerHeaders
    });
    const removeData = await removeRes.json();
    if (!removeRes.ok || !removeData.success) {
      throw new Error(`Remove user failed: ${JSON.stringify(removeData)}`);
    }
    console.log(`11. ✓ DELETE remove user from company succeeded`);

    // 12. Test Self-Removal Protection: Trying to remove oneself must return 400 CANNOT_REMOVE_SELF
    const removeSelfRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${ownerId}`, {
      method: 'DELETE',
      headers: ownerHeaders
    });
    const removeSelfData = await removeSelfRes.json();
    if (removeSelfRes.status !== 400 || removeSelfData.error?.code !== 'CANNOT_REMOVE_SELF') {
      throw new Error(`Expected 400 CANNOT_REMOVE_SELF, got ${removeSelfRes.status}: ${JSON.stringify(removeSelfData)}`);
    }
    console.log(`12a. ✓ Self-removal prevented (400 CANNOT_REMOVE_SELF)`);

    // Register a second admin user who tries to remove the sole owner
    const admin2Email = `admin2_${Date.now()}@example.com`;
    const admin2RegRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Admin Two', email: admin2Email, password: 'Password123!' })
    });
    const admin2Data = await admin2RegRes.json();
    const admin2Id = admin2Data.user.id;
    const admin2Cookie = admin2RegRes.headers.get('set-cookie')?.split(';')[0] || '';
    const admin2Headers = { 'Content-Type': 'application/json', Cookie: admin2Cookie };

    // Grant Admin Two workspace membership as Admin
    await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${admin2Id}/workspaces`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ workspace_ids: [ws1Id], role_id: adminRole.id })
    });

    // Admin Two attempts to remove the Owner
    const removeSoleOwnerRes = await fetch(`${baseUrl}/api/workspaces/${ws1Id}/company-members/${ownerId}`, {
      method: 'DELETE',
      headers: admin2Headers
    });
    const removeSoleOwnerData = await removeSoleOwnerRes.json();
    const isOwnerProtected =
      (removeSoleOwnerRes.status === 400 && removeSoleOwnerData.error?.code === 'CANNOT_REMOVE_OWNER') ||
      (removeSoleOwnerRes.status === 403 && removeSoleOwnerData.error?.code === 'ONLY_OWNER_MAY_MODIFY_OWNER');
    if (!isOwnerProtected) {
      throw new Error(`Expected owner deletion to be blocked (CANNOT_REMOVE_OWNER or ONLY_OWNER_MAY_MODIFY_OWNER), got ${removeSoleOwnerRes.status}: ${JSON.stringify(removeSoleOwnerData)}`);
    }
    console.log(`12b. ✓ Organization owner deletion protection enforced (${removeSoleOwnerData.error?.code})`);

    console.log('\n======================================================');
    console.log('✅ ALL COMPANY MEMBERS & INVITATION TESTS PASSED!');
    console.log('======================================================\n');
  } finally {
    server.close();
  }
}

run().catch((err) => {
  console.error('❌ Test failed with error:', err);
  process.exit(1);
});
