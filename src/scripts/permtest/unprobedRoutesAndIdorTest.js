// server/src/scripts/permtest/unprobedRoutesAndIdorTest.js
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { withFixture } = require('./fixtures');
const { PermtestClient } = require('./client');

async function runTest() {
  console.log('================================================================');
  console.log('        TEST: UNPROBED ROUTES & SELF-SCOPED IDOR CONTROLS       ');
  console.log('================================================================\n');

  let totalChecks = 0;
  let checksPassed = 0;

  await withFixture(async (fixture) => {
    const {
      tenantId,
      w1Id,
      boardAId,
      boardBId,
      card1Id,
      cardBId,
      ownerClient,
      users,
      tenantDb
    } = fixture.context;

    const memberClient = users['Team Member'].client;
    const guestClient = users['Guest'].client;
    const guestUser = users['Guest'].user;
    const adminClient = users['Admin'].client;

    // -------------------------------------------------------------
    // PART A: GET /api/files/:tenantId/*
    // -------------------------------------------------------------
    console.log('--- [1] Testing GET /api/files/:tenantId/* ---');

    // Create real test files on disk and attach in database
    const UPLOADS_DIR = process.env.UPLOADS_DIR
      ? path.resolve(process.env.UPLOADS_DIR)
      : path.resolve(__dirname, '../../../uploads');

    const boardADir = path.join(UPLOADS_DIR, String(tenantId), 'cards', String(card1Id));
    fs.mkdirSync(boardADir, { recursive: true });
    const filenameA = 'test-board-a.txt';
    fs.writeFileSync(path.join(boardADir, filenameA), 'Secret Board A Content');
    const fileUrlA = `/api/files/${tenantId}/cards/${card1Id}/${filenameA}`;

    await tenantDb.query(
      `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
       VALUES (?, ?, ?, ?, 'text/plain', 22)`,
      [card1Id, ownerClient.user.id, filenameA, fileUrlA]
    );

    const boardBDir = path.join(UPLOADS_DIR, String(tenantId), 'cards', String(cardBId));
    fs.mkdirSync(boardBDir, { recursive: true });
    const filenameB = 'test-board-b.txt';
    fs.writeFileSync(path.join(boardBDir, filenameB), 'Secret Board B Content');
    const fileUrlB = `/api/files/${tenantId}/cards/${cardBId}/${filenameB}`;

    await tenantDb.query(
      `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
       VALUES (?, ?, ?, ?, 'text/plain', 22)`,
      [cardBId, ownerClient.user.id, filenameB, fileUrlB]
    );

    // 1. Unauthenticated -> 401
    totalChecks++;
    const anonClient = new PermtestClient({ frontendUrl: fixture.frontendUrl });
    const anonRes = await anonClient.get(fileUrlA);
    assert.strictEqual(anonRes.status, 401, `Unauthenticated request should return 401, got ${anonRes.status}`);
    checksPassed++;
    console.log('[1] PASS: Unauthenticated file download rejected with 401.');

    // 2. Foreign tenant ID in path -> denied (403)
    totalChecks++;
    const fakeTenantUrl = fileUrlA.replace(`/api/files/${tenantId}/`, `/api/files/999999/`);
    const foreignTenantRes = await memberClient.get(fakeTenantUrl);
    assert.strictEqual(foreignTenantRes.status, 403, `Foreign tenant request should return 403, got ${foreignTenantRes.status}`);
    checksPassed++;
    console.log('[2] PASS: Foreign tenantId in path rejected with 403.');

    // 3. User NOT on Board B requesting attachment of Board B -> denied (403)
    totalChecks++;
    // Team Member is on Board A only in fixture setup, NOT on Board B.
    const memberOnBoardBRes = await memberClient.get(fileUrlB);
    assert.strictEqual(memberOnBoardBRes.status, 403, `Member not on board B should return 403, got ${memberOnBoardBRes.status}`);
    checksPassed++;
    console.log('[3] PASS: Member not on Board B requesting Board B attachment rejected with 403.');

    // 4. User without file.view -> denied (403)
    totalChecks++;
    // Create a role that has project.view but strictly lacks file.view
    const noFileRoleInsert = await tenantDb.query(
      `INSERT INTO roles (name, is_system, is_editable, rank, workspace_id)
       VALUES ('NoFileRole', 0, 1, 15, ?)`,
      [w1Id]
    );
    const noFileRoleId = noFileRoleInsert.insertId;
    const projViewPermRes = await tenantDb.query("SELECT id FROM permissions WHERE `key` = 'project.view'");
    if (projViewPermRes.length > 0) {
      await tenantDb.query("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", [noFileRoleId, projViewPermRes[0].id]);
    }
    // Update guestUser in both workspace_members and board_members to noFileRoleId
    await tenantDb.query(
      `UPDATE workspace_members SET role_id = ? WHERE workspace_id = ? AND user_id = ?`,
      [noFileRoleId, w1Id, guestUser.id]
    );
    await tenantDb.query(
      `INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE role_id = VALUES(role_id)`,
      [boardAId, guestUser.id, noFileRoleId]
    );
    const guestFileRes = await guestClient.get(fileUrlA);
    assert.strictEqual(guestFileRes.status, 403, `User without file.view should return 403, got ${guestFileRes.status}`);
    checksPassed++;
    console.log('[4] PASS: User without file.view rejected with 403.');

    // Restore Guest's role in workspace_members
    await tenantDb.query(
      `UPDATE workspace_members SET role_id = ? WHERE workspace_id = ? AND user_id = ?`,
      [fixture.context.roleMap['Guest'], w1Id, guestUser.id]
    );

    // 5. Authorised control -> 200
    totalChecks++;
    // Owner has file.view and workspace-wide access
    const ownerFileRes = await ownerClient.get(fileUrlA);
    assert.strictEqual(ownerFileRes.status, 200, `Authorised Owner should receive 200, got ${ownerFileRes.status}`);
    checksPassed++;
    console.log('[5] PASS: Authorised Owner successfully accesses file (200).');

    // -------------------------------------------------------------
    // PART B: Self-Scoped IDOR Tests with Controls
    // -------------------------------------------------------------
    console.log('\n--- [2] Testing Self-Scoped IDOR Controls ---');

    // (b.1) Session revocation: Actor A cannot revoke Actor B's session
    totalChecks++;
    const guestSessions = await guestClient.get('/api/auth/sessions');
    assert.strictEqual(guestSessions.status, 200);
    const guestSessionId = guestSessions.data?.sessions?.[0]?.id || guestSessions.data?.[0]?.id;
    assert(guestSessionId, 'Guest should have an active session');

    // Team Member (Actor A) lacks session.revoke_others -> should be denied 403
    const memberRevokeGuest = await memberClient.delete(`/api/auth/sessions/${guestSessionId}`);
    assert.strictEqual(
      memberRevokeGuest.status,
      403,
      `Actor A revoking Actor B session without session.revoke_others must return 403, got ${memberRevokeGuest.status}`
    );
    checksPassed++;
    console.log('[6] PASS: Actor A cannot revoke Actor B session (403 FORBIDDEN without session.revoke_others).');

    // (b.1.rank) session.revoke_others must respect rank: cannot revoke equal or higher rank
    totalChecks++;
    const ownerSessions = await ownerClient.get('/api/auth/sessions');
    const ownerSessionId = ownerSessions.data?.sessions?.[0]?.id || ownerSessions.data?.[0]?.id;
    // Admin (rank 80) attempts to revoke Owner (rank 100) session -> must be rejected 403 INSUFFICIENT_ROLE_RANK
    const adminRevokeOwner = await adminClient.delete(`/api/auth/sessions/${ownerSessionId}`);
    assert.strictEqual(
      adminRevokeOwner.status,
      403,
      `Admin revoking Owner session must return 403, got ${adminRevokeOwner.status}`
    );
    assert.strictEqual(
      adminRevokeOwner.data?.error?.code,
      'INSUFFICIENT_ROLE_RANK',
      `Expected error code INSUFFICIENT_ROLE_RANK, got ${adminRevokeOwner.data?.error?.code}`
    );
    checksPassed++;
    console.log('[7] PASS: session.revoke_others respects rank (Admin cannot revoke Owner session -> 403 INSUFFICIENT_ROLE_RANK).');

    // CONTROL: Owner possesses session.revoke_others -> should succeed 200
    totalChecks++;
    const ownerRevokeGuest = await ownerClient.delete(`/api/auth/sessions/${guestSessionId}`);
    assert.strictEqual(
      ownerRevokeGuest.status,
      200,
      `Owner with session.revoke_others revoking Actor B session should succeed 200, got ${ownerRevokeGuest.status}`
    );
    checksPassed++;
    console.log('[8] PASS: CONTROL: User with session.revoke_others successfully revokes session (200).');

    // (b.2) Notifications IDOR: Actor A cannot read/unread/delete Actor B's notifications
    const notifInsert = await tenantDb.query(
      `INSERT INTO notifications (user_id, workspace_id, board_id, type, event_type, message, is_read, created_at)
       VALUES (?, ?, ?, 'info', 'card.created', 'Hello guest notification', 0, NOW())`,
      [guestUser.id, w1Id, boardAId]
    );
    const guestNotifId = notifInsert.insertId;

    // Team Member (Actor A) tries to mark Guest's notification as read
    totalChecks++;
    const actorAReadRes = await memberClient.patch(`/api/notifications/${guestNotifId}/read`);
    assert.strictEqual(
      actorAReadRes.status,
      404,
      `Actor A marking Actor B notification read must return 404, got ${actorAReadRes.status}`
    );
    checksPassed++;
    console.log('[8] PASS: Actor A cannot mark Actor B notification as read (404 NOT_FOUND).');

    // Team Member (Actor A) tries to mark Guest's notification as unread
    totalChecks++;
    const actorAUnreadRes = await memberClient.patch(`/api/notifications/${guestNotifId}/unread`);
    assert.strictEqual(
      actorAUnreadRes.status,
      404,
      `Actor A marking Actor B notification unread must return 404, got ${actorAUnreadRes.status}`
    );
    checksPassed++;
    console.log('[9] PASS: Actor A cannot mark Actor B notification as unread (404 NOT_FOUND).');

    // Team Member (Actor A) tries to delete Guest's notification
    totalChecks++;
    const actorADeleteRes = await memberClient.delete(`/api/notifications/${guestNotifId}`);
    assert.strictEqual(
      actorADeleteRes.status,
      404,
      `Actor A deleting Actor B notification must return 404, got ${actorADeleteRes.status}`
    );
    checksPassed++;
    console.log('[10] PASS: Actor A cannot delete Actor B notification (404 NOT_FOUND).');

    // CONTROL: Guest (Actor B) logs back in and marks own notification read
    totalChecks++;
    await guestClient.post('/api/auth/login', {
      email: users['Guest'].email,
      password: users['Guest'].password,
      tenant_slug: fixture.slug
    });
    const guestReadOwn = await guestClient.patch(`/api/notifications/${guestNotifId}/read`);
    assert.strictEqual(guestReadOwn.status, 200);
    checksPassed++;
    console.log('[11] PASS: CONTROL: Actor B successfully marks own notification as read (200).');

    // (b.3) Mark read-all for a board they cannot view
    // Team Member is NOT on Board B
    totalChecks++;
    const memberReadAllBoardB = await memberClient.patch(`/api/notifications/board/${boardBId}/read-all`);
    assert.strictEqual(
      memberReadAllBoardB.status,
      403,
      `Actor A marking read-all for inaccessible Board B must return 403, got ${memberReadAllBoardB.status}`
    );
    checksPassed++;
    console.log('[12] PASS: Actor A cannot mark read-all for Board B they cannot view (403 FORBIDDEN).');

    // CONTROL: Owner can mark read-all for Board B
    totalChecks++;
    const ownerReadAllBoardB = await ownerClient.patch(`/api/notifications/board/${boardBId}/read-all`);
    assert.strictEqual(
      ownerReadAllBoardB.status,
      200,
      `Owner marking read-all for Board B should return 200, got ${ownerReadAllBoardB.status}`
    );
    checksPassed++;
    console.log('[13] PASS: CONTROL: Authorised user successfully marks read-all for Board B (200).');

    // Cleanup files on disk
    try {
      fs.rmSync(path.join(UPLOADS_DIR, String(tenantId)), { recursive: true, force: true });
    } catch (_) {}
  });

  console.log(`\nUnprobed Routes & IDOR Suite: ${checksPassed}/${totalChecks} Checks Passed.`);
  return { checksPassed, totalChecks };

  console.log('\n✅ ALL UNPROBED ROUTES & IDOR TESTS PASSED!\n');
}

if (require.main === module) {
  runTest().catch((err) => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = { runTest };
