// server/src/scripts/permtest/testSelfAssign.js
// Tests that card assignment accepts (task.assign_self OR task.assign) for self,
// and strictly task.assign for assigning other users.

const assert = require('assert');
const { PermtestFixture } = require('./fixtures');

async function testSelfAssign() {
  console.log('================================================================');
  console.log('         TEST: SELF-ASSIGN (task.assign_self OR task.assign)    ');
  console.log('================================================================\n');

  const fixture = new PermtestFixture();
  await fixture.setup();

  try {
    const ctx = fixture.context;
    const ownerClient = fixture.ownerClient;
    const tenantDb = fixture.tenantDb;

    // 1. Create a custom role with ONLY task.assign (NO task.assign_self)
    console.log('[1] Creating custom role with ONLY task.assign (NO task.assign_self)...');
    const roleRes = await ownerClient.post(`/api/workspaces/${ctx.w1Id}/roles`, {
      name: 'Assign Only Role',
      permission_keys: ['project.view', 'task.view', 'task.assign']
    });
    const assignOnlyRoleId = roleRes.data?.role?.id || roleRes.data?.id;

    // 2. Assign Probe user to this role on workspace and Board A
    const probeUser = fixture.users['Probe'].user;
    const probeClient = fixture.users['Probe'].client;

    await ownerClient.patch(`/api/workspaces/${ctx.w1Id}/members/${probeUser.id}/role`, {
      role_id: assignOnlyRoleId
    });
    await ownerClient.post(`/api/boards/${ctx.boardAId}/members`, {
      user_id: probeUser.id,
      role: 'member'
    });

    // Verify probe user permissions in DB / API on Board A
    const myPerms = await probeClient.get(`/api/workspaces/${ctx.w1Id}/my-permissions?board_id=${ctx.boardAId}`);
    const perms = myPerms.data?.permissions || [];
    assert(perms.includes('task.assign'), 'Must have task.assign');
    assert(!perms.includes('task.assign_self'), 'Must NOT have task.assign_self');
    console.log(`    Role permissions: [${perms.join(', ')}]`);

    // 3. Probe user attempts SELF-ASSIGNMENT
    console.log('[2] Testing self-assignment with task.assign only...');
    const selfAssignRes = await probeClient.post(`/api/cards/${ctx.card1Id}/members`, {
      user_id: probeUser.id
    });
    assert.strictEqual(selfAssignRes.status, 200, `Self-assign with task.assign only must succeed (got ${selfAssignRes.status})`);
    console.log(`    PASS: Self-assignment SUCCEEDED with task.assign alone (status: ${selfAssignRes.status})`);

    // 4. Probe user attempts ASSIGNING OTHERS (Team Member)
    console.log('[3] Testing assigning another member with task.assign...');
    const otherUser = fixture.users['Team Member'].user;
    const assignOtherRes = await probeClient.post(`/api/cards/${ctx.card1Id}/members`, {
      user_id: otherUser.id
    });
    assert.strictEqual(assignOtherRes.status, 200, `Assigning other member with task.assign must succeed (got ${assignOtherRes.status})`);
    console.log(`    PASS: Assigning other member SUCCEEDED with task.assign (status: ${assignOtherRes.status})`);

    // 5. Compare with Team Member role (has task.assign_self, LACKS task.assign)
    console.log('[4] Comparing with Team Member (has task.assign_self, LACKS task.assign)...');
    const memberClient = fixture.users['Team Member'].client;
    const memberUser = fixture.users['Team Member'].user;

    // Member self-assign -> SUCCEEDS
    const memberSelfRes = await memberClient.post(`/api/cards/${ctx.card1Id}/members`, {
      user_id: memberUser.id
    });
    assert.strictEqual(memberSelfRes.status, 200, 'Member self-assign with task.assign_self must succeed');
    console.log(`    PASS: Member self-assign SUCCEEDED with task.assign_self (status: 200)`);

    // Member assigning Probe user -> FORBIDDEN (403)
    const memberOtherRes = await memberClient.post(`/api/cards/${ctx.card1Id}/members`, {
      user_id: probeUser.id
    });
    assert.strictEqual(memberOtherRes.status, 403, 'Member assigning another user must fail with 403');
    console.log(`    PASS: Member assigning another user STRICTLY FORBIDDEN (status: 403)`);

    console.log('\n✅ ALL SELF-ASSIGN TESTS PASSED: self-assign accepts (task.assign_self OR task.assign).');
  } finally {
    await fixture.cleanup();
  }
}

if (require.main === module) {
  testSelfAssign().catch(err => {
    console.error('FAILED:', err);
    process.exit(1);
  });
}

module.exports = { testSelfAssign };
