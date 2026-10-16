// server/src/scripts/permtest/ownerDetectionTest.js
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });
const assert = require('assert');
const { withFixture } = require('./fixtures');
const { isOwnerRole } = require('../../utils/roleRank');
const { countOwners } = require('../../middleware/permissions');

async function runTest() {
  console.log('================================================================');
  console.log('        TEST: OWNER DETECTION & SPOOFED ROLE DEFENSE            ');
  console.log('================================================================\n');

  await withFixture(async (fixture) => {
    const { tenantDb, w1Id, ownerClient, users } = fixture.context;
    const memberClient = users['Team Member'].client;
    const memberUser = users['Team Member'].user;

    // 1. Direct unit assertion on isOwnerRole
    const spoofCases = [
      { name: 'Owner', is_system: 0, is_editable: 1, rank: 30 },
      { name: 'Owner', is_system: 0, is_editable: 1, rank: 100 },
      { name: 'Super Admin', is_system: 0, is_editable: 1, rank: 99 },
      { name: '\u041Ewner', is_system: 0, is_editable: 1, rank: 100 }, // Cyrillic О
      { name: 'Owner\u200B', is_system: 0, is_editable: 1, rank: 50 }, // zero-width space
      { name: 'Owner', is_system: null, is_editable: 1, rank: 100 }
    ];

    for (const c of spoofCases) {
      assert.strictEqual(
        isOwnerRole(c),
        false,
        `Expected isOwnerRole to return false for non-system role: ${JSON.stringify(c)}`
      );
    }
    console.log('✓ PASS: isOwnerRole strictly returns false for all non-system roles regardless of name or rank.');

    // Real system owner check
    const realOwnerObj = { name: 'Owner', is_system: 1, is_editable: 0, rank: 100 };
    assert.strictEqual(isOwnerRole(realOwnerObj), true);
    console.log('✓ PASS: isOwnerRole returns true for real system owner.');

    // 2. Insert spoofed roles directly into the database
    const res1 = await tenantDb.query(
      `INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) 
       VALUES ('Owner', 0, 1, 30, ?)`,
      [w1Id]
    );
    const spoofOwnerRoleId = res1.insertId;

    const res2 = await tenantDb.query(
      `INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) 
       VALUES ('\u041Ewner', 0, 1, 30, ?)`,
      [w1Id]
    );
    const unicodeSpoofRoleId = res2.insertId;

    // 3. Verify countOwners in workspace W1
    const initialOwnersCount = await countOwners(w1Id, tenantDb);
    assert.strictEqual(initialOwnersCount, 1, 'Initial real owners count should be 1');

    // Assign Member to the spoofed "Owner" role
    await tenantDb.query(
      `UPDATE workspace_members SET role_id = ? WHERE workspace_id = ? AND user_id = ?`,
      [spoofOwnerRoleId, w1Id, memberUser.id]
    );

    const countAfterSpoof = await countOwners(w1Id, tenantDb);
    assert.strictEqual(
      countAfterSpoof,
      1,
      `Spoofed custom role named "Owner" must NOT increment countOwners (expected 1, got ${countAfterSpoof})`
    );
    console.log('✓ PASS: countOwners ignores custom non-system roles named "Owner".');

    // 4. Verify GET /api/workspaces/:id/roles does NOT grant full permissions to spoofed role
    const rolesRes = await ownerClient.get(`/api/workspaces/${w1Id}/roles`);
    assert.strictEqual(rolesRes.status, 200);
    const rolesList = rolesRes.data?.roles || [];
    const spoofRoleEntry = rolesList.find(r => r.id === spoofOwnerRoleId);
    assert(spoofRoleEntry, 'Spoof role should be present in roles list');
    assert.notStrictEqual(
      spoofRoleEntry.permission_keys.length,
      rolesList.find(r => r.name === 'Owner' && r.is_system).permission_keys.length,
      'Spoofed role must NOT receive full permissions list in GET /:id/roles'
    );
    assert.strictEqual(spoofRoleEntry.permission_keys.length, 0, 'Spoofed role with no assigned permissions should have 0 keys');
    console.log('✓ PASS: Spoofed "Owner" role does not receive all permissions in GET /:id/roles.');

    // 5. Attempt last-Owner bypass: try to demote the real Owner while spoofed "Owner" is present
    const demoteRes = await ownerClient.patch(`/api/workspaces/${w1Id}/members/${ownerClient.user.id}/role`, {
      role_id: spoofOwnerRoleId
    });
    assert.strictEqual(
      demoteRes.status,
      400,
      `Demoting real Owner should be blocked by last-Owner guard even if spoofed role exists (status: ${demoteRes.status})`
    );
    assert.strictEqual(demoteRes.data?.error?.code, 'LAST_OWNER_PROTECTION');
    console.log('✓ PASS: Last-Owner demotion protection cannot be bypassed by spoofed Owner role.');

    // 6. Member with spoofed role attempts to remove the real Owner
    const spoofMemberRemoveOwner = await memberClient.delete(`/api/workspaces/${w1Id}/members/${ownerClient.user.id}`);
    assert.strictEqual(
      spoofMemberRemoveOwner.status,
      403,
      `Spoofed Owner member cannot remove real Owner (status: ${spoofMemberRemoveOwner.status})`
    );
    console.log('✓ PASS: Spoofed Owner user is strictly rejected on owner removal with 403.');
  });

  console.log('\n✅ ALL OWNER DETECTION AND SPOOF TESTS PASSED!\n');
}

if (require.main === module) {
  runTest().catch((err) => {
    console.error('Owner detection test failed:', err);
    process.exit(1);
  });
}

module.exports = { runTest };
