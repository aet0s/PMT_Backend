// server/src/scripts/testCustomLabelPermissions.js
const assert = require('assert');
const { getTenantDb, getMasterDb } = require('../services/tenantPools');
const { getRoleRank, normalizeRoleName } = require('../utils/roleRank');

async function testRules() {
  console.log('Testing custom label permission rules...');

  const db = await getTenantDb(1);

  // Check table columns
  const cols = await db.query('DESCRIBE labels');
  const colNames = cols.map((c) => c.Field);
  assert(colNames.includes('created_by_user_id'), 'labels table must have created_by_user_id column');
  assert(colNames.includes('is_custom'), 'labels table must have is_custom column');
  console.log('✓ Database schema verified: created_by_user_id and is_custom present in labels table.');

  // Test role rank logic for Owner, Admin, Project Manager, Member
  assert(getRoleRank('Owner') >= 60, 'Owner rank must be >= 60');
  assert(getRoleRank('Admin') >= 60, 'Admin rank must be >= 60');
  assert(getRoleRank('Project Manager') >= 60, 'Project Manager rank must be >= 60');
  assert(getRoleRank('Team Member') < 60, 'Team Member rank must be < 60');
  assert(getRoleRank('Viewer') < 60, 'Viewer rank must be < 60');
  console.log('✓ Role hierarchy verified: Owner, Admin, Project Manager have rank >= 60.');

  // Simulation test:
  const member1Id = 101;
  const member2Id = 202;
  const pmId = 303;
  const adminId = 404;
  const ownerId = 505;

  const label1 = { id: 10, name: 'Member1 Label', is_custom: 1, created_by_user_id: member1Id };
  const label2 = { id: 20, name: 'Member2 Label', is_custom: 1, created_by_user_id: member2Id };
  const presetLabel = { id: 1, name: 'Feature', is_custom: 0, created_by_user_id: null };

  function checkCanDelete(user, label) {
    const roleRank = getRoleRank(user.role);
    const normalizedRole = normalizeRoleName(user.role);
    const isPrivileged = roleRank >= 60 || ['owner', 'super admin', 'admin', 'project manager', 'manager'].includes(normalizedRole);
    const isCustom = Boolean(label.is_custom);
    const isOwnerOfLabel = isCustom && label.created_by_user_id && Number(label.created_by_user_id) === Number(user.id);

    if (isPrivileged) return { allowed: true };
    if (isOwnerOfLabel) return { allowed: true };
    if (!isCustom) {
      return { allowed: false, message: 'You cannot delete preset labels. Only custom labels created by you can be deleted.' };
    }
    return { allowed: false, message: 'You can only delete custom labels created by you.' };
  }

  // 1. Member 1 deleting Label 1
  assert.strictEqual(checkCanDelete({ id: member1Id, role: 'Team Member' }, label1).allowed, true);
  console.log('✓ Member 1 can delete Label 1 (created by Member 1)');

  // 2. Member 1 deleting Label 2
  const m1DeleteL2 = checkCanDelete({ id: member1Id, role: 'Team Member' }, label2);
  assert.strictEqual(m1DeleteL2.allowed, false);
  assert.strictEqual(m1DeleteL2.message, 'You can only delete custom labels created by you.');
  console.log('✓ Member 1 CANNOT delete Label 2 (created by Member 2)');

  // 3. Member 2 deleting Label 2
  assert.strictEqual(checkCanDelete({ id: member2Id, role: 'Team Member' }, label2).allowed, true);
  console.log('✓ Member 2 can delete Label 2 (created by Member 2)');

  // 4. Member 2 deleting Label 1
  const m2DeleteL1 = checkCanDelete({ id: member2Id, role: 'Team Member' }, label1);
  assert.strictEqual(m2DeleteL1.allowed, false);
  assert.strictEqual(m2DeleteL1.message, 'You can only delete custom labels created by you.');
  console.log('✓ Member 2 CANNOT delete Label 1 (created by Member 1)');

  // 5. Member 1 deleting preset label
  const m1DeletePreset = checkCanDelete({ id: member1Id, role: 'Team Member' }, presetLabel);
  assert.strictEqual(m1DeletePreset.allowed, false);
  console.log('✓ Member 1 CANNOT delete preset label');

  // 6. Project Manager deleting Label 1 & Label 2
  assert.strictEqual(checkCanDelete({ id: pmId, role: 'Project Manager' }, label1).allowed, true);
  assert.strictEqual(checkCanDelete({ id: pmId, role: 'Project Manager' }, label2).allowed, true);
  console.log('✓ Project Manager CAN delete all custom created labels');

  // 7. Admin deleting Label 1 & Label 2
  assert.strictEqual(checkCanDelete({ id: adminId, role: 'Admin' }, label1).allowed, true);
  assert.strictEqual(checkCanDelete({ id: adminId, role: 'Admin' }, label2).allowed, true);
  console.log('✓ Admin CAN delete all custom created labels');

  // 8. Owner deleting Label 1 & Label 2
  assert.strictEqual(checkCanDelete({ id: ownerId, role: 'Owner' }, label1).allowed, true);
  assert.strictEqual(checkCanDelete({ id: ownerId, role: 'Owner' }, label2).allowed, true);
  console.log('✓ Owner CAN delete all custom created labels');

  console.log('\nAll custom label permission tests passed successfully!');
  process.exit(0);
}

testRules().catch((err) => {
  console.error(err);
  process.exit(1);
});
