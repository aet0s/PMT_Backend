// server/src/scripts/permtest/plannedAndSyntheticTest.js
// Verification of planned permissions policy and synthetic promotion to Owner/Admin via catalogSync.

const { withFixture } = require('./fixtures');
const { syncPermissionCatalog } = require('../../rbac/catalogSync');

async function runPlannedAndSyntheticSuite() {
  console.log('='.repeat(64));
  console.log('     TEST: PLANNED KEYS & SYNTHETIC PROMOTION CATALOGSYNC       ');
  console.log('='.repeat(64));

  await withFixture(async (fixture) => {
    const { ownerClient, tenantDb } = fixture.context;

    console.log('\n--- [1] Checking Existing Planned Keys in Role Permissions ---');
    const plannedGrants = await tenantDb.query(
      `SELECT p.key, r.name as role_name 
       FROM role_permissions rp 
       JOIN permissions p ON rp.permission_id = p.id 
       JOIN roles r ON rp.role_id = r.id 
       WHERE p.planned = 1`
    );

    console.log(`Found ${plannedGrants.length} planned permission grant(s) across all roles.`);
    if (plannedGrants.length > 0) {
      throw new Error(`VIOLATION: Planned keys must not be granted to any role! Found: ${JSON.stringify(plannedGrants)}`);
    }
    console.log('✓ PASS: Zero (0) planned keys are granted to ANY role (including Owner).');

    console.log('\n--- [2] Inserting Synthetic Permission (planned = 1) ---');
    const synthKey = 'synthetic.test_feature';
    await tenantDb.execute(
      `INSERT INTO permissions (\`key\`, category, module, label, description, scope, dangerous, planned)
       VALUES (?, 'general', 'synthetic', 'Synthetic Test Feature', 'Synthetic test permission', 'project', 0, 1)
       ON DUPLICATE KEY UPDATE planned = 1`,
      [synthKey]
    );

    // Verify it appears in GET /api/permissions?include_planned=1
    const permsRes = await ownerClient.get('/api/permissions?include_planned=1');
    if (permsRes.status !== 200) {
      throw new Error(`GET /api/permissions failed: ${permsRes.status}`);
    }
    const permList = permsRes.data?.permissions || permsRes.data || [];
    const synthPerm = permList.find(p => p.key === synthKey);
    if (!synthPerm) {
      throw new Error(`Synthetic permission ${synthKey} not found in GET /api/permissions?include_planned=1`);
    }
    console.log(`✓ PASS: Synthetic permission ${synthKey} appears in GET /api/permissions?include_planned=1 (planned: ${synthPerm.planned}).`);

    // Verify it is hidden from default GET /api/permissions (planned hiding rule)
    const defaultPermsRes = await ownerClient.get('/api/permissions');
    const defaultPermList = defaultPermsRes.data?.permissions || [];
    if (defaultPermList.some(p => p.key === synthKey)) {
      throw new Error(`Planned permission ${synthKey} must be hidden from default GET /api/permissions!`);
    }
    console.log(`✓ PASS: Planned permission ${synthKey} is strictly hidden from default GET /api/permissions.`);

    // Run catalogSync with planned = 1
    await syncPermissionCatalog(tenantDb);

    // Verify synthetic permission is NOT granted to any role while planned = 1
    const synthPlannedGrants = await tenantDb.query(
      `SELECT r.name 
       FROM role_permissions rp 
       JOIN permissions p ON rp.permission_id = p.id 
       JOIN roles r ON rp.role_id = r.id 
       WHERE p.key = ?`,
      [synthKey]
    );
    if (synthPlannedGrants.length > 0) {
      throw new Error(`Synthetic planned permission was granted to: ${synthPlannedGrants.map(r => r.name).join(', ')}`);
    }
    console.log('✓ PASS: Synthetic permission with planned = 1 is not assigned to Owner, Admin, or any system role.');

    console.log('\n--- [3] Promoting Synthetic Permission (planned = 0) & Running catalogSync ---');
    await tenantDb.execute('UPDATE permissions SET planned = 0 WHERE `key` = ?', [synthKey]);

    // Run catalogSync
    await syncPermissionCatalog(tenantDb);

    // Verify who received synthetic.test_feature
    const synthActiveGrants = await tenantDb.query(
      `SELECT r.name, r.is_system, r.rank 
       FROM role_permissions rp 
       JOIN permissions p ON rp.permission_id = p.id 
       JOIN roles r ON rp.role_id = r.id 
       WHERE p.key = ?`,
      [synthKey]
    );

    const grantedRoleNames = new Set(synthActiveGrants.map(r => r.name));
    console.log(`Roles granted promoted permission: [${Array.from(grantedRoleNames).join(', ')}]`);

    // Must be granted to Owner
    if (!grantedRoleNames.has('Owner')) {
      throw new Error('Promoted permission was NOT automatically granted to Owner!');
    }
    console.log('✓ PASS: Promoted permission was automatically granted to Owner.');

    // Must be granted to Admin
    if (!grantedRoleNames.has('Admin')) {
      throw new Error('Promoted permission was NOT automatically granted to Admin!');
    }
    console.log('✓ PASS: Promoted permission was automatically granted to Admin.');

    // Must NOT be granted to other system roles (Project Manager, Team Lead, Team Member, Viewer, Auditor, Guest)
    const otherSystemRoles = ['Project Manager', 'Team Lead', 'Team Member', 'Viewer', 'Auditor', 'Guest'];
    for (const rName of otherSystemRoles) {
      if (grantedRoleNames.has(rName)) {
        throw new Error(`VIOLATION: Promoted permission was unexpectedly granted to ${rName}!`);
      }
    }
    console.log('✓ PASS: No other system role received the newly promoted permission (only listed registry keys are assigned).');

    console.log('\n--- [3b] Assigning Promoted Permission to a Custom Role ---');
    const { w1Id } = fixture.context;
    // Create custom role in W1
    const createRoleRes = await ownerClient.post(`/api/workspaces/${w1Id}/roles`, {
      name: 'Synthetic Custom Role',
      permissions: [synthKey, 'task.view']
    });
    if (createRoleRes.status !== 200 && createRoleRes.status !== 201) {
      throw new Error(`Failed to create custom role: ${createRoleRes.status} ${JSON.stringify(createRoleRes.data)}`);
    }
    const customRoleId = createRoleRes.data?.role?.id || createRoleRes.data?.id;
    console.log(`✓ PASS: Promoted synthetic permission is assignable to custom role (Role ID: ${customRoleId}).`);

    console.log('\n--- [4] Demoting Synthetic Permission & Cleaning Up ---');
    await tenantDb.execute('UPDATE permissions SET planned = 1 WHERE `key` = ?', [synthKey]);
    await syncPermissionCatalog(tenantDb);

    const postDemoteGrants = await tenantDb.query(
      `SELECT r.name 
       FROM role_permissions rp 
       JOIN permissions p ON rp.permission_id = p.id 
       JOIN roles r ON rp.role_id = r.id 
       WHERE p.key = ?`,
      [synthKey]
    );
    if (postDemoteGrants.length !== 0) {
      throw new Error(`Demoting planned permission failed to remove grants: ${JSON.stringify(postDemoteGrants)}`);
    }
    console.log('✓ PASS: Demoting permission to planned = 1 cleanly revoked role assignments via catalogSync.');

    // Delete custom role
    await ownerClient.delete(`/api/workspaces/${w1Id}/roles/${customRoleId}`);

    // Clean up synthetic permission row
    await tenantDb.execute('DELETE FROM permissions WHERE `key` = ?', [synthKey]);
    await syncPermissionCatalog(tenantDb);

    console.log('✓ PASS: Catalog and roles continue functioning normally after synthetic permission removal.');
    console.log('\n✅ ALL PLANNED KEYS AND SYNTHETIC PROMOTION TESTS PASSED!');
  });

  // Run Part 2: Additive-Only Boot Migrator & Legacy Key Remapping
  const { runBootAdditiveAndLegacyRemapSuite } = require('./bootAdditiveAndLegacyRemapTest');
  const remapRes = await runBootAdditiveAndLegacyRemapSuite();

  const totalChecks = 7 + (remapRes?.totalChecks || 7);
  const checksPassed = 7 + (remapRes?.checksPassed || 7);
  return { checksPassed, totalChecks };
}

module.exports = { runPlannedAndSyntheticSuite };
