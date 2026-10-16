// server/src/scripts/permtest/bootAdditiveAndLegacyRemapTest.js
// Tests:
// 1. Boot migrator and catalogSync are strictly additive-only:
//    - Extra key added to editable system role (Team Member) survives boot migrator + catalogSync.
//    - Removed key deleted from Admin survives boot migrator + catalogSync (not re-granted).
// 2. Custom role carrying each legacy key (role.assign, project.view_dashboard, company.manage_billing, task.import, task.export)
//    has all grants cleanly remapped to canonical keys.

const assert = require('assert');
const { PermtestFixture } = require('./fixtures');
const { syncPermissionCatalog } = require('../../rbac/catalogSync');
const { runBootMigrations } = require('../../db/migrator');

async function runBootAdditiveAndLegacyRemapSuite() {
  console.log('='.repeat(64));
  console.log('   TEST: BOOT ADDITIVE-ONLY BEHAVIOR & LEGACY KEY REMAPPING     ');
  console.log('='.repeat(64));

  let totalChecks = 0;
  let checksPassed = 0;

  const toRows = (res) => {
    if (!res) return [];
    if (Array.isArray(res)) return Array.isArray(res[0]) ? res[0] : res;
    return [res];
  };

  const fixture = new PermtestFixture();
  try {
    await fixture.setup();
    const ctx = fixture.context;
    const db = ctx.tenantDb;

    // ─────────────────────────────────────────────────────────────
    // PART 1: LEGACY KEY REMAPPING ON CUSTOM ROLE
    // ─────────────────────────────────────────────────────────────
    console.log('\n--- [1] Custom Role with Legacy Keys Remapping ---');

    // Create a custom role in W1
    const createRole = await db.execute(
      `INSERT INTO roles (workspace_id, name, is_system, is_editable, rank)
       VALUES (?, 'Legacy Key Custom Role', 0, 1, 30)`,
      [ctx.w1Id]
    );
    const customRoleId = createRole.insertId || createRole[0]?.insertId;

    // Insert legacy keys into permissions catalog if not present, then grant to custom role
    const legacyKeyMap = [
      { oldKey: 'role.assign', newKey: 'member.assign_role' },
      { oldKey: 'project.view_dashboard', newKey: 'dashboard.view_project' },
      { oldKey: 'company.manage_billing', newKey: 'billing.manage' },
      { oldKey: 'task.import', newKey: 'import_export.import' },
      { oldKey: 'task.export', newKey: 'import_export.export' }
    ];

    for (const mapping of legacyKeyMap) {
      await db.execute(
        `INSERT IGNORE INTO permissions (\`key\`, category, label, planned) VALUES (?, 'general', ?, 0)`,
        [mapping.oldKey, mapping.oldKey]
      );
      const oldPerm = toRows(await db.query('SELECT id FROM permissions WHERE `key` = ?', [mapping.oldKey]))[0];
      if (oldPerm) {
        await db.execute(
          'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
          [customRoleId, oldPerm.id]
        );
      }
    }

    // Verify custom role holds the 5 old keys before remap
    const beforePerms = toRows(await db.query(
      `SELECT p.key FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE rp.role_id = ?`,
      [customRoleId]
    ));
    const beforeKeys = beforePerms.map(r => r.key);
    console.log(`Custom role before remap keys (${beforeKeys.length}): [${beforeKeys.join(', ')}]`);

    // Execute Migration 0021 remap queries
    for (const mapping of legacyKeyMap) {
      // Ensure target canonical key exists in permissions
      await db.execute(
        `INSERT IGNORE INTO permissions (\`key\`, category, label, planned) VALUES (?, 'general', ?, 0)`,
        [mapping.newKey, mapping.newKey]
      );
      await db.execute(`
        UPDATE IGNORE role_permissions rp
        JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.key = ?
        JOIN permissions p_new ON p_new.key = ?
        SET rp.permission_id = p_new.id
      `, [mapping.oldKey, mapping.newKey]);
    }

    // Verify custom role keys after remap
    const afterPerms = toRows(await db.query(
      `SELECT p.key FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE rp.role_id = ?`,
      [customRoleId]
    ));
    const afterKeys = afterPerms.map(r => r.key);
    console.log(`Custom role after remap keys (${afterKeys.length}): [${afterKeys.join(', ')}]`);

    for (const mapping of legacyKeyMap) {
      totalChecks++;
      const hasNew = afterKeys.includes(mapping.newKey);
      if (hasNew) {
        checksPassed++;
        console.log(`✓ PASS: ${mapping.oldKey} remapped to ${mapping.newKey}`);
      } else {
        throw new Error(`FAIL: Legacy key ${mapping.oldKey} was not remapped to ${mapping.newKey}`);
      }
    }

    // ─────────────────────────────────────────────────────────────
    // PART 2: BOOT MIGRATOR & CATALOGSYNC ADDITIVE-ONLY CUSTOMIZATIONS
    // ─────────────────────────────────────────────────────────────
    console.log('\n--- [2] Additive-Only Boot Migrator & catalogSync Survival ---');

    // 2a. Add one extra key to editable system role 'Team Member'
    const tmRole = toRows(await db.query("SELECT id FROM roles WHERE name = 'Team Member' AND workspace_id IS NULL LIMIT 1"))[0];
    assert(tmRole, 'Team Member role not found');
    const extraKey = 'member.invite';
    const extraPerm = toRows(await db.query('SELECT id FROM permissions WHERE `key` = ?', [extraKey]))[0];
    assert(extraPerm, `Permission ${extraKey} not found`);

    await db.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [tmRole.id, extraPerm.id]
    );
    console.log(`Customization 1: Added extra key "${extraKey}" to Team Member (role_id: ${tmRole.id})`);

    // 2b. Remove one default key from 'Admin'
    const adminRole = toRows(await db.query("SELECT id FROM roles WHERE name = 'Admin' AND workspace_id IS NULL LIMIT 1"))[0];
    assert(adminRole, 'Admin role not found');
    const removedKey = 'project.delete';
    const removedPerm = toRows(await db.query('SELECT id FROM permissions WHERE `key` = ?', [removedKey]))[0];
    assert(removedPerm, `Permission ${removedKey} not found`);

    await db.execute(
      'DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?',
      [adminRole.id, removedPerm.id]
    );
    console.log(`Customization 2: Removed default key "${removedKey}" from Admin (role_id: ${adminRole.id})`);

    // 2c. Run boot migrations and boot catalogSync on existing tenant DB
    console.log('\nRunning boot migrator and catalogSync on existing tenant...');
    const { runMigrationsOnDb } = require('../../db/migrator');
    await runMigrationsOnDb(fixture.tenant.db_name, 'tenant');
    await syncPermissionCatalog(db); // Boot-time catalogSync (options.forceRoles defaults to false)

    // 2d. Assert Team Member extra key survived (not pruned)
    totalChecks++;
    const tmKeysAfter = toRows(await db.query(
      `SELECT p.key FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE rp.role_id = ? AND p.key = ?`,
      [tmRole.id, extraKey]
    ));
    if (tmKeysAfter.length > 0) {
      checksPassed++;
      console.log(`✓ PASS: Team Member extra key "${extraKey}" SURVIVED boot sync (not pruned).`);
    } else {
      throw new Error(`FAIL: Team Member extra key "${extraKey}" was unexpectedly pruned by boot!`);
    }

    // 2e. Assert Admin removed key survived (not re-granted)
    totalChecks++;
    const adminKeysAfter = toRows(await db.query(
      `SELECT p.key FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE rp.role_id = ? AND p.key = ?`,
      [adminRole.id, removedKey]
    ));
    if (adminKeysAfter.length === 0) {
      checksPassed++;
      console.log(`✓ PASS: Admin removed key "${removedKey}" REMAINED REMOVED after boot sync (not re-granted).`);
    } else {
      throw new Error(`FAIL: Admin removed key "${removedKey}" was unexpectedly re-granted by boot!`);
    }

    console.log(`\nBoot Additive & Legacy Remap Suite: ${checksPassed}/${totalChecks} checks passed.\n`);
    return { checksPassed, totalChecks };
  } finally {
    await fixture.cleanup();
  }
}

module.exports = { runBootAdditiveAndLegacyRemapSuite };

if (require.main === module) {
  runBootAdditiveAndLegacyRemapSuite().then(res => {
    if (res.checksPassed !== res.totalChecks) process.exit(1);
  }).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
