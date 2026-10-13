// server/src/scripts/rbacSyncCheck.js
// Validates that all tenant databases have their permissions catalog in 100% sync with registry.js.

const { PERMISSIONS, SYSTEM_ROLES } = require('../rbac/registry');
const { getMasterDb, getDevSingleDb, getTenantDb } = require('../services/tenantPools');

async function checkCatalogForDb(db, dbLabel) {
  const errors = [];

  // 1. Fetch permissions in database
  const dbPerms = await db.query('SELECT `key`, planned, module, scope, dangerous FROM permissions');
  const dbPermMap = new Map(dbPerms.map((p) => [p.key, p]));

  for (const regPerm of PERMISSIONS) {
    const dbP = dbPermMap.get(regPerm.key);
    if (!dbP) {
      errors.push(`Missing permission key in DB: "${regPerm.key}"`);
      continue;
    }
    const expectedPlanned = regPerm.planned ? 1 : 0;
    const actualPlanned = dbP.planned ? 1 : 0;
    if (expectedPlanned !== actualPlanned) {
      errors.push(`Permission "${regPerm.key}" planned mismatch: expected ${expectedPlanned}, got ${actualPlanned}`);
    }
  }

  // 2. Check System Roles
  const roles = await db.query('SELECT id, name, is_system, rank FROM roles WHERE workspace_id IS NULL ORDER BY id ASC');
  const roleMap = new Map();
  roles.forEach((r) => {
    if (!roleMap.has(r.name)) roleMap.set(r.name, r);
  });

  for (const [roleName, roleDef] of Object.entries(SYSTEM_ROLES)) {
    const r = roleMap.get(roleName);
    if (!r) {
      errors.push(`Missing system role in DB: "${roleName}"`);
      continue;
    }
    if (!r.is_system) {
      errors.push(`System role "${roleName}" has is_system = 0`);
    }

    // Check permissions
    const rpRows = await db.query(
      `SELECT p.\`key\` FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE rp.role_id = ?`,
      [r.id]
    );
    const assignedKeys = new Set(rpRows.map((row) => row.key));

    if (roleName === 'Owner') {
      const activeKeys = PERMISSIONS.filter((p) => !p.planned).map((p) => p.key);
      const missingKeys = activeKeys.filter((k) => !assignedKeys.has(k));
      if (missingKeys.length > 0) {
        errors.push(`Owner role is missing active permissions: ${missingKeys.slice(0, 5).join(', ')}${missingKeys.length > 5 ? '...' : ''}`);
      }
    } else {
      const expectedKeys = roleDef.permissions.filter((k) => {
        const p = PERMISSIONS.find((regP) => regP.key === k);
        return p && !p.planned;
      });
      const missingKeys = expectedKeys.filter((k) => !assignedKeys.has(k));
      if (missingKeys.length > 0) {
        errors.push(`Role "${roleName}" is missing expected permissions: ${missingKeys.join(', ')}`);
      }
    }
  }

  return errors;
}

async function runSyncCheck() {
  console.log('================================================================');
  console.log('       RBAC PERMISSION CATALOG SYNCHRONIZATION AUDIT            ');
  console.log('================================================================');

  let failed = false;

  try {
    const isSingleTenant = process.env.DEV_SINGLE_TENANT === '1' || process.env.DEV_SINGLE_TENANT === 'true';
    if (isSingleTenant) {
      console.log('Running check on Single Tenant DB...');
      const devDb = getDevSingleDb();
      const errors = await checkCatalogForDb(devDb, 'single-tenant');
      if (errors.length > 0) {
        failed = true;
        console.error('❌ Errors found in Single Tenant DB:');
        errors.forEach((e) => console.error(`  - ${e}`));
      } else {
        console.log('✓ Single Tenant DB catalog is 100% synchronized with registry.js');
      }
    } else {
      const masterDb = getMasterDb();
      let tenants = [];
      try {
        tenants = await masterDb.query(
          "SELECT id, db_name, slug FROM tenants WHERE status = 'active'"
        );
      } catch (masterErr) {
        console.warn('Could not query master tenants table:', masterErr.message);
      }

      if (tenants.length === 0) {
        console.log('No active tenants found in master DB. Checking dev single DB...');
        const devDb = getDevSingleDb();
        const errors = await checkCatalogForDb(devDb, 'default-dev');
        if (errors.length > 0) {
          failed = true;
          console.error('❌ Errors found in default dev DB:');
          errors.forEach((e) => console.error(`  - ${e}`));
        } else {
          console.log('✓ Default dev DB catalog is 100% synchronized with registry.js');
        }
      } else {
        for (const t of tenants) {
          console.log(`Checking tenant: ${t.slug} (${t.db_name})...`);
          const tenantDb = await getTenantDb(t.id);
          const errors = await checkCatalogForDb(tenantDb, t.slug);
          if (errors.length > 0) {
            failed = true;
            console.error(`❌ Errors found in tenant ${t.slug}:`);
            errors.forEach((e) => console.error(`  - ${e}`));
          } else {
            console.log(`✓ Tenant ${t.slug} is 100% synchronized.`);
          }
        }
      }
    }

    if (failed) {
      console.error('\n[RBAC SYNC CHECK FAILED] One or more tenant catalogs differ from registry.js');
      process.exit(1);
    } else {
      console.log('\n[RBAC SYNC CHECK PASSED] All tenant catalogs are 100% in sync with registry.js');
      process.exit(0);
    }
  } catch (err) {
    console.error('[FATAL ERROR during rbac:sync-check]:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  runSyncCheck();
}

module.exports = { checkCatalogForDb, runSyncCheck };
