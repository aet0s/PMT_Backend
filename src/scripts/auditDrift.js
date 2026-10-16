// server/src/scripts/auditDrift.js
// Audits drift between registry.js system role permissions and actual tenant databases.

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');
const { SYSTEM_ROLES, PERMISSIONS } = require('../rbac/registry');

async function auditDrift() {
  const masterDb = getMasterDb();
  const tenants = await masterDb.query(
    "SELECT id, slug, db_name FROM tenants WHERE status = 'active'"
  );

  console.log(`Found ${tenants.length} active tenants.`);

  const sampleTenants = tenants.slice(0, 3); // Check first 3 tenants
  for (const t of sampleTenants) {
    console.log(`\n================================================================`);
    console.log(`TENANT: ${t.slug} (${t.db_name})`);
    console.log(`================================================================`);

    const db = await getTenantDb(t.id);
    const roles = await db.query(
      'SELECT id, name FROM roles WHERE workspace_id IS NULL AND is_system = 1 ORDER BY id ASC'
    );

    for (const r of roles) {
      const rows = await db.query(
        'SELECT p.key FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ?',
        [r.id]
      );
      const actualKeys = rows.map((x) => x.key);
      const expectedKeys =
        r.name === 'Owner'
          ? PERMISSIONS.filter((p) => !p.planned).map((p) => p.key)
          : (SYSTEM_ROLES[r.name]?.permissions.filter((k) => {
              const p = PERMISSIONS.find((regP) => regP.key === k);
              return p && !p.planned;
            }) || []);

      const extra = actualKeys.filter((k) => !expectedKeys.includes(k));
      const missing = expectedKeys.filter((k) => !actualKeys.includes(k));

      console.log(`\nRole: "${r.name}" (ID: ${r.id})`);
      console.log(`  Actual DB permissions:   ${actualKeys.length}`);
      console.log(`  Expected in registry:    ${expectedKeys.length}`);
      if (extra.length > 0) {
        console.log(`  ⚠️  EXTRA in DB (${extra.length}):`, extra.join(', '));
      } else {
        console.log(`  ✓ No unexpected extra permissions in DB`);
      }
      if (missing.length > 0) {
        console.log(`  ⚠️  MISSING in DB (${missing.length}):`, missing.join(', '));
      } else {
        console.log(`  ✓ No missing permissions in DB`);
      }
    }
  }

  await closeAllTenantPools();
}

auditDrift()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Audit failed:', err);
    process.exit(1);
  });
