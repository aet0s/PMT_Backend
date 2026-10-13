#!/usr/bin/env node
// server/src/scripts/permtestDrop.js
// Drops a permtest company database and removes registry records.
// GUARD: Strictly refuses to drop any company whose slug does NOT start with "permtest".

require('dotenv').config();
const { slugify, dropTenantDatabase } = require('../services/tenantProvisioner');
const { getMasterDb, evictTenantPool, closeAllTenantPools } = require('../services/tenantPools');

async function main() {
  const args = process.argv.slice(2);
  let slugArg = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--slug' && args[i + 1]) {
      slugArg = args[i + 1];
      i++;
    }
  }

  const rawSlug = slugArg || process.env.PERMCHECK_COMPANY_SLUG;
  if (!rawSlug) {
    console.error('[ERROR] Company slug required via --slug <name> or PERMCHECK_COMPANY_SLUG env var.');
    process.exit(1);
  }

  const slug = slugify(rawSlug);

  // STRICT GUARD: Must start with "permtest"
  if (!slug.startsWith('permtest')) {
    console.error(`[FATAL REFUSAL] Security violation: Refusing to drop tenant "${slug}". Slug MUST start with "permtest".`);
    process.exit(1);
  }

  const masterDb = getMasterDb();
  const existing = await masterDb.query(
    'SELECT id, slug, db_name FROM tenants WHERE slug = ?',
    [slug]
  );

  if (existing.length === 0) {
    console.log(`[INFO] No tenant found with slug "${slug}". Nothing to drop.`);
    process.exit(0);
  }

  const t = existing[0];
  console.log(`[DROP] Dropping tenant "${t.slug}" (id: ${t.id}, db: ${t.db_name})...`);

  try {
    await dropTenantDatabase(t.db_name);
    console.log(`[DROP] Database "${t.db_name}" successfully dropped.`);
  } catch (err) {
    console.warn(`[WARN] Could not drop database "${t.db_name}": ${err.message}`);
  }

  await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
  await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
  await evictTenantPool(t.id);

  console.log(`[DROP] Tenant "${t.slug}" and associated records successfully removed.`);
}

main()
  .then(async () => {
    await closeAllTenantPools();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error('[ERROR] Failed to drop permtest tenant:', err);
    await closeAllTenantPools();
    process.exit(1);
  });
