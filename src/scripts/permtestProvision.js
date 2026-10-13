#!/usr/bin/env node
// server/src/scripts/permtestProvision.js
// Provisions a permtest company on the server and prints the Owner credentials once.

require('dotenv').config();
const { provisionTenant, slugify, dropTenantDatabase } = require('../services/tenantProvisioner');
const { getMasterDb, evictTenantPool, closeAllTenantPools } = require('../services/tenantPools');
const { generateCompliantPassword } = require('../utils/passwordPolicy');

async function main() {
  const args = process.argv.slice(2);
  let slugArg = null;
  let emailArg = null;
  let passArg = null;
  let force = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--slug' && args[i + 1]) {
      slugArg = args[i + 1];
      i++;
    } else if (args[i] === '--email' && args[i + 1]) {
      emailArg = args[i + 1];
      i++;
    } else if (args[i] === '--password' && args[i + 1]) {
      passArg = args[i + 1];
      i++;
    } else if (args[i] === '--force') {
      force = true;
    }
  }

  const rawSlug = slugArg || process.env.PERMCHECK_COMPANY_SLUG || 'permtest_company';
  const slug = slugify(rawSlug);

  if (!slug.startsWith('permtest')) {
    console.error(`[ERROR] Security guard violation: Company slug "${slug}" must start with "permtest"`);
    process.exit(1);
  }

  const email = (emailArg || process.env.PERMCHECK_OWNER_EMAIL || `owner@permtest.local`).trim().toLowerCase();
  const password = passArg || process.env.PERMCHECK_OWNER_PASSWORD || generateCompliantPassword(16);
  const companyName = `Permtest ${slug.replace(/^permtest[-_]?/i, '') || 'Corp'}`.trim();

  const masterDb = getMasterDb();

  // Check if tenant already exists
  const existing = await masterDb.query(
    'SELECT id, slug, db_name FROM tenants WHERE slug = ?',
    [slug]
  );

  if (existing.length > 0) {
    if (!force) {
      console.log(`[INFO] Tenant with slug "${slug}" already exists (id: ${existing[0].id}, db: ${existing[0].db_name}). Re-provisioning with --force will overwrite.`);
      console.log(`Use: npm run permtest:drop -- --slug ${slug} first, or pass --force.`);
      process.exit(0);
    }

    console.log(`[WARN] Force dropping existing tenant "${slug}" before provisioning...`);
    const t = existing[0];
    try {
      await dropTenantDatabase(t.db_name);
    } catch (e) {
      console.warn(`[WARN] Could not drop DB ${t.db_name}:`, e.message);
    }
    await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
    await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
    await evictTenantPool(t.id);
  }

  // Ensure owner email is not in tenant_user_directory
  await masterDb.execute('DELETE FROM tenant_user_directory WHERE email = ?', [email]);

  console.log(`[PROVISION] Creating permtest company "${companyName}" (slug: ${slug})...`);
  const result = await provisionTenant({
    companyName,
    slug,
    ownerEmail: email,
    ownerPassword: password,
    ownerName: 'Permtest Owner'
  });

  console.log('\n==================================================');
  console.log('PERMTEST PROVISIONED SUCCESSFULLY');
  console.log('--------------------------------------------------');
  console.log(`Company Name:   ${result.tenant.name}`);
  console.log(`Company Slug:   ${result.tenant.slug}`);
  console.log(`Tenant DB:      ${result.tenant.db_name}`);
  console.log(`Tenant ID:      ${result.tenant.id}`);
  console.log(`Owner Email:    ${result.owner.email}`);
  console.log(`Owner Password: ${password}`);
  console.log('==================================================\n');
}

main()
  .then(async () => {
    await closeAllTenantPools();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error('[ERROR] Failed to provision permtest tenant:', err);
    await closeAllTenantPools();
    process.exit(1);
  });
