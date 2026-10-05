// server/src/scripts/tenantsList.js
// CLI script to list all registered companies/tenants and their status.
require('dotenv').config();
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');

async function listTenants() {
  const masterDb = getMasterDb();
  console.log('\n=== Registered Companies / Tenants in pm_master ===\n');

  try {
    const tenants = await masterDb.query(
      `SELECT id, slug, name, db_name, status, owner_email, plan, created_at
       FROM tenants
       ORDER BY id ASC`
    );

    if (tenants.length === 0) {
      console.log('No tenants found in pm_master.');
      return;
    }

    const report = [];

    for (const t of tenants) {
      let userCount = 0;
      let reachable = true;

      try {
        const tenantDb = await getTenantDb(t.id);
        const [uRes] = await tenantDb.query('SELECT COUNT(*) as cnt FROM users');
        userCount = Number(uRes?.cnt || 0);
      } catch (err) {
        reachable = false;
      }

      report.push({
        ID: t.id,
        Slug: t.slug,
        Name: t.name,
        Database: t.db_name,
        Status: t.status,
        Plan: t.plan,
        Users: reachable ? userCount : 'N/A (unreachable)',
        Owner: t.owner_email,
        CreatedAt: t.created_at
      });
    }

    console.table(report);
  } catch (err) {
    console.error('Failed to list tenants:', err.message);
    process.exit(1);
  } finally {
    await closeAllTenantPools();
  }
}

if (require.main === module) {
  listTenants();
}

module.exports = listTenants;
