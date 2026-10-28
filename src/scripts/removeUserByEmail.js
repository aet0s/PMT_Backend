#!/usr/bin/env node
// server/src/scripts/removeUserByEmail.js
// CLI script to cleanly remove one or more users by email from tenant databases and master directory.
// Usage: node src/scripts/removeUserByEmail.js [--tenant=<slug>] <email1> [email2 ...]

require('dotenv').config();
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');

async function removeUsers() {
  const rawArgs = process.argv.slice(2).filter((a) => a !== '--');
  let tenantFilter = null;
  const emails = [];

  for (const arg of rawArgs) {
    if (arg.startsWith('--tenant=')) {
      tenantFilter = arg.split('=')[1].trim().toLowerCase();
    } else if (arg.includes('@')) {
      emails.push(arg.trim().toLowerCase());
    }
  }

  if (emails.length === 0) {
    console.log('Usage: node src/scripts/removeUserByEmail.js [--tenant=<slug>] <email1> [email2 ...]');
    console.log('Example: node src/scripts/removeUserByEmail.js pm@solarman.in pm2@solarman.in');
    process.exit(1);
  }

  console.log(`\nTarget emails to remove: ${emails.join(', ')}\n`);

  try {
    const masterDb = getMasterDb();
    let tenantQuery = "SELECT id, slug, name, db_name FROM tenants WHERE status != 'deleted'";
    const tenantParams = [];
    if (tenantFilter) {
      tenantQuery += ' AND slug = ?';
      tenantParams.push(tenantFilter);
    }

    const tenants = await masterDb.query(tenantQuery, tenantParams);
    if (tenants.length === 0) {
      console.log('No matching tenants found.');
      return;
    }

    for (const tenant of tenants) {
      console.log(`--- Checking Tenant: ${tenant.name} (${tenant.slug}) ---`);
      let tenantDb;
      try {
        tenantDb = await getTenantDb(tenant.id);
      } catch (err) {
        console.warn(`Could not connect to tenant database for ${tenant.slug}: ${err.message}`);
        continue;
      }

      for (const email of emails) {
        const users = await tenantDb.query(
          'SELECT id, email, name FROM users WHERE LOWER(email) = ?',
          [email]
        );

        if (users.length === 0) {
          console.log(`  User "${email}" not found in tenant "${tenant.slug}".`);
          continue;
        }

        const user = users[0];
        console.log(`  Found user "${user.name}" (${user.email}, ID: ${user.id}). Checking owner safety floor...`);

        // Check if removing this user would leave 0 owners
        const owners = await tenantDb.query(
          `SELECT DISTINCT wm.user_id
           FROM workspace_members wm
           JOIN roles r ON wm.role_id = r.id
           WHERE (r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100))
              OR wm.role IN ('Owner', 'Super Admin')`
        );

        const isUserOwner = owners.some((o) => Number(o.user_id) === Number(user.id));
        const remainingOwners = owners.filter((o) => Number(o.user_id) !== Number(user.id));

        if (isUserOwner && remainingOwners.length === 0) {
          console.error(`  [SKIPPED] Cannot remove "${email}" because they are the sole owner of this company!`);
          continue;
        }

        // Perform clean cascade removal
        try {
          await tenantDb.execute(
            'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE user_id = ?',
            [user.id]
          );
        } catch (e) {}

        await tenantDb.execute('DELETE FROM board_members WHERE user_id = ?', [user.id]);
        await tenantDb.execute('DELETE FROM workspace_members WHERE user_id = ?', [user.id]);
        await tenantDb.execute('DELETE FROM pending_invitations WHERE LOWER(email) = ?', [email]);

        try {
          await masterDb.execute(
            'DELETE FROM tenant_user_directory WHERE LOWER(email) = ? AND tenant_id = ?',
            [email, tenant.id]
          );
        } catch (e) {
          console.warn(`  Warning: Master directory cleanup failed: ${e.message}`);
        }

        await tenantDb.execute('DELETE FROM users WHERE id = ?', [user.id]);
        console.log(`  ✓ Successfully removed user "${user.name}" (${email}) from tenant "${tenant.slug}".`);
      }
    }

    console.log('\nAll done.');
  } catch (err) {
    console.error('Removal failed:', err);
    process.exit(1);
  } finally {
    await closeAllTenantPools();
  }
}

if (require.main === module) {
  removeUsers();
}
