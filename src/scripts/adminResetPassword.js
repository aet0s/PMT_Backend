#!/usr/bin/env node
// server/src/scripts/adminResetPassword.js
// CLI script to reset a user's password without email, forcing a change on next login.
// Usage: npm run admin:reset-password -- <tenant-slug> <email>

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { getMasterDb, getTenantDb, closeAllPools } = require('../services/tenantPools');
const { generateCompliantPassword } = require('../utils/passwordPolicy');

async function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== '--');

  if (args.length < 2) {
    console.error('Usage: npm run admin:reset-password -- <tenant-slug> <email>');
    process.exit(1);
  }

  const [tenantSlug, email] = args;
  const cleanSlug = tenantSlug.trim().toLowerCase();
  const cleanEmail = email.trim().toLowerCase();

  try {
    const masterDb = getMasterDb();
    const tenantRes = await masterDb.query(
      "SELECT id, slug, name, db_name, status FROM tenants WHERE slug = ? AND status != 'deleted'",
      [cleanSlug]
    );

    if (tenantRes.length === 0) {
      console.error(`Error: Tenant with slug "${cleanSlug}" was not found.`);
      process.exit(1);
    }

    const tenant = tenantRes[0];
    const tenantDb = await getTenantDb(tenant.id);

    const userRes = await tenantDb.query(
      'SELECT id, name, email FROM users WHERE email = ?',
      [cleanEmail]
    );

    if (userRes.length === 0) {
      console.error(`Error: User with email "${cleanEmail}" was not found in tenant "${cleanSlug}".`);
      process.exit(1);
    }

    const user = userRes[0];
    const tempPassword = generateCompliantPassword(14);
    const passwordHash = await bcrypt.hash(tempPassword, 12);

    await tenantDb.execute(
      'UPDATE users SET password_hash = ?, must_change_password = 1, failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
      [passwordHash, user.id]
    );

    // Revoke all existing sessions
    await tenantDb.execute(
      'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE user_id = ? AND revoked_at IS NULL',
      [user.id]
    );

    // Log auth audit
    await tenantDb.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, metadata)
       VALUES (?, ?, 'CLI_PASSWORD_RESET', ?)`,
      [user.id, user.email, JSON.stringify({ reset_by: 'cli_admin' })]
    );

    console.log('=======================================================');
    console.log('             ADMIN PASSWORD RESET SUCCESS              ');
    console.log('=======================================================');
    console.log(`Tenant:             ${tenant.slug} (${tenant.name})`);
    console.log(`User:               ${user.email} (${user.name})`);
    console.log(`Temporary Password: ${tempPassword}`);
    console.log('Must Change Pwd:    true (forced on next login)');
    console.log('Active Sessions:    All existing sessions revoked');
    console.log('=======================================================');
  } catch (err) {
    console.error('Fatal error resetting password:', err.message);
    process.exit(1);
  } finally {
    await closeAllPools();
  }
}

main();
