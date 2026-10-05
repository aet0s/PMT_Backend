#!/usr/bin/env node
// server/src/scripts/adminReset2fa.js
// CLI script to administratively reset a user's two-factor authentication (2FA).
// Usage: npm run admin:reset-2fa -- <tenant-slug> <email>

require('dotenv').config();
const { getMasterDb, getTenantDb, closeAllPools } = require('../services/tenantPools');
const { disconnectUserSockets } = require('../socket');

async function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== '--');

  if (args.length < 2) {
    console.error('Usage: npm run admin:reset-2fa -- <tenant-slug> <email>');
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
      'SELECT id, name, email, totp_enabled FROM users WHERE email = ?',
      [cleanEmail]
    );

    if (userRes.length === 0) {
      console.error(`Error: User with email "${cleanEmail}" was not found in tenant "${cleanSlug}".`);
      process.exit(1);
    }

    const user = userRes[0];

    // Reset 2FA in users table
    await tenantDb.execute(
      'UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_enrolled_at = NULL, last_totp_code = NULL, last_totp_timestamp = NULL WHERE id = ?',
      [user.id]
    );

    // Delete recovery codes
    await tenantDb.execute('DELETE FROM recovery_codes WHERE user_id = ?', [user.id]);

    // Revoke all existing sessions
    await tenantDb.execute(
      'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE user_id = ? AND revoked_at IS NULL',
      [user.id]
    );

    // Disconnect active sockets
    try {
      disconnectUserSockets(user.id, tenant.id, 'ADMIN_2FA_RESET');
    } catch (e) {}

    // Record auth audit log
    await tenantDb.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, metadata)
       VALUES (?, ?, '2FA_RESET', ?)`,
      [user.id, user.email, JSON.stringify({ resetBy: 'CLI_ADMIN', tenantSlug: cleanSlug })]
    );

    console.log('----------------------------------------------------');
    console.log('✓ 2FA Reset Successful!');
    console.log(`  Tenant:   ${tenant.name} (${tenant.slug})`);
    console.log(`  User:     ${user.name} <${user.email}>`);
    console.log('  Status:   Two-factor authentication disabled & recovery codes cleared');
    console.log('  Sessions: All active sessions revoked');
    console.log('----------------------------------------------------');
  } catch (err) {
    console.error('Fatal error during 2FA reset:', err.message);
    process.exit(1);
  } finally {
    await closeAllPools();
    process.exit(0);
  }
}

main();
