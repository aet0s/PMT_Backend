const db = require('../db');
const { SYSTEM_ROLES } = require('../rbac/registry');

async function verifyAllTenants() {
  console.log('================================================================');
  console.log('       VERIFYING MIGRATION 0037 ACROSS ALL TENANT DATABASES     ');
  console.log('================================================================\n');

  const rawDbs = await db.query("SHOW DATABASES LIKE 'pm_t_%'");
  const tenantDbs = rawDbs.map((r) => Object.values(r)[0]);
  tenantDbs.push('pm_dev_single');

  const obsoleteKeys = ['project.view_dashboard', 'company.manage_billing', 'task.export', 'task.import', 'role.assign'];
  const placeholders = obsoleteKeys.map(() => '?').join(',');

  const report = [];

  for (const dbName of tenantDbs) {
    await db.query(`USE \`${dbName}\``);

    // 1. Check schema_migrations
    let mig0037Applied = false;
    let appliedAt = null;
    try {
      const migRows = await db.query(
        "SELECT version, name, applied_at FROM schema_migrations WHERE version = '0037' OR name LIKE '%0037%'"
      );
      if (migRows.length > 0) {
        mig0037Applied = true;
        appliedAt = migRows[0].applied_at;
      }
    } catch (_) {}

    // 2. Check permissions table for obsolete keys
    const obsP = await db.query(
      `SELECT count(*) as count FROM permissions WHERE \`key\` IN (${placeholders})`,
      obsoleteKeys
    );
    const obsoleteInPerms = Number(obsP[0]?.count || 0);

    // 3. Check role_permissions table for obsolete keys
    const obsRP = await db.query(
      `SELECT count(*) as count FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE p.\`key\` IN (${placeholders})`,
      obsoleteKeys
    );
    const obsoleteInRolePerms = Number(obsRP[0]?.count || 0);

    // 4. Check total active permissions
    const activeP = await db.query('SELECT count(*) as count FROM permissions WHERE planned = 0');
    const activePermsCount = Number(activeP[0]?.count || 0);

    // 5. Check role count and system roles ranks
    const roles = await db.query('SELECT name, rank, is_editable, is_system FROM roles WHERE workspace_id IS NULL');
    const roleNames = roles.map((r) => r.name);
    const hasAll8 = ['Owner', 'Admin', 'Project Manager', 'Team Lead', 'Team Member', 'Viewer', 'Auditor', 'Guest'].every(
      (n) => roleNames.includes(n)
    );

    // 6. Check that role.assign was preserved as member.assign_role
    const assignRoleRows = await db.query(
      `SELECT rp.role_id, r.name FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       JOIN roles r ON rp.role_id = r.id
       WHERE p.\`key\` = 'member.assign_role'`
    );
    const assignRoleCount = assignRoleRows.length;

    report.push({
      database: dbName,
      mig0037Applied,
      obsoleteInPerms,
      obsoleteInRolePerms,
      activePermsCount,
      hasAll8SystemRoles: hasAll8,
      memberAssignRoleGrants: assignRoleCount
    });
  }

  console.table(report);

  const allPassed = report.every(
    (r) => r.mig0037Applied && r.obsoleteInPerms === 0 && r.obsoleteInRolePerms === 0 && r.hasAll8SystemRoles
  );

  if (allPassed) {
    console.log('\n✅ ALL TENANT DATABASES VERIFIED: 100% compliant with Migration 0037.');
    process.exit(0);
  } else {
    console.error('\n❌ VERIFICATION FAILED: Some tenant databases have missing migrations or obsolete keys.');
    process.exit(1);
  }
}

verifyAllTenants().catch((err) => {
  console.error(err);
  process.exit(1);
});
