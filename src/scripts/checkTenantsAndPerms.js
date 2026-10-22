// server/src/scripts/checkTenantsAndPerms.js
const mysql = require('mysql2/promise');
require('dotenv').config();

async function inspect() {
  const masterConn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_MASTER_DATABASE || 'pm_master'
  });

  const [tenants] = await masterConn.query('SELECT * FROM tenants');
  console.log('Tenants:', tenants);



  for (const tenant of tenants) {
    console.log(`\n=== Tenant DB: ${tenant.db_name} ===`);
    const tenantConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || '',
      database: tenant.db_name
    });

    const [ws] = await tenantConn.query('SELECT id, name, is_archived FROM workspaces');
    console.log('Workspaces:', ws);

    const [members] = await tenantConn.query(`
      SELECT wm.workspace_id, wm.user_id, u.email, r.name as role_name, r.rank
      FROM workspace_members wm
      JOIN users u ON wm.user_id = u.id
      JOIN roles r ON wm.role_id = r.id
    `);
    console.log('Workspace members:', members);

    const [roles] = await tenantConn.query('SELECT id, name, rank, is_system FROM roles');
    console.log('Roles:', roles);
    for (const r of roles) {
      const [perms] = await tenantConn.query(
        'SELECT p.key FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ? ORDER BY p.key',
        [r.id]
      );
      const permKeys = perms.map(p => p.key);
      const archPerms = permKeys.filter(k => k.includes('archive') || k.includes('restore'));
      console.log(`Role ${r.id} (${r.name}, rank ${r.rank}): archive/restore perms:`, archPerms);
    }

    await tenantConn.end();
  }

  await masterConn.end();
  process.exit(0);
}

inspect().catch(err => {
  console.error(err);
  process.exit(1);
});
