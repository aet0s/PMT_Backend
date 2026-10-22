// server/src/scripts/checkRolesAndPerms.js
const db = require('../db');

async function check() {
  
  console.log('--- ALL SYSTEM AND WORKSPACE ROLES ---');
  const [roles] = await db.query('SELECT id, name, is_system, is_editable, rank, workspace_id FROM roles');
  console.table(roles);

  console.log('--- ARCHIVE & RESTORE PERMISSIONS ---');
  const [perms] = await db.query("SELECT * FROM permissions WHERE `key` LIKE '%archive%' OR `key` LIKE '%restore%'");
  console.table(perms);

  console.log('--- ROLE PERMISSIONS FOR ARCHIVE / RESTORE ---');
  const [rolePerms] = await db.query(`
    SELECT r.name as role_name, r.id as role_id, r.workspace_id, p.key as perm_key, p.scope
    FROM role_permissions rp
    JOIN roles r ON rp.role_id = r.id
    JOIN permissions p ON rp.permission_id = p.id
    WHERE p.key LIKE '%archive%' OR p.key LIKE '%restore%'
    ORDER BY r.rank DESC, r.name, p.key
  `);
  console.table(rolePerms);

  console.log('--- USERS & WORKSPACE MEMBERS ---');
  const [members] = await db.query(`
    SELECT wm.id, wm.workspace_id, w.name as workspace_name, w.is_archived as ws_archived,
           u.id as user_id, u.email, r.name as role_name, r.rank
    FROM workspace_members wm
    JOIN users u ON wm.user_id = u.id
    JOIN workspaces w ON wm.workspace_id = w.id
    JOIN roles r ON wm.role_id = r.id
    ORDER BY wm.workspace_id, r.rank DESC
  `);
  console.table(members);

  process.exit(0);
}

check().catch(e => { console.error(e); process.exit(1); });
