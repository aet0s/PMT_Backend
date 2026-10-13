require('dotenv').config();
const { getDevSingleDb } = require('../services/tenantPools');
const { userHasPermission } = require('../middleware/permissions');

async function main() {
  const db = getDevSingleDb();
  const userId = 2; // Project Manager
  const workspaceId = 1;
  const projectId = 1;

  console.log('1. userHasPermission before remove:', await userHasPermission(userId, workspaceId, 'task.delete', db, projectId));

  // Remove task.delete from PM role (id 2)
  const taskDeletePerm = await db.query('SELECT id FROM permissions WHERE `key` = "task.delete"');
  await db.execute('DELETE FROM role_permissions WHERE role_id = 2 AND permission_id = ?', [taskDeletePerm[0].id]);

  console.log('2. userHasPermission AFTER remove task.delete:', await userHasPermission(userId, workspaceId, 'task.delete', db, projectId));

  // Restore task.delete
  await db.execute('INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (2, ?)', [taskDeletePerm[0].id]);
  console.log('3. userHasPermission AFTER restore task.delete:', await userHasPermission(userId, workspaceId, 'task.delete', db, projectId));

  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
