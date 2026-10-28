// server/src/utils/syncCompanyOwners.js
// Authoritative Company Owner management decoupled from workspace-level roles.

/**
 * Checks whether a user is an authoritative Company Owner.
 *
 * @param {object} db - Database wrapper
 * @param {number} userId - User ID to verify
 * @returns {Promise<boolean>}
 */
async function isCompanyOwner(db, userId) {
  if (!userId) return false;
  try {
    const rows = await db.query('SELECT 1 FROM company_owners WHERE user_id = ? LIMIT 1', [userId]);
    return rows.length > 0;
  } catch (_) {
    return false;
  }
}

/**
 * Automatically ensures all verified Company Owners are enrolled as Owner in ALL active workspaces.
 * If targetUserId is provided, syncs that specific user if they are a verified company owner;
 * otherwise syncs all verified Company Owners from the authoritative company_owners table.
 *
 * @param {object} db - Database wrapper
 * @param {number|null} [targetUserId] - Optional user ID to sync
 * @returns {Promise<number[]>} Array of synced owner user IDs
 */
async function syncCompanyOwners(db, targetUserId = null) {
  try {
    const sysOwnerRole = await db.query(
      "SELECT id, name FROM roles WHERE is_system = 1 AND (name = 'Owner' OR name = 'Super Admin') AND workspace_id IS NULL ORDER BY (name = 'Owner') DESC LIMIT 1"
    );
    const ownerRoleId = sysOwnerRole[0]?.id;
    const ownerRoleName = sysOwnerRole[0]?.name || 'Owner';
    if (!ownerRoleId) return [];

    // Ensure company_owners table exists
    try {
      await db.execute(`
        CREATE TABLE IF NOT EXISTS company_owners (
          user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
          created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
          CONSTRAINT fk_co_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);
    } catch (_) {}

    let ownerUserIds = [];
    if (targetUserId) {
      const isTargetOwner = await db.query(
        'SELECT 1 FROM company_owners WHERE user_id = ? LIMIT 1',
        [targetUserId]
      );
      if (isTargetOwner.length > 0) {
        ownerUserIds = [Number(targetUserId)];
      }
    } else {
      const allOwners = await db.query('SELECT user_id FROM company_owners');
      ownerUserIds = allOwners.map((o) => Number(o.user_id));
    }

    if (ownerUserIds.length === 0) {
      // If table is completely empty, discover founding owner and populate company_owners
      const foundingRows = await db.query(
        `SELECT u.id
         FROM users u
         JOIN workspace_members wm ON u.id = wm.user_id
         JOIN roles r ON wm.role_id = r.id
         WHERE (r.name = 'Owner' OR r.name = 'Super Admin') AND r.is_system = 1 AND r.workspace_id IS NULL
         ORDER BY u.id ASC
         LIMIT 1`
      );
      if (foundingRows.length > 0) {
        await db.execute('INSERT IGNORE INTO company_owners (user_id) VALUES (?)', [foundingRows[0].id]);
        ownerUserIds = [Number(foundingRows[0].id)];
      } else {
        const anyUser = await db.query('SELECT id FROM users ORDER BY id ASC LIMIT 1');
        if (anyUser.length > 0) {
          await db.execute('INSERT IGNORE INTO company_owners (user_id) VALUES (?)', [anyUser[0].id]);
          ownerUserIds = [Number(anyUser[0].id)];
        } else {
          return [];
        }
      }
    }

    for (const uid of ownerUserIds) {
      await db.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
         SELECT w.id, ?, ?, ?
         FROM workspaces w
         ON DUPLICATE KEY UPDATE role = VALUES(role), role_id = VALUES(role_id)`,
        [uid, ownerRoleName, ownerRoleId]
      );
    }
    return ownerUserIds;
  } catch (err) {
    console.warn('[WARN] syncCompanyOwners error:', err.message);
    return [];
  }
}

module.exports = {
  isCompanyOwner,
  syncCompanyOwners
};
