// server/src/utils/syncCompanyOwners.js
// Universal Owner Policy: Ensures all Company Owners have Owner membership across all active workspaces.

/**
 * Automatically ensures all Company Owners are enrolled as Owner in ALL active workspaces.
 * If targetUserId is provided, syncs that specific user if they are an owner;
 * otherwise syncs all detected Company Owners across all active workspaces.
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

    let ownerUserIds = [];
    if (targetUserId) {
      const isTargetOwner = await db.query(
        `SELECT 1 FROM workspace_members wm
         JOIN roles r ON wm.role_id = r.id
         WHERE wm.user_id = ? AND ((r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100)) OR wm.role IN ('Owner', 'Super Admin'))
         LIMIT 1`,
        [targetUserId]
      );
      if (isTargetOwner.length > 0) {
        ownerUserIds = [Number(targetUserId)];
      }
    } else {
      const allOwners = await db.query(
        `SELECT DISTINCT wm.user_id
         FROM workspace_members wm
         JOIN roles r ON wm.role_id = r.id
         WHERE (r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100))
            OR wm.role IN ('Owner', 'Super Admin')`
      );
      ownerUserIds = allOwners.map((o) => Number(o.user_id));
    }

    if (ownerUserIds.length === 0) return [];

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
  syncCompanyOwners
};
