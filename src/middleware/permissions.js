// server/src/middleware/permissions.js
// Production two-level RBAC evaluation engine (Company-level & Project-level).

const { getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { expandPermissionKeys } = require('../rbac/registry');

function getActiveDb(reqOrDb) {
  if (reqOrDb && reqOrDb.db && typeof reqOrDb.db.query === 'function') {
    return reqOrDb.db;
  }
  if (reqOrDb && typeof reqOrDb.query === 'function') {
    return reqOrDb;
  }
  if (process.env.DEV_SINGLE_TENANT === '1') {
    return getDevSingleDb();
  }
  throw new Error('Tenant database instance is required outside single-tenant development mode (getActiveDb)');
}

/**
 * Resolves workspaceId and projectId from req params, body, or database hierarchy
 */
async function resolveWorkspaceId(req) {
  if (req.workspaceId) return req.workspaceId;
  const db = getActiveDb(req);

  // 1. Direct param or body
  if (req.params.workspaceId) {
    req.workspaceId = Number(req.params.workspaceId);
    return req.workspaceId;
  }
  if (req.body.workspace_id) {
    req.workspaceId = Number(req.body.workspace_id);
    return req.workspaceId;
  }
  if (req.query.workspace_id) {
    req.workspaceId = Number(req.query.workspace_id);
    return req.workspaceId;
  }

  if (req.body.board_id) {
    req.projectId = Number(req.body.board_id);
    const res = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [req.body.board_id]);
    if (res[0]) {
      req.workspaceId = res[0].workspace_id;
      return req.workspaceId;
    }
  }

  if (req.body.list_id) {
    const res = await db.query(
      'SELECT l.board_id, b.workspace_id FROM lists l JOIN boards b ON l.board_id = b.id WHERE l.id = ?',
      [req.body.list_id]
    );
    if (res[0]) {
      req.projectId = res[0].board_id;
      req.workspaceId = res[0].workspace_id;
      return req.workspaceId;
    }
  }

  const routePath = req.baseUrl || req.path || '';
  const paramId = Number(req.params.id);

  if (routePath.includes('/notifications') && req.user?.id) {
    const wmRes = await db.query(
      'SELECT workspace_id FROM workspace_members WHERE user_id = ? ORDER BY workspace_id ASC LIMIT 1',
      [req.user.id]
    );
    if (wmRes[0]?.workspace_id) {
      req.workspaceId = wmRes[0].workspace_id;
      return req.workspaceId;
    }
  }

  if (routePath.includes('/workspaces') && paramId) {
    req.workspaceId = paramId;
    return req.workspaceId;
  }

  if (routePath.includes('/boards') && paramId) {
    req.projectId = paramId;
    const res = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [paramId]);
    if (res[0]) {
      req.workspaceId = res[0].workspace_id;
      return req.workspaceId;
    }
  }

  if (routePath.includes('/lists') && paramId) {
    const res = await db.query(
      'SELECT l.board_id, b.workspace_id FROM lists l JOIN boards b ON l.board_id = b.id WHERE l.id = ?',
      [paramId]
    );
    if (res[0]) {
      req.projectId = res[0].board_id;
      req.workspaceId = res[0].workspace_id;
      return req.workspaceId;
    }
  }

  const subPath = req.path || '';

  if (routePath.includes('/cards') && paramId) {
    if (subPath.startsWith('/attachments/')) {
      const res = await db.query(
        `SELECT l.board_id, b.workspace_id
         FROM attachments a
         JOIN cards c ON a.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE a.id = ?`,
        [paramId]
      );
      if (res[0]) {
        req.projectId = res[0].board_id;
        req.workspaceId = res[0].workspace_id;
        return req.workspaceId;
      }
    } else if (subPath.startsWith('/checklist-items/')) {
      const res = await db.query(
        `SELECT l.board_id, b.workspace_id
         FROM checklist_items ci
         JOIN checklists ch ON ci.checklist_id = ch.id
         JOIN cards c ON ch.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE ci.id = ?`,
        [paramId]
      );
      if (res[0]) {
        req.projectId = res[0].board_id;
        req.workspaceId = res[0].workspace_id;
        return req.workspaceId;
      }
    } else if (subPath.startsWith('/checklists/')) {
      const res = await db.query(
        `SELECT l.board_id, b.workspace_id
         FROM checklists ch
         JOIN cards c ON ch.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE ch.id = ?`,
        [paramId]
      );
      if (res[0]) {
        req.projectId = res[0].board_id;
        req.workspaceId = res[0].workspace_id;
        return req.workspaceId;
      }
    } else if (subPath.startsWith('/comments/')) {
      const res = await db.query(
        `SELECT l.board_id, b.workspace_id
         FROM comments co
         JOIN cards c ON co.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE co.id = ?`,
        [paramId]
      );
      if (res[0]) {
        req.projectId = res[0].board_id;
        req.workspaceId = res[0].workspace_id;
        return req.workspaceId;
      }
    } else {
      const res = await db.query(
        `SELECT l.board_id, b.workspace_id 
         FROM cards c 
         JOIN lists l ON c.list_id = l.id 
         JOIN boards b ON l.board_id = b.id 
         WHERE c.id = ?`,
        [paramId]
      );
      if (res[0]) {
        req.projectId = res[0].board_id;
        req.workspaceId = res[0].workspace_id;
        return req.workspaceId;
      }
    }
  }

  return null;
}

/**
 * Two-level permission check: Company-level grant OR Project-level grant.
 * Evaluates purely by permissions granted in role_permissions (NO role-name branching).
 */
async function userHasPermission(userId, workspaceId, permissionKey, dbInstance = null, projectId = null) {
  if (!userId || !workspaceId) return false;
  const db = getActiveDb(dbInstance);

  const expandedKeys = expandPermissionKeys(permissionKey);

  // 1. Company-level role evaluation
  const wsRows = await db.query(
    `SELECT r.id as role_id, r.name as role_name, r.is_system, p.key as permission_key
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     LEFT JOIN role_permissions rp ON r.id = rp.role_id
     LEFT JOIN permissions p ON rp.permission_id = p.id
     WHERE wm.workspace_id = ? AND wm.user_id = ?`,
    [workspaceId, userId]
  );

  if (wsRows.length > 0) {
    const roleName = wsRows[0].role_name;
    const isCompanyAdmin = ['Owner', 'Super Admin', 'Admin'].includes(roleName) || wsRows.some((r) => r.permission_key === 'workspace.edit_settings');
    const userCompanyPerms = new Set(wsRows.map((r) => r.permission_key).filter(Boolean));
    for (const key of expandedKeys) {
      if (userCompanyPerms.has(key)) {
        // Viewers have company-wide read-only access to view projects and tasks
        if (projectId && roleName === 'Viewer' && ['project.view', 'task.view', 'view.view', 'board.view', 'card.view'].includes(key)) {
          return true;
        }
        // Non-admins must have project membership to exercise project-scoped permissions on a specific project
        if (projectId && !isCompanyAdmin && (key.startsWith('project.') || key.startsWith('task.') || key.startsWith('comment.') || key.startsWith('view.') || key.startsWith('attachment.') || key.startsWith('file.') || key.startsWith('board.'))) {
          continue;
        }
        return true;
      }
    }
  }

  // 2. Project-level evaluation (if project context is provided)
  if (projectId) {
    const bmRows = await db.query(
      `SELECT bm.role_id, r.name as role_name, r.is_system, p.key as permission_key
       FROM board_members bm
       LEFT JOIN roles r ON bm.role_id = r.id
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE bm.board_id = ? AND bm.user_id = ?`,
      [projectId, userId]
    );

    if (bmRows.length > 0) {
      // If user is a member of this project, their company-level permissions for project actions activate
      if (wsRows.length > 0) {
        const companyPerms = new Set(wsRows.map((r) => r.permission_key).filter(Boolean));
        for (const key of expandedKeys) {
          if (companyPerms.has(key)) {
            return true;
          }
        }
      }

      // Direct membership in board automatically grants viewing project & tasks for system roles,
      // but NOT for custom roles whose permissions are explicitly defined
      const hasCustomRole = wsRows.some((r) => r.is_system === 0 || r.is_system === false) || bmRows.some((r) => r.is_system === 0 || r.is_system === false);
      if (!hasCustomRole && ['project.view', 'task.view', 'view.view'].some((k) => expandedKeys.includes(k))) {
        return true;
      }

      // If user has a specific project role assigned
      const userProjectPerms = new Set(bmRows.map((r) => r.permission_key).filter(Boolean));
      for (const key of expandedKeys) {
        if (userProjectPerms.has(key)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Gets all effective permissions for a user in a workspace (and optional project)
 */
async function getUserPermissions(userId, workspaceId, dbInstance = null, projectId = null) {
  if (!userId || !workspaceId) return { role: null, permissions: [] };
  const db = getActiveDb(dbInstance);

  const wsRows = await db.query(
    `SELECT r.id as role_id, r.name as role_name, r.is_system, r.is_editable, p.key as permission_key
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     LEFT JOIN role_permissions rp ON r.id = rp.role_id
     LEFT JOIN permissions p ON rp.permission_id = p.id
     WHERE wm.workspace_id = ? AND wm.user_id = ?`,
    [workspaceId, userId]
  );

  if (wsRows.length === 0) return { role: null, permissions: [] };

  const role = {
    id: wsRows[0].role_id,
    name: wsRows[0].role_name,
    is_system: wsRows[0].is_system,
    is_editable: wsRows[0].is_editable
  };

  const permsSet = new Set(wsRows.map((r) => r.permission_key).filter(Boolean));

  if (projectId) {
    const bmRows = await db.query(
      `SELECT bm.role_id, r.name as role_name, p.key as permission_key
       FROM board_members bm
       LEFT JOIN roles r ON bm.role_id = r.id
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE bm.board_id = ? AND bm.user_id = ?`,
      [projectId, userId]
    );

    if (bmRows.length > 0) {
      permsSet.add('project.view');
      permsSet.add('task.view');
      permsSet.add('view.view');
      bmRows.forEach((r) => {
        if (r.permission_key) permsSet.add(r.permission_key);
      });
    }
  }

  return {
    role,
    permissions: Array.from(permsSet)
  };
}

/**
 * Middleware factory requiring a specific permission key
 */
function requirePermission(permissionKey) {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({ error: { message: 'Unauthorized', code: 'UNAUTHORIZED' } });
      }

      const workspaceId = await resolveWorkspaceId(req);
      if (!workspaceId) {
        if (req.params.id || req.params.workspaceId) {
          return res.status(404).json({ error: { message: 'Resource not found', code: 'NOT_FOUND' } });
        }
        return res.status(400).json({ error: { message: 'Workspace context missing', code: 'BAD_REQUEST' } });
      }

      const db = getActiveDb(req);
      const wsCheck = await db.query('SELECT id FROM workspaces WHERE id = ?', [workspaceId]);
      if (!wsCheck || wsCheck.length === 0) {
        return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
      }

      req.workspaceId = workspaceId;

      const hasPerm = await userHasPermission(
        req.user.id,
        workspaceId,
        permissionKey,
        req.db,
        req.projectId || null
      );

      if (!hasPerm) {
        return res.status(403).json({
          error: {
            message: 'You do not have permission to do that',
            code: 'PERMISSION_DENIED'
          }
        });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Counts Owners in a workspace for safety checks (last Owner rule)
 */
async function countOwners(workspaceId, dbInstance = null) {
  const db = getActiveDb(dbInstance);
  const res = await db.query(
    `SELECT COUNT(*) as count
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     WHERE wm.workspace_id = ? AND r.name IN ('Owner', 'Super Admin')`,
    [workspaceId]
  );
  return Number(res[0]?.count || 0);
}

async function checkPermission(userId, permissionKey, workspaceId, dbInstance = null, projectId = null) {
  return userHasPermission(userId, workspaceId, permissionKey, dbInstance, projectId);
}

/**
 * Bulk resolves which candidate users hold a specific permission in a workspace/board.
 * Guaranteed to execute in a bounded number of SQL queries regardless of candidate count.
 * Produces results identical to userHasPermission for every candidate.
 */
async function usersWithPermission(dbInstance, workspaceId, boardId, permissionKey, candidateIds = []) {
  if (!candidateIds || !Array.isArray(candidateIds) || candidateIds.length === 0) {
    return [];
  }
  const cleanIds = Array.from(new Set(candidateIds.map(Number).filter((id) => !isNaN(id) && id > 0)));
  if (cleanIds.length === 0) return [];

  const db = getActiveDb(dbInstance);
  const expandedKeys = expandPermissionKeys(permissionKey);

  // 1. Fetch workspace role and permissions for all candidate users in 1 query
  const wsRows = await db.query(
    `SELECT wm.user_id, r.name as role_name, r.is_system, p.key as permission_key
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     LEFT JOIN role_permissions rp ON r.id = rp.role_id
     LEFT JOIN permissions p ON rp.permission_id = p.id
     WHERE wm.workspace_id = ? AND wm.user_id IN (?)`,
    [workspaceId, cleanIds]
  );

  const wsUserMap = new Map();
  for (const row of wsRows) {
    if (!wsUserMap.has(row.user_id)) {
      wsUserMap.set(row.user_id, {
        roleName: row.role_name,
        isSystem: row.is_system !== 0 && row.is_system !== false,
        permissions: new Set()
      });
    }
    if (row.permission_key) {
      wsUserMap.get(row.user_id).permissions.add(row.permission_key);
    }
  }

  // 2. Fetch board membership and board role permissions in 1 query (if boardId provided)
  const bmUserMap = new Map();
  if (boardId) {
    const bmRows = await db.query(
      `SELECT bm.user_id, r.name as role_name, r.is_system, p.key as permission_key
       FROM board_members bm
       LEFT JOIN roles r ON bm.role_id = r.id
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE bm.board_id = ? AND bm.user_id IN (?)`,
      [boardId, cleanIds]
    );

    for (const row of bmRows) {
      if (!bmUserMap.has(row.user_id)) {
        bmUserMap.set(row.user_id, {
          isMember: true,
          roleName: row.role_name,
          isSystem: row.is_system !== 0 && row.is_system !== false,
          permissions: new Set()
        });
      }
      if (row.permission_key) {
        bmUserMap.get(row.user_id).permissions.add(row.permission_key);
      }
    }
  }

  const authorizedUserIds = [];

  for (const userId of cleanIds) {
    const wsData = wsUserMap.get(userId);
    if (!wsData) {
      continue;
    }

    const roleName = wsData.roleName;
    const isCompanyAdmin =
      ['Owner', 'Super Admin', 'Admin'].includes(roleName) ||
      wsData.permissions.has('workspace.edit_settings');

    let authorized = false;

    // Check company-level permissions
    for (const key of expandedKeys) {
      if (wsData.permissions.has(key)) {
        if (boardId && roleName === 'Viewer' && ['project.view', 'task.view', 'view.view', 'board.view', 'card.view'].includes(key)) {
          authorized = true;
          break;
        }
        if (boardId && !isCompanyAdmin && (key.startsWith('project.') || key.startsWith('task.') || key.startsWith('comment.') || key.startsWith('view.') || key.startsWith('attachment.') || key.startsWith('file.') || key.startsWith('board.'))) {
          continue;
        }
        authorized = true;
        break;
      }
    }

    if (authorized) {
      authorizedUserIds.push(userId);
      continue;
    }

    // Check project-level membership and role (if boardId provided)
    if (boardId) {
      const bmData = bmUserMap.get(userId);
      if (bmData && bmData.isMember) {
        // Membership in board activates company-level project permissions
        for (const key of expandedKeys) {
          if (wsData.permissions.has(key)) {
            authorized = true;
            break;
          }
        }
        if (authorized) {
          authorizedUserIds.push(userId);
          continue;
        }

        // Direct membership in board automatically grants viewing project & tasks for system roles,
        // but NOT for custom roles whose permissions are explicitly defined
        const isCustom = !wsData.isSystem || (bmData && !bmData.isSystem);
        if (!isCustom && ['project.view', 'task.view', 'view.view'].some((k) => expandedKeys.includes(k))) {
          authorizedUserIds.push(userId);
          continue;
        }

        // Project role permissions
        for (const key of expandedKeys) {
          if (bmData.permissions.has(key)) {
            authorized = true;
            break;
          }
        }
        if (authorized) {
          authorizedUserIds.push(userId);
          continue;
        }
      }
    }
  }

  return authorizedUserIds;
}

module.exports = {
  getActiveDb,
  resolveWorkspaceId,
  userHasPermission,
  usersWithPermission,
  checkPermission,
  getUserPermissions,
  requirePermission,
  countOwners,
  countSuperAdmins: countOwners
};
