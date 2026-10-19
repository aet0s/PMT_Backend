// server/src/middleware/permissions.js
// Production RBAC middleware and authorization engine.
// Powered by evaluate.js pure evaluation function (Deny by default, zero role-name branching).

const { getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { expandPermissionKeys } = require('../rbac/registry');
const { evaluatePermission, getPermissionScope } = require('../rbac/evaluate');
const { isOwnerRole } = require('../utils/roleRank');

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
 * Resolves workspaceId and projectId strictly from the resource hierarchy first.
 * Client-supplied workspace_id is used only when no resource is targeted.
 * If both resource workspace and client workspace are present and disagree, throws WORKSPACE_MISMATCH.
 */
async function resolveWorkspaceId(req) {
  if (req.workspaceId && req.projectId !== undefined) return req.workspaceId;
  const db = getActiveDb(req);

  const routePath = req.baseUrl || req.path || '';
  const subPath = req.path || '';
  const paramId = Number(req.params.id);

  let derivedWorkspaceId = null;
  let derivedProjectId = null;
  let resourceMatched = false;

  // 1. FIRST: Check target route resource param (the resource being mutated or read)
  if (paramId && !isNaN(paramId)) {
    if (routePath.includes('/cards')) {
      if (subPath.startsWith('/attachments/')) {
        const res = await db.query(
          `SELECT a.id, a.card_id, l.board_id, b.workspace_id
           FROM attachments a
           JOIN cards c ON a.card_id = c.id
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE a.id = ?`,
          [paramId]
        );
        if (res[0]) {
          derivedProjectId = res[0].board_id;
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        } else {
          const err = new Error('Attachment not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
      } else if (subPath.startsWith('/checklist-items/')) {
        const res = await db.query(
          `SELECT ci.id, ci.checklist_id, ch.card_id, l.board_id, b.workspace_id
           FROM checklist_items ci
           JOIN checklists ch ON ci.checklist_id = ch.id
           JOIN cards c ON ch.card_id = c.id
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE ci.id = ?`,
          [paramId]
        );
        if (res[0]) {
          derivedProjectId = res[0].board_id;
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        } else {
          const err = new Error('Checklist item not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
      } else if (subPath.startsWith('/comments/')) {
        const res = await db.query(
          `SELECT co.id, co.card_id, l.board_id, b.workspace_id
           FROM comments co
           JOIN cards c ON co.card_id = c.id
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE co.id = ?`,
          [paramId]
        );
        if (res[0]) {
          derivedProjectId = res[0].board_id;
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        } else {
          const err = new Error('Comment not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
      } else if (subPath.startsWith('/checklists/')) {
        const res = await db.query(
          `SELECT ch.id, ch.card_id, l.board_id, b.workspace_id
           FROM checklists ch
           JOIN cards c ON ch.card_id = c.id
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE ch.id = ?`,
          [paramId]
        );
        if (res[0]) {
          derivedProjectId = res[0].board_id;
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        } else {
          const err = new Error('Checklist not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
      } else {
        const res = await db.query(
          `SELECT c.id, c.list_id, l.board_id, b.workspace_id
           FROM cards c
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE c.id = ?`,
          [paramId]
        );
        if (res[0]) {
          derivedProjectId = res[0].board_id;
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        } else {
          const err = new Error('Card not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
      }
    } else if (routePath.includes('/lists')) {
      const res = await db.query(
        'SELECT l.id, l.board_id, b.workspace_id FROM lists l JOIN boards b ON l.board_id = b.id WHERE l.id = ?',
        [paramId]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
        resourceMatched = true;
      } else {
        const err = new Error('List not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (routePath.includes('/boards')) {
      if (req.params.labelId) {
        const labelId = Number(req.params.labelId);
        const res = await db.query(
          'SELECT lb.id, lb.board_id, b.workspace_id FROM labels lb LEFT JOIN boards b ON lb.board_id = b.id WHERE lb.id = ?',
          [labelId]
        );
        if (res[0]) {
          derivedProjectId = res[0].board_id || paramId;
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        }
      }
      if (!resourceMatched) {
        derivedProjectId = paramId;
        const res = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [paramId]);
        if (res[0]) {
          derivedWorkspaceId = res[0].workspace_id;
          resourceMatched = true;
        } else {
          const err = new Error('Board not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
      }
    } else if (routePath.includes('/checklists')) {
      const res = await db.query(
        `SELECT ch.id, ch.card_id, l.board_id, b.workspace_id
         FROM checklists ch
         JOIN cards c ON ch.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE ch.id = ?`,
        [paramId]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
        resourceMatched = true;
      } else {
        const err = new Error('Checklist not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (routePath.includes('/attachments')) {
      const res = await db.query(
        `SELECT a.id, a.card_id, l.board_id, b.workspace_id
         FROM attachments a
         JOIN cards c ON a.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE a.id = ?`,
        [paramId]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
        resourceMatched = true;
      } else {
        const err = new Error('Attachment not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (routePath.includes('/roles')) {
      const res = await db.query('SELECT workspace_id FROM roles WHERE id = ?', [paramId]);
      if (res[0]) {
        derivedWorkspaceId = res[0].workspace_id;
        resourceMatched = true;
      }
    } else if (routePath.includes('/workspaces')) {
      derivedWorkspaceId = paramId;
      resourceMatched = true;
    } else if (routePath.includes('/checkin-reviews') || subPath.includes('/checkin-reviews')) {
      const res = await db.query(
        `SELECT r.id, ci.card_id, l.board_id, b.workspace_id
         FROM check_in_reviews r
         JOIN check_ins ci ON r.check_in_id = ci.id
         JOIN cards c ON ci.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE r.id = ?`,
        [paramId]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
        resourceMatched = true;
      } else {
        const err = new Error('Check-in review not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (routePath.includes('/checkins') || subPath.includes('/checkins')) {
      const res = await db.query(
        `SELECT ci.id, ci.card_id, l.board_id, b.workspace_id
         FROM check_ins ci
         JOIN cards c ON ci.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE ci.id = ?`,
        [paramId]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
        resourceMatched = true;
      } else {
        const err = new Error('Check-in not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    }
  }

  // 2. Creation / Collection routes: Check body/query resource identifiers if not derived from route params
  if (!derivedWorkspaceId) {
    if (req.body?.checklist_id || req.body?.checklistId) {
      const chId = Number(req.body.checklist_id || req.body.checklistId);
      const res = await db.query(
        `SELECT l.board_id, b.workspace_id
         FROM checklists ch
         JOIN cards c ON ch.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE ch.id = ?`,
        [chId]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
      } else {
        const err = new Error('Checklist not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (req.body?.card_id || req.body?.cardId) {
      const cid = Number(req.body.card_id || req.body.cardId);
      const res = await db.query(
        'SELECT l.board_id, b.workspace_id FROM cards c JOIN lists l ON c.list_id = l.id JOIN boards b ON l.board_id = b.id WHERE c.id = ?',
        [cid]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
      } else {
        const err = new Error('Card not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (req.body?.list_id || req.body?.listId) {
      const lid = Number(req.body.list_id || req.body.listId);
      const res = await db.query(
        'SELECT l.board_id, b.workspace_id FROM lists l JOIN boards b ON l.board_id = b.id WHERE l.id = ?',
        [lid]
      );
      if (res[0]) {
        derivedProjectId = res[0].board_id;
        derivedWorkspaceId = res[0].workspace_id;
      } else {
        const err = new Error('List not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    } else if (req.body?.board_id || req.body?.boardId) {
      derivedProjectId = Number(req.body.board_id || req.body.boardId);
      const res = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [derivedProjectId]);
      if (res[0]) {
        derivedWorkspaceId = res[0].workspace_id;
      } else {
        const err = new Error('Board not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
    }
  }

  // 3. Fallback for workspace routes without resource params
  if (!derivedWorkspaceId) {
    const rawWs = req.params?.workspaceId || req.body?.workspace_id || req.body?.workspaceId || req.query?.workspace_id;
    if (rawWs) derivedWorkspaceId = Number(rawWs);
  }

  // Fallback for notifications
  if (!derivedWorkspaceId && routePath.includes('/notifications') && req.user?.id) {
    const wmRes = await db.query(
      'SELECT workspace_id FROM workspace_members WHERE user_id = ? ORDER BY workspace_id ASC LIMIT 1',
      [req.user.id]
    );
    if (wmRes[0]?.workspace_id) {
      derivedWorkspaceId = wmRes[0].workspace_id;
    }
  }

  if (!derivedWorkspaceId) {
    return null;
  }

  // 4. STRICT CONSISTENCY VALIDATION:
  // Any client-supplied board_id or workspace_id in params, query, or body MUST agree with derived values.
  const clientWs = req.params?.workspaceId || req.body?.workspace_id || req.body?.workspaceId || req.query?.workspace_id;
  if (clientWs && Number(clientWs) !== Number(derivedWorkspaceId)) {
    const err = new Error(`Workspace mismatch: resource belongs to workspace ${derivedWorkspaceId}, but request supplied ${clientWs}`);
    err.status = 400;
    err.code = 'WORKSPACE_MISMATCH';
    throw err;
  }

  const clientBoard = req.params?.boardId || req.body?.board_id || req.body?.boardId || req.query?.board_id;
  if (clientBoard && derivedProjectId && Number(clientBoard) !== Number(derivedProjectId)) {
    const err = new Error(`Board mismatch: resource belongs to board ${derivedProjectId}, but request supplied ${clientBoard}`);
    err.status = 400;
    err.code = 'BOARD_MISMATCH';
    throw err;
  }

  // 5. Visibility check: Actor must belong to the resource's workspace
  if (req.user?.id) {
    const memRows = await db.query(
      'SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1',
      [derivedWorkspaceId, req.user.id]
    );
    if (memRows.length === 0) {
      const err = new Error('Resource not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }
  }

  req.projectId = derivedProjectId;
  req.workspaceId = derivedWorkspaceId;
  return req.workspaceId;
}

/**
 * Evaluates whether a user has a specific permission in a workspace (and optional board/project context).
 * Purely permission and rank based, zero role-name branching.
 * Cached once per request when req context is available.
 */
async function userHasPermission(userId, workspaceId, permissionKey, dbInstance = null, projectId = null, req = null) {
  if (!userId || !workspaceId) return false;
  const db = getActiveDb(dbInstance || req);

  // Per-request cache
  if (req) {
    if (!req._rbacPermCache) req._rbacPermCache = new Map();
    const cacheKey = `${userId}:${workspaceId}:${projectId || 'null'}:${permissionKey}`;
    if (req._rbacPermCache.has(cacheKey)) {
      return req._rbacPermCache.get(cacheKey);
    }
  }

  // 1. Fetch workspace role and permissions (with per-request caching)
  let wsRole = null;
  if (req && req._rbacWsRoleCache && req._rbacWsRoleCache.has(`${userId}:${workspaceId}`)) {
    wsRole = req._rbacWsRoleCache.get(`${userId}:${workspaceId}`);
  } else {
    const wsRows = await db.query(
      `SELECT wm.role_id, r.name as role_name, r.rank, r.is_system, p.key as permission_key
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, userId]
    );

    if (wsRows.length > 0) {
      const perms = new Set(wsRows.map((r) => r.permission_key).filter(Boolean));
      wsRole = {
        id: wsRows[0].role_id,
        name: wsRows[0].role_name,
        rank: Number(wsRows[0].rank || 30),
        is_system: wsRows[0].is_system,
        permissions: perms
      };
    }

    if (req) {
      if (!req._rbacWsRoleCache) req._rbacWsRoleCache = new Map();
      req._rbacWsRoleCache.set(`${userId}:${workspaceId}`, wsRole);
    }
  }

  if (!wsRole) {
    if (req && req._rbacPermCache) req._rbacPermCache.set(`${userId}:${workspaceId}:${projectId || 'null'}:${permissionKey}`, false);
    return false;
  }

  // 2. Fetch board membership and board role (if board/project context provided)
  let boardMembership = undefined;
  let boardRole = null;

  if (projectId) {
    const bRows = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [projectId]);
    if (bRows.length === 0 || Number(bRows[0].workspace_id) !== Number(workspaceId)) {
      if (req && req._rbacPermCache) req._rbacPermCache.set(`${userId}:${workspaceId}:${projectId}:${permissionKey}`, false);
      return false;
    }

    let boardData = null;
    if (req && req._rbacBoardCache && req._rbacBoardCache.has(`${userId}:${projectId}`)) {
      boardData = req._rbacBoardCache.get(`${userId}:${projectId}`);
    } else {
      const bmRows = await db.query(
        `SELECT bm.role_id, r.name as role_name, r.rank, r.is_system, p.key as permission_key
         FROM board_members bm
         LEFT JOIN roles r ON bm.role_id = r.id
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE bm.board_id = ? AND bm.user_id = ?`,
        [projectId, userId]
      );

      if (bmRows.length > 0) {
        let bRole = null;
        if (bmRows[0].role_id) {
          bRole = {
            id: bmRows[0].role_id,
            name: bmRows[0].role_name,
            rank: Number(bmRows[0].rank || 30),
            is_system: bmRows[0].is_system,
            permissions: new Set(bmRows.map((r) => r.permission_key).filter(Boolean))
          };
        }
        boardData = { isMember: true, boardRole: bRole };
      } else {
        boardData = { isMember: false, boardRole: null };
      }

      if (req) {
        if (!req._rbacBoardCache) req._rbacBoardCache = new Map();
        req._rbacBoardCache.set(`${userId}:${projectId}`, boardData);
      }
    }

    boardMembership = boardData.isMember;
    boardRole = boardData.boardRole;
  }

  // 3. Pure evaluation (including alias expansion)
  const expandedKeys = expandPermissionKeys(permissionKey);
  let allowed = false;

  for (const k of expandedKeys) {
    const result = evaluatePermission({
      key: k,
      keyScope: getPermissionScope(k),
      workspaceRole: wsRole,
      boardMembership,
      boardRole
    });

    if (result.allowed) {
      allowed = true;
      break;
    }
  }

  if (req && req._rbacPermCache) {
    req._rbacPermCache.set(`${userId}:${workspaceId}:${projectId || 'null'}:${permissionKey}`, allowed);
  }

  return allowed;
}

/**
 * Bulk resolves which candidate users hold a specific permission.
 * Guaranteed identical result to userHasPermission for every candidate via evaluatePermission.
 */
async function usersWithPermission(dbInstance, workspaceId, boardId, permissionKey, candidateIds = []) {
  if (!candidateIds || !Array.isArray(candidateIds) || candidateIds.length === 0) {
    return [];
  }
  const cleanIds = Array.from(new Set(candidateIds.map(Number).filter((id) => !isNaN(id) && id > 0)));
  if (cleanIds.length === 0) return [];

  const db = getActiveDb(dbInstance);

  // 1. Fetch workspace role and permissions for all candidate users in 1 query
  const wsRows = await db.query(
    `SELECT wm.user_id, wm.role_id, r.name as role_name, r.rank, r.is_system, p.key as permission_key
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
        id: row.role_id,
        name: row.role_name,
        rank: Number(row.rank || 30),
        is_system: row.is_system,
        permissions: new Set()
      });
    }
    if (row.permission_key) {
      wsUserMap.get(row.user_id).permissions.add(row.permission_key);
    }
  }

  // 2. Fetch board membership and board role in 1 query (if boardId provided)
  const bmUserMap = new Map();
  if (boardId) {
    const bRows = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [boardId]);
    if (bRows.length === 0 || Number(bRows[0].workspace_id) !== Number(workspaceId)) {
      return [];
    }

    const bmRows = await db.query(
      `SELECT bm.user_id, bm.role_id, r.name as role_name, r.rank, r.is_system, p.key as permission_key
       FROM board_members bm
       LEFT JOIN roles r ON bm.role_id = r.id
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE bm.board_id = ? AND bm.user_id IN (?)`,
      [boardId, cleanIds]
    );

    for (const row of bmRows) {
      if (!bmUserMap.has(row.user_id)) {
        let bRole = null;
        if (row.role_id) {
          bRole = {
            id: row.role_id,
            name: row.role_name,
            rank: Number(row.rank || 30),
            is_system: row.is_system,
            permissions: new Set()
          };
        }
        bmUserMap.set(row.user_id, { isMember: true, boardRole: bRole });
      }
      if (row.permission_key && bmUserMap.get(row.user_id).boardRole) {
        bmUserMap.get(row.user_id).boardRole.permissions.add(row.permission_key);
      }
    }
  }

  const authorizedUserIds = [];
  const expandedKeys = expandPermissionKeys(permissionKey);

  for (const userId of cleanIds) {
    const wsRole = wsUserMap.get(userId);
    if (!wsRole) continue;

    const bmData = bmUserMap.get(userId);
    const boardMembership = boardId ? Boolean(bmData?.isMember) : undefined;
    const boardRole = bmData?.boardRole || null;

    let authorized = false;
    for (const k of expandedKeys) {
      const result = evaluatePermission({
        key: k,
        keyScope: getPermissionScope(k),
        workspaceRole: wsRole,
        boardMembership,
        boardRole
      });

      if (result.allowed) {
        authorized = true;
        break;
      }
    }

    if (authorized) {
      authorizedUserIds.push(userId);
    }
  }

  return authorizedUserIds;
}

/**
 * Gets effective permissions and role for a user in a workspace (and optional board/project context).
 * Removes all legacy implicit grants: permissions come from roles only.
 */
async function getUserPermissions(userId, workspaceId, dbInstance = null, projectId = null) {
  if (!userId || !workspaceId) return { role: null, permissions: [] };
  const db = getActiveDb(dbInstance);

  const wsRows = await db.query(
    `SELECT r.id as role_id, r.name as role_name, r.rank, r.is_system, r.is_editable, p.key as permission_key
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
    rank: Number(wsRows[0].rank || 30),
    is_system: wsRows[0].is_system,
    is_editable: wsRows[0].is_editable
  };

  const wsPerms = new Set(wsRows.map((r) => r.permission_key).filter(Boolean));
  const effectivePerms = new Set();

  // Company-scope permissions are always active
  for (const permKey of wsPerms) {
    if (getPermissionScope(permKey) === 'company') {
      effectivePerms.add(permKey);
    }
  }

  if (projectId) {
    const bRows = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [projectId]);
    if (bRows.length === 0 || Number(bRows[0].workspace_id) !== Number(workspaceId)) {
      return { role: null, permissions: [] };
    }

    const hasAccessAll = wsPerms.has('project.access_all');

    if (hasAccessAll) {
      // With project.access_all, all workspace project-scope keys apply
      for (const permKey of wsPerms) {
        if (getPermissionScope(permKey) === 'project') {
          effectivePerms.add(permKey);
        }
      }
    } else {
      // Check board membership
      const bmRows = await db.query(
        `SELECT bm.role_id, r.name as role_name, r.rank, p.key as permission_key
         FROM board_members bm
         LEFT JOIN roles r ON bm.role_id = r.id
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE bm.board_id = ? AND bm.user_id = ?`,
        [projectId, userId]
      );

      if (bmRows.length > 0) {
        // User is board member: workspace project-scope keys apply
        for (const permKey of wsPerms) {
          if (getPermissionScope(permKey) === 'project') {
            effectivePerms.add(permKey);
          }
        }

        // Board role keys within cap
        if (bmRows[0].role_id) {
          const wsRank = Number(role.rank || 0);
          const bRank = Number(bmRows[0].rank || 0);
          const isAboveCap = bRank > 60 || (wsRank <= 10 && bRank > 40);

          if (!isAboveCap) {
            bmRows.forEach((r) => {
              if (r.permission_key && getPermissionScope(r.permission_key) === 'project') {
                effectivePerms.add(r.permission_key);
              }
            });
          }
        }
      }
    }
  } else {
    // General workspace context: all workspace permissions apply
    for (const permKey of wsPerms) {
      effectivePerms.add(permKey);
    }
  }

  return {
    role,
    permissions: Array.from(effectivePerms)
  };
}

/**
 * Returns all board IDs in a workspace that the user can access with the specified permission.
 * Uses evaluatePermission pure logic (no board leaking).
 */
async function accessibleBoardIds(userId, workspaceId, key = 'project.view', dbInstance = null) {
  if (!userId || !workspaceId) return [];
  const db = getActiveDb(dbInstance);

  const wsRows = await db.query(
    `SELECT wm.role_id, r.name as role_name, r.rank, p.key as permission_key
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     LEFT JOIN role_permissions rp ON r.id = rp.role_id
     LEFT JOIN permissions p ON rp.permission_id = p.id
     WHERE wm.workspace_id = ? AND wm.user_id = ?`,
    [workspaceId, userId]
  );

  if (wsRows.length === 0) return [];

  const wsPerms = new Set(wsRows.map((r) => r.permission_key).filter(Boolean));
  const wsRole = {
    id: wsRows[0].role_id,
    rank: Number(wsRows[0].rank || 30),
    permissions: wsPerms
  };

  // If user has project.access_all and holds the key, all non-archived boards in workspace are accessible
  if (wsPerms.has('project.access_all')) {
    const evalResult = evaluatePermission({
      key,
      keyScope: 'project',
      workspaceRole: wsRole,
      boardMembership: true
    });

    if (evalResult.allowed) {
      const allBoards = await db.query(
        'SELECT id FROM boards WHERE workspace_id = ? AND is_archived = 0',
        [workspaceId]
      );
      return allBoards.map((b) => b.id);
    }
    return [];
  }

  // Otherwise, only boards where user is a member are candidates
  const memberBoards = await db.query(
    `SELECT bm.board_id, bm.role_id, r.rank as board_role_rank,
            GROUP_CONCAT(p.key) as board_perm_keys
     FROM board_members bm
     JOIN boards b ON bm.board_id = b.id
     LEFT JOIN roles r ON bm.role_id = r.id
     LEFT JOIN role_permissions rp ON r.id = rp.role_id
     LEFT JOIN permissions p ON rp.permission_id = p.id
     WHERE b.workspace_id = ? AND bm.user_id = ? AND b.is_archived = 0
     GROUP BY bm.board_id, bm.role_id, r.rank`,
    [workspaceId, userId]
  );

  const accessibleIds = [];
  for (const bRow of memberBoards) {
    let boardRole = null;
    if (bRow.role_id) {
      boardRole = {
        id: bRow.role_id,
        rank: Number(bRow.board_role_rank || 30),
        permissions: new Set((bRow.board_perm_keys || '').split(',').filter(Boolean))
      };
    }

    const evalResult = evaluatePermission({
      key,
      keyScope: 'project',
      workspaceRole: wsRole,
      boardMembership: true,
      boardRole
    });

    if (evalResult.allowed) {
      accessibleIds.push(bRow.board_id);
    }
  }

  return accessibleIds;
}

/**
 * Middleware factory requiring a specific permission key (or { any: [...] }, { all: [...] }).
 */
function requirePermission(permissionConfig, options = {}) {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({ error: { message: 'Unauthorized', code: 'UNAUTHORIZED' } });
      }

      let workspaceId;
      try {
        workspaceId = await resolveWorkspaceId(req);
      } catch (err) {
        if (err.code === 'WORKSPACE_MISMATCH' || err.code === 'BOARD_MISMATCH') {
          return res.status(400).json({ error: { message: err.message, code: err.code } });
        }
        if (err.status === 404 || err.code === 'NOT_FOUND') {
          return res.status(404).json({ error: { message: err.message || 'Resource not found', code: 'NOT_FOUND' } });
        }
        throw err;
      }

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

      // Section 5.5: If resource is project-scoped, actor MUST be able to view the project;
      // if not, return 404 (not 403) so project existence is not leaked to unauthorized users.
      if (req.projectId) {
        const canViewProject = await userHasPermission(req.user.id, workspaceId, 'project.view', req.db, req.projectId, req);
        if (!canViewProject) {
          return res.status(404).json({
            error: {
              message: 'Resource not found',
              code: 'NOT_FOUND'
            }
          });
        }
      }

      // Handle ownership callback (Section 5.1 & 5.2)
      let activeConfig = permissionConfig;
      const opts = (typeof permissionConfig === 'object' && permissionConfig !== null) ? permissionConfig : (options || {});
      const ownershipFn = typeof opts.ownership === 'function' ? opts.ownership : null;

      if (ownershipFn) {
        let isOwner = false;
        try {
          isOwner = Boolean(await ownershipFn(req));
        } catch (e) {
          isOwner = false;
        }

        if (isOwner) {
          activeConfig = typeof opts.own === 'function' ? opts.own(req) : (opts.own || opts.any || permissionConfig);
        } else {
          activeConfig = typeof opts.any === 'function' ? opts.any(req) : (opts.any || opts.own || permissionConfig);
        }
      }

      // Handle config formats: string, array (any), { any: [...] }, { all: [...] }
      let hasPerm = false;
      if (typeof activeConfig === 'object' && !Array.isArray(activeConfig)) {
        if (Array.isArray(activeConfig.all)) {
          let allSatisfied = true;
          for (const k of activeConfig.all) {
            let ok = false;
            if (typeof k === 'object' && k !== null && Array.isArray(k.any)) {
              for (const subK of k.any) {
                if (await userHasPermission(req.user.id, workspaceId, subK, req.db, req.projectId || null, req)) {
                  ok = true;
                  break;
                }
              }
            } else {
              ok = await userHasPermission(req.user.id, workspaceId, k, req.db, req.projectId || null, req);
            }
            if (!ok) { allSatisfied = false; break; }
          }
          hasPerm = allSatisfied;
        } else if (Array.isArray(activeConfig.any)) {
          for (const k of activeConfig.any) {
            if (await userHasPermission(req.user.id, workspaceId, k, req.db, req.projectId || null, req)) {
              hasPerm = true;
              break;
            }
          }
        }
      } else {
        const keys = Array.isArray(activeConfig) ? activeConfig : [activeConfig];
        for (const k of keys) {
          if (await userHasPermission(req.user.id, workspaceId, k, req.db, req.projectId || null, req)) {
            hasPerm = true;
            break;
          }
        }
      }

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
 * Middleware factory for routes whose required key depends on which fields are sent in the body (Section 5.1).
 * Accepts an async resolver function (req) => permissionConfig or mapping object.
 */
function requirePermissionForBody(resolver) {
  return async (req, res, next) => {
    try {
      let config = null;
      if (typeof resolver === 'function') {
        config = await resolver(req);
      } else if (typeof resolver === 'object' && resolver !== null) {
        config = resolver;
      }
      if (!config) {
        return next();
      }
      return requirePermission(config)(req, res, next);
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Counts Owners in a workspace for safety checks (last Owner rule)
 * Uses isOwnerRole from roleRank helper (enforces is_system and rank >= 100 or normalized name).
 */
async function countOwners(workspaceId, dbInstance = null) {
  const db = getActiveDb(dbInstance);
  const rows = await db.query(
    `SELECT wm.user_id, r.id as role_id, r.name, r.is_system, r.is_editable, r.rank
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     WHERE wm.workspace_id = ?`,
    [workspaceId]
  );
  return rows.filter((m) => isOwnerRole({ name: m.name, is_system: m.is_system, rank: m.rank })).length;
}

module.exports = {
  getActiveDb,
  resolveWorkspaceId,
  userHasPermission,
  usersWithPermission,
  getUserPermissions,
  accessibleBoardIds,
  requirePermission,
  requirePermissionForBody,
  countOwners,
  countSuperAdmins: countOwners
};
