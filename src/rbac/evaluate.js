// server/src/rbac/evaluate.js
// Single pure evaluation engine for Role-Based Access Control (RBAC).
// Pure function: no DB queries, no side effects, no role-name branching.

const { PERMISSIONS } = require('./registry');

// Build fast lookup map for permission metadata
const PERMISSION_META = new Map();
for (const p of PERMISSIONS) {
  PERMISSION_META.set(p.key, {
    scope: p.scope || 'project',
    dangerous: Boolean(p.dangerous),
    planned: Boolean(p.planned),
    module: p.module
  });
}

/**
 * Returns the scope ('company' | 'project') for a given permission key.
 * The scope comes ONLY from the registry's scope field (never from key prefixes).
 */
function getPermissionScope(key) {
  const meta = PERMISSION_META.get(key);
  return meta ? meta.scope : 'project';
}

/**
 * Pure evaluation function.
 *
 * @param {Object} params
 * @param {string} params.key - The permission key being requested (e.g. 'task.edit')
 * @param {string} [params.keyScope] - Optional scope override ('company' | 'project'); defaults to registry scope
 * @param {Object|null} params.workspaceRole - Workspace membership role: { id, rank, permissions: Set|Array }
 * @param {boolean|Object|null} params.boardMembership - Truthy if user is a member of the board (or null/false)
 * @param {Object|null} [params.boardRole] - Optional board-level role: { id, rank, permissions: Set|Array }
 * @returns {{ allowed: boolean, reason: string }}
 */
function evaluatePermission({
  key,
  keyScope,
  workspaceRole,
  boardMembership,
  boardRole
}) {
  // 1. Deny by default: A user who is not a workspace member has nothing.
  if (!workspaceRole || !workspaceRole.permissions) {
    return { allowed: false, reason: 'DENY_NOT_WORKSPACE_MEMBER' };
  }

  const wsPerms = workspaceRole.permissions instanceof Set
    ? workspaceRole.permissions
    : new Set(workspaceRole.permissions || []);

  const effectiveScope = keyScope || getPermissionScope(key);

  // 2. Company-scope keys: granted ONLY by the workspace role's permission set.
  // Board context is completely irrelevant; board roles can never grant company-scope keys.
  if (effectiveScope === 'company') {
    if (wsPerms.has(key)) {
      return { allowed: true, reason: 'ALLOW_COMPANY_SCOPE' };
    }
    return { allowed: false, reason: 'DENY_COMPANY_SCOPE' };
  }

  // 3. Project-scope keys:
  // Case A: No specific board context evaluated (e.g. general workspace-level check)
  if (boardMembership === undefined) {
    if (wsPerms.has(key)) {
      return { allowed: true, reason: 'ALLOW_WORKSPACE_PROJECT_KEY' };
    }
    return { allowed: false, reason: 'DENY_WORKSPACE_PROJECT_KEY' };
  }

  // Case B: Specific board context evaluated
  // Check project.access_all: if workspace role holds project.access_all,
  // permissions apply on all boards in the workspace without requiring board membership.
  const hasAccessAll = wsPerms.has('project.access_all');
  if (hasAccessAll) {
    if (wsPerms.has(key)) {
      return { allowed: true, reason: 'ALLOW_PROJECT_ACCESS_ALL' };
    }
    return { allowed: false, reason: 'DENY_PROJECT_ACCESS_ALL_LACKS_KEY' };
  }

  // Otherwise, board membership is mandatory.
  const isBoardMember = Boolean(boardMembership);
  if (!isBoardMember) {
    return { allowed: false, reason: 'DENY_NOT_BOARD_MEMBER' };
  }

  // User is a board member. Effective permissions:
  // (workspace role permissions ∩ project-scope keys) ∪ (effective board role permissions)
  if (wsPerms.has(key)) {
    return { allowed: true, reason: 'ALLOW_BOARD_MEMBER_WORKSPACE_ROLE' };
  }

  // Check board role permissions (if a board role is assigned)
  if (boardRole && boardRole.permissions) {
    const wsRank = Number(workspaceRole.rank || 0);
    const bRank = Number(boardRole.rank || 0);

    // Rule 4: Board role caps:
    // - A board role can raise rights on that board only up to rank 60 (Project Manager).
    // - A user whose workspace role is Guest (rank <= 10) can be given at most rank 40 (Team Member).
    // Ignore board role if it exceeds the cap.
    const isAboveAbsoluteCap = bRank > 60;
    const isAboveGuestCap = wsRank <= 10 && bRank > 40;

    if (!isAboveAbsoluteCap && !isAboveGuestCap) {
      const bPerms = boardRole.permissions instanceof Set
        ? boardRole.permissions
        : new Set(boardRole.permissions || []);

      // Board roles can NEVER grant company-scope permissions (enforced by checking effectiveScope)
      if (effectiveScope === 'project' && bPerms.has(key)) {
        return { allowed: true, reason: 'ALLOW_BOARD_ROLE' };
      }
    }
  }

  return { allowed: false, reason: 'DENY_PROJECT_PERMISSION_NOT_HELD' };
}

/**
 * Convenience helper returning strict boolean.
 */
function isPermissionAllowed(params) {
  return evaluatePermission(params).allowed;
}

module.exports = {
  evaluatePermission,
  isPermissionAllowed,
  getPermissionScope,
  PERMISSION_META
};
