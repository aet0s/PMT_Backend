// server/src/utils/roleRank.js
// Hierarchy, rank, and authority rules for role-based administrative actions.

const RESERVED_ROLE_NAMES = new Set([
  'owner',
  'super admin',
  'admin',
  'project manager',
  'manager',
  'team member',
  'member',
  'viewer',
  'guest'
]);

const ROLE_RANKS = {
  'owner': 100,
  'super admin': 100,
  'admin': 80,
  'project manager': 60,
  'manager': 60,
  'team member': 40,
  'member': 40,
  'viewer': 20,
  'guest': 10
};

/**
 * Normalizes role name strings against unicode spoofing, zero-width spaces, casing, and whitespace.
 */
function normalizeRoleName(name) {
  if (!name || typeof name !== 'string') return '';
  return name
    .normalize('NFKC')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

/**
 * Checks whether a role name is reserved for built-in system roles.
 */
function isReservedRoleName(name) {
  const normalized = normalizeRoleName(name);
  return RESERVED_ROLE_NAMES.has(normalized);
}

/**
 * Resolves numeric rank. For role objects, trusts rank only if is_system === 1.
 * Custom roles default to 30.
 */
function getRoleRank(roleOrName) {
  if (!roleOrName) return 0;
  if (typeof roleOrName === 'object') {
    if (Boolean(roleOrName.is_system)) {
      if (typeof roleOrName.rank === 'number' && !isNaN(roleOrName.rank)) return roleOrName.rank;
      const normalized = normalizeRoleName(roleOrName.name);
      return ROLE_RANKS[normalized] || 30;
    }
    // Custom role: rank can be configured in database (< 80 to prevent escalation above Admin)
    if (typeof roleOrName.rank === 'number' && !isNaN(roleOrName.rank) && roleOrName.rank < 80) {
      return roleOrName.rank;
    }
    return 30;
  }
  const normalized = normalizeRoleName(roleOrName);
  return ROLE_RANKS[normalized] !== undefined ? ROLE_RANKS[normalized] : 30;
}

/**
 * Checks if a role is an Owner role.
 * If a role object is passed, enforces Boolean(is_system) so custom roles named "Owner" are rejected.
 */
function isOwnerRole(roleOrName) {
  if (!roleOrName) return false;
  if (typeof roleOrName === 'object') {
    if (!roleOrName.is_system) return false;
    const rank = getRoleRank(roleOrName);
    if (rank >= 100) return true;
    const normalized = normalizeRoleName(roleOrName.name);
    return normalized === 'owner' || normalized === 'super admin';
  }
  const normalized = normalizeRoleName(roleOrName);
  return normalized === 'owner' || normalized === 'super admin';
}

/**
 * Validates authority to reset password or 2FA for a target user:
 * 1. Never on yourself.
 * 2. Only an Owner may reset an Owner.
 * 3. Otherwise, target's role rank must be strictly below caller's role rank.
 */
function canResetTarget(callerRole, targetRole, callerUserId, targetUserId) {
  if (Number(callerUserId) === Number(targetUserId)) {
    return {
      allowed: false,
      code: 'SELF_RESET_FORBIDDEN',
      message: 'You cannot perform an administrative reset on yourself.'
    };
  }

  const callerRank = getRoleRank(callerRole);
  const targetRank = getRoleRank(targetRole);

  const callerIsOwner = isOwnerRole(callerRole);
  const targetIsOwner = isOwnerRole(targetRole);

  if (targetIsOwner) {
    if (callerIsOwner) {
      return { allowed: true };
    }
    return {
      allowed: false,
      code: 'ONLY_OWNER_MAY_RESET_OWNER',
      message: 'Only an Owner may reset another Owner.'
    };
  }

  if (callerRank > targetRank) {
    return { allowed: true };
  }

  return {
    allowed: false,
    code: 'INSUFFICIENT_ROLE_RANK',
    message: 'You may only reset credentials for members whose role rank is below yours.'
  };
}

module.exports = {
  RESERVED_ROLE_NAMES,
  ROLE_RANKS,
  normalizeRoleName,
  isReservedRoleName,
  getRoleRank,
  isOwnerRole,
  canResetTarget
};
