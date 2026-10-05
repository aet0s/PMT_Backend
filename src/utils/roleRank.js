// server/src/utils/roleRank.js
// Hierarchy and authority rules for role-based administrative actions (password & 2FA reset).

const ROLE_RANKS = {
  'owner': 100,
  'super admin': 100,
  'admin': 80,
  'manager': 60,
  'project manager': 60,
  'team member': 40,
  'member': 40,
  'viewer': 20,
  'guest': 10
};

function getRoleRank(roleName) {
  if (!roleName) return 0;
  const normalized = String(roleName).trim().toLowerCase();
  if (ROLE_RANKS[normalized] !== undefined) {
    return ROLE_RANKS[normalized];
  }
  // Default rank for custom roles: between member and manager (30)
  return 30;
}

function isOwnerRole(roleName) {
  const normalized = String(roleName || '').trim().toLowerCase();
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
    message: "You may only reset credentials for members whose role rank is below yours."
  };
}

module.exports = {
  ROLE_RANKS,
  getRoleRank,
  isOwnerRole,
  canResetTarget
};
