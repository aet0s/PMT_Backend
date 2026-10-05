// server/src/rbac/routeRegistry.js
// Authoritative route permission manifest and declaration registry.

const ROUTE_MANIFEST = [
  // --- Auth & Onboarding (Public / Self) ---
  { method: 'POST', path: '/api/auth/register-company', publicReason: 'Company registration and tenant creation', scope: 'company' },
  { method: 'POST', path: '/api/auth/verify-registration', publicReason: 'Registration OTP verification', scope: 'company' },
  { method: 'POST', path: '/api/auth/register', publicReason: 'Direct user registration alias', scope: 'company' },
  { method: 'POST', path: '/api/auth/login', publicReason: 'User login step 1', scope: 'company' },
  { method: 'POST', path: '/api/auth/2fa/verify-login', publicReason: 'User login step 2 TOTP or recovery code verification', scope: 'company' },
  { method: 'POST', path: '/api/auth/refresh', publicReason: 'Token refresh using rotating refresh token cookie', scope: 'company' },
  { method: 'GET', path: '/api/auth/sessions', permission: 'session.view_own', scope: 'company' },
  { method: 'DELETE', path: '/api/auth/sessions/:id', permission: 'session.revoke_own', scope: 'company' },
  { method: 'POST', path: '/api/auth/sessions/revoke-others', permission: 'session.revoke_own', scope: 'company' },
  { method: 'POST', path: '/api/auth/logout', permission: 'session.revoke_own', scope: 'company' },
  { method: 'POST', path: '/api/auth/logout-all', permission: 'session.revoke_own', scope: 'company' },
  { method: 'POST', path: '/api/auth/2fa/generate', publicReason: 'Self 2FA secret generation', scope: 'company' },
  { method: 'POST', path: '/api/auth/2fa/setup', publicReason: 'Self 2FA secret generation alias', scope: 'company' },
  { method: 'POST', path: '/api/auth/2fa/confirm', publicReason: 'Self 2FA confirmation', scope: 'company' },
  { method: 'POST', path: '/api/auth/2fa/disable', publicReason: 'Self 2FA disable', scope: 'company' },
  { method: 'GET', path: '/api/auth/2fa/status', publicReason: 'Self 2FA status lookup', scope: 'company' },
  { method: 'GET', path: '/api/auth/me', publicReason: 'Authenticated user profile self-check', scope: 'company' },
  { method: 'PUT', path: '/api/auth/profile', publicReason: 'Self profile update', scope: 'company' },
  { method: 'PUT', path: '/api/auth/password', publicReason: 'Self password change', scope: 'company' },
  { method: 'POST', path: '/api/auth/password', publicReason: 'Self password change alias', scope: 'company' },
  { method: 'POST', path: '/api/auth/change-password', publicReason: 'Self password change alias', scope: 'company' },

  // --- Workspaces & Members ---
  { method: 'GET', path: '/api/workspaces', permission: 'workspace.view', scope: 'company' },
  { method: 'POST', path: '/api/workspaces', permission: 'workspace.create', scope: 'company' },
  { method: 'PATCH', path: '/api/workspaces/:id', permission: 'workspace.edit', scope: 'company' },
  { method: 'DELETE', path: '/api/workspaces/:id', permission: 'workspace.delete', scope: 'company' },
  { method: 'GET', path: '/api/workspaces/:id/my-permissions', publicReason: 'Authenticated user effective permission check for workspace', scope: 'project' },
  { method: 'GET', path: '/api/workspaces/:id/roles', permission: 'role.view', scope: 'company' },
  { method: 'POST', path: '/api/workspaces/:id/roles', permission: 'role.create', scope: 'company' },
  { method: 'GET', path: '/api/workspaces/:id/members', permission: 'member.view', scope: 'company' },
  { method: 'PATCH', path: '/api/workspaces/:id/members/:userId/role', permission: 'member.assign_role', scope: 'company' },
  { method: 'DELETE', path: '/api/workspaces/:id/members/:userId', permission: 'member.remove', scope: 'company' },
  { method: 'POST', path: '/api/workspaces/:workspaceId/members/:userId/reset-password', permission: 'member.reset_password', scope: 'company' },
  { method: 'POST', path: '/api/workspaces/:workspaceId/members/:userId/reset-2fa', permission: 'member.reset_2fa', scope: 'company' },

  // --- Roles ---
  { method: 'PATCH', path: '/api/roles/:id', permission: 'role.edit', scope: 'company' },
  { method: 'DELETE', path: '/api/roles/:id', permission: 'role.delete', scope: 'company' },

  // --- Boards (Projects) ---
  { method: 'GET', path: '/api/boards', permission: 'project.view', scope: 'company' },
  { method: 'POST', path: '/api/boards', permission: 'project.create', scope: 'company' },
  { method: 'GET', path: '/api/boards/:id', permission: 'project.view', scope: 'project' },
  { method: 'PATCH', path: '/api/boards/:id', permission: 'project.edit_settings', scope: 'project' },
  { method: 'DELETE', path: '/api/boards/:id', permission: 'project.delete', scope: 'project' },
  { method: 'GET', path: '/api/boards/:id/workspace-members', permission: 'member.view', scope: 'project' },
  { method: 'POST', path: '/api/boards/:id/members', permission: 'project.manage_members', scope: 'project' },
  { method: 'DELETE', path: '/api/boards/:id/members/:userId', permission: 'project.manage_members', scope: 'project' },
  { method: 'GET', path: '/api/boards/:id/labels', permission: 'label.view', scope: 'project' },
  { method: 'POST', path: '/api/boards/:id/labels', permission: 'label.create', scope: 'project' },

  // --- Lists ---
  { method: 'POST', path: '/api/lists', permission: 'list.create', scope: 'project' },
  { method: 'PATCH', path: '/api/lists/:id', permission: 'list.edit', scope: 'project' },
  { method: 'DELETE', path: '/api/lists/:id', permission: 'list.delete', scope: 'project' },

  // --- Cards (Tasks) ---
  { method: 'GET', path: '/api/cards/:id', permission: 'task.view', scope: 'project' },
  { method: 'POST', path: '/api/cards', permission: 'task.create', scope: 'project' },
  { method: 'PATCH', path: '/api/cards/:id', permission: 'task.edit', scope: 'project' },
  { method: 'DELETE', path: '/api/cards/:id', permission: 'task.delete', scope: 'project' },

  // --- Card Labels & Members ---
  { method: 'POST', path: '/api/cards/:id/labels', permission: 'label.create', scope: 'project' },
  { method: 'POST', path: '/api/cards/:id/members', permission: 'task.assign', scope: 'project' },

  // --- Card Attachments & Comments ---
  { method: 'POST', path: '/api/cards/:id/attachments', permission: 'attachment.upload', scope: 'project' },
  { method: 'POST', path: '/api/cards/:id/attachments/file', permission: 'attachment.upload', scope: 'project' },
  { method: 'POST', path: '/api/cards/:id/attachments/link', permission: 'attachment.upload', scope: 'project' },
  { method: 'DELETE', path: '/api/cards/attachments/:id', permission: 'attachment.delete_own', scope: 'project' },
  { method: 'POST', path: '/api/cards/:id/comments', permission: 'comment.create', scope: 'project' },
  { method: 'DELETE', path: '/api/cards/comments/:id', permission: 'comment.delete_own', scope: 'project' },

  // --- Checklists ---
  { method: 'POST', path: '/api/cards/:id/checklists', permission: 'checklist.create', scope: 'project' },
  { method: 'DELETE', path: '/api/cards/checklists/:id', permission: 'checklist.delete', scope: 'project' },
  { method: 'POST', path: '/api/cards/checklist-items', permission: 'checklist.create', scope: 'project' },
  { method: 'PATCH', path: '/api/cards/checklist-items/:id', permission: 'checklist.edit', scope: 'project' },
  { method: 'DELETE', path: '/api/cards/checklist-items/:id', permission: 'checklist.delete', scope: 'project' },

  // --- Archive ---
  { method: 'GET', path: '/api/archive', permission: 'archive.view', scope: 'company' },

  // --- Invitations ---
  { method: 'GET', path: '/api/invitations/verify', publicReason: 'Public verification of signed invite link', scope: 'company' },
  { method: 'GET', path: '/api/invitations', permission: 'member.invite', scope: 'company' },
  { method: 'POST', path: '/api/invitations', permission: 'member.invite', scope: 'company' },
  { method: 'POST', path: '/api/invitations/accept', publicReason: 'Accept invitation and join workspace', scope: 'company' },
  { method: 'DELETE', path: '/api/invitations/:id', permission: 'member.invite', scope: 'company' },

  // --- Notifications ---
  { method: 'GET', path: '/api/notifications', permission: 'notification.view_own', scope: 'company' },
  { method: 'GET', path: '/api/notifications/unread-count', permission: 'notification.view_own', scope: 'company' },
  { method: 'GET', path: '/api/notifications/preferences', permission: 'notification.manage_own', scope: 'company' },
  { method: 'PATCH', path: '/api/notifications/preferences', permission: 'notification.manage_own', scope: 'company' },
  { method: 'PATCH', path: '/api/notifications/:id/read', permission: 'notification.manage_own', scope: 'company' },
  { method: 'PATCH', path: '/api/notifications/:id/unread', permission: 'notification.manage_own', scope: 'company' },
  { method: 'PATCH', path: '/api/notifications/read-all', permission: 'notification.manage_own', scope: 'company' },
  { method: 'DELETE', path: '/api/notifications/:id', permission: 'notification.manage_own', scope: 'company' },
  { method: 'DELETE', path: '/api/notifications/clear/read', permission: 'notification.manage_own', scope: 'company' },

  // --- Permissions Catalog & Self Evaluation ---
  { method: 'GET', path: '/api/permissions', permission: 'role.view', scope: 'company' },
  { method: 'GET', path: '/api/permissions/me', publicReason: 'Authenticated user permission check for project/workspace', scope: 'project' },

  // --- Files & Avatars ---
  { method: 'POST', path: '/api/files/avatar', publicReason: 'Self avatar image upload', scope: 'company' },
  { method: 'GET', path: '/api/files/:tenantId/*', permission: 'file.view', scope: 'project' },

  // --- System Health ---
  { method: 'GET', path: '/api/health', publicReason: 'Public infrastructure health check', scope: 'company' },

  // --- Test / Dev Only Endpoints ---
  { method: 'POST', path: '/api/dev/reset-rate-limit', publicReason: 'Test environment rate limit reset helper', scope: 'company', testOnly: true }
];

const ROUTE_REGISTRY = new Map();

for (const entry of ROUTE_MANIFEST) {
  const key = `${entry.method.toUpperCase()} ${entry.path}`;
  ROUTE_REGISTRY.set(key, entry);
}

function getRouteDeclaration(method, path) {
  const key = `${method.toUpperCase()} ${path}`;
  return ROUTE_REGISTRY.get(key) || null;
}

module.exports = {
  ROUTE_MANIFEST,
  ROUTE_REGISTRY,
  getRouteDeclaration
};
