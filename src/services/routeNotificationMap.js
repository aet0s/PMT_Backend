// server/src/services/routeNotificationMap.js
// Single source of truth mapping mutating routes to declared notification events or explicit no-notify reasons.

const ROUTE_NOTIFICATION_MAP = {
  // --- Boards ---
  'POST /api/boards': {
    events: ['board.created'],
    description: 'Creates project board'
  },
  'PATCH /api/boards/:id': {
    events: ['board.renamed', 'board.background_changed'],
    description: 'Renames board or updates theme/background'
  },
  'DELETE /api/boards/:id': {
    events: ['board.deleted'],
    description: 'Deletes board and all lists/cards'
  },
  'POST /api/boards/:id/archive': {
    events: ['board.archived'],
    description: 'Archives board'
  },
  'POST /api/boards/:id/restore': {
    events: ['board.restored'],
    description: 'Restores archived board'
  },
  'POST /api/boards/:id/members': {
    events: ['board.member_added'],
    description: 'Adds member to board'
  },
  'DELETE /api/boards/:id/members/:userId': {
    events: ['board.member_removed'],
    description: 'Removes member from board'
  },
  'POST /api/boards/:id/labels': {
    events: ['board.label_created'],
    description: 'Creates colored label on board'
  },

  // --- Lists ---
  'POST /api/lists': {
    events: ['list.created'],
    description: 'Creates list column on board'
  },
  'PATCH /api/lists/:id': {
    events: ['list.renamed', 'list.moved', 'list.archived'],
    description: 'Renames, reorders, or archives list'
  },
  'DELETE /api/lists/:id': {
    events: ['list.deleted'],
    description: 'Deletes list column'
  },

  // --- Cards ---
  'POST /api/cards': {
    events: ['card.created'],
    description: 'Creates card in list'
  },
  'PATCH /api/cards/:id': {
    events: [
      'card.renamed',
      'card.description_changed',
      'card.due_date_set',
      'card.due_date_changed',
      'card.due_date_removed',
      'card.completed',
      'card.reopened',
      'card.moved',
      'card.cover_changed',
      'card.archived',
      'card.restored'
    ],
    description: 'Updates card attributes, status, dates, position'
  },
  'DELETE /api/cards/:id': {
    events: ['card.deleted'],
    description: 'Permanently deletes card'
  },
  'POST /api/cards/:id/copy': {
    events: ['card.copied'],
    description: 'Clones card with checklists and labels'
  },
  'POST /api/cards/:id/labels': {
    events: ['card.label_added', 'card.label_removed'],
    description: 'Attaches or detaches label on card'
  },
  'POST /api/cards/:id/members': {
    events: ['card.assigned', 'card.unassigned'],
    description: 'Assigns or unassigns member on card'
  },
  'POST /api/cards/:id/assigners': {
    events: ['card.assigned'],
    description: 'Assigns member on card'
  },

  // --- Comments ---
  'POST /api/cards/:id/comments': {
    events: ['comment.added', 'comment.mention'],
    description: 'Posts discussion comment and notifies members/mentions'
  },
  'DELETE /api/cards/comments/:id': {
    events: ['comment.deleted'],
    description: 'Deletes comment on card'
  },

  // --- Checklists & Items ---
  'POST /api/cards/:id/checklists': {
    events: ['checklist.created'],
    description: 'Creates checklist on card'
  },
  'DELETE /api/cards/checklists/:id': {
    events: ['checklist.deleted'],
    description: 'Deletes checklist from card'
  },
  'POST /api/cards/checklist-items': {
    events: ['checklist_item.added'],
    description: 'Adds item to checklist'
  },
  'PATCH /api/cards/checklist-items/:id': {
    events: [
      'checklist_item.completed',
      'checklist_item.reopened',
      'checklist_item.edited',
      'checklist.completed_all'
    ],
    description: 'Toggles item completion or edits text'
  },
  'DELETE /api/cards/checklist-items/:id': {
    events: ['checklist_item.deleted'],
    description: 'Deletes item from checklist'
  },

  // --- Attachments ---
  'POST /api/cards/:id/attachments': {
    events: ['attachment.added'],
    description: 'Attaches file or URL to card'
  },
  'POST /api/cards/:id/attachments/file': {
    events: ['attachment.added'],
    description: 'Uploads and attaches file to card'
  },
  'POST /api/cards/:id/attachments/link': {
    events: ['attachment.added'],
    description: 'Attaches URL link to card'
  },
  'DELETE /api/cards/attachments/:id': {
    events: ['attachment.removed'],
    description: 'Removes attachment from card'
  },
  'POST /api/attachments': {
    events: ['attachment.added'],
    description: 'Uploads and attaches file'
  },
  'DELETE /api/attachments/:id': {
    events: ['attachment.removed'],
    description: 'Removes file attachment'
  },

  // --- Workspace Members, Roles, Security ---
  'POST /api/workspaces/:id/members': {
    events: ['workspace.member_added'],
    description: 'Adds existing user directly to workspace'
  },
  'DELETE /api/workspaces/:id/members/:userId': {
    events: ['workspace.member_removed'],
    description: 'Removes member from workspace'
  },
  'PATCH /api/workspaces/:id/members/:userId/role': {
    events: ['workspace.member_role_changed', 'workspace.member_permissions_changed'],
    description: 'Updates workspace role/permissions of member'
  },
  'POST /api/workspaces/:workspaceId/members/:userId/reset-password': {
    events: ['security.admin_password_reset'],
    description: 'Admin resets temporary password for member'
  },
  'POST /api/workspaces/:workspaceId/members/:userId/reset-2fa': {
    events: ['security.two_factor_reset'],
    description: 'Admin resets 2FA for member'
  },
  'POST /api/workspaces/:id/roles': {
    events: ['role.created'],
    description: 'Creates new custom workspace role'
  },
  'PATCH /api/roles/:id': {
    events: ['role.updated'],
    description: 'Updates custom role permissions'
  },
  'DELETE /api/roles/:id': {
    events: ['role.deleted'],
    description: 'Deletes unused custom role'
  },

  // --- Invitations ---
  'POST /api/invitations': {
    events: ['invite.sent'],
    description: 'Issues signed workspace invitation link'
  },
  'POST /api/workspaces/:id/invitations': {
    events: ['invite.sent'],
    description: 'Issues workspace invitation link'
  },
  'POST /api/invitations/accept': {
    events: ['invite.accepted'],
    description: 'Accepts invitation and joins workspace'
  },
  'DELETE /api/invitations/:id': {
    events: ['invite.revoked'],
    description: 'Revokes pending workspace invitation'
  },
  'POST /api/invitations/:id/regenerate': {
    events: ['invite.sent'],
    description: 'Regenerates expiring invitation'
  },

  // ==========================================
  // --- EXPLICIT NO-NOTIFY ROUTES ---
  // ==========================================
  'POST /api/auth/register-company': {
    noNotify: true,
    reason: 'Unauthenticated company tenant onboarding flow'
  },
  'POST /api/auth/verify-registration': {
    noNotify: true,
    reason: 'Unauthenticated email/OTP verification flow'
  },
  'POST /api/auth/register': {
    noNotify: true,
    reason: 'Unauthenticated user registration via signed token'
  },
  'POST /api/auth/login': {
    noNotify: true,
    reason: 'Authentication step 1 credentials verification; session tracking handles new device alerts'
  },
  'POST /api/auth/2fa/verify-login': {
    noNotify: true,
    reason: 'Authentication step 2 TOTP challenge verification'
  },
  'POST /api/auth/refresh': {
    noNotify: true,
    reason: 'Token refresh exchange; silent background session rotation'
  },
  'POST /api/auth/logout': {
    noNotify: true,
    reason: 'Session termination; self-initiated logout'
  },
  'POST /api/auth/logout-all': {
    noNotify: true,
    reason: 'Session termination; self-initiated logout everywhere'
  },
  'DELETE /api/auth/sessions/:id': {
    noNotify: true,
    reason: 'Self or administrative session revocation'
  },
  'POST /api/auth/sessions/revoke-others': {
    noNotify: true,
    reason: 'Self session cleanup for other active devices'
  },
  'POST /api/auth/2fa/generate': {
    noNotify: true,
    reason: 'TOTP enrollment secret generation (in-progress)'
  },
  'POST /api/auth/2fa/setup': {
    noNotify: true,
    reason: 'TOTP QR generation (in-progress)'
  },
  'POST /api/auth/2fa/confirm': {
    noNotify: true,
    reason: 'Self TOTP 2FA confirmation'
  },
  'POST /api/auth/2fa/disable': {
    noNotify: true,
    reason: 'Self TOTP 2FA deactivation'
  },
  'PUT /api/auth/profile': {
    noNotify: true,
    reason: 'Self user profile settings update (name, avatar, timezone, locale)'
  },
  'PUT /api/auth/password': {
    noNotify: true,
    reason: 'Self password change'
  },
  'POST /api/auth/password': {
    noNotify: true,
    reason: 'Self password change'
  },
  'POST /api/auth/change-password': {
    noNotify: true,
    reason: 'Self password change'
  },
  'POST /api/workspaces': {
    noNotify: true,
    reason: 'New workspace creation (creator is sole owner)'
  },
  'PATCH /api/workspaces/:id': {
    noNotify: true,
    reason: 'Workspace metadata and setting edits'
  },
  'DELETE /api/workspaces/:id': {
    noNotify: true,
    reason: 'Workspace deletion; destroys workspace cascade'
  },
  'PATCH /api/notifications/preferences': {
    noNotify: true,
    reason: 'Self notification preference updates'
  },
  'PATCH /api/notifications/:id/read': {
    noNotify: true,
    reason: 'Self notification mark read state'
  },
  'PATCH /api/notifications/:id/unread': {
    noNotify: true,
    reason: 'Self notification mark unread state'
  },
  'PATCH /api/notifications/read-all': {
    noNotify: true,
    reason: 'Self notification mark all read state'
  },
  'DELETE /api/notifications/:id': {
    noNotify: true,
    reason: 'Self notification deletion'
  },
  'DELETE /api/notifications/clear/read': {
    noNotify: true,
    reason: 'Self notification cleanup for read items'
  },
  'POST /api/files/avatar': {
    noNotify: true,
    reason: 'Self avatar file upload'
  },
  'POST /api/upload': {
    noNotify: true,
    reason: 'Internal multipart file upload processing staging'
  },
  'POST /api/dev/reset-rate-limit': {
    noNotify: true,
    reason: 'Test-only development environment rate limit reset helper'
  }
};

module.exports = {
  ROUTE_NOTIFICATION_MAP
};
