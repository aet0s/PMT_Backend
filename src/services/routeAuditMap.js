// server/src/services/routeAuditMap.js
// Single source of truth mapping all live Express mutating routes to declared audit events
// or explicit exemptions with documented architectural reasons.

const ROUTE_AUDIT_MAP = {
  // ==========================================
  // --- ATTACHMENTS ---
  // ==========================================
  'POST /api/attachments': {
    auditEvents: ['attachment.created'],
    description: 'Uploads attachment file'
  },
  'DELETE /api/attachments/:id': {
    auditEvents: ['attachment.deleted'],
    description: 'Deletes attachment'
  },

  // ==========================================
  // --- AUTHENTICATION & SESSIONS ---
  // ==========================================
  'POST /api/auth/register': {
    auditEvents: ['auth.registered'],
    description: 'Registers a new user account'
  },
  'POST /api/auth/register-company': {
    auditEvents: ['auth.registered', 'workspace.created'],
    description: 'Registers new company and initial workspace'
  },
  'POST /api/auth/verify-registration': {
    auditEvents: ['auth.registered'],
    description: 'Verifies email and activates account'
  },
  'POST /api/auth/register/send-otp': {
    exemption: true,
    reason: 'Pre-registration OTP email dispatch prior to user record activation'
  },
  'POST /api/auth/register/verify-otp': {
    exemption: true,
    reason: 'Pre-registration OTP validation step'
  },
  'POST /api/auth/login': {
    auditEvents: ['auth.login_success', 'auth.login_failed', 'auth.lockout'],
    description: 'User login with credential validation'
  },
  'POST /api/auth/logout': {
    auditEvents: ['auth.logout'],
    description: 'Logs user out of active session'
  },
  'POST /api/auth/logout-all': {
    auditEvents: ['auth.logout', 'auth.session_revoked'],
    description: 'Logs user out of all active sessions'
  },
  'POST /api/auth/refresh': {
    exemption: true,
    reason: 'Stateless short-lived JWT token rotation'
  },
  'DELETE /api/auth/sessions/:id': {
    auditEvents: ['auth.session_revoked'],
    description: 'Terminates specific session'
  },
  'POST /api/auth/sessions/revoke-others': {
    auditEvents: ['auth.session_revoked'],
    description: 'Revokes all sessions except current one'
  },
  'POST /api/auth/forgot-password/send-otp': {
    auditEvents: ['auth.password_reset_requested'],
    description: 'Sends password reset OTP'
  },
  'POST /api/auth/forgot-password/verify-otp': {
    exemption: true,
    reason: 'Transient verification of reset OTP'
  },
  'POST /api/auth/forgot-password/verify-token': {
    exemption: true,
    reason: 'Transient verification of reset token'
  },
  'POST /api/auth/forgot-password/reset': {
    auditEvents: ['auth.password_reset'],
    description: 'Resets user password via verified reset token'
  },
  'POST /api/auth/change-password': {
    auditEvents: ['auth.password_changed'],
    description: 'Changes password for authenticated user'
  },
  'PUT /api/auth/password': {
    auditEvents: ['auth.password_changed'],
    description: 'Updates password on must_change_password challenge'
  },
  'POST /api/auth/password': {
    auditEvents: ['auth.password_changed'],
    description: 'Updates password on forced password reset'
  },
  'PUT /api/auth/profile': {
    auditEvents: ['member.profile_updated'],
    description: 'Updates user personal profile (name, avatar, timezone)'
  },
  'POST /api/auth/2fa/generate': {
    exemption: true,
    reason: 'Transient TOTP secret generation prior to user confirmation'
  },
  'POST /api/auth/2fa/setup': {
    exemption: true,
    reason: 'Transient TOTP setup helper'
  },
  'POST /api/auth/2fa/confirm': {
    auditEvents: ['auth.2fa_enabled'],
    description: 'Confirms and activates TOTP 2FA'
  },
  'POST /api/auth/2fa/verify': {
    exemption: true,
    reason: 'Transient TOTP verification during setup flow'
  },
  'POST /api/auth/2fa/verify-login': {
    auditEvents: ['auth.login_success', 'auth.login_failed'],
    description: 'Verifies 2FA code during login'
  },
  'POST /api/auth/2fa/disable': {
    auditEvents: ['auth.2fa_disabled'],
    description: 'Disables two-factor authentication'
  },

  // ==========================================
  // --- BOARDS ---
  // ==========================================
  'POST /api/boards': {
    auditEvents: ['board.created'],
    description: 'Creates project board'
  },
  'PATCH /api/boards/:id': {
    auditEvents: ['board.renamed', 'board.background_changed'],
    description: 'Updates board attributes, title, background'
  },
  'DELETE /api/boards/:id': {
    auditEvents: ['board.deleted'],
    description: 'Permanently deletes board'
  },
  'POST /api/boards/:id/archive': {
    auditEvents: ['board.archived'],
    description: 'Archives board'
  },
  'POST /api/boards/:id/restore': {
    auditEvents: ['board.restored'],
    description: 'Restores archived board'
  },
  'POST /api/boards/:id/members': {
    auditEvents: ['board.member_added'],
    description: 'Adds member to board'
  },
  'PATCH /api/boards/:id/members/:userId/role': {
    auditEvents: ['board.member_role_changed'],
    description: 'Updates board member role'
  },
  'DELETE /api/boards/:id/members/:userId': {
    auditEvents: ['board.member_removed'],
    description: 'Removes member from board'
  },
  'POST /api/boards/:id/labels': {
    auditEvents: ['label.created'],
    description: 'Creates board label'
  },
  'PATCH /api/boards/:id/labels/:labelId': {
    auditEvents: ['label.updated'],
    description: 'Updates board label color or name'
  },
  'DELETE /api/boards/:id/labels/:labelId': {
    auditEvents: ['label.deleted'],
    description: 'Deletes board label'
  },

  // ==========================================
  // --- CARDS ---
  // ==========================================
  'POST /api/cards': {
    auditEvents: ['card.created', 'card.assigner_added'],
    description: 'Creates card with creator as default assigner'
  },
  'POST /api/cards/:id/copy': {
    auditEvents: ['card.copied', 'card.assigner_added'],
    description: 'Duplicates card with checklists, attachments, and creator default assigner'
  },
  'PATCH /api/cards/:id': {
    auditEvents: [
      'card.renamed',
      'card.description_updated',
      'card.moved',
      'card.due_date_changed',
      'card.start_date_changed',
      'card.completed',
      'card.reopened',
      'card.archived',
      'card.restored',
      'card.cover_updated'
    ],
    description: 'Updates card details, completion, archive status, movement'
  },
  'DELETE /api/cards/:id': {
    auditEvents: ['card.deleted'],
    description: 'Permanently deletes card'
  },
  'POST /api/cards/:id/members': {
    auditEvents: ['card.assignee_added', 'card.assignee_removed'],
    description: 'Toggles assignee membership on card'
  },
  'POST /api/cards/:id/assigners': {
    auditEvents: ['card.assigner_added', 'card.assigner_removed', 'card.assigner_changed'],
    description: 'Toggles assigner on card with before/after state'
  },
  'POST /api/cards/:id/labels': {
    auditEvents: ['card.label_added', 'card.label_removed'],
    description: 'Toggles label on card'
  },
  'POST /api/cards/:id/comments': {
    auditEvents: ['comment.created'],
    description: 'Posts discussion comment'
  },
  'PATCH /api/cards/comments/:id': {
    auditEvents: ['comment.updated'],
    description: 'Edits comment content'
  },
  'DELETE /api/cards/comments/:id': {
    auditEvents: ['comment.deleted'],
    description: 'Deletes comment'
  },
  'POST /api/cards/:id/attachments': {
    auditEvents: ['attachment.created'],
    description: 'Uploads file attachment'
  },
  'POST /api/cards/:id/attachments/file': {
    auditEvents: ['attachment.created'],
    description: 'Uploads file attachment'
  },
  'POST /api/cards/:id/attachments/link': {
    auditEvents: ['attachment.linked'],
    description: 'Adds external link attachment'
  },
  'DELETE /api/cards/attachments/:id': {
    auditEvents: ['attachment.deleted'],
    description: 'Removes attachment from card'
  },
  'POST /api/cards/:id/checklists': {
    auditEvents: ['checklist.created'],
    description: 'Creates checklist on card'
  },
  'DELETE /api/cards/checklists/:id': {
    auditEvents: ['checklist.deleted'],
    description: 'Deletes checklist'
  },
  'POST /api/cards/checklist-items': {
    auditEvents: ['checklist_item.created'],
    description: 'Creates checklist item'
  },
  'PATCH /api/cards/checklist-items/:id': {
    auditEvents: ['checklist_item.updated', 'checklist_item.toggled'],
    description: 'Updates checklist item text or checked status'
  },
  'DELETE /api/cards/checklist-items/:id': {
    auditEvents: ['checklist_item.deleted'],
    description: 'Deletes checklist item'
  },
  'POST /api/cards/:id/checkins': {
    auditEvents: ['checkin.created'],
    description: 'Records daily tracker card checkin'
  },
  'PATCH /api/cards/:id/checkins/:checkinId': {
    auditEvents: ['checkin.updated'],
    description: 'Updates card checkin'
  },

  // ==========================================
  // --- CHECKINS ---
  // ==========================================
  'POST /api/checkins/:id/review': {
    auditEvents: ['checkin.reviewed'],
    description: 'Submits checkin review'
  },
  'POST /api/checkin-reviews/:id/answer': {
    auditEvents: ['checkin.answered'],
    description: 'Answers checkin review question'
  },

  // ==========================================
  // --- FILES ---
  // ==========================================

  'POST /api/files/preview-token': {
    exemption: true,
    reason: 'Generates short-lived stateless preview token for viewing attachments'
  },
  'POST /api/upload': {
    auditEvents: ['attachment.created'],
    description: 'Standalone file upload endpoint'
  },

  // ==========================================
  // --- INVITATIONS ---
  // ==========================================
  'POST /api/invitations': {
    auditEvents: ['member.invited'],
    description: 'Sends workspace invitation'
  },
  'POST /api/invitations/:id/resend': {
    auditEvents: ['member.invite_resent'],
    description: 'Re-sends pending invitation'
  },
  'POST /api/invitations/:id/regenerate': {
    auditEvents: ['member.invite_resent'],
    description: 'Regenerates invitation link'
  },
  'DELETE /api/invitations/:id': {
    auditEvents: ['member.invite_revoked'],
    description: 'Revokes pending invitation'
  },
  'POST /api/invitations/accept': {
    auditEvents: ['member.invite_accepted', 'member.added'],
    description: 'Accepts workspace invitation'
  },

  // ==========================================
  // --- LISTS ---
  // ==========================================
  'POST /api/lists': {
    auditEvents: ['list.created'],
    description: 'Creates list on board'
  },
  'PATCH /api/lists/:id': {
    auditEvents: ['list.renamed', 'list.reordered', 'list.archived', 'list.done_list_flag_changed', 'list.wip_limit_changed'],
    description: 'Updates list name, position, done flag, or WIP limit'
  },
  'DELETE /api/lists/:id': {
    auditEvents: ['list.deleted'],
    description: 'Deletes list'
  },

  // ==========================================
  // --- NOTIFICATIONS ---
  // ==========================================
  'PATCH /api/notifications/preferences': {
    auditEvents: ['notification.preferences_updated'],
    description: 'Updates notification channel preferences'
  },
  'POST /api/notifications/mute': {
    auditEvents: ['notification.preferences_updated'],
    description: 'Mutes board notifications'
  },
  'POST /api/notifications/unmute': {
    auditEvents: ['notification.preferences_updated'],
    description: 'Unmutes board notifications'
  },
  'PATCH /api/notifications/:id/read': {
    exemption: true,
    reason: 'Individual user UI notification status update (read toggle)'
  },
  'PATCH /api/notifications/:id/unread': {
    exemption: true,
    reason: 'Individual user UI notification status update (unread toggle)'
  },
  'PATCH /api/notifications/read-all': {
    exemption: true,
    reason: 'Bulk notification read state update'
  },
  'PATCH /api/notifications/board/:id/read-all': {
    exemption: true,
    reason: 'Board-specific notification read state update'
  },
  'DELETE /api/notifications/:id': {
    exemption: true,
    reason: 'User personal notification row dismissal'
  },
  'DELETE /api/notifications/clear/read': {
    exemption: true,
    reason: 'User bulk read notification dismissal'
  },

  // ==========================================
  // --- PUSH NOTIFICATIONS ---
  // ==========================================
  'POST /api/push/subscriptions': {
    auditEvents: ['push.subscription_created'],
    description: 'Registers or updates push subscription device'
  },
  'DELETE /api/push/subscriptions/:id': {
    auditEvents: ['push.subscription_revoked'],
    description: 'Revokes specific push subscription device'
  },
  'DELETE /api/push/subscriptions/current': {
    auditEvents: ['push.subscription_revoked'],
    description: 'Revokes current device push subscription on logout'
  },
  'POST /api/push/test': {
    auditEvents: ['push.test_sent'],
    description: 'Dispatches test push notification to caller devices'
  },

  // ==========================================
  // --- ROLES ---
  // ==========================================
  'POST /api/roles': {
    auditEvents: ['role.created'],
    description: 'Creates new role'
  },
  'PATCH /api/roles/:id': {
    auditEvents: ['role.updated'],
    description: 'Updates role permissions or attributes'
  },
  'DELETE /api/roles/:id': {
    auditEvents: ['role.deleted'],
    description: 'Deletes custom role'
  },

  // ==========================================
  // --- WORKSPACES ---
  // ==========================================
  'POST /api/workspaces': {
    auditEvents: ['workspace.created'],
    description: 'Creates workspace'
  },
  'PATCH /api/workspaces/:id': {
    auditEvents: ['workspace.updated', 'workspace.settings_updated', 'workspace.archived', 'workspace.restored'],
    description: 'Updates workspace name, description, settings, or archive state'
  },
  'DELETE /api/workspaces/:id': {
    auditEvents: ['workspace.deleted'],
    description: 'Permanently deletes workspace'
  },
  'POST /api/workspaces/:id/auto-archive': {
    auditEvents: ['workspace.auto_archived'],
    description: 'Triggers auto-archive sweep on workspace'
  },
  'PATCH /api/workspaces/:id/security': {
    auditEvents: ['workspace.settings_updated'],
    description: 'Updates workspace security settings (require_2fa, session timeout)'
  },
  'POST /api/workspaces/:id/icon': {
    auditEvents: ['workspace.updated'],
    description: 'Uploads workspace custom icon'
  },
  'DELETE /api/workspaces/:id/icon': {
    auditEvents: ['workspace.updated'],
    description: 'Removes workspace custom icon'
  },
  'POST /api/workspaces/:id/members': {
    auditEvents: ['member.added'],
    description: 'Adds user to workspace'
  },
  'PATCH /api/workspaces/:id/members/:userId/role': {
    auditEvents: ['member.role_changed'],
    description: 'Updates member workspace role'
  },
  'DELETE /api/workspaces/:id/members/:userId': {
    auditEvents: ['member.removed'],
    description: 'Removes member from workspace'
  },
  'POST /api/workspaces/:id/invitations': {
    auditEvents: ['member.invited'],
    description: 'Invites member to workspace'
  },
  'POST /api/workspaces/:id/roles': {
    auditEvents: ['role.created'],
    description: 'Creates role in workspace context'
  },
  'POST /api/workspaces/:workspaceId/members/:userId/reset-password': {
    auditEvents: ['auth.password_reset'],
    description: 'Admin resets user password'
  },
  'POST /api/workspaces/:workspaceId/members/:userId/reset-2fa': {
    auditEvents: ['auth.2fa_reset'],
    description: 'Admin resets user 2FA'
  },
  'POST /api/workspaces/:id/members/:userId/deactivate': {
    auditEvents: ['auth.user_deactivated'],
    description: 'Deactivates member'
  },
  'POST /api/workspaces/:id/members/:userId/reactivate': {
    auditEvents: ['auth.user_reactivated'],
    description: 'Reactivates deactivated member'
  },
  'PATCH /api/workspaces/:id/company-members/:userId/role': {
    auditEvents: ['member.role_changed', 'member.owner_transferred'],
    description: 'Updates company-wide role or transfers company ownership'
  },
  'PATCH /api/workspaces/:id/company-members/:userId/credentials': {
    auditEvents: ['auth.password_reset'],
    description: 'Company admin resets member credentials'
  },
  'DELETE /api/workspaces/:id/company-members/:userId': {
    auditEvents: ['member.removed'],
    description: 'Removes member from company'
  },
  'POST /api/workspaces/:id/company-members/:userId/workspaces': {
    auditEvents: ['member.added'],
    description: 'Assigns member to workspace'
  },
  'POST /api/workspaces/:id/company-members/:userId/boards': {
    auditEvents: ['board.member_added'],
    description: 'Assigns member to board'
  },
  'POST /api/workspaces/:id/leave-days': {
    auditEvents: ['leave.requested'],
    description: 'Submits leave day request'
  },
  'PATCH /api/workspaces/:id/leave-days/:leaveId': {
    auditEvents: ['leave.approved', 'leave.rejected'],
    description: 'Updates leave day status'
  },
  'DELETE /api/workspaces/:id/leave-days/:leaveId': {
    auditEvents: ['leave.deleted'],
    description: 'Deletes leave day record'
  },
  'POST /api/workspaces/:id/audit-events/verify': {
    auditEvents: ['audit.verified'],
    description: 'Performs cryptographic hash-chain verification'
  },
  'POST /api/files/avatar': {
    auditEvents: ['attachment.created'],
    description: 'Uploads and updates user profile avatar image'
  }
};

module.exports = {
  ROUTE_AUDIT_MAP
};
