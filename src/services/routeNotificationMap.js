// server/src/services/routeNotificationMap.js
// Single source of truth mapping mutating routes to declared notification events or explicit no-notify reasons.

const ROUTE_NOTIFICATION_MAP = {
  // ==========================================
  // --- NOTIFIABLE ROUTES (Main Set) ---
  // ==========================================
  'POST /api/boards': {
    events: ['board.created'],
    description: 'Creates project board'
  },
  'DELETE /api/boards/:id': {
    events: ['board.deleted'],
    description: 'Deletes board and all lists/cards'
  },
  'POST /api/boards/:id/archive': {
    events: ['board.archived'],
    description: 'Archives board'
  },
  'POST /api/boards/:id/members': {
    events: ['board.member_added'],
    description: 'Adds member to board'
  },
  'DELETE /api/boards/:id/members/:userId': {
    events: ['board.member_removed'],
    description: 'Removes member from board'
  },
  'PATCH /api/cards/:id': {
    events: ['card.completed', 'card.archived'],
    description: 'Updates card attributes, status, completion, archive'
  },
  'DELETE /api/cards/:id': {
    events: ['card.deleted'],
    description: 'Permanently deletes card'
  },
  'POST /api/cards/:id/members': {
    events: ['card.assigned', 'card.unassigned'],
    description: 'Assigns or unassigns member on card'
  },
  'POST /api/cards/:id/assigners': {
    events: ['card.assigned'],
    description: 'Assigns member on card'
  },
  'POST /api/cards/:id/comments': {
    events: ['comment.added', 'comment.mention'],
    description: 'Posts discussion comment and notifies assignees/creator/mentions'
  },
  'POST /api/workspaces/:id/members': {
    events: ['workspace.member_added'],
    description: 'Adds existing user directly to workspace'
  },
  'DELETE /api/workspaces/:id/members/:userId': {
    events: ['workspace.member_removed'],
    description: 'Removes member from workspace'
  },
  'PATCH /api/workspaces/:id/members/:userId/role': {
    events: ['workspace.member_role_changed'],
    description: 'Updates workspace role of member'
  },

  // ==========================================
  // --- MUTATING ROUTES WITH EXPLICIT NO-NOTIFY ---
  // ==========================================
  // --- Board Mutations ---
  'PATCH /api/boards/:id': {
    noNotify: true,
    reason: 'Board rename and background updates are non-notifiable (recorded in activity log)'
  },
  'POST /api/boards/:id/restore': {
    noNotify: true,
    reason: 'Board restore is non-notifiable (recorded in activity log)'
  },
  'PATCH /api/boards/:id/members/:userId/role': {
    noNotify: true,
    reason: 'Board member role change is non-notifiable (recorded in activity log)'
  },
  'POST /api/boards/:id/labels': {
    noNotify: true,
    reason: 'Board label creation is non-notifiable'
  },
  'PATCH /api/boards/:id/labels/:labelId': {
    noNotify: true,
    reason: 'Board label update is non-notifiable'
  },
  'DELETE /api/boards/:id/labels/:labelId': {
    noNotify: true,
    reason: 'Board label deletion is non-notifiable'
  },

  // --- List Mutations ---
  'POST /api/lists': {
    noNotify: true,
    reason: 'List creation is non-notifiable (recorded in activity log)'
  },
  'PATCH /api/lists/:id': {
    noNotify: true,
    reason: 'List rename, move, or archive are non-notifiable (recorded in activity log)'
  },
  'DELETE /api/lists/:id': {
    noNotify: true,
    reason: 'List deletion is non-notifiable (recorded in activity log)'
  },

  // --- Card Mutations ---
  'POST /api/cards': {
    noNotify: true,
    reason: 'Card creation is non-notifiable (recorded in activity log)'
  },
  'POST /api/cards/:id/copy': {
    noNotify: true,
    reason: 'Card copy is non-notifiable (recorded in activity log)'
  },
  'POST /api/cards/:id/labels': {
    noNotify: true,
    reason: 'Card label assignment is non-notifiable (recorded in activity log)'
  },

  // --- Comments ---
  'PATCH /api/cards/comments/:id': {
    noNotify: true,
    reason: 'Comment edit is non-notifiable (recorded in activity log)'
  },
  'DELETE /api/cards/comments/:id': {
    noNotify: true,
    reason: 'Comment deletion is non-notifiable (recorded in activity log)'
  },

  // --- Checklists & Items ---
  'POST /api/cards/:id/checklists': {
    noNotify: true,
    reason: 'Checklist creation is non-notifiable (recorded in activity log)'
  },
  'DELETE /api/cards/checklists/:id': {
    noNotify: true,
    reason: 'Checklist deletion is non-notifiable (recorded in activity log)'
  },
  'POST /api/cards/checklist-items': {
    noNotify: true,
    reason: 'Checklist item addition is non-notifiable (recorded in activity log)'
  },
  'PATCH /api/cards/checklist-items/:id': {
    noNotify: true,
    reason: 'Checklist item toggling/editing is non-notifiable (recorded in activity log)'
  },
  'DELETE /api/cards/checklist-items/:id': {
    noNotify: true,
    reason: 'Checklist item deletion is non-notifiable (recorded in activity log)'
  },

  // --- Attachments ---
  'POST /api/cards/:id/attachments': {
    noNotify: true,
    reason: 'Attachment addition is non-notifiable (recorded in activity log)'
  },
  'POST /api/cards/:id/attachments/file': {
    noNotify: true,
    reason: 'File attachment upload is non-notifiable (recorded in activity log)'
  },
  'POST /api/cards/:id/attachments/link': {
    noNotify: true,
    reason: 'Link attachment is non-notifiable (recorded in activity log)'
  },
  'DELETE /api/cards/attachments/:id': {
    noNotify: true,
    reason: 'Attachment removal is non-notifiable (recorded in activity log)'
  },
  'POST /api/attachments': {
    noNotify: true,
    reason: 'Attachment upload is non-notifiable (recorded in activity log)'
  },
  'DELETE /api/attachments/:id': {
    noNotify: true,
    reason: 'Attachment removal is non-notifiable (recorded in activity log)'
  },

  // --- Workspace & Company Administration ---
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
  'PATCH /api/workspaces/:id/security': {
    noNotify: true,
    reason: 'Workspace security settings update (recorded in audit log)'
  },
  'POST /api/workspaces/:id/auto-archive': {
    noNotify: true,
    reason: 'Workspace auto-archive configuration update'
  },
  'POST /api/workspaces/:id/members/:userId/deactivate': {
    noNotify: true,
    reason: 'Member deactivation is recorded in audit logs'
  },
  'POST /api/workspaces/:id/members/:userId/reactivate': {
    noNotify: true,
    reason: 'Member reactivation is recorded in audit logs'
  },
  'PATCH /api/workspaces/:id/company-members/:userId/role': {
    noNotify: true,
    reason: 'Company-level role assignment is recorded in audit logs'
  },
  'POST /api/workspaces/:id/company-members/:userId/workspaces': {
    noNotify: true,
    reason: 'Company member workspace assignment'
  },
  'POST /api/workspaces/:id/company-members/:userId/boards': {
    noNotify: true,
    reason: 'Company member board assignment'
  },
  'DELETE /api/workspaces/:id/company-members/:userId': {
    noNotify: true,
    reason: 'Company member removal'
  },
  'POST /api/workspaces/:workspaceId/members/:userId/reset-password': {
    noNotify: true,
    reason: 'Admin password reset is logged in audit log, not notifiable to in-app'
  },
  'POST /api/workspaces/:workspaceId/members/:userId/reset-2fa': {
    noNotify: true,
    reason: 'Admin 2FA reset is logged in audit log, not notifiable to in-app'
  },
  'POST /api/workspaces/:id/roles': {
    noNotify: true,
    reason: 'Role creation is non-notifiable (recorded in audit logs)'
  },
  'PATCH /api/roles/:id': {
    noNotify: true,
    reason: 'Role update is non-notifiable (recorded in audit logs)'
  },
  'DELETE /api/roles/:id': {
    noNotify: true,
    reason: 'Role deletion is non-notifiable (recorded in audit logs)'
  },

  // --- Invitations ---
  'POST /api/invitations': {
    noNotify: true,
    reason: 'Invitation issuance is handled via email link, non-notifiable to in-app'
  },
  'POST /api/workspaces/:id/invitations': {
    noNotify: true,
    reason: 'Workspace invitation issuance is non-notifiable to in-app'
  },
  'POST /api/invitations/accept': {
    noNotify: true,
    reason: 'Invitation acceptance is non-notifiable to in-app'
  },
  'DELETE /api/invitations/:id': {
    noNotify: true,
    reason: 'Invitation revocation is non-notifiable to in-app'
  },
  'POST /api/invitations/:id/regenerate': {
    noNotify: true,
    reason: 'Invitation regeneration is non-notifiable to in-app'
  },
  'POST /api/invitations/:id/resend': {
    noNotify: true,
    reason: 'Invitation resend is non-notifiable to in-app'
  },

  // --- Authentication, Profile, Session Management ---
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
  'POST /api/auth/register/send-otp': {
    noNotify: true,
    reason: 'Unauthenticated registration OTP dispatch'
  },
  'POST /api/auth/register/verify-otp': {
    noNotify: true,
    reason: 'Unauthenticated registration OTP verification'
  },
  'POST /api/auth/forgot-password/send-otp': {
    noNotify: true,
    reason: 'Unauthenticated password reset OTP dispatch'
  },
  'POST /api/auth/forgot-password/verify-otp': {
    noNotify: true,
    reason: 'Unauthenticated password reset OTP verification'
  },
  'POST /api/auth/forgot-password/verify-token': {
    noNotify: true,
    reason: 'Unauthenticated password reset token check'
  },
  'POST /api/auth/forgot-password/reset': {
    noNotify: true,
    reason: 'Unauthenticated password reset completion'
  },
  'POST /api/auth/login': {
    noNotify: true,
    reason: 'Authentication credentials verification; session tracking records login'
  },
  'POST /api/auth/2fa/verify-login': {
    noNotify: true,
    reason: 'Authentication step 2 TOTP challenge verification'
  },
  'POST /api/auth/2fa/verify': {
    noNotify: true,
    reason: 'TOTP 2FA challenge verification'
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
    reason: 'TOTP enrollment secret generation'
  },
  'POST /api/auth/2fa/setup': {
    noNotify: true,
    reason: 'TOTP QR generation'
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

  // --- Self Notification Actions ---
  'PATCH /api/notifications/preferences': {
    noNotify: true,
    reason: 'Self notification preference updates'
  },
  'POST /api/notifications/mute': {
    noNotify: true,
    reason: 'Self notification mute state modification'
  },
  'POST /api/notifications/unmute': {
    noNotify: true,
    reason: 'Self notification unmute state modification'
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
  'PATCH /api/notifications/board/:id/read-all': {
    noNotify: true,
    reason: 'Self notification mark all read for board'
  },
  'DELETE /api/notifications/:id': {
    noNotify: true,
    reason: 'Self notification deletion'
  },
  'DELETE /api/notifications/clear/read': {
    noNotify: true,
    reason: 'Self notification cleanup for read items'
  },

  // --- Files & Dev Helpers ---
  'POST /api/files/avatar': {
    noNotify: true,
    reason: 'Self avatar file upload'
  },
  'POST /api/files/preview-token': {
    noNotify: true,
    reason: 'Ephemeral file preview token creation'
  },
  'POST /api/upload': {
    noNotify: true,
    reason: 'Internal multipart file upload processing staging'
  },
  'POST /api/dev/reset-rate-limit': {
    noNotify: true,
    reason: 'Test-only development environment rate limit reset helper'
  },

  // --- Workspaces (Icon & Leave Days) ---
  'POST /api/workspaces/:id/icon': {
    noNotify: true,
    reason: 'Workspace icon upload is a visual preference; not notifiable'
  },
  'DELETE /api/workspaces/:id/icon': {
    noNotify: true,
    reason: 'Workspace icon removal is a visual preference; not notifiable'
  },
  'POST /api/workspaces/:id/leave-days': {
    noNotify: true,
    reason: 'Leave day request/creation is tracked administratively in Daily Tracker and audit log'
  },
  'PATCH /api/workspaces/:id/leave-days/:leaveId': {
    noNotify: true,
    reason: 'Leave day approval/rejection is tracked administratively in Daily Tracker and audit log'
  },
  'DELETE /api/workspaces/:id/leave-days/:leaveId': {
    noNotify: true,
    reason: 'Leave day cancellation is tracked administratively in Daily Tracker and audit log'
  },

  // --- Daily Tracker Focus & Check-ins ---
  'POST /api/cards/:id/focus': {
    noNotify: true,
    reason: 'Personal focus selection is productivity state; not a noise event'
  },
  'DELETE /api/cards/:id/focus': {
    noNotify: true,
    reason: 'Ending personal focus is productivity state; not a noise event'
  },
  'POST /api/cards/:id/focus/deep-work': {
    noNotify: true,
    reason: 'Designating deep-work card is productivity metadata; not a noise event'
  },
  'POST /api/cards/:id/checkins': {
    noNotify: true,
    reason: 'Check-in creation is recorded in Daily Tracker; not a noise event'
  },
  'PATCH /api/cards/:id/checkins/:checkinId': {
    noNotify: true,
    reason: 'Check-in 15-minute edit window update; not a noise event'
  },
  'POST /api/checkins/:id/review': {
    noNotify: true,
    reason: 'Check-in review questions/acknowledgments are handled in Daily Tracker review feed'
  },
  'POST /api/checkin-reviews/:id/answer': {
    noNotify: true,
    reason: 'Check-in review answer is recorded in checkin thread'
  }
};

module.exports = {
  ROUTE_NOTIFICATION_MAP
};
