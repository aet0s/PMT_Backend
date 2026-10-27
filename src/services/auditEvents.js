// server/src/services/auditEvents.js
// Single source of truth catalogue for all compliance audit log events.

const AUDIT_CATEGORIES = [
  'auth',
  'security',
  'workspace',
  'member',
  'role',
  'board',
  'list',
  'card',
  'checklist',
  'comment',
  'attachment',
  'label',
  'checkin',
  'leave',
  'settings',
  'export',
  'audit',
  'system'
];

const AUDIT_EVENT_CATALOGUE = {
  // Auth Events
  'auth.login_success': {
    category: 'auth',
    severity: 'info',
    entityType: 'user',
    description: 'User successfully logged into system'
  },
  'auth.login_failed': {
    category: 'auth',
    severity: 'warning',
    entityType: 'user',
    description: 'Failed login attempt'
  },
  'auth.lockout': {
    category: 'auth',
    severity: 'critical',
    entityType: 'user',
    description: 'User account temporarily locked due to consecutive failed login attempts'
  },
  'auth.logout': {
    category: 'auth',
    severity: 'info',
    entityType: 'user',
    description: 'User logged out of active session'
  },
  'auth.password_changed': {
    category: 'auth',
    severity: 'notice',
    entityType: 'user',
    description: 'User updated their account password'
  },
  'auth.password_reset_requested': {
    category: 'auth',
    severity: 'notice',
    entityType: 'user',
    description: 'User requested a password reset OTP'
  },
  'auth.password_reset': {
    category: 'auth',
    severity: 'warning',
    entityType: 'user',
    description: 'User password was reset'
  },
  'auth.2fa_enabled': {
    category: 'auth',
    severity: 'notice',
    entityType: 'user',
    description: 'Two-factor authentication (TOTP) enabled for account'
  },
  'auth.2fa_disabled': {
    category: 'auth',
    severity: 'warning',
    entityType: 'user',
    description: 'Two-factor authentication (TOTP) disabled for account'
  },
  'auth.2fa_reset': {
    category: 'auth',
    severity: 'warning',
    entityType: 'user',
    description: 'Two-factor authentication reset by administrator'
  },
  'auth.session_revoked': {
    category: 'auth',
    severity: 'notice',
    entityType: 'session',
    description: 'Active login session revoked'
  },
  'auth.user_deactivated': {
    category: 'auth',
    severity: 'warning',
    entityType: 'user',
    description: 'User membership deactivated'
  },
  'auth.user_reactivated': {
    category: 'auth',
    severity: 'notice',
    entityType: 'user',
    description: 'User membership reactivated'
  },
  'auth.new_device': {
    category: 'auth',
    severity: 'notice',
    entityType: 'session',
    description: 'Login detected from an unrecognized client device or IP'
  },
  'auth.registered': {
    category: 'auth',
    severity: 'notice',
    entityType: 'user',
    description: 'New user registered an account'
  },

  // Workspace Events
  'workspace.created': {
    category: 'workspace',
    severity: 'notice',
    entityType: 'workspace',
    description: 'New workspace created'
  },
  'workspace.updated': {
    category: 'workspace',
    severity: 'info',
    entityType: 'workspace',
    description: 'Workspace details updated'
  },
  'workspace.archived': {
    category: 'workspace',
    severity: 'warning',
    entityType: 'workspace',
    description: 'Workspace archived'
  },
  'workspace.restored': {
    category: 'workspace',
    severity: 'notice',
    entityType: 'workspace',
    description: 'Workspace restored from archive'
  },
  'workspace.deleted': {
    category: 'workspace',
    severity: 'critical',
    entityType: 'workspace',
    description: 'Workspace permanently deleted'
  },
  'workspace.settings_updated': {
    category: 'workspace',
    severity: 'notice',
    entityType: 'workspace',
    description: 'Workspace settings updated (timezone, working days, retention, 2fa policy)'
  },
  'workspace.auto_archived': {
    category: 'workspace',
    severity: 'info',
    entityType: 'workspace',
    description: 'Auto-archive sweep executed on workspace'
  },

  // Member Events
  'member.invited': {
    category: 'member',
    severity: 'notice',
    entityType: 'invitation',
    description: 'Invitation sent to join workspace'
  },
  'member.invite_revoked': {
    category: 'member',
    severity: 'notice',
    entityType: 'invitation',
    description: 'Pending invitation revoked'
  },
  'member.invite_resent': {
    category: 'member',
    severity: 'info',
    entityType: 'invitation',
    description: 'Invitation re-sent'
  },
  'member.invite_accepted': {
    category: 'member',
    severity: 'notice',
    entityType: 'invitation',
    description: 'Invitation accepted by user'
  },
  'member.added': {
    category: 'member',
    severity: 'notice',
    entityType: 'user',
    description: 'User added to workspace or company'
  },
  'member.removed': {
    category: 'member',
    severity: 'warning',
    entityType: 'user',
    description: 'User removed from workspace or company'
  },
  'member.role_changed': {
    category: 'member',
    severity: 'warning',
    entityType: 'user',
    description: 'Member workspace role updated'
  },
  'member.owner_transferred': {
    category: 'member',
    severity: 'critical',
    entityType: 'user',
    description: 'Company owner transferred to another user'
  },
  'member.profile_updated': {
    category: 'member',
    severity: 'info',
    entityType: 'user',
    description: 'User personal profile updated (name, email, timezone, locale, avatar)'
  },

  // Role Events
  'role.created': {
    category: 'role',
    severity: 'notice',
    entityType: 'role',
    description: 'New custom role created'
  },
  'role.updated': {
    category: 'role',
    severity: 'warning',
    entityType: 'role',
    description: 'Role permissions or attributes updated'
  },
  'role.deleted': {
    category: 'role',
    severity: 'critical',
    entityType: 'role',
    description: 'Role deleted'
  },

  // Board Events
  'board.created': {
    category: 'board',
    severity: 'info',
    entityType: 'board',
    description: 'New board created'
  },
  'board.renamed': {
    category: 'board',
    severity: 'info',
    entityType: 'board',
    description: 'Board renamed'
  },
  'board.background_changed': {
    category: 'board',
    severity: 'info',
    entityType: 'board',
    description: 'Board background color or image updated'
  },
  'board.archived': {
    category: 'board',
    severity: 'warning',
    entityType: 'board',
    description: 'Board archived'
  },
  'board.restored': {
    category: 'board',
    severity: 'notice',
    entityType: 'board',
    description: 'Board restored from archive'
  },
  'board.deleted': {
    category: 'board',
    severity: 'critical',
    entityType: 'board',
    description: 'Board permanently deleted'
  },
  'board.member_added': {
    category: 'board',
    severity: 'info',
    entityType: 'board_member',
    description: 'Member added to board'
  },
  'board.member_removed': {
    category: 'board',
    severity: 'notice',
    entityType: 'board_member',
    description: 'Member removed from board'
  },
  'board.member_role_changed': {
    category: 'board',
    severity: 'notice',
    entityType: 'board_member',
    description: 'Board member role updated'
  },

  // List Events
  'list.created': {
    category: 'list',
    severity: 'info',
    entityType: 'list',
    description: 'New list created on board'
  },
  'list.renamed': {
    category: 'list',
    severity: 'info',
    entityType: 'list',
    description: 'List renamed'
  },
  'list.reordered': {
    category: 'list',
    severity: 'info',
    entityType: 'list',
    description: 'List position updated'
  },
  'list.archived': {
    category: 'list',
    severity: 'notice',
    entityType: 'list',
    description: 'List archived'
  },
  'list.deleted': {
    category: 'list',
    severity: 'warning',
    entityType: 'list',
    description: 'List permanently deleted'
  },
  'list.done_list_flag_changed': {
    category: 'list',
    severity: 'info',
    entityType: 'list',
    description: 'List marked or unmarked as done list'
  },
  'list.wip_limit_changed': {
    category: 'list',
    severity: 'info',
    entityType: 'list',
    description: 'List WIP limit updated'
  },

  // Card Events
  'card.created': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card created'
  },
  'card.copied': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card duplicated with lists, boards, checklists, and attachments'
  },
  'card.renamed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card title updated'
  },
  'card.description_updated': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card description content updated'
  },
  'card.moved': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card moved between lists or boards'
  },
  'card.due_date_changed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card due date updated'
  },
  'card.start_date_changed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card start date updated'
  },
  'card.label_added': {
    category: 'label',
    severity: 'info',
    entityType: 'card',
    description: 'Label assigned to card'
  },
  'card.label_removed': {
    category: 'label',
    severity: 'info',
    entityType: 'card',
    description: 'Label unassigned from card'
  },
  'card.cover_updated': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card cover image updated'
  },
  'card.completed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card marked as completed'
  },
  'card.reopened': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card reopened from completed status'
  },
  'card.archived': {
    category: 'card',
    severity: 'notice',
    entityType: 'card',
    description: 'Card archived'
  },
  'card.restored': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card unarchived'
  },
  'card.deleted': {
    category: 'card',
    severity: 'warning',
    entityType: 'card',
    description: 'Card permanently deleted'
  },
  'card.assignee_added': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Assignee added to card'
  },
  'card.assignee_removed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Assignee removed from card'
  },
  'card.assigner_added': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Assigner added to card'
  },
  'card.assigner_removed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Assigner removed from card'
  },
  'card.assigner_changed': {
    category: 'card',
    severity: 'info',
    entityType: 'card',
    description: 'Card assigner swapped or updated'
  },

  // Checklist Events
  'checklist.created': {
    category: 'checklist',
    severity: 'info',
    entityType: 'checklist',
    description: 'Checklist added to card'
  },
  'checklist.deleted': {
    category: 'checklist',
    severity: 'info',
    entityType: 'checklist',
    description: 'Checklist removed from card'
  },
  'checklist_item.created': {
    category: 'checklist',
    severity: 'info',
    entityType: 'checklist_item',
    description: 'Checklist item added'
  },
  'checklist_item.updated': {
    category: 'checklist',
    severity: 'info',
    entityType: 'checklist_item',
    description: 'Checklist item text updated'
  },
  'checklist_item.deleted': {
    category: 'checklist',
    severity: 'info',
    entityType: 'checklist_item',
    description: 'Checklist item deleted'
  },
  'checklist_item.toggled': {
    category: 'checklist',
    severity: 'info',
    entityType: 'checklist_item',
    description: 'Checklist item checked or unchecked'
  },

  // Comment Events
  'comment.created': {
    category: 'comment',
    severity: 'info',
    entityType: 'comment',
    description: 'Discussion comment posted on card'
  },
  'comment.updated': {
    category: 'comment',
    severity: 'info',
    entityType: 'comment',
    description: 'Comment edited with before and after'
  },
  'comment.deleted': {
    category: 'comment',
    severity: 'notice',
    entityType: 'comment',
    description: 'Comment deleted'
  },

  // Attachment Events
  'attachment.created': {
    category: 'attachment',
    severity: 'info',
    entityType: 'attachment',
    description: 'File attachment uploaded to card'
  },
  'attachment.linked': {
    category: 'attachment',
    severity: 'info',
    entityType: 'attachment',
    description: 'External link attachment added to card'
  },
  'attachment.deleted': {
    category: 'attachment',
    severity: 'info',
    entityType: 'attachment',
    description: 'Attachment removed from card'
  },
  'attachment.downloaded': {
    category: 'attachment',
    severity: 'info',
    entityType: 'attachment',
    description: 'Attachment downloaded'
  },

  // Label Events
  'label.created': {
    category: 'label',
    severity: 'info',
    entityType: 'label',
    description: 'Board label created'
  },
  'label.updated': {
    category: 'label',
    severity: 'info',
    entityType: 'label',
    description: 'Board label updated'
  },
  'label.deleted': {
    category: 'label',
    severity: 'notice',
    entityType: 'label',
    description: 'Board label deleted'
  },

  // Checkin Events
  'checkin.created': {
    category: 'checkin',
    severity: 'info',
    entityType: 'checkin',
    description: 'Check-in entry created'
  },
  'checkin.updated': {
    category: 'checkin',
    severity: 'info',
    entityType: 'checkin',
    description: 'Check-in entry updated'
  },
  'checkin.reviewed': {
    category: 'checkin',
    severity: 'info',
    entityType: 'checkin',
    description: 'Check-in review recorded'
  },
  'checkin.answered': {
    category: 'checkin',
    severity: 'info',
    entityType: 'checkin',
    description: 'Check-in review answered'
  },

  // Leave Events
  'leave.requested': {
    category: 'leave',
    severity: 'info',
    entityType: 'leave_day',
    description: 'Leave request submitted'
  },
  'leave.approved': {
    category: 'leave',
    severity: 'notice',
    entityType: 'leave_day',
    description: 'Leave request approved'
  },
  'leave.rejected': {
    category: 'leave',
    severity: 'notice',
    entityType: 'leave_day',
    description: 'Leave request rejected'
  },
  'leave.deleted': {
    category: 'leave',
    severity: 'notice',
    entityType: 'leave_day',
    description: 'Leave record removed'
  },

  // Settings & Preferences
  'notification.preferences_updated': {
    category: 'settings',
    severity: 'info',
    entityType: 'user_preferences',
    description: 'User notification preferences updated'
  },
  'push.subscription_created': {
    category: 'settings',
    severity: 'info',
    entityType: 'push_subscription',
    description: 'Web push notification device subscription registered'
  },
  'push.subscription_revoked': {
    category: 'settings',
    severity: 'info',
    entityType: 'push_subscription',
    description: 'Web push notification device subscription revoked'
  },
  'push.test_sent': {
    category: 'settings',
    severity: 'info',
    entityType: 'push_subscription',
    description: 'Test web push notification dispatched to user devices'
  },

  // Export Events
  'export.generated': {
    category: 'export',
    severity: 'notice',
    entityType: 'export',
    description: 'Data or audit export generated'
  },

  // Audit Access Events
  'audit.page_viewed': {
    category: 'audit',
    severity: 'info',
    entityType: 'audit',
    description: 'Audit log page accessed or filtered'
  },
  'audit.exported': {
    category: 'export',
    severity: 'notice',
    entityType: 'audit',
    description: 'Audit logs exported to CSV/JSON'
  },
  'audit.verified': {
    category: 'audit',
    severity: 'notice',
    entityType: 'audit',
    description: 'Cryptographic hash-chain integrity check run'
  },

  // Security Denials & Fallback
  'security.permission_denied': {
    category: 'security',
    severity: 'warning',
    entityType: 'permission',
    description: 'Unauthorized access attempt denied'
  },
  'api.mutation': {
    category: 'system',
    severity: 'info',
    entityType: 'api',
    description: 'Generic mutating API request captured by safety net'
  }
};

module.exports = {
  AUDIT_CATEGORIES,
  AUDIT_EVENT_CATALOGUE
};
