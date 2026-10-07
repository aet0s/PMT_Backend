// server/src/services/notificationEvents.js
// Single source-of-truth catalogue of all 66 atomic notification events.
// Every event declares category, recipients rule, requiredPermission (real registry key, never null),
// template, metaFields, coalescingPolicy, and deepLink.

const NOTIFICATION_EVENTS = {
  // ==========================================
  // --- BOARDS (12 events) ---
  // ==========================================
  'board.created': {
    category: 'Boards',
    recipients: 'workspaceMembers',
    requiredPermission: 'project.view',
    template: '{actor} created board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'board.renamed': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} renamed board to "{boardName}"',
    metaFields: ['boardName', 'oldName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}'
  },
  'board.background_changed': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} changed the background of board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}'
  },
  'board.archived': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} archived board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'board.restored': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} restored board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'board.deleted': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} deleted board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}'
  },
  'board.member_added': {
    category: 'Boards',
    recipients: 'targetUser',
    requiredPermission: 'project.view',
    template: '{actor} added you to board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'board.member_removed': {
    category: 'Boards',
    recipients: 'targetUser',
    requiredPermission: 'project.view',
    template: '{actor} removed you from board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}'
  },
  'board.label_created': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'label.view',
    template: '{actor} created label "{labelName}" on board "{boardName}"',
    metaFields: ['boardName', 'labelName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },

  // ==========================================
  // --- LISTS (5 events) ---
  // ==========================================
  'list.created': {
    category: 'Lists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} created list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'list.renamed': {
    category: 'Lists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} renamed list to "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'oldTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}'
  },
  'list.moved': {
    category: 'Lists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} moved list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}'
  },
  'list.archived': {
    category: 'Lists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} archived list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'list.deleted': {
    category: 'Lists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} deleted list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },

  // ==========================================
  // --- CARDS (19 events) ---
  // ==========================================
  'card.created': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} created task "{cardTitle}" in "{boardName}"',
    metaFields: ['cardTitle', 'boardName', 'listTitle'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.renamed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} renamed task to "{cardTitle}"',
    metaFields: ['cardTitle', 'oldTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.description_changed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} updated the description of "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.due_date_set': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} set due date on "{cardTitle}" to {dueDate}',
    metaFields: ['cardTitle', 'dueDate', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.due_date_changed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} changed due date on "{cardTitle}" to {dueDate}',
    metaFields: ['cardTitle', 'dueDate', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.due_date_removed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} removed due date from "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.completed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} marked "{cardTitle}" as complete',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.reopened': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} reopened "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.moved': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} moved "{cardTitle}" from {fromList} to {toList}',
    metaFields: ['cardTitle', 'fromList', 'toList', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.archived': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} archived "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'card.restored': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} restored "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.deleted': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} deleted "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}'
  },
  'card.copied': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} copied card to "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.cover_changed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} changed cover of "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.assigned': {
    category: 'Cards',
    recipients: 'targetUser',
    requiredPermission: 'task.view',
    template: '{actor} assigned you to "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.unassigned': {
    category: 'Cards',
    recipients: 'targetUser',
    requiredPermission: 'task.view',
    template: '{actor} removed you from "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.label_added': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} added label "{labelName}" to "{cardTitle}"',
    metaFields: ['cardTitle', 'labelName', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.label_removed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} removed label "{labelName}" from "{cardTitle}"',
    metaFields: ['cardTitle', 'labelName', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },

  // ==========================================
  // --- CHECKLISTS (9 events) ---
  // ==========================================
  'checklist.created': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} added checklist "{checklistTitle}" to "{cardTitle}"',
    metaFields: ['checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist.deleted': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} removed checklist "{checklistTitle}" from "{cardTitle}"',
    metaFields: ['checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist_item.added': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} added "{itemText}" to {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist_item.edited': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} edited "{itemText}" in {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist_item.deleted': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} deleted item "{itemText}" from {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist_item.completed': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} completed "{itemText}" from {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist_item.reopened': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} reopened "{itemText}" from {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'checklist.completed_all': {
    category: 'Checklists',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} completed all items in {checklistTitle} on "{cardTitle}"',
    metaFields: ['checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },

  // ==========================================
  // --- COMMENTS & ATTACHMENTS (6 events) ---
  // ==========================================
  'comment.added': {
    category: 'Comments & Attachments',
    recipients: 'cardMembersExcludingMentioned',
    requiredPermission: 'comment.view',
    template: '{actor} commented on "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'comment.deleted': {
    category: 'Comments & Attachments',
    recipients: 'cardMembers',
    requiredPermission: 'comment.view',
    template: '{actor} deleted comment on "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'comment.mention': {
    category: 'Comments & Attachments',
    recipients: 'mentionedUsers',
    requiredPermission: 'comment.view',
    template: '{actor} mentioned you in a comment on "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'attachment.added': {
    category: 'Comments & Attachments',
    recipients: 'boardMembers',
    requiredPermission: 'attachment.view',
    template: '{actor} attached "{fileName}" to "{cardTitle}"',
    metaFields: ['fileName', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'attachment.removed': {
    category: 'Comments & Attachments',
    recipients: 'boardMembers',
    requiredPermission: 'attachment.view',
    template: '{actor} removed attachment "{fileName}" from "{cardTitle}"',
    metaFields: ['fileName', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },

  // ==========================================
  // --- DUE DATES & REMINDERS (2 events) ---
  // ==========================================
  'card.due_soon': {
    category: 'Due Dates',
    recipients: 'cardAssigneesOrCreator',
    requiredPermission: 'task.view',
    template: '"{cardTitle}" is due {relativeDueTime}',
    metaFields: ['cardTitle', 'relativeDueTime', 'dueDate', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },
  'card.overdue': {
    category: 'Due Dates',
    recipients: 'cardAssigneesOrCreator',
    requiredPermission: 'task.view',
    template: '"{cardTitle}" is overdue',
    metaFields: ['cardTitle', 'dueDate', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}'
  },

  // ==========================================
  // --- WORKSPACE & SECURITY (13 events) ---
  // ==========================================
  'workspace.member_added': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: '{actor} added you to workspace "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}'
  },
  'workspace.member_removed': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: '{actor} removed you from workspace "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/'
  },
  'workspace.member_role_changed': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: '{actor} changed your role to {roleName} in "{workspaceName}"',
    metaFields: ['workspaceName', 'roleName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}'
  },
  'invite.sent': {
    category: 'Workspace & Security',
    recipients: 'invitee',
    requiredPermission: 'member.view',
    template: '{actor} invited you to join "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/invite/{token}'
  },
  'invite.accepted': {
    category: 'Workspace & Security',
    recipients: 'workspaceMembers',
    requiredPermission: 'member.view',
    template: '{actor} accepted the invite and joined "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}'
  },
  'invite.revoked': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: 'Invitation for {email} to "{workspaceName}" was revoked',
    metaFields: ['workspaceName', 'email'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}'
  },
  'role.created': {
    category: 'Workspace & Security',
    recipients: 'workspaceMembers',
    requiredPermission: 'role.view',
    template: '{actor} created custom role "{roleName}"',
    metaFields: ['roleName', 'workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}/settings/roles'
  },
  'role.updated': {
    category: 'Workspace & Security',
    recipients: 'workspaceMembers',
    requiredPermission: 'role.view',
    template: '{actor} updated role "{roleName}"',
    metaFields: ['roleName', 'workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}/settings/roles'
  },
  'role.deleted': {
    category: 'Workspace & Security',
    recipients: 'workspaceMembers',
    requiredPermission: 'role.view',
    template: '{actor} deleted role "{roleName}"',
    metaFields: ['roleName', 'workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}/settings/roles'
  },
  'security.admin_password_reset': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: 'Your password was reset by an administrator',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/profile'
  },
  'security.two_factor_reset': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: 'Your two-factor authentication was reset by an administrator',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/profile'
  },
  'security.new_device_session': {
    category: 'Workspace & Security',
    recipients: 'targetUser',
    requiredPermission: 'session.view_own',
    template: 'New login session established from {deviceInfo}',
    metaFields: ['deviceInfo', 'ipAddress'],
    coalescingPolicy: 'immediate',
    deepLink: '/profile/sessions'
  }
};

const EVENT_CATEGORIES = [
  'Boards',
  'Lists',
  'Cards',
  'Checklists',
  'Comments & Attachments',
  'Due Dates',
  'Workspace & Security'
];

/**
 * Renders template string using meta object and actor name
 * Function replacers are strictly used so user text containing "$&", "$`", "$'", "$1" stays 100% literal.
 */
function renderMessage(eventType, meta = {}, actorName = 'Someone') {
  const eventConfig = NOTIFICATION_EVENTS[eventType];
  if (!eventConfig) {
    return meta.customMessage || `${actorName} performed an action`;
  }

  let text = eventConfig.template;
  const data = {
    actor: actorName || 'Someone',
    workspace: meta.workspaceName || meta.workspace || 'Workspace',
    workspaceName: meta.workspaceName || meta.workspace || 'Workspace',
    roleName: meta.roleName || 'Member',
    boardName: meta.boardName || 'Board',
    cardTitle: meta.cardTitle || meta.card_title || 'Card',
    listTitle: meta.listTitle || meta.title || 'List',
    fromList: meta.fromList || 'List',
    toList: meta.toList || 'List',
    dueDate: meta.dueDate || meta.due_date || 'soon',
    relativeDueTime: meta.relativeDueTime || 'soon',
    itemText: meta.itemText || 'item',
    checklistTitle: meta.checklistTitle || 'Checklist',
    fileName: meta.fileName || 'file',
    labelName: meta.labelName || 'label',
    targetBoardName: meta.targetBoardName || 'Board',
    deviceInfo: meta.deviceInfo || 'a new browser',
    ipAddress: meta.ipAddress || 'unknown IP',
    email: meta.email || 'user',
    count: meta.count || 1,
    ...meta
  };

  Object.keys(data).forEach((key) => {
    const placeholder = `{${key}}`;
    text = text.replace(new RegExp(placeholder, 'g'), () => String(data[key] ?? ''));
  });

  return text;
}

module.exports = {
  NOTIFICATION_EVENTS,
  EVENT_CATEGORIES,
  renderMessage
};
