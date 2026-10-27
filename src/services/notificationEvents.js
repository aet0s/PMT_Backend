// server/src/services/notificationEvents.js
// Single source-of-truth catalogue of all 59 atomic notification events.
// 17 core events are notifiable (notifiable: true). All other 42 events have notifiable: false.
// Every event declares category ('Workspace', 'Boards', or 'Cards'), recipients rule,
// requiredPermission, template, metaFields, coalescingPolicy, and deepLink.

const NOTIFICATION_EVENTS = {
  // ==========================================
  // --- BOARDS (9 events, 5 notifiable) ---
  // ==========================================
  'board.created': {
    category: 'Boards',
    recipients: 'workspaceProjectAccessAll',
    requiredPermission: 'project.view',
    template: '{actor} created board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: true
  },
  'board.renamed': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} renamed board to "{boardName}"',
    metaFields: ['boardName', 'oldName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'board.background_changed': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} changed the background of board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'board.archived': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} archived board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: true
  },
  'board.restored': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} restored board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'board.deleted': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'project.view',
    template: '{actor} deleted board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}',
    notifiable: true
  },
  'board.member_added': {
    category: 'Boards',
    recipients: 'targetUser',
    requiredPermission: 'project.view',
    template: '{actor} added you to board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: true
  },
  'board.member_removed': {
    category: 'Boards',
    recipients: 'targetUser',
    requiredPermission: 'project.view',
    template: '{actor} removed you from board "{boardName}"',
    metaFields: ['boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}',
    notifiable: true
  },
  'board.label_created': {
    category: 'Boards',
    recipients: 'boardMembers',
    requiredPermission: 'label.view',
    template: '{actor} created label "{labelName}" on board "{boardName}"',
    metaFields: ['boardName', 'labelName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: false
  },

  // ==========================================
  // --- LISTS (5 events, 0 notifiable) ---
  // ==========================================
  'list.created': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} created list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'list.renamed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} renamed list to "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'oldTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'list.moved': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} moved list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'list.archived': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} archived list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: false
  },
  'list.deleted': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} deleted list "{listTitle}" in "{boardName}"',
    metaFields: ['listTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: false
  },

  // ==========================================
  // --- CARDS (18 events, 5 notifiable) ---
  // ==========================================
  'card.created': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} created task "{cardTitle}" in "{boardName}"',
    metaFields: ['cardTitle', 'boardName', 'listTitle'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.renamed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} renamed task to "{cardTitle}"',
    metaFields: ['cardTitle', 'oldTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.description_changed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} updated the description of "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.due_date_set': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} set due date on "{cardTitle}" to {dueDate}',
    metaFields: ['cardTitle', 'dueDate', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.due_date_changed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} changed due date on "{cardTitle}" to {dueDate}',
    metaFields: ['cardTitle', 'dueDate', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.due_date_removed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} removed due date from "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.completed': {
    category: 'Cards',
    recipients: 'cardAssigneesAndCreator',
    requiredPermission: 'task.view',
    template: '{actor} marked "{cardTitle}" as complete',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'card.reopened': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} reopened "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.moved': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} moved "{cardTitle}" from {fromList} to {toList}',
    metaFields: ['cardTitle', 'fromList', 'toList', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.submitted_for_review': {
    category: 'Cards',
    recipients: 'cardAssignersOnly',
    requiredPermission: 'task.view',
    template: '{actor} submitted task "{cardTitle}" for your review',
    metaFields: ['cardTitle', 'fromList', 'toList', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'card.changes_requested': {
    category: 'Cards',
    recipients: 'cardAssigneesOnly',
    requiredPermission: 'task.view',
    template: '{actor} returned "{cardTitle}" to In Progress for revision{feedbackText}',
    metaFields: ['cardTitle', 'fromList', 'toList', 'boardName', 'feedbackText'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'card.archived': {
    category: 'Cards',
    recipients: 'cardAssigneesAndCreator',
    requiredPermission: 'task.view',
    template: '{actor} archived "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: true
  },
  'card.restored': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} restored "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.deleted': {
    category: 'Cards',
    recipients: 'cardAssigneesAndCreator',
    requiredPermission: 'task.view',
    template: '{actor} deleted "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}',
    notifiable: true
  },
  'card.copied': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} copied card to "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.cover_changed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} changed cover of "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.assigned': {
    category: 'Cards',
    recipients: 'targetUser',
    requiredPermission: 'task.view',
    template: '{actor} assigned you to "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'card.unassigned': {
    category: 'Cards',
    recipients: 'targetUser',
    requiredPermission: 'task.view',
    template: '{actor} removed you from "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'card.label_added': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} added label "{labelName}" to "{cardTitle}"',
    metaFields: ['cardTitle', 'labelName', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'card.label_removed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} removed label "{labelName}" from "{cardTitle}"',
    metaFields: ['cardTitle', 'labelName', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },

  // ==========================================
  // --- CHECKLISTS (8 events, 0 notifiable) ---
  // ==========================================
  'checklist.created': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} added checklist "{checklistTitle}" to "{cardTitle}"',
    metaFields: ['checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist.deleted': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} removed checklist "{checklistTitle}" from "{cardTitle}"',
    metaFields: ['checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist_item.added': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} added "{itemText}" to {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist_item.edited': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} edited "{itemText}" in {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist_item.deleted': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} deleted item "{itemText}" from {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist_item.completed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} completed "{itemText}" from {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist_item.reopened': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} reopened "{itemText}" from {checklistTitle} on "{cardTitle}"',
    metaFields: ['itemText', 'checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'coalesce_60s',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'checklist.completed_all': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'task.view',
    template: '{actor} completed all items in {checklistTitle} on "{cardTitle}"',
    metaFields: ['checklistTitle', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },

  // ==========================================
  // --- COMMENTS & ATTACHMENTS (5 events, 2 notifiable) ---
  // ==========================================
  'comment.added': {
    category: 'Cards',
    recipients: 'commentAddedRecipients',
    requiredPermission: 'comment.view',
    template: '{actor} commented on "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'comment.deleted': {
    category: 'Cards',
    recipients: 'cardMembers',
    requiredPermission: 'comment.view',
    template: '{actor} deleted comment on "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'comment.mention': {
    category: 'Cards',
    recipients: 'mentionedUsers',
    requiredPermission: 'comment.view',
    template: '{actor} mentioned you in a comment on "{cardTitle}"',
    metaFields: ['cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'attachment.added': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'attachment.view',
    template: '{actor} attached "{fileName}" to "{cardTitle}"',
    metaFields: ['fileName', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },
  'attachment.removed': {
    category: 'Cards',
    recipients: 'boardMembers',
    requiredPermission: 'attachment.view',
    template: '{actor} removed attachment "{fileName}" from "{cardTitle}"',
    metaFields: ['fileName', 'cardTitle', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: false
  },

  // ==========================================
  // --- DUE DATES & REMINDERS (2 events, 2 notifiable) ---
  // ==========================================
  'card.due_soon': {
    category: 'Cards',
    recipients: 'cardAssigneesOrCreator',
    requiredPermission: 'task.view',
    template: '"{cardTitle}" is due {relativeDueTime}',
    metaFields: ['cardTitle', 'relativeDueTime', 'dueDate', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'card.overdue': {
    category: 'Cards',
    recipients: 'cardAssigneesOrCreator',
    requiredPermission: 'task.view',
    template: '"{cardTitle}" is overdue',
    metaFields: ['cardTitle', 'dueDate', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true
  },
  'checkin.due': {
    category: 'Cards',
    recipients: 'targetUser',
    requiredPermission: 'task.view',
    template: 'Daily check-in is due for your focused card "{cardTitle}"',
    metaFields: ['cardTitle', 'cardId', 'boardName'],
    coalescingPolicy: 'immediate',
    deepLink: '/b/{boardId}?card={cardId}',
    notifiable: true,
    personal: true,
    noSound: true
  },

  // ==========================================
  // --- WORKSPACE & SECURITY (12 events, 3 notifiable) ---
  // ==========================================
  'workspace.member_added': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: '{actor} added you to workspace "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}',
    notifiable: true
  },
  'workspace.member_removed': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: '{actor} removed you from workspace "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/',
    notifiable: true
  },
  'workspace.member_role_changed': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: '{actor} changed your role to {roleName} in "{workspaceName}"',
    metaFields: ['workspaceName', 'roleName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}',
    notifiable: true
  },
  'invite.sent': {
    category: 'Workspace',
    recipients: 'invitee',
    requiredPermission: 'member.view',
    template: '{actor} invited you to join "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/invite/{token}',
    notifiable: false
  },
  'invite.accepted': {
    category: 'Workspace',
    recipients: 'workspaceMembers',
    requiredPermission: 'member.view',
    template: '{actor} accepted the invite and joined "{workspaceName}"',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}',
    notifiable: false
  },
  'invite.revoked': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: 'Invitation for {email} to "{workspaceName}" was revoked',
    metaFields: ['workspaceName', 'email'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}',
    notifiable: false
  },
  'role.created': {
    category: 'Workspace',
    recipients: 'workspaceMembers',
    requiredPermission: 'role.view',
    template: '{actor} created custom role "{roleName}"',
    metaFields: ['roleName', 'workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}/settings/roles',
    notifiable: false
  },
  'role.updated': {
    category: 'Workspace',
    recipients: 'workspaceMembers',
    requiredPermission: 'role.view',
    template: '{actor} updated role "{roleName}"',
    metaFields: ['roleName', 'workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}/settings/roles',
    notifiable: false
  },
  'role.deleted': {
    category: 'Workspace',
    recipients: 'workspaceMembers',
    requiredPermission: 'role.view',
    template: '{actor} deleted role "{roleName}"',
    metaFields: ['roleName', 'workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/w/{workspaceId}/settings/roles',
    notifiable: false
  },
  'security.admin_password_reset': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: 'Your password was reset by an administrator',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/profile',
    notifiable: false
  },
  'security.two_factor_reset': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'member.view',
    template: 'Your two-factor authentication was reset by an administrator',
    metaFields: ['workspaceName'],
    coalescingPolicy: 'immediate',
    deepLink: '/profile',
    notifiable: false
  },
  'security.new_device_session': {
    category: 'Workspace',
    recipients: 'targetUser',
    requiredPermission: 'session.view_own',
    template: 'New login session established from {deviceInfo}',
    metaFields: ['deviceInfo', 'ipAddress'],
    coalescingPolicy: 'immediate',
    deepLink: '/profile/sessions',
    notifiable: false
  }
};

const EVENT_CATEGORIES = [
  'Workspace',
  'Boards',
  'Cards'
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
