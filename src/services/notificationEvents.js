/**
 * Single source-of-truth catalog of 20 atomic notification events.
 */

const NOTIFICATION_EVENTS = {
  // --- Invitations & Workspace ---
  'invite.sent': {
    category: 'Invites & Workspace',
    recipients: 'invitee',
    template: '{actor} invited you to join {workspace}'
  },
  'invite.accepted': {
    category: 'Invites & Workspace',
    recipients: 'workspaceAdmins',
    template: '{actor} accepted the invite and joined {workspace}'
  },
  'member.role_changed': {
    category: 'Invites & Workspace',
    recipients: 'targetUser',
    template: '{actor} changed your role to {roleName} in {workspace}'
  },
  'member.removed': {
    category: 'Invites & Workspace',
    recipients: 'targetUser',
    template: '{actor} removed you from {workspace}'
  },

  // --- Boards ---
  'board.member_added': {
    category: 'Boards',
    recipients: 'targetUser',
    template: '{actor} added you to the board "{boardName}"'
  },
  'board.member_removed': {
    category: 'Boards',
    recipients: 'targetUser',
    template: '{actor} removed you from the board "{boardName}"'
  },
  'board.archived': {
    category: 'Boards',
    recipients: 'boardMembers',
    template: '{actor} archived the board "{boardName}"'
  },

  // --- Cards ---
  'card.assigned': {
    category: 'Cards',
    recipients: 'targetUser',
    template: '{actor} assigned you to "{cardTitle}"'
  },
  'card.unassigned': {
    category: 'Cards',
    recipients: 'targetUser',
    template: '{actor} removed you from "{cardTitle}"'
  },
  'card.moved': {
    category: 'Cards',
    recipients: 'cardMembers',
    template: '{actor} moved "{cardTitle}" from {fromList} to {toList}'
  },
  'card.due_soon': {
    category: 'Due Dates',
    recipients: 'cardMembers',
    template: '"{cardTitle}" is due {relativeDueTime}'
  },
  'card.overdue': {
    category: 'Due Dates',
    recipients: 'cardMembers',
    template: '"{cardTitle}" is overdue'
  },
  'card.completed': {
    category: 'Cards',
    recipients: 'cardMembers',
    template: '{actor} marked "{cardTitle}" as complete'
  },
  'card.deleted': {
    category: 'Cards',
    recipients: 'cardMembers',
    template: '{actor} deleted "{cardTitle}"'
  },

  // --- Checklists ---
  'checklist_item.completed': {
    category: 'Checklists',
    recipients: 'cardMembers',
    template: '{actor} completed "{itemText}" from {checklistTitle} on "{cardTitle}"'
  },
  'checklist_item.reopened': {
    category: 'Checklists',
    recipients: 'cardMembers',
    template: '{actor} reopened "{itemText}" from {checklistTitle} on "{cardTitle}"'
  },
  'checklist.completed_all': {
    category: 'Checklists',
    recipients: 'cardMembers',
    template: '{actor} completed all items in {checklistTitle} on "{cardTitle}"'
  },

  // --- Comments & Mentions ---
  'comment.added': {
    category: 'Comments & Mentions',
    recipients: 'cardMembersExcludingMentioned',
    template: '{actor} commented on "{cardTitle}"'
  },
  'comment.mention': {
    category: 'Comments & Mentions',
    recipients: 'mentionedUsers',
    template: '{actor} mentioned you in a comment on "{cardTitle}"'
  },

  // --- Attachments & Labels ---
  'attachment.added': {
    category: 'Attachments & Labels',
    recipients: 'cardMembers',
    template: '{actor} attached "{fileName}" to "{cardTitle}"'
  },
  'label.added': {
    category: 'Attachments & Labels',
    recipients: 'cardMembers',
    template: '{actor} added the "{labelName}" label to "{cardTitle}"'
  }
};

const EVENT_CATEGORIES = [
  'Invites & Workspace',
  'Boards',
  'Cards',
  'Due Dates',
  'Checklists',
  'Comments & Mentions',
  'Attachments & Labels'
];

/**
 * Renders template string using meta object and actor name
 */
function renderMessage(eventType, meta = {}, actorName = 'Someone') {
  const eventConfig = NOTIFICATION_EVENTS[eventType];
  if (!eventConfig) {
    return meta.customMessage || `${actorName} performed an action`;
  }

  let text = eventConfig.template;
  const data = {
    actor: actorName || 'Someone',
    workspace: meta.workspaceName || 'Workspace',
    roleName: meta.roleName || 'Member',
    boardName: meta.boardName || 'Board',
    cardTitle: meta.cardTitle || 'Card',
    fromList: meta.fromList || 'List',
    toList: meta.toList || 'List',
    relativeDueTime: meta.relativeDueTime || 'soon',
    itemText: meta.itemText || 'item',
    checklistTitle: meta.checklistTitle || 'Checklist',
    fileName: meta.fileName || 'file',
    labelName: meta.labelName || 'label',
    count: meta.count || 1,
    ...meta
  };

  Object.keys(data).forEach((key) => {
    const placeholder = `{${key}}`;
    text = text.replace(new RegExp(placeholder, 'g'), data[key]);
  });

  return text;
}

module.exports = {
  NOTIFICATION_EVENTS,
  EVENT_CATEGORIES,
  renderMessage
};
