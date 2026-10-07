const { notify, insertAndDeliverNotification } = require('./notify');

module.exports = {
  notify,
  createNotification: async ({ userId, type, cardId, boardId, actorUserId, message, db, tenantId }) => {
    return insertAndDeliverNotification(
      userId,
      type || 'system',
      message || 'Notification',
      { customMessage: message },
      { cardId, boardId, actorUserId },
      'System',
      db,
      tenantId
    );
  },
  notifyOnComment: async ({ cardId, boardId, commentBody, authorUserId, authorName, mentionedUserIds = [] }) => {
    return notify({
      eventType: 'comment.added',
      actorUserId: authorUserId,
      boardId,
      cardId,
      mentionedUserIds,
      meta: { actorName }
    });
  },
  notifyOnAssignment: async ({ cardId, boardId, targetUserId, actorUserId, actorName }) => {
    return notify({
      eventType: 'card.assigned',
      actorUserId,
      boardId,
      cardId,
      targetUserId,
      meta: { actorName }
    });
  }
};
