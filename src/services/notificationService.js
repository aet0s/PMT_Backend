const { notify } = require('./notify');
const { flushSingleNotification } = require('./notifyBatcher');

module.exports = {
  notify,
  createNotification: async ({ userId, type, cardId, boardId, actorUserId, message }) => {
    return flushSingleNotification(
      userId,
      type || 'system',
      { cardId, boardId, actorUserId },
      { customMessage: message },
      'System'
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
