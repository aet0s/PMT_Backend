const { getDevSingleDb } = require('./tenantPools');
const { NOTIFICATION_EVENTS } = require('./notificationEvents');

/**
 * Resolves recipient user IDs for a given notification event
 */
async function resolveRecipients(eventType, ctx = {}, dbInstance = null) {
  const db = dbInstance || getDevSingleDb();
  const eventConfig = NOTIFICATION_EVENTS[eventType];
  if (!eventConfig) return [];

  const recipientType = eventConfig.recipients;
  let userIds = [];

  try {
    switch (recipientType) {
      case 'targetUser': {
        if (ctx.targetUserId) userIds = [ctx.targetUserId];
        break;
      }
      case 'invitee': {
        if (ctx.inviteeUserId) userIds = [ctx.inviteeUserId];
        break;
      }
      case 'cardMembers': {
        if (ctx.cardId) {
          const res = await db.query(
            'SELECT user_id FROM card_members WHERE card_id = ?',
            [ctx.cardId]
          );
          userIds = res.map((r) => r.user_id);
        }
        break;
      }
      case 'cardMembersExcludingMentioned': {
        if (ctx.cardId) {
          const mentioned = Array.isArray(ctx.mentionedUserIds) ? ctx.mentionedUserIds : [];
          let query = 'SELECT user_id FROM card_members WHERE card_id = ?';
          const params = [ctx.cardId];

          if (mentioned.length > 0) {
            query += ' AND user_id NOT IN (?)';
            params.push(mentioned);
          }

          const res = await db.query(query, params);
          userIds = res.map((r) => r.user_id);
        }
        break;
      }
      case 'mentionedUsers': {
        if (Array.isArray(ctx.mentionedUserIds)) {
          userIds = ctx.mentionedUserIds;
        }
        break;
      }
      case 'boardMembers': {
        if (ctx.boardId) {
          const res = await db.query(
            'SELECT user_id FROM board_members WHERE board_id = ?',
            [ctx.boardId]
          );
          userIds = res.map((r) => r.user_id);
        }
        break;
      }
      case 'workspaceAdmins': {
        if (ctx.workspaceId) {
          const res = await db.query(
            `SELECT wm.user_id 
             FROM workspace_members wm
             LEFT JOIN roles r ON wm.role_id = r.id
             WHERE wm.workspace_id = ? AND (r.name IN ('Super Admin', 'Manager') OR wm.role = 'admin' OR wm.role = 'Super Admin')`,
            [ctx.workspaceId]
          );
          userIds = res.map((r) => r.user_id);
        }
        break;
      }
      default:
        userIds = [];
    }

    // Clean & Deduplicate IDs
    const cleanIds = Array.from(new Set(userIds.map(Number).filter((id) => !isNaN(id) && id > 0)));

    // Recipient Safety Guard: Ensure target users still belong to workspace if workspaceId is present
    if (ctx.workspaceId && cleanIds.length > 0) {
      const validWsMembers = await db.query(
        'SELECT user_id FROM workspace_members WHERE workspace_id = ? AND user_id IN (?)',
        [ctx.workspaceId, cleanIds]
      );
      const validSet = new Set(validWsMembers.map((r) => r.user_id));
      return cleanIds.filter((id) => validSet.has(id));
    }

    return cleanIds;
  } catch (err) {
    console.error(`Error resolving recipients for event ${eventType}:`, err);
    return [];
  }
}

module.exports = { resolveRecipients };
