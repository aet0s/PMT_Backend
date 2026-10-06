const { getDevSingleDb } = require('./tenantPools');
const { NOTIFICATION_EVENTS } = require('./notificationEvents');
const { userHasPermission } = require('../middleware/permissions');

/**
 * Resolves recipient user IDs for a given notification event.
 * Ensures strict security & permission verification:
 * 1. User must be in workspace (workspace_members).
 * 2. If event is board/card scoped, user must have access to that board (board_members or workspace admin).
 * 3. User must possess the required RBAC permission for the action (e.g. task.view, comment.view).
 * If user is outside of permission/access, notification will NOT be sent to them.
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
          // If no members are assigned to this card, fallback to board members so updates are not lost
          if (userIds.length === 0 && ctx.boardId) {
            const bRes = await db.query(
              'SELECT user_id FROM board_members WHERE board_id = ?',
              [ctx.boardId]
            );
            userIds = bRes.map((r) => r.user_id);
          }
        } else if (ctx.boardId) {
          const bRes = await db.query(
            'SELECT user_id FROM board_members WHERE board_id = ?',
            [ctx.boardId]
          );
          userIds = bRes.map((r) => r.user_id);
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

          // If no card members assigned, notify all board members (excluding mentioned)
          if (userIds.length === 0 && ctx.boardId) {
            let bQuery = 'SELECT user_id FROM board_members WHERE board_id = ?';
            const bParams = [ctx.boardId];
            if (mentioned.length > 0) {
              bQuery += ' AND user_id NOT IN (?)';
              bParams.push(mentioned);
            }
            const bRes = await db.query(bQuery, bParams);
            userIds = bRes.map((r) => r.user_id);
          }
        } else if (ctx.boardId) {
          const bRes = await db.query(
            'SELECT user_id FROM board_members WHERE board_id = ?',
            [ctx.boardId]
          );
          userIds = bRes.map((r) => r.user_id);
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
             WHERE wm.workspace_id = ? AND (
               r.name IN ('Owner', 'Super Admin', 'Admin', 'Manager')
               OR wm.role IN ('admin', 'Super Admin', 'Owner')
               OR EXISTS (
                 SELECT 1 FROM role_permissions rp
                 JOIN permissions p ON rp.permission_id = p.id
                 WHERE rp.role_id = wm.role_id AND p.key IN ('member.view', 'workspace.edit_settings')
               )
             )`,
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
    let cleanIds = Array.from(new Set(userIds.map(Number).filter((id) => !isNaN(id) && id > 0)));

    // 1. Workspace Safety Guard: Ensure target users belong to workspace (unless invite.sent)
    if (ctx.workspaceId && cleanIds.length > 0 && eventType !== 'invite.sent') {
      const validWsMembers = await db.query(
        'SELECT user_id FROM workspace_members WHERE workspace_id = ? AND user_id IN (?)',
        [ctx.workspaceId, cleanIds]
      );
      const validSet = new Set(validWsMembers.map((r) => r.user_id));
      cleanIds = cleanIds.filter((id) => validSet.has(id));
    }

    // 2. Board Authorization Guard: If event is board or card scoped, user must have access to that board
    // (Workspace Admin, Owner, or direct board_member). Exclude board.member_removed, board.member_added, and card.assigned so assigned user gets notice.
    if (ctx.boardId && ctx.workspaceId && cleanIds.length > 0 && eventType !== 'board.member_removed' && eventType !== 'board.member_added' && eventType !== 'card.assigned') {
      const authorizedBoardUsers = await db.query(
        `SELECT wm.user_id
         FROM workspace_members wm
         LEFT JOIN roles r ON wm.role_id = r.id
         LEFT JOIN board_members bm ON bm.board_id = ? AND bm.user_id = wm.user_id
         WHERE wm.workspace_id = ? AND wm.user_id IN (?)
           AND (
             r.name IN ('Owner', 'Super Admin', 'Admin')
             OR EXISTS (
               SELECT 1 FROM role_permissions rp
               JOIN permissions p ON rp.permission_id = p.id
               WHERE rp.role_id = wm.role_id AND p.key IN ('workspace.edit_settings', 'workspace.delete')
             )
             OR bm.user_id IS NOT NULL
           )`,
        [ctx.boardId, ctx.workspaceId, cleanIds]
      );
      const authorizedSet = new Set(authorizedBoardUsers.map((r) => r.user_id));
      cleanIds = cleanIds.filter((id) => authorizedSet.has(id));
    }

    // 3. RBAC Permission Guard: If event has required permission, verify user has it
    if (eventConfig.requiredPermission && ctx.workspaceId && cleanIds.length > 0) {
      const permittedIds = [];
      for (const id of cleanIds) {
        const hasPerm = await userHasPermission(id, ctx.workspaceId, eventConfig.requiredPermission, db, ctx.boardId);
        if (hasPerm) {
          permittedIds.push(id);
        }
      }
      cleanIds = permittedIds;
    }

    return cleanIds;
  } catch (err) {
    console.error(`Error resolving recipients for event ${eventType}:`, err);
    return [];
  }
}

module.exports = { resolveRecipients };
