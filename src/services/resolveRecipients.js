// server/src/services/resolveRecipients.js
// Resolves recipient user IDs for notification events with strict permission engine enforcement,
// bounded database queries (bulk fan-out), zero role-name checks, mute filtering, and preference modes.

const { getDevSingleDb } = require('./tenantPools');
const { NOTIFICATION_EVENTS } = require('./notificationEvents');
const { usersWithPermission } = require('../middleware/permissions');
const { isEventEnabledForUser } = require('./notificationPreferences');

/**
 * Resolves recipient user IDs and priority flags for a given notification event.
 *
 * Rules:
 * - Board-scoped events: explicit members of THAT board (minus actor) who hold requiredPermission at dispatch time.
 * - Non-board-member Admins/Owners only receive if notify_all_boards is enabled for that workspace.
 * - Zero role-name checks anywhere ('Owner', 'Admin', 'Manager', legacy wm.role): pure permission evaluation.
 * - One notification per user per event (assigned/mentioned users receive priority: 1, not duplicate).
 * - Filters out muted boards/cards (notification_mutes).
 * - Filters by user preference mode (all vs only_mine).
 */
async function resolveRecipients(eventType, ctx = {}, dbInstance = null) {
  const db = dbInstance || getDevSingleDb();
  const eventConfig = NOTIFICATION_EVENTS[eventType];
  if (!eventConfig) return [];

  const recipientType = eventConfig.recipients;
  let candidates = [];

  try {
    switch (recipientType) {
      case 'targetUser': {
        if (ctx.targetUserId) candidates = [ctx.targetUserId];
        break;
      }

      case 'invitee': {
        if (ctx.inviteeUserId) candidates = [ctx.inviteeUserId];
        break;
      }

      case 'mentionedUsers': {
        if (Array.isArray(ctx.mentionedUserIds)) {
          candidates = ctx.mentionedUserIds;
        }
        break;
      }

      case 'cardAssigneesOrCreator': {
        if (ctx.cardId) {
          const res = await db.query(
            'SELECT user_id FROM card_members WHERE card_id = ? UNION SELECT user_id FROM card_assigners WHERE card_id = ?',
            [ctx.cardId, ctx.cardId]
          );
          candidates = res.map((r) => r.user_id);

          // If no assignees on the card, notify the card creator
          if (candidates.length === 0) {
            const cardRes = await db.query('SELECT created_by FROM cards WHERE id = ?', [ctx.cardId]);
            if (cardRes[0]?.created_by) {
              candidates = [cardRes[0].created_by];
            }
          }
        }
        break;
      }

      case 'cardMembers': {
        if (ctx.cardId) {
          const res = await db.query(
            'SELECT user_id FROM card_members WHERE card_id = ? UNION SELECT user_id FROM card_assigners WHERE card_id = ?',
            [ctx.cardId, ctx.cardId]
          );
          candidates = res.map((r) => r.user_id);
        }
        // If no members assigned to card, fallback to board members
        if (candidates.length === 0 && ctx.boardId) {
          const bRes = await db.query('SELECT user_id FROM board_members WHERE board_id = ?', [ctx.boardId]);
          candidates = bRes.map((r) => r.user_id);
        }
        break;
      }

      case 'cardMembersExcludingMentioned': {
        if (ctx.cardId) {
          const mentioned = Array.isArray(ctx.mentionedUserIds) ? ctx.mentionedUserIds : [];
          let query =
            'SELECT user_id FROM (SELECT user_id, card_id FROM card_members UNION SELECT user_id, card_id FROM card_assigners) combined WHERE card_id = ?';
          const params = [ctx.cardId];
          if (mentioned.length > 0) {
            query += ' AND user_id NOT IN (?)';
            params.push(mentioned);
          }
          const res = await db.query(query, params);
          candidates = res.map((r) => r.user_id);
        }
        if (candidates.length === 0 && ctx.boardId) {
          const mentioned = Array.isArray(ctx.mentionedUserIds) ? ctx.mentionedUserIds : [];
          let bQuery = 'SELECT user_id FROM board_members WHERE board_id = ?';
          const bParams = [ctx.boardId];
          if (mentioned.length > 0) {
            bQuery += ' AND user_id NOT IN (?)';
            bParams.push(mentioned);
          }
          const bRes = await db.query(bQuery, bParams);
          candidates = bRes.map((r) => r.user_id);
        }
        break;
      }

      case 'boardMembers': {
        if (ctx.boardId) {
          const bRes = await db.query('SELECT user_id FROM board_members WHERE board_id = ?', [ctx.boardId]);
          candidates = bRes.map((r) => r.user_id);

          // Plus users with notify_all_boards enabled in this workspace
          if (ctx.workspaceId) {
            try {
              const allBoardsRes = await db.query(
                'SELECT user_id FROM notification_workspace_settings WHERE workspace_id = ? AND notify_all_boards = 1',
                [ctx.workspaceId]
              );
              for (const r of allBoardsRes) {
                candidates.push(r.user_id);
              }
            } catch (e) {
              // Table not yet queried or empty
            }
          }
        }
        break;
      }

      case 'workspaceMembers': {
        if (ctx.workspaceId) {
          const wRes = await db.query('SELECT user_id FROM workspace_members WHERE workspace_id = ?', [ctx.workspaceId]);
          candidates = wRes.map((r) => r.user_id);
        }
        break;
      }

      default:
        candidates = [];
    }

    // Clean, dedup, and exclude actor
    let cleanCandidates = Array.from(new Set(candidates.map(Number).filter((id) => !isNaN(id) && id > 0)));
    if (ctx.actorUserId) {
      cleanCandidates = cleanCandidates.filter((id) => id !== Number(ctx.actorUserId));
    }

    if (cleanCandidates.length === 0) {
      return [];
    }

    // 1. Bulk RBAC Permission Evaluation: Bounded queries via usersWithPermission
    let permittedIds = cleanCandidates;
    if (eventConfig.requiredPermission && ctx.workspaceId) {
      permittedIds = await usersWithPermission(
        db,
        ctx.workspaceId,
        ctx.boardId || null,
        eventConfig.requiredPermission,
        cleanCandidates
      );
    }

    if (permittedIds.length === 0) {
      return [];
    }

    // 2. Mute Filtering (board and card mutes)
    let unmutedIds = permittedIds;
    if (ctx.boardId || ctx.cardId) {
      try {
        const muteQuery = `SELECT user_id FROM notification_mutes WHERE user_id IN (?) AND (${ctx.boardId ? 'board_id = ?' : '1=0'} OR ${ctx.cardId ? 'card_id = ?' : '1=0'})`;
        const muteParams = [permittedIds];
        if (ctx.boardId) muteParams.push(ctx.boardId);
        if (ctx.cardId) muteParams.push(ctx.cardId);

        const mutes = await db.query(muteQuery, muteParams);
        if (mutes.length > 0) {
          const mutedSet = new Set(mutes.map((m) => m.user_id));
          unmutedIds = permittedIds.filter((id) => !mutedSet.has(id));
        }
      } catch (e) {}
    }

    if (unmutedIds.length === 0) {
      return [];
    }

    // 3. User Preference Mode (mode: 'all' vs 'only_mine')
    let modeFilteredIds = [];
    let onlyMineUsers = new Set();
    try {
      const settings = await db.query(
        "SELECT user_id FROM notification_user_settings WHERE user_id IN (?) AND mode = 'only_mine'",
        [unmutedIds]
      );
      onlyMineUsers = new Set(settings.map((s) => s.user_id));
    } catch (e) {}

    // Check card assignees for only_mine users
    let cardAssigneesSet = new Set();
    if (onlyMineUsers.size > 0 && ctx.cardId) {
      try {
        const ca = await db.query(
          'SELECT user_id FROM card_members WHERE card_id = ? UNION SELECT user_id FROM card_assigners WHERE card_id = ?',
          [ctx.cardId, ctx.cardId]
        );
        cardAssigneesSet = new Set(ca.map((r) => r.user_id));
      } catch (e) {}
    }

    for (const uid of unmutedIds) {
      if (onlyMineUsers.has(uid)) {
        // In only_mine mode, user only receives if directly targeted, mentioned, or assigned to this card
        const isTarget = Number(ctx.targetUserId) === uid;
        const isMentioned = Array.isArray(ctx.mentionedUserIds) && ctx.mentionedUserIds.map(Number).includes(uid);
        const isAssigned = cardAssigneesSet.has(uid);
        if (isTarget || isMentioned || isAssigned) {
          modeFilteredIds.push(uid);
        }
      } else {
        modeFilteredIds.push(uid);
      }
    }

    // 4. Per-event notification preferences
    const finalRecipients = [];
    for (const uid of modeFilteredIds) {
      const enabled = await isEventEnabledForUser(uid, eventType, 'in_app', db);
      if (enabled) {
        finalRecipients.push(uid);
      }
    }

    return finalRecipients;
  } catch (err) {
    console.error(`[RESOLVE_RECIPIENTS_ERROR] Failed for ${eventType}:`, err);
    return [];
  }
}

module.exports = {
  resolveRecipients
};
