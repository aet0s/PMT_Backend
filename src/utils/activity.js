// server/src/utils/activity.js
// Centralized comprehensive activity & audit logging helper across all company domains.
// Bridges legacy logActivity calls into the audit service (dual-write).

const { getDevSingleDb } = require('../services/tenantPools');
const { broadcastBoardEvent, broadcastWorkspaceEvent } = require('../socket');
const { parseJson } = require('../db/mysql');
const auditService = require('../services/audit');

const ACTIVITY_TO_AUDIT_ACTION = {
  'created_card': { action: 'card.created', category: 'card', entityType: 'card' },
  'copied_card': { action: 'card.copied', category: 'card', entityType: 'card' },
  'moved_card': { action: 'card.moved', category: 'card', entityType: 'card' },
  'marked_complete': { action: 'card.completed', category: 'card', entityType: 'card' },
  'marked_incomplete': { action: 'card.reopened', category: 'card', entityType: 'card' },
  'archived_card': { action: 'card.archived', category: 'card', entityType: 'card' },
  'unarchived_card': { action: 'card.restored', category: 'card', entityType: 'card' },
  'deleted_card': { action: 'card.deleted', category: 'card', entityType: 'card' },
  'due_date_changed': { action: 'card.due_date_changed', category: 'card', entityType: 'card' },
  'member_added': { action: 'card.assignee_added', category: 'card', entityType: 'card' },
  'member_removed': { action: 'card.assignee_removed', category: 'card', entityType: 'card' },
  'assigner_added': { action: 'card.assigner_added', category: 'card', entityType: 'card' },
  'assigner_removed': { action: 'card.assigner_removed', category: 'card', entityType: 'card' },
  'label_added': { action: 'card.label_added', category: 'label', entityType: 'label' },
  'label_removed': { action: 'card.label_removed', category: 'label', entityType: 'label' },
  'attachment_added': { action: 'attachment.created', category: 'attachment', entityType: 'attachment' },
  'checklist_toggled': { action: 'checklist_item.toggled', category: 'checklist', entityType: 'checklist_item' },
  'added_comment': { action: 'comment.created', category: 'comment', entityType: 'comment' },
  'created_board': { action: 'board.created', category: 'board', entityType: 'board' },
  'archived_board': { action: 'board.archived', category: 'board', entityType: 'board' },
  'deleted_board': { action: 'board.deleted', category: 'board', entityType: 'board' }
};

/**
 * Log any system action to the tenant's activity_log and audit_events.
 */
async function logActivity(boardIdOrOptions, cardIdArg, userIdArg, actionTypeArg, metaJsonArg = {}, dbInstanceArg = null, tenantIdArg = null) {
  let boardId = null;
  let cardId = null;
  let userId = null;
  let workspaceId = null;
  let actionType = null;
  let metaJson = {};
  let dbInstance = null;
  let tenantId = null;

  if (boardIdOrOptions && typeof boardIdOrOptions === 'object' && !('id' in boardIdOrOptions) && boardIdOrOptions.actionType) {
    boardId = boardIdOrOptions.boardId || null;
    cardId = boardIdOrOptions.cardId || null;
    userId = boardIdOrOptions.userId || null;
    workspaceId = boardIdOrOptions.workspaceId || null;
    actionType = boardIdOrOptions.actionType;
    metaJson = boardIdOrOptions.metaJson || {};
    dbInstance = boardIdOrOptions.dbInstance || null;
    tenantId = boardIdOrOptions.tenantId || null;
  } else {
    boardId = boardIdOrOptions || null;
    cardId = cardIdArg || null;
    userId = userIdArg || null;
    actionType = actionTypeArg;
    metaJson = metaJsonArg || {};
    dbInstance = dbInstanceArg || null;
    tenantId = tenantIdArg || null;
  }

  if (!actionType) return;

  const db = dbInstance || getDevSingleDb();
  if (!db) return;

  const effectiveTenantId = tenantId || db?.tenantId || metaJson?.tenantId || null;

  try {
    // If cardId is provided without boardId or workspaceId, resolve them
    if (cardId && (!boardId || !workspaceId)) {
      try {
        const cRes = await db.query(
          `SELECT l.board_id, b.workspace_id 
           FROM cards c
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE c.id = ?`,
          [cardId]
        );
        if (cRes.length > 0) {
          if (!boardId) boardId = cRes[0].board_id;
          if (!workspaceId) workspaceId = cRes[0].workspace_id;
        }
      } catch (e) {}
    }

    // If boardId is provided without workspaceId, resolve it
    if (boardId && !workspaceId) {
      try {
        const bRes = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [boardId]);
        if (bRes.length > 0) {
          workspaceId = bRes[0].workspace_id;
        }
      } catch (e) {}
    }

    if (!userId && (metaJson.user_id || metaJson.userId)) {
      userId = metaJson.user_id || metaJson.userId;
    }

    // Determine audit action and category mapping based on entity context
    let auditMap = ACTIVITY_TO_AUDIT_ACTION[actionType];
    if (actionType === 'member_removed') {
      if (cardId) {
        auditMap = { action: 'card.assignee_removed', category: 'card', entityType: 'card' };
      } else if (boardId) {
        auditMap = { action: 'board.member_removed', category: 'board', entityType: 'board' };
      } else {
        auditMap = { action: 'member.removed', category: 'member', entityType: 'workspace' };
      }
    } else if (actionType === 'member_added') {
      if (cardId) {
        auditMap = { action: 'card.assignee_added', category: 'card', entityType: 'card' };
      } else if (boardId) {
        auditMap = { action: 'board.member_added', category: 'board', entityType: 'board' };
      } else {
        auditMap = { action: 'member.added', category: 'member', entityType: 'workspace' };
      }
    } else if (!auditMap) {
      auditMap = {
        action: actionType.includes('.') ? actionType : `system.${actionType}`,
        category: 'system',
        entityType: cardId ? 'card' : boardId ? 'board' : workspaceId ? 'workspace' : 'unknown'
      };
    }

    // Record through primary audit service (handles audit_events and activity_log dual-write)
    const auditRes = await auditService.record({
      action: auditMap.action,
      category: auditMap.category,
      entityType: auditMap.entityType,
      entityId: cardId || boardId || workspaceId || null,
      entityLabel: metaJson?.title || metaJson?.cardTitle || metaJson?.card_title || metaJson?.board_name || null,
      workspaceId,
      boardId,
      cardId,
      actorUserId: userId,
      activityAction: actionType,
      activityMeta: metaJson,
      meta: metaJson,
      db
    });

    return auditRes;
  } catch (err) {
    console.error(`[AUDIT_ERROR] Failed to log activity "${actionType}":`, err.message);
  }
}

module.exports = { logActivity };
