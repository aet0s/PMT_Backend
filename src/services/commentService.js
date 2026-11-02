// server/src/services/commentService.js
// Centralized service for threaded comments, board-scoped mentions, and intelligent notification routing.

const { broadcastBoardEvent, sendUserNotification } = require('../socket');
const { logActivity } = require('../utils/activity');
const { NOTIFICATION_EVENTS, renderMessage } = require('./notificationEvents');
const { isEventEnabledForUser } = require('./notificationPreferences');
const { usersWithPermission } = require('../middleware/permissions');
const { getDevSingleDb } = require('./tenantPools');
const audit = require('./audit');

function formatCommentSnippet(text, maxLength = 75) {
  if (!text) return '';
  // Clean markdown mention tags if any, e.g. @[Name](user:123) -> @Name
  const clean = text.replace(/@\[([^\]]+)\]\(user:\d+\)/g, '@$1').trim();
  if (clean.length <= maxLength) return clean;
  return clean.slice(0, maxLength).trimEnd() + '...';
}

function sanitizeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Parses mentions from comment body and/or client-supplied mentions array.
 * Supported syntax:
 *   @[Display Name](user:123)
 *   @123
 */
function extractMentionedUserIds(body = '', clientMentionIds = []) {
  const ids = new Set();

  if (Array.isArray(clientMentionIds)) {
    for (const id of clientMentionIds) {
      const num = Number(id);
      if (!isNaN(num) && num > 0) ids.add(num);
    }
  }

  if (typeof body === 'string') {
    // 1. Structured syntax: @[User Name](user:42)
    const structuredRegex = /@\[([^\]]+)\]\(user:(\d+)\)/g;
    let match;
    while ((match = structuredRegex.exec(body)) !== null) {
      const num = Number(match[2]);
      if (!isNaN(num) && num > 0) ids.add(num);
    }

    // 2. Direct ID syntax: @user:42
    const directRegex = /@user:(\d+)/g;
    while ((match = directRegex.exec(body)) !== null) {
      const num = Number(match[1]);
      if (!isNaN(num) && num > 0) ids.add(num);
    }
  }

  return Array.from(ids);
}

/**
 * Searches eligible mention candidates for a given board.
 * Strictly board-scoped:
 * - Must be an active member of the workspace (wm.status = 'active')
 * - Must have board access (explicit board_members OR project.access_all)
 * - Excludes deactivated, removed, or foreign workspace/tenant members.
 */
async function searchMentionCandidates(db, { boardId, query = '', limit = 10 }) {
  if (!boardId) return [];
  const boundedLimit = Math.min(20, Math.max(1, parseInt(limit || '10', 10)));
  const cleanQuery = (query || '').trim().toLowerCase();

  const bRows = await db.query('SELECT id, workspace_id FROM boards WHERE id = ?', [boardId]);
  if (bRows.length === 0) return [];
  const workspaceId = bRows[0].workspace_id;

  let sql = `
    SELECT DISTINCT u.id, u.name, u.email, u.avatar_url
    FROM users u
    JOIN workspace_members wm ON wm.user_id = u.id AND wm.status = 'active'
    JOIN boards b ON b.id = ? AND b.workspace_id = wm.workspace_id
    LEFT JOIN board_members bm ON bm.board_id = b.id AND bm.user_id = u.id
    LEFT JOIN roles r ON wm.role_id = r.id
    LEFT JOIN role_permissions rp ON r.id = rp.role_id
    LEFT JOIN permissions p ON rp.permission_id = p.id AND p.key = 'project.access_all'
    WHERE b.id = ?
      AND (bm.user_id IS NOT NULL OR p.id IS NOT NULL)
  `;
  const params = [boardId, boardId];

  if (cleanQuery) {
    sql += ` AND (LOWER(u.name) LIKE ? OR LOWER(u.email) LIKE ?)`;
    const searchPattern = `%${cleanQuery}%`;
    params.push(searchPattern, searchPattern);
  }

  sql += ` ORDER BY u.name ASC LIMIT ?`;
  params.push(boundedLimit);

  const rows = await db.query(sql, params);
  return rows.map((r) => ({
    id: Number(r.id),
    name: r.name,
    email: r.email,
    avatar_url: r.avatar_url
  }));
}

/**
 * Validates that all mentioned user IDs belong to eligible active board members.
 * Throws 400 error if any mention target is unauthorized or invalid.
 */
async function validateMentionTargets(db, boardId, mentionedUserIds = []) {
  if (!mentionedUserIds || mentionedUserIds.length === 0) return [];

  const candidates = await searchMentionCandidates(db, { boardId, limit: 1000 });
  const eligibleMap = new Map(candidates.map((c) => [c.id, c]));

  for (const uid of mentionedUserIds) {
    if (!eligibleMap.has(uid)) {
      const err = new Error(`User with ID ${uid} is not an authorized active member of this board.`);
      err.status = 400;
      err.code = 'INVALID_MENTION_TARGET';
      throw err;
    }
  }

  return mentionedUserIds.map((uid) => eligibleMap.get(uid));
}

/**
 * Resolves recipients and dispatches notifications according to Section 5:
 * Rule A: New top-level comment -> card assignees + mentions (minus author, deduplicated).
 * Rule B: Reply to comment -> thread author + direct parent author + mentions (minus author). No unrelated assignees!
 * Rule C: Reply to reply -> thread author + direct parent author + mentions (minus author). No unrelated assignees!
 * Rule D: Direct mentions -> priority 1, deduplicated.
 */
async function dispatchCommentNotifications({
  db,
  tenantId,
  boardId,
  workspaceId,
  cardId,
  cardTitle,
  actorUserId,
  actorName,
  commentId,
  rootCommentId,
  parentCommentId,
  isReply,
  validatedMentions = [],
  commentBody = ''
}) {
  try {
    const mentionedUserIds = validatedMentions.map((m) => Number(m.id)).filter((id) => id !== Number(actorUserId));
    const mentionedSet = new Set(mentionedUserIds);

    let assigneeRecipients = [];
    let rootAuthorId = null;
    let parentAuthorId = null;

    if (!isReply) {
      // Rule A: New top-level comment (notify active assignees AND assigners on the card)
      const caRows = await db.query(
        `SELECT DISTINCT user_id FROM (
           SELECT cm.user_id 
           FROM card_members cm
           JOIN workspace_members wm ON wm.workspace_id = ? AND wm.user_id = cm.user_id AND wm.status = 'active'
           WHERE cm.card_id = ?
           UNION
           SELECT ca.user_id 
           FROM card_assigners ca
           JOIN workspace_members wm ON wm.workspace_id = ? AND wm.user_id = ca.user_id AND wm.status = 'active'
           WHERE ca.card_id = ?
         ) combined`,
        [workspaceId, cardId, workspaceId, cardId]
      );
      assigneeRecipients = caRows
        .map((r) => Number(r.user_id))
        .filter((uid) => uid !== Number(actorUserId) && !mentionedSet.has(uid));
    } else {
      // Rule B & C: Reply to comment or reply
      if (rootCommentId) {
        const rootRows = await db.query(
          `SELECT c.user_id 
           FROM comments c 
           JOIN workspace_members wm ON wm.workspace_id = ? AND wm.user_id = c.user_id AND wm.status = 'active'
           WHERE c.id = ?`,
          [workspaceId, rootCommentId]
        );
        if (rootRows[0]?.user_id) {
          const rId = Number(rootRows[0].user_id);
          if (rId !== Number(actorUserId) && !mentionedSet.has(rId)) {
            rootAuthorId = rId;
          }
        }
      }

      if (parentCommentId && Number(parentCommentId) !== Number(rootCommentId)) {
        const parentRows = await db.query(
          `SELECT c.user_id 
           FROM comments c 
           JOIN workspace_members wm ON wm.workspace_id = ? AND wm.user_id = c.user_id AND wm.status = 'active'
           WHERE c.id = ?`,
          [workspaceId, parentCommentId]
        );
        if (parentRows[0]?.user_id) {
          const pId = Number(parentRows[0].user_id);
          if (pId !== Number(actorUserId) && pId !== rootAuthorId && !mentionedSet.has(pId)) {
            parentAuthorId = pId;
          }
        }
      }
    }

    // Verify all potential recipients currently hold comment.view permission
    const allCandidateIds = Array.from(
      new Set([
        ...assigneeRecipients,
        ...(rootAuthorId ? [rootAuthorId] : []),
        ...(parentAuthorId ? [parentAuthorId] : []),
        ...mentionedUserIds
      ])
    );

    if (allCandidateIds.length === 0) return;

    const permittedIds = new Set(
      await usersWithPermission(db, workspaceId, boardId, 'comment.view', allCandidateIds)
    );

    // Filter mutes
    let unmutedSet = new Set(permittedIds);
    try {
      const muteRows = await db.query(
        `SELECT user_id FROM notification_mutes 
         WHERE user_id IN (?) AND (board_id = ? OR card_id = ?)`,
        [Array.from(permittedIds), boardId, cardId]
      );
      for (const m of muteRows) {
        unmutedSet.delete(Number(m.user_id));
      }
    } catch (_) {}

    const snippet = formatCommentSnippet(commentBody, 75);

    const helperInsert = async (recipientId, eventType, message, priority = 0) => {
      if (!unmutedSet.has(recipientId)) return;
      const enabled = await isEventEnabledForUser(recipientId, eventType, 'in_app', db);
      if (!enabled) return;

      const metaJson = JSON.stringify({
        actorName: actorName || 'Someone',
        boardId,
        cardId,
        cardTitle: cardTitle || 'Card',
        commentId,
        rootCommentId: rootCommentId || commentId,
        parentCommentId: parentCommentId || null,
        workspaceId,
        snippet,
        commentText: commentBody
      });

      const insertRes = await db.execute(
        `INSERT INTO notifications (user_id, type, event_type, card_id, board_id, workspace_id, actor_user_id, message, meta, priority)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          recipientId,
          eventType,
          eventType,
          cardId,
          boardId,
          workspaceId,
          actorUserId,
          message,
          metaJson,
          priority
        ]
      );

      const [nRow] = await db.query('SELECT * FROM notifications WHERE id = ?', [insertRes.insertId]);
      if (nRow) {
        nRow.actor_name = actorName;
        nRow.card_title = cardTitle;
        try { nRow.meta = JSON.parse(nRow.meta); } catch (_) {}
        sendUserNotification(recipientId, nRow, tenantId);
      }
    };

    // 1. Deliver Mentions (Rule D, priority 1)
    for (const uid of mentionedUserIds) {
      const msg = snippet
        ? `${actorName} mentioned you in a comment: "${snippet}"`
        : `${actorName} mentioned you in a comment`;
      await helperInsert(uid, 'comment.mention', msg, 1);
    }

    // 2. Deliver Assignee / Assigner Notifications (Rule A)
    for (const uid of assigneeRecipients) {
      const msg = snippet
        ? `${actorName} commented on a card assigned to you: "${snippet}"`
        : `${actorName} commented on a card assigned to you`;
      await helperInsert(uid, 'comment.added', msg, 0);
    }

    // 3. Deliver Reply Notifications (Rule B & C)
    if (rootAuthorId) {
      const isThreadRoot = parentCommentId && Number(parentCommentId) !== Number(rootCommentId);
      const prefix = isThreadRoot
        ? `${actorName} replied to a discussion you started`
        : `${actorName} replied to your comment`;
      const msg = snippet ? `${prefix}: "${snippet}"` : prefix;
      const evType = isThreadRoot ? 'comment.thread_reply' : 'comment.reply';
      await helperInsert(rootAuthorId, evType, msg, 0);
    }

    if (parentAuthorId) {
      const prefix = `${actorName} replied to your comment`;
      const msg = snippet ? `${prefix}: "${snippet}"` : prefix;
      await helperInsert(parentAuthorId, 'comment.reply', msg, 0);
    }
  } catch (err) {
    console.error('[COMMENT_NOTIFY_ERROR] Failed to dispatch notifications:', err);
  }
}

/**
 * Creates a top-level comment or a reply.
 */
async function createComment(db, {
  cardId,
  userId,
  body,
  parentCommentId = null,
  clientMentionIds = [],
  originId = null,
  tenantId = null
}) {
  if (!body || !body.trim()) {
    const err = new Error('Comment text cannot be empty');
    err.status = 400;
    err.code = 'BAD_REQUEST';
    throw err;
  }

  // 1. Verify card and retrieve board & workspace
  const cardRows = await db.query(
    `SELECT c.id, c.title, l.board_id, b.workspace_id, b.name as board_name
     FROM cards c
     JOIN lists l ON c.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     WHERE c.id = ?`,
    [cardId]
  );
  if (cardRows.length === 0) {
    const err = new Error('Card not found');
    err.status = 404;
    err.code = 'NOT_FOUND';
    throw err;
  }
  const card = cardRows[0];
  const boardId = card.board_id;
  const workspaceId = card.workspace_id;

  // 2. If reply, validate parent comment
  let resolvedRootCommentId = null;
  let resolvedParentCommentId = null;
  let parentComment = null;

  if (parentCommentId) {
    const pRows = await db.query(
      'SELECT id, card_id, parent_comment_id, root_comment_id, user_id FROM comments WHERE id = ? AND deleted_at IS NULL',
      [parentCommentId]
    );
    if (pRows.length === 0) {
      const err = new Error('Parent comment not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }
    parentComment = pRows[0];

    // Anti-leak check: Parent must belong to the exact same card!
    if (Number(parentComment.card_id) !== Number(cardId)) {
      const err = new Error('Parent comment belongs to a different card');
      err.status = 400;
      err.code = 'CROSS_CARD_PARENT_INVALID';
      throw err;
    }

    resolvedParentCommentId = Number(parentComment.id);
    resolvedRootCommentId = parentComment.root_comment_id
      ? Number(parentComment.root_comment_id)
      : Number(parentComment.id);
  }

  // 3. Extract and validate mentions
  const mentionIdSet = new Set(extractMentionedUserIds(body, clientMentionIds));
  const boardCandidates = await searchMentionCandidates(db, { boardId, limit: 1000 });
  const lowerBody = (body || '').toLowerCase();
  for (const c of boardCandidates) {
    if (c.name && lowerBody.includes(`@${c.name.toLowerCase()}`)) {
      mentionIdSet.add(c.id);
    }
  }
  const validatedMentions = await validateMentionTargets(db, boardId, Array.from(mentionIdSet));

  // 4. Retrieve author details
  const [author] = await db.query('SELECT id, name, email, avatar_url FROM users WHERE id = ?', [userId]);
  const actorName = author?.name || 'Someone';
  const authorName = actorName;

  let createdComment = null;

  // 5. Transactional insert
  await db.transaction(async (tx) => {
    const comExec = await tx.execute(
      `INSERT INTO comments (card_id, user_id, parent_comment_id, root_comment_id, body)
       VALUES (?, ?, ?, ?, ?)`,
      [cardId, userId, resolvedParentCommentId, resolvedRootCommentId, body.trim()]
    );
    const commentId = comExec.insertId;

    // Persist normalized mentions
    if (validatedMentions.length > 0) {
      for (const m of validatedMentions) {
        await tx.execute(
          `INSERT IGNORE INTO comment_mentions (comment_id, mentioned_user_id) VALUES (?, ?)`,
          [commentId, m.id]
        );
      }
    }

    // Log card activity
    await logActivity(
      boardId,
      cardId,
      userId,
      resolvedParentCommentId ? 'replied_comment' : 'added_comment',
      {
        comment_id: commentId,
        parent_comment_id: resolvedParentCommentId,
        root_comment_id: resolvedRootCommentId,
        body_snippet: body.trim().slice(0, 80)
      },
      tx
    );

    const [cRow] = await tx.query('SELECT * FROM comments WHERE id = ?', [commentId]);
    createdComment = cRow;
  });

  let parentAuthorName = null;
  if (resolvedParentCommentId) {
    const parentRows = await db.query(
      `SELECT u.name FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?`,
      [resolvedParentCommentId]
    );
    if (parentRows.length > 0) {
      parentAuthorName = parentRows[0].name;
    }
  }

  createdComment.author_name = authorName;
  createdComment.author_avatar = author?.avatar_url || null;
  createdComment.author_email = author?.email || null;
  createdComment.mentions = validatedMentions;
  createdComment.parent_author_name = parentAuthorName;
  createdComment.replies = [];
  createdComment.reply_count = 0;

  // 6. Intelligent notification delivery
  await dispatchCommentNotifications({
    db,
    tenantId,
    boardId,
    workspaceId,
    cardId,
    cardTitle: card.title,
    actorUserId: userId,
    actorName,
    commentId: createdComment.id,
    rootCommentId: resolvedRootCommentId,
    parentCommentId: resolvedParentCommentId,
    isReply: Boolean(resolvedParentCommentId),
    validatedMentions,
    commentBody: body.trim()
  });

  // 7. Real-time board event broadcasting
  broadcastBoardEvent(
    boardId,
    'comment:created',
    {
      cardId,
      comment: createdComment,
      rootCommentId: resolvedRootCommentId,
      parentCommentId: resolvedParentCommentId
    },
    originId,
    tenantId
  );

  // Backwards compatibility events
  broadcastBoardEvent(
    boardId,
    'comment:added',
    { cardId, comment: createdComment },
    originId,
    tenantId
  );

  return createdComment;
}

/**
 * Retrieves threaded comments for a card.
 */
async function getThreadedComments(db, cardId) {
  const commentRows = await db.query(
    `SELECT c.id, c.card_id, c.user_id, c.parent_comment_id, c.root_comment_id,
            c.body, c.created_at, c.updated_at, c.deleted_at, c.original_length,
            u.name as author_name, u.avatar_url as author_avatar, u.email as author_email
     FROM comments c
     JOIN users u ON c.user_id = u.id
     WHERE c.card_id = ? AND c.deleted_at IS NULL
     ORDER BY c.created_at ASC`,
    [cardId]
  );

  if (commentRows.length === 0) {
    return { comments: [], total_count: 0 };
  }

  // Fetch all mentions on this card
  const mentionRows = await db.query(
    `SELECT cm.comment_id, u.id as user_id, u.name, u.email, u.avatar_url
     FROM comment_mentions cm
     JOIN comments c ON cm.comment_id = c.id
     JOIN users u ON cm.mentioned_user_id = u.id
     WHERE c.card_id = ? AND c.deleted_at IS NULL`,
    [cardId]
  );

  const mentionMap = new Map();
  for (const m of mentionRows) {
    if (!mentionMap.has(m.comment_id)) mentionMap.set(m.comment_id, []);
    mentionMap.get(m.comment_id).push({
      id: Number(m.user_id),
      name: m.name,
      email: m.email,
      avatar_url: m.avatar_url
    });
  }

  // Author lookup map for resolving reply_to_author_name
  const authorMap = new Map();
  for (const c of commentRows) {
    authorMap.set(Number(c.id), c.author_name);
  }

  const rootComments = [];
  const repliesByRootId = new Map();

  for (const row of commentRows) {
    const item = {
      ...row,
      id: Number(row.id),
      card_id: Number(row.card_id),
      user_id: Number(row.user_id),
      parent_comment_id: row.parent_comment_id ? Number(row.parent_comment_id) : null,
      root_comment_id: row.root_comment_id ? Number(row.root_comment_id) : null,
      mentions: mentionMap.get(row.id) || [],
      parent_author_name: row.parent_comment_id ? (authorMap.get(Number(row.parent_comment_id)) || null) : null
    };

    if (!row.parent_comment_id) {
      item.replies = [];
      item.reply_count = 0;
      rootComments.push(item);
    } else {
      const rootId = Number(row.root_comment_id || row.parent_comment_id);
      if (!repliesByRootId.has(rootId)) {
        repliesByRootId.set(rootId, []);
      }
      repliesByRootId.get(rootId).push(item);
    }
  }

  // Attach replies and reply counts to root comments
  for (const root of rootComments) {
    const threadReplies = repliesByRootId.get(root.id) || [];
    root.replies = threadReplies;
    root.reply_count = threadReplies.length;
  }

  return {
    comments: rootComments,
    total_count: commentRows.length
  };
}

/**
 * Updates a comment's content.
 */
async function editComment(db, { commentId, userId, body, originId = null, tenantId = null }) {
  if (!body || !body.trim()) {
    const err = new Error('Comment text cannot be empty');
    err.status = 400;
    err.code = 'BAD_REQUEST';
    throw err;
  }

  const comRows = await db.query(
    `SELECT c.*, l.board_id, b.workspace_id 
     FROM comments c
     JOIN cards cd ON c.card_id = cd.id
     JOIN lists l ON cd.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     WHERE c.id = ? AND c.deleted_at IS NULL`,
    [commentId]
  );
  if (comRows.length === 0) {
    const err = new Error('Comment not found');
    err.status = 404;
    err.code = 'NOT_FOUND';
    throw err;
  }
  const comment = comRows[0];

  // Extract and validate any new mentions
  const extractedIds = extractMentionedUserIds(body);
  const validatedMentions = await validateMentionTargets(db, comment.board_id, extractedIds);

  await db.transaction(async (tx) => {
    await tx.execute(
      `UPDATE comments 
       SET body = ?, updated_at = CURRENT_TIMESTAMP(3), original_length = COALESCE(original_length, CHAR_LENGTH(body))
       WHERE id = ?`,
      [body.trim(), commentId]
    );

    // Update mentions
    await tx.execute('DELETE FROM comment_mentions WHERE comment_id = ?', [commentId]);
    for (const m of validatedMentions) {
      await tx.execute(
        'INSERT IGNORE INTO comment_mentions (comment_id, mentioned_user_id) VALUES (?, ?)',
        [commentId, m.id]
      );
    }

    await logActivity(comment.board_id, comment.card_id, userId, 'edited_comment', {
      comment_id: commentId
    }, tx);
  });

  const [updated] = await db.query('SELECT * FROM comments WHERE id = ?', [commentId]);
  const [author] = await db.query('SELECT name, avatar_url, email FROM users WHERE id = ?', [updated.user_id]);
  updated.author_name = author?.name;
  updated.author_avatar = author?.avatar_url;
  updated.author_email = author?.email;
  updated.mentions = validatedMentions;

  broadcastBoardEvent(
    comment.board_id,
    'comment:updated',
    { cardId: comment.card_id, comment: updated },
    originId,
    tenantId
  );

  return updated;
}

/**
 * Deletes a comment (soft-delete with cascade of mentions).
 */
async function deleteComment(db, { commentId, userId, originId = null, tenantId = null }) {
  const comRows = await db.query(
    `SELECT c.*, l.board_id, b.workspace_id, cd.title as card_title, u.name as author_name, u.email as author_email
     FROM comments c
     JOIN cards cd ON c.card_id = cd.id
     JOIN lists l ON cd.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     JOIN users u ON c.user_id = u.id
     WHERE c.id = ? AND c.deleted_at IS NULL`,
    [commentId]
  );
  if (comRows.length === 0) {
    const err = new Error('Comment not found');
    err.status = 404;
    err.code = 'NOT_FOUND';
    throw err;
  }
  const comment = comRows[0];

  await db.transaction(async (tx) => {
    // If root comment is deleted, also delete all replies to it
    if (!comment.parent_comment_id) {
      await tx.execute('DELETE FROM comments WHERE root_comment_id = ?', [commentId]);
    }
    await tx.execute('DELETE FROM comments WHERE id = ?', [commentId]);

    await logActivity(comment.board_id, comment.card_id, userId, 'deleted_comment', {
      comment_id: commentId,
      card_title: comment.card_title,
      deleted_comment_text: comment.body,
      comment_author_id: comment.user_id,
      comment_author_name: comment.author_name,
      deleted_at: new Date().toISOString()
    }, tx);
  });

  // Record enterprise audit log
  try {
    await audit.record({
      db,
      action: 'comment.deleted',
      category: 'comment',
      entityType: 'comment',
      entityId: commentId,
      entityLabel: `Comment on "${comment.card_title || 'Card'}"`,
      cardId: comment.card_id,
      boardId: comment.board_id,
      workspaceId: comment.workspace_id,
      actorUserId: userId,
      meta: {
        comment_id: commentId,
        card_id: comment.card_id,
        card_title: comment.card_title,
        deleted_comment_text: comment.body,
        comment_author_id: comment.user_id,
        comment_author_name: comment.author_name,
        is_reply: Boolean(comment.parent_comment_id),
        parent_comment_id: comment.parent_comment_id,
        root_comment_id: comment.root_comment_id,
        deleted_by_user_id: userId,
        deleted_at: new Date().toISOString()
      }
    });
  } catch (auditErr) {
    console.warn('[WARN] Audit logging for comment deletion failed:', auditErr.message);
  }

  broadcastBoardEvent(
    comment.board_id,
    'comment:deleted',
    {
      cardId: comment.card_id,
      commentId: Number(commentId),
      rootCommentId: comment.root_comment_id ? Number(comment.root_comment_id) : Number(commentId),
      parentCommentId: comment.parent_comment_id ? Number(comment.parent_comment_id) : null
    },
    originId,
    tenantId
  );

  return { success: true };
}

module.exports = {
  createComment,
  getThreadedComments,
  editComment,
  deleteComment,
  searchMentionCandidates,
  validateMentionTargets,
  extractMentionedUserIds
};
