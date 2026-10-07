const express = require('express');
const { z } = require('zod');
const sanitizeHtml = require('sanitize-html');
const { getDevSingleDb } = require('../services/tenantPools');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const upload = require('../middleware/upload');
const localStorage = require('../storage');
const { broadcastBoardEvent } = require('../socket');
const { notifyOnComment, notifyOnAssignment } = require('../services/notificationService');
const { notify } = require('../services/notify');
const { requirePermission, userHasPermission } = require('../middleware/permissions');
const { sanitizePlain } = require('../utils/sanitizer');
const { logActivity } = require('../utils/activity');

const router = express.Router();

const createCardSchema = z.object({
  list_id: z.number(),
  title: z.string().min(1, 'Card title is required').transform((v) => sanitizePlain(v)),
  description: z.string().optional(),
  position: z.number().optional(),
  due_date: z.string().nullable().optional()
});

const updateCardSchema = z.object({
  list_id: z.number().optional(),
  title: z.string().min(1).transform((v) => sanitizePlain(v)).optional(),
  description: z.string().optional(),
  position: z.number().optional(),
  start_date: z.string().nullable().optional(),
  due_date: z.string().nullable().optional(),
  is_complete: z.boolean().optional(),
  is_archived: z.boolean().optional()
});

function sanitizeDescription(html) {
  if (!html) return '';
  return sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat([
      'img', 'h1', 'h2', 'h3', 'span', 'u', 's', 'strong', 'em', 'a', 'p', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'hr', 'br'
    ]),
    allowedAttributes: {
      ...sanitizeHtml.defaults.allowedAttributes,
      img: ['src', 'alt', 'title', 'width', 'height', 'class', 'style'],
      a: ['href', 'name', 'target', 'rel']
    }
  });
}


// Helper to fetch full card with all nested relations
async function getFullCard(cardId, dbInstance = null) {
  const db = dbInstance || getDevSingleDb();
  try {
    const cardRes = await db.query('SELECT * FROM cards WHERE id = ?', [cardId]);
    if (cardRes.length === 0) return null;
    const card = cardRes[0];

    const labelsRes = await db.query(
      'SELECT l.* FROM labels l JOIN card_labels cl ON l.id = cl.label_id WHERE cl.card_id = ?',
      [cardId]
    );
    card.labels = labelsRes;

    const assignersRes = await db.query(
      'SELECT u.id, u.name, u.email FROM users u JOIN card_assigners ca ON u.id = ca.user_id WHERE ca.card_id = ? ORDER BY u.name ASC',
      [cardId]
    );
    card.assigners = assignersRes;

    const membersRes = await db.query(
      'SELECT u.id, u.name, u.email FROM users u JOIN card_members cm ON u.id = cm.user_id WHERE cm.card_id = ? ORDER BY u.name ASC',
      [cardId]
    );
    card.members = membersRes;

    const checklistsRes = await db.query(
      'SELECT * FROM checklists WHERE card_id = ? ORDER BY id ASC',
      [cardId]
    );
    const checklists = checklistsRes;
    for (let chk of checklists) {
      const itemsRes = await db.query(
        'SELECT * FROM checklist_items WHERE checklist_id = ? ORDER BY position ASC, id ASC',
        [chk.id]
      );
      chk.items = itemsRes;
    }
    card.checklists = checklists;

    const commentsRes = await db.query(
      `SELECT c.*, u.name as author_name 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.card_id = ? 
       ORDER BY c.created_at DESC`,
      [cardId]
    );
    card.comments = commentsRes;
    card.comments_count = commentsRes.length;

    const attRes = await db.query(
      `SELECT a.*, u.name as uploader_name 
       FROM attachments a 
       LEFT JOIN users u ON a.uploaded_by_user_id = u.id 
       WHERE a.card_id = ? 
       ORDER BY a.created_at DESC`,
      [cardId]
    );
    card.attachments = attRes;

    return card;
  } catch (err) {
    console.error('Failed to fetch full card:', err);
    return null;
  }
}

// GET /api/cards/:id
router.get('/:id', requireAuth, requirePermission('board.view'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  if (isNaN(cardId)) return next();
  try {
    const card = await getFullCard(cardId, req.db);
    if (!card) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    return res.json({ card });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards
router.post('/', requireAuth, requirePermission('card.create'), validate(createCardSchema), async (req, res, next) => {
  let { list_id, title, description = '', position, due_date = null } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const listRes = await req.db.query('SELECT board_id, name FROM lists WHERE id = ?', [list_id]);
    if (listRes.length === 0) {
      return res.status(404).json({ error: { message: 'List not found', code: 'NOT_FOUND' } });
    }
    const boardId = listRes[0].board_id;

    if (position === undefined) {
      const maxPosRes = await req.db.query(
        'SELECT MAX(position) as max_pos FROM cards WHERE list_id = ?',
        [list_id]
      );
      const maxPos = maxPosRes[0]?.max_pos;
      position = maxPos ? Number(maxPos) + 1000.0 : 1000.0;
    }

    const cleanDescription = sanitizeDescription(description);

    const cardExec = await req.db.execute(
      'INSERT INTO cards (list_id, title, description, position, due_date) VALUES (?, ?, ?, ?, ?)',
      [list_id, title, cleanDescription, position, due_date]
    );
    const cardId = cardExec.insertId;

    // Automatically set creator as default assigner
    await req.db.execute(
      'INSERT IGNORE INTO card_assigners (card_id, user_id) VALUES (?, ?)',
      [cardId, req.user.id]
    );

    const [card] = await req.db.query('SELECT * FROM cards WHERE id = ?', [cardId]);

    await logActivity(boardId, card.id, req.user.id, 'created_card', { title: card.title }, req.db);

    const bRes = await req.db.query('SELECT name, workspace_id FROM boards WHERE id = ?', [boardId]);
    await notify(
      {
        eventType: 'card.created',
        actorUserId: req.user.id,
        boardId,
        cardId: card.id,
        workspaceId: bRes[0]?.workspace_id || null,
        tenantId: req.tenant?.id || null,
        meta: { cardTitle: card.title, boardName: bRes[0]?.name || 'Board' }
      },
      req.db
    );

    const newCard = await getFullCard(card.id, req.db);

    broadcastBoardEvent(boardId, 'card:created', { card: newCard }, originId, req.tenant ? req.tenant.id : null);

    return res.status(201).json({ card: newCard });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/cards/:id
router.patch('/:id', requireAuth, requirePermission('card.edit'), validate(updateCardSchema), async (req, res, next) => {
  const cardId = Number(req.params.id);
  if (isNaN(cardId)) return next();
  const { list_id, title, description, position, start_date, due_date, is_complete, is_archived } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const oldCardRes = await req.db.query(
      `SELECT c.*, l.board_id, l.name as list_name 
       FROM cards c 
       JOIN lists l ON c.list_id = l.id 
       WHERE c.id = ?`,
      [cardId]
    );

    if (oldCardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const oldCard = oldCardRes[0];

    const updates = [];
    const values = [];

    if (list_id !== undefined) {
      updates.push('list_id = ?');
      values.push(list_id);
    }
    if (title !== undefined) {
      updates.push('title = ?');
      values.push(title);
    }
    if (description !== undefined) {
      const cleanDesc = sanitizeDescription(description);
      updates.push('description = ?');
      values.push(cleanDesc);
    }
    if (position !== undefined) {
      updates.push('position = ?');
      values.push(position);
    }
    if (start_date !== undefined) {
      updates.push('start_date = ?');
      values.push(start_date);
    }
    if (due_date !== undefined) {
      updates.push('due_date = ?');
      values.push(due_date);
    }
    if (is_complete !== undefined) {
      updates.push('is_complete = ?');
      values.push(is_complete ? 1 : 0);
    }
    if (is_archived !== undefined) {
      updates.push('is_archived = ?');
      values.push(is_archived ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: { message: 'No fields to update', code: 'BAD_REQUEST' } });
    }

    values.push(cardId);
    await req.db.execute(
      `UPDATE cards SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    const [updatedCard] = await req.db.query('SELECT * FROM cards WHERE id = ?', [cardId]);
    const fullCard = await getFullCard(cardId, req.db);

    if (list_id !== undefined || position !== undefined) {
      broadcastBoardEvent(
        oldCard.board_id,
        'card:moved',
        {
          cardId,
          fromListId: oldCard.list_id,
          toListId: updatedCard.list_id,
          targetListId: updatedCard.list_id,
          newPosition: updatedCard.position,
          position: updatedCard.position,
          card: fullCard || updatedCard
        },
        originId
      , req.tenant ? req.tenant.id : null);
    } else {
      broadcastBoardEvent(
        oldCard.board_id,
        'card:updated',
        { cardId, updates: req.body, card: fullCard || updatedCard },
        originId
      , req.tenant ? req.tenant.id : null);
    }

    if (list_id !== undefined && list_id !== oldCard.list_id) {
      const newListRes = await req.db.query('SELECT name FROM lists WHERE id = ?', [list_id]);
      const newListName = newListRes[0]?.name || 'another list';
      await logActivity(oldCard.board_id, cardId, req.user.id, 'moved_card', {
        title: updatedCard.title,
        from: oldCard.list_name,
        to: newListName
      }, req.db);
      await notify(
        {
          eventType: 'card.moved',
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: updatedCard.title, fromList: oldCard.list_name, toList: newListName }
        },
        req.db
      );
    }

    if (title !== undefined && title !== oldCard.title) {
      await notify(
        {
          eventType: 'card.renamed',
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: title, oldTitle: oldCard.title }
        },
        req.db
      );
    }

    if (description !== undefined && description !== oldCard.description) {
      await notify(
        {
          eventType: 'card.description_changed',
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: updatedCard.title }
        },
        req.db
      );
    }

    if (due_date !== undefined && due_date !== oldCard.due_date) {
      await logActivity(oldCard.board_id, cardId, req.user.id, 'due_date_changed', {
        title: updatedCard.title,
        due_date: due_date
      }, req.db);

      let dueEventType = 'card.due_date_changed';
      if (!oldCard.due_date && due_date) dueEventType = 'card.due_date_set';
      else if (oldCard.due_date && !due_date) dueEventType = 'card.due_date_removed';

      await notify(
        {
          eventType: dueEventType,
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: updatedCard.title, dueDate: due_date }
        },
        req.db
      );
    }

    if (is_complete !== undefined && Boolean(is_complete) !== Boolean(oldCard.is_complete)) {
      await logActivity(
        oldCard.board_id,
        cardId,
        req.user.id,
        is_complete ? 'marked_complete' : 'marked_incomplete',
        { title: updatedCard.title }
      , req.db);
      await notify(
        {
          eventType: is_complete ? 'card.completed' : 'card.reopened',
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: updatedCard.title }
        },
        req.db
      );
    }

    if (cover_url !== undefined && cover_url !== oldCard.cover_url) {
      await notify(
        {
          eventType: 'card.cover_changed',
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: updatedCard.title }
        },
        req.db
      );
    }

    if (is_archived !== undefined && Boolean(is_archived) !== Boolean(oldCard.is_archived)) {
      await notify(
        {
          eventType: is_archived ? 'card.archived' : 'card.restored',
          actorUserId: req.user.id,
          boardId: oldCard.board_id,
          cardId,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: updatedCard.title }
        },
        req.db
      );
    }

    return res.json({ card: fullCard || updatedCard });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/cards/:id
router.delete('/:id', requireAuth, requirePermission('card.delete'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  if (isNaN(cardId)) return next();
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query(
      'SELECT c.title, l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );

    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }

    const { title: cardTitle, board_id: boardId } = cardRes[0];

    await notify(
      {
        eventType: 'card.deleted',
        actorUserId: req.user.id,
        boardId,
        cardId,
        tenantId: req.tenant?.id || null,
        meta: { cardTitle }
      },
      req.db
    );

    await req.db.execute('DELETE FROM cards WHERE id = ?', [cardId]);

    broadcastBoardEvent(boardId, 'card:deleted', { cardId }, originId, req.tenant ? req.tenant.id : null);

    return res.json({ message: 'Card deleted successfully', id: cardId });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/labels (Toggle label assignment on card)
router.post('/:id/labels', requireAuth, requirePermission('card.edit'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const { label_id } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query(
      'SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );
    const boardId = cardRes[0]?.board_id;

    const existing = await req.db.query(
      'SELECT * FROM card_labels WHERE card_id = ? AND label_id = ?',
      [cardId, label_id]
    );

    const labelRes = await req.db.query('SELECT name FROM labels WHERE id = ?', [label_id]);
    const labelName = labelRes[0]?.name || 'Label';

    let action = '';
    if (existing.length > 0) {
      await req.db.execute('DELETE FROM card_labels WHERE card_id = ? AND label_id = ?', [cardId, label_id]);
      action = 'removed';
      if (boardId) {
        await logActivity(boardId, cardId, req.user.id, 'label_removed', { label_name: labelName }, req.db);
        const cardTitleRes = await req.db.query('SELECT title FROM cards WHERE id = ?', [cardId]);
        await notify(
          {
            eventType: 'card.label_removed',
            actorUserId: req.user.id,
            boardId,
            cardId,
            tenantId: req.tenant?.id || null,
            meta: { labelName, cardTitle: cardTitleRes[0]?.title || 'Card' }
          },
          req.db
        );
      }
    } else {
      await req.db.execute('INSERT IGNORE INTO card_labels (card_id, label_id) VALUES (?, ?)', [cardId, label_id]);
      action = 'added';
      if (boardId) {
        await logActivity(boardId, cardId, req.user.id, 'label_added', { label_name: labelName }, req.db);
        const cardTitleRes = await req.db.query('SELECT title FROM cards WHERE id = ?', [cardId]);
        await notify(
          {
            eventType: 'card.label_added',
            actorUserId: req.user.id,
            boardId,
            cardId,
            tenantId: req.tenant?.id || null,
            meta: { labelName, cardTitle: cardTitleRes[0]?.title || 'Card' }
          },
          req.db
        );
      }
    }

    if (boardId) {
      const fullCard = await getFullCard(cardId, req.db);
      broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
    }

    return res.json({ action, label_id });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/members (Toggle member assignment on card)
router.post('/:id/members', requireAuth, requirePermission('card.assign_members'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const { user_id } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query(
      'SELECT c.title, l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );
    const boardId = cardRes[0]?.board_id;
    const cardTitle = cardRes[0]?.title || 'Card';

    const userRes = await req.db.query('SELECT name FROM users WHERE id = ?', [req.user.id]);
    const actorName = userRes[0]?.name || 'Someone';

    const targetUserRes = await req.db.query('SELECT name, email FROM users WHERE id = ?', [user_id]);
    const targetUser = targetUserRes[0];
    const targetUserName = targetUser?.name || 'Member';

    const existing = await req.db.query(
      'SELECT * FROM card_members WHERE card_id = ? AND user_id = ?',
      [cardId, user_id]
    );

    let action = '';
    if (existing.length > 0) {
      await req.db.execute('DELETE FROM card_members WHERE card_id = ? AND user_id = ?', [cardId, user_id]);
      action = 'removed';
      if (boardId) {
        await logActivity(boardId, cardId, req.user.id, 'member_removed', { member_name: targetUserName }, req.db);
        await notify(
          {
            eventType: 'card.unassigned',
            actorUserId: req.user.id,
            targetUserId: user_id,
            boardId,
            cardId,
            tenantId: req.tenant?.id || null,
            meta: { cardTitle }
          },
          req.db
        );
      }
    } else {
      await req.db.execute('INSERT IGNORE INTO card_members (card_id, user_id) VALUES (?, ?)', [cardId, user_id]);
      if (boardId) {
        await req.db.execute('INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, ?)', [boardId, user_id, 'member']);
      }
      action = 'added';
      if (boardId) {
        await logActivity(boardId, cardId, req.user.id, 'member_added', { member_name: targetUserName }, req.db);
        await notify(
          {
            eventType: 'card.assigned',
            actorUserId: req.user.id,
            targetUserId: user_id,
            boardId,
            cardId,
            tenantId: req.tenant?.id || null,
            meta: { cardTitle }
          },
          req.db
        );
      }
    }

    if (boardId) {
      const fullCard = await getFullCard(cardId, req.db);
      broadcastBoardEvent(
        boardId,
        action === 'added' ? 'member:added' : 'member:removed',
        { cardId, userId: user_id, member: targetUser, action },
        originId,
        req.tenant ? req.tenant.id : null
      );
      broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
    }

    return res.json({ action, user_id });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/assigners (Toggle assigner on card)
router.post('/:id/assigners', requireAuth, requirePermission('card.edit'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const { user_id } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query(
      'SELECT c.title, l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );
    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const boardId = cardRes[0]?.board_id;
    const cardTitle = cardRes[0]?.title || 'Card';

    const targetUserRes = await req.db.query('SELECT name, email FROM users WHERE id = ?', [user_id]);
    const targetUser = targetUserRes[0];
    const targetUserName = targetUser?.name || 'User';

    const existing = await req.db.query(
      'SELECT * FROM card_assigners WHERE card_id = ? AND user_id = ?',
      [cardId, user_id]
    );

    let action = '';
    if (existing.length > 0) {
      await req.db.execute('DELETE FROM card_assigners WHERE card_id = ? AND user_id = ?', [cardId, user_id]);
      action = 'removed';
      if (boardId) {
        await logActivity(boardId, cardId, req.user.id, 'assigner_removed', { assigner_name: targetUserName }, req.db);
      }
    } else {
      await req.db.execute('INSERT IGNORE INTO card_assigners (card_id, user_id) VALUES (?, ?)', [cardId, user_id]);
      action = 'added';
      if (boardId) {
        await logActivity(boardId, cardId, req.user.id, 'assigner_added', { assigner_name: targetUserName }, req.db);
      }
    }

    if (boardId) {
      const fullCard = await getFullCard(cardId, req.db);
      broadcastBoardEvent(
        boardId,
        'card:updated',
        { cardId, card: fullCard },
        originId,
        req.tenant ? req.tenant.id : null
      );
    }

    return res.json({ action, user_id });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/copy (Deep copy card)
router.post('/:id/copy', requireAuth, async (req, res, next) => {
  const sourceCardId = Number(req.params.id);
  const { list_id, title } = req.body;
  const originId = req.headers['x-origin-id'];

  if (!list_id) {
    return res.status(400).json({ error: { message: 'Target list_id is required', code: 'BAD_REQUEST' } });
  }

  try {
    // 1. Fetch source card with full details
    const sourceCard = await getFullCard(sourceCardId, req.db);
    if (!sourceCard) {
      return res.status(404).json({ error: { message: 'Source card not found', code: 'NOT_FOUND' } });
    }

    // 2. Fetch target list & board
    const listRes = await req.db.query(
      `SELECT l.id, l.name, l.board_id, b.workspace_id, b.name as board_name 
       FROM lists l 
       JOIN boards b ON l.board_id = b.id 
       WHERE l.id = ? AND l.is_archived = 0`,
      [list_id]
    );
    if (listRes.length === 0) {
      return res.status(404).json({ error: { message: 'Target list not found', code: 'NOT_FOUND' } });
    }
    const targetList = listRes[0];
    const targetBoardId = targetList.board_id;
    const targetWorkspaceId = targetList.workspace_id;

    // Check permission on target workspace / board
    const hasCreatePerm = await userHasPermission(req.user.id, targetWorkspaceId, 'card.create', req.db, targetBoardId);
    if (!hasCreatePerm) {
      return res.status(403).json({ error: { message: 'No permission to create cards in target board', code: 'FORBIDDEN' } });
    }

    // 3. Calculate position in target list
    const maxPosRes = await req.db.query(
      'SELECT MAX(position) as max_pos FROM cards WHERE list_id = ?',
      [list_id]
    );
    const maxPos = maxPosRes[0]?.max_pos;
    const position = maxPos ? Number(maxPos) + 1000.0 : 1000.0;

    const newTitle = title?.trim() ? sanitizePlain(title.trim()) : `(Copy) ${sourceCard.title}`;

    // 4. Insert new card
    const cardExec = await req.db.execute(
      `INSERT INTO cards (list_id, title, description, position, start_date, due_date, is_complete) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        list_id,
        newTitle,
        sourceCard.description || '',
        position,
        sourceCard.start_date || null,
        sourceCard.due_date || null,
        sourceCard.is_complete ? 1 : 0
      ]
    );
    const newCardId = cardExec.insertId;

    // 5. Add creator as default assigner
    await req.db.execute(
      'INSERT IGNORE INTO card_assigners (card_id, user_id) VALUES (?, ?)',
      [newCardId, req.user.id]
    );

    // 6. Copy Checklists & Items
    if (Array.isArray(sourceCard.checklists) && sourceCard.checklists.length > 0) {
      for (const chk of sourceCard.checklists) {
        const chkExec = await req.db.execute(
          'INSERT INTO checklists (card_id, title, position) VALUES (?, ?, ?)',
          [newCardId, chk.title, chk.position || 1000.0]
        );
        const newChkId = chkExec.insertId;
        if (Array.isArray(chk.items) && chk.items.length > 0) {
          for (const it of chk.items) {
            await req.db.execute(
              'INSERT INTO checklist_items (checklist_id, text, is_checked, position) VALUES (?, ?, ?, ?)',
              [newChkId, it.text, it.is_checked ? 1 : 0, it.position || 1000.0]
            );
          }
        }
      }
    }

    // 7. Copy Attachments / Images
    if (Array.isArray(sourceCard.attachments) && sourceCard.attachments.length > 0) {
      for (const att of sourceCard.attachments) {
        await req.db.execute(
          `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [
            newCardId,
            req.user.id,
            att.file_name,
            att.file_url,
            att.file_type || 'application/octet-stream',
            att.file_size_bytes || 0
          ]
        );
      }
    }

    // 8. Copy Labels: resolve on target board or create if missing
    if (Array.isArray(sourceCard.labels) && sourceCard.labels.length > 0) {
      for (const srcLabel of sourceCard.labels) {
        const existingLabelRes = await req.db.query(
          'SELECT id FROM labels WHERE board_id = ? AND LOWER(name) = LOWER(?) LIMIT 1',
          [targetBoardId, srcLabel.name]
        );

        let targetLabelId;
        if (existingLabelRes.length > 0) {
          targetLabelId = existingLabelRes[0].id;
        } else {
          const newLabelExec = await req.db.execute(
            'INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)',
            [targetBoardId, srcLabel.name, srcLabel.color || '#3b82f6']
          );
          targetLabelId = newLabelExec.insertId;
        }

        await req.db.execute(
          'INSERT IGNORE INTO card_labels (card_id, label_id) VALUES (?, ?)',
          [newCardId, targetLabelId]
        );
      }
    }

    // 9. Members & comments explicitly NOT copied

    // 10. Log Activity on target board
    await logActivity(targetBoardId, newCardId, req.user.id, 'created_card', { title: newTitle, copied_from: sourceCard.title }, req.db);

    // 11. Notifications
    await notify(
      {
        eventType: 'card.copied',
        actorUserId: req.user.id,
        boardId: targetBoardId,
        cardId: newCardId,
        workspaceId: targetWorkspaceId,
        tenantId: req.tenant?.id || null,
        meta: { cardTitle: newTitle, boardName: targetList.board_name || 'Board' }
      },
      req.db
    );

    // 12. Fetch full new card
    const fullNewCard = await getFullCard(newCardId, req.db);

    // 13. Broadcast socket event to target board
    broadcastBoardEvent(targetBoardId, 'card:created', { card: fullNewCard }, originId, req.tenant ? req.tenant.id : null);

    return res.status(201).json({ card: fullNewCard });
  } catch (err) {
    next(err);
  }
});

// GET /api/cards/:id/attachments
router.get('/:id/attachments', requireAuth, async (req, res, next) => {
  const cardId = Number(req.params.id);
  try {
    const cardRes = await req.db.query(
      'SELECT l.board_id, b.workspace_id FROM cards c JOIN lists l ON c.list_id = l.id JOIN boards b ON l.board_id = b.id WHERE c.id = ?',
      [cardId]
    );
    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const { board_id: boardId, workspace_id: workspaceId } = cardRes[0];
    const hasPerm = await userHasPermission(req.user.id, workspaceId, 'project.view', req.db, boardId);
    if (!hasPerm) {
      return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });
    }
    const attachments = await req.db.query(
      `SELECT a.*, u.name as uploader_name FROM attachments a
       LEFT JOIN users u ON a.uploaded_by_user_id = u.id
       WHERE a.card_id = ? ORDER BY a.created_at DESC`,
      [cardId]
    );
    return res.json({ attachments });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/attachments (Handles BOTH file upload & link attachment)
router.post('/:id/attachments', requireAuth, requirePermission('card.manage_attachments'), upload.single('file'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query(
      'SELECT l.board_id, c.title FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );
    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const boardId = cardRes[0].board_id;

    let attachment;
    if (req.file) {
      // File upload
      const saved = await localStorage.save(req.file, cardId, req.tenant ? req.tenant.id : 1);
      const attExec = await req.db.execute(
        `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [cardId, req.user.id, saved.file_name, saved.file_url, saved.file_type, saved.file_size_bytes]
      );
      const [row] = await req.db.query('SELECT * FROM attachments WHERE id = ?', [attExec.insertId]);
      attachment = row;
    } else {
      // Link attachment
      const { link_url, display_name, url } = req.body || {};
      const targetUrl = (link_url || url || '').trim();
      if (!targetUrl) {
        return res.status(400).json({ error: { message: 'No file or link URL provided', code: 'BAD_REQUEST' } });
      }
      const fileName = display_name?.trim() || targetUrl;
      const attExec = await req.db.execute(
        `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
         VALUES (?, ?, ?, ?, 'link', 0)`,
        [cardId, req.user.id, fileName, targetUrl]
      );
      const [row] = await req.db.query('SELECT * FROM attachments WHERE id = ?', [attExec.insertId]);
      attachment = row;
    }

    await logActivity(boardId, cardId, req.user.id, 'attachment_added', { file_name: attachment.file_name }, req.db);
    await notify(
      {
        eventType: 'attachment.added',
        actorUserId: req.user.id,
        boardId,
        cardId,
        tenantId: req.tenant?.id || null,
        meta: { fileName: attachment.file_name, cardTitle: cardRes[0].title }
      },
      req.db
    );

    const fullCard = await getFullCard(cardId, req.db);
    broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);

    return res.status(201).json({ attachment: { ...attachment, uploader_name: req.user.name } });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/attachments/file (Multipart file upload alias)
router.post('/:id/attachments/file', requireAuth, requirePermission('card.manage_attachments'), upload.single('file'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query(
      'SELECT l.board_id, c.title FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );
    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const boardId = cardRes[0].board_id;

    if (!req.file) {
      return res.status(400).json({ error: { message: 'No file uploaded', code: 'BAD_REQUEST' } });
    }

    const saved = await localStorage.save(req.file, cardId, req.tenant ? req.tenant.id : 1);
    const attExec = await req.db.execute(
      `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [cardId, req.user.id, saved.file_name, saved.file_url, saved.file_type, saved.file_size_bytes]
    );
    const [attachment] = await req.db.query('SELECT * FROM attachments WHERE id = ?', [attExec.insertId]);

    await logActivity(boardId, cardId, req.user.id, 'attachment_added', { file_name: attachment.file_name }, req.db);
    await notify(
      {
        eventType: 'attachment.added',
        actorUserId: req.user.id,
        boardId,
        cardId,
        tenantId: req.tenant?.id || null,
        meta: { fileName: attachment.file_name, cardTitle: cardRes[0].title }
      },
      req.db
    );

    const fullCard = await getFullCard(cardId, req.db);
    broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);

    return res.status(201).json({ attachment: { ...attachment, uploader_name: req.user.name } });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/attachments/link (JSON link attachment alias)
router.post('/:id/attachments/link', requireAuth, requirePermission('card.manage_attachments'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const { link_url, display_name } = req.body || {};
  const originId = req.headers['x-origin-id'];

  if (!link_url || !link_url.trim()) {
    return res.status(400).json({ error: { message: 'link_url is required', code: 'BAD_REQUEST' } });
  }

  try {
    const cardRes = await req.db.query(
      'SELECT l.board_id, c.title FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );
    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const boardId = cardRes[0].board_id;

    const fileName = display_name?.trim() || link_url.trim();

    const attExec = await req.db.execute(
      `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
       VALUES (?, ?, ?, ?, 'link', 0)`,
      [cardId, req.user.id, fileName, link_url.trim()]
    );
    const [attachment] = await req.db.query('SELECT * FROM attachments WHERE id = ?', [attExec.insertId]);

    await logActivity(boardId, cardId, req.user.id, 'attachment_added', { file_name: attachment.file_name }, req.db);
    await notify({
      eventType: 'attachment.added',
      actorUserId: req.user.id,
      boardId,
      cardId,
      meta: { fileName: attachment.file_name, cardTitle: cardRes[0].title }
    });

    const fullCard = await getFullCard(cardId, req.db);
    broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);

    return res.status(201).json({ attachment: { ...attachment, uploader_name: req.user.name } });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/cards/attachments/:id
router.delete('/attachments/:id', requireAuth, requirePermission('card.manage_attachments'), async (req, res, next) => {
  const attachmentId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const attRes = await req.db.query('SELECT * FROM attachments WHERE id = ?', [attachmentId]);
    if (attRes.length === 0) {
      return res.status(404).json({ error: { message: 'Attachment not found', code: 'NOT_FOUND' } });
    }
    const att = attRes[0];

    const cardRes = await req.db.query('SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?', [att.card_id]);
    const boardId = cardRes[0]?.board_id;

    if (att.file_type !== 'link') {
      if (att.file_url.startsWith('/uploads/')) {
        const relativeKey = att.file_url.replace('/uploads/', '');
        await localStorage.delete(relativeKey);
      } else if (att.file_url.startsWith('/api/files/')) {
        const relativeKey = att.file_url.replace('/api/files/', '');
        await localStorage.delete(relativeKey);
      }
    }

    await req.db.execute('DELETE FROM attachments WHERE id = ?', [attachmentId]);

    if (boardId) {
      const fullCard = await getFullCard(att.card_id, req.db);
      broadcastBoardEvent(boardId, 'card:updated', { cardId: att.card_id, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        boardId,
        cardId: att.card_id,
        eventType: 'attachment.removed',
        actorId: req.user.id,
        data: { attachmentName: att.file_name || 'File', cardTitle: fullCard?.title || 'Card' }
      });
    }

    return res.json({ message: 'Attachment deleted successfully', id: attachmentId });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/comments
router.post('/:id/comments', requireAuth, requirePermission('card.comment'), async (req, res, next) => {
  const cardId = Number(req.params.id);
  const { body } = req.body;
  const originId = req.headers['x-origin-id'];

  if (!body || !body.trim()) {
    return res.status(400).json({ error: { message: 'Comment text cannot be empty', code: 'BAD_REQUEST' } });
  }

  try {
    const cleanBody = sanitizeDescription(body.trim());

    const comExec = await req.db.execute(
      'INSERT INTO comments (card_id, user_id, body) VALUES (?, ?, ?)',
      [cardId, req.user.id, cleanBody]
    );
    const [comment] = await req.db.query('SELECT * FROM comments WHERE id = ?', [comExec.insertId]);

    const userRes = await req.db.query('SELECT name FROM users WHERE id = ?', [req.user.id]);
    const author_name = userRes[0]?.name || 'Unknown';

    const cardRes = await req.db.query(
      'SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [cardId]
    );

    const boardId = cardRes[0]?.board_id;
    if (boardId) {
      await logActivity(boardId, cardId, req.user.id, 'added_comment', {
        body: cleanBody.substring(0, 60)
      }, req.db);

      const newComment = { ...comment, author_name };
      const fullCard = await getFullCard(cardId, req.db);
      broadcastBoardEvent(boardId, 'comment:added', { cardId, comment: newComment, card: fullCard }, originId, req.tenant ? req.tenant.id : null);

      // Parse @mentions
      const mentionRegex = /@([a-zA-Z0-9._-]+)/g;
      let match;
      const mentionedNames = new Set();
      while ((match = mentionRegex.exec(cleanBody)) !== null) {
        mentionedNames.add(match[1].toLowerCase());
      }

      const mentionedUserIds = [];
      if (mentionedNames.size > 0) {
        const usersRes = await req.db.query('SELECT id, name, email FROM users');
        usersRes.forEach((u) => {
          const uName = (u.name || '').toLowerCase().replace(/\s+/g, '');
          const uEmailPrefix = (u.email || '').split('@')[0].toLowerCase();
          if (mentionedNames.has(uName) || mentionedNames.has(uEmailPrefix)) {
            mentionedUserIds.push(u.id);
          }
        });
      }

      if (mentionedUserIds.length > 0) {
        await notify(
          {
            eventType: 'comment.mention',
            actorUserId: req.user.id,
            boardId,
            cardId,
            mentionedUserIds,
            tenantId: req.tenant?.id || null,
            meta: { cardTitle: fullCard?.title || 'Card', actorName: author_name }
          },
          req.db
        );
      }

      await notify(
        {
          eventType: 'comment.added',
          actorUserId: req.user.id,
          boardId,
          cardId,
          mentionedUserIds,
          tenantId: req.tenant?.id || null,
          meta: { cardTitle: fullCard?.title || 'Card', actorName: author_name }
        },
        req.db
      );
    }

    return res.status(201).json({ comment: { ...comment, author_name } });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/comments/:id
router.delete('/comments/:id', requireAuth, async (req, res, next) => {
  const commentId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const comRes = await req.db.query('SELECT card_id FROM comments WHERE id = ?', [commentId]);
    const cardId = comRes[0]?.card_id;

    await req.db.execute('DELETE FROM comments WHERE id = ? AND user_id = ?', [commentId, req.user.id]);

    if (cardId) {
      const cardRes = await req.db.query('SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?', [cardId]);
      const boardId = cardRes[0]?.board_id;
      if (boardId) {
        const fullCard = await getFullCard(cardId, req.db);
        broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
        await notify({
          db: req.db,
          tenantId: req.tenant?.id,
          boardId,
          cardId,
          eventType: 'comment.deleted',
          actorId: req.user.id,
          data: { cardTitle: fullCard?.title || 'Card' }
        });
      }
    }

    return res.json({ message: 'Comment deleted' });
  } catch (err) {
    next(err);
  }
});

// POST /api/cards/:id/checklists
router.post('/:id/checklists', requireAuth, async (req, res, next) => {
  const cardId = Number(req.params.id);
  const { title = 'Checklist', items = [] } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const cardRes = await req.db.query('SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?', [cardId]);
    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }
    const boardId = cardRes[0]?.board_id;

    const filteredItems = (Array.isArray(items) ? items : [])
      .map((it) => (typeof it === 'string' ? it.trim() : it?.text?.trim()))
      .filter(Boolean);

    const chExec = await req.db.execute(
      'INSERT INTO checklists (card_id, title) VALUES (?, ?)',
      [cardId, sanitizePlain(title) || 'Checklist']
    );
    const checklistId = chExec.insertId;

    const insertedItems = [];
    for (let i = 0; i < filteredItems.length; i++) {
      const pos = (i + 1) * 1000.0;
      const itExec = await req.db.execute(
        'INSERT INTO checklist_items (checklist_id, text, position) VALUES (?, ?, ?)',
        [checklistId, sanitizePlain(filteredItems[i]), pos]
      );
      const [itRow] = await req.db.query('SELECT * FROM checklist_items WHERE id = ?', [itExec.insertId]);
      if (itRow) insertedItems.push({ ...itRow, is_checked: Boolean(itRow.is_checked) });
    }

    const [checklist] = await req.db.query('SELECT * FROM checklists WHERE id = ?', [checklistId]);

    if (boardId) {
      const fullCard = await getFullCard(cardId, req.db);
      broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        boardId,
        cardId,
        eventType: 'checklist.created',
        actorId: req.user.id,
        data: { checklistTitle: checklist?.title || 'Checklist', cardTitle: fullCard?.title || 'Card' }
      });
    }

    return res.status(201).json({ checklist: { ...checklist, items: insertedItems } });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/checklists/:id
router.delete('/checklists/:id', requireAuth, async (req, res, next) => {
  const checklistId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const chRes = await req.db.query('SELECT card_id, title FROM checklists WHERE id = ?', [checklistId]);
    const cardId = chRes[0]?.card_id;

    await req.db.execute('DELETE FROM checklists WHERE id = ?', [checklistId]);

    if (cardId) {
      const cardRes = await req.db.query('SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?', [cardId]);
      const boardId = cardRes[0]?.board_id;
      if (boardId) {
        const fullCard = await getFullCard(cardId, req.db);
        broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
        await notify({
          db: req.db,
          tenantId: req.tenant?.id,
          boardId,
          cardId,
          eventType: 'checklist.deleted',
          actorId: req.user.id,
          data: { checklistTitle: chRes[0]?.title || 'Checklist', cardTitle: fullCard?.title || 'Card' }
        });
      }
    }

    return res.json({ message: 'Checklist deleted' });
  } catch (err) {
    next(err);
  }
});

// POST /api/checklist-items
router.post('/checklist-items', requireAuth, async (req, res, next) => {
  const { checklist_id, text } = req.body;
  const originId = req.headers['x-origin-id'];

  if (!text || !text.trim()) {
    return res.status(400).json({ error: { message: 'Item text cannot be empty', code: 'BAD_REQUEST' } });
  }

  try {
    const itemExec = await req.db.execute(
      'INSERT INTO checklist_items (checklist_id, text) VALUES (?, ?)',
      [checklist_id, sanitizePlain(text)]
    );
    const [item] = await req.db.query('SELECT * FROM checklist_items WHERE id = ?', [itemExec.insertId]);

    const chRes = await req.db.query('SELECT card_id, title FROM checklists WHERE id = ?', [checklist_id]);
    const cardId = chRes[0]?.card_id;
    if (cardId) {
      const cardRes = await req.db.query('SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?', [cardId]);
      const boardId = cardRes[0]?.board_id;
      if (boardId) {
        const fullCard = await getFullCard(cardId, req.db);
        broadcastBoardEvent(boardId, 'card:updated', { cardId, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
        await notify({
          db: req.db,
          tenantId: req.tenant?.id,
          boardId,
          cardId,
          eventType: 'checklist_item.added',
          actorId: req.user.id,
          data: { itemText: text, checklistTitle: chRes[0]?.title || 'Checklist', cardTitle: fullCard?.title || 'Card' }
        });
      }
    }

    return res.status(201).json({ item });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/checklist-items/:id
router.patch('/checklist-items/:id', requireAuth, async (req, res, next) => {
  const itemId = Number(req.params.id);
  const { text, is_checked, position } = req.body;
  const originId = req.headers['x-origin-id'];
  const clientMutationId = req.headers['x-client-mutation-id'] || req.body?.clientMutationId || null;

  try {
    const updates = [];
    const values = [];

    if (text !== undefined) {
      updates.push('text = ?');
      values.push(sanitizePlain(text));
    }
    if (is_checked !== undefined) {
      updates.push('is_checked = ?');
      values.push(is_checked ? 1 : 0);
    }
    if (position !== undefined) {
      updates.push('position = ?');
      values.push(position);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: { message: 'No fields to update', code: 'BAD_REQUEST' } });
    }

    values.push(itemId);
    await req.db.execute(
      `UPDATE checklist_items SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    const [updatedItem] = await req.db.query('SELECT * FROM checklist_items WHERE id = ?', [itemId]);

    const chRes = await req.db.query(
      `SELECT c.id as card_id, l.board_id 
       FROM checklist_items ci
       JOIN checklists ch ON ci.checklist_id = ch.id
       JOIN cards c ON ch.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       WHERE ci.id = ?`,
      [itemId]
    );

    if (chRes.length > 0) {
      const { card_id, board_id } = chRes[0];

      if (text !== undefined && is_checked === undefined) {
        const detailRes = await req.db.query(
          `SELECT ch.title as checklist_title, c.title as card_title
           FROM checklist_items ci
           JOIN checklists ch ON ci.checklist_id = ch.id
           JOIN cards c ON ch.card_id = c.id
           WHERE ci.id = ?`,
          [itemId]
        );
        if (detailRes.length > 0) {
          await notify({
            db: req.db,
            tenantId: req.tenant?.id,
            boardId,
            cardId: card_id,
            eventType: 'checklist_item.edited',
            actorId: req.user.id,
            data: { itemText: sanitizePlain(text), checklistTitle: detailRes[0].checklist_title, cardTitle: detailRes[0].card_title }
          });
        }
      }

      if (is_checked !== undefined) {
        await logActivity(board_id, card_id, req.user.id, 'checklist_toggled', {
          item_text: updatedItem.text,
          is_checked: is_checked
        }, req.db);
        broadcastBoardEvent(
          board_id,
          'checklist_item:toggled',
          {
            itemId,
            is_checked: updatedItem.is_checked,
            cardId: card_id,
            updated_at: updatedItem.updated_at || new Date().toISOString()
          },
          originId,
          req.tenant ? req.tenant.id : null,
          clientMutationId
        );

        const detailRes = await req.db.query(
          `SELECT ch.id as checklist_id, ch.title as checklist_title, c.title as card_title
           FROM checklist_items ci
           JOIN checklists ch ON ci.checklist_id = ch.id
           JOIN cards c ON ch.card_id = c.id
           WHERE ci.id = ?`,
          [itemId]
        );

        if (detailRes.length > 0) {
          const { checklist_id, checklist_title, card_title } = detailRes[0];
          const eventType = is_checked ? 'checklist_item.completed' : 'checklist_item.reopened';

          await notify(
            {
              eventType,
              actorUserId: req.user.id,
              boardId: board_id,
              cardId: card_id,
              tenantId: req.tenant?.id || null,
              meta: { itemText: updatedItem.text, checklistTitle: checklist_title, cardTitle: card_title }
            },
            req.db
          );

          if (is_checked) {
            const countsRes = await req.db.query(
              `SELECT COUNT(*) as total, SUM(CASE WHEN is_checked = 1 THEN 1 ELSE 0 END) as checked_count
               FROM checklist_items WHERE checklist_id = ?`,
              [checklist_id]
            );
            const total = Number(countsRes[0]?.total || 0);
            const checked_count = Number(countsRes[0]?.checked_count || 0);
            if (total > 0 && total === checked_count) {
              await notify({
                eventType: 'checklist.completed_all',
                actorUserId: req.user.id,
                boardId: board_id,
                cardId: card_id,
                meta: { checklistTitle: checklist_title, cardTitle: card_title }
              });
            }
          }
        }
      }
      const fullCard = await getFullCard(card_id, req.db);
      broadcastBoardEvent(board_id, 'card:updated', { cardId: card_id, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
    }

    return res.json({ item: updatedItem });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/checklist-items/:id
router.delete('/checklist-items/:id', requireAuth, async (req, res, next) => {
  const itemId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const chRes = await req.db.query(
      `SELECT c.id as card_id, l.board_id, ci.text, ch.title as checklist_title
       FROM checklist_items ci
       JOIN checklists ch ON ci.checklist_id = ch.id
       JOIN cards c ON ch.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       WHERE ci.id = ?`,
      [itemId]
    );

    await req.db.execute('DELETE FROM checklist_items WHERE id = ?', [itemId]);

    if (chRes.length > 0) {
      const { card_id, board_id, text, checklist_title } = chRes[0];
      const fullCard = await getFullCard(card_id, req.db);
      broadcastBoardEvent(board_id, 'card:updated', { cardId: card_id, card: fullCard }, originId, req.tenant ? req.tenant.id : null);
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        boardId,
        cardId,
        eventType: 'checklist_item.deleted',
        actorId: req.user.id,
        data: { itemText: text, checklistTitle: checklist_title, cardTitle: fullCard?.title || 'Card' }
      });
    }

    return res.json({ message: 'Checklist item deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
