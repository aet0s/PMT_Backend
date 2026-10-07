// server/src/routes/attachments.js
const express = require('express');
const { requireAuth } = require('../middleware/auth');
const upload = require('../middleware/upload');
const localStorage = require('../storage');
const { broadcastBoardEvent } = require('../socket');
const { notify } = require('../services/notify');
const { userHasPermission } = require('../middleware/permissions');

const router = express.Router();

// Helper to fetch full card with all nested relations
async function getFullCard(cardId, db) {
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

  const checklistsRes = await db.query('SELECT * FROM checklists WHERE card_id = ? ORDER BY position ASC', [cardId]);
  for (const ch of checklistsRes) {
    ch.items = await db.query('SELECT * FROM checklist_items WHERE checklist_id = ? ORDER BY position ASC', [ch.id]);
  }
  card.checklists = checklistsRes;

  const commentsRes = await db.query(
    `SELECT co.*, u.name as author_name FROM comments co
     LEFT JOIN users u ON co.user_id = u.id
     WHERE co.card_id = ? ORDER BY co.created_at ASC`,
    [cardId]
  );
  card.comments = commentsRes;

  const attachmentsRes = await db.query(
    `SELECT a.*, u.name as uploader_name FROM attachments a
     LEFT JOIN users u ON a.uploaded_by_user_id = u.id
     WHERE a.card_id = ? ORDER BY a.created_at DESC`,
    [cardId]
  );
  card.attachments = attachmentsRes;

  return card;
}

// GET /api/attachments - List attachments
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const cardId = req.query.card_id || req.query.cardId;
    if (cardId) {
      const attachments = await req.db.query(
        `SELECT a.*, u.name as uploader_name FROM attachments a
         LEFT JOIN users u ON a.uploaded_by_user_id = u.id
         WHERE a.card_id = ? ORDER BY a.created_at DESC`,
        [Number(cardId)]
      );
      return res.json({ attachments });
    }
    const attachments = await req.db.query(
      `SELECT DISTINCT a.*, u.name as uploader_name, c.title as card_title FROM attachments a
       JOIN cards c ON a.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       JOIN workspace_members wm ON b.workspace_id = wm.workspace_id AND wm.user_id = ?
       LEFT JOIN users u ON a.uploaded_by_user_id = u.id
       ORDER BY a.created_at DESC LIMIT 50`,
      [req.user.id]
    );
    return res.json({ attachments });
  } catch (err) {
    next(err);
  }
});

// GET /api/attachments/:id - Fetch attachment by ID
router.get('/:id', requireAuth, async (req, res, next) => {
  const attachmentId = Number(req.params.id);

  try {
    const attRes = await req.db.query(
      `SELECT a.*, u.name as uploader_name, c.title as card_title, l.board_id, b.workspace_id
       FROM attachments a
       JOIN cards c ON a.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       LEFT JOIN users u ON a.uploaded_by_user_id = u.id
       WHERE a.id = ?`,
      [attachmentId]
    );

    if (attRes.length === 0) {
      return res.status(404).json({ error: { message: 'Attachment not found', code: 'NOT_FOUND' } });
    }

    const att = attRes[0];
    const hasPerm = await userHasPermission(req.user.id, att.workspace_id, 'file.view', req.db, att.board_id);
    if (!hasPerm) {
      return res.status(403).json({ error: { message: 'Access denied to attachment', code: 'FORBIDDEN' } });
    }

    return res.json({ attachment: att });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/attachments/:id - Delete attachment
router.delete('/:id', requireAuth, async (req, res, next) => {
  const attachmentId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const attRes = await req.db.query(
      `SELECT a.*, l.board_id, b.workspace_id
       FROM attachments a
       JOIN cards c ON a.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE a.id = ?`,
      [attachmentId]
    );

    if (attRes.length === 0) {
      return res.status(404).json({ error: { message: 'Attachment not found', code: 'NOT_FOUND' } });
    }

    const att = attRes[0];
    const hasPerm = await userHasPermission(req.user.id, att.workspace_id, 'attachment.delete', req.db, att.board_id);
    if (!hasPerm && att.uploaded_by_user_id !== req.user.id) {
      return res.status(403).json({ error: { message: 'Permission denied to delete attachment', code: 'FORBIDDEN' } });
    }

    if (att.file_type !== 'link') {
      if (att.file_url.startsWith('/uploads/')) {
        const relativeKey = att.file_url.replace('/uploads/', '');
        await localStorage.delete(relativeKey);
      } else if (att.file_url.startsWith('/api/files/')) {
        const relativeKey = att.file_url.replace('/api/files/', '');
        await localStorage.delete(relativeKey);
      }
    }

    const fullCard = await getFullCard(att.card_id, req.db);
    broadcastBoardEvent(att.board_id, 'card:updated', { cardId: att.card_id, card: fullCard }, originId, req.tenant ? req.tenant.id : null);

    await notify({
      db: req.db,
      tenantId: req.tenant?.id,
      boardId: att.board_id,
      cardId: att.card_id,
      eventType: 'attachment.removed',
      actorId: req.user.id,
      data: { attachmentName: att.file_name || 'File', cardTitle: fullCard?.title || 'Card' }
    });

    return res.json({ message: 'Attachment deleted successfully', id: attachmentId });
  } catch (err) {
    next(err);
  }
});

// POST /api/attachments - Upload attachment with card_id in body
router.post('/', requireAuth, upload.single('file'), async (req, res, next) => {
  const cardId = Number(req.body.card_id || req.body.cardId);
  const originId = req.headers['x-origin-id'];

  if (!cardId) {
    return res.status(400).json({ error: { message: 'card_id is required', code: 'BAD_REQUEST' } });
  }

  try {
    const cardRes = await req.db.query(
      `SELECT l.board_id, b.workspace_id, c.title
       FROM cards c
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE c.id = ?`,
      [cardId]
    );

    if (cardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
    }

    const { board_id: boardId, workspace_id: workspaceId, title: cardTitle } = cardRes[0];
    const hasPerm = await userHasPermission(req.user.id, workspaceId, 'attachment.upload', req.db, boardId);
    if (!hasPerm) {
      return res.status(403).json({ error: { message: 'Permission denied to upload attachments', code: 'FORBIDDEN' } });
    }

    let attachment;
    if (req.file) {
      const saved = await localStorage.save(req.file, cardId, req.tenant ? req.tenant.id : 1);
      const attExec = await req.db.execute(
        `INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type, file_size_bytes)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [cardId, req.user.id, saved.file_name, saved.file_url, saved.file_type, saved.file_size_bytes]
      );
      const [row] = await req.db.query('SELECT * FROM attachments WHERE id = ?', [attExec.insertId]);
      attachment = row;
    } else {
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

    await notify(
      {
        eventType: 'attachment.added',
        actorUserId: req.user.id,
        boardId,
        cardId,
        tenantId: req.tenant?.id || null,
        meta: { fileName: attachment.file_name, cardTitle }
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

module.exports = router;
