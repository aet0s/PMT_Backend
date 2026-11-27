// server/src/routes/notes.js
const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { getActiveDb, requirePermission, userHasPermission } = require('../middleware/permissions');
const { apiRateLimiter } = require('../middleware/rateLimit');
const { getIO, getUserRoom } = require('../socket');

const CANVAS_WIDTH = 4000;
const CANVAS_HEIGHT = 3000;
const MIN_WIDTH = 160;
const MAX_WIDTH = 480;
const MIN_HEIGHT = 120;
const MAX_HEIGHT = 480;
const DEFAULT_WIDTH = 220;
const DEFAULT_HEIGHT = 200;
const MAX_ACTIVE_NOTES = 500;
const MAX_CONTENT_LENGTH = 5000;
const ALLOWED_COLORS = new Set(['yellow', 'peach', 'blush', 'lilac', 'sky', 'mint', 'sage']);

function sanitizeContent(raw) {
  if (raw === undefined || raw === null) return '';
  if (typeof raw !== 'string') {
    const err = new Error('Content must be a plain text string');
    err.status = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  if (raw.length > MAX_CONTENT_LENGTH) {
    const err = new Error(`Note content cannot exceed ${MAX_CONTENT_LENGTH} characters`);
    err.status = 400;
    err.code = 'CONTENT_TOO_LONG';
    throw err;
  }
  // Strip ASCII control characters except \t (0x09), \n (0x0A), \r (0x0D)
  return raw.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

function validateColor(color, fallback = 'yellow') {
  if (color === undefined) return fallback;
  if (typeof color !== 'string' || !ALLOWED_COLORS.has(color)) {
    const err = new Error(`Invalid note colour. Allowed: ${Array.from(ALLOWED_COLORS).join(', ')}`);
    err.status = 400;
    err.code = 'INVALID_COLOR';
    throw err;
  }
  return color;
}

function clampSize(width, height, fallbackW = DEFAULT_WIDTH, fallbackH = DEFAULT_HEIGHT) {
  const wNum = width !== undefined ? Number(width) : fallbackW;
  const hNum = height !== undefined ? Number(height) : fallbackH;
  if (!Number.isFinite(wNum) || !Number.isFinite(hNum)) {
    const err = new Error('Width and height must be valid numbers');
    err.status = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  return {
    width: Math.round(Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, wNum))),
    height: Math.round(Math.min(MAX_HEIGHT, Math.max(MIN_HEIGHT, hNum)))
  };
}

function clampPosition(x, y, width, height, fallbackX = 100, fallbackY = 100) {
  const xNum = x !== undefined ? Number(x) : fallbackX;
  const yNum = y !== undefined ? Number(y) : fallbackY;
  if (!Number.isFinite(xNum) || !Number.isFinite(yNum)) {
    const err = new Error('Coordinates x and y must be valid numbers');
    err.status = 400;
    err.code = 'VALIDATION_ERROR';
    throw err;
  }
  const maxX = Math.max(0, CANVAS_WIDTH - width);
  const maxY = Math.max(0, CANVAS_HEIGHT - height);
  return {
    x: Math.round(Math.min(maxX, Math.max(0, xNum))),
    y: Math.round(Math.min(maxY, Math.max(0, yNum)))
  };
}

function formatNoteRow(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    user_id: Number(row.user_id),
    content: row.content || '',
    color: row.color || 'yellow',
    x: Number(row.x),
    y: Number(row.y),
    width: Number(row.width),
    height: Number(row.height),
    z_index: Number(row.z_index),
    is_pinned: Boolean(row.is_pinned),
    rotation_seed: Number(row.rotation_seed || 0),
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at,
    deleted_at: row.deleted_at ? (row.deleted_at instanceof Date ? row.deleted_at.toISOString() : row.deleted_at) : null
  };
}

async function emitNoteEventToOwner(req, eventName, payload) {
  try {
    const io = getIO();
    if (!io || !req.user?.id) return;
    const db = getActiveDb(req);
    const wsId = req.workspaceId;
    if (wsId) {
      const stillAllowed = await userHasPermission(req.user.id, wsId, 'notes.view_own', db, null, req);
      if (!stillAllowed) return;
    }
    const room = getUserRoom(req.user.id, req.tenantId || req.user?.tenant_id);
    if (room) {
      io.to(room).emit(eventName, payload);
    }
  } catch (_) {
    // Non-fatal live sync
  }
}

async function countActiveNotes(db, userId) {
  const rows = await db.query(
    'SELECT COUNT(*) AS cnt FROM user_notes WHERE user_id = ? AND deleted_at IS NULL',
    [userId]
  );
  return Number(rows[0]?.cnt || 0);
}

// GET /api/notes (?trash=1&q=...)
router.get('/', requireAuth, requirePermission('notes.view_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const isTrash = req.query.trash === '1' || req.query.trash === 'true';
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';

    let sql = `SELECT id, user_id, content, color, x, y, width, height, z_index, is_pinned, rotation_seed, created_at, updated_at, deleted_at
               FROM user_notes
               WHERE user_id = ? AND ${isTrash ? 'deleted_at IS NOT NULL' : 'deleted_at IS NULL'}`;
    const params = [userId];

    if (q) {
      sql += ' AND content LIKE ?';
      params.push(`%${q}%`);
    }

    sql += isTrash ? ' ORDER BY deleted_at DESC' : ' ORDER BY z_index ASC, updated_at DESC';

    const rows = await db.query(sql, params);
    res.json({ notes: rows.map(formatNoteRow) });
  } catch (err) {
    next(err);
  }
});

// POST /api/notes
router.post('/', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;

    const activeCount = await countActiveNotes(db, userId);
    if (activeCount >= MAX_ACTIVE_NOTES) {
      return res.status(400).json({
        error: {
          message: `You have reached the maximum of ${MAX_ACTIVE_NOTES} active notes. Delete or purge old notes to add more.`,
          code: 'NOTE_LIMIT_REACHED'
        }
      });
    }

    const content = sanitizeContent(req.body.content ?? '');
    const color = validateColor(req.body.color, 'yellow');
    const { width, height } = clampSize(req.body.width, req.body.height);
    const { x, y } = clampPosition(req.body.x, req.body.y, width, height);
    const isPinned = req.body.is_pinned ? 1 : 0;

    const maxZRows = await db.query(
      'SELECT COALESCE(MAX(z_index), 0) AS max_z FROM user_notes WHERE user_id = ? AND deleted_at IS NULL',
      [userId]
    );
    const nextZ = Number.isFinite(Number(req.body.z_index))
      ? Math.max(1, Math.round(Number(req.body.z_index)))
      : Number(maxZRows[0]?.max_z || 0) + 1;
    const rotationSeed = Number.isFinite(Number(req.body.rotation_seed))
      ? Math.max(-10, Math.min(20, Math.round(Number(req.body.rotation_seed))))
      : Math.floor(Math.random() * 21);

    const result = await db.query(
      `INSERT INTO user_notes (user_id, content, color, x, y, width, height, z_index, is_pinned, rotation_seed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, content, color, x, y, width, height, nextZ, isPinned, rotationSeed]
    );

    const createdRows = await db.query('SELECT * FROM user_notes WHERE id = ? AND user_id = ?', [result.insertId, userId]);
    const note = formatNoteRow(createdRows[0]);
    await emitNoteEventToOwner(req, 'note:created', { note });
    res.status(201).json({ note });
  } catch (err) {
    next(err);
  }
});

// POST /api/notes/batch-positions
router.post('/batch-positions', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const updates = Array.isArray(req.body?.positions) ? req.body.positions : null;
    if (!updates || updates.length === 0) {
      return res.status(400).json({ error: { message: 'positions array is required', code: 'VALIDATION_ERROR' } });
    }
    if (updates.length > 200) {
      return res.status(400).json({ error: { message: 'Maximum 200 positions per batch', code: 'VALIDATION_ERROR' } });
    }

    const updatedNotes = [];
    for (const item of updates) {
      const noteId = Number(item?.id);
      if (!Number.isInteger(noteId) || noteId <= 0) continue;
      const existingRows = await db.query(
        'SELECT * FROM user_notes WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
        [noteId, userId]
      );
      const existing = existingRows[0];
      if (!existing) continue;

      const nextZ = item.z_index !== undefined && Number.isFinite(Number(item.z_index))
        ? Math.max(1, Math.round(Number(item.z_index)))
        : existing.z_index;

      if (existing.is_pinned) {
        await db.query('UPDATE user_notes SET z_index = ? WHERE id = ? AND user_id = ?', [nextZ, noteId, userId]);
      } else {
        const pos = clampPosition(
          item.x !== undefined ? item.x : existing.x,
          item.y !== undefined ? item.y : existing.y,
          existing.width,
          existing.height
        );
        await db.query(
          'UPDATE user_notes SET x = ?, y = ?, z_index = ? WHERE id = ? AND user_id = ?',
          [pos.x, pos.y, nextZ, noteId, userId]
        );
      }

      const refreshed = await db.query('SELECT * FROM user_notes WHERE id = ? AND user_id = ?', [noteId, userId]);
      if (refreshed[0]) updatedNotes.push(formatNoteRow(refreshed[0]));
    }

    await emitNoteEventToOwner(req, 'note:batch_updated', { notes: updatedNotes });
    res.json({ notes: updatedNotes });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notes/:id
router.patch('/:id', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const noteId = Number(req.params.id);
    if (!Number.isInteger(noteId) || noteId <= 0) {
      return res.status(400).json({ error: { message: 'Invalid note ID', code: 'VALIDATION_ERROR' } });
    }

    const existingRows = await db.query(
      'SELECT * FROM user_notes WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
      [noteId, userId]
    );
    const existing = existingRows[0];
    if (!existing) {
      return res.status(404).json({ error: { message: 'Note not found', code: 'NOT_FOUND' } });
    }

    // Optimistic concurrency check if client passes updated_at
    if (req.body.updated_at !== undefined && req.body.updated_at !== null) {
      const clientTs = new Date(req.body.updated_at).getTime();
      const dbTs = new Date(existing.updated_at).getTime();
      if (Number.isFinite(clientTs) && Number.isFinite(dbTs) && Math.abs(clientTs - dbTs) > 5) {
        return res.status(409).json({
          error: { message: 'Note was modified elsewhere. Refreshing latest version.', code: 'CONFLICT' },
          note: formatNoteRow(existing)
        });
      }
    }

    const nextContent = req.body.content !== undefined ? sanitizeContent(req.body.content) : existing.content;
    const nextColor = req.body.color !== undefined ? validateColor(req.body.color, existing.color) : existing.color;
    const nextPinned = req.body.is_pinned !== undefined ? (req.body.is_pinned ? 1 : 0) : existing.is_pinned;
    const nextZ = req.body.z_index !== undefined && Number.isFinite(Number(req.body.z_index))
      ? Math.max(1, Math.round(Number(req.body.z_index)))
      : existing.z_index;

    // Pinned notes cannot be moved or resized while remaining pinned
    let nextWidth = existing.width;
    let nextHeight = existing.height;
    let nextX = existing.x;
    let nextY = existing.y;

    if (!existing.is_pinned || (req.body.is_pinned !== undefined && !nextPinned)) {
      const size = clampSize(
        req.body.width !== undefined ? req.body.width : existing.width,
        req.body.height !== undefined ? req.body.height : existing.height,
        existing.width,
        existing.height
      );
      nextWidth = size.width;
      nextHeight = size.height;

      const pos = clampPosition(
        req.body.x !== undefined ? req.body.x : existing.x,
        req.body.y !== undefined ? req.body.y : existing.y,
        nextWidth,
        nextHeight,
        existing.x,
        existing.y
      );
      nextX = pos.x;
      nextY = pos.y;
    }

    await db.query(
      `UPDATE user_notes
       SET content = ?, color = ?, x = ?, y = ?, width = ?, height = ?, z_index = ?, is_pinned = ?
       WHERE id = ? AND user_id = ?`,
      [nextContent, nextColor, nextX, nextY, nextWidth, nextHeight, nextZ, nextPinned, noteId, userId]
    );

    const updatedRows = await db.query('SELECT * FROM user_notes WHERE id = ? AND user_id = ?', [noteId, userId]);
    const note = formatNoteRow(updatedRows[0]);
    await emitNoteEventToOwner(req, 'note:updated', { note });
    res.json({ note });
  } catch (err) {
    next(err);
  }
});

// POST /api/notes/:id/duplicate
router.post('/:id/duplicate', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const noteId = Number(req.params.id);
    if (!Number.isInteger(noteId) || noteId <= 0) {
      return res.status(400).json({ error: { message: 'Invalid note ID', code: 'VALIDATION_ERROR' } });
    }

    const activeCount = await countActiveNotes(db, userId);
    if (activeCount >= MAX_ACTIVE_NOTES) {
      return res.status(400).json({
        error: {
          message: `You have reached the maximum of ${MAX_ACTIVE_NOTES} active notes.`,
          code: 'NOTE_LIMIT_REACHED'
        }
      });
    }

    const existingRows = await db.query(
      'SELECT * FROM user_notes WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
      [noteId, userId]
    );
    const src = existingRows[0];
    if (!src) {
      return res.status(404).json({ error: { message: 'Note not found', code: 'NOT_FOUND' } });
    }

    const maxZRows = await db.query(
      'SELECT COALESCE(MAX(z_index), 0) AS max_z FROM user_notes WHERE user_id = ? AND deleted_at IS NULL',
      [userId]
    );
    const nextZ = Number(maxZRows[0]?.max_z || 0) + 1;
    const pos = clampPosition(src.x + 24, src.y + 24, src.width, src.height);

    const result = await db.query(
      `INSERT INTO user_notes (user_id, content, color, x, y, width, height, z_index, is_pinned, rotation_seed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
      [userId, src.content, src.color, pos.x, pos.y, src.width, src.height, nextZ, Math.floor(Math.random() * 21)]
    );

    const createdRows = await db.query('SELECT * FROM user_notes WHERE id = ? AND user_id = ?', [result.insertId, userId]);
    const note = formatNoteRow(createdRows[0]);
    await emitNoteEventToOwner(req, 'note:created', { note });
    res.status(201).json({ note });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/notes/:id (soft delete)
router.delete('/:id', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const noteId = Number(req.params.id);
    if (!Number.isInteger(noteId) || noteId <= 0) {
      return res.status(400).json({ error: { message: 'Invalid note ID', code: 'VALIDATION_ERROR' } });
    }

    const result = await db.query(
      'UPDATE user_notes SET deleted_at = NOW(3) WHERE id = ? AND user_id = ? AND deleted_at IS NULL',
      [noteId, userId]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: { message: 'Note not found', code: 'NOT_FOUND' } });
    }

    const deletedRows = await db.query('SELECT * FROM user_notes WHERE id = ? AND user_id = ?', [noteId, userId]);
    const note = formatNoteRow(deletedRows[0]);
    await emitNoteEventToOwner(req, 'note:deleted', { id: noteId, note });
    res.json({ success: true, id: noteId, note });
  } catch (err) {
    next(err);
  }
});

// POST /api/notes/:id/restore
router.post('/:id/restore', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const noteId = Number(req.params.id);
    if (!Number.isInteger(noteId) || noteId <= 0) {
      return res.status(400).json({ error: { message: 'Invalid note ID', code: 'VALIDATION_ERROR' } });
    }

    const activeCount = await countActiveNotes(db, userId);
    if (activeCount >= MAX_ACTIVE_NOTES) {
      return res.status(400).json({
        error: {
          message: `You have reached the maximum of ${MAX_ACTIVE_NOTES} active notes.`,
          code: 'NOTE_LIMIT_REACHED'
        }
      });
    }

    const result = await db.query(
      'UPDATE user_notes SET deleted_at = NULL WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL',
      [noteId, userId]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: { message: 'Trashed note not found', code: 'NOT_FOUND' } });
    }

    const restoredRows = await db.query('SELECT * FROM user_notes WHERE id = ? AND user_id = ?', [noteId, userId]);
    const note = formatNoteRow(restoredRows[0]);
    await emitNoteEventToOwner(req, 'note:restored', { note });
    res.json({ note });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/notes/:id/purge (permanent delete)
router.delete('/:id/purge', requireAuth, apiRateLimiter, requirePermission('notes.manage_own'), async (req, res, next) => {
  try {
    const db = getActiveDb(req);
    const userId = req.user.id;
    const noteId = Number(req.params.id);
    if (!Number.isInteger(noteId) || noteId <= 0) {
      return res.status(400).json({ error: { message: 'Invalid note ID', code: 'VALIDATION_ERROR' } });
    }

    const result = await db.query(
      'DELETE FROM user_notes WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL',
      [noteId, userId]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: { message: 'Trashed note not found', code: 'NOT_FOUND' } });
    }

    await emitNoteEventToOwner(req, 'note:purged', { id: noteId });
    res.json({ success: true, id: noteId });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
module.exports.cleanOldTrashedNotes = async function cleanOldTrashedNotes(db) {
  if (!db) return 0;
  const result = await db.query(
    'DELETE FROM user_notes WHERE deleted_at IS NOT NULL AND deleted_at < DATE_SUB(NOW(3), INTERVAL 30 DAY)'
  );
  return Number(result?.affectedRows || 0);
};
