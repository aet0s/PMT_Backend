const express = require('express');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { broadcastBoardEvent } = require('../socket');
const { requirePermission } = require('../middleware/permissions');
const { sanitizePlain } = require('../utils/sanitizer');
const { logActivity } = require('../utils/activity');

const router = express.Router();

const createListSchema = z.object({
  board_id: z.number(),
  name: z.string().min(1, 'List name is required').transform((v) => sanitizePlain(v)),
  position: z.number().optional()
});

const updateListSchema = z.object({
  name: z.string().min(1).transform((v) => sanitizePlain(v)).optional(),
  position: z.number().optional(),
  is_archived: z.boolean().optional()
});

// POST /api/lists
router.post('/', requireAuth, requirePermission('list.create'), validate(createListSchema), async (req, res, next) => {
  let { board_id, name, position } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    if (position === undefined) {
      const maxPosRes = await req.db.query(
        'SELECT MAX(position) as max_pos FROM lists WHERE board_id = ?',
        [board_id]
      );
      const maxPos = maxPosRes[0]?.max_pos;
      position = maxPos ? Number(maxPos) + 1000.0 : 1000.0;
    }

    const listExec = await req.db.execute(
      'INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)',
      [board_id, name, position]
    );

    const [createdList] = await req.db.query('SELECT * FROM lists WHERE id = ?', [listExec.insertId]);
    const newList = { ...createdList, cards: [] };
    await logActivity(board_id, null, req.user.id, 'list_created', { list_name: name }, req.db);
    broadcastBoardEvent(board_id, 'list:created', { list: newList }, originId);

    return res.status(201).json({ list: newList });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/lists/:id
router.patch('/:id', requireAuth, requirePermission('list.edit'), validate(updateListSchema), async (req, res, next) => {
  const listId = Number(req.params.id);
  const { name, position, is_archived } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const listCheck = await req.db.query('SELECT board_id, name FROM lists WHERE id = ?', [listId]);
    if (listCheck.length === 0) {
      return res.status(404).json({ error: { message: 'List not found', code: 'NOT_FOUND' } });
    }
    const boardId = listCheck[0].board_id;

    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(name);
    }
    if (position !== undefined) {
      updates.push('position = ?');
      values.push(position);
    }
    if (is_archived !== undefined) {
      updates.push('is_archived = ?');
      values.push(is_archived ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: { message: 'No fields to update', code: 'BAD_REQUEST' } });
    }

    values.push(listId);
    await req.db.execute(
      `UPDATE lists SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    const [updatedList] = await req.db.query('SELECT * FROM lists WHERE id = ?', [listId]);
    if (is_archived === true) {
      await logActivity(boardId, null, req.user.id, 'list_archived', { list_name: updatedList.name || listCheck[0]?.name }, req.db);
    } else if (name !== undefined) {
      await logActivity(boardId, null, req.user.id, 'list_renamed', { list_name: name }, req.db);
    }
    const eventName = position !== undefined ? 'list:reordered' : 'list:updated';
    broadcastBoardEvent(boardId, eventName, { listId: updatedList.id, position: updatedList.position, list: updatedList }, originId);

    return res.json({ list: updatedList });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/lists/:id
router.delete('/:id', requireAuth, requirePermission('list.delete'), async (req, res, next) => {
  const listId = Number(req.params.id);
  const originId = req.headers['x-origin-id'];

  try {
    const listRes = await req.db.query('SELECT board_id FROM lists WHERE id = ?', [listId]);
    if (listRes.length === 0) {
      return res.status(404).json({ error: { message: 'List not found', code: 'NOT_FOUND' } });
    }
    const boardId = listRes[0].board_id;

    await req.db.execute('DELETE FROM lists WHERE id = ?', [listId]);
    broadcastBoardEvent(boardId, 'list:deleted', { listId, boardId }, originId);

    return res.json({ message: 'List deleted successfully', id: listId });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
