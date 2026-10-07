const express = require('express');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { broadcastBoardEvent } = require('../socket');
const { requirePermission, userHasPermission } = require('../middleware/permissions');
const { sanitizePlain } = require('../utils/sanitizer');
const { logActivity } = require('../utils/activity');
const { notify } = require('../services/notify');

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
    await logActivity(board_id, null, req.user.id, 'list_created', { list_name: name }, req.db, req.tenant?.id);
    broadcastBoardEvent(board_id, 'list:created', { list: newList }, originId, req.tenant?.id);

    const [bRes] = await req.db.query('SELECT workspace_id, name FROM boards WHERE id = ?', [board_id]);
    if (bRes) {
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        workspaceId: bRes.workspace_id,
        boardId: board_id,
        eventType: 'list.created',
        actorId: req.user.id,
        data: { listTitle: name, boardName: bRes.name }
      });
    }

    return res.status(201).json({ list: newList });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/lists/:id
router.patch('/:id', requireAuth, validate(updateListSchema), async (req, res, next) => {
  const listId = Number(req.params.id);
  const { name, position, is_archived } = req.body;
  const originId = req.headers['x-origin-id'];

  try {
    const listCheck = await req.db.query(
      `SELECT l.board_id, l.name, b.workspace_id 
       FROM lists l 
       JOIN boards b ON l.board_id = b.id 
       WHERE l.id = ?`,
      [listId]
    );
    if (listCheck.length === 0) {
      return res.status(404).json({ error: { message: 'List not found', code: 'NOT_FOUND' } });
    }
    const { board_id: boardId, workspace_id: workspaceId } = listCheck[0];

    const isReorder = position !== undefined;
    const isEdit = name !== undefined || is_archived !== undefined;

    if (isReorder) {
      const canReorder = await userHasPermission(req.user.id, workspaceId, 'list.reorder', req.db, boardId);
      if (!canReorder) {
        return res.status(403).json({ error: { message: 'Permission denied to reorder lists', code: 'PERMISSION_DENIED' } });
      }
    }
    if (isEdit || !isReorder) {
      const canEdit = await userHasPermission(req.user.id, workspaceId, 'list.edit', req.db, boardId);
      if (!canEdit) {
        return res.status(403).json({ error: { message: 'Permission denied to edit lists', code: 'PERMISSION_DENIED' } });
      }
    }

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
    const [bRes] = await req.db.query('SELECT workspace_id, name FROM boards WHERE id = ?', [boardId]);

    if (is_archived === true) {
      await logActivity(boardId, null, req.user.id, 'list_archived', { list_name: updatedList.name || listCheck[0]?.name }, req.db, req.tenant?.id);
      if (bRes) {
        await notify({
          db: req.db,
          tenantId: req.tenant?.id,
          workspaceId: bRes.workspace_id,
          boardId,
          eventType: 'list.archived',
          actorId: req.user.id,
          data: { listTitle: updatedList.name || listCheck[0]?.name, boardName: bRes.name }
        });
      }
    } else if (name !== undefined) {
      await logActivity(boardId, null, req.user.id, 'list_renamed', { list_name: name }, req.db, req.tenant?.id);
      if (bRes) {
        await notify({
          db: req.db,
          tenantId: req.tenant?.id,
          workspaceId: bRes.workspace_id,
          boardId,
          eventType: 'list.renamed',
          actorId: req.user.id,
          data: { listTitle: name, boardName: bRes.name }
        });
      }
    } else if (position !== undefined && bRes) {
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        workspaceId: bRes.workspace_id,
        boardId,
        eventType: 'list.moved',
        actorId: req.user.id,
        data: { listTitle: updatedList.name || listCheck[0]?.name, boardName: bRes.name }
      });
    }

    const eventName = position !== undefined ? 'list:reordered' : 'list:updated';
    broadcastBoardEvent(boardId, eventName, { listId: updatedList.id, position: updatedList.position, list: updatedList }, originId, req.tenant?.id);

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
    const listRes = await req.db.query('SELECT board_id, name FROM lists WHERE id = ?', [listId]);
    if (listRes.length === 0) {
      return res.status(404).json({ error: { message: 'List not found', code: 'NOT_FOUND' } });
    }
    const boardId = listRes[0].board_id;
    const [bRes] = await req.db.query('SELECT workspace_id, name FROM boards WHERE id = ?', [boardId]);

    await req.db.execute('DELETE FROM lists WHERE id = ?', [listId]);
    broadcastBoardEvent(boardId, 'list:deleted', { listId, boardId }, originId, req.tenant?.id);

    if (bRes) {
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        workspaceId: bRes.workspace_id,
        boardId,
        eventType: 'list.deleted',
        actorId: req.user.id,
        data: { listTitle: listRes[0]?.name || 'List', boardName: bRes.name }
      });
    }

    return res.json({ message: 'List deleted successfully', id: listId });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
