const express = require('express');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { broadcastBoardEvent } = require('../socket');
const { requirePermission, requirePermissionForBody, userHasPermission } = require('../middleware/permissions');
const { sanitizePlain } = require('../utils/sanitizer');
const { logActivity } = require('../utils/activity');
const { notify } = require('../services/notify');

const router = express.Router();

const createListSchema = z.object({
  board_id: z.number(),
  name: z.string().min(1, 'List name is required').transform((v) => sanitizePlain(v)),
  position: z.number().optional(),
  wip_limit_enabled: z.boolean().optional(),
  wip_limit: z.number().nullable().optional()
});

const updateListSchema = z.object({
  name: z.string().min(1).transform((v) => sanitizePlain(v)).optional(),
  position: z.number().optional(),
  is_archived: z.boolean().optional(),
  wip_limit_enabled: z.boolean().optional(),
  wip_limit: z.number().nullable().optional()
});

// POST /api/lists
router.post('/', requireAuth, requirePermission('list.create'), validate(createListSchema), async (req, res, next) => {
  let { board_id, name, position, wip_limit_enabled, wip_limit } = req.body;
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

    const isDone = /^(done|completed|finished|closed|released|shipped|archive)/i.test(name.trim());
    const finalWipEnabled = wip_limit_enabled !== undefined ? (wip_limit_enabled ? 1 : 0) : (isDone ? 0 : 1);
    const finalWipLimit = wip_limit !== undefined ? (wip_limit === null ? null : Number(wip_limit)) : null;

    const listExec = await req.db.execute(
      'INSERT INTO lists (board_id, name, position, wip_limit_enabled, wip_limit) VALUES (?, ?, ?, ?, ?)',
      [board_id, name, position, finalWipEnabled, finalWipLimit]
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
router.patch(
  '/:id',
  requireAuth,
  requirePermissionForBody((req) => {
    const { name, position, is_archived, wip_limit_enabled, wip_limit } = req.body;
    const isEdit = name !== undefined || is_archived !== undefined || wip_limit_enabled !== undefined || wip_limit !== undefined;
    const isReorderOnly = position !== undefined && !isEdit;
    if (isReorderOnly) {
      return { any: ['list.reorder', 'list.edit'] };
    }
    return 'list.edit';
  }),
  validate(updateListSchema),
  async (req, res, next) => {
  const listId = Number(req.params.id);
  const { name, position, is_archived, wip_limit_enabled, wip_limit } = req.body;
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
    const { board_id: boardId } = listCheck[0];

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
    if (wip_limit_enabled !== undefined) {
      updates.push('wip_limit_enabled = ?');
      values.push(wip_limit_enabled ? 1 : 0);
    }
    if (wip_limit !== undefined) {
      updates.push('wip_limit = ?');
      values.push(wip_limit === null ? null : Number(wip_limit));
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: { message: 'No fields to update', code: 'BAD_REQUEST' } });
    }

    values.push(listId, boardId);
    await req.db.execute(
      `UPDATE lists SET ${updates.join(', ')} WHERE id = ? AND board_id = ?`,
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
      await logActivity(boardId, null, req.user.id, 'list_reordered', { list_name: updatedList.name || listCheck[0]?.name, position: updatedList.position }, req.db, req.tenant?.id);
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

    await req.db.execute('DELETE FROM lists WHERE id = ? AND board_id = ?', [listId, boardId]);
    await logActivity(boardId, null, req.user.id, 'list_deleted', { list_name: listRes[0]?.name }, req.db, req.tenant?.id);
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
