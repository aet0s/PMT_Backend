const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { requirePermission, accessibleBoardIds } = require('../middleware/permissions');

const router = express.Router();

// GET /api/archive
router.get('/', requireAuth, requirePermission('archive.view'), async (req, res, next) => {
  try {
    const workspaceIdFilter = req.query.workspace_id && req.query.workspace_id !== 'all' ? Number(req.query.workspace_id) : null;
    const boardIdFilter = req.query.board_id && req.query.board_id !== 'all' ? Number(req.query.board_id) : null;
    const rawLabel = req.query.label_id || req.query.label_name || req.query.label;
    const labelFilter = rawLabel && rawLabel !== 'all' ? rawLabel.trim() : null;
    const assigneeIdFilter = req.query.assignee_id && req.query.assignee_id !== 'all' ? Number(req.query.assignee_id) : null;
    const assignerIdFilter = req.query.assigner_id && req.query.assigner_id !== 'all' ? Number(req.query.assigner_id) : null;
    const startDateFilter = req.query.start_date && req.query.start_date !== 'all' ? req.query.start_date.trim() : null;
    const endDateFilter = req.query.end_date && req.query.end_date !== 'all' ? req.query.end_date.trim() : null;
    const searchQuery = req.query.search ? req.query.search.trim() : '';

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 20));
    const offset = (page - 1) * limit;

    // 1. Fetch user's active workspaces for progressive workspace selection
    const userWorkspaces = await req.db.query(
      `SELECT DISTINCT w.id, w.name, w.created_at
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       WHERE wm.user_id = ? AND w.is_archived = 0
       ORDER BY w.name ASC`,
      [req.user.id]
    );

    // Section 5.4: Resolve accessibleBoardIds across candidate workspaces
    let allAccessibleBoardIds = [];
    if (workspaceIdFilter) {
      allAccessibleBoardIds = await accessibleBoardIds(req.user.id, workspaceIdFilter, 'project.view', req.db);
    } else {
      for (const uw of userWorkspaces) {
        const bIds = await accessibleBoardIds(req.user.id, uw.id, 'project.view', req.db);
        allAccessibleBoardIds.push(...bIds);
      }
    }

    if (boardIdFilter) {
      const [boardCheck] = await req.db.query(
        `SELECT b.id FROM boards b
         JOIN workspace_members wm ON b.workspace_id = wm.workspace_id
         WHERE b.id = ? AND wm.user_id = ?`,
        [boardIdFilter, req.user.id]
      );
      if (!boardCheck) {
        return res.json({
          userWorkspaces,
          userBoards: [],
          workspaces: [],
          boards: [],
          cards: [],
          total: 0,
          page,
          limit,
          totalPages: 0,
          availableLabels: [],
          availableMembers: []
        });
      }
    }

    // 2. Fetch user's active boards for board selection (filtered by accessibleBoardIds)
    let userBoards = [];
    if (allAccessibleBoardIds.length > 0) {
      userBoards = await req.db.query(
        `SELECT DISTINCT b.id, b.workspace_id, b.name, b.background_color
         FROM boards b
         JOIN workspaces w ON b.workspace_id = w.id
         WHERE b.id IN (?) AND b.is_archived = 0 AND w.is_archived = 0
         ORDER BY b.name ASC`,
        [allAccessibleBoardIds]
      );
    }

    // Check if user is a Company Owner / Admin
    const isCompanyAdminOrOwner = await req.db.query(
      `SELECT 1 FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ? AND ((r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 80)) OR wm.role IN ('Owner', 'Super Admin', 'Admin'))
       LIMIT 1`,
      [req.user.id]
    );
    const hasCompanyWideAccess = isCompanyAdminOrOwner.length > 0;

    // 3. Fetch archived workspaces
    let workspacesRes = [];
    if (hasCompanyWideAccess) {
      workspacesRes = await req.db.query(
        `SELECT DISTINCT w.id, w.name, w.created_at, COALESCE(r.name, wm.role, 'Owner') as role, COALESCE(r.rank, 100) as rank
         FROM workspaces w
         LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
         LEFT JOIN roles r ON wm.role_id = r.id
         WHERE w.is_archived = 1
         ORDER BY w.created_at DESC`,
        [req.user.id]
      );
    } else {
      workspacesRes = await req.db.query(
        `SELECT w.id, w.name, w.created_at, COALESCE(r.name, wm.role) as role, r.rank
         FROM workspaces w
         JOIN workspace_members wm ON w.id = wm.workspace_id
         LEFT JOIN roles r ON wm.role_id = r.id
         WHERE wm.user_id = ? AND w.is_archived = 1
         ORDER BY w.created_at DESC`,
        [req.user.id]
      );
    }

    // 4. Fetch archived boards (scoped to candidate workspaces user has access to, NOT filtered by single card boardIdFilter)
    let boardsRes = [];
    if (hasCompanyWideAccess) {
      const boardParams = [req.user.id];
      let wsCond = '';
      if (workspaceIdFilter) {
        wsCond = 'AND w.id = ?';
        boardParams.push(workspaceIdFilter);
      }
      boardsRes = await req.db.query(
        `SELECT DISTINCT b.id, b.workspace_id, b.name, b.background_color, b.created_at, w.name as workspace_name, COALESCE(r.name, wm.role, 'Owner') as role
         FROM boards b
         JOIN workspaces w ON b.workspace_id = w.id
         LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
         LEFT JOIN roles r ON wm.role_id = r.id
         WHERE b.is_archived = 1 ${wsCond}
         ORDER BY b.created_at DESC`,
        boardParams
      );
    } else {
      const boardParams = [req.user.id];
      let wsCond = '';
      if (workspaceIdFilter) {
        wsCond = 'AND w.id = ?';
        boardParams.push(workspaceIdFilter);
      }
      boardsRes = await req.db.query(
        `SELECT DISTINCT b.id, b.workspace_id, b.name, b.background_color, b.created_at, w.name as workspace_name, COALESCE(r.name, wm.role) as role
         FROM boards b
         JOIN workspaces w ON b.workspace_id = w.id
         JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
         LEFT JOIN roles r ON wm.role_id = r.id
         WHERE b.is_archived = 1 ${wsCond}
         ORDER BY b.created_at DESC`,
        boardParams
      );
    }

    // 5. Fetch available labels for dropdowns (scoped to selected workspace/board, or user's active workspaces)
    const labelParams = [req.user.id];
    let labelScopeCondition = '';
    if (boardIdFilter) {
      labelScopeCondition = 'AND b.id = ?';
      labelParams.push(boardIdFilter);
    } else if (workspaceIdFilter) {
      labelScopeCondition = 'AND w.id = ?';
      labelParams.push(workspaceIdFilter);
    }

    const availableLabels = await req.db.query(
      `SELECT MIN(l.id) as id, l.name, l.color
       FROM labels l
       JOIN boards b ON l.board_id = b.id
       JOIN workspaces w ON b.workspace_id = w.id
       JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
       WHERE b.is_archived = 0 AND w.is_archived = 0 ${labelScopeCondition}
       AND l.name IS NOT NULL AND TRIM(l.name) != ''
       GROUP BY l.name, l.color
       ORDER BY l.name ASC`,
      labelParams
    );

    // 6. Fetch available members / assigners for dropdowns
    const memberParams = [req.user.id];
    let memberScopeCondition = '';
    if (workspaceIdFilter) {
      memberScopeCondition = 'AND w.id = ?';
      memberParams.push(workspaceIdFilter);
    }

    const availableMembers = await req.db.query(
      `SELECT DISTINCT u.id, u.name, u.email, u.avatar_url
       FROM users u
       JOIN workspace_members wm ON u.id = wm.user_id
       JOIN workspaces w ON wm.workspace_id = w.id
       JOIN workspace_members wm_user ON w.id = wm_user.workspace_id AND wm_user.user_id = ?
       WHERE w.is_archived = 0 ${memberScopeCondition}
       ORDER BY u.name ASC`,
      memberParams
    );

    // 7. Build card filtering query
    const cardConditions = [
      'c.is_archived = 1',
      '(wm.user_id IS NOT NULL OR bm.user_id IS NOT NULL)'
    ];
    const cardParams = [req.user.id, req.user.id];

    if (workspaceIdFilter) {
      cardConditions.push('w.id = ?');
      cardParams.push(workspaceIdFilter);
    }
    if (boardIdFilter) {
      cardConditions.push('b.id = ?');
      cardParams.push(boardIdFilter);
    }

    if (searchQuery) {
      const cleanId = searchQuery.replace(/^#/, '');
      const isNum = !isNaN(Number(cleanId)) && cleanId.length > 0;
      if (isNum) {
        cardConditions.push('(c.title LIKE ? OR c.description LIKE ? OR c.id = ?)');
        cardParams.push(`%${searchQuery}%`, `%${searchQuery}%`, Number(cleanId));
      } else {
        cardConditions.push('(c.title LIKE ? OR c.description LIKE ?)');
        cardParams.push(`%${searchQuery}%`, `%${searchQuery}%`);
      }
    }

    if (labelFilter) {
      const isNum = !isNaN(Number(labelFilter));
      if (isNum) {
        cardConditions.push(`
          EXISTS (
            SELECT 1 FROM card_labels cl 
            JOIN labels l2 ON cl.label_id = l2.id 
            WHERE cl.card_id = c.id 
            AND (cl.label_id = ? OR LOWER(l2.name) = (SELECT LOWER(name) FROM labels WHERE id = ? LIMIT 1))
          )
        `);
        cardParams.push(Number(labelFilter), Number(labelFilter));
      } else {
        cardConditions.push('EXISTS (SELECT 1 FROM card_labels cl JOIN labels l2 ON cl.label_id = l2.id WHERE cl.card_id = c.id AND LOWER(l2.name) = LOWER(?))');
        cardParams.push(labelFilter);
      }
    }

    if (assigneeIdFilter) {
      cardConditions.push('EXISTS (SELECT 1 FROM card_members cm WHERE cm.card_id = c.id AND cm.user_id = ?)');
      cardParams.push(assigneeIdFilter);
    }

    if (assignerIdFilter) {
      cardConditions.push('EXISTS (SELECT 1 FROM card_assigners ca WHERE ca.card_id = c.id AND ca.user_id = ?)');
      cardParams.push(assignerIdFilter);
    }

    // Filter cards made/created between Start Date and End Date
    if (startDateFilter) {
      const sDate = startDateFilter.split('T')[0];
      cardConditions.push('c.created_at >= ?');
      cardParams.push(`${sDate} 00:00:00`);
    }

    if (endDateFilter) {
      const eDate = endDateFilter.split('T')[0];
      cardConditions.push('c.created_at <= ?');
      cardParams.push(`${eDate} 23:59:59`);
    }

    const whereClause = cardConditions.join(' AND ');

    // Count total matching cards
    const countSql = `
      SELECT COUNT(DISTINCT c.id) as total
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      JOIN boards b ON l.board_id = b.id
      JOIN workspaces w ON b.workspace_id = w.id
      JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
      LEFT JOIN board_members bm ON b.id = bm.board_id AND bm.user_id = ?
      WHERE ${whereClause}
    `;
    const countRes = await req.db.query(countSql, cardParams);
    const totalCards = Number(countRes[0]?.total || 0);
    const totalPages = Math.ceil(totalCards / limit) || 1;

    // Fetch paginated cards with summary counts
    const cardsSql = `
      SELECT DISTINCT c.id, c.list_id, c.title, c.description, c.due_date, c.start_date,
             c.is_complete, c.completed_at, c.created_at,
             l.name as list_name, b.id as board_id, b.name as board_name,
             w.id as workspace_id, w.name as workspace_name,
             (SELECT COUNT(*) FROM attachments a WHERE a.card_id = c.id) as attachments_count,
             (SELECT COUNT(*) FROM comments cm WHERE cm.card_id = c.id) as comments_count,
             (SELECT COUNT(*) FROM checklists ch WHERE ch.card_id = c.id) as checklists_count,
             (SELECT COUNT(*) FROM checklist_items ci JOIN checklists ch2 ON ci.checklist_id = ch2.id WHERE ch2.card_id = c.id) as checklist_items_total,
             (SELECT COUNT(*) FROM checklist_items ci2 JOIN checklists ch3 ON ci2.checklist_id = ch3.id WHERE ch3.card_id = c.id AND ci2.is_checked = 1) as checklist_items_completed
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      JOIN boards b ON l.board_id = b.id
      JOIN workspaces w ON b.workspace_id = w.id
      JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
      LEFT JOIN board_members bm ON b.id = bm.board_id AND bm.user_id = ?
      WHERE ${whereClause}
      ORDER BY c.created_at DESC
      LIMIT ? OFFSET ?
    `;

    const cardsRes = await req.db.query(cardsSql, [...cardParams, limit, offset]);

    // Attach all detailed relations for the retrieved page of cards
    const cardIds = cardsRes.map((c) => c.id);
    const cardLabelsMap = {};
    const cardMembersMap = {};
    const cardAssignersMap = {};
    const cardAttachmentsMap = {};
    const cardCommentsMap = {};
    const cardChecklistsMap = {};

    if (cardIds.length > 0) {
      const [labels, members, assigners, attachments, comments, checklists] = await Promise.all([
        req.db.query(
          `SELECT cl.card_id, l.id, l.name, l.color 
           FROM card_labels cl 
           JOIN labels l ON cl.label_id = l.id 
           WHERE cl.card_id IN (?)`,
          [cardIds]
        ),
        req.db.query(
          `SELECT cm.card_id, u.id, u.name, u.email, u.avatar_url 
           FROM card_members cm 
           JOIN users u ON cm.user_id = u.id 
           WHERE cm.card_id IN (?) 
           ORDER BY u.name ASC`,
          [cardIds]
        ),
        req.db.query(
          `SELECT ca.card_id, u.id, u.name, u.email, u.avatar_url 
           FROM card_assigners ca 
           JOIN users u ON ca.user_id = u.id 
           WHERE ca.card_id IN (?) 
           ORDER BY u.name ASC`,
          [cardIds]
        ),
        req.db.query(
          `SELECT a.*, u.name as uploader_name 
           FROM attachments a 
           LEFT JOIN users u ON a.uploaded_by_user_id = u.id 
           WHERE a.card_id IN (?) 
           ORDER BY a.created_at DESC`,
          [cardIds]
        ),
        req.db.query(
          `SELECT c.*, u.name as author_name, u.avatar_url as author_avatar
           FROM comments c 
           JOIN users u ON c.user_id = u.id 
           WHERE c.card_id IN (?) 
           ORDER BY c.created_at ASC`,
          [cardIds]
        ),
        req.db.query(
          `SELECT ch.id, ch.card_id, ch.title 
           FROM checklists ch 
           WHERE ch.card_id IN (?) 
           ORDER BY ch.id ASC`,
          [cardIds]
        )
      ]);

      labels.forEach((row) => {
        if (!cardLabelsMap[row.card_id]) cardLabelsMap[row.card_id] = [];
        cardLabelsMap[row.card_id].push({ id: row.id, name: row.name, color: row.color });
      });

      members.forEach((row) => {
        if (!cardMembersMap[row.card_id]) cardMembersMap[row.card_id] = [];
        cardMembersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email, avatar_url: row.avatar_url });
      });

      assigners.forEach((row) => {
        if (!cardAssignersMap[row.card_id]) cardAssignersMap[row.card_id] = [];
        cardAssignersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email, avatar_url: row.avatar_url });
      });

      attachments.forEach((row) => {
        if (!cardAttachmentsMap[row.card_id]) cardAttachmentsMap[row.card_id] = [];
        cardAttachmentsMap[row.card_id].push(row);
      });

      comments.forEach((row) => {
        if (!cardCommentsMap[row.card_id]) cardCommentsMap[row.card_id] = [];
        cardCommentsMap[row.card_id].push(row);
      });

      // Fetch checklist items for found checklists
      const checklistIds = checklists.map((ch) => ch.id);
      const checklistItemsMap = {};
      if (checklistIds.length > 0) {
        const items = await req.db.query(
          `SELECT * FROM checklist_items WHERE checklist_id IN (?) ORDER BY position ASC, id ASC`,
          [checklistIds]
        );
        items.forEach((it) => {
          if (!checklistItemsMap[it.checklist_id]) checklistItemsMap[it.checklist_id] = [];
          checklistItemsMap[it.checklist_id].push(it);
        });
      }

      checklists.forEach((ch) => {
        if (!cardChecklistsMap[ch.card_id]) cardChecklistsMap[ch.card_id] = [];
        cardChecklistsMap[ch.card_id].push({
          ...ch,
          items: checklistItemsMap[ch.id] || []
        });
      });
    }

    const cards = cardsRes.map((c) => ({
      ...c,
      labels: cardLabelsMap[c.id] || [],
      members: cardMembersMap[c.id] || [],
      assigners: cardAssignersMap[c.id] || [],
      attachments: cardAttachmentsMap[c.id] || [],
      comments: cardCommentsMap[c.id] || [],
      checklists: cardChecklistsMap[c.id] || []
    }));

    return res.json({
      userWorkspaces,
      userBoards,
      availableLabels,
      availableMembers,
      availableAssigners: availableMembers,
      workspaces: workspacesRes,
      boards: boardsRes,
      cards,
      pagination: {
        page,
        limit,
        totalCards,
        totalPages
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
