const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// GET /api/permissions - Full permission catalog grouped by category
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const result = await req.db.query('SELECT id, `key`, category, description FROM permissions ORDER BY category ASC, id ASC');

    const grouped = {};
    result.forEach((p) => {
      if (!grouped[p.category]) {
        grouped[p.category] = [];
      }
      grouped[p.category].push(p);
    });

    const categories = Object.keys(grouped).map((categoryName) => ({
      name: categoryName,
      permissions: grouped[categoryName]
    }));

    return res.json({ categories, permissions: result });
  } catch (err) {
    next(err);
  }
});

// GET /api/permissions/me?workspace_id=&project_id=
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const { getUserPermissions } = require('../middleware/permissions');
    let workspaceId = req.query.workspace_id ? Number(req.query.workspace_id) : null;
    const projectId = req.query.project_id ? Number(req.query.project_id) : null;

    if (!workspaceId && projectId) {
      const bRes = await req.db.query('SELECT workspace_id FROM boards WHERE id = ?', [projectId]);
      if (bRes[0]) workspaceId = bRes[0].workspace_id;
    }

    if (!workspaceId) {
      const wsRows = await req.db.query(
        'SELECT workspace_id FROM workspace_members WHERE user_id = ? ORDER BY workspace_id ASC LIMIT 1',
        [req.user.id]
      );
      workspaceId = wsRows[0]?.workspace_id || 1;
    }

    const data = await getUserPermissions(req.user.id, workspaceId, req.db, projectId);
    return res.json(data);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
