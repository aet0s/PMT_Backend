-- Migration: 0017_grant_team_member_workspace_view
-- Ensure Team Member system role has workspace.view, task.archive, task.restore, task.duplicate, checklist.delete, and label.edit permissions

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.`key` IN (
  'workspace.view',
  'task.archive',
  'task.restore',
  'task.duplicate',
  'checklist.delete',
  'label.edit'
)
WHERE r.name = 'Team Member' AND r.is_system = 1 AND r.workspace_id IS NULL;
