-- Migration: 0043_grant_team_member_task_assign.sql
-- Description: Grants task.assign permission to the system role 'Team Member' across all workspaces.

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Team Member'
  AND r.is_system = 1
  AND r.workspace_id IS NULL
  AND p.`key` = 'task.assign';

