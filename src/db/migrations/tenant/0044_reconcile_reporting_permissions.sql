-- 0044_reconcile_reporting_permissions.sql
-- Activate report.view_team and reconcile reporting permissions across all roles

-- 1. Activate report.view_team (promote from planned to active)
UPDATE permissions SET planned = 0 WHERE `key` = 'report.view_team';

-- 2. Revoke report.view_project from Team Member, Member, Viewer, and Guest
DELETE rp FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.is_system = 1
  AND r.name IN ('Team Member', 'Member', 'Viewer', 'Guest')
  AND p.`key` = 'report.view_project';

-- 3. Revoke report.view_team from unauthorized roles
DELETE rp FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.is_system = 1
  AND r.name IN ('Team Member', 'Member', 'Viewer', 'Auditor', 'Guest')
  AND p.`key` = 'report.view_team';

-- 4. Grant report.view_team to Owner, Admin, Project Manager, Team Lead
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.is_system = 1
  AND r.workspace_id IS NULL
  AND r.name IN ('Owner', 'Admin', 'Project Manager', 'Team Lead')
  AND p.`key` = 'report.view_team';

-- 5. Grant report.export to Team Lead as well (Owner, Admin, PM already have it)
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.is_system = 1
  AND r.workspace_id IS NULL
  AND r.name = 'Team Lead'
  AND p.`key` = 'report.export';

