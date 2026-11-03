-- 0042_activate_report_export_permission.sql
-- Activate report.export permission and grant to Owner, Admin, Project Manager, and Auditor

UPDATE permissions SET planned = 0 WHERE `key` = 'report.export';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.is_system = 1
  AND r.workspace_id IS NULL
  AND r.name IN ('Owner', 'Admin', 'Project Manager', 'Auditor')
  AND p.`key` = 'report.export';

