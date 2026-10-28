-- Migration: 0037_cleanup_legacy_duplicate_role_permissions.sql
-- Description: Purges obsolete legacy duplicate permission keys (project.view_dashboard, company.manage_billing, role.assign, task.export, task.import) from role_permissions and permissions tables.

-- 1. Remap role.assign to member.assign_role if member.assign_role not already assigned
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, p_new.id
FROM role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.`key` = 'role.assign'
CROSS JOIN permissions p_new ON p_new.`key` = 'member.assign_role';

-- 2. Delete all role_permissions rows referencing obsolete legacy duplicate keys
DELETE rp FROM role_permissions rp
JOIN permissions p ON rp.permission_id = p.id
WHERE p.`key` IN ('project.view_dashboard', 'company.manage_billing', 'role.assign', 'task.export', 'task.import');

-- 3. Delete obsolete legacy duplicate permissions from permissions table
DELETE FROM permissions
WHERE `key` IN ('project.view_dashboard', 'company.manage_billing', 'role.assign', 'task.export', 'task.import');
