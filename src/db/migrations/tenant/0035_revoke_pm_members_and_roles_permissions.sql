-- 0035_revoke_pm_members_and_roles_permissions.sql
-- Default permission hardening: Project Manager cannot view members or roles/permissions tab.
DELETE rp FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.name = 'Project Manager'
  AND r.is_system = 1
  AND r.workspace_id IS NULL
  AND (p.`key` LIKE 'member.%' OR p.`key` LIKE 'role.%');
