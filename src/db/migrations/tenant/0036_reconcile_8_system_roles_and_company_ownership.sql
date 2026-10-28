-- Migration: 0036_reconcile_8_system_roles_and_company_ownership.sql
-- Description: Creates company_owners table, reconciles all 8 system roles, and hardens least-privilege matrix.

-- 1. Create company_owners table to decouple tenant-level ownership from arbitrary workspace memberships
CREATE TABLE IF NOT EXISTS company_owners (
  user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_co_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Populate company_owners with founding/initial owner if table is empty
INSERT IGNORE INTO company_owners (user_id)
SELECT u.id
FROM users u
JOIN workspace_members wm ON u.id = wm.user_id
JOIN roles r ON wm.role_id = r.id
WHERE (r.name = 'Owner' OR r.name = 'Super Admin')
  AND r.is_system = 1
  AND r.workspace_id IS NULL
ORDER BY u.id ASC
LIMIT 1;

INSERT IGNORE INTO company_owners (user_id)
SELECT u.id
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM company_owners)
ORDER BY u.id ASC
LIMIT 1;

-- 3. Ensure all 8 system roles exist with proper metadata and ranks
INSERT INTO roles (name, is_system, is_editable, rank, workspace_id)
SELECT val.name, val.is_system, val.is_editable, val.rank, NULL
FROM (
  SELECT 'Owner' as name, 1 as is_system, 0 as is_editable, 100 as rank UNION ALL
  SELECT 'Admin', 1, 1, 80 UNION ALL
  SELECT 'Project Manager', 1, 1, 60 UNION ALL
  SELECT 'Team Lead', 1, 1, 50 UNION ALL
  SELECT 'Team Member', 1, 1, 40 UNION ALL
  SELECT 'Viewer', 1, 1, 20 UNION ALL
  SELECT 'Auditor', 1, 1, 15 UNION ALL
  SELECT 'Guest', 1, 1, 10
) val
WHERE NOT EXISTS (
  SELECT 1 FROM roles r WHERE r.name = val.name AND r.workspace_id IS NULL
);

-- Update ranks and properties on existing system roles to guarantee consistency
UPDATE roles SET rank = 100, is_editable = 0, is_system = 1 WHERE (name = 'Owner' OR name = 'Super Admin') AND workspace_id IS NULL;
UPDATE roles SET rank = 80, is_editable = 1, is_system = 1 WHERE name = 'Admin' AND workspace_id IS NULL;
UPDATE roles SET rank = 60, is_editable = 1, is_system = 1 WHERE name = 'Project Manager' AND workspace_id IS NULL;
UPDATE roles SET rank = 50, is_editable = 1, is_system = 1 WHERE name = 'Team Lead' AND workspace_id IS NULL;
UPDATE roles SET rank = 40, is_editable = 1, is_system = 1 WHERE name = 'Team Member' AND workspace_id IS NULL;
UPDATE roles SET rank = 20, is_editable = 1, is_system = 1 WHERE name = 'Viewer' AND workspace_id IS NULL;
UPDATE roles SET rank = 15, is_editable = 1, is_system = 1 WHERE name = 'Auditor' AND workspace_id IS NULL;
UPDATE roles SET rank = 10, is_editable = 1, is_system = 1 WHERE name = 'Guest' AND workspace_id IS NULL;

-- 4. Seed canonical permissions for Team Lead
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Team Lead' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.planned = 0
  AND p.`key` IN (
    'workspace.view', 'company.view', 'member.view', 'team.view',
    'project.view', 'list.create', 'list.edit', 'list.reorder',
    'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign', 'task.assign_self', 'task.complete', 'task.delete_own',
    'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.duplicate', 'task.archive', 'task.restore',
    'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
    'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any',
    'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'file.view',
    'checkin.create', 'checkin.view', 'checkin.review', 'leave.request', 'leave.approve',
    'label.view', 'label.create', 'label.edit', 'label.delete_own',
    'custom_field.view', 'custom_field.create', 'custom_field.edit', 'milestone.view', 'milestone.create', 'milestone.edit',
    'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'backlog.view', 'backlog.reorder',
    'epic.view', 'epic.create', 'epic.edit',
    'time.view_own', 'time.log', 'time.edit_own', 'time.view_all',
    'report.view_project', 'report.view_team', 'dashboard.view_project',
    'view.view', 'view.create', 'view.edit', 'view.delete', 'import_export.export',
    'archive.view', 'archive.restore', 'activity.view',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  );

-- 5. Seed canonical permissions for Auditor
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Auditor' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.planned = 0
  AND p.`key` IN (
    'workspace.view', 'company.view', 'member.view', 'role.view', 'team.view',
    'project.access_all', 'project.view', 'task.view', 'view.view', 'comment.view', 'attachment.view', 'file.view', 'label.view',
    'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
    'audit.view', 'audit.export', 'archive.view', 'activity.view',
    'report.view_project', 'report.view_team', 'report.view_all', 'report.export',
    'dashboard.view_project', 'dashboard.view_executive', 'time.view_all',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  );

-- 6. Enforce least-privilege on Project Manager:
-- Remove workspace-wide member, role, and bypass permissions
DELETE rp FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.name = 'Project Manager' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND (p.`key` LIKE 'member.%' OR p.`key` LIKE 'role.%' OR p.`key` = 'project.access_all');

-- 7. Enforce that Admin does not hold Owner-exclusive destructive capabilities
DELETE rp FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.name = 'Admin' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('workspace.delete', 'company.delete', 'company.export_data', 'billing.manage', 'company.manage_billing');

-- 8. Purge any planned permissions from all roles (planned capabilities must never be active)
DELETE rp FROM role_permissions rp
JOIN permissions p ON rp.permission_id = p.id
WHERE p.planned = 1;
