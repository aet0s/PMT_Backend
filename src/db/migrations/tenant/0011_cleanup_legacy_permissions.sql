-- Migration: 0011_cleanup_legacy_permissions.sql
-- Remap all legacy role permissions to canonical Phase 4 RBAC keys,
-- eliminate duplicate legacy permission rows from permissions table,
-- and synchronize built-in system role permissions with the canonical registry.

-- 1. Remap role_permissions from legacy keys to their canonical equivalents
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, p_new.id
FROM role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id
JOIN permissions p_new ON p_new.`key` = (
  CASE p_old.`key`
    WHEN 'card.delete' THEN 'task.delete'
    WHEN 'card.create' THEN 'task.create'
    WHEN 'card.edit' THEN 'task.edit'
    WHEN 'card.move' THEN 'task.move'
    WHEN 'card.assign_members' THEN 'task.assign'
    WHEN 'card.comment' THEN 'comment.create'
    WHEN 'card.manage_attachments' THEN 'attachment.upload'
    WHEN 'board.create' THEN 'project.create'
    WHEN 'board.edit_settings' THEN 'project.edit_settings'
    WHEN 'board.delete' THEN 'project.delete'
    WHEN 'board.manage_members' THEN 'project.manage_members'
    WHEN 'workspace.edit_settings' THEN 'workspace.edit'
    WHEN 'workspace.manage_roles' THEN 'role.create'
    WHEN 'workspace.view_billing' THEN 'billing.view'
    WHEN 'member.view_all' THEN 'member.view'
    ELSE NULL
  END
)
WHERE p_new.id IS NOT NULL;

-- 2. Delete legacy role_permissions mappings
DELETE rp FROM role_permissions rp
JOIN permissions p ON rp.permission_id = p.id
WHERE p.`key` IN (
  'card.delete', 'card.create', 'card.edit', 'card.move',
  'card.assign_members', 'card.comment', 'card.manage_attachments',
  'board.create', 'board.edit_settings', 'board.delete', 'board.manage_members',
  'workspace.edit_settings', 'workspace.manage_roles', 'workspace.view_billing',
  'member.view_all'
);

-- 3. Delete legacy permission entries from permissions catalog
DELETE FROM permissions
WHERE `key` IN (
  'card.delete', 'card.create', 'card.edit', 'card.move',
  'card.assign_members', 'card.comment', 'card.manage_attachments',
  'board.create', 'board.edit_settings', 'board.delete', 'board.manage_members',
  'workspace.edit_settings', 'workspace.manage_roles', 'workspace.view_billing',
  'member.view_all'
);

-- 4. Clean up any invalid or legacy category labels
UPDATE permissions SET category = 'workspace' WHERE category = 'Workspace';
UPDATE permissions SET category = 'member' WHERE category = 'Members';
UPDATE permissions SET category = 'project' WHERE category = 'Boards';
UPDATE permissions SET category = 'task' WHERE category = 'Cards';

-- Ensure Team Member does not retain project.create from legacy board.create
DELETE rp FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.name = 'Team Member' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('project.create', 'board.create');

-- 5. Deduplicate system roles if multiple copies exist with workspace_id IS NULL
UPDATE workspace_members wm
JOIN roles r_dup ON wm.role_id = r_dup.id
JOIN (
  SELECT name, MIN(id) as canonical_id
  FROM roles
  WHERE workspace_id IS NULL AND is_system = 1
  GROUP BY name
) r_canon ON r_dup.name = r_canon.name AND r_dup.id > r_canon.canonical_id
SET wm.role_id = r_canon.canonical_id;

UPDATE board_members bm
JOIN roles r_dup ON bm.role_id = r_dup.id
JOIN (
  SELECT name, MIN(id) as canonical_id
  FROM roles
  WHERE workspace_id IS NULL AND is_system = 1
  GROUP BY name
) r_canon ON r_dup.name = r_canon.name AND r_dup.id > r_canon.canonical_id
SET bm.role_id = r_canon.canonical_id;

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r_canon.canonical_id, rp.permission_id
FROM role_permissions rp
JOIN roles r_dup ON rp.role_id = r_dup.id
JOIN (
  SELECT name, MIN(id) as canonical_id
  FROM roles
  WHERE workspace_id IS NULL AND is_system = 1
  GROUP BY name
) r_canon ON r_dup.name = r_canon.name AND r_dup.id > r_canon.canonical_id;

DELETE r_dup FROM roles r_dup
JOIN (
  SELECT name, MIN(id) as canonical_id
  FROM roles
  WHERE workspace_id IS NULL AND is_system = 1
  GROUP BY name
) r_canon ON r_dup.name = r_canon.name AND r_dup.id > r_canon.canonical_id;

