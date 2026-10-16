-- Migration: 0021_rbac_matrix_v2_schema.sql
-- Description: Schema changes for RBAC Matrix v2: cards.created_by, workspace_members.status, and catalog additions.

SET @dbname = DATABASE();

-- 1. Add created_by column to cards table
SET @col_cards_created_by = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND COLUMN_NAME = 'created_by'
);

SET @stmt_c_cb = IF(
  @col_cards_created_by = 0,
  'ALTER TABLE cards ADD COLUMN created_by BIGINT UNSIGNED NULL AFTER list_id;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt_c_cb;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Index on cards.created_by
SET @idx_cards_created_by = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND INDEX_NAME = 'idx_cards_created_by'
);

SET @stmt_idx_cb = IF(
  @idx_cards_created_by = 0,
  'CREATE INDEX idx_cards_created_by ON cards (created_by);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt_idx_cb;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Backfill cards.created_by from activity_log where created_card event exists
UPDATE cards c
JOIN (
  SELECT card_id, user_id
  FROM activity_log
  WHERE card_id IS NOT NULL AND action_type = 'created_card'
  GROUP BY card_id, user_id
) act ON c.id = act.card_id
SET c.created_by = act.user_id
WHERE c.created_by IS NULL;

-- 2. Add status column to workspace_members table
SET @col_wm_status = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'workspace_members'
    AND COLUMN_NAME = 'status'
);

SET @stmt_wm_status = IF(
  @col_wm_status = 0,
  'ALTER TABLE workspace_members ADD COLUMN status ENUM(''active'',''deactivated'') NOT NULL DEFAULT ''active'' AFTER role_id;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt_wm_status;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 3. Register new RBAC permissions in permissions catalog
INSERT IGNORE INTO permissions (`key`, category, description, dangerous, planned, label) VALUES
('project.access_all', 'project', 'Permissions apply across all workspace boards without explicit board membership', 1, 0, 'Access All Projects'),
('project.assign_role', 'project', 'Assign or modify board-level member roles', 1, 0, 'Assign Project Roles'),
('member.invite_guest', 'member', 'Invite external collaborators to specific boards', 0, 0, 'Invite Guest Members'),
('task.assign_self', 'task', 'Assign or unassign yourself on cards', 0, 0, 'Assign Self to Tasks'),
('task.complete', 'task', 'Mark tasks done or reopen completed tasks', 0, 0, 'Complete Tasks'),
('task.delete_own', 'task', 'Delete cards created by yourself', 1, 0, 'Delete Own Tasks'),
('label.delete_own', 'label', 'Delete custom labels created by yourself', 0, 0, 'Delete Own Labels'),
('project.duplicate', 'project', 'Clone project board and structure', 0, 1, 'Duplicate Project'),
('project.change_visibility', 'project', 'Toggle board public or private visibility', 0, 1, 'Change Project Visibility');

-- 4. Promote member.deactivate and company.manage_security from planned to real
UPDATE permissions SET planned = 0 WHERE `key` IN ('member.deactivate', 'company.manage_security');

-- 5. Migrate role_permissions rows from deprecated duplicate keys to canonical keys
-- role.assign -> member.assign_role
UPDATE IGNORE role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.key = 'role.assign'
JOIN permissions p_new ON p_new.key = 'member.assign_role'
SET rp.permission_id = p_new.id;

-- project.view_dashboard -> dashboard.view_project
UPDATE IGNORE role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.key = 'project.view_dashboard'
JOIN permissions p_new ON p_new.key = 'dashboard.view_project'
SET rp.permission_id = p_new.id;

-- company.manage_billing -> billing.manage
UPDATE IGNORE role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.key = 'company.manage_billing'
JOIN permissions p_new ON p_new.key = 'billing.manage'
SET rp.permission_id = p_new.id;

-- task.import -> import_export.import
UPDATE IGNORE role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.key = 'task.import'
JOIN permissions p_new ON p_new.key = 'import_export.import'
SET rp.permission_id = p_new.id;

-- task.export -> import_export.export
UPDATE IGNORE role_permissions rp
JOIN permissions p_old ON rp.permission_id = p_old.id AND p_old.key = 'task.export'
JOIN permissions p_new ON p_new.key = 'import_export.export'
SET rp.permission_id = p_new.id;
