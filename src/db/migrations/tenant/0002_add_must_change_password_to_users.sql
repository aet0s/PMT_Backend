-- Migration: 0002_add_must_change_password_to_users
-- Adds must_change_password flag, expires_at to invitations, and member.reset_password permission

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password TINYINT(1) NOT NULL DEFAULT 0;

ALTER TABLE pending_invitations ADD COLUMN IF NOT EXISTS expires_at DATETIME(3) NULL;

INSERT IGNORE INTO permissions (`key`, category, description)
VALUES ('member.reset_password', 'Members', 'Reset temporary password for workspace members');

-- Grant member.reset_password to Super Admin and Manager
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Super Admin' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` = 'member.reset_password';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Manager' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` = 'member.reset_password';
