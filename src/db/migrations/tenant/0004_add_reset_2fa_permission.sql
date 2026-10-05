-- Migration: 0004_add_reset_2fa_permission.sql
-- Adds member.reset_2fa permission and TOTP anti-replay tracking columns

INSERT IGNORE INTO permissions (`key`, category, description) VALUES
  ('member.reset_2fa', 'Members', 'Reset two-factor authentication (2FA) for workspace members');

-- Grant member.reset_2fa to Super Admin and Manager
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Super Admin' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` = 'member.reset_2fa';

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'Manager' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` = 'member.reset_2fa';

-- Columns for TOTP anti-replay tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_code VARCHAR(10) NULL AFTER totp_enabled;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_timestamp BIGINT NULL AFTER last_totp_code;
