-- 0047_notes_table_and_permissions.sql
-- Adds personal private user_notes table and notes.view_own / notes.manage_own RBAC permissions

CREATE TABLE IF NOT EXISTS user_notes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  content TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  color ENUM('yellow', 'peach', 'blush', 'lilac', 'sky', 'mint', 'sage') NOT NULL DEFAULT 'yellow',
  x INT NOT NULL DEFAULT 100,
  y INT NOT NULL DEFAULT 100,
  width INT NOT NULL DEFAULT 220,
  height INT NOT NULL DEFAULT 200,
  z_index INT NOT NULL DEFAULT 1,
  is_pinned TINYINT(1) NOT NULL DEFAULT 0,
  rotation_seed TINYINT NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at DATETIME(3) NULL DEFAULT NULL,
  INDEX idx_user_notes_user_deleted (user_id, deleted_at),
  INDEX idx_user_notes_user_updated (user_id, updated_at),
  CONSTRAINT fk_user_notes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 1. Insert the two personal notes permissions (idempotent)
INSERT IGNORE INTO permissions (`key`, category, description, label, dangerous, planned) VALUES
  ('notes.view_own', 'Personal', 'Open the Notes page and read own sticky notes', 'View Personal Notes', 0, 0),
  ('notes.manage_own', 'Personal', 'Create, edit, move, resize, pin, and delete own sticky notes', 'Manage Personal Notes', 0, 0);

-- 2. Grant both permissions to all 8 system roles (including legacy aliases if present)
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.is_system = 1
  AND r.name IN ('Owner', 'Super Admin', 'Admin', 'Project Manager', 'Manager', 'Team Lead', 'Lead', 'Team Member', 'Member', 'Viewer', 'Auditor', 'Guest')
  AND p.`key` IN ('notes.view_own', 'notes.manage_own');

-- 3. Grant both permissions to all existing custom roles so current users retain Notes access by default
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.is_system = 0
  AND p.`key` IN ('notes.view_own', 'notes.manage_own');
