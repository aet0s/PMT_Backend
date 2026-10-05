-- Migration: 0001_baseline
-- Baseline tenant schema for MySQL / MariaDB

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS workspaces (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  is_archived TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS permissions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `key` VARCHAR(100) NOT NULL UNIQUE,
  category VARCHAR(100) NOT NULL,
  description TEXT,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS roles (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workspace_id BIGINT UNSIGNED NULL,
  name VARCHAR(100) NOT NULL,
  is_system TINYINT(1) NOT NULL DEFAULT 0,
  is_editable TINYINT(1) NOT NULL DEFAULT 1,
  created_by_user_id BIGINT UNSIGNED NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_roles_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_roles_creator FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_roles_workspace_id (workspace_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id BIGINT UNSIGNED NOT NULL,
  permission_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  CONSTRAINT fk_rp_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
  INDEX idx_rp_permission_id (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS workspace_members (
  workspace_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  role_id BIGINT UNSIGNED NULL,
  role VARCHAR(50) DEFAULT 'member',
  PRIMARY KEY (workspace_id, user_id),
  CONSTRAINT fk_wm_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_wm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_wm_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL,
  INDEX idx_wm_user_id (user_id),
  INDEX idx_wm_role_id (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS boards (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workspace_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(255) NOT NULL,
  background_color VARCHAR(100) DEFAULT 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950',
  is_archived TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_boards_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  INDEX idx_boards_workspace_id (workspace_id),
  INDEX idx_boards_is_archived (is_archived)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS board_members (
  board_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'member',
  PRIMARY KEY (board_id, user_id),
  CONSTRAINT fk_bm_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE,
  CONSTRAINT fk_bm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_bm_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS lists (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  board_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(255) NOT NULL,
  position DOUBLE NOT NULL,
  is_archived TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_lists_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE,
  INDEX idx_lists_board_id_position (board_id, position),
  INDEX idx_lists_is_archived (is_archived)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS cards (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  list_id BIGINT UNSIGNED NOT NULL,
  title VARCHAR(500) NOT NULL,
  description TEXT NULL,
  position DOUBLE NOT NULL,
  due_date DATETIME(3) NULL,
  start_date DATETIME(3) NULL,
  is_complete TINYINT(1) NOT NULL DEFAULT 0,
  is_archived TINYINT(1) NOT NULL DEFAULT 0,
  due_reminder_sent_at DATETIME(3) NULL,
  overdue_notified_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_cards_list FOREIGN KEY (list_id) REFERENCES lists(id) ON DELETE CASCADE,
  INDEX idx_cards_list_id_position (list_id, position),
  INDEX idx_cards_due_date (due_date),
  INDEX idx_cards_is_archived (is_archived)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS labels (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  board_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(100) NOT NULL,
  color VARCHAR(50) NOT NULL,
  CONSTRAINT fk_labels_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE,
  INDEX idx_labels_board_id (board_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS card_labels (
  card_id BIGINT UNSIGNED NOT NULL,
  label_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (card_id, label_id),
  CONSTRAINT fk_cl_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_cl_label FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE,
  INDEX idx_cl_label_id (label_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS card_members (
  card_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (card_id, user_id),
  CONSTRAINT fk_cm_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_cm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_cm_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS checklists (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  card_id BIGINT UNSIGNED NOT NULL,
  title VARCHAR(255) NOT NULL,
  position DOUBLE NOT NULL DEFAULT 1000.0,
  CONSTRAINT fk_checklists_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  INDEX idx_checklists_card_id (card_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS checklist_items (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  checklist_id BIGINT UNSIGNED NOT NULL,
  text VARCHAR(500) NOT NULL,
  is_checked TINYINT(1) NOT NULL DEFAULT 0,
  position DOUBLE NOT NULL DEFAULT 1000.0,
  CONSTRAINT fk_cli_checklist FOREIGN KEY (checklist_id) REFERENCES checklists(id) ON DELETE CASCADE,
  INDEX idx_cli_checklist_id (checklist_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS comments (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  card_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_comments_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_comments_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_comments_card_id (card_id),
  INDEX idx_comments_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS attachments (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  card_id BIGINT UNSIGNED NOT NULL,
  uploaded_by_user_id BIGINT UNSIGNED NULL,
  file_name VARCHAR(255) NOT NULL,
  file_url TEXT NOT NULL,
  file_type VARCHAR(100) NOT NULL,
  file_size_bytes BIGINT NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_attachments_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_attachments_uploader FOREIGN KEY (uploaded_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_attachments_card_id (card_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS activity_log (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  board_id BIGINT UNSIGNED NOT NULL,
  card_id BIGINT UNSIGNED NULL,
  user_id BIGINT UNSIGNED NULL,
  action_type VARCHAR(100) NOT NULL,
  meta_json JSON NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_act_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE,
  CONSTRAINT fk_act_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE SET NULL,
  CONSTRAINT fk_act_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_act_board_id (board_id),
  INDEX idx_act_card_id (card_id),
  INDEX idx_act_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notifications (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  type VARCHAR(100) NOT NULL,
  event_type VARCHAR(100) NULL,
  card_id BIGINT UNSIGNED NULL,
  board_id BIGINT UNSIGNED NULL,
  workspace_id BIGINT UNSIGNED NULL,
  actor_user_id BIGINT UNSIGNED NULL,
  message TEXT NOT NULL,
  is_read TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_notif_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_notif_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_notif_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE,
  CONSTRAINT fk_notif_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_notif_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_notif_user_read_created (user_id, is_read, created_at),
  INDEX idx_notif_event_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id BIGINT UNSIGNED NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  channel VARCHAR(20) NOT NULL,
  is_enabled TINYINT(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id, event_type, channel),
  CONSTRAINT fk_np_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS pending_invitations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  workspace_id BIGINT UNSIGNED NOT NULL,
  invited_by_user_id BIGINT UNSIGNED NULL,
  token VARCHAR(255) NOT NULL UNIQUE,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  accepted_at DATETIME(3) NULL,
  accepted_by_user_id BIGINT UNSIGNED NULL,
  CONSTRAINT fk_pi_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_pi_inviter FOREIGN KEY (invited_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_pi_acceptor FOREIGN KEY (accepted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_pi_email (email),
  INDEX idx_pi_workspace_id (workspace_id),
  INDEX idx_pi_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS invitation_boards (
  invitation_id BIGINT UNSIGNED NOT NULL,
  board_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (invitation_id, board_id),
  CONSTRAINT fk_ib_invitation FOREIGN KEY (invitation_id) REFERENCES pending_invitations(id) ON DELETE CASCADE,
  CONSTRAINT fk_ib_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed permissions catalog
INSERT IGNORE INTO permissions (`key`, category, description) VALUES
  ('workspace.edit_settings', 'Workspace', 'Edit workspace name and settings'),
  ('workspace.delete', 'Workspace', 'Delete workspace'),
  ('workspace.manage_roles', 'Workspace', 'Create, edit, and delete custom roles'),
  ('workspace.view_billing', 'Workspace', 'View billing information'),
  ('member.invite', 'Members', 'Invite new members to workspace'),
  ('member.remove', 'Members', 'Remove members from workspace'),
  ('member.assign_role', 'Members', 'Assign roles to workspace members'),
  ('member.view_all', 'Members', 'View all workspace members'),
  ('board.create', 'Boards', 'Create new boards'),
  ('board.edit_settings', 'Boards', 'Rename, change background, archive boards'),
  ('board.delete', 'Boards', 'Delete boards'),
  ('board.manage_members', 'Boards', 'Add or remove members from specific boards'),
  ('list.create', 'Lists', 'Create new lists'),
  ('list.edit', 'Lists', 'Rename and reorder lists'),
  ('list.delete', 'Lists', 'Delete lists'),
  ('card.create', 'Cards', 'Create new cards'),
  ('card.edit', 'Cards', 'Edit card title, description, dates, labels'),
  ('card.delete', 'Cards', 'Delete cards'),
  ('card.move', 'Cards', 'Drag and move cards between lists'),
  ('card.assign_members', 'Cards', 'Assign or unassign members on cards'),
  ('card.comment', 'Cards', 'Add and delete comments on cards'),
  ('card.manage_attachments', 'Cards', 'Upload and remove attachments on cards'),
  ('archive.restore', 'Archive', 'Restore archived items'),
  ('archive.permanent_delete', 'Archive', 'Permanently delete archived items');

-- Seed System Roles
INSERT IGNORE INTO roles (name, is_system, is_editable, workspace_id) VALUES
  ('Super Admin', 1, 0, NULL),
  ('Manager', 1, 1, NULL),
  ('Team Member', 1, 1, NULL);

-- Seed System Role Permissions (Super Admin gets all; Manager gets subset; Team Member gets basic)
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Super Admin' AND r.is_system = 1 AND r.workspace_id IS NULL;

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Manager' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` NOT IN ('workspace.delete', 'workspace.manage_roles', 'archive.permanent_delete');

INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'Team Member' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN (
    'card.create', 'card.edit', 'card.move', 'card.comment',
    'card.manage_attachments', 'card.assign_members', 'list.create', 'board.create'
  );
