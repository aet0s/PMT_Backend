-- Migration: 0029_audit_events.sql
-- Production-level, append-only, tamper-evident audit log with hash chaining, finalizer support, and triggers.

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_uid VARCHAR(36) NOT NULL,
  occurred_at DATETIME(3) NOT NULL,
  workspace_id BIGINT UNSIGNED NULL,
  board_id BIGINT UNSIGNED NULL,
  card_id BIGINT UNSIGNED NULL,
  actor_user_id BIGINT UNSIGNED NULL,
  actor_type ENUM('user','system','api','cron') NOT NULL DEFAULT 'user',
  actor_name VARCHAR(255) NULL,
  actor_email VARCHAR(255) NULL,
  actor_role VARCHAR(100) NULL,
  ip_address VARCHAR(45) NULL,
  user_agent TEXT NULL,
  request_id VARCHAR(64) NULL,
  session_id VARCHAR(64) NULL,
  action VARCHAR(100) NOT NULL,
  category ENUM('auth','security','workspace','member','role','board','list','card','checklist','comment','attachment','label','checkin','leave','settings','export','audit','system') NOT NULL,
  entity_type VARCHAR(50) NOT NULL,
  entity_id BIGINT UNSIGNED NULL,
  entity_label VARCHAR(255) NULL,
  target_user_id BIGINT UNSIGNED NULL,
  target_user_name VARCHAR(255) NULL,
  outcome ENUM('success','denied','failed') NOT NULL DEFAULT 'success',
  severity ENUM('info','notice','warning','critical') NOT NULL DEFAULT 'info',
  changes JSON NULL,
  meta JSON NULL,
  source ENUM('live','backfill') NOT NULL DEFAULT 'live',
  key_id VARCHAR(32) NOT NULL DEFAULT 'v1',
  prev_hash VARCHAR(64) NULL,
  row_hash VARCHAR(64) NULL,
  INDEX idx_audit_occ_id (occurred_at, id),
  INDEX idx_audit_actor_occ (actor_user_id, occurred_at),
  INDEX idx_audit_ws_occ (workspace_id, occurred_at),
  INDEX idx_audit_board_occ (board_id, occurred_at),
  INDEX idx_audit_card_occ (card_id, occurred_at),
  INDEX idx_audit_cat_occ (category, occurred_at),
  INDEX idx_audit_action_occ (action, occurred_at),
  INDEX idx_audit_entity (entity_type, entity_id),
  INDEX idx_audit_target_occ (target_user_id, occurred_at),
  INDEX idx_audit_outcome_occ (outcome, occurred_at),
  INDEX idx_audit_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Guarded addition of key_id to audit_events if table was previously created
SET @col_exists_key_id = 0;
SELECT COUNT(*) INTO @col_exists_key_id FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_events' AND COLUMN_NAME = 'key_id';
SET @stmt_key_id = IF(@col_exists_key_id = 0, 'ALTER TABLE audit_events ADD COLUMN key_id VARCHAR(32) NOT NULL DEFAULT \'v1\';', 'SELECT 1;');
PREPARE stmt_key_id_exec FROM @stmt_key_id;
EXECUTE stmt_key_id_exec;
DEALLOCATE PREPARE stmt_key_id_exec;

-- Ensure row_hash is nullable to support fast async finalization
ALTER TABLE audit_events MODIFY COLUMN row_hash VARCHAR(64) NULL;

-- System status table for trigger diagnostics and audit health
CREATE TABLE IF NOT EXISTS audit_system_status (
  setting_key VARCHAR(100) PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Guarded addition of audit_retention_days to workspaces table
SET @col_exists_retention = 0;
SELECT COUNT(*) INTO @col_exists_retention FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'workspaces' AND COLUMN_NAME = 'audit_retention_days';
SET @stmt_retention = IF(@col_exists_retention = 0, 'ALTER TABLE workspaces ADD COLUMN audit_retention_days INT UNSIGNED NULL DEFAULT NULL;', 'SELECT 1;');
PREPARE stmt_retention_exec FROM @stmt_retention;
EXECUTE stmt_retention_exec;
DEALLOCATE PREPARE stmt_retention_exec;

-- Append-only guard triggers
DROP TRIGGER IF EXISTS trg_audit_events_prevent_update;
CREATE TRIGGER trg_audit_events_prevent_update
BEFORE UPDATE ON audit_events
FOR EACH ROW
BEGIN
  -- Strict immutability: once row_hash is assigned, row can never be modified
  IF OLD.row_hash IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is an immutable append-only ledger; finalized rows cannot be modified.';
  END IF;

  -- Verify all immutable audit fields remain unchanged
  IF NOT (
    NEW.id = OLD.id AND
    NEW.event_uid = OLD.event_uid AND
    NEW.occurred_at = OLD.occurred_at AND
    NEW.workspace_id <=> OLD.workspace_id AND
    NEW.board_id <=> OLD.board_id AND
    NEW.card_id <=> OLD.card_id AND
    NEW.actor_user_id <=> OLD.actor_user_id AND
    NEW.actor_type = OLD.actor_type AND
    NEW.actor_name <=> OLD.actor_name AND
    NEW.actor_email <=> OLD.actor_email AND
    NEW.actor_role <=> OLD.actor_role AND
    NEW.ip_address <=> OLD.ip_address AND
    NEW.user_agent <=> OLD.user_agent AND
    NEW.request_id <=> OLD.request_id AND
    NEW.session_id <=> OLD.session_id AND
    NEW.action = OLD.action AND
    NEW.category = OLD.category AND
    NEW.entity_type = OLD.entity_type AND
    NEW.entity_id <=> OLD.entity_id AND
    NEW.entity_label <=> OLD.entity_label AND
    NEW.target_user_id <=> OLD.target_user_id AND
    NEW.target_user_name <=> OLD.target_user_name AND
    NEW.outcome = OLD.outcome AND
    NEW.severity = OLD.severity AND
    NEW.changes <=> OLD.changes AND
    NEW.source = OLD.source AND
    NEW.key_id = OLD.key_id
  ) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Modifying immutable audit event fields is strictly prohibited.';
  END IF;

  -- Allow cryptographic finalizer (NULL -> NOT NULL) or pre-finalization coalescing meta update
  IF NEW.row_hash IS NOT NULL THEN
    SET @audit_finalizing = 1;
  ELSEIF NEW.meta IS NOT NULL THEN
    SET @audit_coalescing = 1;
  ELSE
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events update is only permitted for cryptographic finalization or pre-finalization coalescing.';
  END IF;
END;

DROP TRIGGER IF EXISTS trg_audit_events_prevent_delete;
CREATE TRIGGER trg_audit_events_prevent_delete
BEFORE DELETE ON audit_events
FOR EACH ROW
BEGIN
  IF CURRENT_USER() NOT LIKE '%audit_archive%' AND (@ALLOW_AUDIT_ARCHIVE IS NULL OR @ALLOW_AUDIT_ARCHIVE <> 1) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only: DELETE requires audit_archive database user privileges.';
  END IF;
END;
