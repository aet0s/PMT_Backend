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
  -- Allow cryptographic finalizer to assign hashes once (transition from NULL to hash)
  IF OLD.row_hash IS NULL AND NEW.row_hash IS NOT NULL THEN
    SET @audit_finalizing = 1;
  ELSE
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is an immutable append-only ledger; row modification is strictly prohibited.';
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
