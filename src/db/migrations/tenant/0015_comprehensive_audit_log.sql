-- Migration: 0015_comprehensive_audit_log
-- Expands activity_log to support company-wide and workspace-wide audit logging:
-- 1. Makes board_id nullable for non-board actions (login, logout, roles, workspace settings, etc.)
-- 2. Adds workspace_id for workspace-level scoped audit queries
-- 3. Adds indexes for fast server-side pagination, searching, and filtering

ALTER TABLE activity_log MODIFY COLUMN board_id BIGINT UNSIGNED NULL;
ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS workspace_id BIGINT UNSIGNED NULL;
ALTER TABLE activity_log ADD INDEX IF NOT EXISTS idx_act_workspace_id (workspace_id);
ALTER TABLE activity_log ADD INDEX IF NOT EXISTS idx_act_user_id (user_id);
ALTER TABLE activity_log ADD INDEX IF NOT EXISTS idx_act_action_type (action_type);
