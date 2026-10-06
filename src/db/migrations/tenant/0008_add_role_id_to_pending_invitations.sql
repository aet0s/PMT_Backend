-- 0008_add_role_id_to_pending_invitations.sql
-- Store the selected workspace role_id for invited members

ALTER TABLE pending_invitations ADD COLUMN IF NOT EXISTS role_id BIGINT UNSIGNED NULL;
