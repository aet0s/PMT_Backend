-- Tenant Migration 0045: Outbox Processing Lease & Recovery
ALTER TABLE notification_outbox ADD COLUMN IF NOT EXISTS processing_started_at DATETIME(3) NULL;
ALTER TABLE notification_outbox ADD COLUMN IF NOT EXISTS lease_expires_at DATETIME(3) NULL;
ALTER TABLE notification_outbox ADD INDEX IF NOT EXISTS idx_outbox_status_lease (status, lease_expires_at);
