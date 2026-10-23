-- Migration: 0030_audit_events_nullable_hash.sql
-- Ensure row_hash is nullable so fast concurrent audit inserts can happen before async finalization

ALTER TABLE audit_events MODIFY COLUMN row_hash VARCHAR(64) NULL;
ALTER TABLE audit_events MODIFY COLUMN prev_hash VARCHAR(64) NULL;
