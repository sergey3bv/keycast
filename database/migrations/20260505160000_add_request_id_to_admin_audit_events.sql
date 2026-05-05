-- Correlate admin_audit_events with request-scoped auth observability (x-request-id).
ALTER TABLE admin_audit_events
    ADD COLUMN IF NOT EXISTS request_id TEXT;

CREATE INDEX IF NOT EXISTS idx_admin_audit_events_tenant_request_occurred
    ON admin_audit_events (tenant_id, request_id, occurred_at DESC)
    WHERE request_id IS NOT NULL;
