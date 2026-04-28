CREATE TABLE IF NOT EXISTS relay_list_publish_pending (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    user_pubkey CHAR(64) NOT NULL REFERENCES users(pubkey) ON DELETE CASCADE,
    encrypted_secret_key BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT relay_list_publish_pending_tenant_user_unique UNIQUE (tenant_id, user_pubkey)
);

CREATE INDEX IF NOT EXISTS idx_relay_list_publish_pending_due
ON relay_list_publish_pending (next_attempt_at);

CREATE TRIGGER relay_list_publish_pending_update_trigger
BEFORE UPDATE ON relay_list_publish_pending
FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
