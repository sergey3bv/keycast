-- Functional index for case-insensitive username search in admin lookup.
-- The tenant_id prefix allows efficient filtering per tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_lower_username_tenant
    ON users (tenant_id, LOWER(username))
    WHERE username IS NOT NULL;
