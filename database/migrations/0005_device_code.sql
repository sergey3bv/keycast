-- RFC 8628 Device Code for secure polling
-- Unlike 'state' (visible in URL), device_code is returned in response body only
-- This prevents polling credential leakage via referrer headers, logs, or browser history
-- See: https://datatracker.ietf.org/doc/html/rfc8628
ALTER TABLE oauth_codes ADD COLUMN device_code TEXT;
CREATE INDEX idx_oauth_codes_device_code ON oauth_codes(device_code) WHERE device_code IS NOT NULL;
