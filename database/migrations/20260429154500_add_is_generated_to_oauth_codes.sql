-- Track whether OAuth pending registrations use auto-generated keys.
-- This allows us to gate side effects (like kind:10002 publish) to generated accounts only.
ALTER TABLE oauth_codes
ADD COLUMN IF NOT EXISTS is_generated BOOLEAN NOT NULL DEFAULT FALSE;
