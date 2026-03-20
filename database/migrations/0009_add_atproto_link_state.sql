ALTER TABLE users
  ADD COLUMN atproto_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN atproto_state text DEFAULT NULL,
  ADD COLUMN atproto_did text DEFAULT NULL,
  ADD COLUMN atproto_error text DEFAULT NULL,
  ADD COLUMN atproto_updated_at timestamptz DEFAULT NULL;
