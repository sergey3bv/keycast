-- Add state column to oauth_codes for CSRF protection and redirect correlation
-- Used by clients that provide OAuth state parameter
-- Optional: only included in redirect if originally provided

ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS state TEXT;
