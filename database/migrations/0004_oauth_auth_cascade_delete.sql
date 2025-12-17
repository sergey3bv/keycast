-- Add ON DELETE CASCADE to oauth_authorizations.user_pubkey foreign key
-- This ensures oauth_authorizations are automatically deleted when users are deleted
-- (matches behavior of personal_keys, email_verification_tokens, etc.)

ALTER TABLE oauth_authorizations
    DROP CONSTRAINT oauth_authorizations_user_pubkey_fkey,
    ADD CONSTRAINT oauth_authorizations_user_pubkey_fkey
        FOREIGN KEY (user_pubkey) REFERENCES users(pubkey) ON DELETE CASCADE;
