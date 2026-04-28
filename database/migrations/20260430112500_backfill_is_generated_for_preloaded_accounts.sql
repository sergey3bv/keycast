-- Backfill known legacy generated cohort.
-- Preloaded Vine accounts always used server-generated personal keys.
UPDATE personal_keys pk
SET is_generated = TRUE
FROM users u
WHERE pk.user_pubkey = u.pubkey
  AND pk.tenant_id = u.tenant_id
  AND pk.is_generated = FALSE
  AND u.vine_id IS NOT NULL;
