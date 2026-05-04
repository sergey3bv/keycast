-- Fail closed for dangling oauth_authorizations.policy_id references.
-- 1) Revoke active OAuth authorizations pointing at missing policies.
-- 2) Clear dangling policy_id for all affected rows so FK can be added safely.
-- 3) Add FK to prevent future dangling references.
--
-- Affected rows end up with policy_id NULL and revoked_at set. Application code
-- must treat NULL policy_id as full access only when revoked_at IS NULL; otherwise
-- a revoked row could be mistaken for an active unrestricted authorization.

UPDATE oauth_authorizations oa
SET revoked_at = CASE
        WHEN oa.revoked_at IS NULL THEN NOW()
        ELSE oa.revoked_at
    END,
    policy_id = NULL,
    updated_at = NOW()
WHERE oa.policy_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM policies p
      WHERE p.id = oa.policy_id
  );

ALTER TABLE ONLY public.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_policy_id_fkey
    FOREIGN KEY (policy_id) REFERENCES public.policies(id) ON DELETE RESTRICT;
