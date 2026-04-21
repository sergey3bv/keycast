# Keycast Production Readiness Issues

## Summary
**Active Issues:**
- 0 CRITICAL ✅
- 5 HIGH
- 6 MEDIUM
- 3 LOW

**Total: 14 active issues** | **Completed: 16 issues** (see bottom for history)

---

## HIGH Priority Issues

### ⚠️ 2. CORS Configuration
**Status:** PARTIALLY FIXED
**Location:** `keycast/src/main.rs:183-193`
**Issue:** Configurable via `ALLOWED_ORIGINS` env var but has hardcoded fallback values
**Plan:** Remove fallback, fail fast if env var not set in production
**Effort:** 1 hour

### ❌ 28. Three Auth Tests Disabled
**Priority:** HIGH
**Status:** NOT STARTED
**Location:** `api/src/api/http/auth.rs:1847, 1920, 1985`
**Impact:** Test coverage gaps - 3 auth integration tests ignored due to PostgreSQL isolation issues
**Tests:**
- test_fast_path_components
- test_fast_path_with_policies
- test_login_fast_path
**Plan:**
- Convert SQLite syntax to PostgreSQL ($1, $2 vs ?)
- Add proper test transaction isolation
- Remove #[ignore] attributes
**Effort:** 8-12 hours

### ❌ 11. No Rate Limiting
**Priority:** HIGH
**Status:** NOT STARTED
**Impact:** API vulnerable to abuse, brute force attacks
**Plan:**
- Add tower-governor or tower-limit dependency
- Configure per-endpoint limits (auth: 5-10/hour, API: 100/min)
- Return 429 status when exceeded
**Effort:** 3-4 hours

### ❌ 12. Health Check Doesn't Validate Anything
**Priority:** HIGH (used by Kamal deployment monitoring)
**Status:** NOT STARTED
**Location:** `keycast/src/main.rs:73-75`
**Issue:** Returns 200 OK without checking database, signer, or any services
**Plan:**
- Query PostgreSQL: `SELECT 1`
- Check signer status (if handlers loaded)
- Return 503 if unhealthy
**Effort:** 1-2 hours

### ❌ 16. No Runtime Env Var Validation
**Priority:** HIGH (upgraded from MEDIUM)
**Status:** NOT STARTED
**Issue:** Critical env vars use `.unwrap_or_else()` fallbacks instead of failing fast
**Impact:** Silent failures, wrong configuration in production
**Plan:**
- Create startup validation function
- Check all required vars: DATABASE_URL, ALLOWED_ORIGINS, and KMS vars by provider (`KMS_PROVIDER=file|gcp|aws`):
  - `file` -> `MASTER_KEY_PATH`
  - `gcp` -> `GCP_PROJECT_ID`
  - `aws` -> `AWS_KMS_KEY_ID` (and usually `AWS_REGION`)
- Fail with clear error if missing
**Effort:** 2-3 hours

---

## MEDIUM Priority Issues

### ⚠️ 15. Docker Compose vs Cloud Build Config Mismatch
**Status:** PARTIALLY FIXED
**Issue:** Configs aligned for PostgreSQL but documentation inconsistent (README/CLAUDE.md still reference SQLite)
**Plan:** Update all docs to reflect PostgreSQL migration
**Effort:** 30 minutes

### ❌ 17. No Request ID Tracking
**Status:** NOT STARTED
**Impact:** Difficult to trace requests across logs
**Plan:** Add tower-http RequestIdLayer
**Effort:** 1-2 hours

### ❌ 18. No Request Timeout Configuration
**Status:** NOT STARTED
**Impact:** Requests can hang indefinitely
**Plan:** Add tower::timeout::TimeoutLayer with 30s default
**Effort:** 1 hour

### ❌ 19. No Graceful Shutdown
**Status:** NOT STARTED
**Impact:** In-flight requests lost on restart/deploy
**Plan:** Use axum::serve graceful_shutdown with SIGTERM handler
**Effort:** 2-3 hours

### ❌ 20. No .dockerignore
**Status:** NOT STARTED
**Impact:** Slower builds, unnecessary files in build context
**Plan:** Create .dockerignore with: .git, target, node_modules, docs, examples
**Effort:** 10 minutes

### ⚠️ 21. No Migration Verification in Deployment
**Status:** PARTIALLY FIXED
**Location:** `core/src/database.rs:40-56`
**Current:** Migrations auto-run on startup with 3-attempt retry logic
**Issue:** Not verified as separate CI step before app starts
**Plan:** Consider if current approach is acceptable or needs CI-time verification
**Effort:** 2 hours (if changing to CI-based)

### ⚠️ 23. Test Environment Setup
**Status:** PARTIALLY FIXED
**Current:** Test setup documented in CLAUDE.md
**Issue:** 3 auth tests disabled (#[ignore]) - need PostgreSQL isolation
**Plan:** See Issue 28
**Effort:** Included in Issue 28

### ⚠️ 24. Duplicated Documentation
**Status:** PARTIALLY FIXED
**Current:** Major consolidation done, single DEPLOYMENT.md exists
**Remaining:** Minor cleanup (SQLite references, archive organization)
**Effort:** 1-2 hours

---

## LOW Priority Issues

### ❌ 25. No Rollback Migrations
**Status:** NOT STARTED
**Location:** `database/migrations/` (19 forward-only migrations)
**Impact:** Can't easily rollback schema changes
**Plan:** Create down.sql for each migration
**Effort:** 4-6 hours (19 migrations)

---

## Next Steps - Prioritized

### Immediate (HIGH Priority - 3-4 hours)
1. ❌ **Issue 11:** Add rate limiting (3-4 hrs)

### Short Term (Testing & Reliability - 12-15 hours)
1. ❌ **Issue 28:** Fix 3 disabled auth tests (8-12 hrs)
2. ❌ **Issue 12:** Enhance health check (1-2 hrs)
3. ⚠️ **Issue 2:** Remove CORS fallback (1 hr)
4. ⏳ **Issue 4:** Verify build errors resolved

### Medium Term (Production Hardening - 6-8 hours)
1. ❌ **Issue 17:** Add request ID tracking (1-2 hrs)
2. ❌ **Issue 18:** Add request timeouts (1 hr)
3. ❌ **Issue 19:** Add graceful shutdown (2-3 hrs)
4. ⚠️ **Issue 21:** Verify migration strategy (2 hrs if changing)

### Low Priority (Polish - 5-7 hours)
1. ⚠️ **Issue 24:** Final documentation cleanup (1-2 hrs)
2. ❌ **Issue 25:** Add rollback migrations (4-6 hrs) - optional


---

## Completed Issues

See [docs/archive/COMPLETED_ISSUES.md](archive/COMPLETED_ISSUES.md) for the 16 resolved issues.
