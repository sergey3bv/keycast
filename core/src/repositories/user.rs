// ABOUTME: User repository for data access operations
// ABOUTME: Provides methods for finding, creating, and querying user data

use crate::repositories::RepositoryError;
use crate::types::user::User;
use chrono::{DateTime, Utc};
use nostr_sdk::PublicKey;
use sqlx::PgPool;

/// Repository for user-related database operations.
#[derive(Debug, Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    /// Create a new UserRepository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find a user by their public key.
    pub async fn find_by_pubkey(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
    ) -> Result<User, RepositoryError> {
        sqlx::query_as::<_, User>(
            "SELECT pubkey, created_at, updated_at FROM users WHERE tenant_id = $1 AND pubkey = $2",
        )
        .bind(tenant_id)
        .bind(pubkey.to_hex())
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a user by pubkey, or create them if they don't exist.
    /// Returns the user (existing or newly created).
    pub async fn find_or_create(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
    ) -> Result<User, RepositoryError> {
        let pubkey_hex = pubkey.to_hex();

        // Use upsert pattern: INSERT ... ON CONFLICT ... RETURNING
        // This is atomic and handles the race condition properly
        sqlx::query_as::<_, User>(
            "INSERT INTO users (tenant_id, pubkey, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             ON CONFLICT (pubkey) DO UPDATE SET updated_at = users.updated_at
             RETURNING pubkey, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(&pubkey_hex)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if a user is an admin of a specific team.
    ///
    /// The `tenant_id` parameter is reserved for future multi-tenant isolation
    /// at the team_users level. Currently, tenant isolation is enforced at the
    /// team level by handlers validating team ownership before calling this.
    #[allow(unused_variables)]
    pub async fn is_team_admin(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2 AND role = 'admin'",
        )
        .bind(pubkey.to_hex())
        .bind(team_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Check if a user is a member (non-admin) of a specific team.
    ///
    /// The `tenant_id` parameter is reserved for future multi-tenant isolation.
    #[allow(unused_variables)]
    pub async fn is_team_member(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2 AND role = 'member'",
        )
        .bind(pubkey.to_hex())
        .bind(team_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Check if a user is part of a team (admin or member).
    ///
    /// The `tenant_id` parameter is reserved for future multi-tenant isolation.
    #[allow(unused_variables)]
    pub async fn is_team_teammate(
        &self,
        tenant_id: i64,
        pubkey: &PublicKey,
        team_id: i32,
    ) -> Result<bool, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE user_pubkey = $1 AND team_id = $2",
        )
        .bind(pubkey.to_hex())
        .bind(team_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    // =========================================================================
    // Authentication methods
    // =========================================================================

    /// Check if a user exists by pubkey.
    pub async fn exists(&self, pubkey: &str, tenant_id: i64) -> Result<bool, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE pubkey = $1 AND tenant_id = $2")
                .bind(pubkey)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.is_some())
    }

    /// Find user pubkey by email for login.
    pub async fn find_pubkey_by_email(
        &self,
        email: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = $2")
                .bind(email)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.map(|r| r.0))
    }

    /// Find user pubkey by username (for NIP-05).
    pub async fn find_pubkey_by_username(
        &self,
        username: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT pubkey FROM users WHERE username = $1 AND tenant_id = $2")
                .bind(username)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(result.map(|r| r.0))
    }

    /// Find user with password hash and email verification status for login verification.
    /// Returns (pubkey, password_hash, email_verified).
    pub async fn find_with_password(
        &self,
        email: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String, bool)>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, password_hash, email_verified FROM users WHERE email = $1 AND tenant_id = $2 AND password_hash IS NOT NULL",
        )
        .bind(email)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create a new user with email/password credentials.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_credentials(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        email_verified: bool,
        verification_token: &str,
        verification_expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(email_verified)
        .bind(verification_token)
        .bind(verification_expires_at)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Create a new user with email/password and verified status (used during key change).
    pub async fn create_with_password_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        email_verified: bool,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(email_verified)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ensure a user exists (create if not exists, for API compatibility).
    pub async fn ensure_exists(&self, pubkey: &str, tenant_id: i64) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Register a new user with email/password and personal key atomically.
    ///
    /// Creates both the user record and personal key in a single transaction,
    /// ensuring consistency if either operation fails.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Duplicate`] if email already exists.
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn register_with_personal_key(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        verification_token: &str,
        verification_expires_at: DateTime<Utc>,
        encrypted_secret: &[u8],
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Insert user with email verification token
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(false)
        .bind(verification_token)
        .bind(verification_expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Insert personal key
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Email verification methods
    // =========================================================================

    /// Find user by email verification token.
    pub async fn find_by_verification_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, email_verification_expires_at FROM users
             WHERE email_verification_token = $1 AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark user's email as verified.
    pub async fn verify_email(&self, pubkey: &str, tenant_id: i64) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET email_verified = true, email_verification_token = NULL, email_verification_expires_at = NULL, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get email verification status.
    pub async fn get_verification_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, bool, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, email_verified, email_verification_sent_at FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Set new email verification token (for resending verification).
    pub async fn set_verification_token(
        &self,
        pubkey: &str,
        tenant_id: i64,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET email_verification_token = $1, email_verification_expires_at = $2, email_verification_sent_at = $3, updated_at = $4
             WHERE pubkey = $5 AND tenant_id = $6",
        )
        .bind(token)
        .bind(expires_at)
        .bind(Utc::now())
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get email_verified status only.
    pub async fn get_email_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<bool>, RepositoryError> {
        sqlx::query_scalar("SELECT email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Password reset methods
    // =========================================================================

    /// Set password reset token.
    pub async fn set_password_reset_token(
        &self,
        pubkey: &str,
        tenant_id: i64,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = $3
             WHERE pubkey = $4 AND tenant_id = $5",
        )
        .bind(token)
        .bind(expires_at)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find user by password reset token.
    pub async fn find_by_reset_token(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, Option<DateTime<Utc>>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT pubkey, password_reset_expires_at FROM users
             WHERE password_reset_token = $1 AND tenant_id = $2",
        )
        .bind(token)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Reset user's password.
    /// Also clears the reset token and marks email as verified (password reset proves email ownership).
    pub async fn reset_password(
        &self,
        pubkey: &str,
        tenant_id: i64,
        password_hash: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users
             SET password_hash = $1,
                 password_reset_token = NULL,
                 password_reset_expires_at = NULL,
                 email_verified = true,
                 email_verification_token = NULL,
                 email_verification_expires_at = NULL,
                 updated_at = $2
             WHERE pubkey = $3 AND tenant_id = $4",
        )
        .bind(password_hash)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find user with email, password hash, and email verified status (for key export verification).
    pub async fn find_with_password_and_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String, bool)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    // =========================================================================
    // Profile methods
    // =========================================================================

    /// Get user's username.
    pub async fn get_username(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<Option<String>>, RepositoryError> {
        sqlx::query_as("SELECT username FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map(|opt: Option<(Option<String>,)>| opt.map(|r| r.0))
            .map_err(Into::into)
    }

    /// Get user's email and verified status.
    /// Returns None if user doesn't exist, Some with nullable email/verified if user exists.
    pub async fn get_account_status(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(Option<String>, Option<bool>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if username is available (excluding a specific pubkey).
    pub async fn check_username_available(
        &self,
        username: &str,
        exclude_pubkey: &str,
        tenant_id: i64,
    ) -> Result<bool, RepositoryError> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT pubkey FROM users WHERE username = $1 AND pubkey != $2 AND tenant_id = $3",
        )
        .bind(username)
        .bind(exclude_pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.is_none())
    }

    /// Update user's username.
    pub async fn update_username(
        &self,
        pubkey: &str,
        username: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET username = $1, updated_at = $2 WHERE pubkey = $3 AND tenant_id = $4",
        )
        .bind(username)
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get user's email and password hash for credential verification.
    pub async fn get_credentials(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, password_hash FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get user's email, password hash, and verified status.
    pub async fn get_credentials_with_verified(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<(String, String, bool)>, RepositoryError> {
        sqlx::query_as(
            "SELECT email, password_hash, email_verified FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get user's email (for token exchange).
    pub async fn get_email(&self, pubkey: &str, tenant_id: i64) -> Result<String, RepositoryError> {
        sqlx::query_scalar("SELECT email FROM users WHERE pubkey = $1 AND tenant_id = $2")
            .bind(pubkey)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Key change methods
    // =========================================================================

    /// Orphan user's identity (clear email/password for key change).
    pub async fn orphan_identity(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET email = NULL, password_hash = NULL, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(Utc::now())
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Finalize OAuth registration atomically.
    ///
    /// Creates user and personal key records, then deletes the one-time oauth code.
    /// Used in the token exchange flow to finalize pending registrations.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_oauth_registration(
        &self,
        pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        verification_token: &str,
        verification_expires_at: DateTime<Utc>,
        encrypted_secret: &[u8],
        oauth_code: &str,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Create users row
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(false)
        .bind(verification_token)
        .bind(verification_expires_at)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Create personal_keys row
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Delete the oauth code (one-time use)
        sqlx::query("DELETE FROM oauth_codes WHERE tenant_id = $1 AND code = $2")
            .bind(tenant_id)
            .bind(oauth_code)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Change user's key in a single transaction.
    ///
    /// Performs a complete key rotation:
    /// 1. Counts and deletes OAuth authorizations for the old pubkey
    /// 2. Deletes personal_keys for the old pubkey
    /// 3. Orphans the old user identity (clears email/password)
    /// 4. Creates new user identity with email/password
    /// 5. Creates personal_keys for the new identity
    ///
    /// Returns the count of OAuth authorizations that were deleted.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_key_transaction(
        &self,
        old_pubkey: &str,
        new_pubkey: &str,
        tenant_id: i64,
        email: &str,
        password_hash: &str,
        encrypted_secret: &[u8],
    ) -> Result<i64, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Count OAuth authorizations that will be deleted (for logging)
        let oauth_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorizations WHERE user_pubkey = $1")
                .bind(old_pubkey)
                .fetch_one(&mut *tx)
                .await?;

        // Delete OAuth authorizations (we can't sign with old nsec anymore)
        sqlx::query("DELETE FROM oauth_authorizations WHERE user_pubkey = $1")
            .bind(old_pubkey)
            .execute(&mut *tx)
            .await?;

        // Delete old personal_keys (we no longer hold old nsec)
        sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(old_pubkey)
            .execute(&mut *tx)
            .await?;

        // Orphan old identity (transfer email/password to NULL)
        sqlx::query(
            "UPDATE users SET email = NULL, password_hash = NULL, updated_at = $1
             WHERE pubkey = $2 AND tenant_id = $3",
        )
        .bind(now)
        .bind(old_pubkey)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

        // Create new user identity with email/password
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(new_pubkey)
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(true) // Keep email verified status
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Create personal_keys for new identity
        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(new_pubkey)
        .bind(encrypted_secret)
        .bind(tenant_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(oauth_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::Keys;
    use sqlx::PgPool;

    async fn setup_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

        // Safety check: don't run on production
        assert!(
            database_url.contains("localhost") || database_url.contains("127.0.0.1"),
            "Tests must run against localhost database"
        );

        PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database")
    }

    fn test_suffix() -> String {
        uuid::Uuid::new_v4().to_string()[..8].to_string()
    }

    async fn create_test_team(pool: &PgPool, name: &str) -> i32 {
        let result: (i32,) = sqlx::query_as(
            "INSERT INTO teams (name, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())
             RETURNING id",
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
        result.0
    }

    async fn add_user_to_team(pool: &PgPool, pubkey: &str, team_id: i32, role: &str) {
        sqlx::query(
            "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             ON CONFLICT (team_id, user_pubkey) DO NOTHING",
        )
        .bind(team_id)
        .bind(pubkey)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_find_by_pubkey_returns_user() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        // Create user directly
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
             VALUES ($1, 1, NOW(), NOW())",
        )
        .bind(pubkey.to_hex())
        .execute(&pool)
        .await
        .unwrap();

        // Find via repository
        let result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(result.is_ok(), "Should find user");
        assert_eq!(result.unwrap().pubkey, pubkey.to_hex());
    }

    #[tokio::test]
    async fn test_find_by_pubkey_not_found() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool);
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        let result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_find_or_create_creates_new() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        // User doesn't exist yet
        let find_result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));

        // Find or create should create
        let result = repo.find_or_create(1, &pubkey).await;
        assert!(result.is_ok(), "Should create user");
        assert_eq!(result.unwrap().pubkey, pubkey.to_hex());

        // Now user exists
        let find_result = repo.find_by_pubkey(1, &pubkey).await;
        assert!(find_result.is_ok(), "User should exist now");
    }

    #[tokio::test]
    async fn test_find_or_create_returns_existing() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();

        // Create user first
        let first = repo.find_or_create(1, &pubkey).await.unwrap();

        // Call again - should return same user
        let second = repo.find_or_create(1, &pubkey).await.unwrap();
        assert_eq!(first.pubkey, second.pubkey);
    }

    #[tokio::test]
    async fn test_is_team_admin_true_for_admin() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Admin Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "admin").await;

        let result = repo.is_team_admin(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "User should be admin");
    }

    #[tokio::test]
    async fn test_is_team_admin_false_for_member() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Member Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "member").await;

        let result = repo.is_team_admin(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Member should not be admin");
    }

    #[tokio::test]
    async fn test_is_team_member_true() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Member Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "member").await;

        let result = repo.is_team_member(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "User should be member");
    }

    #[tokio::test]
    async fn test_is_team_member_false() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team but don't add to team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("No Member Test {}", suffix)).await;

        let result = repo.is_team_member(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "User should not be member");
    }

    #[tokio::test]
    async fn test_is_team_teammate_true() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("Teammate Test {}", suffix)).await;
        add_user_to_team(&pool, &pubkey.to_hex(), team_id, "admin").await;

        let result = repo.is_team_teammate(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap(), "User should be teammate");
    }

    #[tokio::test]
    async fn test_is_team_teammate_false() {
        let pool = setup_pool().await;
        let repo = UserRepository::new(pool.clone());
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        let suffix = test_suffix();

        // Create user and team but don't add to team
        repo.find_or_create(1, &pubkey).await.unwrap();
        let team_id = create_test_team(&pool, &format!("No Teammate Test {}", suffix)).await;

        let result = repo.is_team_teammate(1, &pubkey, team_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "User should not be teammate");
    }
}
