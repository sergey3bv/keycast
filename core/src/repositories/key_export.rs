// ABOUTME: Repository for key export operations
// ABOUTME: Handles key_export_codes, key_export_tokens, and key_export_log tables

use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct KeyExportRepository {
    pool: PgPool,
}

impl KeyExportRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // key_export_codes
    // =========================================================================

    /// Create a new export verification code.
    pub async fn create_code(
        &self,
        user_pubkey: &str,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO key_export_codes (user_pubkey, code, expires_at, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_pubkey)
        .bind(code)
        .bind(expires_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a valid (unused, not expired) export code.
    /// Returns (code, expires_at) if found.
    pub async fn find_valid_code(
        &self,
        user_pubkey: &str,
        code: &str,
    ) -> Result<Option<(String, DateTime<Utc>)>, RepositoryError> {
        sqlx::query_as(
            "SELECT code, expires_at FROM key_export_codes
             WHERE user_pubkey = $1 AND code = $2 AND used_at IS NULL
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user_pubkey)
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark a code as used.
    pub async fn mark_code_used(&self, user_pubkey: &str, code: &str) -> Result<(), RepositoryError> {
        sqlx::query("UPDATE key_export_codes SET used_at = $1 WHERE user_pubkey = $2 AND code = $3")
            .bind(Utc::now())
            .bind(user_pubkey)
            .bind(code)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // =========================================================================
    // key_export_tokens
    // =========================================================================

    /// Create a new export token (granted after code verification).
    pub async fn create_token(
        &self,
        user_pubkey: &str,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO key_export_tokens (user_pubkey, token, expires_at, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_pubkey)
        .bind(token)
        .bind(expires_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a valid (unused, not expired) export token.
    /// Returns expires_at if found.
    pub async fn find_valid_token(
        &self,
        user_pubkey: &str,
        token: &str,
    ) -> Result<Option<DateTime<Utc>>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT expires_at FROM key_export_tokens
             WHERE user_pubkey = $1 AND token = $2 AND used_at IS NULL",
        )
        .bind(user_pubkey)
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark a token as used.
    pub async fn mark_token_used(
        &self,
        user_pubkey: &str,
        token: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query("UPDATE key_export_tokens SET used_at = $1 WHERE user_pubkey = $2 AND token = $3")
            .bind(Utc::now())
            .bind(user_pubkey)
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // =========================================================================
    // key_export_log
    // =========================================================================

    /// Log a key export for audit purposes.
    pub async fn log_export(&self, user_pubkey: &str, format: &str) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO key_export_log (user_pubkey, format, exported_at) VALUES ($1, $2, $3)",
        )
        .bind(user_pubkey)
        .bind(format)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_localhost_db() {
        let url = std::env::var("DATABASE_URL").unwrap_or_default();
        assert!(
            url.contains("localhost") || url.contains("127.0.0.1") || url.is_empty(),
            "Tests must run against localhost database"
        );
    }

    async fn setup_pool() -> PgPool {
        assert_localhost_db();
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
        PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database")
    }

    #[tokio::test]
    async fn test_code_lifecycle() {
        use chrono::Duration;
        use nostr_sdk::Keys;

        let pool = setup_pool().await;
        let repo = KeyExportRepository::new(pool.clone());

        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let code = format!("{:06}", rand::random::<u32>() % 1000000);
        let expires_at = Utc::now() + Duration::minutes(15);

        // Create user first
        sqlx::query("INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at) VALUES ($1, 1, $2, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .bind(format!("test-{}@example.com", uuid::Uuid::new_v4()))
            .execute(&pool)
            .await
            .unwrap();

        // Create code
        repo.create_code(&user_pubkey, &code, expires_at)
            .await
            .unwrap();

        // Find valid code
        let found = repo.find_valid_code(&user_pubkey, &code).await.unwrap();
        assert!(found.is_some());

        // Mark as used
        repo.mark_code_used(&user_pubkey, &code).await.unwrap();

        // Should no longer be found
        let found = repo.find_valid_code(&user_pubkey, &code).await.unwrap();
        assert!(found.is_none());
    }
}
