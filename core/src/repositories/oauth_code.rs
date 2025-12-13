// ABOUTME: Repository for OAuth authorization codes
// ABOUTME: Handles temporary code storage for OAuth 2.0 authorization flow

use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Data returned when finding an OAuth code
#[derive(Debug, Clone)]
pub struct OAuthCodeData {
    pub user_pubkey: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub pending_email: Option<String>,
    pub pending_password_hash: Option<String>,
    pub pending_email_verification_token: Option<String>,
    pub pending_encrypted_secret: Option<Vec<u8>>,
    pub previous_auth_id: Option<i32>,
}

/// Parameters for storing a basic OAuth code
#[derive(Debug, Clone)]
pub struct StoreOAuthCodeParams<'a> {
    pub tenant_id: i64,
    pub code: &'a str,
    pub user_pubkey: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub expires_at: DateTime<Utc>,
    pub previous_auth_id: Option<i32>,
}

/// Parameters for storing OAuth code with pending registration data
#[derive(Debug, Clone)]
pub struct StoreOAuthCodeWithRegistrationParams<'a> {
    pub tenant_id: i64,
    pub code: &'a str,
    pub user_pubkey: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub expires_at: DateTime<Utc>,
    pub pending_email: &'a str,
    pub pending_password_hash: &'a str,
    pub pending_email_verification_token: &'a str,
    pub pending_encrypted_secret: Option<&'a [u8]>,
}

#[derive(Debug, Clone)]
pub struct OAuthCodeRepository {
    pool: PgPool,
}

impl OAuthCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store an OAuth authorization code with PKCE support.
    pub async fn store(&self, params: StoreOAuthCodeParams<'_>) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO oauth_codes (tenant_id, code, user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, previous_auth_id, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(params.tenant_id)
        .bind(params.code)
        .bind(params.user_pubkey)
        .bind(params.client_id)
        .bind(params.redirect_uri)
        .bind(params.scope)
        .bind(params.code_challenge)
        .bind(params.code_challenge_method)
        .bind(params.expires_at)
        .bind(params.previous_auth_id)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Store OAuth code with pending registration data (deferred user creation).
    /// Used by oauth_register to defer user creation until token exchange.
    pub async fn store_with_pending_registration(
        &self,
        params: StoreOAuthCodeWithRegistrationParams<'_>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO oauth_codes (tenant_id, code, user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at,
             pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(params.tenant_id)
        .bind(params.code)
        .bind(params.user_pubkey)
        .bind(params.client_id)
        .bind(params.redirect_uri)
        .bind(params.scope)
        .bind(params.code_challenge)
        .bind(params.code_challenge_method)
        .bind(params.expires_at)
        .bind(Utc::now())
        .bind(params.pending_email)
        .bind(params.pending_password_hash)
        .bind(params.pending_email_verification_token)
        .bind(params.pending_encrypted_secret)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a valid (non-expired) OAuth code.
    pub async fn find_valid(
        &self,
        tenant_id: i64,
        code: &str,
    ) -> Result<Option<OAuthCodeData>, RepositoryError> {
        let result: Option<(
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            Option<i32>,
        )> = sqlx::query_as(
            "SELECT user_pubkey, client_id, redirect_uri, scope, code_challenge, code_challenge_method,
                    pending_email, pending_password_hash, pending_email_verification_token, pending_encrypted_secret,
                    previous_auth_id
             FROM oauth_codes
             WHERE tenant_id = $1 AND code = $2 AND expires_at > $3",
        )
        .bind(tenant_id)
        .bind(code)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|row| OAuthCodeData {
            user_pubkey: row.0,
            client_id: row.1,
            redirect_uri: row.2,
            scope: row.3,
            code_challenge: row.4,
            code_challenge_method: row.5,
            pending_email: row.6,
            pending_password_hash: row.7,
            pending_email_verification_token: row.8,
            pending_encrypted_secret: row.9,
            previous_auth_id: row.10,
        }))
    }

    /// Delete an OAuth code (one-time use).
    pub async fn delete(&self, tenant_id: i64, code: &str) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM oauth_codes WHERE tenant_id = $1 AND code = $2")
            .bind(tenant_id)
            .bind(code)
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
    async fn test_oauth_code_lifecycle() {
        use chrono::Duration;
        use nostr_sdk::Keys;

        let pool = setup_pool().await;
        let repo = OAuthCodeRepository::new(pool.clone());

        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let code = format!("test_code_{}", uuid::Uuid::new_v4());
        let expires_at = Utc::now() + Duration::minutes(10);

        // Create user first
        sqlx::query("INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at) VALUES ($1, 1, $2, NOW(), NOW()) ON CONFLICT (pubkey) DO NOTHING")
            .bind(&user_pubkey)
            .bind(format!("oauth-test-{}@example.com", uuid::Uuid::new_v4()))
            .execute(&pool)
            .await
            .unwrap();

        // Store code
        repo.store(StoreOAuthCodeParams {
            tenant_id: 1,
            code: &code,
            user_pubkey: &user_pubkey,
            client_id: "test_client",
            redirect_uri: "http://localhost:3000/callback",
            scope: "sign_event",
            code_challenge: Some("challenge123"),
            code_challenge_method: Some("S256"),
            expires_at,
            previous_auth_id: None,
        })
        .await
        .unwrap();

        // Find valid code
        let found = repo.find_valid(1, &code).await.unwrap();
        assert!(found.is_some());
        let data = found.unwrap();
        assert_eq!(data.user_pubkey, user_pubkey);
        assert_eq!(data.client_id, "test_client");
        assert_eq!(data.code_challenge, Some("challenge123".to_string()));

        // Delete code
        repo.delete(1, &code).await.unwrap();

        // Should no longer be found
        let found = repo.find_valid(1, &code).await.unwrap();
        assert!(found.is_none());
    }
}
