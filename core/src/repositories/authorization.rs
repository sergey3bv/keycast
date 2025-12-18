// ABOUTME: Authorization repository for data access operations
// ABOUTME: Provides methods for managing authorizations

use crate::repositories::RepositoryError;
use crate::types::authorization::Authorization;
use sqlx::PgPool;

/// Repository for authorization database operations.
#[derive(Debug, Clone)]
pub struct AuthorizationRepository {
    pool: PgPool,
}

impl AuthorizationRepository {
    /// Create a new AuthorizationRepository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find an authorization by ID.
    pub async fn find(
        &self,
        tenant_id: i64,
        authorization_id: i32,
    ) -> Result<Authorization, RepositoryError> {
        sqlx::query_as::<_, Authorization>(
            "SELECT id, tenant_id, stored_key_id, secret_hash, bunker_public_key,
                    relays, policy_id, max_uses, expires_at, connected_client_pubkey,
                    connected_at, label, created_at, updated_at
             FROM authorizations WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(authorization_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find all authorizations for a stored key.
    pub async fn find_by_stored_key(
        &self,
        tenant_id: i64,
        stored_key_id: i32,
    ) -> Result<Vec<Authorization>, RepositoryError> {
        sqlx::query_as::<_, Authorization>(
            "SELECT id, tenant_id, stored_key_id, secret_hash, bunker_public_key,
                    relays, policy_id, max_uses, expires_at, connected_client_pubkey,
                    connected_at, label, created_at, updated_at
             FROM authorizations WHERE tenant_id = $1 AND stored_key_id = $2",
        )
        .bind(tenant_id)
        .bind(stored_key_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Get all authorization IDs for a tenant.
    pub async fn all_ids(&self, tenant_id: i64) -> Result<Vec<i32>, RepositoryError> {
        sqlx::query_scalar::<_, i32>("SELECT id FROM authorizations WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Get all authorization IDs for all tenants.
    pub async fn all_ids_for_all_tenants(&self) -> Result<Vec<(i64, i32)>, RepositoryError> {
        sqlx::query_as::<_, (i64, i32)>("SELECT tenant_id, id FROM authorizations")
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Create a new authorization.
    ///
    /// The `secret_hash` is the bcrypt hash of the connection secret.
    /// The plaintext secret is only available at creation time and returned in the bunker URL.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: i64,
        stored_key_id: i32,
        policy_id: i32,
        secret_hash: &str,
        bunker_public_key: &str,
        relays: &serde_json::Value,
        max_uses: Option<i32>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        label: Option<&str>,
    ) -> Result<Authorization, RepositoryError> {
        sqlx::query_as::<_, Authorization>(
            "INSERT INTO authorizations (tenant_id, stored_key_id, policy_id, secret_hash, bunker_public_key, relays, max_uses, expires_at, label, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
             RETURNING id, tenant_id, stored_key_id, secret_hash, bunker_public_key, relays, policy_id, max_uses, expires_at, connected_client_pubkey, connected_at, label, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(stored_key_id)
        .bind(policy_id)
        .bind(secret_hash)
        .bind(bunker_public_key)
        .bind(relays)
        .bind(max_uses)
        .bind(expires_at)
        .bind(label)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Delete an authorization and its user associations.
    /// Uses a transaction to ensure atomicity.
    pub async fn delete(
        &self,
        tenant_id: i64,
        authorization_id: i32,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM authorizations WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(authorization_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete an authorization by stored_key_id (used when checking ownership).
    pub async fn delete_for_stored_key(
        &self,
        tenant_id: i64,
        authorization_id: i32,
        stored_key_id: i32,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM authorizations WHERE tenant_id = $1 AND id = $2 AND stored_key_id = $3",
        )
        .bind(tenant_id)
        .bind(authorization_id)
        .bind(stored_key_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::{PolicyRepository, StoredKeyRepository, TeamRepository};
    use nostr_sdk::Keys;
    use sqlx::PgPool;

    async fn setup_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast".to_string());

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

    /// Generate a 64-character hex pubkey for bunker_public_key field
    fn generate_bunker_pubkey() -> String {
        Keys::generate().public_key().to_hex()
    }

    async fn create_test_fixtures(pool: &PgPool, suffix: &str) -> (i32, i32, i32) {
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());

        let team = team_repo
            .create(1, &format!("Auth Test Team {}", suffix))
            .await
            .unwrap();
        // Use a proper 64-char hex pubkey for stored_key
        let stored_key_pubkey = Keys::generate().public_key().to_hex();
        let key = key_repo
            .create(
                1,
                team.id,
                &format!("Auth Test Key {}", suffix),
                &stored_key_pubkey,
                b"encrypted_secret",
            )
            .await
            .unwrap();
        let policy = policy_repo
            .create(team.id, &format!("Auth Test Policy {}", suffix))
            .await
            .unwrap();

        (team.id, key.id, policy.id)
    }

    #[tokio::test]
    async fn test_create_authorization() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());
        let suffix = test_suffix();

        let (_, key_id, policy_id) = create_test_fixtures(&pool, &suffix).await;

        let relays = serde_json::json!(["wss://relay1.test", "wss://relay2.test"]);
        let bunker_pubkey = generate_bunker_pubkey();
        // Use a fake bcrypt hash for testing (real hash would be from secret pool)
        let secret_hash = "$2b$10$test_hash_not_real_but_valid_format_xxxxx";
        let auth = auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &bunker_pubkey,
                &relays,
                Some(10i32),
                None,
                None,
            )
            .await;

        assert!(
            auth.is_ok(),
            "Should create authorization: {:?}",
            auth.err()
        );
        let auth = auth.unwrap();
        assert_eq!(auth.stored_key_id, key_id);
        assert_eq!(auth.policy_id, policy_id);
    }

    #[tokio::test]
    async fn test_find_authorization() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());
        let suffix = test_suffix();

        let (_, key_id, policy_id) = create_test_fixtures(&pool, &suffix).await;

        let relays = serde_json::json!(["wss://relay.test"]);
        let bunker_pubkey = generate_bunker_pubkey();
        let secret_hash = "$2b$10$test_hash_not_real_but_valid_format_xxxxx";
        let created = auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &bunker_pubkey,
                &relays,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let found = auth_repo.find(1, created.id).await;
        assert!(found.is_ok(), "Should find authorization");
        assert_eq!(found.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn test_find_authorization_not_found() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());

        let result = auth_repo.find(1, 999999).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_find_by_stored_key() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());
        let suffix = test_suffix();

        let (_, key_id, policy_id) = create_test_fixtures(&pool, &suffix).await;

        // Create two authorizations for the same key
        let relays = serde_json::json!(["wss://relay.test"]);
        let secret_hash = "$2b$10$test_hash_not_real_but_valid_format_xxxxx";
        auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &generate_bunker_pubkey(),
                &relays,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &generate_bunker_pubkey(),
                &relays,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let found = auth_repo.find_by_stored_key(1, key_id).await;
        assert!(found.is_ok(), "Should find authorizations");
        assert_eq!(found.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_delete_authorization() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());
        let suffix = test_suffix();

        let (_, key_id, policy_id) = create_test_fixtures(&pool, &suffix).await;

        let relays = serde_json::json!(["wss://relay.test"]);
        let secret_hash = "$2b$10$test_hash_not_real_but_valid_format_xxxxx";
        let auth = auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &generate_bunker_pubkey(),
                &relays,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let result = auth_repo.delete(1, auth.id).await;
        assert!(result.is_ok(), "Should delete authorization");
        assert!(result.unwrap(), "Should have deleted one row");

        let find_result = auth_repo.find(1, auth.id).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete_for_stored_key() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());
        let suffix = test_suffix();

        let (_, key_id, policy_id) = create_test_fixtures(&pool, &suffix).await;

        let relays = serde_json::json!(["wss://relay.test"]);
        let secret_hash = "$2b$10$test_hash_not_real_but_valid_format_xxxxx";
        let auth = auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &generate_bunker_pubkey(),
                &relays,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Should succeed with correct stored_key_id
        let result = auth_repo.delete_for_stored_key(1, auth.id, key_id).await;
        assert!(result.is_ok(), "Should delete authorization");
        assert!(result.unwrap(), "Should have deleted one row");
    }

    #[tokio::test]
    async fn test_delete_for_stored_key_wrong_key() {
        let pool = setup_pool().await;
        let auth_repo = AuthorizationRepository::new(pool.clone());
        let suffix = test_suffix();

        let (_, key_id, policy_id) = create_test_fixtures(&pool, &suffix).await;

        let relays = serde_json::json!(["wss://relay.test"]);
        let secret_hash = "$2b$10$test_hash_not_real_but_valid_format_xxxxx";
        let auth = auth_repo
            .create(
                1,
                key_id,
                policy_id,
                secret_hash,
                &generate_bunker_pubkey(),
                &relays,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Should not delete with wrong stored_key_id
        let result = auth_repo.delete_for_stored_key(1, auth.id, 999999).await;
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Should not have deleted any rows");

        // Authorization should still exist
        let found = auth_repo.find(1, auth.id).await;
        assert!(found.is_ok(), "Authorization should still exist");
    }
}
