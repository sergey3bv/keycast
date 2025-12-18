// ABOUTME: StoredKey repository for data access operations
// ABOUTME: Provides methods for managing encrypted signing keys

use crate::repositories::RepositoryError;
use crate::types::stored_key::StoredKey;
use sqlx::PgPool;

/// Repository for stored key database operations.
#[derive(Debug, Clone)]
pub struct StoredKeyRepository {
    pool: PgPool,
}

impl StoredKeyRepository {
    /// Create a new StoredKeyRepository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find a stored key by ID.
    pub async fn find(&self, tenant_id: i64, key_id: i32) -> Result<StoredKey, RepositoryError> {
        sqlx::query_as::<_, StoredKey>(
            "SELECT id, team_id, name, pubkey, secret_key, created_at, updated_at
             FROM stored_keys WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(key_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a stored key by team and pubkey.
    pub async fn find_by_pubkey(
        &self,
        tenant_id: i64,
        team_id: i32,
        pubkey: &str,
    ) -> Result<StoredKey, RepositoryError> {
        sqlx::query_as::<_, StoredKey>(
            "SELECT id, team_id, name, pubkey, secret_key, created_at, updated_at
             FROM stored_keys WHERE tenant_id = $1 AND team_id = $2 AND pubkey = $3",
        )
        .bind(tenant_id)
        .bind(team_id)
        .bind(pubkey)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create a new stored key.
    pub async fn create(
        &self,
        tenant_id: i64,
        team_id: i32,
        name: &str,
        pubkey: &str,
        encrypted_secret: &[u8],
    ) -> Result<StoredKey, RepositoryError> {
        sqlx::query_as::<_, StoredKey>(
            "INSERT INTO stored_keys (tenant_id, team_id, name, pubkey, secret_key, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
             RETURNING id, team_id, name, pubkey, secret_key, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(team_id)
        .bind(name)
        .bind(pubkey)
        .bind(encrypted_secret)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Delete a stored key and its associated authorizations.
    /// Uses a transaction to ensure atomicity.
    pub async fn delete(&self, tenant_id: i64, key_id: i32) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        // Delete authorizations for this key
        sqlx::query("DELETE FROM authorizations WHERE tenant_id = $1 AND stored_key_id = $2")
            .bind(tenant_id)
            .bind(key_id)
            .execute(&mut *tx)
            .await?;

        // Delete the stored key
        sqlx::query("DELETE FROM stored_keys WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(key_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Delete a stored key by team and pubkey.
    pub async fn delete_by_pubkey(
        &self,
        tenant_id: i64,
        team_id: i32,
        pubkey: &str,
    ) -> Result<(), RepositoryError> {
        // First find the key to get its ID
        let key = self.find_by_pubkey(tenant_id, team_id, pubkey).await?;
        self.delete(tenant_id, key.id).await
    }

    /// List all stored keys for a team.
    pub async fn list_by_team(
        &self,
        tenant_id: i64,
        team_id: i32,
    ) -> Result<Vec<StoredKey>, RepositoryError> {
        sqlx::query_as::<_, StoredKey>(
            "SELECT id, team_id, name, pubkey, secret_key, created_at, updated_at
             FROM stored_keys WHERE tenant_id = $1 AND team_id = $2",
        )
        .bind(tenant_id)
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::TeamRepository;
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

    #[tokio::test]
    async fn test_create_stored_key() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Key Test {}", suffix))
            .await
            .unwrap();

        let key = key_repo
            .create(
                1,
                team.id,
                "Test Key",
                &format!("pubkey_{}", suffix),
                b"encrypted_secret",
            )
            .await;

        assert!(key.is_ok(), "Should create stored key");
        let key = key.unwrap();
        assert_eq!(key.name, "Test Key");
        assert_eq!(key.team_id, team.id);
    }

    #[tokio::test]
    async fn test_find_stored_key() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Find Key Test {}", suffix))
            .await
            .unwrap();
        let created = key_repo
            .create(
                1,
                team.id,
                "Find Key",
                &format!("findkey_{}", suffix),
                b"secret",
            )
            .await
            .unwrap();

        let found = key_repo.find(1, created.id).await;
        assert!(found.is_ok(), "Should find stored key");
        assert_eq!(found.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn test_find_stored_key_not_found() {
        let pool = setup_pool().await;
        let key_repo = StoredKeyRepository::new(pool.clone());

        let result = key_repo.find(1, 999999).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_find_by_pubkey() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Pubkey Test {}", suffix))
            .await
            .unwrap();
        let pubkey = format!("bypubkey_{}", suffix);
        key_repo
            .create(1, team.id, "Pubkey Key", &pubkey, b"secret")
            .await
            .unwrap();

        let found = key_repo.find_by_pubkey(1, team.id, &pubkey).await;
        assert!(found.is_ok(), "Should find by pubkey");
        // pubkey column is char(64), so it gets padded with spaces
        assert!(found.unwrap().pubkey.trim() == pubkey);
    }

    #[tokio::test]
    async fn test_list_by_team() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("List Keys Test {}", suffix))
            .await
            .unwrap();

        // Create two keys
        key_repo
            .create(
                1,
                team.id,
                "Key 1",
                &format!("listkey1_{}", suffix),
                b"secret1",
            )
            .await
            .unwrap();
        key_repo
            .create(
                1,
                team.id,
                "Key 2",
                &format!("listkey2_{}", suffix),
                b"secret2",
            )
            .await
            .unwrap();

        let keys = key_repo.list_by_team(1, team.id).await;
        assert!(keys.is_ok(), "Should list keys");
        assert_eq!(keys.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_delete_stored_key() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Delete Key Test {}", suffix))
            .await
            .unwrap();
        let key = key_repo
            .create(
                1,
                team.id,
                "Delete Key",
                &format!("delkey_{}", suffix),
                b"secret",
            )
            .await
            .unwrap();

        let result = key_repo.delete(1, key.id).await;
        assert!(result.is_ok(), "Should delete key");

        let find_result = key_repo.find(1, key.id).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete_by_pubkey() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Del Pubkey Test {}", suffix))
            .await
            .unwrap();
        let pubkey = format!("delpubkey_{}", suffix);
        key_repo
            .create(1, team.id, "Del Pubkey Key", &pubkey, b"secret")
            .await
            .unwrap();

        let result = key_repo.delete_by_pubkey(1, team.id, &pubkey).await;
        assert!(result.is_ok(), "Should delete by pubkey");

        let find_result = key_repo.find_by_pubkey(1, team.id, &pubkey).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_create_multiple_keys_same_team() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let key_repo = StoredKeyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Multi Key Test {}", suffix))
            .await
            .unwrap();

        // Create multiple keys for the same team (different pubkeys)
        let key1 = key_repo
            .create(
                1,
                team.id,
                "Key 1",
                &format!("multikey1_{}", suffix),
                b"secret1",
            )
            .await;
        let key2 = key_repo
            .create(
                1,
                team.id,
                "Key 2",
                &format!("multikey2_{}", suffix),
                b"secret2",
            )
            .await;

        assert!(key1.is_ok(), "Should create first key");
        assert!(key2.is_ok(), "Should create second key");
    }
}
