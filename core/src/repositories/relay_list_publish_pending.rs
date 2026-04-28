use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

const CLAIM_LEASE_SECONDS: i64 = 60;

#[derive(Debug, Clone)]
pub struct RelayListPublishPendingRepository {
    pool: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingRelayListPublishJob {
    pub id: i64,
    pub tenant_id: i64,
    pub user_pubkey: String,
    pub encrypted_secret_key: Vec<u8>,
    pub attempts: i32,
}

impl RelayListPublishPendingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn enqueue(
        &self,
        tenant_id: i64,
        user_pubkey: &str,
        encrypted_secret_key: &[u8],
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO relay_list_publish_pending (
                tenant_id, user_pubkey, encrypted_secret_key, attempts, next_attempt_at, last_error, created_at, updated_at
             ) VALUES ($1, $2, $3, 0, NOW(), NULL, NOW(), NOW())
             ON CONFLICT (tenant_id, user_pubkey) DO UPDATE
               SET encrypted_secret_key = EXCLUDED.encrypted_secret_key,
                   attempts = 0,
                   next_attempt_at = NOW(),
                   last_error = NULL,
                   updated_at = NOW()",
        )
        .bind(tenant_id)
        .bind(user_pubkey)
        .bind(encrypted_secret_key)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn claim_due(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingRelayListPublishJob>, RepositoryError> {
        sqlx::query_as(
            "WITH due_jobs AS (
                 SELECT id
                 FROM relay_list_publish_pending
                 WHERE next_attempt_at <= NOW()
                 ORDER BY next_attempt_at ASC
                 LIMIT $1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE relay_list_publish_pending pending
             SET attempts = pending.attempts + 1,
                 next_attempt_at = NOW() + ($2 * INTERVAL '1 second'),
                 updated_at = NOW()
             FROM due_jobs
             WHERE pending.id = due_jobs.id
             RETURNING pending.id, pending.tenant_id, pending.user_pubkey, pending.encrypted_secret_key, pending.attempts",
        )
        .bind(limit)
        .bind(CLAIM_LEASE_SECONDS)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn mark_succeeded(&self, job_id: i64) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM relay_list_publish_pending WHERE id = $1")
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn reschedule(
        &self,
        job_id: i64,
        next_attempt_at: DateTime<Utc>,
        last_error: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE relay_list_publish_pending
             SET next_attempt_at = $2, last_error = $3, updated_at = NOW()
             WHERE id = $1",
        )
        .bind(job_id)
        .bind(next_attempt_at)
        .bind(last_error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use super::*;
    use sqlx::PgPool;

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
    async fn claim_due_applies_lease_and_prevents_immediate_reclaim() {
        let pool = setup_pool().await;
        let repo = RelayListPublishPendingRepository::new(pool.clone());
        let pubkey = format!("{}{}", "a".repeat(56), "deadbeef");
        let encrypted_secret = vec![1_u8, 2, 3, 4];

        // Create user required by FK constraint on pending jobs.
        sqlx::query(
            "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
             VALUES ($1, 1, $2, NOW(), NOW())
             ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(&pubkey)
        .bind(format!(
            "relay-list-lease-{}@example.com",
            uuid::Uuid::new_v4()
        ))
        .execute(&pool)
        .await
        .expect("insert user");

        repo.enqueue(1, &pubkey, &encrypted_secret)
            .await
            .expect("enqueue");

        let first_claim = repo.claim_due(1).await.expect("first claim");
        assert_eq!(first_claim.len(), 1);
        assert_eq!(first_claim[0].attempts, 1);

        let second_claim = repo.claim_due(1).await.expect("second claim");
        assert!(
            second_claim.is_empty(),
            "job should not be immediately claimable while lease is active"
        );

        // Cleanup
        sqlx::query(
            "DELETE FROM relay_list_publish_pending WHERE tenant_id = 1 AND user_pubkey = $1",
        )
        .bind(&pubkey)
        .execute(&pool)
        .await
        .ok();
        sqlx::query("DELETE FROM users WHERE tenant_id = 1 AND pubkey = $1")
            .bind(&pubkey)
            .execute(&pool)
            .await
            .ok();
    }
}
