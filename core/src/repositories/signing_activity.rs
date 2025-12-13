// ABOUTME: Repository for signing activity operations
// ABOUTME: Handles signing_activity table for audit logging

use crate::repositories::RepositoryError;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct SigningActivityRepository {
    pool: PgPool,
}

impl SigningActivityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get recent signing activity for a bunker session.
    pub async fn list_recent(
        &self,
        bunker_secret: &str,
        limit: i32,
    ) -> Result<Vec<(i64, Option<String>, Option<String>, String)>, RepositoryError> {
        sqlx::query_as(
            "SELECT event_kind, event_content, event_id, created_at
             FROM signing_activity
             WHERE bunker_secret = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(bunker_secret)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
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
    async fn test_list_recent_empty() {
        let pool = setup_pool().await;
        let repo = SigningActivityRepository::new(pool);

        // Non-existent secret should return empty list
        let activities = repo
            .list_recent("non_existent_secret", 100)
            .await
            .unwrap();
        assert!(activities.is_empty());
    }
}
