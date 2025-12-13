// ABOUTME: Policy repository for data access operations
// ABOUTME: Provides methods for managing policies and permissions

use crate::repositories::RepositoryError;
use crate::types::permission::Permission;
use crate::types::policy::{Policy, PolicyWithPermissions};
use sqlx::PgPool;

/// Repository for policy database operations.
#[derive(Debug, Clone)]
pub struct PolicyRepository {
    pool: PgPool,
}

impl PolicyRepository {
    /// Create a new PolicyRepository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find a policy by ID.
    pub async fn find(&self, policy_id: i32) -> Result<Policy, RepositoryError> {
        sqlx::query_as::<_, Policy>(
            "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
             FROM policies WHERE id = $1",
        )
        .bind(policy_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a policy by slug.
    pub async fn find_by_slug(&self, slug: &str) -> Result<Policy, RepositoryError> {
        sqlx::query_as::<_, Policy>(
            "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
             FROM policies WHERE slug = $1",
        )
        .bind(slug)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a policy ID by slug. Returns None if not found.
    pub async fn find_id_by_slug(&self, slug: &str) -> Result<Option<i32>, RepositoryError> {
        sqlx::query_scalar("SELECT id FROM policies WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// List all public policies (global policies with slugs).
    pub async fn list_public(&self) -> Result<Vec<Policy>, RepositoryError> {
        sqlx::query_as::<_, Policy>(
            "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
             FROM policies WHERE slug IS NOT NULL AND team_id IS NULL ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// List all policies for a team.
    pub async fn list_by_team(&self, team_id: i32) -> Result<Vec<Policy>, RepositoryError> {
        sqlx::query_as::<_, Policy>(
            "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
             FROM policies WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if a policy exists and belongs to a specific team.
    pub async fn exists_for_team(
        &self,
        team_id: i32,
        policy_id: i32,
    ) -> Result<bool, RepositoryError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM policies WHERE team_id = $1 AND id = $2)",
        )
        .bind(team_id)
        .bind(policy_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    /// Create a new policy.
    pub async fn create(&self, team_id: i32, name: &str) -> Result<Policy, RepositoryError> {
        sqlx::query_as::<_, Policy>(
            "INSERT INTO policies (team_id, name, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id, name, team_id, created_at, updated_at, slug, display_name, description",
        )
        .bind(team_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Create a permission.
    pub async fn create_permission(
        &self,
        identifier: &str,
        config: &serde_json::Value,
    ) -> Result<Permission, RepositoryError> {
        sqlx::query_as::<_, Permission>(
            "INSERT INTO permissions (identifier, config, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id, identifier, config, created_at, updated_at",
        )
        .bind(identifier)
        .bind(config)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Link a permission to a policy.
    pub async fn link_permission(
        &self,
        policy_id: i32,
        permission_id: i32,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(policy_id)
        .bind(permission_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all permissions for a policy.
    pub async fn get_permissions(
        &self,
        policy_id: i32,
    ) -> Result<Vec<Permission>, RepositoryError> {
        sqlx::query_as::<_, Permission>(
            "SELECT p.id, p.identifier, p.config, p.created_at, p.updated_at
             FROM permissions p
             JOIN policy_permissions pp ON pp.permission_id = p.id
             WHERE pp.policy_id = $1",
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a policy with its permissions.
    pub async fn find_with_permissions(
        &self,
        policy_id: i32,
    ) -> Result<PolicyWithPermissions, RepositoryError> {
        let policy = self.find(policy_id).await?;
        let permissions = self.get_permissions(policy_id).await?;

        Ok(PolicyWithPermissions {
            policy,
            permissions,
        })
    }

    /// Delete a policy and its permission links.
    /// Uses a transaction to ensure atomicity.
    /// Note: Does not delete orphaned permissions - call cleanup separately if needed.
    pub async fn delete(&self, policy_id: i32) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        // Delete policy_permissions first
        sqlx::query("DELETE FROM policy_permissions WHERE policy_id = $1")
            .bind(policy_id)
            .execute(&mut *tx)
            .await?;

        // Delete the policy
        sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(policy_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Get the allowed_kinds config JSON for a policy.
    /// Returns the config string if an allowed_kinds permission exists.
    pub async fn get_allowed_kinds_config(
        &self,
        policy_id: i32,
    ) -> Result<Option<String>, RepositoryError> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT p.config FROM permissions p
             JOIN policy_permissions pp ON p.id = pp.permission_id
             WHERE pp.policy_id = $1 AND p.identifier = 'allowed_kinds'",
        )
        .bind(policy_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.map(|r| r.0))
    }

    /// Create a policy with associated permissions atomically.
    ///
    /// Creates permission records first, then the policy, then links them.
    /// Takes a list of (identifier, config) tuples for the permissions.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    pub async fn create_with_permissions(
        &self,
        team_id: i32,
        name: &str,
        permission_configs: Vec<(String, serde_json::Value)>,
    ) -> Result<PolicyWithPermissions, RepositoryError> {
        use chrono::Utc;

        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Create permissions first
        let mut permissions = Vec::new();
        for (identifier, config) in permission_configs {
            let permission = sqlx::query_as::<_, Permission>(
                "INSERT INTO permissions (identifier, config, created_at, updated_at)
                 VALUES ($1, $2, $3, $4)
                 RETURNING *",
            )
            .bind(&identifier)
            .bind(&config)
            .bind(now)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;

            permissions.push(permission);
        }

        // Create policy
        let policy = sqlx::query_as::<_, Policy>(
            "INSERT INTO policies (team_id, name, created_at, updated_at)
             VALUES ($1, $2, $3, $4)
             RETURNING *",
        )
        .bind(team_id)
        .bind(name)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // Link permissions to policy
        for permission in &permissions {
            sqlx::query(
                "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(policy.id)
            .bind(permission.id)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(PolicyWithPermissions {
            policy,
            permissions,
        })
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
    async fn test_create_policy() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("Policy Test {}", suffix)).await.unwrap();

        let policy = policy_repo.create(team.id, &format!("Test Policy {}", suffix)).await;
        assert!(policy.is_ok(), "Should create policy");

        let policy = policy.unwrap();
        assert!(policy.name.contains("Test Policy"));
        assert_eq!(policy.team_id, Some(team.id));
    }

    #[tokio::test]
    async fn test_find_policy() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("Find Policy Test {}", suffix)).await.unwrap();
        let created = policy_repo.create(team.id, &format!("Find Policy {}", suffix)).await.unwrap();

        let found = policy_repo.find(created.id).await;
        assert!(found.is_ok(), "Should find policy");
        assert_eq!(found.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn test_find_policy_not_found() {
        let pool = setup_pool().await;
        let policy_repo = PolicyRepository::new(pool.clone());

        let result = policy_repo.find(999999).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_list_by_team() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("List Policy Test {}", suffix)).await.unwrap();

        // Create two policies
        policy_repo.create(team.id, &format!("Policy 1 {}", suffix)).await.unwrap();
        policy_repo.create(team.id, &format!("Policy 2 {}", suffix)).await.unwrap();

        let policies = policy_repo.list_by_team(team.id).await;
        assert!(policies.is_ok(), "Should list policies");
        assert!(policies.unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn test_exists_for_team() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("Exists Test {}", suffix)).await.unwrap();
        let policy = policy_repo.create(team.id, &format!("Exists Policy {}", suffix)).await.unwrap();

        // Should exist
        let exists = policy_repo.exists_for_team(team.id, policy.id).await.unwrap();
        assert!(exists, "Policy should exist for team");

        // Should not exist for different team
        let other_team = team_repo.create(1, &format!("Other Team {}", suffix)).await.unwrap();
        let not_exists = policy_repo.exists_for_team(other_team.id, policy.id).await.unwrap();
        assert!(!not_exists, "Policy should not exist for other team");
    }

    #[tokio::test]
    async fn test_create_permission() {
        let pool = setup_pool().await;
        let policy_repo = PolicyRepository::new(pool.clone());

        let config = serde_json::json!({"allowed_kinds": [1, 7]});
        let permission = policy_repo.create_permission("allowed_kinds", &config).await;

        assert!(permission.is_ok(), "Should create permission");
        let permission = permission.unwrap();
        assert_eq!(permission.identifier, "allowed_kinds");
    }

    #[tokio::test]
    async fn test_link_permission() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("Link Test {}", suffix)).await.unwrap();
        let policy = policy_repo.create(team.id, &format!("Link Policy {}", suffix)).await.unwrap();
        let config = serde_json::json!({"allowed_kinds": [1]});
        let permission = policy_repo.create_permission("allowed_kinds", &config).await.unwrap();

        let result = policy_repo.link_permission(policy.id, permission.id).await;
        assert!(result.is_ok(), "Should link permission to policy");
    }

    #[tokio::test]
    async fn test_get_permissions() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("Get Perms Test {}", suffix)).await.unwrap();
        let policy = policy_repo.create(team.id, &format!("Get Perms Policy {}", suffix)).await.unwrap();

        // Create and link two permissions
        let config1 = serde_json::json!({"allowed_kinds": [1]});
        let perm1 = policy_repo.create_permission("allowed_kinds", &config1).await.unwrap();
        policy_repo.link_permission(policy.id, perm1.id).await.unwrap();

        let config2 = serde_json::json!({"blocked_words": ["test"]});
        let perm2 = policy_repo.create_permission("content_filter", &config2).await.unwrap();
        policy_repo.link_permission(policy.id, perm2.id).await.unwrap();

        let permissions = policy_repo.get_permissions(policy.id).await;
        assert!(permissions.is_ok(), "Should get permissions");
        assert_eq!(permissions.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_find_with_permissions() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("With Perms Test {}", suffix)).await.unwrap();
        let policy = policy_repo.create(team.id, &format!("With Perms Policy {}", suffix)).await.unwrap();

        let config = serde_json::json!({"allowed_kinds": [1, 7]});
        let perm = policy_repo.create_permission("allowed_kinds", &config).await.unwrap();
        policy_repo.link_permission(policy.id, perm.id).await.unwrap();

        let with_perms = policy_repo.find_with_permissions(policy.id).await;
        assert!(with_perms.is_ok(), "Should find with permissions");

        let with_perms = with_perms.unwrap();
        assert_eq!(with_perms.policy.id, policy.id);
        assert_eq!(with_perms.permissions.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_policy() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo.create(1, &format!("Delete Policy Test {}", suffix)).await.unwrap();
        let policy = policy_repo.create(team.id, &format!("Delete Policy {}", suffix)).await.unwrap();

        // Link a permission
        let config = serde_json::json!({"allowed_kinds": [1]});
        let perm = policy_repo.create_permission("allowed_kinds", &config).await.unwrap();
        policy_repo.link_permission(policy.id, perm.id).await.unwrap();

        // Delete
        let result = policy_repo.delete(policy.id).await;
        assert!(result.is_ok(), "Should delete policy");

        // Verify gone
        let find_result = policy_repo.find(policy.id).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_create_with_permissions() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("CreateWithPerms Test {}", suffix))
            .await
            .unwrap();

        let permission_configs = vec![
            (
                "allowed_kinds".to_string(),
                serde_json::json!({"kinds": [1, 7, 30023]}),
            ),
            (
                "content_filter".to_string(),
                serde_json::json!({"blocked_words": ["spam"]}),
            ),
        ];

        let result = policy_repo
            .create_with_permissions(team.id, &format!("Atomic Policy {}", suffix), permission_configs)
            .await;

        assert!(result.is_ok(), "Should create policy with permissions");

        let policy_with_perms = result.unwrap();
        assert!(policy_with_perms.policy.name.contains("Atomic Policy"));
        assert_eq!(policy_with_perms.policy.team_id, Some(team.id));
        assert_eq!(
            policy_with_perms.permissions.len(),
            2,
            "Should have 2 permissions"
        );

        // Verify permissions are linked
        let fetched = policy_repo
            .find_with_permissions(policy_with_perms.policy.id)
            .await
            .unwrap();
        assert_eq!(fetched.permissions.len(), 2);

        // Verify identifiers
        let identifiers: Vec<&str> = fetched.permissions.iter().map(|p| p.identifier.as_str()).collect();
        assert!(identifiers.contains(&"allowed_kinds"));
        assert!(identifiers.contains(&"content_filter"));
    }

    #[tokio::test]
    async fn test_create_with_permissions_empty() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let policy_repo = PolicyRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("EmptyPerms Test {}", suffix))
            .await
            .unwrap();

        // Create policy with no permissions
        let result = policy_repo
            .create_with_permissions(team.id, &format!("Empty Perms Policy {}", suffix), vec![])
            .await;

        assert!(result.is_ok(), "Should create policy with no permissions");

        let policy_with_perms = result.unwrap();
        assert!(policy_with_perms.permissions.is_empty());
    }
}
