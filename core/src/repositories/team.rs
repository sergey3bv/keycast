// ABOUTME: Team repository for data access operations
// ABOUTME: Provides methods for team CRUD and member management

use crate::repositories::RepositoryError;
use crate::types::policy::{Policy, PolicyWithPermissions};
use crate::types::stored_key::{PublicStoredKey, StoredKey};
use crate::types::team::{Team, TeamWithRelations};
use crate::types::user::TeamUser;
use sqlx::PgPool;

/// Repository for team-related database operations.
#[derive(Debug, Clone)]
pub struct TeamRepository {
    pool: PgPool,
}

impl TeamRepository {
    /// Create a new TeamRepository with the given connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find a team by ID.
    pub async fn find(&self, tenant_id: i64, team_id: i32) -> Result<Team, RepositoryError> {
        sqlx::query_as::<_, Team>(
            "SELECT id, name, created_at, updated_at FROM teams WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(team_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a team with all its relations (users, keys, policies).
    pub async fn find_with_relations(
        &self,
        tenant_id: i64,
        team_id: i32,
    ) -> Result<TeamWithRelations, RepositoryError> {
        // Get team
        let team = self.find(tenant_id, team_id).await?;

        // Get team_users for this team
        let team_users = sqlx::query_as::<_, TeamUser>(
            "SELECT user_pubkey, team_id, role, created_at, updated_at
             FROM team_users WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await?;

        // Get stored keys for this team
        let stored_keys = sqlx::query_as::<_, StoredKey>(
            "SELECT id, team_id, name, pubkey, secret_key, created_at, updated_at
             FROM stored_keys WHERE tenant_id = $1 AND team_id = $2",
        )
        .bind(tenant_id)
        .bind(team_id)
        .fetch_all(&self.pool)
        .await?;

        let public_stored_keys: Vec<PublicStoredKey> =
            stored_keys.into_iter().map(|k| k.into()).collect();

        // Get policies with permissions
        let policies = self.get_policies_with_permissions(team_id).await?;

        Ok(TeamWithRelations {
            team,
            team_users,
            stored_keys: public_stored_keys,
            policies,
        })
    }

    /// Create a new team and return it.
    pub async fn create(&self, tenant_id: i64, name: &str) -> Result<Team, RepositoryError> {
        sqlx::query_as::<_, Team>(
            "INSERT INTO teams (tenant_id, name, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id, name, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Update a team's name.
    pub async fn update(
        &self,
        tenant_id: i64,
        team_id: i32,
        name: &str,
    ) -> Result<Team, RepositoryError> {
        sqlx::query_as::<_, Team>(
            "UPDATE teams SET name = $1, updated_at = NOW()
             WHERE tenant_id = $2 AND id = $3
             RETURNING id, name, created_at, updated_at",
        )
        .bind(name)
        .bind(tenant_id)
        .bind(team_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Delete a team and all associated data (cascading delete).
    /// Uses a transaction to ensure atomicity.
    pub async fn delete(&self, tenant_id: i64, team_id: i32) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        // Delete authorizations for stored keys in this team
        sqlx::query(
            "DELETE FROM authorizations
             WHERE tenant_id = $1 AND stored_key_id IN (
                 SELECT id FROM stored_keys WHERE tenant_id = $1 AND team_id = $2
             )",
        )
        .bind(tenant_id)
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        // Delete stored keys
        sqlx::query("DELETE FROM stored_keys WHERE tenant_id = $1 AND team_id = $2")
            .bind(tenant_id)
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        // Find orphaned permissions (only used by this team's policies)
        let orphaned_perm_ids: Vec<(i32,)> = sqlx::query_as(
            "SELECT pp.permission_id
             FROM policy_permissions pp
             JOIN policies pol ON pp.policy_id = pol.id
             WHERE pol.team_id = $1
             AND pp.permission_id NOT IN (
                 SELECT pp2.permission_id
                 FROM policy_permissions pp2
                 JOIN policies pol2 ON pp2.policy_id = pol2.id
                 WHERE pol2.team_id != $1
             )",
        )
        .bind(team_id)
        .fetch_all(&mut *tx)
        .await?;

        // Delete policy_permissions for this team's policies
        sqlx::query(
            "DELETE FROM policy_permissions
             WHERE policy_id IN (SELECT id FROM policies WHERE team_id = $1)",
        )
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        // Delete orphaned permissions
        if !orphaned_perm_ids.is_empty() {
            let ids: Vec<i32> = orphaned_perm_ids.into_iter().map(|(id,)| id).collect();
            sqlx::query("DELETE FROM permissions WHERE id = ANY($1)")
                .bind(&ids)
                .execute(&mut *tx)
                .await?;
        }

        // Delete policies
        sqlx::query("DELETE FROM policies WHERE team_id = $1")
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        // Delete team_users
        sqlx::query("DELETE FROM team_users WHERE team_id = $1")
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        // Delete the team itself
        sqlx::query("DELETE FROM teams WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Add a member to a team.
    pub async fn add_member(
        &self,
        team_id: i32,
        pubkey: &str,
        role: &str,
    ) -> Result<TeamUser, RepositoryError> {
        sqlx::query_as::<_, TeamUser>(
            "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             RETURNING user_pubkey, team_id, role, created_at, updated_at",
        )
        .bind(team_id)
        .bind(pubkey)
        .bind(role)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if a user is already a member of a team.
    pub async fn is_member(&self, team_id: i32, pubkey: &str) -> Result<bool, RepositoryError> {
        let result = sqlx::query_as::<_, TeamUser>(
            "SELECT user_pubkey, team_id, role, created_at, updated_at
             FROM team_users WHERE team_id = $1 AND user_pubkey = $2",
        )
        .bind(team_id)
        .bind(pubkey)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.is_some())
    }

    /// Get a team member.
    pub async fn get_member(
        &self,
        team_id: i32,
        pubkey: &str,
    ) -> Result<TeamUser, RepositoryError> {
        sqlx::query_as::<_, TeamUser>(
            "SELECT user_pubkey, team_id, role, created_at, updated_at
             FROM team_users WHERE team_id = $1 AND user_pubkey = $2",
        )
        .bind(team_id)
        .bind(pubkey)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Remove a member from a team.
    pub async fn remove_member(&self, team_id: i32, pubkey: &str) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM team_users WHERE team_id = $1 AND user_pubkey = $2")
            .bind(team_id)
            .bind(pubkey)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Count the number of admins in a team, excluding a specific user.
    pub async fn count_other_admins(
        &self,
        team_id: i32,
        exclude_pubkey: &str,
    ) -> Result<i64, RepositoryError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_users WHERE team_id = $1 AND user_pubkey != $2 AND role = 'admin'",
        )
        .bind(team_id)
        .bind(exclude_pubkey)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Get policies with their permissions for a team.
    async fn get_policies_with_permissions(
        &self,
        team_id: i32,
    ) -> Result<Vec<PolicyWithPermissions>, RepositoryError> {
        // Fetch policies for the team
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
             FROM policies WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await?;

        if policies.is_empty() {
            return Ok(Vec::new());
        }

        // Collect policy IDs for batch permission fetch
        let policy_ids: Vec<i32> = policies.iter().map(|p| p.id).collect();

        // Fetch all permissions for all policies
        let permission_rows = sqlx::query_as::<_, PermissionWithPolicyId>(
            "SELECT pp.policy_id,
                    p.id, p.identifier, p.config, p.created_at, p.updated_at
             FROM permissions p
             JOIN policy_permissions pp ON pp.permission_id = p.id
             WHERE pp.policy_id = ANY($1)",
        )
        .bind(&policy_ids)
        .fetch_all(&self.pool)
        .await?;

        // Group permissions by policy_id
        let mut policies_with_permissions = Vec::with_capacity(policies.len());
        for policy in policies {
            let permissions: Vec<crate::types::permission::Permission> = permission_rows
                .iter()
                .filter(|row| row.policy_id == policy.id)
                .map(|row| crate::types::permission::Permission {
                    id: row.id,
                    identifier: row.identifier.clone(),
                    config: row.config.clone(),
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
                .collect();

            policies_with_permissions.push(PolicyWithPermissions {
                policy,
                permissions,
            });
        }

        Ok(policies_with_permissions)
    }

    /// Create a new team with the given admin user atomically.
    ///
    /// Performs complete team setup:
    /// 1. Ensures the admin user exists
    /// 2. Creates the team
    /// 3. Adds the user as admin
    /// 4. Creates a default "All Access" policy with allowed_kinds permission
    ///
    /// Returns the fully populated [`TeamWithRelations`].
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Database`] if the transaction fails.
    pub async fn create_with_admin(
        &self,
        tenant_id: i64,
        name: &str,
        admin_pubkey: &str,
        allowed_kinds_config: serde_json::Value,
    ) -> Result<TeamWithRelations, RepositoryError> {
        use crate::types::permission::{Permission, PolicyPermission};
        use chrono::Utc;

        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        // Ensure user exists
        sqlx::query(
            "INSERT INTO users (tenant_id, pubkey, created_at, updated_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (pubkey) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(admin_pubkey)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Create team
        let team = sqlx::query_as::<_, Team>(
            "INSERT INTO teams (tenant_id, name, created_at, updated_at)
             VALUES ($1, $2, $3, $4)
             RETURNING *",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // Add user as admin
        let team_user = sqlx::query_as::<_, TeamUser>(
            "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, 'admin', $3, $4)
             RETURNING *",
        )
        .bind(team.id)
        .bind(admin_pubkey)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // Create default policy
        let policy = sqlx::query_as::<_, Policy>(
            "INSERT INTO policies (team_id, name, created_at, updated_at)
             VALUES ($1, 'All Access', $2, $3)
             RETURNING *",
        )
        .bind(team.id)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // Create allowed_kinds permission
        let permission = sqlx::query_as::<_, Permission>(
            "INSERT INTO permissions (identifier, config, created_at, updated_at)
             VALUES ('allowed_kinds', $1, $2, $3)
             RETURNING *",
        )
        .bind(allowed_kinds_config)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        // Link permission to policy
        sqlx::query_as::<_, PolicyPermission>(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4)
             RETURNING *",
        )
        .bind(policy.id)
        .bind(permission.id)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let policy_with_permissions = PolicyWithPermissions {
            policy,
            permissions: vec![permission],
        };

        Ok(TeamWithRelations {
            team,
            team_users: vec![team_user],
            stored_keys: vec![],
            policies: vec![policy_with_permissions],
        })
    }
}

/// Helper struct for batch permission loading with policy_id
#[derive(Debug, sqlx::FromRow)]
struct PermissionWithPolicyId {
    policy_id: i32,
    id: i32,
    identifier: String,
    #[sqlx(try_from = "String")]
    config: crate::types::permission::JsonConfig,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::UserRepository;
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

    #[tokio::test]
    async fn test_create_team() {
        let pool = setup_pool().await;
        let repo = TeamRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = repo.create(1, &format!("Test Team {}", suffix)).await;
        assert!(team.is_ok(), "Should create team");

        let team = team.unwrap();
        assert!(team.name.contains("Test Team"));
        assert!(team.id > 0);
    }

    #[tokio::test]
    async fn test_find_team() {
        let pool = setup_pool().await;
        let repo = TeamRepository::new(pool.clone());
        let suffix = test_suffix();

        // Create a team first
        let created = repo
            .create(1, &format!("Find Test {}", suffix))
            .await
            .unwrap();

        // Find it
        let found = repo.find(1, created.id).await;
        assert!(found.is_ok(), "Should find team");
        assert_eq!(found.unwrap().id, created.id);
    }

    #[tokio::test]
    async fn test_find_team_not_found() {
        let pool = setup_pool().await;
        let repo = TeamRepository::new(pool.clone());

        let result = repo.find(1, 999999).await;
        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_team() {
        let pool = setup_pool().await;
        let repo = TeamRepository::new(pool.clone());
        let suffix = test_suffix();

        let created = repo
            .create(1, &format!("Original {}", suffix))
            .await
            .unwrap();

        let updated = repo
            .update(1, created.id, &format!("Updated {}", suffix))
            .await;
        assert!(updated.is_ok(), "Should update team");
        assert!(updated.unwrap().name.contains("Updated"));
    }

    #[tokio::test]
    async fn test_add_member() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        // Create user and team
        let keys = Keys::generate();
        let pubkey = keys.public_key();
        user_repo.find_or_create(1, &pubkey).await.unwrap();
        let team = team_repo
            .create(1, &format!("Member Test {}", suffix))
            .await
            .unwrap();

        // Add member
        let member = team_repo
            .add_member(team.id, &pubkey.to_hex(), "member")
            .await;
        assert!(member.is_ok(), "Should add member");
        assert_eq!(member.unwrap().user_pubkey, pubkey.to_hex());
    }

    #[tokio::test]
    async fn test_add_member_duplicate() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let keys = Keys::generate();
        let pubkey = keys.public_key();
        user_repo.find_or_create(1, &pubkey).await.unwrap();
        let team = team_repo
            .create(1, &format!("Dup Test {}", suffix))
            .await
            .unwrap();

        // Add member twice
        team_repo
            .add_member(team.id, &pubkey.to_hex(), "member")
            .await
            .unwrap();
        let result = team_repo
            .add_member(team.id, &pubkey.to_hex(), "member")
            .await;
        assert!(matches!(result, Err(RepositoryError::Duplicate)));
    }

    #[tokio::test]
    async fn test_is_member() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let keys = Keys::generate();
        let pubkey = keys.public_key();
        user_repo.find_or_create(1, &pubkey).await.unwrap();
        let team = team_repo
            .create(1, &format!("IsMember Test {}", suffix))
            .await
            .unwrap();

        // Not a member yet
        assert!(!team_repo
            .is_member(team.id, &pubkey.to_hex())
            .await
            .unwrap());

        // Add and check
        team_repo
            .add_member(team.id, &pubkey.to_hex(), "member")
            .await
            .unwrap();
        assert!(team_repo
            .is_member(team.id, &pubkey.to_hex())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_remove_member() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let keys = Keys::generate();
        let pubkey = keys.public_key();
        user_repo.find_or_create(1, &pubkey).await.unwrap();
        let team = team_repo
            .create(1, &format!("Remove Test {}", suffix))
            .await
            .unwrap();

        // Add then remove
        team_repo
            .add_member(team.id, &pubkey.to_hex(), "member")
            .await
            .unwrap();
        assert!(team_repo
            .is_member(team.id, &pubkey.to_hex())
            .await
            .unwrap());

        team_repo
            .remove_member(team.id, &pubkey.to_hex())
            .await
            .unwrap();
        assert!(!team_repo
            .is_member(team.id, &pubkey.to_hex())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_count_other_admins() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        // Create two users
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();
        let pubkey1 = keys1.public_key();
        let pubkey2 = keys2.public_key();
        user_repo.find_or_create(1, &pubkey1).await.unwrap();
        user_repo.find_or_create(1, &pubkey2).await.unwrap();

        let team = team_repo
            .create(1, &format!("Admin Count {}", suffix))
            .await
            .unwrap();

        // Add both as admins
        team_repo
            .add_member(team.id, &pubkey1.to_hex(), "admin")
            .await
            .unwrap();
        team_repo
            .add_member(team.id, &pubkey2.to_hex(), "admin")
            .await
            .unwrap();

        // Count other admins (excluding first user)
        let count = team_repo
            .count_other_admins(team.id, &pubkey1.to_hex())
            .await
            .unwrap();
        assert_eq!(count, 1);

        // Count other admins (excluding second user)
        let count = team_repo
            .count_other_admins(team.id, &pubkey2.to_hex())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_delete_team() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let suffix = test_suffix();

        let team = team_repo
            .create(1, &format!("Delete Test {}", suffix))
            .await
            .unwrap();
        let team_id = team.id;

        // Delete it
        let result = team_repo.delete(1, team_id).await;
        assert!(result.is_ok(), "Should delete team");

        // Verify it's gone
        let find_result = team_repo.find(1, team_id).await;
        assert!(matches!(find_result, Err(RepositoryError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_find_with_relations() {
        let pool = setup_pool().await;
        let team_repo = TeamRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let suffix = test_suffix();

        let keys = Keys::generate();
        let pubkey = keys.public_key();
        user_repo.find_or_create(1, &pubkey).await.unwrap();

        let team = team_repo
            .create(1, &format!("Relations Test {}", suffix))
            .await
            .unwrap();
        team_repo
            .add_member(team.id, &pubkey.to_hex(), "admin")
            .await
            .unwrap();

        let with_relations = team_repo.find_with_relations(1, team.id).await;
        assert!(with_relations.is_ok(), "Should find with relations");

        let with_relations = with_relations.unwrap();
        assert_eq!(with_relations.team.id, team.id);
        assert_eq!(with_relations.team_users.len(), 1);
    }
}
