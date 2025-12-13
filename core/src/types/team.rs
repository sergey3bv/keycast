use crate::encryption::KeyManagerError;
use crate::types::authorization::{AuthorizationError, AuthorizationWithRelations};
use crate::types::permission::{Permission, PermissionError};
use crate::types::policy::{Policy, PolicyError, PolicyWithPermissions};
use crate::types::stored_key::{PublicStoredKey, StoredKey};
use crate::types::user::{TeamUser, UserError};
use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::PgPool;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TeamError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("User is not authorized to perform this action")]
    NotAuthorized,

    #[error("User is not an admin of the team")]
    NotAdmin(#[from] UserError),

    #[error("User is already a member of the team")]
    UserAlreadyMember,

    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),

    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),

    #[error("Permission error: {0}")]
    Permission(#[from] PermissionError),

    #[error("Serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Authorization error: {0}")]
    Authorization(#[from] AuthorizationError),
}

/// A team is a collection of users, stored keys, policies, and permissions
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Team {
    /// The id of the team
    pub id: i32,
    /// The name of the team
    pub name: String,
    /// The date and time the team was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the team was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamWithRelations {
    pub team: Team,
    pub team_users: Vec<TeamUser>, // Use team_user here so we get the role
    pub stored_keys: Vec<PublicStoredKey>,
    pub policies: Vec<PolicyWithPermissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyWithRelations {
    pub team: Team,
    pub stored_key: PublicStoredKey,
    pub authorizations: Vec<AuthorizationWithRelations>,
}

impl Team {
    pub async fn find_with_relations(
        pool: &PgPool,
        tenant_id: i64,
        team_id: i32,
    ) -> Result<TeamWithRelations, TeamError> {
        // Get team
        let team = sqlx::query_as::<_, Team>(
            "SELECT id, name, created_at, updated_at FROM teams WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(team_id)
        .fetch_one(pool)
        .await?;

        // Get team_users for this team
        let team_users = sqlx::query_as::<_, TeamUser>(
            "SELECT user_pubkey, team_id, role, created_at, updated_at
             FROM team_users WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_all(pool)
        .await?;

        // Get stored keys for this team
        let stored_keys = sqlx::query_as::<_, StoredKey>(
            "SELECT id, team_id, name, pubkey, secret_key, created_at, updated_at
             FROM stored_keys WHERE tenant_id = $1 AND team_id = $2",
        )
        .bind(tenant_id)
        .bind(team_id)
        .fetch_all(pool)
        .await?;

        let public_stored_keys: Vec<PublicStoredKey> =
            stored_keys.into_iter().map(|k| k.into()).collect();

        // Get policies for this team
        let policies = Team::get_policies_with_permissions(pool, tenant_id, team_id).await?;

        Ok(TeamWithRelations {
            team,
            team_users,
            stored_keys: public_stored_keys,
            policies,
        })
    }

    pub async fn get_policies_with_permissions(
        pool: &PgPool,
        _tenant_id: i64,
        team_id: i32,
    ) -> Result<Vec<PolicyWithPermissions>, TeamError> {
        Self::get_policies_with_permissions_batch(pool, &[team_id]).await
    }

    /// Batch fetch policies with permissions for multiple teams (avoids N+1)
    pub async fn get_policies_with_permissions_batch(
        pool: &PgPool,
        team_ids: &[i32],
    ) -> Result<Vec<PolicyWithPermissions>, TeamError> {
        if team_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Fetch all policies for all teams in one query
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT id, name, team_id, created_at, updated_at, slug, display_name, description
             FROM policies WHERE team_id = ANY($1)",
        )
        .bind(team_ids)
        .fetch_all(pool)
        .await?;

        if policies.is_empty() {
            return Ok(Vec::new());
        }

        // Collect policy IDs for batch permission fetch
        let policy_ids: Vec<i32> = policies.iter().map(|p| p.id).collect();

        // Fetch all permissions for all policies in one query with policy_id for grouping
        let permission_rows = sqlx::query_as::<_, PermissionWithPolicyId>(
            "SELECT pp.policy_id,
                    p.id, p.identifier, p.config, p.created_at, p.updated_at
             FROM permissions p
             JOIN policy_permissions pp ON pp.permission_id = p.id
             WHERE pp.policy_id = ANY($1)",
        )
        .bind(&policy_ids)
        .fetch_all(pool)
        .await?;

        // Group permissions by policy_id
        let mut policies_with_permissions = Vec::with_capacity(policies.len());
        for policy in policies {
            let permissions: Vec<Permission> = permission_rows
                .iter()
                .filter(|row| row.policy_id == policy.id)
                .map(|row| Permission {
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
}

/// Helper struct for batch permission loading with policy_id
#[derive(Debug, FromRow)]
struct PermissionWithPolicyId {
    policy_id: i32,
    id: i32,
    identifier: String,
    #[sqlx(try_from = "String")]
    config: crate::types::permission::JsonConfig,
    created_at: DateTime<chrono::Utc>,
    updated_at: DateTime<chrono::Utc>,
}
