use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};

use keycast_core::types::team::Team;
use keycast_core::types::user::TeamUserRole;

#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub id: i32,
    pub name: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub id: i32,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AddTeammateRequest {
    pub user_pubkey: String,
    pub role: TeamUserRole,
}

#[derive(Debug, Deserialize)]
pub struct AddKeyRequest {
    pub name: String,
    pub secret_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PermissionParams {
    pub identifier: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub permissions: Vec<PermissionParams>,
}

#[derive(Debug, Deserialize)]
pub struct AddAuthorizationRequest {
    pub policy_id: i32,
    pub relays: Vec<String>,
    pub max_uses: Option<i32>,
    #[serde(default)]
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional label for admin tracking (e.g., person's name who received this authorization)
    pub label: Option<String>,
}

impl From<Team> for TeamResponse {
    fn from(team: Team) -> Self {
        Self {
            id: team.id,
            name: team.name,
            created_at: team.created_at,
            updated_at: team.updated_at,
        }
    }
}

/// Response for authorization creation - includes the bunker URL (only available at creation time)
#[derive(Debug, Serialize)]
pub struct AuthorizationCreatedResponse {
    #[serde(flatten)]
    pub authorization: keycast_core::types::authorization::Authorization,
    /// The bunker URL with connection secret - only returned at creation time, cannot be retrieved later
    pub bunker_url: String,
}
