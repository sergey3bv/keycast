use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use keycast_core::repositories::{RepositoryError, UserRepository};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::future::Future;

use super::auth::{extract_user_from_token, AuthError};

#[derive(Debug, Deserialize)]
pub struct EnableAtprotoRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct InternalAtprotoSyncRequest {
    pub nostr_pubkey: String,
    pub enabled: bool,
    pub state: Option<String>,
    pub did: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AtprotoStatusResponse {
    pub enabled: bool,
    pub state: Option<String>,
    pub did: Option<String>,
    pub error: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AtprotoControlError {
    #[error("user not found")]
    UserNotFound,
    #[error("username must be claimed before enabling atproto")]
    UsernameNotClaimed,
    #[error("requested username does not match claimed username")]
    UsernameMismatch,
    #[error("provisioning trigger failed: {0}")]
    ProvisioningTrigger(String),
    #[error("repository error: {0}")]
    Repository(#[from] RepositoryError),
}

fn map_state_to_response(
    username: Option<String>,
    state: keycast_core::types::user::UserAtprotoState,
) -> AtprotoStatusResponse {
    AtprotoStatusResponse {
        enabled: state.enabled,
        state: state.state,
        did: state.did,
        error: state.error,
        username,
    }
}

fn validate_atproto_state(state: Option<&str>) -> Result<(), AuthError> {
    match state {
        Some("pending" | "ready" | "failed" | "disabled") | None => Ok(()),
        Some(_) => Err(AuthError::BadRequest(
            "ATProto state must be one of pending, ready, failed, disabled, or null".to_string(),
        )),
    }
}

fn authorize_internal_sync(headers: &HeaderMap) -> Result<(), AuthError> {
    let expected = std::env::var("KEYCAST_ATPROTO_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            AuthError::Internal("KEYCAST_ATPROTO_TOKEN must be configured".to_string())
        })?;

    let actual = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    if actual != format!("Bearer {expected}") {
        return Err(AuthError::InvalidToken);
    }

    Ok(())
}

pub async fn enable_user_atproto(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    requested_username: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let claimed_username = repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?
        .ok_or(AtprotoControlError::UsernameNotClaimed)?;

    if claimed_username != requested_username {
        return Err(AtprotoControlError::UsernameMismatch);
    }

    repo.set_atproto_state(user_pubkey, tenant_id, true, Some("pending"), None, None)
        .await?;

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(Some(claimed_username), state))
}

pub async fn enable_user_atproto_with_trigger<F, Fut>(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    requested_username: &str,
    trigger: F,
) -> Result<AtprotoStatusResponse, AtprotoControlError>
where
    F: FnOnce(String, String) -> Fut,
    Fut: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
{
    let response = enable_user_atproto(repo, tenant_id, user_pubkey, requested_username).await?;
    let username = response
        .username
        .clone()
        .ok_or(AtprotoControlError::UsernameNotClaimed)?;

    if let Err(error) = trigger(user_pubkey.to_string(), username.clone()).await {
        let error_message = error.to_string();
        repo.set_atproto_state(
            user_pubkey,
            tenant_id,
            true,
            Some("failed"),
            None,
            Some(&error_message),
        )
        .await?;
        return Err(AtprotoControlError::ProvisioningTrigger(error_message));
    }

    Ok(response)
}

pub async fn get_user_atproto_status(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let username = repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(username, state))
}

pub async fn sync_user_atproto_state_by_pubkey(
    repo: &UserRepository,
    user_pubkey: &str,
    enabled: bool,
    state: Option<&str>,
    did: Option<&str>,
    error: Option<&str>,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    repo.set_atproto_state_by_pubkey(user_pubkey, enabled, state, did, error)
        .await?;

    let username = repo
        .get_username_by_pubkey(user_pubkey)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;
    let state = repo
        .get_atproto_state_by_pubkey(user_pubkey)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(username, state))
}

pub async fn disable_user_atproto(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
) -> Result<AtprotoStatusResponse, AtprotoControlError> {
    let username = repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    repo.set_atproto_state(user_pubkey, tenant_id, false, Some("disabled"), None, None)
        .await?;

    let state = repo
        .get_atproto_state(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    Ok(map_state_to_response(username, state))
}

pub async fn disable_user_atproto_with_trigger<F, Fut>(
    repo: &UserRepository,
    tenant_id: i64,
    user_pubkey: &str,
    trigger: F,
) -> Result<AtprotoStatusResponse, AtprotoControlError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<(), crate::atproto_provisioning::AtprotoProvisioningError>>,
{
    let _username = repo
        .get_username(user_pubkey, tenant_id)
        .await?
        .ok_or(AtprotoControlError::UserNotFound)?;

    trigger(user_pubkey.to_string())
        .await
        .map_err(|error| AtprotoControlError::ProvisioningTrigger(error.to_string()))?;

    disable_user_atproto(repo, tenant_id, user_pubkey).await
}

fn map_control_error(error: AtprotoControlError) -> AuthError {
    match error {
        AtprotoControlError::UserNotFound => AuthError::UserNotFound,
        AtprotoControlError::UsernameNotClaimed => {
            AuthError::BadRequest("Username must be claimed before enabling ATProto".to_string())
        }
        AtprotoControlError::UsernameMismatch => AuthError::BadRequest(
            "Requested username does not match the claimed username".to_string(),
        ),
        AtprotoControlError::ProvisioningTrigger(err) => AuthError::Internal(err),
        AtprotoControlError::Repository(err) => AuthError::Internal(err.to_string()),
    }
}

pub async fn enable_atproto(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(request): Json<EnableAtprotoRequest>,
) -> Result<(StatusCode, Json<AtprotoStatusResponse>), AuthError> {
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
    let repo = UserRepository::new(pool);

    let response = enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &request.username,
        |pubkey, username| async move {
            crate::atproto_provisioning::request_enable(&pubkey, &username).await
        },
    )
    .await
    .map_err(map_control_error)?;

    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub async fn atproto_status(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
    let repo = UserRepository::new(pool);

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .map_err(map_control_error)?;

    Ok(Json(response))
}

pub async fn internal_sync_atproto(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(request): Json<InternalAtprotoSyncRequest>,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    authorize_internal_sync(&headers)?;
    validate_atproto_state(request.state.as_deref())?;

    let repo = UserRepository::new(pool);
    let response = sync_user_atproto_state_by_pubkey(
        &repo,
        &request.nostr_pubkey,
        request.enabled,
        request.state.as_deref(),
        request.did.as_deref(),
        request.error.as_deref(),
    )
    .await
    .map_err(map_control_error)?;

    Ok(Json(response))
}

pub async fn disable_atproto(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<AtprotoStatusResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers).await?;
    let tenant_id = tenant.0.id;
    let repo = UserRepository::new(pool);

    let response =
        disable_user_atproto_with_trigger(&repo, tenant_id, &user_pubkey, |pubkey| async move {
            crate::atproto_provisioning::request_disable(&pubkey).await
        })
        .await
        .map_err(map_control_error)?;

    Ok(Json(response))
}
