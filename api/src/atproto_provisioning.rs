use reqwest::Client;
use serde::Serialize;

const DEFAULT_ATPROTO_CONTROL_PLANE_URL: &str = "http://127.0.0.1:3201";
const DEFAULT_HANDLE_DOMAIN: &str = "divine.video";
const CONTROL_PLANE_URL_ENV: &str = "DIVINE_SKY_ATPROTO_CONTROL_PLANE_URL";
const NODE_ENV_VAR: &str = "NODE_ENV";
const PRODUCTION_ENV: &str = "production";

#[derive(Debug, thiserror::Error)]
pub enum AtprotoProvisioningError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("provisioning service returned {status}: {body}")]
    UnexpectedStatus {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("invalid ATProto provisioning configuration: {0}")]
    Configuration(String),
}

#[derive(Debug, Serialize)]
struct EnableProvisioningRequest {
    nostr_pubkey: String,
    handle: String,
    crosspost_enabled: bool,
}

fn is_production_environment() -> bool {
    std::env::var(NODE_ENV_VAR)
        .map(|value| value.eq_ignore_ascii_case(PRODUCTION_ENV))
        .unwrap_or(false)
}

fn validate_control_plane_base_url(url: &str) -> Result<(), AtprotoProvisioningError> {
    reqwest::Url::parse(url).map_err(|error| {
        AtprotoProvisioningError::Configuration(format!(
            "{CONTROL_PLANE_URL_ENV} must be a valid URL: {error}"
        ))
    })?;
    Ok(())
}

fn control_plane_base_url() -> Result<String, AtprotoProvisioningError> {
    if let Ok(base_url) = std::env::var(CONTROL_PLANE_URL_ENV) {
        let trimmed = base_url.trim();
        if trimmed.is_empty() {
            return Err(AtprotoProvisioningError::Configuration(format!(
                "{CONTROL_PLANE_URL_ENV} is set but empty"
            )));
        }

        validate_control_plane_base_url(trimmed)?;
        return Ok(trimmed.to_string());
    }

    if is_production_environment() {
        return Err(AtprotoProvisioningError::Configuration(format!(
            "{CONTROL_PLANE_URL_ENV} must be configured in production"
        )));
    }

    Ok(DEFAULT_ATPROTO_CONTROL_PLANE_URL.to_string())
}

fn handle_domain() -> String {
    std::env::var("DIVINE_HANDLE_DOMAIN").unwrap_or_else(|_| DEFAULT_HANDLE_DOMAIN.to_string())
}

fn maybe_apply_service_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Ok(token) = std::env::var("KEYCAST_ATPROTO_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return request.bearer_auth(trimmed.to_string());
        }
    }
    request
}

pub async fn request_enable(
    nostr_pubkey: &str,
    username: &str,
    crosspost_enabled: bool,
) -> Result<(), AtprotoProvisioningError> {
    let base = control_plane_base_url()?;
    let domain = handle_domain();
    let url = format!("{}/api/account-links/opt-in", base.trim_end_matches('/'));
    let handle = format!("{}.{}", username.trim().to_ascii_lowercase(), domain);

    let body = EnableProvisioningRequest {
        nostr_pubkey: nostr_pubkey.to_string(),
        handle,
        crosspost_enabled,
    };

    let client = Client::new();
    let response = maybe_apply_service_auth(client.post(url).json(&body))
        .send()
        .await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AtprotoProvisioningError::UnexpectedStatus { status, body })
}

pub async fn request_reenable(nostr_pubkey: &str) -> Result<(), AtprotoProvisioningError> {
    let base = control_plane_base_url()?;
    let encoded_pubkey = urlencoding::encode(nostr_pubkey);
    let url = format!(
        "{}/api/account-links/{}/enable",
        base.trim_end_matches('/'),
        encoded_pubkey
    );

    let client = Client::new();
    let response = maybe_apply_service_auth(client.post(url)).send().await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AtprotoProvisioningError::UnexpectedStatus { status, body })
}

pub async fn request_disable(nostr_pubkey: &str) -> Result<(), AtprotoProvisioningError> {
    let base = control_plane_base_url()?;
    let encoded_pubkey = urlencoding::encode(nostr_pubkey);
    let url = format!(
        "{}/api/account-links/{}/disable",
        base.trim_end_matches('/'),
        encoded_pubkey
    );

    let client = Client::new();
    let response = maybe_apply_service_auth(client.post(url)).send().await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AtprotoProvisioningError::UnexpectedStatus { status, body })
}
