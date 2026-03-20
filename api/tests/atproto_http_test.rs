mod common;

use keycast_api::api::http::atproto::{
    disable_user_atproto, disable_user_atproto_with_trigger, enable_user_atproto,
    enable_user_atproto_with_trigger, get_user_atproto_status, sync_user_atproto_state_by_pubkey,
};
use keycast_core::repositories::UserRepository;
use nostr_sdk::Keys;
use reqwest::StatusCode;

#[tokio::test]
async fn enable_sets_pending_and_returns_accepted() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-enable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = enable_user_atproto(&repo, tenant_id, &user_pubkey, &username)
        .await
        .expect("enable should succeed");

    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("pending"));
}

#[tokio::test]
async fn disable_marks_disabled() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:testalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = disable_user_atproto(&repo, tenant_id, &user_pubkey)
        .await
        .expect("disable should succeed");

    assert!(!response.enabled);
    assert_eq!(response.state.as_deref(), Some("disabled"));
    assert_eq!(response.did, None);
}

#[tokio::test]
async fn status_returns_username_and_lifecycle_fields() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-status-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, atproto_error, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'failed', NULL, 'provisioning failed', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");

    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("failed"));
    assert_eq!(response.error.as_deref(), Some("provisioning failed"));
}

#[tokio::test]
async fn enable_trigger_failure_marks_failed_state() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-enable-failed-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error = enable_user_atproto_with_trigger(
        &repo,
        tenant_id,
        &user_pubkey,
        &username,
        |_pubkey, _username| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::UnexpectedStatus {
                    status: StatusCode::BAD_GATEWAY,
                    body: "gateway unavailable".to_string(),
                },
            )
        },
    )
    .await
    .expect_err("enable should surface trigger failure");

    assert!(error.to_string().contains("gateway unavailable"));

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("failed"));
    assert_eq!(
        response.error.as_deref(),
        Some("provisioning service returned 502 Bad Gateway: gateway unavailable"),
    );
}

#[tokio::test]
async fn disable_trigger_failure_preserves_existing_state() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-disable-failed-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, atproto_did, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'ready', 'did:plc:testalice', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let error =
        disable_user_atproto_with_trigger(&repo, tenant_id, &user_pubkey, |_pubkey| async {
            Err(
                keycast_api::atproto_provisioning::AtprotoProvisioningError::UnexpectedStatus {
                    status: StatusCode::BAD_GATEWAY,
                    body: "disable failed".to_string(),
                },
            )
        })
        .await
        .expect_err("disable should surface trigger failure");

    assert!(error.to_string().contains("disable failed"));

    let response = get_user_atproto_status(&repo, tenant_id, &user_pubkey)
        .await
        .expect("status should succeed");
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("ready"));
    assert_eq!(response.did.as_deref(), Some("did:plc:testalice"));
}

#[tokio::test]
async fn internal_sync_updates_lifecycle_state_by_pubkey() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());
    let tenant_id = 1_i64;

    let keys = Keys::generate();
    let user_pubkey = keys.public_key().to_hex();
    let username = format!("alice-sync-{}", &user_pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, username, atproto_enabled, atproto_state, created_at, updated_at)
         VALUES ($1, $2, $3, true, 'pending', NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .bind(&username)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    let response = sync_user_atproto_state_by_pubkey(
        &repo,
        &user_pubkey,
        true,
        Some("ready"),
        Some("did:plc:testalice"),
        None,
    )
    .await
    .expect("sync should succeed");

    assert_eq!(response.username.as_deref(), Some(username.as_str()));
    assert!(response.enabled);
    assert_eq!(response.state.as_deref(), Some("ready"));
    assert_eq!(response.did.as_deref(), Some("did:plc:testalice"));
    assert_eq!(response.error, None);
}
