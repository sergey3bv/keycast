#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    routing::get,
    Router,
};
use bcrypt::hash;
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::{
        http::{auth::generate_server_signed_ucan, oauth::connect_get, routes::AuthState},
        tenant::{Tenant, TenantExtractor},
    },
    bcrypt_queue::BcryptQueue,
    handlers::http_rpc_handler::new_http_handler_cache,
    state::KeycastState,
};
use keycast_core::{
    encryption::{KeyManager, KeyManagerError},
    secret_pool::SecretPool,
};
use moka::future::Cache;
use nostr_sdk::{Keys, ToBech32};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

async fn cleanup_user(pool: &PgPool, pubkey: &str) {
    let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .execute(pool)
        .await;
}

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

fn create_test_auth_state(pool: PgPool) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));
    let server_keys = Keys::generate();
    std::env::set_var(
        "SERVER_NSEC",
        server_keys
            .secret_key()
            .to_bech32()
            .expect("server nsec bech32"),
    );

    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys,
            tenant_cache,
            bcrypt_sender: bcrypt_queue.sender(),
            redis: None,
            secret_pool: secret_pool.receiver(),
        }),
        auth_tx: None,
    }
}

fn create_test_tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn encoded_connect_uri(client_pk: &str) -> String {
    let inner = format!(
        "nostrconnect://{}?relay=wss://relay.example.com/ws&secret=testsecret",
        client_pk
    );
    format!("/connect/{}", urlencoding::encode(&inner))
}

fn build_app(auth_state: AuthState) -> Router {
    Router::new()
        .route(
            "/connect/*nostrconnect",
            get(
                |State(state): State<AuthState>, headers: HeaderMap, path: Path<String>| async move {
                    connect_get(create_test_tenant(), State(state), headers, path).await
                },
            ),
        )
        .with_state(auth_state)
}

#[tokio::test]
#[serial]
async fn connect_get_without_cookie_has_no_session_marker() {
    let pool = setup_pool().await;
    let client_keys = Keys::generate();
    let client_pk = client_keys.public_key().to_hex();
    let auth_state = create_test_auth_state(pool);
    let app = build_app(auth_state);

    let uri = encoded_connect_uri(&client_pk);
    let res = app
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(!body.contains(r#"data-keycast-session="signed-in""#));
    assert!(!body.contains("Signed in as"));
}

#[tokio::test]
#[serial]
async fn connect_get_with_valid_session_shows_signed_in() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let email = format!("connect-session-{}@example.com", Uuid::new_v4());

    cleanup_user(&pool, &user_pubkey).await;

    let password_hash = hash("pw", 4).expect("bcrypt");
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, $4, true, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(TENANT_ID)
    .bind(&email)
    .bind(&password_hash)
    .execute(&pool)
    .await
    .expect("insert user");

    let auth_state = create_test_auth_state(pool.clone());
    let server_keys = auth_state.state.server_keys.clone();
    let session_token = generate_server_signed_ucan(
        &user_keys.public_key(),
        TENANT_ID,
        &email,
        "https://localhost",
        None,
        &server_keys,
        true,
        None,
    )
    .await
    .expect("ucan");

    let client_keys = Keys::generate();
    let client_pk = client_keys.public_key().to_hex();
    let app = build_app(auth_state);
    let uri = encoded_connect_uri(&client_pk);

    let res = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(body.contains(r#"data-keycast-session="signed-in""#));
    assert!(body.contains("Signed in as"));
    assert!(body.contains(&email));

    cleanup_user(&pool, &user_pubkey).await;
}

#[tokio::test]
#[serial]
async fn connect_get_stale_ucan_clears_cookie() {
    let pool = setup_pool().await;
    let ghost_keys = Keys::generate();
    let ghost_pubkey = ghost_keys.public_key().to_hex();
    cleanup_user(&pool, &ghost_pubkey).await;

    let auth_state = create_test_auth_state(pool.clone());
    let server_keys = auth_state.state.server_keys.clone();
    let session_token = generate_server_signed_ucan(
        &ghost_keys.public_key(),
        TENANT_ID,
        "ghost@example.com",
        "https://localhost",
        None,
        &server_keys,
        true,
        None,
    )
    .await
    .expect("ucan");

    let client_keys = Keys::generate();
    let client_pk = client_keys.public_key().to_hex();
    let app = build_app(auth_state);
    let uri = encoded_connect_uri(&client_pk);

    let res = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(header::COOKIE, format!("keycast_session={session_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let clear = res.headers().get_all(header::SET_COOKIE).iter().any(|v| {
        v.to_str()
            .ok()
            .is_some_and(|s| s.starts_with("keycast_session=") && s.contains("Max-Age=0"))
    });
    assert!(clear, "expected Set-Cookie clearing session");

    let body =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(!body.contains(r#"data-keycast-session="signed-in""#));
}
