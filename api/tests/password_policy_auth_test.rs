#![cfg(feature = "integration-tests")]

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::post,
    Json, Router,
};
use bcrypt::{hash, verify};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::{
        http::auth::{
            change_password, generate_server_signed_ucan, register, ChangePasswordRequest,
            RegisterRequest,
        },
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
use nostr_sdk::Keys;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

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

fn create_test_auth_state(pool: PgPool) -> keycast_api::api::http::routes::AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    keycast_api::api::http::routes::AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            server_keys: Keys::generate(),
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
        id: 1,
        domain: "localhost".to_string(),
        name: "Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn cleanup_by_email(pool: &PgPool, email: &str) {
    let _ = sqlx::query("DELETE FROM auth_events WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await;
}

fn ensure_server_nsec() -> Keys {
    if std::env::var("SERVER_NSEC").is_err() {
        let seed = "0".repeat(63) + "1";
        std::env::set_var("SERVER_NSEC", seed);
    }

    let nsec = std::env::var("SERVER_NSEC").expect("SERVER_NSEC should exist");
    Keys::parse(&nsec).expect("SERVER_NSEC must be valid")
}

#[tokio::test]
async fn test_register_rejects_weak_password_with_stable_code() {
    let pool = setup_pool().await;
    let auth_state = create_test_auth_state(pool.clone());
    let email = format!("register-weak-{}@example.com", Uuid::new_v4());

    cleanup_by_email(&pool, &email).await;

    let app = {
        let auth_state = auth_state.clone();
        Router::new().route(
            "/auth/register",
            post(
                move |headers: HeaderMap, Json(req): Json<RegisterRequest>| {
                    let auth_state = auth_state.clone();
                    async move {
                        register(create_test_tenant(), State(auth_state), headers, Json(req)).await
                    }
                },
            ),
        )
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "password123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let payload: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .expect("response should be json");
    assert_eq!(payload["code"], "WEAK_PASSWORD");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("query should succeed");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_change_password_rejects_weak_password_with_stable_code() {
    let pool = setup_pool().await;
    let email = format!("change-password-weak-{}@example.com", Uuid::new_v4());
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let old_password = "old-password-123!";
    let old_password_hash = hash(old_password, 4).unwrap();

    cleanup_by_email(&pool, &email).await;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, 1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&user_pubkey)
    .bind(&email)
    .bind(&old_password_hash)
    .execute(&pool)
    .await
    .expect("Should create user");

    let server_keys = ensure_server_nsec();
    let token = generate_server_signed_ucan(
        &user_keys.public_key(),
        1,
        &email,
        "https://app.divine.video",
        None,
        &server_keys,
        true,
        None,
    )
    .await
    .expect("should generate token");

    let app = {
        let pool = pool.clone();
        Router::new().route(
            "/user/change-password",
            post(
                move |headers: HeaderMap, Json(req): Json<ChangePasswordRequest>| {
                    let pool = pool.clone();
                    async move {
                        change_password(create_test_tenant(), State(pool), headers, Json(req)).await
                    }
                },
            ),
        )
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/user/change-password")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::json!({
                        "current_password": old_password,
                        "new_password": "password123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let payload: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .expect("response should be json");
    assert_eq!(payload["code"], "WEAK_PASSWORD");

    let latest_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE email = $1 AND tenant_id = 1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("stored hash should exist");
    assert!(verify(old_password, &latest_hash).unwrap());

    cleanup_by_email(&pool, &email).await;
}
