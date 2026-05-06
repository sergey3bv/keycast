#![cfg(feature = "integration-tests")]

// ABOUTME: HTTP-handler tests verifying preload_user, claim tokens, and user-token
// ABOUTME: admin actions write durable rows to admin_audit_events.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::{
            admin::{
                batch_create_claim_tokens, create_claim_token, get_user_token,
                invalidate_claim_token, preload_user, BatchCreateClaimTokensRequest,
                CreateClaimTokenRequest, InvalidateClaimTokenRequest, PreloadUserRequest,
                UserTokenRequest,
            },
            routes::AuthState,
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
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

mod common;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");
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

fn ensure_server_nsec() {
    if std::env::var("SERVER_NSEC").is_err() {
        let fake = format!("{:0>64}", "1");
        std::env::set_var("SERVER_NSEC", fake);
    }
}

fn make_auth_state(pool: PgPool) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(TestKeyManager));

    AuthState {
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

fn make_tenant(id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id,
        domain: "localhost".to_string(),
        name: "Admin Actions Audit Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn make_admin_auth(pubkey: &str) -> UcanAuth {
    UcanAuth {
        pubkey: pubkey.to_string(),
        admin_role: Some("full".to_string()),
    }
}

async fn ensure_tenant(pool: &PgPool, tenant_id: i64) {
    let _ = sqlx::query(
        "INSERT INTO tenants (id, name, domain, created_at, updated_at)
         VALUES ($1, 'Admin Actions Audit', 'audit-admin-actions.example.com', NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .execute(pool)
    .await;
}

async fn cleanup(pool: &PgPool, tenant_id: i64, vine_id: &str, actor_pubkey: &str) {
    let pubkey: Option<(String,)> =
        sqlx::query_as("SELECT pubkey FROM users WHERE vine_id = $1 AND tenant_id = $2")
            .bind(vine_id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);

    if let Some((pk,)) = pubkey {
        let _ = sqlx::query("DELETE FROM account_claim_tokens WHERE user_pubkey = $1")
            .bind(&pk)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM personal_keys WHERE user_pubkey = $1")
            .bind(&pk)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE pubkey = $1")
            .bind(&pk)
            .execute(pool)
            .await;
    }

    let _ =
        sqlx::query("DELETE FROM admin_audit_events WHERE tenant_id = $1 AND actor_pubkey = $2")
            .bind(tenant_id)
            .bind(actor_pubkey)
            .execute(pool)
            .await;
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    action: String,
}

async fn read_audit_actions(pool: &PgPool, tenant_id: i64, actor_pubkey: &str) -> Vec<String> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT action FROM admin_audit_events
         WHERE tenant_id = $1 AND actor_pubkey = $2
         ORDER BY occurred_at ASC, id ASC",
    )
    .bind(tenant_id)
    .bind(actor_pubkey)
    .fetch_all(pool)
    .await
    .expect("audit rows fetch")
    .into_iter()
    .map(|r| r.action)
    .collect()
}

#[tokio::test]
async fn preload_claim_token_and_user_token_write_admin_audit_events() {
    ensure_server_nsec();
    let pool = setup_pool().await;

    let tenant_id: i64 = 9_400_000 + (Uuid::new_v4().as_u128() as i64).rem_euclid(1_000_000);
    ensure_tenant(&pool, tenant_id).await;

    let actor_pubkey = format!("{:0>64}", Uuid::new_v4().simple());
    let vine_id = format!("vine_audit_{}", &Uuid::new_v4().to_string()[..12]);
    let username = format!("u_{}", Uuid::new_v4().simple());

    cleanup(&pool, tenant_id, &vine_id, &actor_pubkey).await;

    let state = make_auth_state(pool.clone());

    let first = preload_user(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Json(PreloadUserRequest {
            vine_id: vine_id.clone(),
            username: username.clone(),
            display_name: Some("Audit Display".to_string()),
        }),
    )
    .await
    .expect("preload_user")
    .0;

    let _ = create_claim_token(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Json(CreateClaimTokenRequest {
            vine_id: vine_id.clone(),
        }),
    )
    .await
    .expect("create_claim_token");

    let _ = get_user_token(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Json(UserTokenRequest {
            pubkey: first.pubkey.clone(),
        }),
    )
    .await
    .expect("get_user_token");

    let _ = invalidate_claim_token(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Json(InvalidateClaimTokenRequest {
            vine_id: vine_id.clone(),
            reason: Some("audit test".to_string()),
        }),
    )
    .await
    .expect("invalidate_claim_token");

    let _ = batch_create_claim_tokens(
        make_tenant(tenant_id),
        State(state.clone()),
        make_admin_auth(&actor_pubkey),
        Json(BatchCreateClaimTokensRequest {
            vine_ids: vec![vine_id.clone()],
            delivery_email: None,
        }),
    )
    .await
    .expect("batch_create_claim_tokens");

    let _ = preload_user(
        make_tenant(tenant_id),
        State(state),
        make_admin_auth(&actor_pubkey),
        Json(PreloadUserRequest {
            vine_id: vine_id.clone(),
            username: username.clone(),
            display_name: None,
        }),
    )
    .await
    .expect("preload_user idempotent");

    let actions = read_audit_actions(&pool, tenant_id, &actor_pubkey).await;
    assert_eq!(
        actions,
        vec![
            "preload_user.create",
            "claim_token.create",
            "preload_user.user_token",
            "claim_token.invalidate",
            "claim_token.create",
            "preload_user.token_issued",
        ]
    );

    cleanup(&pool, tenant_id, &vine_id, &actor_pubkey).await;
}
