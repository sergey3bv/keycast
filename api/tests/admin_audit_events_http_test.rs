// ABOUTME: HTTP-layer auth tests for GET /admin/audit-events
// ABOUTME: Support and full admins allowed; non-admin forbidden

#![cfg(feature = "integration-tests")]

mod common;

use axum::{
    body::Body,
    extract::{Query, State},
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::{
    api::{
        extractors::UcanAuth,
        http::{
            admin::{list_admin_audit_events, ListAdminAuditEventsQuery},
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
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

#[derive(Clone)]
struct AuthConfig {
    pubkey: String,
    admin_role: Option<String>,
}

impl AuthConfig {
    fn full_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("full".to_string()),
        }
    }

    fn support_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: Some("support".to_string()),
        }
    }

    fn non_admin() -> Self {
        Self {
            pubkey: Keys::generate().public_key().to_hex(),
            admin_role: None,
        }
    }

    fn into_auth(self) -> UcanAuth {
        UcanAuth {
            pubkey: self.pubkey,
            admin_role: self.admin_role,
        }
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

fn build_app(auth_state: AuthState, config: AuthConfig) -> Router {
    Router::new().route(
        "/admin/audit-events",
        get(move |Query(query): Query<ListAdminAuditEventsQuery>| {
            let state = auth_state.clone();
            let cfg = config.clone();
            async move {
                list_admin_audit_events(
                    create_test_tenant(),
                    State(state),
                    cfg.into_auth(),
                    Query(query),
                )
                .await
            }
        }),
    )
}

fn request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

async fn read_body_string(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn list_audit_events_allows_full_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::full_admin());

    let response = app
        .oneshot(request("GET", "/admin/audit-events"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body_string(response).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert!(v.get("events").is_some());
}

#[tokio::test]
async fn list_audit_events_allows_support_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::support_admin());

    let response = app
        .oneshot(request("GET", "/admin/audit-events"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_audit_events_rejects_non_admin() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::non_admin());

    let response = app
        .oneshot(request("GET", "/admin/audit-events"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        read_body_string(response)
            .await
            .contains("Admin access required"),
        "non-admin should get the support-admin gate message"
    );
}

#[tokio::test]
async fn list_audit_events_rejects_bad_occurred_after() {
    let pool = common::setup_test_db().await;
    let app = build_app(create_test_auth_state(pool), AuthConfig::full_admin());

    let response = app
        .oneshot(request(
            "GET",
            "/admin/audit-events?occurred_after=not-a-date",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
