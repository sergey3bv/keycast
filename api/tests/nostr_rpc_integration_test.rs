#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for nostr_rpc signing endpoint
// ABOUTME: Tests the full sign_event code path including handler loading

mod common;

use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use keycast_api::api::{
    http::{
        auth::AuthError,
        nostr_rpc::{nostr_rpc, NostrRpcRequest, NostrRpcResponse, RpcError},
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::{new_http_handler_cache, HttpRpcHandler};
use keycast_api::state::KeycastState;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::secret_pool::SecretPool;
use keycast_core::signing_session::{parse_cache_key, SigningSession};
use moka::future::Cache;
use nostr_sdk::prelude::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

// ============================================================================
// Test Helpers
// ============================================================================

async fn setup_db() -> PgPool {
    common::assert_test_database_url();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    // Clean up test data from previous runs (preserve tenant ID 1 which is seeded)
    sqlx::query("DELETE FROM oauth_authorizations WHERE tenant_id > 1")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM personal_keys WHERE tenant_id > 1")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE tenant_id > 1")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id > 1")
        .execute(&pool)
        .await
        .ok();

    // Reset tenant sequence to ensure no conflicts
    sqlx::query(
        "SELECT setval('tenants_id_seq', (SELECT COALESCE(MAX(id), 1) FROM tenants), true)",
    )
    .execute(&pool)
    .await
    .ok();

    pool
}

async fn create_test_tenant(pool: &PgPool) -> i64 {
    let domain = format!("test-rpc-{}.example.com", Uuid::new_v4());
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = NOW()
         RETURNING id",
    )
    .bind(&domain)
    .bind("Test Tenant")
    .fetch_one(pool)
    .await
    .expect("Failed to create test tenant")
}

fn create_test_tenant_extractor(tenant_id: i64) -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: tenant_id,
        domain: "login.divine.video".to_string(),
        name: "Integration Test Tenant".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn create_test_auth_state(pool: PgPool, key_manager: Arc<Box<dyn KeyManager>>) -> AuthState {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let tenant_cache = Cache::builder().max_capacity(10).build();

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
            email_sender: Arc::new(keycast_api::email_service::DevEmailSender::new()),
        }),
        auth_tx: None,
    }
}

fn create_test_user() -> (Keys, String) {
    let keys = Keys::generate();
    let pubkey_hex = keys.public_key().to_hex();
    (keys, pubkey_hex)
}

async fn insert_user(pool: &PgPool, tenant_id: i64, pubkey: &str) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(pubkey)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to insert user");
}

async fn create_personal_key(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    user_keys: &Keys,
    key_manager: &dyn KeyManager,
) {
    let user_secret = user_keys.secret_key().secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(&user_secret)
        .await
        .expect("Failed to encrypt user secret");

    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(user_pubkey)
    .bind(&encrypted_secret)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("Failed to create personal key");
}

/// Create oauth_authorization and return (auth_id, bunker_public_key)
#[allow(clippy::too_many_arguments)]
async fn create_test_oauth_authorization(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    policy_id: Option<i32>,
    expires_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
) -> (i32, String) {
    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key().to_hex();
    let auth_handle = hex::encode(rand::random::<[u8; 32]>());

    let auth_id: i32 = sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, policy_id, tenant_id, expires_at, revoked_at, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'test_hash', $4, $5, $6, $7, $8, $9, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id"
    )
    .bind(user_pubkey)
    .bind(redirect_origin)
    .bind(&bunker_pubkey)
    .bind(json!(["wss://relay.example.com"]).to_string())
    .bind(policy_id)
    .bind(tenant_id)
    .bind(expires_at)
    .bind(revoked_at)
    .bind(&auth_handle)
    .fetch_one(pool)
    .await
    .expect("Failed to create oauth authorization");

    (auth_id, bunker_pubkey)
}

#[allow(clippy::too_many_arguments)]
async fn create_test_oauth_authorization_with_bunker(
    pool: &PgPool,
    tenant_id: i64,
    user_pubkey: &str,
    redirect_origin: &str,
    bunker_pubkey: &str,
    policy_id: Option<i32>,
    expires_at: Option<chrono::DateTime<Utc>>,
    revoked_at: Option<chrono::DateTime<Utc>>,
) -> i32 {
    let auth_handle = hex::encode(rand::random::<[u8; 32]>());

    sqlx::query_scalar(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, policy_id, tenant_id, expires_at, revoked_at, authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'test_hash', $4, $5, $6, $7, $8, $9, NOW() + INTERVAL '30 days', NOW(), NOW())
         RETURNING id",
    )
    .bind(user_pubkey)
    .bind(redirect_origin)
    .bind(bunker_pubkey)
    .bind(json!(["wss://relay.example.com"]).to_string())
    .bind(policy_id)
    .bind(tenant_id)
    .bind(expires_at)
    .bind(revoked_at)
    .bind(&auth_handle)
    .fetch_one(pool)
    .await
    .expect("Failed to create oauth authorization with custom bunker pubkey")
}

async fn build_dpop_bound_ucan(
    user_keys: &Keys,
    tenant_id: i64,
    email: &str,
    redirect_origin: &str,
    bunker_pubkey: &str,
    dpop_jkt: &str,
) -> String {
    let user_did = nostr_pubkey_to_did(&user_keys.public_key());
    let key_material = NostrKeyMaterial::from_keys(user_keys.clone());
    let facts = json!({
        "tenant_id": tenant_id,
        "email": email,
        "redirect_origin": redirect_origin,
        "bunker_pubkey": bunker_pubkey,
        "cnf": {
            "jkt": dpop_jkt
        }
    });

    let ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&user_did)
        .with_lifetime(3600)
        .with_fact(facts)
        .build()
        .expect("Failed to build DPoP-bound UCAN")
        .sign()
        .await
        .expect("Failed to sign DPoP-bound UCAN");

    ucan.encode().expect("Failed to encode DPoP-bound UCAN")
}

fn dpop_thumbprint(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let jwk_map: serde_json::Map<String, serde_json::Value> = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate")),
    }))
    .expect("valid JWK map");

    keycast_api::ucan_auth::dpop::jwk_thumbprint(&jwk_map).expect("jwk thumbprint")
}

fn create_dpop_proof(signing_key: &SigningKey, method: &str, htu: &str, jti: &str) -> String {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"));
    let iat = Utc::now().timestamp();

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });
    let payload = json!({
        "htm": method,
        "htu": htu,
        "iat": iat,
        "jti": jti
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload json"));
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: P256Signature = signing_key.sign(signing_input.as_bytes());
    let (r_bytes, s_bytes) = signature.split_bytes();
    let mut sig_raw = Vec::with_capacity(64);
    sig_raw.extend_from_slice(&r_bytes);
    sig_raw.extend_from_slice(&s_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_raw);

    format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
}

fn get_public_key_request() -> NostrRpcRequest {
    NostrRpcRequest {
        method: "get_public_key".to_string(),
        params: vec![],
    }
}

async fn invoke_nostr_rpc(
    tenant: TenantExtractor,
    auth_state: AuthState,
    auth_header: &str,
    dpop_proof: Option<&str>,
    request: NostrRpcRequest,
) -> Result<NostrRpcResponse, RpcError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        auth_header
            .parse()
            .expect("Authorization header should be valid"),
    );
    headers.insert("host", "login.divine.video".parse().expect("valid host"));
    headers.insert("x-forwarded-proto", "https".parse().expect("valid proto"));
    if let Some(proof) = dpop_proof {
        headers.insert("DPoP", proof.parse().expect("valid DPoP header"));
    }

    let Json(response) = nostr_rpc(tenant, State(auth_state), headers, Json(request)).await?;
    Ok(response)
}

/// Create a policy with allowed_kinds restriction
async fn create_kind_restricted_policy(pool: &PgPool, allowed_kinds: Vec<u16>) -> i32 {
    let policy_id: i32 = sqlx::query_scalar(
        "INSERT INTO policies (name, created_at, updated_at)
         VALUES ($1, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("Test Policy {}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("Failed to create policy");

    let permission_id: i32 = sqlx::query_scalar(
        "INSERT INTO permissions (identifier, config, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind("allowed_kinds")
    .bind(json!({"allowed_kinds": allowed_kinds}))
    .fetch_one(pool)
    .await
    .expect("Failed to create permission");

    sqlx::query(
        "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(policy_id)
    .bind(permission_id)
    .execute(pool)
    .await
    .expect("Failed to link permission to policy");

    policy_id
}

/// Simulates load_handler_on_demand - loads user keys from DB and creates HttpRpcHandler
/// Note: This loads regardless of expiration/revocation - caller should check is_valid()
async fn load_handler_from_db(
    pool: &PgPool,
    bunker_pubkey_hex: &str,
    key_manager: &dyn KeyManager,
) -> Result<Arc<HttpRpcHandler>, String> {
    // Query oauth_authorization for this bunker_pubkey (including expires_at, revoked_at)
    #[allow(clippy::type_complexity)]
    let auth_data: Option<(
        i32,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT id, user_pubkey, authorization_handle, expires_at, revoked_at
         FROM oauth_authorizations
         WHERE bunker_public_key = $1",
    )
    .bind(bunker_pubkey_hex)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    let (auth_id, user_pubkey, auth_handle_opt, expires_at, revoked_at) =
        auth_data.ok_or_else(|| "No authorization found".to_string())?;

    // Get user's encrypted secret key
    let encrypted_secret: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(&user_pubkey)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

    // Decrypt the secret key
    let decrypted_secret = key_manager
        .decrypt(&encrypted_secret)
        .await
        .map_err(|e| format!("Decryption failed: {}", e))?;

    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
        .map_err(|e| format!("Invalid secret key bytes: {}", e))?;
    let user_keys = Keys::new(secret_key.into());

    // Parse cache keys
    let bunker_key =
        parse_cache_key(bunker_pubkey_hex).map_err(|e| format!("Invalid bunker_pubkey: {}", e))?;

    let auth_handle = if let Some(ref handle) = auth_handle_opt {
        parse_cache_key(handle).map_err(|e| format!("Invalid authorization_handle: {}", e))?
    } else {
        bunker_key
    };

    // Create signing session (pure crypto - just keys)
    let session = Arc::new(SigningSession::new(user_keys));

    // Create handler with cached metadata and cache keys (no permissions = full access)
    Ok(Arc::new(HttpRpcHandler::new(
        session,
        auth_id as i64,
        expires_at,
        revoked_at,
        vec![], // No permissions = full access (permissive default)
        true,   // OAuth authorization
        bunker_key,
        auth_handle,
        None,
    )))
}

// ============================================================================
// Test 1: Valid sign_event returns signed event
// ============================================================================

#[tokio::test]
#[serial]
async fn test_sign_event_returns_valid_signature() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (user_keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup: user, personal_key, and oauth_authorization
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &user_keys, &key_manager).await;

    let redirect_origin = format!("https://sign-test-{}.example.com", Uuid::new_v4());
    let (_auth_id, bunker_pubkey) = create_test_oauth_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        None, // No policy = full access
        None, // No expiration
        None, // Not revoked
    )
    .await;

    // Load handler from DB (simulates what nostr_rpc does)
    let handler = load_handler_from_db(&pool, &bunker_pubkey, &key_manager)
        .await
        .expect("Failed to load handler");

    // Verify handler is valid (not expired/revoked)
    assert!(handler.is_valid(), "Handler should be valid");

    // Verify keys loaded correctly
    assert_eq!(handler.keys().public_key().to_hex(), pubkey);
    assert_eq!(handler.user_pubkey_hex(), pubkey);

    // Create and sign an event
    let unsigned =
        EventBuilder::text_note("Hello from integration test").build(handler.keys().public_key());

    let signed = handler
        .sign_event(unsigned.clone())
        .await
        .expect("Signing should succeed");

    // Verify the signature
    assert_eq!(signed.kind.as_u16(), 1);
    assert_eq!(signed.content, "Hello from integration test");
    assert_eq!(signed.pubkey.to_hex(), pubkey);

    // Verify signature is valid
    signed.verify().expect("Signature should be valid");
}

// ============================================================================
// Test 2: Expired authorization - handler loads but is_valid() returns false
// ============================================================================

#[tokio::test]
#[serial]
async fn test_expired_authorization_handler_not_valid() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (user_keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user and personal_key
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &user_keys, &key_manager).await;

    let redirect_origin = format!("https://expired-{}.example.com", Uuid::new_v4());

    // Create EXPIRED authorization
    let expired_at = Utc::now() - Duration::hours(1);
    let (_auth_id, bunker_pubkey) = create_test_oauth_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        None,
        Some(expired_at), // Expired 1 hour ago
        None,
    )
    .await;

    // Handler loads successfully (new behavior - no DB filtering)
    let handler = load_handler_from_db(&pool, &bunker_pubkey, &key_manager)
        .await
        .expect("Handler should load even for expired auth");

    // But is_valid() returns false for expired authorization
    assert!(
        !handler.is_valid(),
        "Handler should NOT be valid for expired authorization"
    );

    // Signing should fail for expired handler
    let unsigned = EventBuilder::text_note("test").build(handler.keys().public_key());

    let result = handler.sign_event(unsigned).await;
    assert!(
        result.is_err(),
        "Signing should fail for expired authorization"
    );
}

// ============================================================================
// Test 3: Revoked authorization - handler loads but is_valid() returns false
// ============================================================================

#[tokio::test]
#[serial]
async fn test_revoked_authorization_handler_not_valid() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (user_keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup user and personal_key
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &user_keys, &key_manager).await;

    let redirect_origin = format!("https://revoked-{}.example.com", Uuid::new_v4());

    // Create REVOKED authorization
    let revoked_at = Utc::now() - Duration::minutes(30);
    let (_auth_id, bunker_pubkey) = create_test_oauth_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        None,
        None,
        Some(revoked_at), // Revoked 30 minutes ago
    )
    .await;

    // Handler loads successfully (new behavior - no DB filtering)
    let handler = load_handler_from_db(&pool, &bunker_pubkey, &key_manager)
        .await
        .expect("Handler should load even for revoked auth");

    // But is_valid() returns false for revoked authorization
    assert!(
        !handler.is_valid(),
        "Handler should NOT be valid for revoked authorization"
    );

    // Signing should fail for revoked handler
    let unsigned = EventBuilder::text_note("test").build(handler.keys().public_key());

    let result = handler.sign_event(unsigned).await;
    assert!(
        result.is_err(),
        "Signing should fail for revoked authorization"
    );
}

// ============================================================================
// Test 4: Handler caching works correctly
// ============================================================================

#[tokio::test]
#[serial]
async fn test_handler_cache_stores_and_retrieves() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (user_keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &user_keys, &key_manager).await;

    let redirect_origin = format!("https://cache-test-{}.example.com", Uuid::new_v4());
    let (_auth_id, bunker_pubkey) = create_test_oauth_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        None,
        None,
        None,
    )
    .await;

    // Create a handler cache
    let cache = new_http_handler_cache();

    // Load handler
    let handler = load_handler_from_db(&pool, &bunker_pubkey, &key_manager)
        .await
        .expect("Failed to load handler");

    // Insert into cache using dual-key pattern
    let bunker_key = parse_cache_key(&bunker_pubkey).expect("Invalid bunker pubkey");
    cache.insert(bunker_key, handler.clone()).await;

    // Verify cache retrieval
    let cached = cache.get(&bunker_key).await;
    assert!(cached.is_some(), "Handler should be in cache");

    let cached_handler = cached.unwrap();
    assert!(cached_handler.is_valid(), "Cached handler should be valid");
    assert_eq!(cached_handler.user_pubkey_hex(), pubkey);
    assert_eq!(cached_handler.keys().public_key().to_hex(), pubkey);
}

// ============================================================================
// Test 5: Permission validation blocks unauthorized signing
// ============================================================================

#[tokio::test]
#[serial]
async fn test_sign_event_blocked_by_policy() {
    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (user_keys, pubkey) = create_test_user();
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Setup
    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(&pool, tenant_id, &pubkey, &user_keys, &key_manager).await;

    // Create policy that only allows kind 1
    let policy_id = create_kind_restricted_policy(&pool, vec![1]).await;

    let redirect_origin = format!("https://policy-test-{}.example.com", Uuid::new_v4());
    let (_auth_id, bunker_pubkey) = create_test_oauth_authorization(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        Some(policy_id), // Restricted to kind 1 only
        None,
        None,
    )
    .await;

    // Load handler successfully
    let handler = load_handler_from_db(&pool, &bunker_pubkey, &key_manager)
        .await
        .expect("Failed to load handler");

    assert!(handler.is_valid(), "Handler should be valid");

    // Create kind 4 event (encrypted DM - not in allowed list)
    let unsigned_kind4 = EventBuilder::new(Kind::EncryptedDirectMessage, "Secret")
        .build(handler.keys().public_key());

    // Permission validation should fail
    let result = keycast_api::api::http::auth::validate_signing_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        &unsigned_kind4,
    )
    .await;

    assert!(
        result.is_err(),
        "Kind 4 should be blocked by policy that only allows kind 1"
    );

    // Create kind 1 event (text note - in allowed list)
    let unsigned_kind1 = EventBuilder::text_note("Allowed").build(handler.keys().public_key());

    // Permission validation should succeed for kind 1
    let result = keycast_api::api::http::auth::validate_signing_permissions(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        &unsigned_kind1,
    )
    .await;

    assert!(
        result.is_ok(),
        "Kind 1 should be allowed by policy: {:?}",
        result
    );

    // And signing should work (via handler)
    let signed = handler
        .sign_event(unsigned_kind1)
        .await
        .expect("Signing allowed event should succeed");

    signed.verify().expect("Signature should be valid");
}

// ============================================================================
// Test 6: Cache-hit DPoP enforcement with DPoP-bound UCAN
// ============================================================================

#[tokio::test]
#[serial]
async fn test_cache_hit_dpop_bound_ucan_enforced_end_to_end() {
    // Integration tests run without Redis in CI, so explicitly enable
    // degraded replay-cache fallback for this end-to-end DPoP flow.
    std::env::set_var("DPOP_REPLAY_FAIL_OPEN", "true");

    let pool = setup_db().await;
    let tenant_id = create_test_tenant(&pool).await;
    let (user_keys, pubkey) = create_test_user();
    let key_manager: Arc<Box<dyn KeyManager>> = Arc::new(Box::new(
        FileKeyManager::new().expect("Failed to create key manager"),
    ));
    let redirect_origin = format!("https://dpop-cache-hit-{}.example.com", Uuid::new_v4());
    let bunker_pubkey = Keys::generate().public_key().to_hex();
    let auth_state = create_test_auth_state(pool.clone(), key_manager.clone());
    let htu = "https://login.divine.video/api/nostr";

    insert_user(&pool, tenant_id, &pubkey).await;
    create_personal_key(
        &pool,
        tenant_id,
        &pubkey,
        &user_keys,
        key_manager.as_ref().as_ref(),
    )
    .await;
    create_test_oauth_authorization_with_bunker(
        &pool,
        tenant_id,
        &pubkey,
        &redirect_origin,
        &bunker_pubkey,
        None,
        None,
        None,
    )
    .await;

    let valid_dpop_key = SigningKey::random(&mut OsRng);
    let expected_jkt = dpop_thumbprint(&valid_dpop_key);
    let token = build_dpop_bound_ucan(
        &user_keys,
        tenant_id,
        "dpop-cache-hit@example.com",
        &redirect_origin,
        &bunker_pubkey,
        &expected_jkt,
    )
    .await;
    let auth_header = format!("Bearer {}", token);
    let token_cache_key = *blake3::hash(token.as_bytes()).as_bytes();

    // Request 1: cache miss with valid DPoP proof must succeed and populate cache.
    let proof_1 = create_dpop_proof(
        &valid_dpop_key,
        "POST",
        htu,
        &format!("cache-miss-{}", Uuid::new_v4()),
    );
    let response_1 = invoke_nostr_rpc(
        create_test_tenant_extractor(tenant_id),
        auth_state.clone(),
        &auth_header,
        Some(&proof_1),
        get_public_key_request(),
    )
    .await
    .expect("Initial DPoP-bound request should succeed");
    assert_eq!(response_1.result, Some(Value::String(pubkey.clone())));
    assert!(
        auth_state
            .state
            .http_handler_cache
            .get(&token_cache_key)
            .await
            .is_some(),
        "Cache should contain token-keyed handler after first request"
    );

    // Request 2: cache hit with missing DPoP proof must be rejected.
    let err_missing = invoke_nostr_rpc(
        create_test_tenant_extractor(tenant_id),
        auth_state.clone(),
        &auth_header,
        None,
        get_public_key_request(),
    )
    .await
    .expect_err("Missing DPoP proof on cache hit must be rejected");
    assert!(matches!(
        err_missing,
        RpcError::Auth(AuthError::InvalidToken)
    ));

    // Request 3: cache hit with invalid DPoP proof (wrong key) must be rejected.
    let wrong_key = SigningKey::random(&mut OsRng);
    let wrong_proof = create_dpop_proof(
        &wrong_key,
        "POST",
        htu,
        &format!("cache-hit-invalid-{}", Uuid::new_v4()),
    );
    let err_invalid = invoke_nostr_rpc(
        create_test_tenant_extractor(tenant_id),
        auth_state.clone(),
        &auth_header,
        Some(&wrong_proof),
        get_public_key_request(),
    )
    .await
    .expect_err("Invalid DPoP proof on cache hit must be rejected");
    assert!(matches!(
        err_invalid,
        RpcError::Auth(AuthError::InvalidToken)
    ));

    // Request 4: cache hit with a fresh, valid DPoP proof must succeed.
    let proof_2 = create_dpop_proof(
        &valid_dpop_key,
        "POST",
        htu,
        &format!("cache-hit-valid-{}", Uuid::new_v4()),
    );
    let response_4 = invoke_nostr_rpc(
        create_test_tenant_extractor(tenant_id),
        auth_state,
        &auth_header,
        Some(&proof_2),
        get_public_key_request(),
    )
    .await
    .expect("Valid DPoP proof on cache hit should succeed");
    assert_eq!(response_4.result, Some(Value::String(pubkey)));
}
