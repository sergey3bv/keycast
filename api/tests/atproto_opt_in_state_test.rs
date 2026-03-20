mod common;

use keycast_core::repositories::UserRepository;
use nostr_sdk::Keys;

#[tokio::test]
async fn user_atproto_state_round_trips() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let tenant_id = 1_i64;

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to create test user");

    repo.set_atproto_state(&pubkey, tenant_id, true, Some("pending"), None, None)
        .await
        .unwrap();

    let state = repo
        .get_atproto_state(&pubkey, tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.enabled);
    assert_eq!(state.state.as_deref(), Some("pending"));
    assert_eq!(state.did, None);
}
