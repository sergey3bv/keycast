mod common;

use keycast_core::repositories::UserRepository;
use nostr_sdk::Keys;

#[tokio::test]
async fn update_profile_claims_name_without_enabling_atproto() {
    let pool = common::setup_test_db().await;
    let repo = UserRepository::new(pool.clone());

    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    let tenant_id = 1_i64;
    let username = format!("alice-update-profile-{}", &pubkey[..8]);

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await
    .expect("failed to insert user");

    repo.update_username(&pubkey, &username, tenant_id)
        .await
        .unwrap();

    let state = repo
        .get_atproto_state(&pubkey, tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!state.enabled);
    assert_eq!(state.state, None);
}
