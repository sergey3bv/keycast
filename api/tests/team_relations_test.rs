// ABOUTME: Tests for team relations batch queries
// ABOUTME: Verifies N+1 query optimizations work correctly

use keycast_core::types::team::Team;
use keycast_core::types::user::User;
use nostr_sdk::{Keys, PublicKey};
use sqlx::PgPool;
use uuid::Uuid;

mod common;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database")
}

/// Helper to create a test user
async fn create_test_user(pool: &PgPool, pubkey: &str) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, 1, NOW(), NOW())
         ON CONFLICT (pubkey) DO NOTHING",
    )
    .bind(pubkey)
    .execute(pool)
    .await
    .unwrap();
}

/// Helper to create a test team and return its ID
async fn create_test_team(pool: &PgPool, name: &str) -> i32 {
    let result: (i32,) = sqlx::query_as(
        "INSERT INTO teams (name, tenant_id, created_at, updated_at)
         VALUES ($1, 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    result.0
}

/// Helper to add user to team
async fn add_user_to_team(pool: &PgPool, user_pubkey: &str, team_id: i32, role: &str) {
    sqlx::query(
        "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (team_id, user_pubkey) DO NOTHING",
    )
    .bind(team_id)
    .bind(user_pubkey)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
}

/// Helper to create a stored key for a team
async fn create_stored_key(pool: &PgPool, team_id: i32, name: &str, pubkey: &str) -> i32 {
    let result: (i32,) = sqlx::query_as(
        "INSERT INTO stored_keys (team_id, name, pubkey, secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 1, NOW(), NOW())
         RETURNING id",
    )
    .bind(team_id)
    .bind(name)
    .bind(pubkey)
    .bind(vec![0u8; 32]) // Dummy encrypted key
    .fetch_one(pool)
    .await
    .unwrap();
    result.0
}

/// Helper to create a policy for a team
async fn create_team_policy(pool: &PgPool, team_id: i32, name: &str) -> i32 {
    let result: (i32,) = sqlx::query_as(
        "INSERT INTO policies (name, team_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(name)
    .bind(team_id)
    .fetch_one(pool)
    .await
    .unwrap();
    result.0
}

/// Helper to create a permission
async fn create_permission(pool: &PgPool, identifier: &str, config: &str) -> i32 {
    // First try to find existing permission
    let existing: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM permissions WHERE identifier = $1")
            .bind(identifier)
            .fetch_optional(pool)
            .await
            .unwrap();

    if let Some((id,)) = existing {
        return id;
    }

    let result: (i32,) = sqlx::query_as(
        "INSERT INTO permissions (identifier, config, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id",
    )
    .bind(identifier)
    .bind(config)
    .fetch_one(pool)
    .await
    .unwrap();
    result.0
}

/// Helper to link policy to permission
async fn link_policy_permission(pool: &PgPool, policy_id: i32, permission_id: i32) {
    sqlx::query(
        "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (policy_id, permission_id) DO NOTHING",
    )
    .bind(policy_id)
    .bind(permission_id)
    .execute(pool)
    .await
    .unwrap();
}

/// Test User::teams() returns correct data with batch queries
#[tokio::test]
async fn test_user_teams_batch_query() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let test_suffix = Uuid::new_v4().to_string()[..8].to_string();

    // Create user
    create_test_user(&pool, &user_pubkey).await;

    // Create two teams
    let team1_name = format!("Team Alpha {}", test_suffix);
    let team2_name = format!("Team Beta {}", test_suffix);
    let team1_id = create_test_team(&pool, &team1_name).await;
    let team2_id = create_test_team(&pool, &team2_name).await;

    // Add user to both teams (admin in one, member in other)
    add_user_to_team(&pool, &user_pubkey, team1_id, "admin").await;
    add_user_to_team(&pool, &user_pubkey, team2_id, "member").await;

    // Add another user to team1
    let other_keys = Keys::generate();
    let other_pubkey = other_keys.public_key().to_hex();
    create_test_user(&pool, &other_pubkey).await;
    add_user_to_team(&pool, &other_pubkey, team1_id, "member").await;

    // Create stored keys for each team
    let key1_pubkey = Keys::generate().public_key().to_hex();
    let key2_pubkey = Keys::generate().public_key().to_hex();
    create_stored_key(&pool, team1_id, &format!("Key1 {}", test_suffix), &key1_pubkey).await;
    create_stored_key(&pool, team2_id, &format!("Key2 {}", test_suffix), &key2_pubkey).await;

    // Create policies with permissions
    let policy1_id = create_team_policy(&pool, team1_id, &format!("Policy1 {}", test_suffix)).await;
    let perm_id = create_permission(
        &pool,
        &format!("test_perm_{}", test_suffix),
        r#"{"allowed_kinds": [1, 7]}"#,
    )
    .await;
    link_policy_permission(&pool, policy1_id, perm_id).await;

    // Now test User::teams()
    let user = User::find_by_pubkey(
        &pool,
        1,
        &PublicKey::from_hex(&user_pubkey).unwrap(),
    )
    .await
    .expect("User should exist");

    let teams = user
        .teams(&pool, 1)
        .await
        .expect("Should fetch teams successfully");

    // Verify we got both teams
    assert!(
        teams.len() >= 2,
        "User should be in at least 2 teams, got {}",
        teams.len()
    );

    // Find our test teams
    let team1 = teams.iter().find(|t| t.team.name == team1_name);
    let team2 = teams.iter().find(|t| t.team.name == team2_name);

    assert!(team1.is_some(), "Team1 should be in results");
    assert!(team2.is_some(), "Team2 should be in results");

    let team1 = team1.unwrap();
    let team2 = team2.unwrap();

    // Verify team1 has 2 users
    assert_eq!(
        team1.team_users.len(),
        2,
        "Team1 should have 2 users"
    );

    // Verify team1 has stored key
    assert!(
        team1.stored_keys.iter().any(|k| k.pubkey == key1_pubkey),
        "Team1 should have the stored key"
    );

    // Verify team1 has policy with permission
    assert!(
        !team1.policies.is_empty(),
        "Team1 should have at least one policy"
    );
    let policy = team1
        .policies
        .iter()
        .find(|p| p.policy.name.contains(&test_suffix));
    assert!(policy.is_some(), "Team1 should have test policy");
    assert!(
        !policy.unwrap().permissions.is_empty(),
        "Policy should have permissions"
    );

    // Verify team2 has stored key
    assert!(
        team2.stored_keys.iter().any(|k| k.pubkey == key2_pubkey),
        "Team2 should have the stored key"
    );
}

/// Test Team::find_with_relations() returns correct data
#[tokio::test]
async fn test_team_find_with_relations() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let test_suffix = Uuid::new_v4().to_string()[..8].to_string();

    // Create user
    create_test_user(&pool, &user_pubkey).await;

    // Create team
    let team_name = format!("Relations Test Team {}", test_suffix);
    let team_id = create_test_team(&pool, &team_name).await;

    // Add user to team
    add_user_to_team(&pool, &user_pubkey, team_id, "admin").await;

    // Create stored key
    let key_pubkey = Keys::generate().public_key().to_hex();
    create_stored_key(&pool, team_id, &format!("Test Key {}", test_suffix), &key_pubkey).await;

    // Create policy with permission
    let policy_id =
        create_team_policy(&pool, team_id, &format!("Test Policy {}", test_suffix)).await;
    let perm_id = create_permission(
        &pool,
        &format!("test_find_rel_{}", test_suffix),
        r#"{"allowed_kinds": [0, 1, 3]}"#,
    )
    .await;
    link_policy_permission(&pool, policy_id, perm_id).await;

    // Test find_with_relations
    let team_with_relations = Team::find_with_relations(&pool, 1, team_id)
        .await
        .expect("Should find team with relations");

    // Verify team data
    assert_eq!(team_with_relations.team.id, team_id);
    assert_eq!(team_with_relations.team.name, team_name);

    // Verify team users
    assert_eq!(team_with_relations.team_users.len(), 1);
    assert_eq!(team_with_relations.team_users[0].user_pubkey, user_pubkey);

    // Verify stored keys
    assert!(
        team_with_relations
            .stored_keys
            .iter()
            .any(|k| k.pubkey == key_pubkey),
        "Should have the stored key"
    );

    // Verify policies
    let policy = team_with_relations
        .policies
        .iter()
        .find(|p| p.policy.name.contains(&test_suffix));
    assert!(policy.is_some(), "Should have test policy");
    assert!(
        !policy.unwrap().permissions.is_empty(),
        "Policy should have permissions"
    );
}

/// Test get_policies_with_permissions_batch with multiple teams
#[tokio::test]
async fn test_policies_batch_query() {
    let pool = setup_pool().await;
    let test_suffix = Uuid::new_v4().to_string()[..8].to_string();

    // Create 3 teams with different policies
    let team1_id = create_test_team(&pool, &format!("Batch Team 1 {}", test_suffix)).await;
    let team2_id = create_test_team(&pool, &format!("Batch Team 2 {}", test_suffix)).await;
    let team3_id = create_test_team(&pool, &format!("Batch Team 3 {}", test_suffix)).await;

    // Create policies for each team
    let policy1_id =
        create_team_policy(&pool, team1_id, &format!("Batch Policy 1 {}", test_suffix)).await;
    let policy2_id =
        create_team_policy(&pool, team2_id, &format!("Batch Policy 2 {}", test_suffix)).await;
    let policy3_id =
        create_team_policy(&pool, team3_id, &format!("Batch Policy 3 {}", test_suffix)).await;

    // Create permissions
    let perm1_id = create_permission(
        &pool,
        &format!("batch_perm1_{}", test_suffix),
        r#"{"allowed_kinds": [1]}"#,
    )
    .await;
    let perm2_id = create_permission(
        &pool,
        &format!("batch_perm2_{}", test_suffix),
        r#"{"allowed_kinds": [1, 7]}"#,
    )
    .await;

    // Link permissions (policy1 has perm1, policy2 has both, policy3 has perm2)
    link_policy_permission(&pool, policy1_id, perm1_id).await;
    link_policy_permission(&pool, policy2_id, perm1_id).await;
    link_policy_permission(&pool, policy2_id, perm2_id).await;
    link_policy_permission(&pool, policy3_id, perm2_id).await;

    // Test batch query
    let team_ids = vec![team1_id, team2_id, team3_id];
    let policies = Team::get_policies_with_permissions_batch(&pool, &team_ids)
        .await
        .expect("Should fetch policies successfully");

    // Should have 3 policies
    assert!(
        policies.len() >= 3,
        "Should have at least 3 policies, got {}",
        policies.len()
    );

    // Find our test policies
    let p1 = policies
        .iter()
        .find(|p| p.policy.name.contains("Batch Policy 1"));
    let p2 = policies
        .iter()
        .find(|p| p.policy.name.contains("Batch Policy 2"));
    let p3 = policies
        .iter()
        .find(|p| p.policy.name.contains("Batch Policy 3"));

    assert!(p1.is_some(), "Policy 1 should be in results");
    assert!(p2.is_some(), "Policy 2 should be in results");
    assert!(p3.is_some(), "Policy 3 should be in results");

    // Verify permission counts
    assert_eq!(p1.unwrap().permissions.len(), 1, "Policy 1 should have 1 permission");
    assert_eq!(p2.unwrap().permissions.len(), 2, "Policy 2 should have 2 permissions");
    assert_eq!(p3.unwrap().permissions.len(), 1, "Policy 3 should have 1 permission");
}

/// Test empty team list returns empty results
#[tokio::test]
async fn test_policies_batch_empty() {
    let pool = setup_pool().await;

    let policies = Team::get_policies_with_permissions_batch(&pool, &[])
        .await
        .expect("Should handle empty team list");

    assert!(policies.is_empty(), "Empty team list should return empty policies");
}

/// Test user with no teams returns empty
#[tokio::test]
async fn test_user_no_teams() {
    let pool = setup_pool().await;
    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Create user but don't add to any teams
    create_test_user(&pool, &user_pubkey).await;

    let user = User::find_by_pubkey(
        &pool,
        1,
        &PublicKey::from_hex(&user_pubkey).unwrap(),
    )
    .await
    .expect("User should exist");

    let teams = user
        .teams(&pool, 1)
        .await
        .expect("Should handle user with no teams");

    assert!(teams.is_empty(), "User with no team memberships should have empty teams");
}
