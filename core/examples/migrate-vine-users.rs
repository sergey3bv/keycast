// ABOUTME: Full user migration from openvine-co to target environment
// ABOUTME: Re-encrypts personal keys with target GCP KMS key
// ABOUTME: Run with: cargo run --example migrate-vine-users
//
// Migrates ALL users (vine and non-vine) and their personal keys.
// Non-vine users keep email, password_hash, email_verified for login.
// Authorizations are NOT migrated - only users and personal_keys.
//
// Environment variables:
//   SOURCE_GCP_PROJECT_ID, SOURCE_GCP_KMS_LOCATION, SOURCE_GCP_KMS_KEY_RING, SOURCE_GCP_KMS_KEY_NAME
//   TARGET_GCP_PROJECT_ID, TARGET_GCP_KMS_LOCATION, TARGET_GCP_KMS_KEY_RING, TARGET_GCP_KMS_KEY_NAME
//   SOURCE_DATABASE_URL, TARGET_DATABASE_URL
//   TENANT_ID (default: 1)
//   DRY_RUN (default: true)
//   CONCURRENCY (default: 20) - number of parallel KMS operations
//   LIMIT (default: 0 = unlimited) - max users to migrate

use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use nostr_sdk::SecretKey;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::Row;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{} is required", name))
}

async fn validate_schema(
    pool: &sqlx::PgPool,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let required_tables = ["users", "personal_keys"];
    for table in &required_tables {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = $1
            )",
        )
        .bind(table)
        .fetch_one(pool)
        .await?;

        if !exists {
            return Err(format!(
                "{} database is missing required table '{}'. Run migrations first.",
                label, table
            )
            .into());
        }
    }
    println!("{} schema validated (users, personal_keys present)", label);
    Ok(())
}

struct SourceUser {
    pubkey: String,
    tenant_id: i64,
    email: Option<String>,
    password_hash: Option<String>,
    email_verified: Option<bool>,
    username: Option<String>,
    display_name: Option<String>,
    vine_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    encrypted_secret_key: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== User Migration ===");
    println!();

    let dry_run = env::var("DRY_RUN").unwrap_or_else(|_| "true".to_string()) == "true";
    let tenant_id: i64 = env::var("TENANT_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("TENANT_ID must be a number");
    let concurrency: usize = env::var("CONCURRENCY")
        .unwrap_or_else(|_| "20".to_string())
        .parse()
        .expect("CONCURRENCY must be a number");
    let limit: usize = env::var("LIMIT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("LIMIT must be a number");

    if dry_run {
        println!("** DRY RUN MODE - no writes will be made **");
        println!();
    }
    println!("Concurrency: {}", concurrency);

    // Initialize source KMS
    println!("Initializing source KMS...");
    let source_kms = Arc::new(
        GcpKeyManager::from_config(
            &required_env("SOURCE_GCP_PROJECT_ID"),
            &required_env("SOURCE_GCP_KMS_LOCATION"),
            &required_env("SOURCE_GCP_KMS_KEY_RING"),
            &required_env("SOURCE_GCP_KMS_KEY_NAME"),
        )
        .await?,
    );
    println!("Source KMS ready");

    // Initialize target KMS
    println!("Initializing target KMS...");
    let target_kms = Arc::new(
        GcpKeyManager::from_config(
            &required_env("TARGET_GCP_PROJECT_ID"),
            &required_env("TARGET_GCP_KMS_LOCATION"),
            &required_env("TARGET_GCP_KMS_KEY_RING"),
            &required_env("TARGET_GCP_KMS_KEY_NAME"),
        )
        .await?,
    );
    println!("Target KMS ready");

    // Connect to source database
    println!("Connecting to source database...");
    let source_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&required_env("SOURCE_DATABASE_URL"))
        .await?;
    println!("Source DB connected");

    // Connect to target database
    println!("Connecting to target database...");
    let target_pool = Arc::new(
        PgPoolOptions::new()
            .max_connections(concurrency as u32 + 5)
            .connect(&required_env("TARGET_DATABASE_URL"))
            .await?,
    );
    println!("Target DB connected");
    println!();

    // Validate both databases have required tables
    validate_schema(&source_pool, "Source").await?;
    validate_schema(target_pool.as_ref(), "Target").await?;
    println!();

    // Query all users with personal keys from source
    println!("Querying source users (tenant_id={})...", tenant_id);
    let rows = sqlx::query(
        "SELECT u.pubkey, u.tenant_id, u.email, u.password_hash, u.email_verified,
                u.username, u.display_name, u.vine_id, u.created_at, u.updated_at,
                pk.encrypted_secret_key
         FROM users u
         JOIN personal_keys pk ON u.pubkey = pk.user_pubkey AND u.tenant_id = pk.tenant_id
         WHERE u.tenant_id = $1
         ORDER BY u.created_at",
    )
    .bind(tenant_id)
    .fetch_all(&source_pool)
    .await?;

    let mut users: Vec<SourceUser> = rows
        .iter()
        .map(|row| SourceUser {
            pubkey: row.get("pubkey"),
            tenant_id: row.get("tenant_id"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            email_verified: row.get("email_verified"),
            username: row.get("username"),
            display_name: row.get("display_name"),
            vine_id: row.get("vine_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            encrypted_secret_key: row.get("encrypted_secret_key"),
        })
        .collect();

    println!("Found {} users with personal keys", users.len());
    if limit > 0 && limit < users.len() {
        users.truncate(limit);
        println!("Limited to {} users", limit);
    }
    let total = users.len();
    println!();

    // Canary: test KMS on the first user before spawning the batch
    println!("--- Canary Check ---");
    let canary = &users[0];
    let canary_label = canary
        .username
        .as_deref()
        .or(canary.email.as_deref())
        .unwrap_or(&canary.pubkey[..8]);
    println!("Testing source KMS decrypt on {}...", canary_label);
    let canary_plaintext = source_kms.decrypt(&canary.encrypted_secret_key).await?;
    println!("Source KMS decrypt OK ({} bytes)", canary_plaintext.len());
    if !dry_run {
        println!("Testing target KMS round-trip...");
        let canary_ct = target_kms.encrypt(&canary_plaintext).await?;
        let canary_rt = target_kms.decrypt(&canary_ct).await?;
        assert_eq!(&*canary_plaintext, &*canary_rt, "KMS round-trip mismatch");
        println!("Target KMS round-trip OK");
    }
    println!();

    let migrated = Arc::new(AtomicU64::new(0));
    let skipped = Arc::new(AtomicU64::new(0));
    let processed = Arc::new(AtomicU64::new(0));
    let sem = Arc::new(Semaphore::new(concurrency));

    // Migration pass using JoinSet for abort-on-failure
    println!("--- Migration Pass ---");
    let mut tasks = JoinSet::new();

    for user in users {
        let permit = sem.clone().acquire_owned().await?;
        let source_kms = source_kms.clone();
        let target_kms = target_kms.clone();
        let target_pool = target_pool.clone();
        let migrated = migrated.clone();
        let skipped = skipped.clone();
        let processed = processed.clone();

        tasks.spawn(async move {
            let _permit = permit;
            let label = user
                .username
                .as_deref()
                .or(user.email.as_deref())
                .unwrap_or(&user.pubkey[..8]);

            // Check if user already exists in target (idempotent)
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE pubkey = $1 AND tenant_id = $2)",
            )
            .bind(&user.pubkey)
            .bind(user.tenant_id)
            .fetch_one(target_pool.as_ref())
            .await
            .map_err(|e| format!("[{}] FAIL (db check: {})", label, e))?;

            if exists {
                let n = processed.fetch_add(1, Ordering::Relaxed) + 1;
                println!("[{}/{}] {} ... SKIP", n, total, label);
                skipped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }

            // Decrypt with source KMS
            let plaintext: Zeroizing<Vec<u8>> = source_kms
                .decrypt(&user.encrypted_secret_key)
                .await
                .map_err(|e| format!("[{}] FAIL (source decrypt: {})", label, e))?;

            if dry_run {
                let n = processed.fetch_add(1, Ordering::Relaxed) + 1;
                println!("[{}/{}] {} ... OK (dry run)", n, total, label);
                migrated.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }

            // Re-encrypt with target KMS
            let target_ciphertext = target_kms
                .encrypt(&plaintext)
                .await
                .map_err(|e| format!("[{}] FAIL (target encrypt: {})", label, e))?;

            // Atomic insert: user + personal_key in a transaction
            let mut tx = target_pool
                .begin()
                .await
                .map_err(|e| format!("[{}] FAIL (begin tx: {})", label, e))?;

            sqlx::query(
                "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified,
                                    username, display_name, vine_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(&user.pubkey)
            .bind(user.tenant_id)
            .bind(&user.email)
            .bind(&user.password_hash)
            .bind(user.email_verified)
            .bind(&user.username)
            .bind(&user.display_name)
            .bind(&user.vine_id)
            .bind(user.created_at)
            .bind(user.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("[{}] FAIL (insert user: {})", label, e))?;

            sqlx::query(
                "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&user.pubkey)
            .bind(&target_ciphertext)
            .bind(user.tenant_id)
            .bind(user.created_at)
            .bind(user.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("[{}] FAIL (insert key: {})", label, e))?;

            tx.commit()
                .await
                .map_err(|e| format!("[{}] FAIL (commit: {})", label, e))?;

            let n = processed.fetch_add(1, Ordering::Relaxed) + 1;
            println!("[{}/{}] {} ... OK", n, total, label);
            migrated.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
    }

    // Drain tasks, abort all on first failure
    let mut abort_reason: Option<String> = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(msg)) => {
                println!("{}", msg);
                abort_reason = Some(msg);
                tasks.abort_all();
                break;
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => {
                abort_reason = Some(format!("task panicked: {}", e));
                tasks.abort_all();
                break;
            }
        }
    }

    let migrated_val = migrated.load(Ordering::Relaxed);
    let skipped_val = skipped.load(Ordering::Relaxed);

    println!();
    println!("--- Migration Summary ---");
    println!("Total:    {}", total);
    println!("Migrated: {}", migrated_val);
    println!("Skipped:  {}", skipped_val);
    if let Some(reason) = &abort_reason {
        println!("ABORTED:  {}", reason);
        std::process::exit(1);
    }

    if dry_run {
        println!();
        println!("** DRY RUN - set DRY_RUN=false to perform actual migration **");
        return Ok(());
    }

    // Verification pass
    if migrated_val > 0 {
        println!();
        println!("--- Verification Pass ---");

        let target_rows = sqlx::query(
            "SELECT u.pubkey, pk.encrypted_secret_key
             FROM users u
             JOIN personal_keys pk ON u.pubkey = pk.user_pubkey AND u.tenant_id = pk.tenant_id
             WHERE u.tenant_id = $1
             ORDER BY u.created_at",
        )
        .bind(tenant_id)
        .fetch_all(target_pool.as_ref())
        .await?;

        let verify_total = target_rows.len();
        let verified = Arc::new(AtomicU64::new(0));
        let verify_failed = Arc::new(AtomicU64::new(0));
        let verify_done = Arc::new(AtomicU64::new(0));

        let mut vtasks = JoinSet::new();

        for row in target_rows {
            let permit = sem.clone().acquire_owned().await?;
            let target_kms = target_kms.clone();
            let verified = verified.clone();
            let verify_failed = verify_failed.clone();
            let verify_done = verify_done.clone();

            let pubkey: String = row.get("pubkey");
            let encrypted: Vec<u8> = row.get("encrypted_secret_key");

            vtasks.spawn(async move {
                let _permit = permit;
                match target_kms.decrypt(&encrypted).await {
                    Ok(plaintext) => match SecretKey::from_slice(&plaintext) {
                        Ok(sk) => {
                            let derived = nostr_sdk::Keys::new(sk).public_key().to_hex();
                            if derived == pubkey {
                                verified.fetch_add(1, Ordering::Relaxed);
                            } else {
                                println!("VERIFY FAIL: pubkey mismatch for {}", &pubkey[..8]);
                                verify_failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            println!(
                                "VERIFY FAIL: invalid secret key for {} ({})",
                                &pubkey[..8],
                                e
                            );
                            verify_failed.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    Err(e) => {
                        println!("VERIFY FAIL: decrypt failed for {} ({})", &pubkey[..8], e);
                        verify_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let done = verify_done.fetch_add(1, Ordering::Relaxed) + 1;
                if done.is_multiple_of(100) || done == verify_total as u64 {
                    println!("  verified {}/{}", done, verify_total);
                }
            });
        }

        while let Some(result) = vtasks.join_next().await {
            if let Err(e) = result {
                if !e.is_cancelled() {
                    println!("VERIFY: task panicked: {}", e);
                }
            }
        }

        let v = verified.load(Ordering::Relaxed);
        let vf = verify_failed.load(Ordering::Relaxed);
        println!("Verified: {}/{} (failed: {})", v, verify_total, vf);

        if vf > 0 {
            println!();
            println!("WARNING: Some verifications failed!");
            std::process::exit(1);
        }
    }

    println!();
    println!("Migration complete.");

    Ok(())
}
