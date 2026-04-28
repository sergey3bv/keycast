// ABOUTME: One-off backfill for publishing kind:10002 relay lists for existing user-facing accounts
// ABOUTME: Run with `cargo run -p keycast_api --example backfill_kind10002`

use keycast_api::relay_list_publisher;
#[cfg(feature = "aws")]
use keycast_core::encryption::aws_key_manager::AwsKeyManager;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use nostr_sdk::{Client, Filter, Keys, Kind, PublicKey};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::env;
use std::io;
use std::time::Duration;

const ADD_RELAY_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const FETCH_EVENTS_TIMEOUT: Duration = Duration::from_secs(4);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{} is required", name))
}

fn parse_dry_run_env(raw: Option<String>) -> Result<bool, String> {
    let value = raw.unwrap_or_else(|| "true".to_string());
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        invalid => Err(format!(
            "invalid DRY_RUN value '{invalid}'. Use one of: 1,true,yes,0,false,no"
        )),
    }
}

fn parse_live_run_env(raw: Option<String>) -> Result<Option<bool>, String> {
    let Some(value) = raw else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(Some(true)),
        "0" | "false" | "no" => Ok(Some(false)),
        invalid => Err(format!(
            "invalid LIVE_RUN value '{invalid}'. Use one of: 1,true,yes,0,false,no"
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KmsProvider {
    File,
    Gcp,
    Aws,
}

fn resolve_kms_provider() -> Result<KmsProvider, String> {
    let use_gcp_kms = env::var("USE_GCP_KMS").ok().map(|v| v == "true");

    if let Ok(provider) = env::var("KMS_PROVIDER") {
        return match provider.trim().to_ascii_lowercase().as_str() {
            "file" => Ok(KmsProvider::File),
            "gcp" => Ok(KmsProvider::Gcp),
            "aws" => Ok(KmsProvider::Aws),
            invalid => Err(format!(
                "KMS_PROVIDER must be one of: file, gcp, aws (got '{invalid}')"
            )),
        };
    }

    if use_gcp_kms.unwrap_or(false) {
        Ok(KmsProvider::Gcp)
    } else {
        Ok(KmsProvider::File)
    }
}

async fn build_key_manager(
    kms_provider: KmsProvider,
) -> Result<Box<dyn KeyManager>, Box<dyn std::error::Error>> {
    match kms_provider {
        KmsProvider::File => Ok(Box::new(FileKeyManager::new()?)),
        KmsProvider::Gcp => Ok(Box::new(GcpKeyManager::new().await?)),
        KmsProvider::Aws => {
            #[cfg(feature = "aws")]
            {
                Ok(Box::new(AwsKeyManager::new().await?))
            }
            #[cfg(not(feature = "aws"))]
            {
                Err("KMS_PROVIDER=aws but keycast_api was built without --features aws".into())
            }
        }
    }
}

async fn has_kind10002_on_indexer(pubkey: &PublicKey, relay: &str) -> Result<bool, String> {
    let client = Client::new(Keys::generate());
    let add_result = tokio::time::timeout(ADD_RELAY_TIMEOUT, client.add_relay(relay))
        .await
        .map_err(|_| "add_relay timed out".to_string())?;
    add_result.map_err(|e| format!("add_relay failed: {e}"))?;

    client
        .try_connect_relay(relay, CONNECT_TIMEOUT)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;

    let filter = Filter::new()
        .author(*pubkey)
        .kind(Kind::Custom(10002))
        .limit(1);
    let fetch_result = tokio::time::timeout(
        FETCH_EVENTS_TIMEOUT,
        client.fetch_events(filter, FETCH_EVENTS_TIMEOUT),
    )
    .await
    .map_err(|_| "fetch_events timed out".to_string())?;

    let has_events = fetch_result
        .map_err(|e| format!("fetch_events failed: {e}"))?
        .first()
        .is_some();

    if tokio::time::timeout(DISCONNECT_TIMEOUT, client.disconnect())
        .await
        .is_err()
    {
        println!("WARN relay={} disconnect timed out", relay);
    }

    Ok(has_events)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingKind10002Status {
    Found,
    NotFound,
    Unknown,
}

fn summarize_existing_kind10002_results(
    results: &[Result<bool, String>],
) -> ExistingKind10002Status {
    if results.iter().any(|result| matches!(result, Ok(true))) {
        return ExistingKind10002Status::Found;
    }

    if results.iter().all(|result| matches!(result, Ok(false))) {
        return ExistingKind10002Status::NotFound;
    }

    ExistingKind10002Status::Unknown
}

async fn has_existing_kind10002(pubkey: &PublicKey) -> (ExistingKind10002Status, Vec<String>) {
    let mut relay_results = Vec::with_capacity(relay_list_publisher::INDEXER_RELAYS.len());
    let mut errors = Vec::new();

    for relay in relay_list_publisher::INDEXER_RELAYS {
        let result = has_kind10002_on_indexer(pubkey, relay).await;
        if let Err(err) = &result {
            errors.push(format!("relay {relay}: {err}"));
        }
        relay_results.push(result);
    }

    let status = summarize_existing_kind10002_results(&relay_results);
    (status, errors)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = required_env("DATABASE_URL");
    let tenant_id: i64 = env::var("TENANT_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("TENANT_ID must be a number");
    let dry_run_from_env = parse_dry_run_env(env::var("DRY_RUN").ok())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let live_run_override = parse_live_run_env(env::var("LIVE_RUN").ok())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let dry_run = live_run_override
        .map(|live_run| !live_run)
        .unwrap_or(dry_run_from_env);
    if live_run_override.is_some() {
        println!("LIVE_RUN override is set; ignoring DRY_RUN");
    }
    let limit: i64 = env::var("LIMIT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .expect("LIMIT must be a number");

    println!("=== kind:10002 backfill ===");
    println!("tenant_id={}", tenant_id);
    println!("dry_run={}", dry_run);
    println!("limit={}", limit);

    let kms_provider =
        resolve_kms_provider().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    println!(
        "kms_provider={}",
        env::var("KMS_PROVIDER").unwrap_or_else(|_| "legacy".to_string())
    );
    let key_manager = build_key_manager(kms_provider).await?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    let rows = if limit > 0 {
        sqlx::query(
            "SELECT u.pubkey, pk.encrypted_secret_key
             FROM users u
             JOIN personal_keys pk ON pk.user_pubkey = u.pubkey AND pk.tenant_id = u.tenant_id
             WHERE u.tenant_id = $1
               AND u.email IS NOT NULL
               AND pk.is_generated = TRUE
             ORDER BY u.created_at ASC
             LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&pool)
        .await?
    } else {
        sqlx::query(
            "SELECT u.pubkey, pk.encrypted_secret_key
             FROM users u
             JOIN personal_keys pk ON pk.user_pubkey = u.pubkey AND pk.tenant_id = u.tenant_id
             WHERE u.tenant_id = $1
               AND u.email IS NOT NULL
               AND pk.is_generated = TRUE
             ORDER BY u.created_at ASC",
        )
        .bind(tenant_id)
        .fetch_all(&pool)
        .await?
    };

    println!("users_selected={}", rows.len());

    let mut processed = 0_u64;
    let mut published_ok = 0_u64;
    let mut published_partial = 0_u64;
    let mut skipped_existing = 0_u64;
    let mut skipped_unknown = 0_u64;
    let mut failed = 0_u64;

    for row in rows {
        processed += 1;
        let pubkey: String = row.get("pubkey");
        let nostr_pubkey = match PublicKey::from_hex(&pubkey) {
            Ok(value) => value,
            Err(e) => {
                failed += 1;
                println!(
                    "[{processed}] FAIL pubkey={} reason=invalid_pubkey:{}",
                    pubkey, e
                );
                continue;
            }
        };

        let (existing_status, existing_errors) = has_existing_kind10002(&nostr_pubkey).await;

        if dry_run {
            match existing_status {
                ExistingKind10002Status::Found => {
                    println!(
                        "[{processed}] DRY_RUN_SKIP pubkey={} reason=existing_kind10002_found",
                        pubkey
                    );
                }
                ExistingKind10002Status::NotFound => {
                    println!("[{processed}] DRY_RUN_PUBLISH pubkey={}", pubkey);
                }
                ExistingKind10002Status::Unknown => {
                    println!(
                        "[{processed}] DRY_RUN_UNKNOWN pubkey={} reason=existing_kind10002_check_unknown:{}",
                        pubkey,
                        existing_errors.join(" | ")
                    );
                }
            }
            continue;
        }

        match existing_status {
            ExistingKind10002Status::Found => {
                skipped_existing += 1;
                println!(
                    "[{processed}] SKIP pubkey={} reason=existing_kind10002_found",
                    pubkey
                );
                continue;
            }
            ExistingKind10002Status::NotFound => {}
            ExistingKind10002Status::Unknown => {
                skipped_unknown += 1;
                println!(
                    "[{processed}] SKIP pubkey={} reason=existing_kind10002_check_unknown:{}",
                    pubkey,
                    existing_errors.join(" | ")
                );
                continue;
            }
        }

        let encrypted_secret: Vec<u8> = row.get("encrypted_secret_key");
        let decrypted_secret = match key_manager.decrypt(&encrypted_secret).await {
            Ok(secret) => secret,
            Err(e) => {
                failed += 1;
                println!(
                    "[{processed}] FAIL pubkey={} reason=decrypt_error:{}",
                    pubkey, e
                );
                continue;
            }
        };

        let secret_key = match nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret) {
            Ok(key) => key,
            Err(e) => {
                failed += 1;
                println!(
                    "[{processed}] FAIL pubkey={} reason=invalid_secret_key:{}",
                    pubkey, e
                );
                continue;
            }
        };

        let keys = Keys::new(secret_key.into());
        let derived_pubkey = keys.public_key().to_hex();
        if derived_pubkey != pubkey {
            failed += 1;
            println!(
                "[{processed}] FAIL pubkey={} reason=pubkey_mismatch:{}",
                pubkey, derived_pubkey
            );
            continue;
        }

        match relay_list_publisher::publish_minimum_relay_list(&keys).await {
            Ok(outcomes) => {
                let success_count = outcomes.iter().filter(|outcome| outcome.success).count();
                if success_count == outcomes.len() {
                    published_ok += 1;
                    println!(
                        "[{processed}] OK pubkey={} indexers={}/3",
                        pubkey, success_count
                    );
                } else if success_count > 0 {
                    published_partial += 1;
                    println!(
                        "[{processed}] PARTIAL pubkey={} indexers={}/3",
                        pubkey, success_count
                    );
                } else {
                    failed += 1;
                    println!(
                        "[{processed}] FAIL pubkey={} reason=indexers_rejected indexers={}/3",
                        pubkey, success_count
                    );
                }
            }
            Err(e) => {
                failed += 1;
                println!(
                    "[{processed}] FAIL pubkey={} reason=publish_setup:{}",
                    pubkey, e
                );
            }
        }
    }

    println!("--- Summary ---");
    println!("processed={}", processed);
    println!("published_ok={}", published_ok);
    println!("published_partial={}", published_partial);
    println!("skipped_existing={}", skipped_existing);
    println!("skipped_unknown={}", skipped_unknown);
    println!("failed={}", failed);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_dry_run_env, parse_live_run_env, summarize_existing_kind10002_results,
        ExistingKind10002Status,
    };

    #[test]
    fn dry_run_defaults_to_true() {
        assert_eq!(parse_dry_run_env(None).expect("parse should succeed"), true);
    }

    #[test]
    fn dry_run_accepts_truthy_values() {
        for raw in ["1", "true", "TRUE", "yes", " yes "] {
            assert_eq!(
                parse_dry_run_env(Some(raw.to_string())).expect("parse should succeed"),
                true
            );
        }
    }

    #[test]
    fn dry_run_accepts_live_values() {
        for raw in ["0", "false", "FALSE", "no", " no "] {
            assert_eq!(
                parse_dry_run_env(Some(raw.to_string())).expect("parse should succeed"),
                false
            );
        }
    }

    #[test]
    fn dry_run_rejects_invalid_values() {
        for raw in ["", "on", "off", "truthy", "f", "n"] {
            assert!(parse_dry_run_env(Some(raw.to_string())).is_err());
        }
    }

    #[test]
    fn live_run_is_optional() {
        assert_eq!(
            parse_live_run_env(None).expect("parse should succeed"),
            None
        );
    }

    #[test]
    fn live_run_accepts_truthy_values() {
        for raw in ["1", "true", "TRUE", "yes", " yes "] {
            assert_eq!(
                parse_live_run_env(Some(raw.to_string())).expect("parse should succeed"),
                Some(true)
            );
        }
    }

    #[test]
    fn live_run_accepts_false_values() {
        for raw in ["0", "false", "FALSE", "no", " no "] {
            assert_eq!(
                parse_live_run_env(Some(raw.to_string())).expect("parse should succeed"),
                Some(false)
            );
        }
    }

    #[test]
    fn live_run_rejects_invalid_values() {
        for raw in ["", "on", "off", "truthy", "f", "n"] {
            assert!(parse_live_run_env(Some(raw.to_string())).is_err());
        }
    }

    #[test]
    fn existing_kind10002_status_found_if_any_indexer_has_event() {
        let status = summarize_existing_kind10002_results(&[
            Err("relay down".to_string()),
            Ok(true),
            Ok(false),
        ]);
        assert_eq!(status, ExistingKind10002Status::Found);
    }

    #[test]
    fn existing_kind10002_status_not_found_only_when_all_false() {
        let status = summarize_existing_kind10002_results(&[Ok(false), Ok(false), Ok(false)]);
        assert_eq!(status, ExistingKind10002Status::NotFound);
    }

    #[test]
    fn existing_kind10002_status_unknown_when_all_indexers_error() {
        let status = summarize_existing_kind10002_results(&[
            Err("one".to_string()),
            Err("two".to_string()),
            Err("three".to_string()),
        ]);
        assert_eq!(status, ExistingKind10002Status::Unknown);
    }

    #[test]
    fn existing_kind10002_status_unknown_when_mix_false_and_errors() {
        let status =
            summarize_existing_kind10002_results(&[Ok(false), Err("two".to_string()), Ok(false)]);
        assert_eq!(status, ExistingKind10002Status::Unknown);
    }
}
