use crate::relay_list_publisher;
use crate::state::KeycastState;
use chrono::{Duration as ChronoDuration, Utc};
use keycast_core::repositories::RelayListPublishPendingRepository;
use nostr_sdk::Keys;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

const WORKER_INTERVAL: Duration = Duration::from_secs(5);
const CLAIM_BATCH_SIZE: i64 = 25;
const BASE_RETRY_SECONDS: i64 = 5;
const MAX_RETRY_SECONDS: i64 = 300;

fn retry_delay_for_attempt(attempts: i32) -> Duration {
    let exponent = attempts.saturating_sub(1).clamp(0, 6) as u32;
    let seconds = (BASE_RETRY_SECONDS * (1_i64 << exponent)).min(MAX_RETRY_SECONDS);
    Duration::from_secs(seconds as u64)
}

fn relay_publish_error_message(outcomes: &[relay_list_publisher::IndexerPublishOutcome]) -> String {
    let failed: Vec<String> = outcomes
        .iter()
        .filter(|outcome| !outcome.success)
        .map(|outcome| {
            format!(
                "{}:{}",
                outcome.relay,
                outcome.error.as_deref().unwrap_or("unknown")
            )
        })
        .collect();

    if failed.is_empty() {
        "publish did not report relay failures".to_string()
    } else {
        format!("relay publish failures: {}", failed.join(" | "))
    }
}

pub async fn run_relay_list_publish_worker(state: Arc<KeycastState>, shutdown: Arc<Notify>) {
    let repo = RelayListPublishPendingRepository::new(state.db.clone());
    let mut interval = tokio::time::interval(WORKER_INTERVAL);

    loop {
        if !wait_for_tick_or_shutdown(&mut interval, shutdown.as_ref()).await {
            tracing::info!("Relay-list publish worker received shutdown signal");
            return;
        }

        let jobs = match repo.claim_due(CLAIM_BATCH_SIZE).await {
            Ok(jobs) => jobs,
            Err(e) => {
                tracing::error!(
                    event = "relay_list_publish_worker_claim_failed",
                    error = %e,
                    "Failed claiming pending relay-list publish jobs"
                );
                continue;
            }
        };

        for job in jobs {
            let retry_delay = retry_delay_for_attempt(job.attempts);
            let next_attempt_at = Utc::now()
                + ChronoDuration::from_std(retry_delay)
                    .unwrap_or_else(|_| ChronoDuration::seconds(MAX_RETRY_SECONDS));

            let job_result = async {
                let decrypted_secret = state
                    .key_manager
                    .decrypt(&job.encrypted_secret_key)
                    .await
                    .map_err(|e| format!("decrypt failed: {}", e))?;

                let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&decrypted_secret)
                    .map_err(|e| format!("invalid secret key: {}", e))?;
                let keys = Keys::new(secret_key.into());
                let derived_pubkey = keys.public_key().to_hex();
                if derived_pubkey != job.user_pubkey {
                    return Err(format!(
                        "pubkey mismatch derived={} expected={}",
                        derived_pubkey, job.user_pubkey
                    ));
                }

                let outcomes = relay_list_publisher::publish_minimum_relay_list(&keys)
                    .await
                    .map_err(|e| format!("publish setup failed: {}", e))?;

                if outcomes.iter().all(|outcome| outcome.success) {
                    Ok(())
                } else {
                    Err(relay_publish_error_message(&outcomes))
                }
            }
            .await;

            match job_result {
                Ok(()) => {
                    if let Err(e) = repo.mark_succeeded(job.id).await {
                        tracing::error!(
                            event = "relay_list_publish_worker_mark_success_failed",
                            job_id = job.id,
                            tenant_id = job.tenant_id,
                            user_pubkey = %job.user_pubkey,
                            error = %e,
                            "Failed removing completed relay-list publish job"
                        );
                    } else {
                        tracing::info!(
                            event = "relay_list_publish_worker_job_succeeded",
                            job_id = job.id,
                            tenant_id = job.tenant_id,
                            user_pubkey = %job.user_pubkey,
                            attempts = job.attempts,
                            "Relay-list publish job completed"
                        );
                    }
                }
                Err(error) => {
                    if let Err(repo_err) = repo.reschedule(job.id, next_attempt_at, &error).await {
                        tracing::error!(
                            event = "relay_list_publish_worker_reschedule_failed",
                            job_id = job.id,
                            tenant_id = job.tenant_id,
                            user_pubkey = %job.user_pubkey,
                            attempts = job.attempts,
                            error = %repo_err,
                            publish_error = %error,
                            "Failed rescheduling relay-list publish job"
                        );
                    } else {
                        tracing::warn!(
                            event = "relay_list_publish_worker_job_failed",
                            job_id = job.id,
                            tenant_id = job.tenant_id,
                            user_pubkey = %job.user_pubkey,
                            attempts = job.attempts,
                            retry_in_seconds = retry_delay.as_secs(),
                            error = %error,
                            "Relay-list publish job failed; scheduled retry"
                        );
                    }
                }
            };
        }
    }
}

pub fn spawn_relay_list_publish_worker(
    state: Arc<KeycastState>,
    shutdown: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_relay_list_publish_worker(state, shutdown))
}

async fn wait_for_tick_or_shutdown(
    interval: &mut tokio::time::Interval,
    shutdown: &Notify,
) -> bool {
    tokio::select! {
        _ = shutdown.notified() => false,
        _ = interval.tick() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_for_tick_returns_false_after_shutdown_signal() {
        let shutdown = Arc::new(Notify::new());
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let shutdown_for_task = shutdown.clone();
        let wait_handle = tokio::spawn(async move {
            wait_for_tick_or_shutdown(&mut interval, shutdown_for_task.as_ref()).await
        });

        tokio::task::yield_now().await;
        shutdown.notify_waiters();
        let keep_running = tokio::time::timeout(Duration::from_secs(2), wait_handle)
            .await
            .expect("wait should finish quickly")
            .expect("task should complete");
        assert!(!keep_running, "shutdown should stop worker loop");
    }
}
