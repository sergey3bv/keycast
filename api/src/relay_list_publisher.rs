// ABOUTME: Publishes NIP-65 kind:10002 relay lists for newly created accounts
// ABOUTME: Fans out signed events to indexer relays with per-indexer telemetry

use nostr_sdk::{Client, Event, EventBuilder, Keys, Kind, Tag};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;

pub const DISCOVERY_RELAY: &str = "wss://relay.divine.video";
pub const INDEXER_RELAYS: [&str; 3] = [
    "wss://purplepag.es",
    "wss://user.kindpag.es",
    "wss://relay.nos.social",
];

const ADD_RELAY_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const SEND_EVENT_TIMEOUT: Duration = Duration::from_secs(4);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error)]
pub enum RelayListPublisherError {
    #[error("failed to create relay tag for {relay}: {reason}")]
    InvalidRelayTag { relay: String, reason: String },
    #[error("failed to sign kind:10002 relay list event: {0}")]
    Signing(String),
}

#[derive(Debug, Clone)]
pub struct IndexerPublishOutcome {
    pub relay: String,
    pub success: bool,
    pub error: Option<String>,
}

fn normalize_relay_url(relay: &str) -> String {
    relay.trim_end_matches('/').to_ascii_lowercase()
}

fn classify_send_event_outcome(
    indexer: &str,
    success_relays: &[String],
    failed_relays: &[(String, String)],
) -> Result<(), String> {
    let normalized_indexer = normalize_relay_url(indexer);

    if success_relays
        .iter()
        .any(|relay| normalize_relay_url(relay) == normalized_indexer)
    {
        return Ok(());
    }

    if let Some((_, reason)) = failed_relays
        .iter()
        .find(|(relay, _)| normalize_relay_url(relay) == normalized_indexer)
    {
        return Err(format!("send_event rejected: {}", reason));
    }

    Err("send_event not accepted by target relay".to_string())
}

fn build_relay_tags(relays: &[&str]) -> Result<Vec<Tag>, RelayListPublisherError> {
    relays
        .iter()
        .map(|relay| {
            Tag::parse(vec!["r".to_string(), relay.to_string()]).map_err(|e| {
                RelayListPublisherError::InvalidRelayTag {
                    relay: relay.to_string(),
                    reason: e.to_string(),
                }
            })
        })
        .collect()
}

pub fn build_relay_list_event(
    keys: &Keys,
    relays: &[&str],
) -> Result<Event, RelayListPublisherError> {
    let tags = build_relay_tags(relays)?;
    EventBuilder::new(Kind::Custom(10002), "")
        .tags(tags)
        .sign_with_keys(keys)
        .map_err(|e| RelayListPublisherError::Signing(e.to_string()))
}

async fn publish_event_to_indexer(keys: Keys, indexer: &str, event: &Event) -> Result<(), String> {
    let client = Client::new(keys);
    let publish_result = async {
        let add_result = tokio::time::timeout(ADD_RELAY_TIMEOUT, client.add_relay(indexer)).await;
        match add_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("add_relay failed: {}", e)),
            Err(_) => return Err("add_relay timed out".to_string()),
        }

        client
            .try_connect_relay(indexer, CONNECT_TIMEOUT)
            .await
            .map_err(|e| format!("connect failed: {}", e))?;

        let send_result = tokio::time::timeout(SEND_EVENT_TIMEOUT, client.send_event(event)).await;
        match send_result {
            Ok(Ok(output)) => {
                let success_relays: Vec<String> = output
                    .success
                    .iter()
                    .map(|relay| relay.to_string())
                    .collect();
                let failed_relays: Vec<(String, String)> = output
                    .failed
                    .iter()
                    .map(|(relay, error)| (relay.to_string(), error.to_string()))
                    .collect();
                classify_send_event_outcome(indexer, &success_relays, &failed_relays)
            }
            Ok(Err(e)) => Err(format!("send_event failed: {}", e)),
            Err(_) => Err("send_event timed out".to_string()),
        }
    }
    .await;

    if tokio::time::timeout(DISCONNECT_TIMEOUT, client.disconnect())
        .await
        .is_err()
    {
        tracing::debug!(
            relay = %indexer,
            "Timed out while disconnecting relay client"
        );
    }

    publish_result
}

pub async fn publish_to_indexers_with<F, Fut>(
    event: &Event,
    indexers: &[&str],
    mut publish_one: F,
) -> Vec<IndexerPublishOutcome>
where
    F: FnMut(&str, &Event) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let mut outcomes = Vec::with_capacity(indexers.len());

    for indexer in indexers {
        let outcome = match publish_one(indexer, event).await {
            Ok(()) => IndexerPublishOutcome {
                relay: indexer.to_string(),
                success: true,
                error: None,
            },
            Err(error) => IndexerPublishOutcome {
                relay: indexer.to_string(),
                success: false,
                error: Some(error),
            },
        };

        outcomes.push(outcome);
    }

    outcomes
}

pub async fn publish_minimum_relay_list(
    keys: &Keys,
) -> Result<Vec<IndexerPublishOutcome>, RelayListPublisherError> {
    let event = build_relay_list_event(keys, &[DISCOVERY_RELAY])?;
    let user_pubkey = keys.public_key().to_hex();

    let keys_for_publish = keys.clone();
    let outcomes = publish_to_indexers_with(&event, &INDEXER_RELAYS, move |indexer, event| {
        let keys = keys_for_publish.clone();
        let relay = indexer.to_string();
        let event = event.clone();
        async move { publish_event_to_indexer(keys, &relay, &event).await }
    })
    .await;

    for outcome in &outcomes {
        if outcome.success {
            tracing::info!(
                event = "relay_list_publish_success",
                user_pubkey = %user_pubkey,
                relay = %outcome.relay,
                kind = 10002,
                "Published kind:10002 relay list to indexer"
            );
        } else {
            tracing::warn!(
                event = "relay_list_publish_failed",
                user_pubkey = %user_pubkey,
                relay = %outcome.relay,
                kind = 10002,
                error = %outcome.error.as_deref().unwrap_or("unknown"),
                "Failed publishing kind:10002 relay list to indexer"
            );
        }
    }

    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn relay_list_event_contains_required_relay_tag() {
        let keys = Keys::generate();
        let event = build_relay_list_event(&keys, &[DISCOVERY_RELAY]).expect("event should build");

        assert_eq!(event.kind, Kind::Custom(10002));
        let tags: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0], vec!["r".to_string(), DISCOVERY_RELAY.to_string()]);
    }

    #[tokio::test]
    async fn fanout_attempts_every_indexer_even_with_failures() {
        let keys = Keys::generate();
        let event = build_relay_list_event(&keys, &[DISCOVERY_RELAY]).expect("event should build");

        let attempted_relays: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let attempted_relays_cloned = attempted_relays.clone();

        let outcomes = publish_to_indexers_with(&event, &INDEXER_RELAYS, move |indexer, _| {
            let attempted_relays = attempted_relays_cloned.clone();
            let indexer = indexer.to_string();
            async move {
                attempted_relays
                    .lock()
                    .expect("lock should succeed")
                    .push(indexer.clone());
                if indexer == INDEXER_RELAYS[1] {
                    Err("simulated failure".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert_eq!(outcomes.len(), INDEXER_RELAYS.len());
        assert_eq!(outcomes.iter().filter(|o| o.success).count(), 2);
        assert_eq!(outcomes.iter().filter(|o| !o.success).count(), 1);

        let attempted = attempted_relays
            .lock()
            .expect("lock should succeed")
            .clone();
        assert_eq!(
            attempted,
            INDEXER_RELAYS
                .iter()
                .map(|relay| relay.to_string())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn classify_send_event_outcome_accepts_when_target_is_successful() {
        let result = classify_send_event_outcome(
            "wss://purplepag.es",
            &["wss://purplepag.es/".to_string()],
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn classify_send_event_outcome_returns_rejection_reason() {
        let result = classify_send_event_outcome(
            "wss://purplepag.es",
            &[],
            &[(
                "wss://purplepag.es".to_string(),
                "auth required".to_string(),
            )],
        );
        assert_eq!(
            result,
            Err("send_event rejected: auth required".to_string())
        );
    }

    #[test]
    fn classify_send_event_outcome_returns_not_accepted_when_missing() {
        let result = classify_send_event_outcome("wss://purplepag.es", &[], &[]);
        assert_eq!(
            result,
            Err("send_event not accepted by target relay".to_string())
        );
    }
}
