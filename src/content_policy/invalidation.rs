use std::{process, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use prost::Message;
use rdkafka::{
    ClientConfig, Message as KafkaMessage,
    consumer::{CommitMode, Consumer, StreamConsumer},
    message::Headers,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::AppConfig;

use super::{Authority, PolicyScope, ReloadError, service::ContentPolicyRuntime};

pub const CONTENT_POLICY_INVALIDATED_EVENT_TYPE: &str =
    "interchat.trust-safety.content-policy.invalidated.v1";

/// Wire-compatible source for the canonical invalidation event. This compact
/// event intentionally carries no rule data: each replica reloads only the
/// named authoritative scope from PostgreSQL on the cold path.
#[derive(Clone, PartialEq, Message)]
pub struct ContentPolicyInvalidated {
    #[prost(string, tag = "1")]
    pub authority: String,
    #[prost(string, tag = "2")]
    pub scope_id: String,
    #[prost(uint64, tag = "3")]
    pub version: u64,
    #[prost(message, optional, tag = "4")]
    pub occurred_at: Option<prost_types::Timestamp>,
}

const RELOAD_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(250),
    Duration::from_millis(500),
];

/// Reconciliation is a safety net for missed Kafka deliveries, not the normal
/// content-policy propagation path.
pub const DEFAULT_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedContentPolicyInvalidation {
    pub scope: PolicyScope,
    pub version: u64,
}

impl TryFrom<ContentPolicyInvalidated> for ParsedContentPolicyInvalidation {
    type Error = anyhow::Error;

    fn try_from(event: ContentPolicyInvalidated) -> Result<Self, Self::Error> {
        let authority = match event.authority.as_str() {
            "GLOBAL" => Authority::Global,
            "HUB" => Authority::Hub,
            "SERVER" => Authority::Server,
            value => anyhow::bail!("unknown content policy authority {value:?}"),
        };
        ensure!(
            event.version > 0,
            "content policy invalidation version is zero"
        );

        let scope = PolicyScope {
            authority,
            id: event.scope_id,
        };
        scope.validate().map_err(|error| anyhow::anyhow!(error))?;
        Ok(Self {
            scope,
            version: event.version,
        })
    }
}

pub fn parse_content_policy_invalidation(
    payload: &[u8],
) -> anyhow::Result<ParsedContentPolicyInvalidation> {
    ContentPolicyInvalidated::decode(payload)
        .context("content policy invalidation is not valid protobuf")?
        .try_into()
}

pub fn validate_content_policy_invalidation_headers<H: Headers>(
    headers: Option<&H>,
) -> Result<(), &'static str> {
    let Some(headers) = headers else {
        return Err("CLOUDEVENT_HEADERS_MISSING");
    };
    if header_value(headers, "ce_specversion") != Some(b"1.0".as_slice()) {
        return Err("CLOUDEVENT_SPECVERSION_INVALID");
    }
    if header_value(headers, "ce_type") != Some(CONTENT_POLICY_INVALIDATED_EVENT_TYPE.as_bytes()) {
        return Err("CLOUDEVENT_TYPE_INVALID");
    }
    if header_value(headers, "ce_datacontenttype") != Some(b"application/protobuf".as_slice()) {
        return Err("CLOUDEVENT_CONTENT_TYPE_INVALID");
    }
    for required in ["ce_id", "ce_source", "ce_time"] {
        if header_value(headers, required).is_none_or(|value| value.is_empty()) {
            return Err("CLOUDEVENT_REQUIRED_HEADER_MISSING");
        }
    }
    Ok(())
}

fn header_value<'a, H: Headers>(headers: &'a H, name: &str) -> Option<&'a [u8]> {
    (0..headers.count()).find_map(|index| {
        let header = headers.get(index);
        (header.key == name).then_some(header.value).flatten()
    })
}

/// Build a replica-local group. A shared group would load-balance invalidations
/// and leave some replicas with stale snapshots.
pub fn content_policy_consumer_group(base_group: &str, hostname: &str, process_id: u32) -> String {
    format!(
        "{}-content-policy-{}-{}",
        base_group,
        group_identity_component(hostname),
        process_id
    )
}

fn group_identity_component(value: &str) -> String {
    let component = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    if component.is_empty() {
        "unknown".to_owned()
    } else {
        component
    }
}

fn local_hostname() -> String {
    hostname::get()
        .ok()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

pub struct ContentPolicyInvalidationConsumer {
    consumer: StreamConsumer,
    topic: String,
    runtime: Arc<ContentPolicyRuntime>,
    cancel: CancellationToken,
}

impl ContentPolicyInvalidationConsumer {
    pub fn new(
        config: &AppConfig,
        runtime: Arc<ContentPolicyRuntime>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        let group_id =
            content_policy_consumer_group(&config.kafka_group_id, &local_hostname(), process::id());
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set("group.id", &group_id)
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("auto.offset.reset", "earliest")
            .set("isolation.level", "read_committed")
            .create()?;
        consumer.subscribe(&[&config.content_policy_invalidation_topic])?;
        Ok(Self {
            consumer,
            topic: config.content_policy_invalidation_topic.clone(),
            runtime,
            cancel,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(topic = %self.topic, "content policy invalidation consumer started");
        loop {
            let message = tokio::select! {
                _ = self.cancel.cancelled() => break,
                message = self.consumer.recv() => match message {
                    Ok(message) => message,
                    Err(error) => {
                        warn!(error = %error, "content policy invalidation receive failed");
                        continue;
                    }
                },
            };

            let Some(payload) = message.payload() else {
                warn!("content policy invalidation payload is missing; skipping poison message");
                self.consumer.commit_message(&message, CommitMode::Sync)?;
                continue;
            };
            if let Err(reason) = validate_content_policy_invalidation_headers(message.headers()) {
                warn!(
                    reason,
                    "invalid content policy invalidation headers; skipping poison message"
                );
                self.consumer.commit_message(&message, CommitMode::Sync)?;
                continue;
            }
            let invalidation = match parse_content_policy_invalidation(payload) {
                Ok(invalidation) => invalidation,
                Err(error) => {
                    warn!(error = %error, "invalid content policy invalidation protobuf; skipping poison message");
                    self.consumer.commit_message(&message, CommitMode::Sync)?;
                    continue;
                }
            };
            self.reload_with_retry(&invalidation).await?;

            // The offset is committed only after the version is visible and the
            // corresponding snapshot has been atomically replaced/removed.
            self.consumer.commit_message(&message, CommitMode::Sync)?;
        }
        info!(topic = %self.topic, "content policy invalidation consumer stopped");
        Ok(())
    }

    async fn reload_with_retry(
        &self,
        invalidation: &ParsedContentPolicyInvalidation,
    ) -> anyhow::Result<()> {
        // One attempt per retry delay, plus a final attempt with no delay after it.
        let schedule = RELOAD_RETRY_DELAYS
            .iter()
            .copied()
            .map(Some)
            .chain(std::iter::once(None));
        for (attempt, retry_delay) in schedule.enumerate() {
            match self
                .runtime
                .reload_scope(&invalidation.scope, invalidation.version)
                .await
            {
                Ok(_) => return Ok(()),
                Err(ReloadError::VersionNotVisible { loaded, .. }) if retry_delay.is_some() => {
                    let delay = retry_delay.unwrap_or_default();
                    debug!(
                        scope = ?invalidation.scope,
                        expected_version = invalidation.version,
                        loaded_version = loaded,
                        attempt = attempt + 1,
                        "content policy version is not visible yet; retrying"
                    );
                    tokio::select! {
                        _ = self.cancel.cancelled() => {
                            anyhow::bail!("content policy invalidation cancelled during retry")
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
                Err(error) => {
                    error!(
                        error = %error,
                        scope = ?invalidation.scope,
                        expected_version = invalidation.version,
                        "content policy invalidation reload failed"
                    );
                    return Err(error.into());
                }
            }
        }
        unreachable!("content policy reload retry loop always returns")
    }
}

pub struct ContentPolicyReconciliationTask {
    runtime: Arc<ContentPolicyRuntime>,
    interval: Duration,
    cancel: CancellationToken,
}

impl ContentPolicyReconciliationTask {
    pub fn new(runtime: Arc<ContentPolicyRuntime>, cancel: CancellationToken) -> Self {
        Self {
            runtime,
            interval: DEFAULT_RECONCILIATION_INTERVAL,
            cancel,
        }
    }

    pub fn with_interval(
        runtime: Arc<ContentPolicyRuntime>,
        interval: Duration,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        ensure!(
            !interval.is_zero(),
            "content policy reconciliation interval must be greater than zero"
        );
        Ok(Self {
            runtime,
            interval,
            cancel,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(interval = ?self.interval, "content policy reconciliation task started");
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = tokio::time::sleep(self.interval) => {
                    match self.runtime.reconcile().await {
                        Ok(scope_count) => debug!(scope_count, "content policy reconciliation completed"),
                        Err(error) => warn!(error = %error, "content policy reconciliation failed"),
                    }
                }
            }
        }
        info!("content policy reconciliation task stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdkafka::message::{Header, OwnedHeaders};

    fn headers(event_type: &str, content_type: &str) -> OwnedHeaders {
        OwnedHeaders::new()
            .insert(Header {
                key: "ce_specversion",
                value: Some("1.0"),
            })
            .insert(Header {
                key: "ce_type",
                value: Some(event_type),
            })
            .insert(Header {
                key: "ce_source",
                value: Some("/polarizer"),
            })
            .insert(Header {
                key: "ce_id",
                value: Some("event-1"),
            })
            .insert(Header {
                key: "ce_time",
                value: Some("2026-08-10T00:00:00Z"),
            })
            .insert(Header {
                key: "ce_datacontenttype",
                value: Some(content_type),
            })
    }

    #[test]
    fn parses_global_hub_and_server_scopes() {
        for (authority, scope_id, expected) in [
            ("GLOBAL", "", PolicyScope::global()),
            ("HUB", "hub-1", PolicyScope::hub("hub-1")),
            ("SERVER", "server-1", PolicyScope::server("server-1")),
        ] {
            let payload = ContentPolicyInvalidated {
                authority: authority.into(),
                scope_id: scope_id.into(),
                version: 7,
                occurred_at: None,
            }
            .encode_to_vec();
            let parsed = parse_content_policy_invalidation(&payload).unwrap();
            assert_eq!(parsed.scope, expected);
            assert_eq!(parsed.version, 7);
        }
    }

    #[test]
    fn rejects_invalid_scope_and_protobuf_contracts() {
        let event = ContentPolicyInvalidated {
            authority: "GLOBAL".into(),
            scope_id: "unexpected".into(),
            version: 1,
            occurred_at: None,
        };
        assert!(parse_content_policy_invalidation(&event.encode_to_vec()).is_err());
        assert!(parse_content_policy_invalidation(&[0xff]).is_err());
    }

    #[test]
    fn validates_content_policy_cloud_event_headers() {
        let valid = headers(
            CONTENT_POLICY_INVALIDATED_EVENT_TYPE,
            "application/protobuf",
        );
        assert_eq!(
            validate_content_policy_invalidation_headers(Some(&valid)),
            Ok(())
        );
        let wrong_type = headers("interchat.other.v1", "application/protobuf");
        assert_eq!(
            validate_content_policy_invalidation_headers(Some(&wrong_type)),
            Err("CLOUDEVENT_TYPE_INVALID")
        );
        let wrong_content_type = headers(CONTENT_POLICY_INVALIDATED_EVENT_TYPE, "application/json");
        assert_eq!(
            validate_content_policy_invalidation_headers(Some(&wrong_content_type)),
            Err("CLOUDEVENT_CONTENT_TYPE_INVALID")
        );
    }

    #[test]
    fn replica_groups_are_unique_and_derived_from_base_group() {
        let first = content_policy_consumer_group("polarizer", "worker-a", 101);
        let second = content_policy_consumer_group("polarizer", "worker-a", 102);
        let other_replica = content_policy_consumer_group("polarizer", "worker-b", 101);
        assert_ne!(first, second);
        assert_ne!(first, other_replica);
        assert!(first.starts_with("polarizer-content-policy-"));
    }

    #[test]
    fn reconciliation_interval_defaults_to_safety_net_cadence() {
        assert_eq!(DEFAULT_RECONCILIATION_INTERVAL, Duration::from_secs(300));
    }
}
