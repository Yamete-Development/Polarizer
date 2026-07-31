use std::{sync::Arc, time::Duration};

use prost::Message as ProstMessage;
use rdkafka::{
    ClientConfig, Message,
    consumer::{CommitMode, Consumer, StreamConsumer},
    message::{Header, Headers, OwnedHeaders},
    producer::{FutureProducer, FutureRecord},
};
use sqlx::{PgPool, Row};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    config::AppConfig,
    contract::v2::{self, ActionRequested, PrismDeliveryCallback},
    grpc::action_from_proto,
    health::HealthState,
    policy::{engine::PolicyEngine, repository::PostgresPolicyRepository},
};

pub struct ActionConsumer {
    consumer: StreamConsumer,
    dlq_producer: FutureProducer,
    action_topic: String,
    dlq_topic: String,
    engine: Arc<PolicyEngine>,
    health: Arc<HealthState>,
    cancel: CancellationToken,
}

pub struct DeliveryCallbackConsumer {
    consumer: StreamConsumer,
    dlq_producer: FutureProducer,
    topic: String,
    dlq_topic: String,
    repository: Arc<PostgresPolicyRepository>,
    cancel: CancellationToken,
}

pub struct StaffAuthorizationChangeConsumer {
    consumer: StreamConsumer,
    topic: String,
    db: PgPool,
    cancel: CancellationToken,
}

impl StaffAuthorizationChangeConsumer {
    pub fn new(config: &AppConfig, db: PgPool, cancel: CancellationToken) -> anyhow::Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set(
                "group.id",
                format!("{}-staff-authz-changes", config.kafka_group_id),
            )
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("auto.offset.reset", "earliest")
            .set("isolation.level", "read_committed")
            .create()?;
        consumer.subscribe(&[&config.staff_authorization_change_topic])?;
        Ok(Self {
            consumer,
            topic: config.staff_authorization_change_topic.clone(),
            db,
            cancel,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(topic=%self.topic,"staff authorization change consumer started");
        loop {
            let message = tokio::select! {_=self.cancel.cancelled()=>break,message=self.consumer.recv()=>match message{Ok(message)=>message,Err(error)=>{warn!(error=%error,"staff authorization change receive failed");continue;}}};
            let envelope: serde_json::Value =
                match serde_json::from_slice(message.payload().unwrap_or_default()) {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(error=%error,"invalid staff authorization change event");
                        self.consumer.commit_message(&message, CommitMode::Sync)?;
                        continue;
                    }
                };
            let user_id = envelope
                .pointer("/data/user_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if user_id.is_empty() {
                warn!("staff authorization change missing user_id");
                self.consumer.commit_message(&message, CommitMode::Sync)?;
                continue;
            }
            let event_id = envelope
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("iris-staff-change");
            let mut tx = self.db.begin().await?;
            sqlx::query("WITH changed AS (
                UPDATE trust_safety.report SET claimed_by=NULL,claimed_at=NULL,claim_expires_at=NULL,
                    last_claim_change_at=clock_timestamp(),updated_at=clock_timestamp(),version=version+1
                WHERE claimed_by=$1 RETURNING id
            ) INSERT INTO trust_safety.audit_log
                (request_id,actor_id,actor_type,action,resource_type,resource_id,metadata)
                SELECT $2,'iris','SERVICE','RELEASE_CLAIM_AFTER_STAFF_AUTH_CHANGE','REPORT',id::text,
                    jsonb_build_object('staff_user_id',$1) FROM changed")
                .bind(user_id).bind(event_id).execute(&mut *tx).await?;
            sqlx::query("WITH changed AS (
                UPDATE trust_safety.staff_action_request SET status='CANCELLED',decided_by='iris',
                    decision_reason='staff authorization changed',decided_at=clock_timestamp(),version=version+1
                WHERE requested_by=$1 AND status='PENDING' AND report_id IS NOT NULL RETURNING id
            ) INSERT INTO trust_safety.audit_log
                (request_id,actor_id,actor_type,action,resource_type,resource_id,metadata)
                SELECT $2,'iris','SERVICE','CANCEL_ACTION_AFTER_STAFF_AUTH_CHANGE','STAFF_ACTION_REQUEST',
                    id::text,jsonb_build_object('staff_user_id',$1) FROM changed")
                .bind(user_id).bind(event_id).execute(&mut *tx).await?;
            tx.commit().await?;
            self.consumer.commit_message(&message, CommitMode::Sync)?;
        }
        Ok(())
    }
}

impl DeliveryCallbackConsumer {
    pub fn new(
        config: &AppConfig,
        repository: Arc<PostgresPolicyRepository>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set(
                "group.id",
                format!("{}-prism-delivery", config.kafka_group_id),
            )
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("auto.offset.reset", "earliest")
            .set("isolation.level", "read_committed")
            .create()?;
        consumer.subscribe(&[&config.delivery_callback_topic])?;
        let dlq_producer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set("message.timeout.ms", "10000")
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .create()?;
        Ok(Self {
            consumer,
            dlq_producer,
            topic: config.delivery_callback_topic.clone(),
            dlq_topic: config.delivery_dlq_topic.clone(),
            repository,
            cancel,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(topic = %self.topic, "Prism delivery callback consumer started");
        loop {
            let message = tokio::select! {
                _ = self.cancel.cancelled() => break,
                message = self.consumer.recv() => match message {
                    Ok(message) => message,
                    Err(error) => { warn!(error = %error, "delivery callback receive failed"); continue; }
                },
            };
            let payload = message.payload().unwrap_or_default();
            let key = message.key().unwrap_or_default();
            if let Err(reason) =
                validate_cloud_event_headers(message.headers(), "interchat.prism.delivery.v2")
            {
                warn!(reason, "invalid delivery callback CloudEvents headers");
                publish_dlq(&self.dlq_producer, &self.dlq_topic, payload, key, reason).await?;
                self.consumer.commit_message(&message, CommitMode::Sync)?;
                continue;
            }
            let callback = match PrismDeliveryCallback::decode(payload) {
                Ok(callback) => callback,
                Err(error) => {
                    warn!(error = %error, "invalid delivery callback Protobuf");
                    publish_dlq(
                        &self.dlq_producer,
                        &self.dlq_topic,
                        payload,
                        key,
                        "PROTOBUF_DECODE_FAILED",
                    )
                    .await?;
                    self.consumer.commit_message(&message, CommitMode::Sync)?;
                    continue;
                }
            };
            let action_id = match uuid::Uuid::parse_str(&callback.action_id) {
                Ok(id) => id,
                Err(_) => {
                    publish_dlq(
                        &self.dlq_producer,
                        &self.dlq_topic,
                        payload,
                        key,
                        "ACTION_ID_INVALID",
                    )
                    .await?;
                    self.consumer.commit_message(&message, CommitMode::Sync)?;
                    continue;
                }
            };
            let state = match v2::MessageState::try_from(callback.state).unwrap_or_default() {
                v2::MessageState::Active => "ACTIVE",
                v2::MessageState::DeliveryFailed => "DELIVERY_FAILED",
                _ => {
                    publish_dlq(
                        &self.dlq_producer,
                        &self.dlq_topic,
                        payload,
                        key,
                        "STATE_INVALID",
                    )
                    .await?;
                    self.consumer.commit_message(&message, CommitMode::Sync)?;
                    continue;
                }
            };
            let applied = self
                .repository
                .apply_delivery_callback(
                    action_id,
                    state,
                    (!callback.failure_code.is_empty()).then_some(callback.failure_code.as_str()),
                )
                .await?;
            if !applied {
                warn!(%action_id, state, "delivery callback did not match a pending action");
            }
            self.consumer.commit_message(&message, CommitMode::Sync)?;
        }
        info!("Prism delivery callback consumer stopped");
        Ok(())
    }
}

impl ActionConsumer {
    pub fn new(
        config: &AppConfig,
        engine: Arc<PolicyEngine>,
        health: Arc<HealthState>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set("group.id", &config.kafka_group_id)
            .set("enable.auto.commit", "false")
            .set("enable.auto.offset.store", "false")
            .set("auto.offset.reset", "earliest")
            .set("isolation.level", "read_committed")
            .set("max.poll.interval.ms", "300000")
            .create()?;
        consumer.subscribe(&[&config.action_topic])?;
        let dlq_producer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set("message.timeout.ms", "10000")
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .create()?;
        Ok(Self {
            consumer,
            dlq_producer,
            action_topic: config.action_topic.clone(),
            dlq_topic: config.dlq_topic.clone(),
            engine,
            health,
            cancel,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(topic = %self.action_topic, "binary Protobuf action consumer started");
        loop {
            let message = tokio::select! {
                _ = self.cancel.cancelled() => break,
                message = self.consumer.recv() => match message {
                    Ok(message) => message,
                    Err(error) => { warn!(error = %error, "Kafka receive failed"); continue; }
                },
            };
            let payload = message.payload().unwrap_or_default();
            let partition_key = message.key().unwrap_or_default();
            if let Err(reason) = validate_cloud_event_headers(
                message.headers(),
                "interchat.trust-safety.action.requested.v2",
            ) {
                warn!(reason, "invalid action CloudEvents headers; routing to DLQ");
                self.publish_dlq(payload, partition_key, reason).await?;
                self.consumer.commit_message(&message, CommitMode::Sync)?;
                self.health.record_evaluation(false);
                continue;
            }
            let requested = match ActionRequested::decode(payload) {
                Ok(requested) => requested,
                Err(error) => {
                    warn!(error = %error, partition = message.partition(), offset = message.offset(), "invalid action Protobuf; routing to DLQ");
                    self.publish_dlq(payload, partition_key, "PROTOBUF_DECODE_FAILED")
                        .await?;
                    self.consumer.commit_message(&message, CommitMode::Sync)?;
                    self.health.record_evaluation(false);
                    continue;
                }
            };
            let Some(action_proto) = requested.action else {
                self.publish_dlq(payload, partition_key, "ACTION_MISSING")
                    .await?;
                self.consumer.commit_message(&message, CommitMode::Sync)?;
                self.health.record_evaluation(false);
                continue;
            };
            let mut action = match action_from_proto(action_proto) {
                Ok(action) => action,
                Err(status) => {
                    self.publish_dlq(
                        payload,
                        partition_key,
                        &format!("ACTION_INVALID_{}", status.code() as i32),
                    )
                    .await?;
                    self.consumer.commit_message(&message, CommitMode::Sync)?;
                    self.health.record_evaluation(false);
                    continue;
                }
            };
            action.prism_payload = requested
                .prism_payload
                .map(|payload| payload.encode_to_vec());

            let mut processed = false;
            for attempt in 1..=3u32 {
                match self.engine.evaluate_with_shadow(&action).await {
                    Ok(_) => {
                        processed = true;
                        break;
                    }
                    Err(error) => {
                        error!(error = %error, action_id = %action.id, attempt, "action evaluation failed");
                        if attempt < 3 {
                            tokio::time::sleep(Duration::from_millis(100 * (1 << (attempt - 1))))
                                .await;
                        }
                    }
                }
            }
            if !processed {
                self.publish_dlq(payload, partition_key, "EVALUATION_FAILED")
                    .await?;
                self.health.record_evaluation(false);
            } else {
                self.health.record_evaluation(true);
            }
            self.consumer.commit_message(&message, CommitMode::Sync)?;
        }
        info!("action consumer stopped");
        Ok(())
    }

    async fn publish_dlq(
        &self,
        payload: &[u8],
        key: &[u8],
        error_code: &str,
    ) -> anyhow::Result<()> {
        publish_dlq(
            &self.dlq_producer,
            &self.dlq_topic,
            payload,
            key,
            error_code,
        )
        .await
    }
}

fn validate_cloud_event_headers<H: Headers>(
    headers: Option<&H>,
    expected_type: &str,
) -> Result<(), &'static str> {
    let Some(headers) = headers else {
        return Err("CLOUDEVENT_HEADERS_MISSING");
    };
    if header_value(headers, "ce_specversion") != Some(b"1.0".as_slice()) {
        return Err("CLOUDEVENT_SPECVERSION_INVALID");
    }
    if header_value(headers, "ce_type") != Some(expected_type.as_bytes()) {
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

pub struct OutboxRelay {
    db: PgPool,
    producer: FutureProducer,
    cancel: CancellationToken,
}

impl OutboxRelay {
    pub fn new(db: PgPool, config: &AppConfig, cancel: CancellationToken) -> anyhow::Result<Self> {
        let producer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka_brokers)
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .set("message.timeout.ms", "10000")
            .create()?;
        Ok(Self {
            db,
            producer,
            cancel,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                result = self.relay_batch() => {
                    match result {
                        Ok(0) => tokio::time::sleep(Duration::from_millis(100)).await,
                        Ok(_) => {},
                        Err(error) => { error!(error = %error, "outbox relay batch failed"); tokio::time::sleep(Duration::from_secs(1)).await; }
                    }
                }
            }
        }
        Ok(())
    }

    async fn relay_batch(&self) -> anyhow::Result<usize> {
        let lease_token = uuid::Uuid::now_v7();
        let rows = sqlx::query(
            "WITH candidates AS ( \
                 SELECT id FROM trust_safety.outbox \
                 WHERE (status IN ('PENDING', 'FAILED') AND available_at <= clock_timestamp()) \
                    OR (status = 'CLAIMED' AND lease_expires_at <= clock_timestamp()) \
                 ORDER BY created_at LIMIT 25 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE trust_safety.outbox AS outbox \
             SET status = 'CLAIMED', lease_token = $1, \
                 lease_expires_at = clock_timestamp() + INTERVAL '5 minutes' \
             FROM candidates WHERE outbox.id = candidates.id \
             RETURNING outbox.id, outbox.topic, outbox.partition_key, outbox.headers, outbox.payload",
        )
        .bind(lease_token)
        .fetch_all(&self.db)
        .await?;
        let count = rows.len();
        for row in rows {
            let id: uuid::Uuid = row.try_get("id")?;
            let topic: String = row.try_get("topic")?;
            let key: String = row.try_get("partition_key")?;
            let payload: Vec<u8> = row.try_get("payload")?;
            let header_json: serde_json::Value = row.try_get("headers")?;
            let mut headers = OwnedHeaders::new();
            if let Some(values) = header_json.as_object() {
                for (name, value) in values {
                    if let Some(value) = value.as_str() {
                        headers = headers.insert(Header {
                            key: name,
                            value: Some(value),
                        });
                    }
                }
            }
            let result = self
                .producer
                .send(
                    FutureRecord::to(&topic)
                        .payload(&payload)
                        .key(&key)
                        .headers(headers),
                    Duration::from_secs(10),
                )
                .await;
            match result {
                Ok(_) => {
                    sqlx::query("UPDATE trust_safety.outbox SET status = 'PUBLISHED', published_at = clock_timestamp(), attempts = attempts + 1, last_error_code = NULL, lease_token = NULL, lease_expires_at = NULL WHERE id = $1 AND status = 'CLAIMED' AND lease_token = $2")
                        .bind(id).bind(lease_token).execute(&self.db).await?;
                }
                Err((error, _)) => {
                    warn!(error = %error, outbox_id = %id, "outbox publish failed");
                    sqlx::query("UPDATE trust_safety.outbox SET status = 'FAILED', attempts = attempts + 1, available_at = clock_timestamp() + make_interval(secs => LEAST(60, power(2, LEAST(attempts, 6))::int)), last_error_code = $2, lease_token = NULL, lease_expires_at = NULL WHERE id = $1 AND status = 'CLAIMED' AND lease_token = $3")
                        .bind(id).bind(error.rdkafka_error_code().map(|code| format!("{code:?}")).unwrap_or_else(|| "KAFKA_ERROR".into())).bind(lease_token).execute(&self.db).await?;
                }
            }
        }
        Ok(count)
    }
}

async fn publish_dlq(
    producer: &FutureProducer,
    topic: &str,
    payload: &[u8],
    key: &[u8],
    error_code: &str,
) -> anyhow::Result<()> {
    let headers = dlq_headers(error_code);
    producer
        .send(
            FutureRecord::to(topic)
                .payload(payload)
                .key(key)
                .headers(headers),
            Duration::from_secs(10),
        )
        .await
        .map_err(|(error, _)| anyhow::anyhow!("DLQ publish failed: {error}"))?;
    Ok(())
}

fn dlq_headers(error_code: &str) -> OwnedHeaders {
    let event_id = uuid::Uuid::now_v7().to_string();
    let event_time = chrono::Utc::now().to_rfc3339();
    OwnedHeaders::new()
        .insert(Header {
            key: "ce_specversion",
            value: Some("1.0"),
        })
        .insert(Header {
            key: "ce_type",
            value: Some("interchat.trust-safety.dlq.v2"),
        })
        .insert(Header {
            key: "ce_source",
            value: Some("/polarizer"),
        })
        .insert(Header {
            key: "ce_id",
            value: Some(event_id.as_str()),
        })
        .insert(Header {
            key: "ce_time",
            value: Some(event_time.as_str()),
        })
        .insert(Header {
            key: "ce_datacontenttype",
            value: Some("application/protobuf"),
        })
        .insert(Header {
            key: "content-type",
            value: Some("application/protobuf"),
        })
        .insert(Header {
            key: "polarizer-error-code",
            value: Some(error_code),
        })
}

pub async fn policy_activation_worker(
    repository: Arc<PostgresPolicyRepository>,
    engine: Arc<PolicyEngine>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                for activation in repository.due_activations().await? {
                    let version = match repository.get_version(activation.policy_version_id).await {
                        Ok(version) => version,
                        Err(error) => {
                            warn!(error = %error, activation_id = %activation.id, "scheduled policy version is unavailable");
                            repository.finish_scheduled_activation(activation.id, Some("POLICY_VERSION_UNAVAILABLE")).await?;
                            continue;
                        }
                    };
                    let issues = engine.provider_activation_issues(&version).await;
                    if !issues.is_empty() {
                        warn!(activation_id = %activation.id, issues = ?issues, "scheduled activation provider check failed");
                        repository.finish_scheduled_activation(activation.id, Some("REQUIRED_PROVIDER_UNHEALTHY")).await?;
                        continue;
                    }
                    let context = v2::RequestContext {
                        request_id: activation.id.to_string(),
                        actor_id: activation.requested_by.clone(),
                        actor_type: v2::ActorType::Human as i32,
                        service_principal: "polarizer-activation-worker".to_owned(),
                        idempotency_key: activation.id.to_string(),
                        trace_id: String::new(),
                    };
                    match repository.activate(
                        activation.bundle_id,
                        activation.policy_version_id,
                        &context,
                        activation.expected_bundle_version,
                        &activation.activation_type,
                    ).await {
                        Ok(_) => repository.finish_scheduled_activation(activation.id, None).await?,
                        Err(error) => {
                            warn!(error = %error, activation_id = %activation.id, "scheduled policy activation failed");
                            repository.finish_scheduled_activation(activation.id, Some("ACTIVATION_FAILED")).await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn expiry_worker(
    repository: Arc<PostgresPolicyRepository>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let db = repository.pool().clone();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                let mut tx = db.begin().await?;
                sqlx::query("UPDATE trust_safety.restriction SET status = 'EXPIRED', version = version + 1, updated_at = clock_timestamp() WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at <= clock_timestamp()")
                    .execute(&mut *tx).await?;
                sqlx::query("UPDATE trust_safety.infraction SET status = 'EXPIRED', version = version + 1, updated_at = clock_timestamp() WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at <= clock_timestamp()")
                    .execute(&mut *tx).await?;
                sqlx::query("UPDATE trust_safety.staff_action_request SET status='EXPIRED',
                    decision_reason='approval window expired',decided_at=clock_timestamp(),version=version+1
                    WHERE status='PENDING' AND expires_at<=clock_timestamp()")
                    .execute(&mut *tx).await?;
                sqlx::query("UPDATE trust_safety.staff_action_request request SET status='CANCELLED',
                    decision_reason='requester no longer owns a live report claim',decided_at=clock_timestamp(),
                    version=version+1 FROM trust_safety.report report
                    WHERE request.status='PENDING' AND request.report_id=report.id
                      AND (report.status<>'PENDING' OR report.claimed_by IS DISTINCT FROM request.requested_by
                           OR report.claim_expires_at<=clock_timestamp())")
                    .execute(&mut *tx).await?;
                sqlx::query("DELETE FROM trust_safety.policy_counter WHERE window_end <= clock_timestamp() - INTERVAL '1 day'")
                    .execute(&mut *tx).await?;
                tx.commit().await?;
                repository.expire_due_held_actions(500).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod cloud_event_tests {
    use super::{dlq_headers, header_value, validate_cloud_event_headers};
    use rdkafka::message::{Header, Headers, OwnedHeaders};

    fn valid_headers(event_type: &str) -> OwnedHeaders {
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
                value: Some("/bot"),
            })
            .insert(Header {
                key: "ce_id",
                value: Some("event-1"),
            })
            .insert(Header {
                key: "ce_time",
                value: Some("2026-07-17T00:00:00Z"),
            })
            .insert(Header {
                key: "ce_datacontenttype",
                value: Some("application/protobuf"),
            })
    }

    #[test]
    fn accepts_complete_binary_cloud_event_headers() {
        let headers = valid_headers("interchat.trust-safety.action.requested.v2");
        assert_eq!(
            validate_cloud_event_headers(
                Some(&headers),
                "interchat.trust-safety.action.requested.v2"
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_missing_or_wrong_contract_headers() {
        assert_eq!(
            validate_cloud_event_headers::<OwnedHeaders>(
                None,
                "interchat.trust-safety.action.requested.v2"
            ),
            Err("CLOUDEVENT_HEADERS_MISSING")
        );
        let headers = valid_headers("interchat.prism.delivery.v2");
        assert_eq!(
            validate_cloud_event_headers(
                Some(&headers),
                "interchat.trust-safety.action.requested.v2"
            ),
            Err("CLOUDEVENT_TYPE_INVALID")
        );
    }

    #[test]
    fn dlq_headers_are_complete_binary_cloud_events() {
        let headers = dlq_headers("ACTION_INVALID");
        assert_eq!(
            header_value(&headers, "ce_specversion"),
            Some(b"1.0".as_slice())
        );
        assert_eq!(
            header_value(&headers, "ce_type"),
            Some(b"interchat.trust-safety.dlq.v2".as_slice())
        );
        assert_eq!(
            header_value(&headers, "ce_datacontenttype"),
            Some(b"application/protobuf".as_slice())
        );
        assert_eq!(
            header_value(&headers, "polarizer-error-code"),
            Some(b"ACTION_INVALID".as_slice())
        );
        for required in ["ce_id", "ce_source", "ce_time"] {
            assert!(header_value(&headers, required).is_some_and(|value| !value.is_empty()));
        }
        assert!(headers.count() >= 8);
    }
}
