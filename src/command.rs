use chrono::{DateTime, Utc};
use prost::Message;
use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::contract::v2;

const MIN_LEASE_SECONDS: i64 = 5;
const MAX_LEASE_SECONDS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimState {
    Acquired,
    Busy,
    Completed,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    pub success: bool,
    pub result_code: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandCompletion {
    pub outcome: CommandOutcome,
    pub decision_id: Uuid,
    pub idempotency_key: String,
    pub command_type: String,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommandClaim {
    pub state: ClaimState,
    pub command: v2::CommandEnvelope,
    pub lease_token: Option<Uuid>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub attempt_count: i32,
    pub version: i64,
    pub outcome: Option<CommandOutcome>,
}

#[derive(Debug, Error)]
pub enum CommandRepositoryError {
    #[error("command was not found")]
    NotFound,
    #[error("command lease does not match the active claim")]
    LeaseMismatch,
    #[error("command requires operator recovery")]
    RecoveryRequired,
    #[error("command result conflicts with its durable completed outcome")]
    ConflictingCompletion,
    #[error("command version does not match the active claim")]
    VersionMismatch,
    #[error("stored command payload is invalid")]
    CorruptCommand,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct CommandRepository {
    db: PgPool,
    result_topic: String,
}

impl CommandRepository {
    pub fn new(db: PgPool, result_topic: impl Into<String>) -> Self {
        Self {
            db,
            result_topic: result_topic.into(),
        }
    }

    pub async fn claim(
        &self,
        command_id: Uuid,
        claimant_id: &str,
        requested_lease_seconds: i64,
    ) -> Result<CommandClaim, CommandRepositoryError> {
        let lease_seconds = requested_lease_seconds.clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS);
        let mut tx = self.db.begin().await?;
        let row = sqlx::query(
            "SELECT status, payload, retry_safe, claimant_id, lease_token, lease_expires_at, \
                    attempt_count, version, success, result_code, processed_at \
             FROM trust_safety.processed_command WHERE command_id = $1 FOR UPDATE",
        )
        .bind(command_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(CommandRepositoryError::NotFound)?;

        let status: String = row.try_get("status")?;
        let command = v2::CommandEnvelope::decode(row.try_get::<Vec<u8>, _>("payload")?.as_slice())
            .map_err(|_| CommandRepositoryError::CorruptCommand)?;
        let retry_safe: bool = row.try_get("retry_safe")?;
        let active_claimant: Option<String> = row.try_get("claimant_id")?;
        let active_token: Option<Uuid> = row.try_get("lease_token")?;
        let active_expiry: Option<DateTime<Utc>> = row.try_get("lease_expires_at")?;
        let attempt_count: i32 = row.try_get("attempt_count")?;
        let version: i64 = row.try_get("version")?;
        let now = Utc::now();

        let decision = decide_claim(
            &status,
            retry_safe,
            active_claimant.as_deref(),
            claimant_id,
            active_expiry,
            now,
        );

        let claim = match decision {
            ClaimDecision::ReturnCompleted => CommandClaim {
                state: ClaimState::Completed,
                command: command.clone(),
                lease_token: None,
                lease_expires_at: None,
                attempt_count,
                version,
                outcome: Some(CommandOutcome {
                    success: row.try_get("success")?,
                    result_code: row.try_get("result_code")?,
                    occurred_at: row.try_get("processed_at")?,
                }),
            },
            ClaimDecision::ReturnRecoveryRequired => CommandClaim {
                state: ClaimState::RecoveryRequired,
                command: command.clone(),
                lease_token: None,
                lease_expires_at: None,
                attempt_count,
                version,
                outcome: None,
            },
            ClaimDecision::ReturnBusy => CommandClaim {
                state: ClaimState::Busy,
                command: command.clone(),
                lease_token: None,
                lease_expires_at: active_expiry,
                attempt_count,
                version,
                outcome: None,
            },
            ClaimDecision::ReturnExistingClaim => CommandClaim {
                state: ClaimState::Acquired,
                command: command.clone(),
                lease_token: active_token,
                lease_expires_at: active_expiry,
                attempt_count,
                version,
                outcome: None,
            },
            ClaimDecision::MarkRecoveryRequired => {
                let row = sqlx::query(
                    "UPDATE trust_safety.processed_command SET \
                       status = 'RECOVERY_REQUIRED', claimant_id = NULL, lease_token = NULL, \
                       lease_expires_at = NULL, version = version + 1, updated_at = clock_timestamp() \
                     WHERE command_id = $1 RETURNING attempt_count, version",
                )
                .bind(command_id)
                .fetch_one(&mut *tx)
                .await?;
                CommandClaim {
                    state: ClaimState::RecoveryRequired,
                    command: command.clone(),
                    lease_token: None,
                    lease_expires_at: None,
                    attempt_count: row.try_get("attempt_count")?,
                    version: row.try_get("version")?,
                    outcome: None,
                }
            }
            ClaimDecision::Acquire => {
                let lease_token = Uuid::now_v7();
                let row = sqlx::query(
                    "UPDATE trust_safety.processed_command SET \
                       status = 'CLAIMED', claimant_id = $2, lease_token = $3, \
                       lease_expires_at = clock_timestamp() + make_interval(secs => $4), \
                       attempt_count = attempt_count + 1, claimed_at = clock_timestamp(), \
                       version = version + 1, updated_at = clock_timestamp() \
                     WHERE command_id = $1 \
                     RETURNING lease_expires_at, attempt_count, version",
                )
                .bind(command_id)
                .bind(claimant_id)
                .bind(lease_token)
                .bind(lease_seconds as f64)
                .fetch_one(&mut *tx)
                .await?;
                CommandClaim {
                    state: ClaimState::Acquired,
                    command,
                    lease_token: Some(lease_token),
                    lease_expires_at: Some(row.try_get("lease_expires_at")?),
                    attempt_count: row.try_get("attempt_count")?,
                    version: row.try_get("version")?,
                    outcome: None,
                }
            }
        };
        tx.commit().await?;
        Ok(claim)
    }

    pub async fn complete(
        &self,
        command_id: Uuid,
        lease_token: Uuid,
        expected_version: i64,
        outcome: CommandOutcome,
    ) -> Result<CommandCompletion, CommandRepositoryError> {
        let mut tx = self.db.begin().await?;
        let row = sqlx::query(
            "SELECT decision_id, command_type, idempotency_key, status, lease_token, \
                    success, result_code, processed_at, version \
             FROM trust_safety.processed_command WHERE command_id = $1 FOR UPDATE",
        )
        .bind(command_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(CommandRepositoryError::NotFound)?;

        let status: String = row.try_get("status")?;
        if status == "COMPLETED" {
            let stored = CommandOutcome {
                success: row.try_get("success")?,
                result_code: row.try_get("result_code")?,
                occurred_at: row.try_get("processed_at")?,
            };
            if stored.success != outcome.success || stored.result_code != outcome.result_code {
                return Err(CommandRepositoryError::ConflictingCompletion);
            }
            tx.commit().await?;
            return Ok(CommandCompletion {
                outcome: stored,
                decision_id: row.try_get("decision_id")?,
                idempotency_key: row.try_get("idempotency_key")?,
                command_type: row.try_get("command_type")?,
                version: row.try_get("version")?,
            });
        }
        if status == "RECOVERY_REQUIRED" {
            return Err(CommandRepositoryError::RecoveryRequired);
        }
        if status != "CLAIMED"
            || row.try_get::<Option<Uuid>, _>("lease_token")? != Some(lease_token)
        {
            return Err(CommandRepositoryError::LeaseMismatch);
        }
        if row.try_get::<i64, _>("version")? != expected_version {
            return Err(CommandRepositoryError::VersionMismatch);
        }

        let decision_id: Uuid = row.try_get("decision_id")?;
        let command_type: String = row.try_get("command_type")?;
        let idempotency_key: String = row.try_get("idempotency_key")?;
        let updated = sqlx::query(
            "UPDATE trust_safety.processed_command SET \
               status = 'COMPLETED', claimant_id = NULL, lease_token = NULL, lease_expires_at = NULL, \
               processed_at = $2, success = $3, result_code = $4, result = $5, \
               version = version + 1, updated_at = clock_timestamp() \
             WHERE command_id = $1 RETURNING version",
        )
        .bind(command_id)
        .bind(outcome.occurred_at)
        .bind(outcome.success)
        .bind(&outcome.result_code)
        .bind(json!({"success": outcome.success, "result_code": outcome.result_code}))
        .fetch_one(&mut *tx)
        .await?;
        let version: i64 = updated.try_get("version")?;

        let event = v2::CommandResult {
            command_id: command_id.to_string(),
            decision_id: decision_id.to_string(),
            idempotency_key,
            success: outcome.success,
            result_code: outcome.result_code.clone(),
            occurred_at: Some(prost_types::Timestamp {
                seconds: outcome.occurred_at.timestamp(),
                nanos: outcome.occurred_at.timestamp_subsec_nanos() as i32,
            }),
            command_type,
        };
        insert_result_outbox(
            &mut tx,
            command_id,
            &self.result_topic,
            event.encode_to_vec(),
        )
        .await?;
        tx.commit().await?;
        Ok(CommandCompletion {
            outcome,
            decision_id,
            idempotency_key: event.idempotency_key,
            command_type: event.command_type,
            version,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimDecision {
    Acquire,
    ReturnExistingClaim,
    ReturnBusy,
    ReturnCompleted,
    ReturnRecoveryRequired,
    MarkRecoveryRequired,
}

fn decide_claim(
    status: &str,
    retry_safe: bool,
    active_claimant: Option<&str>,
    claimant_id: &str,
    lease_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> ClaimDecision {
    match status {
        "COMPLETED" => ClaimDecision::ReturnCompleted,
        "RECOVERY_REQUIRED" => ClaimDecision::ReturnRecoveryRequired,
        "PENDING" => ClaimDecision::Acquire,
        "CLAIMED" if active_claimant == Some(claimant_id) && lease_expires_at > Some(now) => {
            ClaimDecision::ReturnExistingClaim
        }
        "CLAIMED" if lease_expires_at > Some(now) => ClaimDecision::ReturnBusy,
        "CLAIMED" if retry_safe => ClaimDecision::Acquire,
        "CLAIMED" => ClaimDecision::MarkRecoveryRequired,
        _ => ClaimDecision::ReturnRecoveryRequired,
    }
}

async fn insert_result_outbox(
    tx: &mut Transaction<'_, Postgres>,
    command_id: Uuid,
    topic: &str,
    payload: Vec<u8>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO trust_safety.outbox \
         (aggregate_type, aggregate_id, topic, partition_key, headers, payload) \
         VALUES ('COMMAND_RESULT', $1, $2, $3, $4, $5)",
    )
    .bind(command_id)
    .bind(topic)
    .bind(command_id.to_string())
    .bind(json!({
        "ce_specversion": "1.0",
        "ce_type": "interchat.trust-safety.command-result.v2",
        "ce_source": "/polarizer",
        "ce_id": Uuid::now_v7().to_string(),
        "ce_time": Utc::now().to_rfc3339(),
        "ce_datacontenttype": "application/protobuf",
        "content-type": "application/protobuf"
    }))
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn active_claim_is_stable_for_rpc_retry_and_busy_for_another_worker() {
        let now = Utc::now();
        let expiry = now + Duration::seconds(30);
        assert_eq!(
            decide_claim(
                "CLAIMED",
                true,
                Some("attempt-a"),
                "attempt-a",
                Some(expiry),
                now
            ),
            ClaimDecision::ReturnExistingClaim
        );
        assert_eq!(
            decide_claim(
                "CLAIMED",
                true,
                Some("attempt-a"),
                "attempt-b",
                Some(expiry),
                now
            ),
            ClaimDecision::ReturnBusy
        );
    }

    #[test]
    fn expired_retry_safe_commands_can_be_reclaimed() {
        let now = Utc::now();
        assert_eq!(
            decide_claim(
                "CLAIMED",
                true,
                Some("dead-attempt"),
                "new-attempt",
                Some(now - Duration::seconds(1)),
                now,
            ),
            ClaimDecision::Acquire
        );
    }

    #[test]
    fn expired_non_idempotent_notification_requires_recovery() {
        let now = Utc::now();
        assert_eq!(
            decide_claim(
                "CLAIMED",
                false,
                Some("dead-attempt"),
                "new-attempt",
                Some(now - Duration::seconds(1)),
                now,
            ),
            ClaimDecision::MarkRecoveryRequired
        );
    }
}
