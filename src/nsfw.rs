use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use crate::contract::v2;

const CREATE_OPERATION: &str = "CREATE_NSFW_OVERRIDE";
const UPDATE_OPERATION: &str = "UPDATE_NSFW_OVERRIDE";
const DELETE_OPERATION: &str = "DELETE_NSFW_OVERRIDE";

pub struct NsfwOverridePage {
    pub items: Vec<v2::NsfwOverride>,
    pub next_cursor: String,
}

#[derive(Debug, Clone, Copy)]
pub struct NsfwOverrideUpdateMask {
    pub exact_sha256: bool,
    pub perceptual_hash: bool,
    pub classification: bool,
    pub reason: bool,
}

impl NsfwOverrideUpdateMask {
    pub fn any(self) -> bool {
        self.exact_sha256 || self.perceptual_hash || self.classification || self.reason
    }
}

#[derive(Clone)]
pub struct NsfwOverrideRepository {
    db: PgPool,
}

impl NsfwOverrideRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        context: &v2::RequestContext,
        input: &v2::NsfwOverride,
    ) -> anyhow::Result<v2::NsfwOverride> {
        anyhow::ensure!(
            input.id.is_empty(),
            "override.id must be empty when creating"
        );
        let normalized = validate_and_normalize(input)?;
        let id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, CREATE_OPERATION, id).await?
        {
            tx.rollback().await?;
            return self.get(existing).await;
        }
        let row = sqlx::query(
            "INSERT INTO trust_safety.nsfw_override \
             (id, exact_hash, perceptual_hash, classification, reason, created_by, updated_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $6) \
             RETURNING id, exact_hash, perceptual_hash, classification, reason, created_by, \
             created_at, updated_by, updated_at, version",
        )
        .bind(id)
        .bind(&normalized.exact_sha256)
        .bind(&normalized.perceptual_hash)
        .bind(normalized.classification)
        .bind(&normalized.reason)
        .bind(&context.actor_id)
        .fetch_one(&mut *tx)
        .await?;
        let created = override_from_row(&row)?;
        insert_audit(
            &mut tx,
            context,
            CREATE_OPERATION,
            id,
            None,
            Some(override_json(&created)),
        )
        .await?;
        tx.commit().await?;
        Ok(created)
    }

    pub async fn get(&self, id: Uuid) -> anyhow::Result<v2::NsfwOverride> {
        let row = sqlx::query(
            "SELECT id, exact_hash, perceptual_hash, classification, reason, created_by, \
             created_at, updated_by, updated_at, version \
             FROM trust_safety.nsfw_override WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?;
        override_from_row(&row)
    }

    pub async fn list(
        &self,
        classification: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<NsfwOverridePage> {
        let limit = limit.clamp(1, 100);
        let rows = sqlx::query(
            "SELECT id, exact_hash, perceptual_hash, classification, reason, created_by, \
             created_at, updated_by, updated_at, version \
             FROM trust_safety.nsfw_override \
             WHERE ($1::text IS NULL OR classification = $1) \
             AND ($2::uuid IS NULL OR id < $2) ORDER BY id DESC LIMIT $3",
        )
        .bind(classification)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.db)
        .await?;
        let next_cursor = if rows.len() == limit as usize {
            rows.last()
                .map(|row| row.get::<Uuid, _>("id").to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let items = rows
            .iter()
            .map(override_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(NsfwOverridePage { items, next_cursor })
    }

    pub async fn update(
        &self,
        context: &v2::RequestContext,
        input: &v2::NsfwOverride,
        mask: NsfwOverrideUpdateMask,
        expected_version: i64,
    ) -> anyhow::Result<v2::NsfwOverride> {
        anyhow::ensure!(mask.any(), "update_mask is required");
        anyhow::ensure!(expected_version > 0, "expected_version is required");
        let id = Uuid::parse_str(&input.id).map_err(|_| anyhow::anyhow!("invalid override.id"))?;
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, UPDATE_OPERATION, id).await?
        {
            anyhow::ensure!(
                existing == id,
                "idempotency key targets a different resource"
            );
            tx.rollback().await?;
            return self.get(existing).await;
        }
        let before_row = sqlx::query(
            "SELECT id, exact_hash, perceptual_hash, classification, reason, created_by, \
             created_at, updated_by, updated_at, version \
             FROM trust_safety.nsfw_override WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let before = override_from_row(&before_row)?;
        anyhow::ensure!(
            before.version == expected_version as u64,
            "override version conflict"
        );
        let merged = v2::NsfwOverride {
            id: input.id.clone(),
            exact_sha256: if mask.exact_sha256 {
                input.exact_sha256.clone()
            } else {
                before.exact_sha256.clone()
            },
            perceptual_hash: if mask.perceptual_hash {
                input.perceptual_hash.clone()
            } else {
                before.perceptual_hash.clone()
            },
            classification: if mask.classification {
                input.classification
            } else {
                before.classification
            },
            reason: if mask.reason {
                input.reason.clone()
            } else {
                before.reason.clone()
            },
            ..Default::default()
        };
        let normalized = validate_and_normalize(&merged)?;
        let updated_row = sqlx::query(
            "UPDATE trust_safety.nsfw_override SET exact_hash = $2, perceptual_hash = $3, \
             classification = $4, reason = $5, updated_by = $6, updated_at = clock_timestamp(), \
             version = version + 1 WHERE id = $1 AND version = $7 \
             RETURNING id, exact_hash, perceptual_hash, classification, reason, created_by, \
             created_at, updated_by, updated_at, version",
        )
        .bind(id)
        .bind(&normalized.exact_sha256)
        .bind(&normalized.perceptual_hash)
        .bind(normalized.classification)
        .bind(&normalized.reason)
        .bind(&context.actor_id)
        .bind(expected_version)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("override version conflict"))?;
        let updated = override_from_row(&updated_row)?;
        insert_audit(
            &mut tx,
            context,
            UPDATE_OPERATION,
            id,
            Some(override_json(&before)),
            Some(override_json(&updated)),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn delete(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        reason: &str,
        expected_version: i64,
    ) -> anyhow::Result<()> {
        let reason = reason.trim();
        anyhow::ensure!(expected_version > 0, "expected_version is required");
        anyhow::ensure!(
            !reason.is_empty() && reason.len() <= 2000,
            "delete reason must be between 1 and 2000 characters"
        );
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, DELETE_OPERATION, id).await?
        {
            anyhow::ensure!(
                existing == id,
                "idempotency key targets a different resource"
            );
            tx.rollback().await?;
            return Ok(());
        }
        let row = sqlx::query(
            "DELETE FROM trust_safety.nsfw_override WHERE id = $1 AND version = $2 \
             RETURNING id, exact_hash, perceptual_hash, classification, reason, created_by, \
             created_at, updated_by, updated_at, version",
        )
        .bind(id)
        .bind(expected_version)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("override not found or version conflict"))?;
        let deleted = override_from_row(&row)?;
        insert_audit(
            &mut tx,
            context,
            DELETE_OPERATION,
            id,
            Some(override_json(&deleted)),
            Some(serde_json::json!({ "deleted": true, "reason": reason })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

struct NormalizedOverride {
    exact_sha256: Option<String>,
    perceptual_hash: Option<String>,
    classification: &'static str,
    reason: String,
}

fn validate_and_normalize(input: &v2::NsfwOverride) -> anyhow::Result<NormalizedOverride> {
    let exact_sha256 = nonempty(&input.exact_sha256).map(str::to_ascii_lowercase);
    let perceptual_hash = nonempty(&input.perceptual_hash).map(str::to_owned);
    anyhow::ensure!(
        exact_sha256.is_some() || perceptual_hash.is_some(),
        "exact_sha256 or perceptual_hash is required"
    );
    if let Some(exact) = exact_sha256.as_deref() {
        anyhow::ensure!(
            exact.len() == 64 && exact.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "exact_sha256 must be a 64-character hexadecimal SHA-256 digest"
        );
    }
    if let Some(perceptual) = perceptual_hash.as_deref() {
        anyhow::ensure!(
            perceptual.len() <= 512,
            "perceptual_hash must be at most 512 characters"
        );
    }
    let classification = classification_name(input.classification)?;
    let reason = input.reason.trim().to_owned();
    anyhow::ensure!(
        !reason.is_empty() && reason.len() <= 2000,
        "reason must be between 1 and 2000 characters"
    );
    Ok(NormalizedOverride {
        exact_sha256,
        perceptual_hash,
        classification,
        reason,
    })
}

pub fn classification_name(value: i32) -> anyhow::Result<&'static str> {
    match v2::NsfwOverrideClassification::try_from(value) {
        Ok(v2::NsfwOverrideClassification::Safe) => Ok("SAFE"),
        Ok(v2::NsfwOverrideClassification::Unsafe) => Ok("UNSAFE"),
        _ => anyhow::bail!("classification is required"),
    }
}

fn classification_proto(value: &str) -> anyhow::Result<i32> {
    match value {
        "SAFE" => Ok(v2::NsfwOverrideClassification::Safe as i32),
        "UNSAFE" => Ok(v2::NsfwOverrideClassification::Unsafe as i32),
        _ => anyhow::bail!("invalid stored NSFW override classification"),
    }
}

fn nonempty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn override_from_row(row: &PgRow) -> anyhow::Result<v2::NsfwOverride> {
    Ok(v2::NsfwOverride {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        exact_sha256: row
            .try_get::<Option<String>, _>("exact_hash")?
            .unwrap_or_default(),
        perceptual_hash: row
            .try_get::<Option<String>, _>("perceptual_hash")?
            .unwrap_or_default(),
        classification: classification_proto(row.try_get("classification")?)?,
        reason: row.try_get("reason")?,
        created_by: row.try_get("created_by")?,
        created_at: Some(timestamp(row.try_get("created_at")?)),
        updated_by: row.try_get("updated_by")?,
        updated_at: Some(timestamp(row.try_get("updated_at")?)),
        version: row.try_get::<i64, _>("version")?.max(0) as u64,
    })
}

fn override_json(value: &v2::NsfwOverride) -> serde_json::Value {
    serde_json::json!({
        "id": value.id,
        "exact_sha256": value.exact_sha256,
        "perceptual_hash": value.perceptual_hash,
        "classification": value.classification,
        "reason": value.reason,
        "created_by": value.created_by,
        "updated_by": value.updated_by,
        "version": value.version,
    })
}

enum IdempotencyClaim {
    Claimed,
    Existing(Uuid),
}

async fn claim_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    context: &v2::RequestContext,
    operation: &str,
    resource_id: Uuid,
) -> anyhow::Result<IdempotencyClaim> {
    let inserted = sqlx::query(
        "INSERT INTO trust_safety.mutation_idempotency \
         (service_principal, actor_id, idempotency_key, operation, resource_id) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (service_principal, actor_id, idempotency_key) DO NOTHING",
    )
    .bind(&context.service_principal)
    .bind(&context.actor_id)
    .bind(&context.idempotency_key)
    .bind(operation)
    .bind(resource_id)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(IdempotencyClaim::Claimed);
    }
    let row = sqlx::query(
        "SELECT operation, resource_id FROM trust_safety.mutation_idempotency \
         WHERE service_principal = $1 AND actor_id = $2 AND idempotency_key = $3",
    )
    .bind(&context.service_principal)
    .bind(&context.actor_id)
    .bind(&context.idempotency_key)
    .fetch_one(&mut **tx)
    .await?;
    let existing_operation: String = row.try_get("operation")?;
    anyhow::ensure!(
        existing_operation == operation,
        "idempotency key was already used for a different operation"
    );
    Ok(IdempotencyClaim::Existing(row.try_get("resource_id")?))
}

async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    context: &v2::RequestContext,
    action: &str,
    resource_id: Uuid,
    before_state: Option<serde_json::Value>,
    after_state: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO trust_safety.audit_log \
         (request_id, actor_id, actor_type, action, resource_type, resource_id, before_state, after_state, trace_id) \
         VALUES ($1, $2, $3, $4, 'NSFW_OVERRIDE', $5, $6, $7, NULLIF($8, ''))",
    )
    .bind(&context.request_id)
    .bind(&context.actor_id)
    .bind(actor_type_name(context.actor_type))
    .bind(action)
    .bind(resource_id.to_string())
    .bind(before_state)
    .bind(after_state)
    .bind(&context.trace_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn actor_type_name(value: i32) -> &'static str {
    match v2::ActorType::try_from(value).unwrap_or_default() {
        v2::ActorType::Human => "HUMAN",
        v2::ActorType::Service => "SERVICE",
        v2::ActorType::Policy => "POLICY",
        v2::ActorType::Unspecified => "UNSPECIFIED",
    }
}

fn timestamp(value: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(classification: v2::NsfwOverrideClassification) -> v2::NsfwOverride {
        v2::NsfwOverride {
            exact_sha256: "A".repeat(64),
            classification: classification as i32,
            reason: " reviewed by safety ".into(),
            ..Default::default()
        }
    }

    #[test]
    fn normalizes_exact_hash_and_reason() {
        let normalized = validate_and_normalize(&input(v2::NsfwOverrideClassification::Safe))
            .expect("valid override");
        assert_eq!(
            normalized.exact_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(normalized.reason, "reviewed by safety");
        assert_eq!(normalized.classification, "SAFE");
    }

    #[test]
    fn requires_a_hash_and_typed_classification() {
        let mut value = input(v2::NsfwOverrideClassification::Unspecified);
        value.exact_sha256.clear();
        assert!(validate_and_normalize(&value).is_err());
        value.perceptual_hash = "perceptual".into();
        assert!(validate_and_normalize(&value).is_err());
    }

    #[test]
    fn rejects_malformed_sha256_and_empty_reason() {
        let mut value = input(v2::NsfwOverrideClassification::Unsafe);
        value.exact_sha256 = "not-a-digest".into();
        assert!(validate_and_normalize(&value).is_err());
        value.exact_sha256 = "b".repeat(64);
        value.reason = " ".into();
        assert!(validate_and_normalize(&value).is_err());
    }
}
