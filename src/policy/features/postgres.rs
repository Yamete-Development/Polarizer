use async_trait::async_trait;
use serde_json::json;
use sqlx::{PgPool, Row};

use super::{FeatureProvider, ProviderCategory, ProviderError, ProviderOutput};
use crate::policy::model::Action;

pub struct RestrictionProvider {
    db: PgPool,
}
pub struct CounterProvider {
    db: PgPool,
}
pub struct SafetyAssessmentProvider {
    db: PgPool,
}
pub struct EntityLabelProvider {
    db: PgPool,
}

impl RestrictionProvider {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}
impl CounterProvider {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}
impl SafetyAssessmentProvider {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}
impl EntityLabelProvider {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

fn subjects(action: &Action) -> Vec<(&'static str, &str)> {
    let mut values = Vec::new();
    if let Some(id) = action.subject.user_id.as_deref() {
        values.push(("USER", id));
    }
    if let Some(id) = action.subject.server_id.as_deref() {
        values.push(("SERVER", id));
    }
    values
}

#[async_trait]
impl FeatureProvider for RestrictionProvider {
    fn name(&self) -> &str {
        "restrictions.active"
    }
    fn version(&self) -> &str {
        "postgres-v2"
    }
    fn category(&self) -> ProviderCategory {
        ProviderCategory::State
    }
    async fn resolve(
        &self,
        action: &Action,
        _: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let mut restrictions = Vec::new();
        for (subject_type, subject_id) in subjects(action) {
            let rows = sqlx::query(
                "SELECT id, restriction_type, scope_type::text, scope_id, reason, expires_at \
                 FROM trust_safety.restriction \
                 WHERE subject_type = $1 AND subject_id = $2 AND status = 'ACTIVE' \
                   AND (expires_at IS NULL OR expires_at > clock_timestamp()) \
                   AND (scope_type = 'PLATFORM' OR (scope_type = $3::trust_safety.scope_type AND scope_id = $4))"
            )
            .bind(subject_type).bind(subject_id)
            .bind(format!("{:?}", action.scope.scope_type).to_uppercase())
            .bind(&action.scope.id)
            .fetch_all(&self.db).await.map_err(|_| ProviderError::Unavailable)?;
            for row in rows {
                restrictions.push(json!({
                    "id": row.try_get::<uuid::Uuid, _>("id").map_err(|_| ProviderError::Internal)?,
                    "subject_type": subject_type, "subject_id": subject_id,
                    "restriction_type": row.try_get::<String, _>("restriction_type").map_err(|_| ProviderError::Internal)?,
                    "scope_type": row.try_get::<String, _>("scope_type").map_err(|_| ProviderError::Internal)?,
                    "scope_id": row.try_get::<String, _>("scope_id").map_err(|_| ProviderError::Internal)?,
                    "reason": row.try_get::<String, _>("reason").map_err(|_| ProviderError::Internal)?,
                    "expires_at": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at").map_err(|_| ProviderError::Internal)?,
                }));
            }
        }
        Ok(ProviderOutput {
            value: json!(restrictions),
            cache_hit: false,
            input_hash: None,
        })
    }
}

#[async_trait]
impl FeatureProvider for CounterProvider {
    fn name(&self) -> &str {
        "counters.state"
    }
    fn version(&self) -> &str {
        "postgres-v2"
    }
    fn category(&self) -> ProviderCategory {
        ProviderCategory::State
    }
    async fn resolve(
        &self,
        action: &Action,
        _: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let mut counters = Vec::new();
        for (subject_type, subject_id) in subjects(action) {
            let rows = sqlx::query(
                "SELECT counter_type, value, window_start, window_end FROM trust_safety.policy_counter \
                 WHERE subject_type = $1 AND subject_id = $2 AND window_end > clock_timestamp()"
            ).bind(subject_type).bind(subject_id).fetch_all(&self.db).await.map_err(|_| ProviderError::Unavailable)?;
            for row in rows {
                counters.push(json!({
                    "subject_type": subject_type, "subject_id": subject_id,
                    "counter_type": row.try_get::<String, _>("counter_type").map_err(|_| ProviderError::Internal)?,
                    "value": row.try_get::<i64, _>("value").map_err(|_| ProviderError::Internal)?,
                    "window_start": row.try_get::<chrono::DateTime<chrono::Utc>, _>("window_start").map_err(|_| ProviderError::Internal)?,
                    "window_end": row.try_get::<chrono::DateTime<chrono::Utc>, _>("window_end").map_err(|_| ProviderError::Internal)?,
                }));
            }
        }
        Ok(ProviderOutput {
            value: json!(counters),
            cache_hit: false,
            input_hash: None,
        })
    }
}

#[async_trait]
impl FeatureProvider for SafetyAssessmentProvider {
    fn name(&self) -> &str {
        "safety.assessment"
    }
    fn version(&self) -> &str {
        "postgres-v2"
    }
    fn category(&self) -> ProviderCategory {
        ProviderCategory::State
    }
    async fn resolve(
        &self,
        action: &Action,
        _: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let Some((subject_type, subject_id)) = subjects(action).into_iter().next() else {
            return Ok(ProviderOutput {
                value: serde_json::Value::Null,
                cache_hit: false,
                input_hash: None,
            });
        };
        let row = sqlx::query(
            "SELECT score, tier, signal_breakdown, algorithm_version, assessed_at FROM trust_safety.safety_assessment \
             WHERE subject_type = $1 AND subject_id = $2 \
               AND (scope_type = 'PLATFORM' OR (scope_type = $3::trust_safety.scope_type AND scope_id = $4)) \
             ORDER BY CASE WHEN scope_type = $3::trust_safety.scope_type AND scope_id = $4 THEN 0 ELSE 1 END LIMIT 1"
        ).bind(subject_type).bind(subject_id)
        .bind(format!("{:?}", action.scope.scope_type).to_uppercase()).bind(&action.scope.id)
        .fetch_optional(&self.db).await.map_err(|_| ProviderError::Unavailable)?;
        let value = row.map(|row| json!({
            "score": row.try_get::<f64, _>("score").ok(),
            "tier": row.try_get::<String, _>("tier").ok(),
            "signals": row.try_get::<serde_json::Value, _>("signal_breakdown").ok(),
            "algorithm_version": row.try_get::<String, _>("algorithm_version").ok(),
            "assessed_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("assessed_at").ok(),
        })).unwrap_or(serde_json::Value::Null);
        Ok(ProviderOutput {
            value,
            cache_hit: false,
            input_hash: None,
        })
    }
}

#[async_trait]
impl FeatureProvider for EntityLabelProvider {
    fn name(&self) -> &str {
        "entity.labels"
    }
    fn version(&self) -> &str {
        "postgres-v2"
    }
    fn category(&self) -> ProviderCategory {
        ProviderCategory::State
    }
    async fn resolve(
        &self,
        action: &Action,
        _: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let mut labels = serde_json::Map::new();
        for (subject_type, subject_id) in subjects(action) {
            let rows = sqlx::query(
                "SELECT label, value FROM trust_safety.entity_label WHERE subject_type = $1 AND subject_id = $2"
            ).bind(subject_type).bind(subject_id).fetch_all(&self.db).await.map_err(|_| ProviderError::Unavailable)?;
            for row in rows {
                labels.insert(
                    row.try_get::<String, _>("label")
                        .map_err(|_| ProviderError::Internal)?,
                    row.try_get::<serde_json::Value, _>("value")
                        .map_err(|_| ProviderError::Internal)?,
                );
            }
        }
        Ok(ProviderOutput {
            value: serde_json::Value::Object(labels),
            cache_hit: false,
            input_hash: None,
        })
    }
}
