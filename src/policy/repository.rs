use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use prost::Message;
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::sync::RwLock;
use uuid::Uuid;

pub(crate) fn automated_reason(reason: &str) -> String {
    format!("Automated: {reason}")
}

use crate::{
    config::AppConfig,
    contract::{emitted_effect_to_proto, prism, scope_to_proto, subject_to_proto, v2},
    moderation::insert_derived_safety_observation_tx,
};

use super::model::{
    Action, Decision, Effect, EmittedEffect, EvaluationResult, ExecutionTrace, FeatureSnapshot,
    PolicyBundle, PolicyBundleState, PolicyLanguage, PolicyManifest, PolicyState, PolicyVersion,
    Product, Scope, ScopeType, Subject,
};

#[derive(Debug, Clone)]
pub struct ActivePolicy {
    pub bundle: PolicyBundle,
    pub version: PolicyVersion,
    pub shadow: bool,
}

#[derive(Debug, Clone)]
pub struct StoredFixture {
    pub id: Uuid,
    pub policy_version_id: Uuid,
    pub name: String,
    pub action: Action,
    pub features: FeatureSnapshot,
    pub expected_effects: Vec<Effect>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub version: i64,
}

#[derive(Debug, Clone)]
pub struct ScheduledActivation {
    pub id: Uuid,
    pub bundle_id: Uuid,
    pub policy_version_id: Uuid,
    pub expected_bundle_version: i64,
    pub activation_type: String,
    pub requested_by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistOutcome {
    Applied,
    Duplicate,
}

pub(crate) enum PolicyIdempotencyClaim {
    Claimed,
    Existing(Uuid),
}

#[async_trait]
pub trait PolicyRepository: Send + Sync {
    async fn active_policies(&self, action: &Action) -> anyhow::Result<Vec<ActivePolicy>>;
    async fn persist_and_apply(
        &self,
        action: &Action,
        result: &EvaluationResult,
    ) -> anyhow::Result<PersistOutcome>;
    async fn persist_shadow_comparison(
        &self,
        action: &Action,
        active: &EvaluationResult,
        shadow: &EvaluationResult,
    ) -> anyhow::Result<()>;
}

async fn append_lobby_evidence_event(
    tx: &mut Transaction<'_, Postgres>,
    action: &Action,
) -> anyhow::Result<()> {
    if action.scope.scope_type != super::model::ScopeType::Lobby
        || !matches!(
            action.action_type.as_str(),
            "lobby.message.created"
                | "lobby.message.edited"
                | "lobby.message.deleted"
                | "lobby.call.connected"
                | "lobby.call.ended"
                | "lobby.participant.joined"
                | "lobby.participant.left"
                | "lobby.report.submitted"
        )
    {
        return Ok(());
    }

    anyhow::ensure!(
        !action.scope.id.is_empty(),
        "Lobby evidence requires a lobby id"
    );
    sqlx::query(
        "INSERT INTO trust_safety.call_evidence_archive (lobby_id) VALUES ($1) \
         ON CONFLICT (lobby_id) DO NOTHING",
    )
    .bind(&action.scope.id)
    .execute(&mut **tx)
    .await?;
    let sequence: i64 = sqlx::query_scalar(
        "UPDATE trust_safety.call_evidence_archive \
         SET last_sequence = last_sequence + 1, updated_at = clock_timestamp() \
         WHERE lobby_id = $1 RETURNING last_sequence",
    )
    .bind(&action.scope.id)
    .fetch_one(&mut **tx)
    .await?;
    let message_kind = action
        .attributes
        .get("message_kind")
        .and_then(serde_json::Value::as_str);
    let event_kind =
        if action.action_type.starts_with("lobby.message.") && message_kind != Some("system") {
            "USER_MESSAGE"
        } else {
            "SYSTEM_EVENT"
        };
    sqlx::query(
        "INSERT INTO trust_safety.call_evidence_event \
         (lobby_id, sequence, action_id, event_kind, occurred_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&action.scope.id)
    .bind(sequence)
    .bind(action.id)
    .bind(event_kind)
    .bind(action.occurred_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub struct ActionCipher {
    key: aead::LessSafeKey,
    random: SystemRandom,
}

impl ActionCipher {
    pub fn new(key: &[u8]) -> anyhow::Result<Self> {
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("invalid action encryption key"))?;
        Ok(Self {
            key: aead::LessSafeKey::new(key),
            random: SystemRandom::new(),
        })
    }

    pub fn seal(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        self.random
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("unable to generate encryption nonce"))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut output = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut output)
            .map_err(|_| anyhow::anyhow!("unable to encrypt action"))?;
        let mut sealed = nonce_bytes.to_vec();
        sealed.extend_from_slice(&output);
        Ok(sealed)
    }

    pub fn open(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= 12, "encrypted action is truncated");
        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| anyhow::anyhow!("encrypted action has an invalid nonce"))?;
        let mut plaintext = encrypted.to_vec();
        let opened = self
            .key
            .open_in_place(nonce, aead::Aad::empty(), &mut plaintext)
            .map_err(|_| anyhow::anyhow!("unable to decrypt action"))?;
        Ok(opened.to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldActionResolution {
    Approve,
    Reject,
    Expire,
}

#[derive(Debug, Clone)]
pub struct HeldActionRecord {
    pub action_id: Uuid,
    pub decision_id: Uuid,
    pub scope: Scope,
    pub state: String,
    pub hold_until: Option<chrono::DateTime<Utc>>,
    pub version: i64,
    pub resolved_by: Option<String>,
    pub resolution_reason: Option<String>,
    pub resolved_review_item_ids: Vec<Uuid>,
}

pub struct PostgresPolicyRepository {
    db: PgPool,
    cipher: ActionCipher,
    encryption_key_id: String,
    decision_topic: String,
    command_topic: String,
    policy_invalidation_topic: String,
    prism_topic: String,
}

impl PostgresPolicyRepository {
    pub fn new(db: PgPool, config: &AppConfig) -> anyhow::Result<Self> {
        let key = config.encryption_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("ACTION_ENCRYPTION_KEY_HEX is required for action persistence")
        })?;
        Ok(Self {
            db,
            cipher: ActionCipher::new(key)?,
            encryption_key_id: config.encryption_key_id.clone(),
            decision_topic: config.decision_topic.clone(),
            command_topic: config.command_topic.clone(),
            policy_invalidation_topic: config.policy_invalidation_topic.clone(),
            prism_topic: config.prism_topic.clone(),
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.db
    }

    pub async fn load_persisted_action(&self, action_id: Uuid) -> anyhow::Result<Action> {
        let encrypted: Vec<u8> = sqlx::query_scalar(
            "SELECT action_ciphertext FROM trust_safety.action_inbox WHERE action_id = $1",
        )
        .bind(action_id)
        .fetch_one(&self.db)
        .await?;
        Ok(serde_json::from_slice(&self.cipher.open(&encrypted)?)?)
    }

    pub async fn create_bundle(
        &self,
        name: &str,
        description: &str,
        scope: &Scope,
        mandatory: bool,
        priority: i32,
        context: &v2::RequestContext,
    ) -> anyhow::Result<PolicyBundle> {
        validate_bundle_fields(name, description, scope, priority)?;
        let mut tx = self.db.begin().await?;
        let id = Uuid::now_v7();
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "CREATE_POLICY_BUNDLE", id).await?
        {
            tx.rollback().await?;
            return self.load_bundle(existing).await;
        }
        sqlx::query(
            "INSERT INTO trust_safety.policy_bundle \
             (id, name, description, scope_type, scope_id, product, mandatory, priority, created_by) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(name.trim())
        .bind(description.trim())
        .bind(scope_name(scope.scope_type))
        .bind(&scope.id)
        .bind(scope.product.map(product_name))
        .bind(mandatory)
        .bind(priority)
        .bind(&context.actor_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            context,
            "CREATE_POLICY_BUNDLE",
            "POLICY_BUNDLE",
            &id.to_string(),
            None,
            Some(json!({"name": name.trim(), "scope": scope, "mandatory": mandatory, "priority": priority, "state": "ACTIVE"})),
        )
        .await?;
        tx.commit().await?;
        self.load_bundle(id).await
    }

    pub async fn list_bundles(
        &self,
        scope: &Scope,
        state: Option<PolicyBundleState>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<(Vec<PolicyBundle>, Option<Uuid>)> {
        let rows = sqlx::query(
            "SELECT id, name, description, scope_type::text, scope_id, product, mandatory, priority, \
             active_version_id, shadow_version_id, state::text, version, created_at, updated_at \
             FROM trust_safety.policy_bundle WHERE scope_type = $1::trust_safety.scope_type \
             AND scope_id = $2 AND product IS NOT DISTINCT FROM $3 \
             AND ($4::text IS NULL OR state = $4::trust_safety.policy_bundle_state) \
             AND ($5::uuid IS NULL OR id < $5) ORDER BY id DESC LIMIT $6",
        )
        .bind(scope_name(scope.scope_type))
        .bind(&scope.id)
        .bind(scope.product.map(product_name))
        .bind(state.map(bundle_state_name))
        .bind(cursor)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        let bundles = rows
            .iter()
            .map(bundle_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let next = (rows.len() == limit.clamp(1, 100) as usize)
            .then(|| rows.last().and_then(|row| row.try_get("id").ok()))
            .flatten();
        Ok((bundles, next))
    }

    // This application boundary mirrors the independently optional update-mask
    // fields plus concurrency and actor context.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_bundle(
        &self,
        id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        mandatory: Option<bool>,
        priority: Option<i32>,
        expected_version: i64,
        context: &v2::RequestContext,
    ) -> anyhow::Result<PolicyBundle> {
        let current = self.load_bundle(id).await?;
        let next_name = name.unwrap_or(&current.name);
        let next_description = description.unwrap_or(&current.description);
        let next_priority = priority.unwrap_or(current.priority);
        validate_bundle_fields(next_name, next_description, &current.scope, next_priority)?;
        if mandatory.is_some_and(|value| value != current.mandatory) {
            anyhow::ensure!(
                current.active_version_id.is_none() && current.shadow_version_id.is_none(),
                "policy bundle mandatory flag cannot change after versions are activated"
            );
        }
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "UPDATE_POLICY_BUNDLE", id).await?
        {
            tx.rollback().await?;
            return self.load_bundle(existing).await;
        }
        let row = sqlx::query(
            "UPDATE trust_safety.policy_bundle SET name = $2, description = $3, mandatory = $4, \
             priority = $5, version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $6 AND state <> 'RETIRED' RETURNING version",
        )
        .bind(id)
        .bind(next_name.trim())
        .bind(next_description.trim())
        .bind(mandatory.unwrap_or(current.mandatory))
        .bind(next_priority)
        .bind(expected_version)
        .fetch_optional(&mut *tx)
        .await?;
        anyhow::ensure!(
            row.is_some(),
            "policy bundle version conflict or is retired"
        );
        insert_audit(
            &mut tx,
            context,
            "UPDATE_POLICY_BUNDLE",
            "POLICY_BUNDLE",
            &id.to_string(),
            Some(bundle_audit_json(&current)),
            Some(json!({"name": next_name.trim(), "description": next_description.trim(), "mandatory": mandatory.unwrap_or(current.mandatory), "priority": next_priority, "version": expected_version + 1})),
        )
        .await?;
        insert_outbox(
            &mut tx,
            "POLICY_BUNDLE",
            id,
            &self.policy_invalidation_topic,
            "interchat.trust-safety.policy.invalidated.v2",
            &id.to_string(),
            v2::PolicyCacheInvalidated {
                bundle_id: id.to_string(),
                active_policy_version_id: current
                    .active_version_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                bundle_version: (expected_version + 1) as u64,
                occurred_at: Some(timestamp(Utc::now())),
            }
            .encode_to_vec(),
        )
        .await?;
        tx.commit().await?;
        self.load_bundle(id).await
    }

    pub async fn transition_bundle(
        &self,
        id: Uuid,
        target: PolicyBundleState,
        expected_version: i64,
        context: &v2::RequestContext,
    ) -> anyhow::Result<PolicyBundle> {
        anyhow::ensure!(
            matches!(
                target,
                PolicyBundleState::Disabled | PolicyBundleState::Retired
            ),
            "unsupported policy bundle transition"
        );
        let operation = if target == PolicyBundleState::Disabled {
            "DISABLE_POLICY_BUNDLE"
        } else {
            "RETIRE_POLICY_BUNDLE"
        };
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, operation, id).await?
        {
            tx.rollback().await?;
            return self.load_bundle(existing).await;
        }
        let current_row = sqlx::query(
            "SELECT id, name, description, scope_type::text, scope_id, product, mandatory, priority, \
             active_version_id, shadow_version_id, state::text, version, created_at, updated_at \
             FROM trust_safety.policy_bundle WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let current = bundle_from_row(&current_row)?;
        anyhow::ensure!(
            current.version == expected_version,
            "policy bundle version conflict"
        );
        let legal = is_legal_bundle_transition(current.state, target);
        anyhow::ensure!(legal, "illegal policy bundle state transition");
        sqlx::query(
            "UPDATE trust_safety.policy_bundle SET state = $2::trust_safety.policy_bundle_state, \
             version = version + 1, updated_at = clock_timestamp() WHERE id = $1",
        )
        .bind(id)
        .bind(bundle_state_name(target))
        .execute(&mut *tx)
        .await?;
        insert_outbox(
            &mut tx,
            "POLICY_BUNDLE",
            id,
            &self.policy_invalidation_topic,
            "interchat.trust-safety.policy.invalidated.v2",
            &id.to_string(),
            v2::PolicyCacheInvalidated {
                bundle_id: id.to_string(),
                active_policy_version_id: String::new(),
                bundle_version: (expected_version + 1) as u64,
                occurred_at: Some(timestamp(Utc::now())),
            }
            .encode_to_vec(),
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            operation,
            "POLICY_BUNDLE",
            &id.to_string(),
            Some(bundle_audit_json(&current)),
            Some(json!({"state": bundle_state_name(target), "version": expected_version + 1})),
        )
        .await?;
        tx.commit().await?;
        self.load_bundle(id).await
    }

    pub async fn create_draft(
        &self,
        bundle_id: Uuid,
        language: PolicyLanguage,
        source: String,
        manifest: PolicyManifest,
        context: &v2::RequestContext,
        expected_bundle_version: i64,
    ) -> anyhow::Result<PolicyVersion> {
        let mut tx = self.db.begin().await?;
        let id = Uuid::now_v7();
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "CREATE_POLICY_DRAFT", id).await?
        {
            tx.rollback().await?;
            return self.get_version(existing).await;
        }
        let bundle = sqlx::query(
            "SELECT scope_type::text, mandatory, state::text, version FROM trust_safety.policy_bundle WHERE id = $1 FOR UPDATE",
        )
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        let current_version: i64 = bundle.try_get("version")?;
        anyhow::ensure!(
            current_version == expected_bundle_version,
            "policy bundle version conflict"
        );
        let bundle_state: String = bundle.try_get("state")?;
        anyhow::ensure!(
            bundle_state != "RETIRED",
            "retired policy bundle is immutable"
        );
        let scope_type: String = bundle.try_get("scope_type")?;
        let mandatory: bool = bundle.try_get("mandatory")?;
        if scope_type == "PLATFORM" && mandatory {
            anyhow::ensure!(
                manifest.runtime_error_behavior != super::model::ErrorBehavior::Continue
                    && manifest
                        .required_features
                        .iter()
                        .all(|feature| feature.error_behavior
                            != super::model::ErrorBehavior::Continue),
                "global mandatory policies may not continue after provider or runtime errors"
            );
        }
        let version_number: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM trust_safety.policy_version WHERE bundle_id = $1",
        )
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        let source_sha256 = super::runtime::sha256_hex(source.as_bytes());
        sqlx::query(
            "INSERT INTO trust_safety.policy_version \
             (id, bundle_id, version, language, runtime_version, source, source_sha256, manifest, created_by) \
             VALUES ($1, $2, $3, $4::trust_safety.policy_language, '', $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(bundle_id)
        .bind(version_number)
        .bind(language_name(language))
        .bind(&source)
        .bind(&source_sha256)
        .bind(serde_json::to_value(&manifest)?)
        .bind(&context.actor_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE trust_safety.policy_bundle SET version = version + 1, updated_at = clock_timestamp() WHERE id = $1",
        )
        .bind(bundle_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            context,
            "CREATE_POLICY_DRAFT",
            "POLICY_VERSION",
            &id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        self.get_version(id).await
    }

    pub async fn get_version(&self, id: Uuid) -> anyhow::Result<PolicyVersion> {
        let row = sqlx::query(
            "SELECT id, bundle_id, version, language::text, runtime_version, source, compiled_artifact, source_sha256, artifact_sha256, manifest, state::text \
             FROM trust_safety.policy_version WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?;
        policy_version_from_row(&row)
    }

    pub async fn mark_validated(
        &self,
        id: Uuid,
        runtime_version: &str,
        artifact: &[u8],
        artifact_sha256: &str,
        diagnostics: serde_json::Value,
        context: &v2::RequestContext,
    ) -> anyhow::Result<PolicyVersion> {
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "VALIDATE_POLICY", id).await?
        {
            tx.rollback().await?;
            return self.get_version(existing).await;
        }
        let updated = sqlx::query(
            "UPDATE trust_safety.policy_version SET runtime_version = $2, compiled_artifact = $3, artifact_sha256 = $4, \
             validation_diagnostics = $5, state = 'VALIDATED', validated_at = clock_timestamp() \
             WHERE id = $1 AND state = 'DRAFT'",
        )
        .bind(id)
        .bind(runtime_version)
        .bind(artifact)
        .bind(artifact_sha256)
        .bind(diagnostics)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(
            updated.rows_affected() == 1,
            "policy version is not a draft"
        );
        insert_audit(
            &mut tx,
            context,
            "VALIDATE_POLICY",
            "POLICY_VERSION",
            &id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        self.get_version(id).await
    }

    pub async fn fixtures(&self, policy_version_id: Uuid) -> anyhow::Result<Vec<StoredFixture>> {
        let rows = sqlx::query(
            "SELECT id, policy_version_id, name, action, feature_snapshot, expected_effects, created_at, updated_at, version \
             FROM trust_safety.policy_fixture \
             WHERE policy_version_id = $1 AND committed = TRUE ORDER BY name",
        )
        .bind(policy_version_id)
            .fetch_all(&self.db)
            .await?;
        rows.iter().map(stored_fixture_from_row).collect()
    }

    pub async fn fixture(&self, fixture_id: Uuid) -> anyhow::Result<StoredFixture> {
        let row = sqlx::query(
            "SELECT id, policy_version_id, name, action, feature_snapshot, expected_effects, created_at, updated_at, version \
             FROM trust_safety.policy_fixture WHERE id = $1",
        )
        .bind(fixture_id)
        .fetch_one(&self.db)
        .await?;
        stored_fixture_from_row(&row)
    }

    pub async fn list_fixtures(
        &self,
        policy_version_id: Uuid,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Vec<StoredFixture>> {
        let rows = sqlx::query(
            "SELECT id, policy_version_id, name, action, feature_snapshot, expected_effects, created_at, updated_at, version \
             FROM trust_safety.policy_fixture WHERE policy_version_id = $1 \
             AND ($2::uuid IS NULL OR id > $2) ORDER BY id LIMIT $3",
        )
        .bind(policy_version_id)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.db)
        .await?;
        rows.iter().map(stored_fixture_from_row).collect()
    }

    pub async fn create_fixture(
        &self,
        policy_version_id: Uuid,
        name: &str,
        action: &Action,
        features: &FeatureSnapshot,
        expected_effects: &[Effect],
        context: &v2::RequestContext,
    ) -> anyhow::Result<StoredFixture> {
        anyhow::ensure!(!name.trim().is_empty(), "fixture name is required");
        let mut tx = self.db.begin().await?;
        let fixture_id = Uuid::now_v7();
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "CREATE_POLICY_FIXTURE", fixture_id).await?
        {
            tx.rollback().await?;
            return self.fixture(existing).await;
        }
        ensure_fixture_version_mutable(&mut tx, policy_version_id).await?;
        sqlx::query(
            "INSERT INTO trust_safety.policy_fixture \
             (id, policy_version_id, name, action, feature_snapshot, expected_effects) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(fixture_id)
        .bind(policy_version_id)
        .bind(name.trim())
        .bind(serde_json::to_value(action)?)
        .bind(serde_json::to_value(features)?)
        .bind(serde_json::to_value(expected_effects)?)
        .execute(&mut *tx)
        .await?;
        bump_fixture_revision(&mut tx, policy_version_id).await?;
        insert_audit(
            &mut tx,
            context,
            "CREATE_POLICY_FIXTURE",
            "POLICY_FIXTURE",
            &fixture_id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        self.fixture(fixture_id).await
    }

    // Fixture contents are separate typed values in both the contract and row;
    // keep them explicit alongside concurrency and audit context.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_fixture(
        &self,
        fixture_id: Uuid,
        name: &str,
        action: &Action,
        features: &FeatureSnapshot,
        expected_effects: &[Effect],
        expected_version: i64,
        context: &v2::RequestContext,
    ) -> anyhow::Result<StoredFixture> {
        anyhow::ensure!(!name.trim().is_empty(), "fixture name is required");
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "UPDATE_POLICY_FIXTURE", fixture_id).await?
        {
            tx.rollback().await?;
            return self.fixture(existing).await;
        }
        let policy_version_id: Uuid = sqlx::query_scalar(
            "SELECT policy_version_id FROM trust_safety.policy_fixture WHERE id = $1 FOR UPDATE",
        )
        .bind(fixture_id)
        .fetch_one(&mut *tx)
        .await?;
        ensure_fixture_version_mutable(&mut tx, policy_version_id).await?;
        let updated = sqlx::query(
            "UPDATE trust_safety.policy_fixture SET name = $2, action = $3, feature_snapshot = $4, \
             expected_effects = $5, version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $6",
        )
        .bind(fixture_id)
        .bind(name.trim())
        .bind(serde_json::to_value(action)?)
        .bind(serde_json::to_value(features)?)
        .bind(serde_json::to_value(expected_effects)?)
        .bind(expected_version)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(
            updated.rows_affected() == 1,
            "policy fixture version conflict"
        );
        bump_fixture_revision(&mut tx, policy_version_id).await?;
        insert_audit(
            &mut tx,
            context,
            "UPDATE_POLICY_FIXTURE",
            "POLICY_FIXTURE",
            &fixture_id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        self.fixture(fixture_id).await
    }

    pub async fn delete_fixture(
        &self,
        fixture_id: Uuid,
        expected_version: i64,
        context: &v2::RequestContext,
    ) -> anyhow::Result<()> {
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(_) =
            claim_policy_idempotency(&mut tx, context, "DELETE_POLICY_FIXTURE", fixture_id).await?
        {
            tx.rollback().await?;
            return Ok(());
        }
        let policy_version_id: Uuid = sqlx::query_scalar(
            "SELECT policy_version_id FROM trust_safety.policy_fixture WHERE id = $1 FOR UPDATE",
        )
        .bind(fixture_id)
        .fetch_one(&mut *tx)
        .await?;
        ensure_fixture_version_mutable(&mut tx, policy_version_id).await?;
        let deleted =
            sqlx::query("DELETE FROM trust_safety.policy_fixture WHERE id = $1 AND version = $2")
                .bind(fixture_id)
                .bind(expected_version)
                .execute(&mut *tx)
                .await?;
        anyhow::ensure!(
            deleted.rows_affected() == 1,
            "policy fixture version conflict"
        );
        bump_fixture_revision(&mut tx, policy_version_id).await?;
        insert_audit(
            &mut tx,
            context,
            "DELETE_POLICY_FIXTURE",
            "POLICY_FIXTURE",
            &fixture_id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn record_test_run(
        &self,
        policy_version_id: Uuid,
        passed: bool,
        results: serde_json::Value,
        context: &v2::RequestContext,
    ) -> anyhow::Result<()> {
        let mut tx = self.db.begin().await?;
        let test_run_id = Uuid::now_v7();
        if let PolicyIdempotencyClaim::Existing(_) =
            claim_policy_idempotency(&mut tx, context, "RUN_POLICY_TESTS", test_run_id).await?
        {
            tx.rollback().await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO trust_safety.policy_test_run \
             (id, policy_version_id, passed, results, fixture_revision, created_by) \
             SELECT $1, $2, $3, $4, fixture_revision, $5 FROM trust_safety.policy_version WHERE id = $2",
        )
        .bind(test_run_id)
        .bind(policy_version_id)
        .bind(passed)
        .bind(results)
        .bind(&context.actor_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn replayed_test_run(
        &self,
        context: &v2::RequestContext,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let row = sqlx::query(
            "SELECT mutation.operation, test.results \
             FROM trust_safety.mutation_idempotency mutation \
             LEFT JOIN trust_safety.policy_test_run test ON test.id = mutation.resource_id \
             WHERE mutation.service_principal = $1 AND mutation.actor_id = $2 \
               AND mutation.idempotency_key = $3",
        )
        .bind(&context.service_principal)
        .bind(&context.actor_id)
        .bind(&context.idempotency_key)
        .fetch_optional(&self.db)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let operation: String = row.try_get("operation")?;
        anyhow::ensure!(
            operation == "RUN_POLICY_TESTS",
            "idempotency key was already used for a different operation"
        );
        Ok(row.try_get("results")?)
    }

    pub async fn publish(
        &self,
        id: Uuid,
        context: &v2::RequestContext,
        expected_bundle_version: i64,
    ) -> anyhow::Result<PolicyVersion> {
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "PUBLISH_POLICY_VERSION", id).await?
        {
            tx.rollback().await?;
            return self.get_version(existing).await;
        }
        let row = sqlx::query(
            "SELECT state::text, bundle_id FROM trust_safety.policy_version WHERE id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let state: String = row.try_get("state")?;
        anyhow::ensure!(
            state == "VALIDATED",
            "policy version has not been validated"
        );
        let bundle_id: Uuid = row.try_get("bundle_id")?;
        let bundle_version: i64 = sqlx::query_scalar(
            "SELECT version FROM trust_safety.policy_bundle WHERE id = $1 FOR UPDATE",
        )
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        anyhow::ensure!(
            bundle_version == expected_bundle_version,
            "policy bundle version conflict"
        );
        let fixture_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM trust_safety.policy_fixture WHERE policy_version_id = $1 AND committed = TRUE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if fixture_count > 0 {
            let passed: Option<bool> = sqlx::query_scalar(
                "SELECT test.passed FROM trust_safety.policy_test_run test \
                 JOIN trust_safety.policy_version version ON version.id = test.policy_version_id \
                 WHERE test.policy_version_id = $1 AND test.fixture_revision = version.fixture_revision \
                 ORDER BY test.created_at DESC LIMIT 1",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            anyhow::ensure!(
                passed == Some(true),
                "committed policy fixtures have not passed"
            );
        }
        sqlx::query(
            "UPDATE trust_safety.policy_version SET published_at = COALESCE(published_at, clock_timestamp()) WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            context,
            "PUBLISH_POLICY_VERSION",
            "POLICY_VERSION",
            &id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        self.get_version(id).await
    }

    pub async fn approve(
        &self,
        policy_version_id: Uuid,
        context: &v2::RequestContext,
    ) -> anyhow::Result<chrono::DateTime<Utc>> {
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) = claim_policy_idempotency(
            &mut tx,
            context,
            "APPROVE_POLICY_VERSION",
            policy_version_id,
        )
        .await?
        {
            tx.rollback().await?;
            return self.approval(existing, &context.actor_id).await;
        }
        let row = sqlx::query(
            "SELECT bundle.scope_type::text AS scope_type, bundle.mandatory, version.published_at \
             FROM trust_safety.policy_version version \
             JOIN trust_safety.policy_bundle bundle ON bundle.id = version.bundle_id \
             WHERE version.id = $1 FOR UPDATE OF version",
        )
        .bind(policy_version_id)
        .fetch_one(&mut *tx)
        .await?;
        let scope_type: String = row.try_get("scope_type")?;
        let mandatory: bool = row.try_get("mandatory")?;
        let published_at: Option<chrono::DateTime<Utc>> = row.try_get("published_at")?;
        anyhow::ensure!(
            scope_type == "PLATFORM" && mandatory,
            "only mandatory platform policies require administrator approval"
        );
        anyhow::ensure!(
            published_at.is_some(),
            "policy version has not been published"
        );
        let approved_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO trust_safety.policy_approval (policy_version_id, administrator_id) \
             VALUES ($1, $2) ON CONFLICT (policy_version_id, administrator_id) \
             DO UPDATE SET administrator_id = EXCLUDED.administrator_id RETURNING approved_at",
        )
        .bind(policy_version_id)
        .bind(&context.actor_id)
        .fetch_one(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            context,
            "APPROVE_POLICY_VERSION",
            "POLICY_VERSION",
            &policy_version_id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(approved_at)
    }

    async fn approval(
        &self,
        policy_version_id: Uuid,
        administrator_id: &str,
    ) -> anyhow::Result<chrono::DateTime<Utc>> {
        Ok(sqlx::query_scalar(
            "SELECT approved_at FROM trust_safety.policy_approval \
             WHERE policy_version_id = $1 AND administrator_id = $2",
        )
        .bind(policy_version_id)
        .bind(administrator_id)
        .fetch_one(&self.db)
        .await?)
    }

    pub async fn set_shadow(
        &self,
        bundle_id: Uuid,
        version_id: Uuid,
        enabled: bool,
        context: &v2::RequestContext,
        expected_version: i64,
    ) -> anyhow::Result<PolicyBundle> {
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "SET_SHADOW_MODE", bundle_id).await?
        {
            tx.rollback().await?;
            return self.load_bundle(existing).await;
        }
        let bundle = sqlx::query(
            "SELECT version, shadow_version_id FROM trust_safety.policy_bundle WHERE id = $1 FOR UPDATE",
        )
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        anyhow::ensure!(
            bundle.try_get::<i64, _>("version")? == expected_version,
            "policy bundle version conflict"
        );
        if enabled {
            let published: bool = sqlx::query_scalar(
                "SELECT published_at IS NOT NULL FROM trust_safety.policy_version WHERE id = $1 AND bundle_id = $2",
            )
            .bind(version_id)
            .bind(bundle_id)
            .fetch_one(&mut *tx)
            .await?;
            anyhow::ensure!(
                published,
                "policy version must be published before shadow mode"
            );
        }
        let previous: Option<Uuid> = bundle.try_get("shadow_version_id")?;
        sqlx::query(
            "UPDATE trust_safety.policy_bundle SET shadow_version_id = $1, version = version + 1, updated_at = clock_timestamp() WHERE id = $2",
        )
        .bind(enabled.then_some(version_id))
        .bind(bundle_id)
        .execute(&mut *tx)
        .await?;
        if enabled {
            sqlx::query("UPDATE trust_safety.policy_version SET state = 'SHADOW' WHERE id = $1 AND state = 'VALIDATED'")
                .bind(version_id).execute(&mut *tx).await?;
        } else if let Some(previous) = previous {
            sqlx::query("UPDATE trust_safety.policy_version SET state = 'VALIDATED' WHERE id = $1 AND state = 'SHADOW'")
                .bind(previous).execute(&mut *tx).await?;
        }
        sqlx::query(
            "INSERT INTO trust_safety.policy_activation (bundle_id, from_version_id, to_version_id, activation_type, activated_by) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(bundle_id)
        .bind(previous)
        .bind(version_id)
        .bind(if enabled { "SHADOW_START" } else { "SHADOW_STOP" })
        .bind(&context.actor_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            context,
            if enabled {
                "SHADOW_START"
            } else {
                "SHADOW_STOP"
            },
            "POLICY_BUNDLE",
            &bundle_id.to_string(),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        self.load_bundle(bundle_id).await
    }

    pub async fn list_versions(
        &self,
        bundle_id: Uuid,
        limit: i64,
        before_version: Option<i32>,
    ) -> anyhow::Result<Vec<PolicyVersion>> {
        let rows = sqlx::query(
            "SELECT id, bundle_id, version, language::text, runtime_version, source, compiled_artifact, source_sha256, artifact_sha256, manifest, state::text \
             FROM trust_safety.policy_version WHERE bundle_id = $1 AND ($2::int IS NULL OR version < $2) ORDER BY version DESC LIMIT $3",
        )
        .bind(bundle_id)
        .bind(before_version)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        rows.iter().map(policy_version_from_row).collect()
    }

    pub async fn execution_trace(&self, id: Uuid) -> anyhow::Result<ExecutionTrace> {
        let value: serde_json::Value =
            sqlx::query_scalar("SELECT trace FROM trust_safety.execution_trace WHERE id = $1")
                .bind(id)
                .fetch_one(&self.db)
                .await?;
        Ok(serde_json::from_value(value)?)
    }

    pub async fn execution_trace_with_scope(
        &self,
        id: Uuid,
    ) -> anyhow::Result<(ExecutionTrace, Scope)> {
        let row = sqlx::query(
            "SELECT trace.trace, inbox.scope_type::text, inbox.scope_id \
             FROM trust_safety.execution_trace trace \
             JOIN trust_safety.action_inbox inbox ON inbox.action_id = trace.action_id \
             WHERE trace.id = $1",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?;
        let scope_type: String = row.try_get("scope_type")?;
        Ok((
            serde_json::from_value(row.try_get("trace")?)?,
            Scope {
                scope_type: parse_scope(&scope_type)?,
                id: row.try_get("scope_id")?,
                product: None,
            },
        ))
    }

    pub async fn schedule_activation(
        &self,
        bundle_id: Uuid,
        policy_version_id: Uuid,
        expected_bundle_version: i64,
        activation_type: &str,
        activate_at: chrono::DateTime<Utc>,
        context: &v2::RequestContext,
    ) -> anyhow::Result<Uuid> {
        let id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "SCHEDULE_POLICY_ACTIVATION", id).await?
        {
            tx.rollback().await?;
            return Ok(existing);
        }
        sqlx::query(
            "INSERT INTO trust_safety.scheduled_policy_activation \
             (id, bundle_id, policy_version_id, expected_bundle_version, activation_type, activate_at, requested_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(bundle_id)
        .bind(policy_version_id)
        .bind(expected_bundle_version)
        .bind(activation_type)
        .bind(activate_at)
        .bind(&context.actor_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(
            &mut tx,
            context,
            "SCHEDULE_POLICY_ACTIVATION",
            "POLICY_BUNDLE",
            &bundle_id.to_string(),
            None,
            Some(json!({"scheduled_activation_id": id, "activate_at": activate_at})),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn due_activations(&self) -> anyhow::Result<Vec<ScheduledActivation>> {
        let rows = sqlx::query(
            "WITH due AS ( \
                SELECT id FROM trust_safety.scheduled_policy_activation \
                WHERE (status = 'PENDING' AND activate_at <= clock_timestamp()) \
                   OR (status = 'PROCESSING' AND lease_until <= clock_timestamp()) \
                ORDER BY activate_at LIMIT 20 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE trust_safety.scheduled_policy_activation scheduled \
             SET status = 'PROCESSING', lease_until = clock_timestamp() + INTERVAL '1 minute' \
             FROM due WHERE scheduled.id = due.id \
             RETURNING scheduled.id, scheduled.bundle_id, scheduled.policy_version_id, \
                       scheduled.expected_bundle_version, scheduled.activation_type, scheduled.requested_by",
        )
        .fetch_all(&self.db)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ScheduledActivation {
                    id: row.try_get("id")?,
                    bundle_id: row.try_get("bundle_id")?,
                    policy_version_id: row.try_get("policy_version_id")?,
                    expected_bundle_version: row.try_get("expected_bundle_version")?,
                    activation_type: row.try_get("activation_type")?,
                    requested_by: row.try_get("requested_by")?,
                })
            })
            .collect()
    }

    pub async fn finish_scheduled_activation(
        &self,
        id: Uuid,
        error_code: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE trust_safety.scheduled_policy_activation SET status = $2, failure_code = $3, \
             applied_at = clock_timestamp(), lease_until = NULL WHERE id = $1 AND status = 'PROCESSING'",
        )
        .bind(id)
        .bind(if error_code.is_some() { "FAILED" } else { "APPLIED" })
        .bind(error_code)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn apply_delivery_callback(
        &self,
        action_id: Uuid,
        state: &str,
        failure_code: Option<&str>,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            matches!(state, "ACTIVE" | "DELIVERY_FAILED"),
            "invalid delivery callback state"
        );
        let updated = sqlx::query(
            "UPDATE trust_safety.action_inbox SET state = $2::trust_safety.message_state, \
             last_error_code = $3, processed_at = clock_timestamp() \
             WHERE action_id = $1 AND (state = 'APPROVED_PENDING_DELIVERY' \
             OR ($2 = 'ACTIVE' AND state = 'DELIVERY_FAILED'))",
        )
        .bind(action_id)
        .bind(state)
        .bind(failure_code)
        .execute(&self.db)
        .await?;
        if updated.rows_affected() == 1 {
            return Ok(true);
        }
        let current: Option<String> = sqlx::query_scalar(
            "SELECT state::text FROM trust_safety.action_inbox WHERE action_id = $1",
        )
        .bind(action_id)
        .fetch_optional(&self.db)
        .await?;
        Ok(current.as_deref() == Some(state))
    }

    pub async fn get_held_action(&self, action_id: Uuid) -> anyhow::Result<HeldActionRecord> {
        let row = sqlx::query(
            "SELECT a.action_id, d.id AS decision_id, a.scope_type::text, a.scope_id, \
             a.state::text, a.hold_until, a.version, a.resolved_by, a.resolution_reason \
             FROM trust_safety.action_inbox a \
             JOIN trust_safety.decision_record d ON d.action_id = a.action_id \
             WHERE a.action_id = $1",
        )
        .bind(action_id)
        .fetch_one(&self.db)
        .await?;
        let decision_id: Uuid = row.try_get("decision_id")?;
        let resolved_review_item_ids = sqlx::query_scalar(
            "SELECT id FROM trust_safety.review_item WHERE decision_id = $1 AND status <> 'PENDING' ORDER BY id",
        )
        .bind(decision_id)
        .fetch_all(&self.db)
        .await?;
        held_action_from_row(&row, resolved_review_item_ids)
    }

    pub async fn held_action_id_for_review_item(
        &self,
        review_item_id: Uuid,
    ) -> anyhow::Result<Uuid> {
        Ok(sqlx::query_scalar(
            "SELECT d.action_id FROM trust_safety.review_item r \
             JOIN trust_safety.decision_record d ON d.id = r.decision_id WHERE r.id = $1",
        )
        .bind(review_item_id)
        .fetch_one(&self.db)
        .await?)
    }

    pub async fn adjudicate_held_action(
        &self,
        context: &v2::RequestContext,
        action_id: Uuid,
        resolution: HeldActionResolution,
        reason: &str,
        expected_version: i64,
    ) -> anyhow::Result<HeldActionRecord> {
        anyhow::ensure!(!reason.trim().is_empty(), "resolution reason is required");
        anyhow::ensure!(reason.len() <= 2_000, "resolution reason is too long");
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "ADJUDICATE_HELD_ACTION", action_id).await?
        {
            anyhow::ensure!(
                existing == action_id,
                "idempotency key was used for another action"
            );
            tx.rollback().await?;
            return self.get_held_action(action_id).await;
        }

        let row = sqlx::query(
            "SELECT a.action_id, d.id AS decision_id, a.scope_type::text, a.scope_id, \
             a.state::text, a.hold_until, a.version, a.resolved_by, a.resolution_reason, \
             a.prism_payload_ciphertext \
             FROM trust_safety.action_inbox a \
             JOIN trust_safety.decision_record d ON d.action_id = a.action_id \
             WHERE a.action_id = $1 FOR UPDATE OF a",
        )
        .bind(action_id)
        .fetch_one(&mut *tx)
        .await?;
        let before = held_action_from_row(&row, Vec::new())?;
        anyhow::ensure!(
            before.state == "HELD",
            "action is not awaiting adjudication"
        );
        anyhow::ensure!(
            before.version == expected_version,
            "held action version conflict"
        );

        let (state, review_status, resolution_name) = held_resolution_values(resolution);
        if resolution == HeldActionResolution::Approve {
            let encrypted: Option<Vec<u8>> = row.try_get("prism_payload_ciphertext")?;
            if let Some(encrypted) = encrypted {
                let payload = self.cipher.open(&encrypted)?;
                prism::PrismStreamPayload::decode(payload.as_slice())
                    .map_err(|_| anyhow::anyhow!("stored Prism payload is invalid"))?;
                insert_outbox(
                    &mut tx,
                    "PRISM_JOB",
                    before.decision_id,
                    &self.prism_topic,
                    "fun.interchat.prism.job",
                    &scope_partition_key(&before.scope),
                    payload,
                )
                .await?;
            }
        }

        let updated = sqlx::query(
            "UPDATE trust_safety.action_inbox SET state = $2::trust_safety.message_state, \
             resolved_by = $3, resolution_reason = $4, processed_at = clock_timestamp(), \
             updated_at = clock_timestamp(), version = version + 1 \
             WHERE action_id = $1 AND state = 'HELD' AND version = $5",
        )
        .bind(action_id)
        .bind(state)
        .bind(&context.actor_id)
        .bind(reason)
        .bind(expected_version)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(updated.rows_affected() == 1, "held action version conflict");

        let review_rows = sqlx::query(
            "UPDATE trust_safety.review_item SET status = $2::trust_safety.resource_status, \
             resolution = $3, resolved_by = $4, version = version + 1, \
             updated_at = clock_timestamp() WHERE decision_id = $1 AND status = 'PENDING' RETURNING id",
        )
        .bind(before.decision_id)
        .bind(review_status)
        .bind(resolution_name)
        .bind(&context.actor_id)
        .fetch_all(&mut *tx)
        .await?;
        let resolved_review_item_ids = review_rows
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<Result<Vec<Uuid>, sqlx::Error>>()?;
        let mut after = before.clone();
        after.state = state.to_owned();
        after.version += 1;
        after.resolved_by = Some(context.actor_id.clone());
        after.resolution_reason = Some(reason.to_owned());
        after.resolved_review_item_ids = resolved_review_item_ids;
        insert_audit(
            &mut tx,
            context,
            "ADJUDICATE_HELD_ACTION",
            "HELD_ACTION",
            &action_id.to_string(),
            Some(held_action_audit_json(&before)),
            Some(held_action_audit_json(&after)),
        )
        .await?;
        tx.commit().await?;
        Ok(after)
    }

    pub async fn expire_due_held_actions(&self, limit: i64) -> anyhow::Result<u64> {
        let mut tx = self.db.begin().await?;
        let rows = sqlx::query(
            "SELECT a.action_id, d.id AS decision_id FROM trust_safety.action_inbox a \
             JOIN trust_safety.decision_record d ON d.action_id = a.action_id \
             WHERE a.state = 'HELD' AND a.hold_until IS NOT NULL \
             AND a.hold_until <= clock_timestamp() ORDER BY a.hold_until \
             FOR UPDATE OF a SKIP LOCKED LIMIT $1",
        )
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&mut *tx)
        .await?;
        for row in &rows {
            let action_id: Uuid = row.try_get("action_id")?;
            let decision_id: Uuid = row.try_get("decision_id")?;
            sqlx::query(
                "UPDATE trust_safety.action_inbox SET state = 'EXPIRED', \
                 resolved_by = 'polarizer-expiry-worker', resolution_reason = 'hold maximum duration elapsed', \
                 processed_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1 \
                 WHERE action_id = $1 AND state = 'HELD'",
            )
            .bind(action_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE trust_safety.review_item SET status = 'RESOLVED', resolution = 'EXPIRED', \
                 resolved_by = 'polarizer-expiry-worker', version = version + 1, updated_at = clock_timestamp() \
                 WHERE decision_id = $1 AND status = 'PENDING'",
            )
            .bind(decision_id)
            .execute(&mut *tx)
            .await?;
            let context = v2::RequestContext {
                request_id: Uuid::now_v7().to_string(),
                actor_id: "polarizer-expiry-worker".into(),
                actor_type: v2::ActorType::Service as i32,
                service_principal: "polarizer".into(),
                idempotency_key: format!("expire-held:{action_id}"),
                trace_id: String::new(),
            };
            insert_audit(
                &mut tx,
                &context,
                "EXPIRE_HELD_ACTION",
                "HELD_ACTION",
                &action_id.to_string(),
                None,
                Some(json!({"state": "EXPIRED", "decision_id": decision_id})),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    pub async fn activate(
        &self,
        bundle_id: Uuid,
        target_version_id: Uuid,
        context: &v2::RequestContext,
        expected_version: i64,
        activation_type: &str,
    ) -> anyhow::Result<PolicyBundle> {
        let mut tx = self.db.begin().await?;
        let operation = match activation_type {
            "ACTIVATE" => "ACTIVATE_POLICY_VERSION",
            "ROLLBACK" => "ROLLBACK_POLICY",
            _ => anyhow::bail!("invalid policy activation type"),
        };
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, operation, bundle_id).await?
        {
            tx.rollback().await?;
            return self.load_bundle(existing).await;
        }
        let bundle_row = sqlx::query(
            "SELECT scope_type::text, mandatory, active_version_id, version FROM trust_safety.policy_bundle WHERE id = $1 FOR UPDATE"
        ).bind(bundle_id).fetch_one(&mut *tx).await?;
        let current_version: i64 = bundle_row.try_get("version")?;
        anyhow::ensure!(
            current_version == expected_version,
            "policy bundle version conflict"
        );

        let version_row = sqlx::query(
            "SELECT state::text, published_at IS NOT NULL AS published FROM trust_safety.policy_version WHERE id = $1 AND bundle_id = $2",
        )
        .bind(target_version_id)
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        let state: String = version_row.try_get("state")?;
        let published: bool = version_row.try_get("published")?;
        anyhow::ensure!(
            matches!(
                state.as_str(),
                "VALIDATED" | "SHADOW" | "ACTIVE" | "RETIRED"
            ),
            "target policy version is not publishable"
        );
        anyhow::ensure!(published, "target policy version has not been published");

        let scope_type: String = bundle_row.try_get("scope_type")?;
        let mandatory: bool = bundle_row.try_get("mandatory")?;
        if scope_type == "PLATFORM" && mandatory {
            let approvals: i64 = sqlx::query_scalar(
                "SELECT COUNT(DISTINCT administrator_id) FROM trust_safety.policy_approval WHERE policy_version_id = $1"
            ).bind(target_version_id).fetch_one(&mut *tx).await?;
            anyhow::ensure!(
                approvals >= 2,
                "global mandatory policy activation requires two distinct administrators"
            );
        }

        let previous: Option<Uuid> = bundle_row.try_get("active_version_id")?;
        sqlx::query(
            "UPDATE trust_safety.policy_bundle SET active_version_id = $1, \
             shadow_version_id = CASE WHEN shadow_version_id = $1 THEN NULL ELSE shadow_version_id END, \
             version = version + 1, updated_at = clock_timestamp() WHERE id = $2"
        ).bind(target_version_id).bind(bundle_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE trust_safety.policy_version SET state = 'ACTIVE', published_at = COALESCE(published_at, clock_timestamp()) WHERE id = $1")
            .bind(target_version_id).execute(&mut *tx).await?;
        if let Some(previous) = previous.filter(|id| *id != target_version_id) {
            sqlx::query("UPDATE trust_safety.policy_version SET state = 'RETIRED' WHERE id = $1")
                .bind(previous)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "INSERT INTO trust_safety.policy_activation (bundle_id, from_version_id, to_version_id, activation_type, activated_by) VALUES ($1, $2, $3, $4, $5)"
        ).bind(bundle_id).bind(previous).bind(target_version_id).bind(activation_type).bind(&context.actor_id).execute(&mut *tx).await?;
        insert_audit(
            &mut tx,
            context,
            activation_type,
            "POLICY_BUNDLE",
            &bundle_id.to_string(),
            None,
            None,
        )
        .await?;
        let new_bundle_version = current_version + 1;
        insert_outbox(
            &mut tx,
            "POLICY_BUNDLE",
            bundle_id,
            &self.policy_invalidation_topic,
            "interchat.trust-safety.policy.invalidated.v2",
            &bundle_id.to_string(),
            v2::PolicyCacheInvalidated {
                bundle_id: bundle_id.to_string(),
                active_policy_version_id: target_version_id.to_string(),
                bundle_version: new_bundle_version as u64,
                occurred_at: Some(timestamp(Utc::now())),
            }
            .encode_to_vec(),
        )
        .await?;
        tx.commit().await?;
        self.load_bundle(bundle_id).await
    }

    pub async fn load_bundle(&self, id: Uuid) -> anyhow::Result<PolicyBundle> {
        let row = sqlx::query(
            "SELECT id, name, description, scope_type::text, scope_id, product, mandatory, priority, active_version_id, shadow_version_id, state::text, version, created_at, updated_at FROM trust_safety.policy_bundle WHERE id = $1"
        ).bind(id).fetch_one(&self.db).await?;
        bundle_from_row(&row)
    }
}

#[async_trait]
impl PolicyRepository for PostgresPolicyRepository {
    async fn active_policies(&self, action: &Action) -> anyhow::Result<Vec<ActivePolicy>> {
        let rows = sqlx::query(
            "SELECT b.id AS bundle_id, b.name, b.description, b.scope_type::text, b.scope_id, b.product, b.mandatory, b.priority, b.active_version_id, b.shadow_version_id, b.state::text AS bundle_state, b.version AS bundle_version, b.created_at AS bundle_created_at, b.updated_at AS bundle_updated_at, \
                    v.id AS policy_version_id, v.version AS policy_version, v.language::text, v.runtime_version, v.source, v.compiled_artifact, v.source_sha256, v.artifact_sha256, v.manifest, v.state::text, \
                    (v.id = b.shadow_version_id) AS is_shadow \
             FROM trust_safety.policy_bundle b \
             JOIN trust_safety.policy_version v ON v.id = b.active_version_id OR v.id = b.shadow_version_id \
             WHERE b.state = 'ACTIVE' AND (b.active_version_id IS NOT NULL OR b.shadow_version_id IS NOT NULL) \
             ORDER BY CASE b.scope_type WHEN 'PLATFORM' THEN 0 WHEN 'PRODUCT' THEN 1 WHEN 'HUB' THEN 2 WHEN 'LOBBY' THEN 2 ELSE 3 END, b.priority, v.version"
        ).fetch_all(&self.db).await?;
        let mut policies = Vec::new();
        for row in rows {
            let bundle = bundle_from_joined_row(&row)?;
            if !bundle.scope.applies_to(action) {
                continue;
            }
            let language: String = row.try_get("language")?;
            let state: String = row.try_get("state")?;
            policies.push(ActivePolicy {
                bundle: bundle.clone(),
                version: PolicyVersion {
                    id: row.try_get("policy_version_id")?,
                    bundle_id: bundle.id,
                    version: row.try_get("policy_version")?,
                    language: parse_language(&language)?,
                    runtime_version: row.try_get("runtime_version")?,
                    source: row.try_get("source")?,
                    compiled_artifact: row
                        .try_get::<Option<Vec<u8>>, _>("compiled_artifact")?
                        .unwrap_or_default(),
                    source_sha256: row.try_get("source_sha256")?,
                    artifact_sha256: row
                        .try_get::<Option<String>, _>("artifact_sha256")?
                        .unwrap_or_default(),
                    manifest: serde_json::from_value(row.try_get("manifest")?)?,
                    state: parse_state(&state)?,
                },
                shadow: row.try_get("is_shadow")?,
            });
        }
        Ok(policies)
    }

    async fn persist_and_apply(
        &self,
        action: &Action,
        result: &EvaluationResult,
    ) -> anyhow::Result<PersistOutcome> {
        let approved_content = build_approved_content(action, result)?;
        let approved_prism_payload =
            build_approved_prism_payload(action, result, approved_content.as_deref())?;
        let mut action_without_prism = action.clone();
        action_without_prism.prism_payload = None;
        let action_ciphertext = self
            .cipher
            .seal(&serde_json::to_vec(&action_without_prism)?)?;
        let prism_ciphertext = action
            .prism_payload
            .as_ref()
            .map(|payload| self.cipher.seal(payload))
            .transpose()?;
        let mut tx = self.db.begin().await?;
        let (subject_type, subject_id) = optional_primary_subject(&action.subject);
        let inserted = sqlx::query(
            "INSERT INTO trust_safety.action_inbox \
             (action_id, action_type, schema_version, scope_type, scope_id, subject_type, subject_id, partition_key, action_ciphertext, prism_payload_ciphertext, encryption_key_id) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (action_id) DO NOTHING"
        )
        .bind(action.id).bind(&action.action_type).bind(action.schema_version as i32)
        .bind(scope_name(action.scope.scope_type)).bind(&action.scope.id)
        .bind(subject_type).bind(subject_id)
        .bind(scope_partition_key(&action.scope))
        .bind(action_ciphertext).bind(prism_ciphertext).bind(&self.encryption_key_id)
        .execute(&mut *tx).await?;
        if inserted.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(PersistOutcome::Duplicate);
        }

        append_lobby_evidence_event(&mut tx, action).await?;

        let effects_json = serde_json::to_value(&result.accepted_effects)?;
        let policy_versions = serde_json::to_value(&result.trace.policy_versions)?;
        let provider_versions = json!(
            result
                .trace
                .features
                .iter()
                .map(|(name, value)| (name, &value.provider_version))
                .collect::<HashMap<_, _>>()
        );
        sqlx::query(
            "INSERT INTO trust_safety.decision_record (id, action_id, decision, reason_codes, effects, policy_versions, provider_versions, shadow) \
             VALUES ($1, $2, $3::trust_safety.decision, $4, $5, $6, $7, $8)"
        ).bind(result.id).bind(action.id).bind(decision_name(result.decision)).bind(&result.reason_codes)
        .bind(effects_json).bind(policy_versions).bind(provider_versions).bind(result.shadow)
        .execute(&mut *tx).await?;

        if result.trace.sampled || matches!(result.decision, Decision::Block | Decision::Hold) {
            sqlx::query(
                "INSERT INTO trust_safety.execution_trace (id, action_id, decision_id, trace, final_decision, sampled) VALUES ($1, $2, $3, $4, $5::trust_safety.decision, $6)"
            ).bind(result.trace.id).bind(action.id).bind(result.id).bind(serde_json::to_value(&result.trace)?)
            .bind(decision_name(result.decision)).bind(result.trace.sampled).execute(&mut *tx).await?;
        }

        for emitted in &result.accepted_effects {
            apply_effect(&mut tx, result.id, action, emitted, &self.command_topic).await?;
            if let Some(command) = command_for_effect(result.id, &emitted.effect) {
                register_command(&mut tx, &command).await?;
                insert_outbox(
                    &mut tx,
                    "COMMAND",
                    result.id,
                    &self.command_topic,
                    "interchat.trust-safety.command.v2",
                    &command.id,
                    command.encode_to_vec(),
                )
                .await?;
            }
        }

        let state = match result.decision {
            Decision::Allow | Decision::Censor if approved_prism_payload.is_none() => "ACTIVE",
            Decision::Allow | Decision::Censor => "APPROVED_PENDING_DELIVERY",
            Decision::Hold => "HELD",
            Decision::Block => "BLOCKED",
        };
        let hold_until = hold_deadline(&result.accepted_effects, Utc::now());
        sqlx::query("UPDATE trust_safety.action_inbox SET state = $1::trust_safety.message_state, \
                     hold_until = $3, processed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE action_id = $2")
            .bind(state).bind(action.id).bind(hold_until).execute(&mut *tx).await?;

        let decision_event = v2::DecisionPublished {
            decision: Some(v2::PolicyDecision {
                id: result.id.to_string(),
                action_id: action.id.to_string(),
                decision: proto_decision(result.decision),
                reason_codes: result.reason_codes.clone(),
                accepted_effects: result
                    .accepted_effects
                    .iter()
                    .map(emitted_effect_to_proto)
                    .collect(),
                rejected_effects: result
                    .rejected_effects
                    .iter()
                    .map(|rejected| v2::RejectedEffect {
                        effect: Some(emitted_effect_to_proto(&rejected.effect)),
                        reason: rejected.reason.clone(),
                        superseded_by_effect_id: rejected.superseded_by.clone().unwrap_or_default(),
                    })
                    .collect(),
                execution_trace_id: result.trace.id.to_string(),
                decided_at: Some(timestamp(Utc::now())),
                shadow: result.shadow,
            }),
            approved_prism_payload: approved_prism_payload.clone(),
            scope: Some(scope_to_proto(&action.scope)),
            subject: Some(subject_to_proto(&action.subject)),
            approved_content,
        };
        insert_outbox(
            &mut tx,
            "DECISION",
            result.id,
            &self.decision_topic,
            "interchat.trust-safety.decision.v2",
            &scope_partition_key(&action.scope),
            decision_event.encode_to_vec(),
        )
        .await?;
        if matches!(result.decision, Decision::Allow | Decision::Censor)
            && let Some(payload) = approved_prism_payload
        {
            insert_outbox(
                &mut tx,
                "PRISM_JOB",
                result.id,
                &self.prism_topic,
                "fun.interchat.prism.job",
                &scope_partition_key(&action.scope),
                payload.encode_to_vec(),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(PersistOutcome::Applied)
    }

    async fn persist_shadow_comparison(
        &self,
        action: &Action,
        active: &EvaluationResult,
        shadow: &EvaluationResult,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(shadow.shadow, "shadow comparison requires a shadow result");
        anyhow::ensure!(
            active.action_id == action.id && shadow.action_id == action.id,
            "decision action mismatch"
        );
        let differences = effect_differences(active, shadow);
        let mut tx = self.db.begin().await?;
        if shadow.trace.sampled
            || matches!(shadow.decision, Decision::Block | Decision::Hold)
            || active.decision != shadow.decision
        {
            sqlx::query(
                "INSERT INTO trust_safety.execution_trace (id, action_id, trace, final_decision, sampled) \
                 VALUES ($1, $2, $3, $4::trust_safety.decision, $5) ON CONFLICT (id) DO NOTHING",
            )
            .bind(shadow.trace.id)
            .bind(action.id)
            .bind(serde_json::to_value(&shadow.trace)?)
            .bind(decision_name(shadow.decision))
            .bind(shadow.trace.sampled)
            .execute(&mut *tx)
            .await?;
        }
        for policy_version_id in &shadow.trace.policy_versions {
            sqlx::query(
                "INSERT INTO trust_safety.shadow_result \
                 (action_id, bundle_id, active_decision_id, shadow_policy_version_id, shadow_decision, effect_differences) \
                 SELECT $1, bundle_id, $2, id, $3::trust_safety.decision, $4 \
                 FROM trust_safety.policy_version WHERE id = $5",
            )
            .bind(action.id)
            .bind(active.id)
            .bind(decision_name(shadow.decision))
            .bind(&differences)
            .bind(policy_version_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

fn effect_differences(active: &EvaluationResult, shadow: &EvaluationResult) -> serde_json::Value {
    let active_effects = active
        .accepted_effects
        .iter()
        .map(|emitted| (emitted.effect.id(), &emitted.effect))
        .collect::<HashMap<_, _>>();
    let shadow_effects = shadow
        .accepted_effects
        .iter()
        .map(|emitted| (emitted.effect.id(), &emitted.effect))
        .collect::<HashMap<_, _>>();
    let mut differences = Vec::new();
    if active.decision != shadow.decision {
        differences.push(json!({
            "type": "DECISION_CHANGED",
            "active": decision_name(active.decision),
            "shadow": decision_name(shadow.decision),
        }));
    }
    for (id, effect) in &active_effects {
        match shadow_effects.get(id) {
            None => differences.push(json!({"type": "REMOVED_EFFECT", "effect_id": id})),
            Some(shadow_effect) if *shadow_effect != *effect => {
                differences.push(json!({"type": "CHANGED_EFFECT", "effect_id": id}));
            }
            Some(_) => {}
        }
    }
    for id in shadow_effects.keys() {
        if !active_effects.contains_key(id) {
            differences.push(json!({"type": "ADDED_EFFECT", "effect_id": id}));
        }
    }
    serde_json::Value::Array(differences)
}

fn build_approved_content(
    action: &Action,
    result: &EvaluationResult,
) -> anyhow::Result<Option<String>> {
    if !matches!(result.decision, Decision::Allow | Decision::Censor) {
        return Ok(None);
    }
    if action.prism_payload.is_none() {
        return Ok(None);
    }
    let content = action
        .attributes
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("approving decision requires canonical string content"))?;
    if result.decision == Decision::Allow {
        return Ok(Some(content.to_owned()));
    }

    let replacements = censor_replacements(result);
    anyhow::ensure!(
        !replacements.is_empty(),
        "censor decision did not include any character spans"
    );
    Ok(Some(apply_censors_to_content(content, replacements)?))
}

fn censor_replacements(result: &EvaluationResult) -> Vec<(usize, usize, String)> {
    result
        .accepted_effects
        .iter()
        .filter_map(|emitted| match &emitted.effect {
            Effect::Censor {
                spans, replacement, ..
            } => Some(
                spans
                    .iter()
                    .map(|span| {
                        (
                            span.start_character as usize,
                            span.end_character as usize,
                            replacement.clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect()
}

fn build_approved_prism_payload(
    action: &Action,
    result: &EvaluationResult,
    approved_content: Option<&str>,
) -> anyhow::Result<Option<prism::PrismStreamPayload>> {
    if !matches!(result.decision, Decision::Allow | Decision::Censor) {
        return Ok(None);
    }
    let Some(bytes) = action.prism_payload.as_deref() else {
        return Ok(None);
    };
    let mut payload = prism::PrismStreamPayload::decode(bytes)?;
    // Polarizer owns the moderation identity. Never trust a producer-supplied
    // value here: Prism callbacks must correlate to the action we persisted.
    payload.action_id = Some(action.id.to_string());
    let structured_prefix = action
        .attributes
        .get("content_prefix")
        .and_then(serde_json::Value::as_str);
    if let Some(prefix) = structured_prefix {
        let mut body: serde_json::Value = serde_json::from_str(&payload.payload)
            .map_err(|_| anyhow::anyhow!("Prism content payload is not valid JSON"))?;
        let canonical = approved_content
            .ok_or_else(|| anyhow::anyhow!("approving decision requires canonical content"))?;
        if body
            .get("content")
            .is_some_and(serde_json::Value::is_string)
        {
            body["content"] =
                serde_json::Value::String(compose_delivery_content(prefix, canonical));
            payload.payload = serde_json::to_string(&body)?;
        }
    } else if result.decision == Decision::Censor {
        // Rolling-upgrade compatibility for producers that do not yet send
        // structured presentation metadata. Remove after all producers use it.
        let mut body: serde_json::Value = serde_json::from_str(&payload.payload)
            .map_err(|_| anyhow::anyhow!("Prism content payload is not valid JSON"))?;
        let content = body
            .get("content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("censor decision requires a string content field"))?;
        body["content"] = serde_json::Value::String(apply_censors_to_content(
            content,
            censor_replacements(result),
        )?);
        payload.payload = serde_json::to_string(&body)?;
    }
    if let Some(plan) = result.content_policy.as_ref() {
        apply_content_policy_plan(action, &mut payload, plan)?;
        if payload.targets.is_empty() {
            return Ok(None);
        }
    }
    Ok(Some(payload))
}

fn apply_content_policy_plan(
    action: &Action,
    payload: &mut prism::PrismStreamPayload,
    plan: &crate::content_policy::ContentPolicyPlan,
) -> anyhow::Result<()> {
    let structured_prefix = action
        .attributes
        .get("content_prefix")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match plan {
        crate::content_policy::ContentPolicyPlan::Call(plan) => {
            let decisions = plan
                .destinations
                .iter()
                .map(|decision| (decision.target_index, decision))
                .collect::<HashMap<_, _>>();
            let mut retained = Vec::with_capacity(payload.targets.len());
            for (target_index, mut target) in payload.targets.drain(..).enumerate() {
                let Some(decision) = decisions.get(&target_index) else {
                    continue;
                };
                if decision.is_blocked() {
                    continue;
                }
                let fingerprint = decision.variant_fingerprint.ok_or_else(|| {
                    anyhow::anyhow!("allowed content-policy destination has no delivery variant")
                })?;
                let variant = plan
                    .variants
                    .get(&fingerprint)
                    .ok_or_else(|| anyhow::anyhow!("content-policy delivery variant is missing"))?;
                let mut overrides = target
                    .overrides
                    .as_deref()
                    .map(serde_json::from_str::<serde_json::Value>)
                    .transpose()
                    .map_err(|_| anyhow::anyhow!("Prism target overrides are not valid JSON"))?
                    .unwrap_or_else(|| serde_json::json!({}));
                anyhow::ensure!(
                    overrides.is_object(),
                    "Prism target overrides must be a JSON object"
                );
                apply_call_delivery_variant(action, &mut overrides, structured_prefix, variant);
                target.overrides = Some(serde_json::to_string(&overrides)?);
                retained.push(target);
            }
            payload.targets = retained;
        }
        crate::content_policy::ContentPolicyPlan::Hub(plan) => {
            let decisions = plan
                .destinations
                .iter()
                .map(|decision| (decision.target_index, decision))
                .collect::<HashMap<_, _>>();
            let mut retained = Vec::with_capacity(payload.targets.len());
            for (target_index, mut target) in payload.targets.drain(..).enumerate() {
                let Some(decision) = decisions.get(&target_index) else {
                    // A target without a policy decision is unsafe to deliver:
                    // the decoded target set is the evaluator's exact input.
                    continue;
                };
                if decision.is_blocked() {
                    continue;
                }
                let fingerprint = decision.variant_fingerprint.ok_or_else(|| {
                    anyhow::anyhow!("allowed content-policy destination has no delivery variant")
                })?;
                let variant = plan
                    .variants
                    .get(&fingerprint)
                    .ok_or_else(|| anyhow::anyhow!("content-policy delivery variant is missing"))?;
                let mut overrides = target
                    .overrides
                    .as_deref()
                    .map(serde_json::from_str::<serde_json::Value>)
                    .transpose()
                    .map_err(|_| anyhow::anyhow!("Prism target overrides are not valid JSON"))?
                    .unwrap_or_else(|| serde_json::json!({}));
                anyhow::ensure!(
                    overrides.is_object(),
                    "Prism target overrides must be a JSON object"
                );
                apply_hub_delivery_variant(action, &mut overrides, structured_prefix, variant);
                target.overrides = Some(serde_json::to_string(&overrides)?);
                retained.push(target);
            }
            payload.targets = retained;
        }
    }
    Ok(())
}

fn apply_hub_delivery_variant(
    action: &Action,
    body: &mut serde_json::Value,
    prefix: &str,
    variant: &crate::content_policy::DeliveryVariant,
) {
    body["content"] =
        serde_json::Value::String(compose_delivery_content(prefix, &variant.message_content));

    let orig_display_name = action
        .attributes
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let orig_username = action
        .attributes
        .get("username")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let orig_server_name = action
        .attributes
        .get("server_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let use_nicknames = action
        .attributes
        .get("use_nicknames")
        .and_then(serde_json::Value::as_bool);

    let (user_part, orig_user_part) = match use_nicknames {
        Some(false) => (variant.username.as_ref(), orig_username),
        Some(true) => (variant.display_name.as_ref(), orig_display_name),
        None => {
            if variant.display_name.as_ref() != orig_display_name {
                (variant.display_name.as_ref(), orig_display_name)
            } else if variant.username.as_ref() != orig_username {
                (variant.username.as_ref(), orig_username)
            } else if !orig_display_name.is_empty() || !variant.display_name.is_empty() {
                (variant.display_name.as_ref(), orig_display_name)
            } else {
                (variant.username.as_ref(), orig_username)
            }
        }
    };

    let user_changed = user_part != orig_user_part;
    let server_changed = variant.server_name.as_ref() != orig_server_name;

    if user_changed || server_changed {
        let safe_user = if user_part.is_empty() {
            crate::content_policy::delivery::DEFAULT_SAFE_NAME
        } else {
            user_part
        };
        let safe_server = variant.server_name.as_ref();
        let formatted = if safe_server.is_empty() {
            safe_user.to_owned()
        } else {
            format!("{safe_user} | {safe_server}")
        };
        body["username"] = serde_json::Value::String(truncate_chars(&formatted, 80));
    }

    if variant.suppress_links {
        let flags = body
            .get("flags")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        body["flags"] = serde_json::Value::from(flags | 4);
    }
}

fn apply_call_delivery_variant(
    action: &Action,
    body: &mut serde_json::Value,
    prefix: &str,
    variant: &crate::content_policy::DeliveryVariant,
) {
    body["content"] =
        serde_json::Value::String(compose_delivery_content(prefix, &variant.message_content));

    let orig_display_name = action
        .attributes
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let orig_username = action
        .attributes
        .get("username")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let orig_server_name = action
        .attributes
        .get("server_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let (user_part, orig_user_part) = if variant.display_name.as_ref() != orig_display_name {
        (variant.display_name.as_ref(), orig_display_name)
    } else if variant.username.as_ref() != orig_username {
        (variant.username.as_ref(), orig_username)
    } else if !orig_display_name.is_empty() || !variant.display_name.is_empty() {
        (variant.display_name.as_ref(), orig_display_name)
    } else {
        (variant.username.as_ref(), orig_username)
    };

    let user_changed = (variant.display_name.as_ref() != orig_display_name)
        || (variant.username.as_ref() != orig_username);
    let server_changed = variant.server_name.as_ref() != orig_server_name;

    let existing_username = body
        .get("username")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let shows_server_name = !orig_server_name.is_empty()
        && (existing_username.ends_with(&format!("({orig_server_name})"))
            || (existing_username.contains('(') && existing_username.ends_with(')')));

    if shows_server_name {
        if user_changed || server_changed {
            let safe_user = if user_part.is_empty() {
                crate::content_policy::delivery::DEFAULT_SAFE_NAME
            } else {
                user_part
            };
            let safe_server = variant.server_name.as_ref();
            let formatted = if safe_server.is_empty() {
                safe_user.to_owned()
            } else {
                format!("{safe_user} ({safe_server})")
            };
            body["username"] = serde_json::Value::String(truncate_chars(&formatted, 80));
        }
    } else {
        // Server name is not shown in this call target.
        // Only update the username if the user's name itself was modified.
        if user_changed {
            let safe_user = if user_part.is_empty() {
                crate::content_policy::delivery::DEFAULT_SAFE_NAME
            } else {
                user_part
            };
            body["username"] = serde_json::Value::String(truncate_chars(safe_user, 80));
        }
    }

    if variant.suppress_links {
        let flags = body
            .get("flags")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        body["flags"] = serde_json::Value::from(flags | 4);
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn compose_delivery_content(prefix: &str, canonical: &str) -> String {
    const DISCORD_CONTENT_LIMIT: usize = 2_000;
    let prefix_chars = prefix
        .chars()
        .take(DISCORD_CONTENT_LIMIT)
        .collect::<String>();
    let remaining = DISCORD_CONTENT_LIMIT.saturating_sub(prefix_chars.chars().count());
    let body = canonical.chars().take(remaining).collect::<String>();
    format!("{prefix_chars}{body}")
}

fn hold_deadline(
    effects: &[EmittedEffect],
    now: chrono::DateTime<Utc>,
) -> Option<chrono::DateTime<Utc>> {
    effects
        .iter()
        .filter_map(|emitted| match emitted.effect {
            Effect::Hold {
                maximum_duration_ms: Some(duration),
                ..
            } => Some(duration),
            _ => None,
        })
        .min()
        .and_then(|duration| i64::try_from(duration).ok())
        .and_then(|duration| now.checked_add_signed(chrono::Duration::milliseconds(duration)))
}

fn held_resolution_values(
    resolution: HeldActionResolution,
) -> (&'static str, &'static str, &'static str) {
    match resolution {
        HeldActionResolution::Approve => ("APPROVED_PENDING_DELIVERY", "DISMISSED", "APPROVED"),
        HeldActionResolution::Reject => ("BLOCKED", "RESOLVED", "REJECTED"),
        HeldActionResolution::Expire => ("EXPIRED", "RESOLVED", "EXPIRED"),
    }
}

fn held_action_from_row(
    row: &sqlx::postgres::PgRow,
    resolved_review_item_ids: Vec<Uuid>,
) -> anyhow::Result<HeldActionRecord> {
    let scope_type: String = row.try_get("scope_type")?;
    let scope_type = parse_scope(&scope_type)?;
    Ok(HeldActionRecord {
        action_id: row.try_get("action_id")?,
        decision_id: row.try_get("decision_id")?,
        scope: Scope {
            scope_type,
            id: row.try_get("scope_id")?,
            product: match scope_type {
                ScopeType::Hub => Some(Product::Hub),
                ScopeType::Lobby => Some(Product::Lobby),
                _ => None,
            },
        },
        state: row.try_get("state")?,
        hold_until: row.try_get("hold_until")?,
        version: row.try_get("version")?,
        resolved_by: row.try_get("resolved_by")?,
        resolution_reason: row.try_get("resolution_reason")?,
        resolved_review_item_ids,
    })
}

fn held_action_audit_json(record: &HeldActionRecord) -> serde_json::Value {
    json!({
        "action_id": record.action_id,
        "decision_id": record.decision_id,
        "state": record.state,
        "hold_until": record.hold_until,
        "version": record.version,
        "resolved_by": record.resolved_by,
        "resolution_reason": record.resolution_reason,
        "resolved_review_item_ids": record.resolved_review_item_ids,
    })
}

fn apply_censors_to_content(
    content: &str,
    mut replacements: Vec<(usize, usize, String)>,
) -> anyhow::Result<String> {
    let mut characters = content.chars().collect::<Vec<_>>();
    replacements.sort_by_key(|(start, end, _)| (*start, *end));
    let mut prior_end = 0usize;
    for (index, (start, end, _)) in replacements.iter().enumerate() {
        anyhow::ensure!(start < end, "censor span must not be empty");
        anyhow::ensure!(*end <= characters.len(), "censor span is out of bounds");
        anyhow::ensure!(index == 0 || *start >= prior_end, "censor spans overlap");
        prior_end = *end;
    }
    for (start, end, replacement) in replacements.into_iter().rev() {
        characters.splice(start..end, replacement.chars());
    }
    Ok(characters.into_iter().collect())
}

async fn apply_effect(
    tx: &mut Transaction<'_, Postgres>,
    decision_id: Uuid,
    action: &Action,
    emitted: &EmittedEffect,
    command_topic: &str,
) -> anyhow::Result<()> {
    let effect = &emitted.effect;
    validate_effect_for_action(effect, action)?;
    let action_scope_type = scope_name(action.scope.scope_type);
    let action_scope_id = &action.scope.id;
    let policy_actor = if emitted.origin.policy_version_id.is_nil() {
        format!(
            "content-policy:{}:rule:{}",
            emitted.origin.policy_bundle_id, emitted.origin.rule_id
        )
    } else {
        format!("policy:{}", emitted.origin.policy_version_id)
    };
    match effect {
        Effect::CreateRestriction {
            subject,
            restriction_type,
            reason,
            duration_ms,
            ..
        } => {
            let (subject_type, subject_id) = primary_subject(subject)?;
            let effect_scope_type = scope_name(emitted.origin.scope.scope_type);
            let effect_scope_id = &emitted.origin.scope.id;
            let source_policy_version_id = (!emitted.origin.policy_version_id.is_nil())
                .then_some(emitted.origin.policy_version_id);
            let expires_at = duration_ms
                .map(|duration| Utc::now() + chrono::Duration::milliseconds(duration as i64));
            let restriction_row = sqlx::query(
                "INSERT INTO trust_safety.restriction \
                 (subject_type, subject_id, scope_type, scope_id, restriction_type, reason, source_action_id, source_policy_version_id, created_by, expires_at) \
                 VALUES ($1, $2, $3::trust_safety.scope_type, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (subject_type, subject_id, scope_type, scope_id, restriction_type) WHERE status = 'ACTIVE' \
                 DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at, \
                   source_action_id = EXCLUDED.source_action_id, source_policy_version_id = EXCLUDED.source_policy_version_id, \
                   created_by = EXCLUDED.created_by, version = trust_safety.restriction.version + 1, updated_at = clock_timestamp() \
                 RETURNING id, version",
            )
            .bind(subject_type)
            .bind(subject_id)
            .bind(effect_scope_type)
            .bind(effect_scope_id)
            .bind(restriction_type)
            .bind(automated_reason(reason))
            .bind(action.id)
            .bind(source_policy_version_id)
            .bind(&policy_actor)
            .bind(expires_at)
            .fetch_one(&mut **tx)
            .await?;
            let restriction_id: Uuid = restriction_row.try_get("id")?;
            let restriction_version: i64 = restriction_row.try_get("version")?;
            insert_policy_audit(
                tx,
                action,
                emitted,
                "APPLY_CREATE_RESTRICTION",
                "RESTRICTION",
                &restriction_id.to_string(),
            )
            .await?;
            if let Some(user_id) = subject.user_id.as_deref() {
                insert_moderation_notice_command(
                    tx,
                    command_topic,
                    decision_id,
                    action,
                    emitted,
                    user_id,
                    None,
                    Some(restriction_id),
                    expires_at,
                    restriction_version,
                )
                .await?;
            }
        }
        Effect::CreateInfraction {
            subject,
            infraction_type,
            reason,
            duration_ms,
            enforcement,
            ..
        } => {
            let (subject_type, subject_id) = primary_subject(subject)?;
            let effect_scope_type = scope_name(emitted.origin.scope.scope_type);
            let effect_scope_id = &emitted.origin.scope.id;
            let source_policy_version_id = (!emitted.origin.policy_version_id.is_nil())
                .then_some(emitted.origin.policy_version_id);
            let expires_at = duration_ms
                .map(|duration| Utc::now() + chrono::Duration::milliseconds(duration as i64));
            let enforcement_restriction_id = if let Some(enforcement) = enforcement {
                let (enforcement_subject_type, enforcement_subject_id) =
                    primary_subject(&enforcement.subject)?;
                let restriction_expires_at = enforcement
                    .duration_ms
                    .map(|duration| Utc::now() + chrono::Duration::milliseconds(duration as i64));
                let restriction_id: Uuid = sqlx::query_scalar(
                    "INSERT INTO trust_safety.restriction \
                     (subject_type, subject_id, scope_type, scope_id, restriction_type, reason, source_action_id, source_policy_version_id, created_by, expires_at) \
                     VALUES ($1, $2, $3::trust_safety.scope_type, $4, $5, $6, $7, $8, $9, $10) \
                     ON CONFLICT (subject_type, subject_id, scope_type, scope_id, restriction_type) WHERE status = 'ACTIVE' \
                     DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at, \
                       source_action_id = EXCLUDED.source_action_id, source_policy_version_id = EXCLUDED.source_policy_version_id, \
                       created_by = EXCLUDED.created_by, version = trust_safety.restriction.version + 1, updated_at = clock_timestamp() \
                     RETURNING id",
                )
                .bind(enforcement_subject_type)
                .bind(enforcement_subject_id)
                .bind(effect_scope_type)
                .bind(effect_scope_id)
                .bind(&enforcement.restriction_type)
                .bind(automated_reason(&enforcement.reason))
                .bind(action.id)
                .bind(source_policy_version_id)
                .bind(&policy_actor)
                .bind(restriction_expires_at)
                .fetch_one(&mut **tx)
                .await?;
                insert_policy_audit(
                    tx,
                    action,
                    emitted,
                    "APPLY_CREATE_RESTRICTION",
                    "RESTRICTION",
                    &restriction_id.to_string(),
                )
                .await?;
                Some(restriction_id)
            } else {
                None
            };
            let infraction_id: Uuid = sqlx::query_scalar(
                "INSERT INTO trust_safety.infraction \
                 (subject_type, subject_id, scope_type, scope_id, infraction_type, reason, source_action_id, source_policy_version_id, created_by, expires_at, enforcement_restriction_id) \
                 VALUES ($1, $2, $3::trust_safety.scope_type, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
            )
            .bind(subject_type)
            .bind(subject_id)
            .bind(effect_scope_type)
            .bind(effect_scope_id)
            .bind(infraction_type)
            .bind(automated_reason(reason))
            .bind(action.id)
            .bind(source_policy_version_id)
            .bind(&policy_actor)
            .bind(expires_at)
            .bind(enforcement_restriction_id)
            .fetch_one(&mut **tx)
            .await?;
            if matches!(subject_type, "USER" | "SERVER") {
                let signal_value = match infraction_type.as_str() {
                    "WARNING" => 5.0,
                    "MUTE" => 15.0,
                    "BAN" => 30.0,
                    "CONTENT" => 10.0,
                    _ => 0.0,
                };
                let (observation_id, assessment_id) = insert_derived_safety_observation_tx(
                    tx,
                    subject_type,
                    subject_id,
                    effect_scope_type,
                    effect_scope_id,
                    &format!("INFRACTION_{infraction_type}"),
                    signal_value,
                    false,
                    serde_json::json!({
                        "infraction_id": infraction_id,
                        "source_action_id": action.id,
                        "source_policy_version_id": emitted.origin.policy_version_id,
                    }),
                )
                .await?;
                insert_policy_audit(
                    tx,
                    action,
                    emitted,
                    "DERIVE_SAFETY_OBSERVATION",
                    "SAFETY_OBSERVATION",
                    &observation_id.to_string(),
                )
                .await?;
                insert_policy_audit(
                    tx,
                    action,
                    emitted,
                    "RECALCULATE_SAFETY_ASSESSMENT",
                    "SAFETY_ASSESSMENT",
                    &assessment_id.to_string(),
                )
                .await?;
            }
            insert_policy_audit(
                tx,
                action,
                emitted,
                "APPLY_CREATE_INFRACTION",
                "INFRACTION",
                &infraction_id.to_string(),
            )
            .await?;
            if let Some(user_id) = subject.user_id.as_deref() {
                insert_moderation_notice_command(
                    tx,
                    command_topic,
                    decision_id,
                    action,
                    emitted,
                    user_id,
                    Some(infraction_id),
                    enforcement_restriction_id,
                    expires_at,
                    1,
                )
                .await?;
            }
        }
        Effect::Flag {
            flag_type,
            severity,
            ..
        } => {
            let (subject_type, subject_id) = optional_primary_subject(&action.subject);
            let subject_type = subject_type.unwrap_or("ACTION");
            let subject_id = subject_id
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| action.id.to_string());
            let review_id: Uuid = sqlx::query_scalar(
                "INSERT INTO trust_safety.review_item \
                 (queue, scope_type, scope_id, subject_type, subject_id, priority, reason_codes, decision_id) \
                 VALUES ('policy-flags', $1::trust_safety.scope_type, $2, $3, $4, $5, $6, $7) RETURNING id",
            )
            .bind(action_scope_type)
            .bind(action_scope_id)
            .bind(subject_type)
            .bind(subject_id)
            .bind(100_i32.saturating_sub(severity.round() as i32).clamp(0, 100))
            .bind(vec![flag_type.clone()])
            .bind(decision_id)
            .fetch_one(&mut **tx)
            .await?;
            insert_policy_audit(
                tx,
                action,
                emitted,
                "APPLY_FLAG",
                "REVIEW_ITEM",
                &review_id.to_string(),
            )
            .await?;
        }
        Effect::RouteReview {
            queue,
            priority,
            reason_codes,
            ..
        } => {
            let (subject_type, subject_id) = optional_primary_subject(&action.subject);
            let subject_type = subject_type.unwrap_or("ACTION");
            let subject_id = subject_id
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| action.id.to_string());
            let review_id: Uuid = sqlx::query_scalar(
                "INSERT INTO trust_safety.review_item \
                 (queue, scope_type, scope_id, subject_type, subject_id, priority, reason_codes, decision_id) \
                 VALUES ($1, $2::trust_safety.scope_type, $3, $4, $5, $6, $7, $8) RETURNING id",
            )
            .bind(queue)
            .bind(action_scope_type)
            .bind(action_scope_id)
            .bind(subject_type)
            .bind(subject_id)
            .bind(priority)
            .bind(reason_codes)
            .bind(decision_id)
            .fetch_one(&mut **tx)
            .await?;
            insert_policy_audit(
                tx,
                action,
                emitted,
                "APPLY_ROUTE_REVIEW",
                "REVIEW_ITEM",
                &review_id.to_string(),
            )
            .await?;
        }
        Effect::LabelEntity {
            subject,
            label,
            value,
            ..
        } => {
            let (subject_type, subject_id) = primary_subject(subject)?;
            let label_id: Uuid = sqlx::query_scalar(
                "INSERT INTO trust_safety.entity_label \
                 (subject_type, subject_id, scope_type, scope_id, label, value, source_policy_version_id) \
                 VALUES ($1, $2, $3::trust_safety.scope_type, $4, $5, $6, $7) \
                 ON CONFLICT (subject_type, subject_id, scope_type, scope_id, label) DO UPDATE SET \
                   value = EXCLUDED.value, source_policy_version_id = EXCLUDED.source_policy_version_id, \
                   version = trust_safety.entity_label.version + 1, updated_at = clock_timestamp() RETURNING id",
            )
            .bind(subject_type)
            .bind(subject_id)
            .bind(action_scope_type)
            .bind(action_scope_id)
            .bind(label)
            .bind(value)
            .bind(emitted.origin.policy_version_id)
            .fetch_one(&mut **tx)
            .await?;
            insert_policy_audit(
                tx,
                action,
                emitted,
                "APPLY_LABEL_ENTITY",
                "ENTITY_LABEL",
                &label_id.to_string(),
            )
            .await?;
        }
        Effect::IncrementCounter {
            subject,
            scope,
            counter_type,
            delta,
            window_ms,
            reset,
            ..
        } => {
            anyhow::ensure!(*window_ms > 0, "counter window must be positive");
            let (subject_type, subject_id) = primary_subject(subject)?;
            let now_ms = Utc::now().timestamp_millis();
            let start_ms = now_ms - now_ms.rem_euclid(*window_ms as i64);
            let window_start = Utc
                .timestamp_millis_opt(start_ms)
                .single()
                .ok_or_else(|| anyhow::anyhow!("invalid counter window"))?;
            let window_end = window_start + chrono::Duration::milliseconds(*window_ms as i64);
            sqlx::query(
                "INSERT INTO trust_safety.policy_counter (subject_type, subject_id, scope_type, scope_id, counter_type, window_start, window_end, value) \
                 VALUES ($1, $2, $3::trust_safety.scope_type, $4, $5, $6, $7, $8) \
                 ON CONFLICT (subject_type, subject_id, scope_type, scope_id, counter_type, window_start) DO UPDATE \
                 SET value = CASE WHEN $9 THEN $8 ELSE trust_safety.policy_counter.value + $8 END, version = trust_safety.policy_counter.version + 1, updated_at = clock_timestamp()"
            ).bind(subject_type).bind(subject_id).bind(scope_name(scope.scope_type)).bind(&scope.id).bind(counter_type)
            .bind(window_start).bind(window_end).bind(delta).bind(reset).execute(&mut **tx).await?;
            insert_policy_audit(
                tx,
                action,
                emitted,
                "APPLY_INCREMENT_COUNTER",
                "POLICY_COUNTER",
                &format!(
                    "{subject_type}:{subject_id}:{counter_type}:{}",
                    window_start.timestamp_millis()
                ),
            )
            .await?;
        }
        Effect::Notify { .. } | Effect::Delete { .. } | Effect::Kick { .. } => {
            insert_policy_audit(
                tx,
                action,
                emitted,
                "EMIT_POLICY_COMMAND",
                "COMMAND",
                effect.id(),
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn validate_effect_for_action(effect: &Effect, action: &Action) -> anyhow::Result<()> {
    const MAX_DURATION_MS: u64 = 10 * 365 * 24 * 60 * 60 * 1_000;
    anyhow::ensure!(
        !effect.id().trim().is_empty() && effect.id().len() <= 128,
        "effect id must be between 1 and 128 characters"
    );

    let validate_subject = |subject: &Subject| -> anyhow::Result<()> {
        let (subject_type, subject_id) = primary_subject(subject)?;
        let matches_action = match subject_type {
            "USER" => action.subject.user_id.as_deref() == Some(subject_id),
            "SERVER" => action.subject.server_id.as_deref() == Some(subject_id),
            "MESSAGE" => action.subject.message_id.as_deref() == Some(subject_id),
            _ => false,
        };
        anyhow::ensure!(
            matches_action,
            "effect subject must be present on the evaluated action"
        );
        Ok(())
    };
    let validate_duration = |duration: Option<u64>| -> anyhow::Result<()> {
        if let Some(duration) = duration {
            anyhow::ensure!(
                duration > 0 && duration <= MAX_DURATION_MS,
                "effect duration must be between 1 millisecond and 10 years"
            );
        }
        Ok(())
    };
    let validate_reason_codes = |reason_codes: &[String]| -> anyhow::Result<()> {
        anyhow::ensure!(reason_codes.len() <= 32, "effect has too many reason codes");
        anyhow::ensure!(
            reason_codes
                .iter()
                .all(|code| !code.trim().is_empty() && code.len() <= 100),
            "reason codes must be between 1 and 100 characters"
        );
        Ok(())
    };

    match effect {
        Effect::Allow { reason_codes, .. } | Effect::Block { reason_codes, .. } => {
            validate_reason_codes(reason_codes)?
        }
        Effect::Hold {
            reason_codes,
            maximum_duration_ms,
            ..
        } => {
            validate_reason_codes(reason_codes)?;
            validate_duration(*maximum_duration_ms)?;
        }
        Effect::Censor {
            spans,
            replacement,
            reason_codes,
            ..
        } => {
            validate_reason_codes(reason_codes)?;
            anyhow::ensure!(
                !spans.is_empty() && spans.len() <= 64,
                "invalid censor spans"
            );
            anyhow::ensure!(
                spans
                    .iter()
                    .all(|span| span.start_character < span.end_character),
                "censor spans must not be empty"
            );
            anyhow::ensure!(replacement.len() <= 100, "censor replacement is too long");
        }
        Effect::Flag {
            flag_type,
            severity,
            evidence,
            ..
        } => {
            anyhow::ensure!(
                !flag_type.trim().is_empty() && flag_type.len() <= 100,
                "flag type must be between 1 and 100 characters"
            );
            anyhow::ensure!(
                severity.is_finite() && (0.0..=100.0).contains(severity),
                "flag severity must be between 0 and 100"
            );
            anyhow::ensure!(
                serde_json::to_vec(evidence)?.len() <= 16_384,
                "flag evidence exceeds 16 KiB"
            );
        }
        Effect::Notify {
            recipient,
            template,
            parameters,
            ..
        } => {
            anyhow::ensure!(
                !recipient.trim().is_empty() && recipient.len() <= 200,
                "notification recipient is invalid"
            );
            anyhow::ensure!(
                !template.trim().is_empty() && template.len() <= 200,
                "notification template is invalid"
            );
            anyhow::ensure!(
                serde_json::to_vec(parameters)?.len() <= 16_384,
                "notification parameters exceed 16 KiB"
            );
        }
        Effect::CreateInfraction {
            subject,
            infraction_type,
            reason,
            duration_ms,
            enforcement,
            ..
        } => {
            validate_subject(subject)?;
            anyhow::ensure!(
                matches!(
                    infraction_type.as_str(),
                    "WARNING" | "MUTE" | "BAN" | "CONTENT"
                ),
                "invalid infraction type"
            );
            anyhow::ensure!(
                !reason.trim().is_empty() && reason.len() <= 2_000,
                "infraction reason must be between 1 and 2000 characters"
            );
            validate_duration(*duration_ms)?;
            if let Some(enforcement) = enforcement {
                validate_subject(&enforcement.subject)?;
                anyhow::ensure!(
                    matches!(
                        enforcement.restriction_type.as_str(),
                        "MUTE" | "BAN" | "BLACKLIST" | "CONTENT_QUARANTINE"
                    ),
                    "invalid enforcement restriction type"
                );
                anyhow::ensure!(
                    !enforcement.reason.trim().is_empty() && enforcement.reason.len() <= 2_000,
                    "enforcement reason must be between 1 and 2000 characters"
                );
                validate_duration(enforcement.duration_ms)?;
            }
        }
        Effect::CreateRestriction {
            subject,
            restriction_type,
            reason,
            duration_ms,
            ..
        } => {
            validate_subject(subject)?;
            anyhow::ensure!(
                matches!(
                    restriction_type.as_str(),
                    "MUTE" | "BAN" | "BLACKLIST" | "CONTENT_QUARANTINE"
                ),
                "invalid restriction type"
            );
            anyhow::ensure!(
                !reason.trim().is_empty() && reason.len() <= 2_000,
                "restriction reason must be between 1 and 2000 characters"
            );
            validate_duration(*duration_ms)?;
        }
        Effect::RouteReview {
            queue,
            priority,
            reason_codes,
            ..
        } => {
            anyhow::ensure!(
                !queue.trim().is_empty() && queue.len() <= 100,
                "review queue must be between 1 and 100 characters"
            );
            anyhow::ensure!((0..=1_000).contains(priority), "review priority is invalid");
            validate_reason_codes(reason_codes)?;
        }
        Effect::LabelEntity {
            subject,
            label,
            value,
            ..
        } => {
            validate_subject(subject)?;
            anyhow::ensure!(
                !label.trim().is_empty() && label.len() <= 100,
                "entity label must be between 1 and 100 characters"
            );
            anyhow::ensure!(
                serde_json::to_vec(value)?.len() <= 16_384,
                "entity label value exceeds 16 KiB"
            );
        }
        Effect::IncrementCounter {
            subject,
            scope,
            counter_type,
            delta,
            window_ms,
            ..
        } => {
            validate_subject(subject)?;
            anyhow::ensure!(
                scope == &action.scope,
                "counter scope must match the action scope"
            );
            anyhow::ensure!(
                !counter_type.trim().is_empty() && counter_type.len() <= 100,
                "counter type must be between 1 and 100 characters"
            );
            anyhow::ensure!(
                delta.unsigned_abs() <= 1_000_000,
                "counter delta is too large"
            );
            validate_duration(Some(*window_ms))?;
        }
        Effect::Delete {
            message_id,
            channel_id,
            reason_codes,
            ..
        } => {
            validate_reason_codes(reason_codes)?;
            anyhow::ensure!(
                action.subject.message_id.as_deref() == Some(message_id),
                "delete effect message must match the action"
            );
            anyhow::ensure!(
                action.subject.channel_id.as_deref() == Some(channel_id),
                "delete effect channel must match the action"
            );
        }
        Effect::Kick {
            user_id,
            server_id,
            reason_codes,
            ..
        } => {
            validate_reason_codes(reason_codes)?;
            anyhow::ensure!(
                action.subject.user_id.as_deref() == Some(user_id),
                "kick effect user must match the action"
            );
            anyhow::ensure!(
                action.subject.server_id.as_deref() == Some(server_id),
                "kick effect server must match the action"
            );
        }
    }
    Ok(())
}

async fn insert_policy_audit(
    tx: &mut Transaction<'_, Postgres>,
    action: &Action,
    emitted: &EmittedEffect,
    audit_action: &str,
    resource_type: &str,
    resource_id: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO trust_safety.audit_log \
         (request_id, actor_id, actor_type, action, resource_type, resource_id, scope_type, scope_id, after_state, trace_id) \
         VALUES ($1, $2, 'POLICY', $3, $4, $5, $6::trust_safety.scope_type, $7, $8, $9)",
    )
    .bind(action.id.to_string())
    .bind(format!("policy:{}", emitted.origin.policy_version_id))
    .bind(audit_action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(scope_name(action.scope.scope_type))
    .bind(&action.scope.id)
    .bind(serde_json::json!({
        "effect_id": emitted.effect.id(),
        "policy_bundle_id": emitted.origin.policy_bundle_id,
        "policy_version_id": emitted.origin.policy_version_id,
        "rule_id": emitted.origin.rule_id,
    }))
    .bind(action.id.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_moderation_notice_command(
    tx: &mut Transaction<'_, Postgres>,
    command_topic: &str,
    decision_id: Uuid,
    action: &Action,
    emitted: &EmittedEffect,
    user_id: &str,
    infraction_id: Option<Uuid>,
    restriction_id: Option<Uuid>,
    expires_at: Option<chrono::DateTime<Utc>>,
    record_version: i64,
) -> anyhow::Result<()> {
    let kind = match &emitted.effect {
        Effect::CreateInfraction {
            infraction_type,
            enforcement,
            ..
        } => match (
            enforcement
                .as_ref()
                .map(|value| value.restriction_type.as_str()),
            emitted.origin.scope.scope_type,
            infraction_type.as_str(),
        ) {
            (Some("BLACKLIST"), _, _) => v2::ModerationNoticeKind::GlobalBlacklist,
            (_, ScopeType::Hub, "WARNING") => v2::ModerationNoticeKind::HubWarning,
            (_, ScopeType::Hub, "MUTE") => v2::ModerationNoticeKind::HubMute,
            (_, ScopeType::Hub, "BAN") => v2::ModerationNoticeKind::HubBan,
            (_, ScopeType::Lobby, "WARNING") => v2::ModerationNoticeKind::LobbyWarning,
            (_, ScopeType::Lobby, "BAN") => v2::ModerationNoticeKind::LobbyBan,
            _ => return Ok(()),
        },
        Effect::CreateRestriction {
            restriction_type, ..
        } => match (restriction_type.as_str(), emitted.origin.scope.scope_type) {
            ("BLACKLIST", _) => v2::ModerationNoticeKind::GlobalBlacklist,
            ("MUTE", ScopeType::Hub) => v2::ModerationNoticeKind::HubMute,
            ("BAN", ScopeType::Hub) => v2::ModerationNoticeKind::HubBan,
            ("BAN", ScopeType::Lobby) => v2::ModerationNoticeKind::LobbyBan,
            _ => return Ok(()),
        },
        _ => return Ok(()),
    };
    let (aggregate_type, aggregate_id, idempotency_key) = match (infraction_id, restriction_id) {
        (Some(infraction_id), _) => (
            "INFRACTION",
            infraction_id,
            format!("moderation-notice:{infraction_id}"),
        ),
        (None, Some(restriction_id)) => (
            "RESTRICTION",
            restriction_id,
            format!("moderation-notice:restriction:{restriction_id}:{record_version}"),
        ),
        (None, None) => anyhow::bail!("moderation notice requires a persisted resource"),
    };
    let notice = v2::ModerationNoticeCommand {
        user_id: user_id.to_owned(),
        kind: kind as i32,
        event: v2::ModerationNoticeEvent::Applied as i32,
        scope: Some(scope_to_proto(&emitted.origin.scope)),
        public_reason: String::new(),
        expires_at: expires_at.map(timestamp),
        infraction_id: infraction_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
        restriction_id: restriction_id
            .map(|value| value.to_string())
            .unwrap_or_default(),
        source: "automod".into(),
        source_channel_id: action.subject.channel_id.clone().unwrap_or_default(),
        source_message_id: action.subject.message_id.clone().unwrap_or_default(),
        source_user_id: user_id.to_owned(),
        record_version: u64::try_from(record_version)?,
    };
    let command = v2::CommandEnvelope {
        id: Uuid::now_v7().to_string(),
        decision_id: decision_id.to_string(),
        idempotency_key,
        command: Some(v2::command_envelope::Command::ModerationNotice(notice)),
    };
    register_command(tx, &command).await?;
    insert_outbox(
        tx,
        aggregate_type,
        aggregate_id,
        command_topic,
        "interchat.trust-safety.command.v2",
        &command.id,
        command.encode_to_vec(),
    )
    .await
}

fn command_for_effect(decision_id: Uuid, effect: &Effect) -> Option<v2::CommandEnvelope> {
    use v2::command_envelope::Command;
    let command = match effect {
        Effect::Notify {
            recipient,
            template,
            parameters,
            ..
        } => Command::Notify(v2::NotifyCommand {
            user_id: recipient.clone(),
            template: template.clone(),
            parameters: parameters
                .as_object()
                .map(|map| {
                    map.iter()
                        .filter_map(|(key, value)| {
                            value.as_str().map(|value| (key.clone(), value.to_owned()))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }),
        Effect::Delete {
            message_id,
            channel_id,
            reason_codes,
            ..
        } => Command::Delete(v2::DeleteCommand {
            message_id: message_id.clone(),
            channel_id: channel_id.clone(),
            reason_codes: reason_codes.clone(),
        }),
        Effect::Kick {
            user_id,
            server_id,
            reason_codes,
            ..
        } => Command::Kick(v2::KickCommand {
            user_id: user_id.clone(),
            server_id: server_id.clone(),
            reason_codes: reason_codes.clone(),
        }),
        _ => return None,
    };
    Some(v2::CommandEnvelope {
        id: Uuid::now_v7().to_string(),
        decision_id: decision_id.to_string(),
        idempotency_key: format!("{decision_id}:{}", effect.id()),
        command: Some(command),
    })
}

pub(crate) async fn register_command(
    tx: &mut Transaction<'_, Postgres>,
    command: &v2::CommandEnvelope,
) -> anyhow::Result<()> {
    use v2::command_envelope::Command;
    let command_id = Uuid::parse_str(&command.id)?;
    let decision_id = (!command.decision_id.is_empty())
        .then(|| Uuid::parse_str(&command.decision_id))
        .transpose()?;
    let (command_type, retry_safe) = match command.command.as_ref() {
        Some(Command::Notify(_)) => ("NOTIFY", false),
        Some(Command::Delete(_)) => ("DELETE", true),
        Some(Command::Kick(_)) => ("KICK", true),
        Some(Command::ModerationNotice(_)) => ("MODERATION_NOTICE", false),
        None => anyhow::bail!("command envelope has no typed command"),
    };
    sqlx::query(
        "INSERT INTO trust_safety.processed_command \
         (command_id, decision_id, command_type, idempotency_key, payload, retry_safe) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(command_id)
    .bind(decision_id)
    .bind(command_type)
    .bind(&command.idempotency_key)
    .bind(command.encode_to_vec())
    .bind(retry_safe)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn insert_outbox(
    tx: &mut Transaction<'_, Postgres>,
    aggregate_type: &str,
    aggregate_id: Uuid,
    topic: &str,
    event_type: &str,
    key: &str,
    payload: Vec<u8>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO trust_safety.outbox (aggregate_type, aggregate_id, topic, partition_key, headers, payload) VALUES ($1, $2, $3, $4, $5, $6)"
    ).bind(aggregate_type).bind(aggregate_id).bind(topic).bind(key)
    .bind(cloud_event_headers(event_type)).bind(payload)
    .execute(&mut **tx).await?;
    Ok(())
}

fn cloud_event_headers(event_type: &str) -> serde_json::Value {
    json!({
        "ce_specversion": "1.0",
        "ce_type": event_type,
        "ce_source": "/polarizer",
        "ce_id": Uuid::now_v7().to_string(),
        "ce_time": Utc::now().to_rfc3339(),
        "ce_datacontenttype": "application/protobuf",
        "content-type": "application/protobuf"
    })
}

pub(crate) async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    context: &v2::RequestContext,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO trust_safety.audit_log (request_id, actor_id, actor_type, action, resource_type, resource_id, before_state, after_state, trace_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''))"
    ).bind(&context.request_id).bind(&context.actor_id).bind(actor_type_name(context.actor_type)).bind(action).bind(resource_type).bind(resource_id).bind(before).bind(after).bind(&context.trace_id)
    .execute(&mut **tx).await?;
    Ok(())
}

pub(crate) async fn claim_policy_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    context: &v2::RequestContext,
    operation: &str,
    resource_id: Uuid,
) -> anyhow::Result<PolicyIdempotencyClaim> {
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
        return Ok(PolicyIdempotencyClaim::Claimed);
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
    Ok(PolicyIdempotencyClaim::Existing(
        row.try_get("resource_id")?,
    ))
}

fn actor_type_name(value: i32) -> &'static str {
    match v2::ActorType::try_from(value).unwrap_or(v2::ActorType::Unspecified) {
        v2::ActorType::Human => "HUMAN",
        v2::ActorType::Service => "SERVICE",
        v2::ActorType::Policy => "POLICY",
        v2::ActorType::Unspecified => "UNSPECIFIED",
    }
}

async fn ensure_fixture_version_mutable(
    tx: &mut Transaction<'_, Postgres>,
    policy_version_id: Uuid,
) -> anyhow::Result<()> {
    let row = sqlx::query(
        "SELECT state::text, published_at FROM trust_safety.policy_version \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(policy_version_id)
    .fetch_one(&mut **tx)
    .await?;
    let state: String = row.try_get("state")?;
    let published_at: Option<chrono::DateTime<Utc>> = row.try_get("published_at")?;
    anyhow::ensure!(
        published_at.is_none() && matches!(state.as_str(), "DRAFT" | "VALIDATED"),
        "published policy fixtures are immutable"
    );
    Ok(())
}

async fn bump_fixture_revision(
    tx: &mut Transaction<'_, Postgres>,
    policy_version_id: Uuid,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE trust_safety.policy_version SET fixture_revision = fixture_revision + 1 \
         WHERE id = $1",
    )
    .bind(policy_version_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn primary_subject(subject: &Subject) -> anyhow::Result<(&'static str, &str)> {
    if let Some(id) = subject.user_id.as_deref() {
        return Ok(("USER", id));
    }
    if let Some(id) = subject.server_id.as_deref() {
        return Ok(("SERVER", id));
    }
    if let Some(id) = subject.message_id.as_deref() {
        return Ok(("MESSAGE", id));
    }
    anyhow::bail!("effect subject has no supported identifier")
}

fn optional_primary_subject(subject: &Subject) -> (Option<&'static str>, Option<&str>) {
    if let Some(id) = subject.user_id.as_deref() {
        return (Some("USER"), Some(id));
    }
    if let Some(id) = subject.server_id.as_deref() {
        return (Some("SERVER"), Some(id));
    }
    if let Some(id) = subject.message_id.as_deref() {
        return (Some("MESSAGE"), Some(id));
    }
    (None, None)
}

fn bundle_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<PolicyBundle> {
    let scope_type: String = row.try_get("scope_type")?;
    let state: String = row.try_get("state")?;
    Ok(PolicyBundle {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        scope: Scope {
            scope_type: parse_scope(&scope_type)?,
            id: row.try_get("scope_id")?,
            product: parse_product(row.try_get::<Option<String>, _>("product")?)?,
        },
        mandatory: row.try_get("mandatory")?,
        priority: row.try_get("priority")?,
        active_version_id: row.try_get("active_version_id")?,
        shadow_version_id: row.try_get("shadow_version_id")?,
        state: parse_bundle_state(&state)?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn stored_fixture_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<StoredFixture> {
    Ok(StoredFixture {
        id: row.try_get("id")?,
        policy_version_id: row.try_get("policy_version_id")?,
        name: row.try_get("name")?,
        action: serde_json::from_value(row.try_get("action")?)?,
        features: serde_json::from_value(row.try_get("feature_snapshot")?)?,
        expected_effects: serde_json::from_value(row.try_get("expected_effects")?)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        version: row.try_get("version")?,
    })
}

fn bundle_from_joined_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<PolicyBundle> {
    let scope_type: String = row.try_get("scope_type")?;
    let state: String = row.try_get("bundle_state")?;
    Ok(PolicyBundle {
        id: row.try_get("bundle_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        scope: Scope {
            scope_type: parse_scope(&scope_type)?,
            id: row.try_get("scope_id")?,
            product: parse_product(row.try_get::<Option<String>, _>("product")?)?,
        },
        mandatory: row.try_get("mandatory")?,
        priority: row.try_get("priority")?,
        active_version_id: row.try_get("active_version_id")?,
        shadow_version_id: row.try_get("shadow_version_id")?,
        state: parse_bundle_state(&state)?,
        version: row.try_get("bundle_version")?,
        created_at: row.try_get("bundle_created_at")?,
        updated_at: row.try_get("bundle_updated_at")?,
    })
}

fn validate_bundle_fields(
    name: &str,
    description: &str,
    scope: &Scope,
    priority: i32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.trim().is_empty() && name.trim().len() <= 100,
        "policy bundle name must be between 1 and 100 characters"
    );
    anyhow::ensure!(
        description.trim().len() <= 2_000,
        "policy bundle description is too long"
    );
    anyhow::ensure!(
        (0..=10_000).contains(&priority),
        "policy bundle priority must be between 0 and 10000"
    );
    match scope.scope_type {
        ScopeType::Platform => {
            anyhow::ensure!(scope.id.is_empty(), "platform scope id must be empty");
            anyhow::ensure!(
                scope.product.is_none(),
                "platform scope cannot declare a product"
            );
        }
        ScopeType::Product => {
            anyhow::ensure!(scope.id.is_empty(), "product scope id must be empty");
            anyhow::ensure!(scope.product.is_some(), "product scope requires a product");
        }
        ScopeType::Hub => {
            anyhow::ensure!(!scope.id.trim().is_empty(), "hub scope id is required");
            anyhow::ensure!(
                scope.product == Some(Product::Hub),
                "hub scope requires HUB product"
            );
        }
        ScopeType::Lobby => {
            anyhow::ensure!(!scope.id.trim().is_empty(), "lobby scope id is required");
            anyhow::ensure!(
                scope.product == Some(Product::Lobby),
                "lobby scope requires LOBBY product"
            );
        }
        ScopeType::IncidentOverlay => {
            anyhow::ensure!(
                !scope.id.trim().is_empty(),
                "incident overlay scope id is required"
            );
        }
    }
    Ok(())
}

fn is_legal_bundle_transition(from: PolicyBundleState, to: PolicyBundleState) -> bool {
    matches!(
        (from, to),
        (PolicyBundleState::Active, PolicyBundleState::Disabled)
            | (PolicyBundleState::Active, PolicyBundleState::Retired)
            | (PolicyBundleState::Disabled, PolicyBundleState::Retired)
    )
}

fn bundle_audit_json(bundle: &PolicyBundle) -> serde_json::Value {
    json!({
        "id": bundle.id,
        "name": bundle.name,
        "description": bundle.description,
        "scope": bundle.scope,
        "mandatory": bundle.mandatory,
        "priority": bundle.priority,
        "state": bundle_state_name(bundle.state),
        "version": bundle.version,
    })
}

fn policy_version_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<PolicyVersion> {
    let language: String = row.try_get("language")?;
    let state: String = row.try_get("state")?;
    Ok(PolicyVersion {
        id: row.try_get("id")?,
        bundle_id: row.try_get("bundle_id")?,
        version: row.try_get("version")?,
        language: parse_language(&language)?,
        runtime_version: row.try_get("runtime_version")?,
        source: row.try_get("source")?,
        compiled_artifact: row
            .try_get::<Option<Vec<u8>>, _>("compiled_artifact")?
            .unwrap_or_default(),
        source_sha256: row.try_get("source_sha256")?,
        artifact_sha256: row
            .try_get::<Option<String>, _>("artifact_sha256")?
            .unwrap_or_default(),
        manifest: serde_json::from_value(row.try_get("manifest")?)?,
        state: parse_state(&state)?,
    })
}

fn parse_scope(value: &str) -> anyhow::Result<ScopeType> {
    Ok(match value {
        "PLATFORM" => ScopeType::Platform,
        "PRODUCT" => ScopeType::Product,
        "HUB" => ScopeType::Hub,
        "LOBBY" => ScopeType::Lobby,
        "INCIDENT_OVERLAY" => ScopeType::IncidentOverlay,
        _ => anyhow::bail!("unknown scope type"),
    })
}
fn parse_product(value: Option<String>) -> anyhow::Result<Option<Product>> {
    Ok(match value.as_deref() {
        Some("HUB") => Some(Product::Hub),
        Some("LOBBY") => Some(Product::Lobby),
        None => None,
        _ => anyhow::bail!("unknown product"),
    })
}
fn parse_language(value: &str) -> anyhow::Result<PolicyLanguage> {
    Ok(match value {
        "policy-ir-v1" => PolicyLanguage::PolicyIrV1,
        "luau-v1" => PolicyLanguage::LuauV1,
        _ => anyhow::bail!("unknown policy language"),
    })
}
fn language_name(value: PolicyLanguage) -> &'static str {
    match value {
        PolicyLanguage::PolicyIrV1 => "policy-ir-v1",
        PolicyLanguage::LuauV1 => "luau-v1",
    }
}
fn parse_state(value: &str) -> anyhow::Result<PolicyState> {
    Ok(match value {
        "DRAFT" => PolicyState::Draft,
        "VALIDATED" => PolicyState::Validated,
        "SHADOW" => PolicyState::Shadow,
        "ACTIVE" => PolicyState::Active,
        "DISABLED" => PolicyState::Disabled,
        "RETIRED" => PolicyState::Retired,
        _ => anyhow::bail!("unknown policy state"),
    })
}
fn parse_bundle_state(value: &str) -> anyhow::Result<PolicyBundleState> {
    Ok(match value {
        "ACTIVE" => PolicyBundleState::Active,
        "DISABLED" => PolicyBundleState::Disabled,
        "RETIRED" => PolicyBundleState::Retired,
        _ => anyhow::bail!("unknown policy bundle state"),
    })
}
fn bundle_state_name(value: PolicyBundleState) -> &'static str {
    match value {
        PolicyBundleState::Active => "ACTIVE",
        PolicyBundleState::Disabled => "DISABLED",
        PolicyBundleState::Retired => "RETIRED",
    }
}
fn product_name(value: Product) -> &'static str {
    match value {
        Product::Hub => "HUB",
        Product::Lobby => "LOBBY",
    }
}
pub fn scope_name(value: ScopeType) -> &'static str {
    match value {
        ScopeType::Platform => "PLATFORM",
        ScopeType::Product => "PRODUCT",
        ScopeType::Hub => "HUB",
        ScopeType::Lobby => "LOBBY",
        ScopeType::IncidentOverlay => "INCIDENT_OVERLAY",
    }
}
fn scope_partition_key(scope: &Scope) -> String {
    format!("{}:{}", scope_name(scope.scope_type), scope.id)
}
fn decision_name(value: Decision) -> &'static str {
    match value {
        Decision::Allow => "ALLOW",
        Decision::Censor => "CENSOR",
        Decision::Hold => "HOLD",
        Decision::Block => "BLOCK",
    }
}
fn proto_decision(value: Decision) -> i32 {
    match value {
        Decision::Allow => v2::Decision::Allow as i32,
        Decision::Censor => v2::Decision::Censor as i32,
        Decision::Hold => v2::Decision::Hold as i32,
        Decision::Block => v2::Decision::Block as i32,
    }
}
fn timestamp(value: chrono::DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActionCipher, HeldActionResolution, apply_censors_to_content, apply_content_policy_plan,
        automated_reason, build_approved_content, build_approved_prism_payload,
        cloud_event_headers, held_resolution_values, hold_deadline, is_legal_bundle_transition,
        scope_partition_key, validate_bundle_fields, validate_effect_for_action,
    };
    use crate::content_policy::{
        CallPolicyPlan, ContentPolicyPlan, DeliveryEffects, DeliveryVariant, DestinationDecision,
        PolicyScope, ResolvedScopeDecision,
    };
    use crate::contract::prism;
    use crate::policy::features::{
        FeatureProvider,
        text::{AutomodMatch, AutomodMatchProvider},
    };
    use crate::policy::model::{
        Action, DataHandlingClass, Decision, Effect, EffectOrigin, EmittedEffect, EvaluationResult,
        ExecutionTrace, PolicyBundleState, Product, Scope, ScopeType, Subject, TextSpan,
    };
    use prost::Message;
    use uuid::Uuid;

    fn action() -> Action {
        Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub-1".into(),
                product: Some(Product::Hub),
            },
            subject: Subject {
                user_id: Some("user-1".into()),
                server_id: Some("server-1".into()),
                message_id: Some("message-1".into()),
                channel_id: Some("channel-1".into()),
                report_id: None,
            },
            occurred_at: chrono::Utc::now(),
            attributes: serde_json::json!({}),
            data_handling: DataHandlingClass::Internal,
            prism_payload: None,
        }
    }

    #[test]
    fn policy_reasons_are_marked_as_automated() {
        assert_eq!(
            automated_reason("Repeated prohibited content"),
            "Automated: Repeated prohibited content"
        );
    }

    fn allow_result(action_id: Uuid) -> EvaluationResult {
        EvaluationResult {
            id: Uuid::now_v7(),
            action_id,
            decision: Decision::Allow,
            reason_codes: Vec::new(),
            accepted_effects: Vec::new(),
            rejected_effects: Vec::new(),
            shadow: false,
            content_policy: None,
            trace: ExecutionTrace {
                id: Uuid::now_v7(),
                action_id,
                action_schema_version: 1,
                policy_versions: Vec::new(),
                features: Default::default(),
                rules: Vec::new(),
                accepted_effect_ids: Vec::new(),
                rejected_effects: Vec::new(),
                final_decision: Decision::Allow,
                reason_codes: Vec::new(),
                total_latency_micros: 0,
                created_at: chrono::Utc::now(),
                sampled: false,
            },
        }
    }

    #[test]
    fn approved_prism_payload_uses_authoritative_action_id() {
        let mut action = action();
        let producer_supplied_id = Uuid::now_v7().to_string();
        action.prism_payload = Some(
            prism::PrismStreamPayload {
                batch_id: "batch-1".into(),
                action: "SEND".into(),
                payload: "{}".into(),
                action_id: Some(producer_supplied_id),
                ..Default::default()
            }
            .encode_to_vec(),
        );

        let approved = build_approved_prism_payload(&action, &allow_result(action.id), Some(""))
            .expect("valid payload")
            .expect("approved payload");

        assert_eq!(approved.action_id, Some(action.id.to_string()));
    }

    #[test]
    fn legacy_allow_payload_is_unchanged_during_rolling_upgrade() {
        let mut action = action();
        action.attributes = serde_json::json!({"content": "canonical"});
        action.prism_payload = Some(
            prism::PrismStreamPayload {
                payload: serde_json::json!({"content": "legacy decorated content"}).to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        );

        let approved =
            build_approved_prism_payload(&action, &allow_result(action.id), Some("canonical"))
                .expect("valid payload")
                .expect("approved payload");
        let body: serde_json::Value = serde_json::from_str(&approved.payload).unwrap();

        assert_eq!(body["content"], "legacy decorated content");
    }

    #[test]
    fn censor_uses_canonical_content_and_structured_prefix() {
        let mut action = action();
        let canonical = "hello unsafe\n-# <:developer_badge:2>";
        let system_prefix = "-# <:staff_badge:1>\n";
        action.attributes = serde_json::json!({
            "content": canonical,
            "content_prefix": system_prefix,
        });
        action.prism_payload = Some(
            prism::PrismStreamPayload {
                batch_id: "batch-1".into(),
                action: "execute".into(),
                payload: serde_json::json!({"content": format!("{system_prefix}{canonical}")})
                    .to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let mut result = allow_result(action.id);
        result.decision = Decision::Censor;
        result.accepted_effects.push(EmittedEffect {
            origin: EffectOrigin {
                policy_bundle_id: Uuid::now_v7(),
                policy_version_id: Uuid::now_v7(),
                rule_id: "rule-1".into(),
                scope: action.scope.clone(),
                priority: 1,
                mandatory: false,
            },
            effect: Effect::Censor {
                effect_id: "censor-1".into(),
                spans: vec![TextSpan {
                    start_character: 6,
                    end_character: 12,
                }],
                replacement: "██████".into(),
                reason_codes: vec![],
            },
        });

        let approved_content = build_approved_content(&action, &result)
            .expect("valid content")
            .expect("approved content");
        let approved_payload =
            build_approved_prism_payload(&action, &result, Some(&approved_content))
                .expect("valid payload")
                .expect("approved payload");
        let body: serde_json::Value = serde_json::from_str(&approved_payload.payload).unwrap();

        assert_eq!(approved_content, "hello ██████\n-# <:developer_badge:2>");
        assert_eq!(
            body["content"],
            "-# <:staff_badge:1>\nhello ██████\n-# <:developer_badge:2>"
        );
    }

    #[test]
    fn call_variants_apply_after_existing_target_overrides() {
        let mut action = action();
        action.action_type = "lobby.message.created".into();
        action.scope = Scope {
            scope_type: ScopeType::Lobby,
            id: "lobby-1".into(),
            product: Some(Product::Lobby),
        };
        action.attributes = serde_json::json!({
            "content": "canonical",
            "display_name": "Alice",
            "username": "alice",
            "content_prefix": "prefix: "
        });

        let fingerprint = [7; 32];
        let mut variants = std::collections::BTreeMap::new();
        variants.insert(
            fingerprint,
            DeliveryVariant {
                message_content: "safe content".into(),
                display_name: "Alice".into(),
                username: "InterChat User".into(),
                server_name: "Server".into(),
                hub_name: "".into(),
                suppress_links: false,
                fingerprint,
            },
        );
        let mut payload = prism::PrismStreamPayload {
            payload: "{}".into(),
            targets: vec![prism::PrismTarget {
                guild_id: Some("server-1".into()),
                overrides: Some(
                    serde_json::json!({
                        "username": "target override",
                        "keep": "existing"
                    })
                    .to_string(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = ContentPolicyPlan::Call(CallPolicyPlan {
            global: ResolvedScopeDecision {
                scope: PolicyScope::global(),
                matched_rules: Vec::new(),
                delivery: DeliveryEffects::default(),
                side_effects: Vec::new(),
            },
            variant: None,
            destinations: vec![DestinationDecision {
                target_index: 0,
                server_id: "server-1".into(),
                policy_id: None,
                policy_version: None,
                matched_rule_ids: Vec::new(),
                blocked_by: Vec::new(),
                variant_fingerprint: Some(fingerprint),
            }],
            variants,
            side_effects: Vec::new(),
            sender_feedback: None,
            evaluated_server_profiles: 0,
        });

        apply_content_policy_plan(&action, &mut payload, &plan).expect("call plan applies");

        let overrides: serde_json::Value = serde_json::from_str(
            payload.targets[0]
                .overrides
                .as_deref()
                .expect("target overrides"),
        )
        .unwrap();
        assert_eq!(overrides["content"], "prefix: safe content");
        assert_eq!(overrides["username"], "InterChat User");
        assert_eq!(overrides["keep"], "existing");
    }

    #[test]
    fn hub_variants_preserve_username_pipe_servername_format_when_server_censored() {
        let mut action = action();
        action.action_type = "hub.message.created".into();
        action.scope = Scope {
            scope_type: ScopeType::Hub,
            id: "hub-1".into(),
            product: Some(Product::Hub),
        };
        action.attributes = serde_json::json!({
            "content": "hello world",
            "display_name": "Alice",
            "username": "alice",
            "server_name": "BadServer",
            "content_prefix": ""
        });

        let fingerprint = [8; 32];
        let mut variants = std::collections::BTreeMap::new();
        variants.insert(
            fingerprint,
            DeliveryVariant {
                message_content: "hello world".into(),
                display_name: "Alice".into(),
                username: "alice".into(),
                server_name: "B#dServer".into(),
                hub_name: "Hub".into(),
                suppress_links: false,
                fingerprint,
            },
        );
        let mut payload = prism::PrismStreamPayload {
            payload: serde_json::json!({
                "username": "Alice | BadServer",
                "content": "hello world"
            })
            .to_string(),
            targets: vec![prism::PrismTarget {
                guild_id: Some("server-1".into()),
                overrides: None,
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = ContentPolicyPlan::Hub(HubPolicyPlan {
            global: ResolvedScopeDecision {
                scope: PolicyScope::global(),
                matched_rules: Vec::new(),
                delivery: DeliveryEffects::default(),
                side_effects: Vec::new(),
            },
            hub: ResolvedScopeDecision {
                scope: PolicyScope::hub("hub-1"),
                matched_rules: Vec::new(),
                delivery: DeliveryEffects::default(),
                side_effects: Vec::new(),
            },
            destinations: vec![DestinationDecision {
                target_index: 0,
                server_id: "server-1".into(),
                policy_id: None,
                policy_version: None,
                matched_rule_ids: Vec::new(),
                blocked_by: Vec::new(),
                variant_fingerprint: Some(fingerprint),
            }],
            variants,
            side_effects: Vec::new(),
            sender_feedback: None,
            evaluated_server_profiles: 0,
        });

        apply_content_policy_plan(&action, &mut payload, &plan).expect("hub plan applies");

        let overrides: serde_json::Value = serde_json::from_str(
            payload.targets[0]
                .overrides
                .as_deref()
                .expect("target overrides"),
        )
        .unwrap();
        assert_eq!(overrides["username"], "Alice | B#dServer");
    }

    #[test]
    fn call_variants_do_not_replace_username_with_server_name_in_1v1_calls() {
        let mut action = action();
        action.action_type = "lobby.message.created".into();
        action.scope = Scope {
            scope_type: ScopeType::Lobby,
            id: "lobby-1".into(),
            product: Some(Product::Lobby),
        };
        action.attributes = serde_json::json!({
            "content": "hello",
            "display_name": "Alice",
            "username": "alice",
            "server_name": "BadServer",
            "content_prefix": ""
        });

        let fingerprint = [9; 32];
        let mut variants = std::collections::BTreeMap::new();
        variants.insert(
            fingerprint,
            DeliveryVariant {
                message_content: "hello".into(),
                display_name: "Alice".into(),
                username: "alice".into(),
                server_name: "B#dServer".into(),
                hub_name: "".into(),
                suppress_links: false,
                fingerprint,
            },
        );
        let mut payload = prism::PrismStreamPayload {
            payload: "{}".into(),
            targets: vec![prism::PrismTarget {
                guild_id: Some("server-1".into()),
                overrides: Some(
                    serde_json::json!({
                        "username": "Alice"
                    })
                    .to_string(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = ContentPolicyPlan::Call(CallPolicyPlan {
            global: ResolvedScopeDecision {
                scope: PolicyScope::global(),
                matched_rules: Vec::new(),
                delivery: DeliveryEffects::default(),
                side_effects: Vec::new(),
            },
            variant: None,
            destinations: vec![DestinationDecision {
                target_index: 0,
                server_id: "server-1".into(),
                policy_id: None,
                policy_version: None,
                matched_rule_ids: Vec::new(),
                blocked_by: Vec::new(),
                variant_fingerprint: Some(fingerprint),
            }],
            variants,
            side_effects: Vec::new(),
            sender_feedback: None,
            evaluated_server_profiles: 0,
        });

        apply_content_policy_plan(&action, &mut payload, &plan).expect("call plan applies");

        let overrides: serde_json::Value = serde_json::from_str(
            payload.targets[0]
                .overrides
                .as_deref()
                .expect("target overrides"),
        )
        .unwrap();
        assert_eq!(overrides["username"], "Alice");
    }

    #[test]
    fn call_variants_replace_censored_server_name_in_group_calls() {
        let mut action = action();
        action.action_type = "lobby.message.created".into();
        action.scope = Scope {
            scope_type: ScopeType::Lobby,
            id: "lobby-1".into(),
            product: Some(Product::Lobby),
        };
        action.attributes = serde_json::json!({
            "content": "hello",
            "display_name": "Alice",
            "username": "alice",
            "server_name": "BadServer",
            "content_prefix": ""
        });

        let fingerprint = [10; 32];
        let mut variants = std::collections::BTreeMap::new();
        variants.insert(
            fingerprint,
            DeliveryVariant {
                message_content: "hello".into(),
                display_name: "Alice".into(),
                username: "alice".into(),
                server_name: "B#dServer".into(),
                hub_name: "".into(),
                suppress_links: false,
                fingerprint,
            },
        );
        let mut payload = prism::PrismStreamPayload {
            payload: "{}".into(),
            targets: vec![prism::PrismTarget {
                guild_id: Some("server-1".into()),
                overrides: Some(
                    serde_json::json!({
                        "username": "Alice (BadServer)"
                    })
                    .to_string(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = ContentPolicyPlan::Call(CallPolicyPlan {
            global: ResolvedScopeDecision {
                scope: PolicyScope::global(),
                matched_rules: Vec::new(),
                delivery: DeliveryEffects::default(),
                side_effects: Vec::new(),
            },
            variant: None,
            destinations: vec![DestinationDecision {
                target_index: 0,
                server_id: "server-1".into(),
                policy_id: None,
                policy_version: None,
                matched_rule_ids: Vec::new(),
                blocked_by: Vec::new(),
                variant_fingerprint: Some(fingerprint),
            }],
            variants,
            side_effects: Vec::new(),
            sender_feedback: None,
            evaluated_server_profiles: 0,
        });

        apply_content_policy_plan(&action, &mut payload, &plan).expect("call plan applies");

        let overrides: serde_json::Value = serde_json::from_str(
            payload.targets[0]
                .overrides
                .as_deref()
                .expect("target overrides"),
        )
        .unwrap();
        assert_eq!(overrides["username"], "Alice (B#dServer)");
    }

    #[test]
    fn censor_spans_use_characters_not_utf8_bytes() {
        let censored = apply_censors_to_content(
            "hi 👋 unsafe",
            vec![(3, 4, "[wave]".into()), (5, 11, "******".into())],
        )
        .expect("valid character spans");
        assert_eq!(censored, "hi [wave] ******");
    }

    #[tokio::test]
    async fn legacy_security_match_span_censors_inserted_punctuation_as_characters() {
        let content = "wum.pus";
        let mut action = action();
        action.attributes = serde_json::json!({"content": content});
        let output = AutomodMatchProvider
            .resolve(
                &action,
                &serde_json::json!({
                    "literals": [{"id": "wumpus", "pattern": "wumpus"}],
                    "regexes": [],
                    "whitelist_pattern_ids": []
                }),
            )
            .await
            .expect("legacy literal provider should resolve");
        let matches: Vec<AutomodMatch> =
            serde_json::from_value(output.value).expect("provider output should be matches");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].original_start_character, 0);
        assert_eq!(matches[0].original_end_character, 7);

        let censored = apply_censors_to_content(
            content,
            vec![(
                matches[0].original_start_character as usize,
                matches[0].original_end_character as usize,
                "[redacted]".into(),
            )],
        )
        .expect("legacy character span should be accepted by delivery");
        assert_eq!(censored, "[redacted]");
    }

    #[test]
    fn overlapping_censor_spans_are_rejected() {
        let error =
            apply_censors_to_content("abcdef", vec![(1, 4, "x".into()), (3, 5, "y".into())])
                .expect_err("overlap must fail closed");
        assert!(error.to_string().contains("overlap"));
    }

    #[test]
    fn outbox_headers_are_complete_binary_cloud_events() {
        let headers = cloud_event_headers("interchat.trust-safety.decision.v2");
        assert_eq!(headers["ce_specversion"], "1.0");
        assert_eq!(headers["ce_type"], "interchat.trust-safety.decision.v2");
        assert_eq!(headers["ce_source"], "/polarizer");
        assert_eq!(headers["ce_datacontenttype"], "application/protobuf");
        assert!(headers["ce_id"].as_str().is_some_and(|id| !id.is_empty()));
        assert!(
            headers["ce_time"]
                .as_str()
                .is_some_and(|time| !time.is_empty())
        );
    }

    #[test]
    fn message_partition_keys_include_scope_type_and_id() {
        let action = action();
        assert_eq!(scope_partition_key(&action.scope), "HUB:hub-1");
    }

    #[test]
    fn effect_validation_prevents_cross_entity_and_cross_scope_writes() {
        let action = action();
        let cross_entity = Effect::CreateRestriction {
            effect_id: "restrict".into(),
            subject: Subject {
                user_id: Some("different-user".into()),
                ..Subject::default()
            },
            restriction_type: "BAN".into(),
            reason: "policy decision".into(),
            duration_ms: None,
        };
        let cross_scope = Effect::IncrementCounter {
            effect_id: "count".into(),
            subject: action.subject.clone(),
            scope: Scope {
                scope_type: ScopeType::Platform,
                id: String::new(),
                product: None,
            },
            counter_type: "violations".into(),
            delta: 1,
            window_ms: 60_000,
            reset: false,
        };

        assert!(validate_effect_for_action(&cross_entity, &action).is_err());
        assert!(validate_effect_for_action(&cross_scope, &action).is_err());
    }

    #[test]
    fn effect_validation_accepts_bounded_same_action_effects() {
        let action = action();
        let effect = Effect::CreateInfraction {
            effect_id: "warning".into(),
            subject: Subject {
                user_id: action.subject.user_id.clone(),
                ..Subject::default()
            },
            infraction_type: "WARNING".into(),
            reason: "policy decision".into(),
            duration_ms: Some(60_000),
            enforcement: None,
        };

        validate_effect_for_action(&effect, &action).expect("valid effect");
    }

    #[test]
    fn action_cipher_round_trips_and_rejects_tampering() {
        let cipher = ActionCipher::new(&[7; 32]).expect("valid key");
        let sealed = cipher.seal(b"pending-prism-payload").expect("encrypt");
        assert_eq!(
            cipher.open(&sealed).expect("decrypt"),
            b"pending-prism-payload"
        );
        let mut tampered = sealed;
        *tampered.last_mut().expect("ciphertext") ^= 1;
        assert!(cipher.open(&tampered).is_err());
    }

    #[test]
    fn hold_deadline_uses_the_shortest_declared_maximum() {
        let now = chrono::Utc::now();
        let origin = EffectOrigin {
            policy_bundle_id: Uuid::now_v7(),
            policy_version_id: Uuid::now_v7(),
            rule_id: "hold".into(),
            scope: action().scope,
            priority: 1,
            mandatory: true,
        };
        let effects = [60_000, 5_000]
            .into_iter()
            .map(|duration| EmittedEffect {
                origin: origin.clone(),
                effect: Effect::Hold {
                    effect_id: format!("hold-{duration}"),
                    reason_codes: vec!["REVIEW".into()],
                    maximum_duration_ms: Some(duration),
                },
            })
            .collect::<Vec<_>>();
        assert_eq!(
            hold_deadline(&effects, now),
            Some(now + chrono::Duration::seconds(5))
        );
    }

    #[test]
    fn hold_resolutions_cannot_release_rejected_or_expired_actions() {
        assert_eq!(
            held_resolution_values(HeldActionResolution::Approve).0,
            "APPROVED_PENDING_DELIVERY"
        );
        assert_eq!(
            held_resolution_values(HeldActionResolution::Reject).0,
            "BLOCKED"
        );
        assert_eq!(
            held_resolution_values(HeldActionResolution::Expire).0,
            "EXPIRED"
        );
    }

    #[test]
    fn bundle_scope_validation_is_typed_and_strict() {
        let valid = Scope {
            scope_type: ScopeType::Hub,
            id: "hub-1".into(),
            product: Some(Product::Hub),
        };
        validate_bundle_fields("anti-spam", "", &valid, 100).expect("valid bundle");

        let wrong_product = Scope {
            product: Some(Product::Lobby),
            ..valid.clone()
        };
        assert!(validate_bundle_fields("anti-spam", "", &wrong_product, 100).is_err());
        assert!(validate_bundle_fields("", "", &valid, 100).is_err());
        assert!(validate_bundle_fields("anti-spam", "", &valid, -1).is_err());
    }

    #[test]
    fn retired_bundles_are_terminal() {
        assert!(is_legal_bundle_transition(
            PolicyBundleState::Active,
            PolicyBundleState::Disabled
        ));
        assert!(is_legal_bundle_transition(
            PolicyBundleState::Disabled,
            PolicyBundleState::Retired
        ));
        assert!(!is_legal_bundle_transition(
            PolicyBundleState::Retired,
            PolicyBundleState::Active
        ));
        assert!(!is_legal_bundle_transition(
            PolicyBundleState::Disabled,
            PolicyBundleState::Disabled
        ));
    }
}

#[derive(Default)]
pub struct InMemoryPolicyRepository {
    pub policies: RwLock<Vec<ActivePolicy>>,
    pub results: RwLock<HashMap<Uuid, EvaluationResult>>,
    pub shadow_results: RwLock<Vec<EvaluationResult>>,
}

#[async_trait]
impl PolicyRepository for InMemoryPolicyRepository {
    async fn active_policies(&self, action: &Action) -> anyhow::Result<Vec<ActivePolicy>> {
        Ok(self
            .policies
            .read()
            .await
            .iter()
            .filter(|policy| policy.bundle.scope.applies_to(action))
            .cloned()
            .collect())
    }
    async fn persist_and_apply(
        &self,
        _action: &Action,
        result: &EvaluationResult,
    ) -> anyhow::Result<PersistOutcome> {
        let mut results = self.results.write().await;
        if results.contains_key(&result.action_id) {
            return Ok(PersistOutcome::Duplicate);
        }
        results.insert(result.action_id, result.clone());
        Ok(PersistOutcome::Applied)
    }

    async fn persist_shadow_comparison(
        &self,
        _action: &Action,
        _active: &EvaluationResult,
        shadow: &EvaluationResult,
    ) -> anyhow::Result<()> {
        self.shadow_results.write().await.push(shadow.clone());
        Ok(())
    }
}
