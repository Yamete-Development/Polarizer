use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use uuid::Uuid;

use crate::{
    contract::v2,
    policy::{
        model::ExecutionTrace,
        repository::{insert_outbox, register_command},
    },
};

pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: String,
}

pub struct RestrictionPage {
    pub items: Vec<v2::Restriction>,
    pub next_cursor: String,
    pub total_count: u64,
}

pub struct ModerationRecordPage {
    pub items: Vec<v2::ModerationRecord>,
    pub next_cursor: String,
    pub total_count: u64,
}

pub struct ReportEvidencePage {
    pub action_ids: Vec<(u64, Uuid)>,
    pub next_cursor: String,
    pub snapshot: v2::ReportEvidenceSnapshot,
}

pub struct ReportSubmissionData {
    pub context: serde_json::Value,
    pub terminal_action_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RestrictionCursor {
    sort: String,
    created_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
struct ModerationRecordCursor {
    sort: String,
    created_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    id: Uuid,
}

struct ModerationLinkTarget {
    resource_type: &'static str,
    id: Uuid,
    subject_type: String,
    subject_id: String,
    scope_type: String,
    scope_id: String,
    kind: &'static str,
    source_report_id: Option<Uuid>,
    version: i64,
    enforcement_restriction_id: Option<Uuid>,
}

struct EnforcementInsert {
    id: Uuid,
    subject_type: &'static str,
    subject_id: String,
    scope_type: &'static str,
    scope_id: String,
    restriction_type: &'static str,
    reason: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct ModerationRepository {
    db: PgPool,
    command_topic: String,
}

impl ModerationRepository {
    pub fn new(db: PgPool, command_topic: impl Into<String>) -> Self {
        Self {
            db,
            command_topic: command_topic.into(),
        }
    }

    pub async fn create_restriction(
        &self,
        context: &v2::RequestContext,
        restriction: v2::Restriction,
    ) -> anyhow::Result<v2::Restriction> {
        let subject = restriction
            .subject
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restriction subject is required"))?;
        let (subject_type, subject_id) = primary_subject(subject, false)?;
        let scope = restriction
            .scope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restriction scope is required"))?;
        let scope_type = scope_name(scope.r#type)?;
        let restriction_type = restriction_type_name(restriction.r#type)?;
        anyhow::ensure!(!restriction.reason.trim().is_empty(), "reason is required");
        let expires_at = restriction.expires_at.map(datetime).transpose()?;
        let source_report_id = optional_uuid(&restriction.source_report_id, "source_report_id")?;
        let id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        match claim_idempotency(&mut tx, context, "CREATE_RESTRICTION", id).await? {
            IdempotencyClaim::Existing(existing) => {
                tx.rollback().await?;
                return self.get_restriction(existing).await;
            }
            IdempotencyClaim::Claimed => {}
        }
        sqlx::query(
            "INSERT INTO trust_safety.restriction \
             (id, subject_type, subject_id, scope_type, scope_id, restriction_type, reason, created_by, expires_at, source_report_id) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(restriction_type)
        .bind(restriction.reason.trim())
        .bind(&context.actor_id)
        .bind(expires_at)
        .bind(source_report_id)
        .execute(&mut *tx)
        .await?;
        insert_audit(&mut tx, context, "CREATE_RESTRICTION", "RESTRICTION", id).await?;
        if subject_type == "USER" {
            self.insert_manual_restriction_notice(
                &mut tx,
                id,
                subject_id,
                scope,
                restriction_type,
                restriction.reason.trim(),
                expires_at,
                1,
                v2::ModerationNoticeEvent::Applied,
            )
            .await?;
        }
        tx.commit().await?;
        self.get_restriction(id).await
    }

    pub async fn revoke_restriction(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        reason: &str,
        expected_version: i64,
    ) -> anyhow::Result<v2::Restriction> {
        anyhow::ensure!(!reason.trim().is_empty(), "revocation reason is required");
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "REVOKE_RESTRICTION", id).await?
        {
            tx.rollback().await?;
            return self.get_restriction(existing).await;
        }
        let updated = sqlx::query(
            "UPDATE trust_safety.restriction SET status = 'REVOKED', revoked_by = $2, revoked_reason = $3, \
             version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $4 AND status = 'ACTIVE'",
        )
        .bind(id)
        .bind(&context.actor_id)
        .bind(reason.trim())
        .bind(expected_version)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(updated.rows_affected() == 1, "restriction version conflict");
        insert_audit(&mut tx, context, "REVOKE_RESTRICTION", "RESTRICTION", id).await?;
        tx.commit().await?;
        self.get_restriction(id).await
    }

    pub async fn update_restriction(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        reason: Option<&str>,
        expires_at: Option<Option<DateTime<Utc>>>,
        expected_version: i64,
    ) -> anyhow::Result<v2::Restriction> {
        anyhow::ensure!(expected_version > 0, "expected_version is required");
        anyhow::ensure!(
            reason.is_some() || expires_at.is_some(),
            "update mask is required"
        );
        if let Some(reason) = reason {
            anyhow::ensure!(!reason.trim().is_empty(), "reason is required");
            anyhow::ensure!(
                reason.trim().chars().count() <= 2_000,
                "invalid reason: must not exceed 2000 characters"
            );
        }
        if let Some(Some(expires_at)) = expires_at {
            anyhow::ensure!(expires_at > Utc::now(), "expires_at must be in the future");
        }

        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "UPDATE_RESTRICTION", id).await?
        {
            tx.rollback().await?;
            return self.get_restriction(existing).await;
        }
        let update_reason = reason.is_some();
        let update_expires_at = expires_at.is_some();
        let updated = sqlx::query(
            "UPDATE trust_safety.restriction SET \
             reason = CASE WHEN $2 THEN $3 ELSE reason END, \
             expires_at = CASE WHEN $4 THEN $5 ELSE expires_at END, \
             version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $6 AND status = 'ACTIVE'",
        )
        .bind(id)
        .bind(update_reason)
        .bind(reason.map(str::trim))
        .bind(update_expires_at)
        .bind(expires_at.flatten())
        .bind(expected_version)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(updated.rows_affected() == 1, "restriction version conflict");
        insert_audit(&mut tx, context, "UPDATE_RESTRICTION", "RESTRICTION", id).await?;
        let updated_record = sqlx::query(
            "SELECT subject_type, subject_id, scope_type::text, scope_id, restriction_type, \
                    reason, expires_at, version \
             FROM trust_safety.restriction WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if updated_record.try_get::<String, _>("subject_type")? == "USER" {
            let scope = scope_from_parts(
                updated_record.try_get("scope_type")?,
                updated_record.try_get("scope_id")?,
            )?;
            let subject_id: String = updated_record.try_get("subject_id")?;
            let restriction_type: String = updated_record.try_get("restriction_type")?;
            let reason: String = updated_record.try_get("reason")?;
            let expires_at: Option<DateTime<Utc>> = updated_record.try_get("expires_at")?;
            let record_version: i64 = updated_record.try_get("version")?;
            self.insert_manual_restriction_notice(
                &mut tx,
                id,
                &subject_id,
                &scope,
                &restriction_type,
                &reason,
                expires_at,
                record_version,
                v2::ModerationNoticeEvent::Updated,
            )
            .await?;
        }
        tx.commit().await?;
        self.get_restriction(id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_restrictions(
        &self,
        scope: &v2::Scope,
        subject: Option<&v2::Subject>,
        status: Option<&str>,
        restriction_type: Option<&str>,
        requested_subject_type: Option<&str>,
        requested_subject_id: Option<&str>,
        created_by: Option<&str>,
        query: Option<&str>,
        sort: &str,
        cursor: &str,
        limit: i64,
        include_total_count: bool,
    ) -> anyhow::Result<RestrictionPage> {
        let (subject_type, subject_id) = subject
            .map(|subject| primary_subject(subject, false))
            .transpose()?
            .map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let page_size = limit.clamp(1, 100);
        let scope_name = scope_name(scope.r#type)?;
        let sort = normalize_restriction_sort(sort)?;
        let parsed_cursor = parse_restriction_cursor(cursor, sort)?;
        let requested_subject_type = requested_subject_type.or(subject_type);
        let requested_subject_id = requested_subject_id.or(subject_id);
        let query_pattern = query.map(like_pattern);

        let total_count = if include_total_count {
            let mut count_query =
                QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM trust_safety.restriction");
            push_restriction_filters(
                &mut count_query,
                scope_name,
                &scope.id,
                status,
                restriction_type,
                requested_subject_type,
                requested_subject_id,
                created_by,
                query_pattern.as_deref(),
            );
            count_query
                .build_query_scalar::<i64>()
                .fetch_one(&self.db)
                .await? as u64
        } else {
            0
        };

        let mut rows_query = QueryBuilder::<Postgres>::new(
            "SELECT id, subject_type, subject_id, scope_type::text, scope_id, restriction_type, \
             status::text, reason, created_by, created_at, expires_at, version, source_report_id \
             FROM trust_safety.restriction",
        );
        push_restriction_filters(
            &mut rows_query,
            scope_name,
            &scope.id,
            status,
            restriction_type,
            requested_subject_type,
            requested_subject_id,
            created_by,
            query_pattern.as_deref(),
        );
        push_restriction_cursor(&mut rows_query, sort, parsed_cursor.as_ref());
        let fetch_size = (page_size + 1).min(100);
        rows_query
            .push(" ORDER BY ")
            .push(restriction_sort_sql(sort))
            .push(" LIMIT ")
            .push_bind(fetch_size);
        let mut rows = rows_query.build().fetch_all(&self.db).await?;
        let has_more = rows.len() > page_size as usize;
        if has_more {
            rows.truncate(page_size as usize);
        }
        let next_cursor = if has_more {
            restriction_page_cursor(&rows, sort)?
        } else {
            String::new()
        };
        let items = rows
            .iter()
            .map(restriction_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(RestrictionPage {
            items,
            next_cursor,
            total_count,
        })
    }

    pub async fn create_infraction(
        &self,
        context: &v2::RequestContext,
        infraction: v2::Infraction,
        enforcement: Option<v2::Restriction>,
    ) -> anyhow::Result<v2::Infraction> {
        let subject = infraction
            .subject
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("infraction subject is required"))?;
        let (subject_type, subject_id) = primary_subject(subject, true)?;
        let scope = infraction
            .scope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("infraction scope is required"))?;
        let scope_type = scope_name(scope.r#type)?;
        let infraction_type = infraction_type_name(infraction.r#type)?;
        anyhow::ensure!(!infraction.reason.trim().is_empty(), "reason is required");
        let expires_at = infraction.expires_at.map(datetime).transpose()?;
        let required_enforcement_type = match infraction_type {
            "MUTE" => Some("MUTE"),
            "BAN" if scope_type == "PLATFORM" => Some("BLACKLIST"),
            "BAN" => Some("BAN"),
            "WARNING" | "CONTENT" => None,
            _ => unreachable!("infraction type was validated"),
        };
        let enforcement = match (required_enforcement_type, enforcement) {
            (Some(expected_type), Some(enforcement)) => {
                let enforcement_subject = enforcement
                    .subject
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("enforcement subject is required"))?;
                let (enforcement_subject_type, enforcement_subject_id) =
                    primary_subject(enforcement_subject, false)?;
                anyhow::ensure!(
                    enforcement_subject_type == subject_type
                        && enforcement_subject_id == subject_id,
                    "enforcement subject must match infraction subject"
                );
                let enforcement_scope = enforcement
                    .scope
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("enforcement scope is required"))?;
                let enforcement_scope_type = scope_name(enforcement_scope.r#type)?;
                anyhow::ensure!(
                    enforcement_scope_type == scope_type && enforcement_scope.id == scope.id,
                    "enforcement scope must match infraction scope"
                );
                let enforcement_type = restriction_type_name(enforcement.r#type)?;
                anyhow::ensure!(
                    enforcement_type == expected_type,
                    "enforcement type must match infraction type"
                );
                anyhow::ensure!(
                    !enforcement.reason.trim().is_empty(),
                    "enforcement reason is required"
                );
                let enforcement_expires_at = enforcement.expires_at.map(datetime).transpose()?;
                anyhow::ensure!(
                    enforcement_expires_at == expires_at,
                    "enforcement expiry must match infraction expiry"
                );
                Some(EnforcementInsert {
                    id: Uuid::now_v7(),
                    subject_type: enforcement_subject_type,
                    subject_id: enforcement_subject_id.to_owned(),
                    scope_type: enforcement_scope_type,
                    scope_id: enforcement_scope.id.clone(),
                    restriction_type: enforcement_type,
                    reason: enforcement.reason.trim().to_owned(),
                    expires_at: enforcement_expires_at,
                })
            }
            (Some(_), None) => anyhow::bail!("mute and ban infractions require enforcement"),
            (None, Some(_)) => {
                anyhow::bail!("warning and content infractions cannot include enforcement")
            }
            (None, None) => None,
        };
        let id = Uuid::now_v7();
        let source_report_id = optional_uuid(&infraction.source_report_id, "source_report_id")?;
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "CREATE_INFRACTION", id).await?
        {
            tx.rollback().await?;
            return self.get_infraction(existing).await;
        }
        if let Some(report_id) = source_report_id {
            let owns_live_claim = sqlx::query(
                "SELECT id FROM trust_safety.report
                 WHERE id=$1 AND status='PENDING'
                   AND (
                     (scope_type='HUB' AND scope_type=$3::trust_safety.scope_type AND scope_id=$4)
                     OR (
                       claimed_by=$2 AND claim_expires_at > clock_timestamp()
                       AND (
                         (scope_type=$3::trust_safety.scope_type AND scope_id=$4)
                         OR (
                           scope_type='LOBBY'
                           AND $3::trust_safety.scope_type IN ('PRODUCT', 'PLATFORM')
                           AND $4=''
                         )
                       )
                     )
                   )
                 FOR UPDATE",
            )
            .bind(report_id)
            .bind(&context.actor_id)
            .bind(scope_type)
            .bind(&scope.id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            anyhow::ensure!(
                owns_live_claim,
                "case-bound action requires a live claim owned by the actor"
            );
        }
        if let Some(enforcement) = &enforcement {
            sqlx::query(
                "INSERT INTO trust_safety.restriction \
                 (id, subject_type, subject_id, scope_type, scope_id, restriction_type, reason, created_by, expires_at, source_report_id) \
                 VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9, $10)",
            )
            .bind(enforcement.id)
            .bind(enforcement.subject_type)
            .bind(&enforcement.subject_id)
            .bind(enforcement.scope_type)
            .bind(&enforcement.scope_id)
            .bind(enforcement.restriction_type)
            .bind(&enforcement.reason)
            .bind(&context.actor_id)
            .bind(enforcement.expires_at)
            .bind(source_report_id)
            .execute(&mut *tx)
            .await?;
            insert_audit(
                &mut tx,
                context,
                "CREATE_ENFORCEMENT_RESTRICTION",
                "RESTRICTION",
                enforcement.id,
            )
            .await?;
        }
        sqlx::query(
            "INSERT INTO trust_safety.infraction \
             (id, subject_type, subject_id, scope_type, scope_id, infraction_type, reason, created_by, expires_at, enforcement_restriction_id, source_report_id) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(infraction_type)
        .bind(infraction.reason.trim())
        .bind(&context.actor_id)
        .bind(expires_at)
        .bind(enforcement.as_ref().map(|item| item.id))
        .bind(source_report_id)
        .execute(&mut *tx)
        .await?;
        let signal_value = match infraction_type {
            "WARNING" => 5.0,
            "MUTE" => 15.0,
            "BAN" => 30.0,
            "CONTENT" => 10.0,
            _ => 0.0,
        };
        let (observation_id, assessment_id) = insert_derived_safety_observation_tx(
            &mut tx,
            subject_type,
            subject_id,
            scope_type,
            &scope.id,
            &format!("INFRACTION_{infraction_type}"),
            signal_value,
            false,
            serde_json::json!({"infraction_id": id}),
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "DERIVE_SAFETY_OBSERVATION",
            "SAFETY_OBSERVATION",
            observation_id,
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "RECALCULATE_SAFETY_ASSESSMENT",
            "SAFETY_ASSESSMENT",
            assessment_id,
        )
        .await?;
        insert_audit(&mut tx, context, "CREATE_INFRACTION", "INFRACTION", id).await?;
        if subject_type == "USER" {
            self.insert_manual_moderation_notice(
                &mut tx,
                id,
                subject_id,
                scope,
                infraction_type,
                infraction.reason.trim(),
                expires_at,
                enforcement.as_ref().map(|value| value.id),
            )
            .await?;
        }
        tx.commit().await?;
        self.get_infraction(id).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_manual_moderation_notice(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        infraction_id: Uuid,
        user_id: &str,
        scope: &v2::Scope,
        infraction_type: &str,
        reason: &str,
        expires_at: Option<DateTime<Utc>>,
        restriction_id: Option<Uuid>,
    ) -> anyhow::Result<()> {
        let scope_type = scope_name(scope.r#type)?;
        let kind = match (restriction_id.is_some(), infraction_type, scope_type) {
            (true, "BAN", "PLATFORM") => v2::ModerationNoticeKind::GlobalBlacklist,
            (_, "WARNING", "HUB") => v2::ModerationNoticeKind::HubWarning,
            (_, "MUTE", "HUB") => v2::ModerationNoticeKind::HubMute,
            (_, "BAN", "HUB") => v2::ModerationNoticeKind::HubBan,
            (_, "WARNING", "LOBBY" | "PRODUCT") => v2::ModerationNoticeKind::LobbyWarning,
            (_, "BAN", "LOBBY" | "PRODUCT") => v2::ModerationNoticeKind::LobbyBan,
            _ => return Ok(()),
        };
        let command = v2::CommandEnvelope {
            id: Uuid::now_v7().to_string(),
            decision_id: String::new(),
            idempotency_key: format!("moderation-notice:{infraction_id}"),
            command: Some(v2::command_envelope::Command::ModerationNotice(
                v2::ModerationNoticeCommand {
                    user_id: user_id.to_owned(),
                    kind: kind as i32,
                    event: v2::ModerationNoticeEvent::Applied as i32,
                    scope: Some(scope.clone()),
                    public_reason: reason.to_owned(),
                    expires_at: expires_at.map(timestamp),
                    infraction_id: infraction_id.to_string(),
                    restriction_id: restriction_id
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    source: "manual".into(),
                    source_channel_id: String::new(),
                    source_message_id: String::new(),
                    source_user_id: user_id.to_owned(),
                    record_version: 1,
                },
            )),
        };
        register_command(tx, &command).await?;
        insert_outbox(
            tx,
            "INFRACTION",
            infraction_id,
            &self.command_topic,
            "interchat.trust-safety.command.v2",
            &command.id,
            command.encode_to_vec(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_manual_restriction_notice(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        restriction_id: Uuid,
        user_id: &str,
        scope: &v2::Scope,
        restriction_type: &str,
        reason: &str,
        expires_at: Option<DateTime<Utc>>,
        record_version: i64,
        event: v2::ModerationNoticeEvent,
    ) -> anyhow::Result<()> {
        let scope_type = scope_name(scope.r#type)?;
        let kind = match (restriction_type, scope_type) {
            ("BLACKLIST", "PLATFORM") => v2::ModerationNoticeKind::GlobalBlacklist,
            ("MUTE", "HUB") => v2::ModerationNoticeKind::HubMute,
            ("BAN", "HUB") => v2::ModerationNoticeKind::HubBan,
            ("BAN", "LOBBY" | "PRODUCT") => v2::ModerationNoticeKind::LobbyBan,
            _ => return Ok(()),
        };
        let command = v2::CommandEnvelope {
            id: Uuid::now_v7().to_string(),
            decision_id: String::new(),
            idempotency_key: format!(
                "moderation-notice:restriction:{restriction_id}:{record_version}"
            ),
            command: Some(v2::command_envelope::Command::ModerationNotice(
                v2::ModerationNoticeCommand {
                    user_id: user_id.to_owned(),
                    kind: kind as i32,
                    event: event as i32,
                    scope: Some(scope.clone()),
                    public_reason: reason.to_owned(),
                    expires_at: expires_at.map(timestamp),
                    infraction_id: String::new(),
                    restriction_id: restriction_id.to_string(),
                    source: "manual".into(),
                    source_channel_id: String::new(),
                    source_message_id: String::new(),
                    source_user_id: user_id.to_owned(),
                    record_version,
                },
            )),
        };
        register_command(tx, &command).await?;
        insert_outbox(
            tx,
            "RESTRICTION",
            restriction_id,
            &self.command_topic,
            "interchat.trust-safety.command.v2",
            &command.id,
            command.encode_to_vec(),
        )
        .await
    }

    pub async fn revoke_infraction(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        reason: &str,
        expected_version: i64,
    ) -> anyhow::Result<v2::Infraction> {
        anyhow::ensure!(!reason.trim().is_empty(), "revocation reason is required");
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "REVOKE_INFRACTION", id).await?
        {
            tx.rollback().await?;
            return self.get_infraction(existing).await;
        }
        let updated = sqlx::query(
            "UPDATE trust_safety.infraction SET status = 'REVOKED', revoked_by = $2, revoked_reason = $3, \
             version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $4 AND status = 'ACTIVE' \
             RETURNING enforcement_restriction_id, subject_type, subject_id, scope_type::text, scope_id, infraction_type",
        )
        .bind(id)
        .bind(&context.actor_id)
        .bind(reason.trim())
        .bind(expected_version)
        .fetch_optional(&mut *tx)
        .await?;
        let updated = updated.ok_or_else(|| anyhow::anyhow!("infraction version conflict"))?;
        let infraction_type: String = updated.try_get("infraction_type")?;
        let signal_value = match infraction_type.as_str() {
            "WARNING" => 5.0,
            "MUTE" => 15.0,
            "BAN" => 30.0,
            "CONTENT" => 10.0,
            _ => 0.0,
        };
        let (observation_id, assessment_id) = insert_derived_safety_observation_tx(
            &mut tx,
            updated.try_get("subject_type")?,
            updated.try_get("subject_id")?,
            updated.try_get("scope_type")?,
            updated.try_get("scope_id")?,
            &format!("INFRACTION_{infraction_type}_REVOKED"),
            signal_value,
            true,
            serde_json::json!({"infraction_id": id, "reason": reason.trim()}),
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "DERIVE_SAFETY_OBSERVATION",
            "SAFETY_OBSERVATION",
            observation_id,
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "RECALCULATE_SAFETY_ASSESSMENT",
            "SAFETY_ASSESSMENT",
            assessment_id,
        )
        .await?;
        if let Some(restriction_id) =
            updated.try_get::<Option<Uuid>, _>("enforcement_restriction_id")?
        {
            let restriction = sqlx::query(
                "UPDATE trust_safety.restriction SET status = 'REVOKED', revoked_by = $2, revoked_reason = $3, \
                 version = version + 1, updated_at = clock_timestamp() WHERE id = $1 AND status = 'ACTIVE'",
            )
            .bind(restriction_id)
            .bind(&context.actor_id)
            .bind(reason.trim())
            .execute(&mut *tx)
            .await?;
            if restriction.rows_affected() == 1 {
                insert_audit(
                    &mut tx,
                    context,
                    "REVOKE_ENFORCEMENT_RESTRICTION",
                    "RESTRICTION",
                    restriction_id,
                )
                .await?;
            }
        }
        insert_audit(&mut tx, context, "REVOKE_INFRACTION", "INFRACTION", id).await?;
        tx.commit().await?;
        self.get_infraction(id).await
    }

    pub async fn revoke_infractions_by_type(
        &self,
        context: &v2::RequestContext,
        scope: &v2::Scope,
        subject: &v2::Subject,
        infraction_type: &str,
        reason: &str,
    ) -> anyhow::Result<(Vec<v2::Infraction>, Vec<v2::Restriction>)> {
        anyhow::ensure!(!reason.trim().is_empty(), "revocation reason is required");
        let (subject_type, subject_id) = primary_subject(subject, true)?;
        let scope_type = scope_name(scope.r#type)?;
        let mut tx = self.db.begin().await?;
        let infraction_rows = sqlx::query(
            "UPDATE trust_safety.infraction SET status = 'REVOKED', revoked_by = $2, revoked_reason = $3, \
             version = version + 1, updated_at = clock_timestamp() \
             WHERE subject_type = $4 AND subject_id = $5 \
               AND scope_type = $6::trust_safety.scope_type AND scope_id = $7 \
               AND infraction_type = $8 AND status = 'ACTIVE' \
             RETURNING id",
        )
        .bind(&context.actor_id)
        .bind(reason.trim())
        .bind(subject_type)
        .bind(subject_id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(infraction_type)
        .fetch_all(&mut *tx)
        .await?;
        let infraction_ids: Vec<Uuid> = infraction_rows
            .iter()
            .map(|r| r.try_get("id"))
            .collect::<Result<_, _>>()?;
        let mut revoked_restrictions = Vec::new();
        for infraction_id in &infraction_ids {
            insert_audit(
                &mut tx,
                context,
                "REVOKE_INFRACTION",
                "INFRACTION",
                *infraction_id,
            )
            .await?;
        }
        let restriction_rows = sqlx::query(
            "UPDATE trust_safety.restriction SET status = 'REVOKED', revoked_by = $2, revoked_reason = $3, \
             version = version + 1, updated_at = clock_timestamp() \
             WHERE subject_type = $4 AND subject_id = $5 \
               AND scope_type = $6::trust_safety.scope_type AND scope_id = $7 \
               AND restriction_type = $8 AND status = 'ACTIVE' \
               AND id NOT IN (SELECT enforcement_restriction_id FROM trust_safety.infraction \
                              WHERE enforcement_restriction_id IS NOT NULL \
                                AND subject_type = $4 AND subject_id = $5 \
                                AND scope_type = $6::trust_safety.scope_type AND scope_id = $7 \
                                AND infraction_type = $8 AND status = 'REVOKED') \
             RETURNING id",
        )
        .bind(&context.actor_id)
        .bind(reason.trim())
        .bind(subject_type)
        .bind(subject_id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(infraction_type)
        .fetch_all(&mut *tx)
        .await?;
        let restriction_ids: Vec<Uuid> = restriction_rows
            .iter()
            .map(|r| r.try_get("id"))
            .collect::<Result<_, _>>()?;
        for restriction_id in &restriction_ids {
            insert_audit(
                &mut tx,
                context,
                "REVOKE_RESTRICTION",
                "RESTRICTION",
                *restriction_id,
            )
            .await?;
        }
        tx.commit().await?;
        let mut revoked_infractions = Vec::new();
        for id in &infraction_ids {
            revoked_infractions.push(self.get_infraction(*id).await?);
        }
        for id in &restriction_ids {
            revoked_restrictions.push(self.get_restriction(*id).await?);
        }
        Ok((revoked_infractions, revoked_restrictions))
    }

    pub async fn list_infractions(
        &self,
        scope: &v2::Scope,
        subject: Option<&v2::Subject>,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<v2::Infraction>> {
        let (subject_type, subject_id) = subject
            .map(|subject| primary_subject(subject, true))
            .transpose()?
            .map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let rows = sqlx::query(
            "SELECT id, subject_type, subject_id, scope_type::text, scope_id, infraction_type, \
             status::text, reason, created_by, created_at, expires_at, version, enforcement_restriction_id, source_report_id \
             FROM trust_safety.infraction WHERE scope_type = $1::trust_safety.scope_type AND scope_id = $2 \
             AND ($3::text IS NULL OR subject_type = $3) AND ($4::text IS NULL OR subject_id = $4) \
             AND ($5::text IS NULL OR status = $5::trust_safety.resource_status) \
             AND ($6::uuid IS NULL OR id < $6) ORDER BY id DESC LIMIT $7",
        )
        .bind(scope_name(scope.r#type)?)
        .bind(&scope.id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(status)
        .bind(cursor)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        let next_cursor = page_cursor(&rows, limit, "id")?;
        let items = rows
            .iter()
            .map(infraction_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }

    pub async fn list_user_infractions(
        &self,
        user_id: &str,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<v2::Infraction>> {
        let rows = sqlx::query(
            "SELECT id, subject_type, subject_id, scope_type::text, scope_id, infraction_type, \
             status::text, reason, created_by, created_at, expires_at, version, enforcement_restriction_id, source_report_id \
             FROM trust_safety.infraction WHERE subject_type = 'USER' AND subject_id = $1 \
             AND ($2::text IS NULL OR status = $2::trust_safety.resource_status) \
             AND ($3::uuid IS NULL OR id < $3) ORDER BY id DESC LIMIT $4",
        )
        .bind(user_id)
        .bind(status)
        .bind(cursor)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        let next_cursor = page_cursor(&rows, limit, "id")?;
        let items = rows
            .iter()
            .map(infraction_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_moderation_records(
        &self,
        kinds: &[i32],
        subject_type: Option<&str>,
        subject_id: Option<&str>,
        created_by: Option<&str>,
        query: Option<&str>,
        status: Option<&str>,
        sort: &str,
        cursor: &str,
        limit: i64,
        include_total_count: bool,
    ) -> anyhow::Result<ModerationRecordPage> {
        let selected_kinds = moderation_kind_names(kinds)?;
        let sort = normalize_moderation_record_sort(sort)?;
        let cursor = parse_moderation_record_cursor(cursor, sort)?;
        let page_size = limit.clamp(1, 100);
        let query_pattern = query.map(like_pattern);

        let mut records = QueryBuilder::<Postgres>::new("WITH records AS (");
        let mut branch_count = 0;
        if selected_kinds.contains("BLACKLIST") {
            records.push(
                "SELECT 'RESTRICTION'::text AS resource_type, 'BLACKLIST'::text AS kind, \
                 restriction.id, restriction.subject_type, restriction.subject_id, \
                 restriction.scope_type::text AS scope_type, restriction.scope_id, \
                 restriction.restriction_type, NULL::text AS infraction_type, \
                 restriction.status::text AS status, restriction.reason, restriction.created_by, \
                 restriction.created_at, restriction.expires_at, restriction.version, \
                 NULL::uuid AS enforcement_restriction_id, restriction.source_report_id \
                 FROM trust_safety.restriction restriction \
                 WHERE restriction.scope_type = 'PLATFORM'::trust_safety.scope_type \
                   AND restriction.restriction_type = 'BLACKLIST'",
            );
            branch_count += 1;
        }

        let include_warning = selected_kinds.contains("WARNING");
        let include_lobby_warning = selected_kinds.contains("LOBBY_WARNING");
        let include_lobby_ban = selected_kinds.contains("LOBBY_BAN");
        if include_warning || include_lobby_warning || include_lobby_ban {
            if branch_count > 0 {
                records.push(" UNION ALL ");
            }
            records.push(
                "SELECT 'INFRACTION'::text AS resource_type, \
                 CASE WHEN infraction.infraction_type = 'WARNING' \
                      AND infraction.scope_type = 'LOBBY'::trust_safety.scope_type \
                   THEN 'LOBBY_WARNING' WHEN infraction.infraction_type = 'BAN' \
                       AND infraction.scope_type = 'PRODUCT'::trust_safety.scope_type \
                   THEN 'LOBBY_BAN' ELSE 'WARNING' END AS kind, \
                 infraction.id, infraction.subject_type, infraction.subject_id, \
                 infraction.scope_type::text AS scope_type, infraction.scope_id, \
                 NULL::text AS restriction_type, infraction.infraction_type, \
                 infraction.status::text AS status, infraction.reason, infraction.created_by, \
                 infraction.created_at, infraction.expires_at, infraction.version, \
                 infraction.enforcement_restriction_id, infraction.source_report_id \
                 FROM trust_safety.infraction infraction WHERE (",
            );
            let mut condition_count = 0;
            if include_warning {
                records.push(
                    "(infraction.infraction_type = 'WARNING' \
                      AND infraction.scope_type <> 'LOBBY'::trust_safety.scope_type)",
                );
                condition_count += 1;
            }
            if include_lobby_warning {
                if condition_count > 0 {
                    records.push(" OR ");
                }
                records.push(
                    "(infraction.infraction_type = 'WARNING' \
                      AND infraction.scope_type = 'LOBBY'::trust_safety.scope_type)",
                );
                condition_count += 1;
            }
            if include_lobby_ban {
                if condition_count > 0 {
                    records.push(" OR ");
                }
                records.push(
                    "(infraction.infraction_type = 'BAN' \
                      AND infraction.scope_type = 'PRODUCT'::trust_safety.scope_type)",
                );
            }
            records.push(")");
            branch_count += 1;
        }

        if branch_count == 0 {
            records.push(
                "SELECT NULL::text AS resource_type, NULL::text AS kind, NULL::uuid AS id, \
                 NULL::text AS subject_type, NULL::text AS subject_id, NULL::text AS scope_type, \
                 NULL::text AS scope_id, NULL::text AS restriction_type, \
                 NULL::text AS infraction_type, NULL::text AS status, NULL::text AS reason, \
                 NULL::text AS created_by, NULL::timestamptz AS created_at, \
                 NULL::timestamptz AS expires_at, NULL::bigint AS version, \
                 NULL::uuid AS enforcement_restriction_id, NULL::uuid AS source_report_id \
                 WHERE FALSE",
            );
        }

        records.push("), filtered AS (SELECT records.*");
        if include_total_count {
            records.push(", COUNT(*) OVER() AS total_count");
        } else {
            records.push(", 0::bigint AS total_count");
        }
        records.push(" FROM records WHERE TRUE");
        push_moderation_record_filters(
            &mut records,
            subject_type,
            subject_id,
            created_by,
            query_pattern.as_deref(),
            status,
        );
        records.push(
            ") SELECT resource_type, kind, id, subject_type, subject_id, scope_type, \
                      scope_id, restriction_type, infraction_type, status, reason, created_by, \
                      created_at, expires_at, version, enforcement_restriction_id, \
                      source_report_id, total_count FROM filtered WHERE TRUE",
        );
        push_moderation_record_cursor(&mut records, sort, cursor.as_ref());
        records
            .push(" ORDER BY ")
            .push(moderation_record_sort_sql(sort))
            .push(" LIMIT ")
            .push_bind(page_size + 1);

        let mut rows = records.build().fetch_all(&self.db).await?;
        let total_count = rows
            .first()
            .map(|row| row.try_get::<i64, _>("total_count"))
            .transpose()?
            .unwrap_or_default()
            .max(0) as u64;
        let has_more = rows.len() > page_size as usize;
        if has_more {
            rows.truncate(page_size as usize);
        }
        let next_cursor = if has_more {
            moderation_record_page_cursor(&rows, sort)?
        } else {
            String::new()
        };
        let items = rows
            .iter()
            .map(moderation_record_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(ModerationRecordPage {
            items,
            next_cursor,
            total_count,
        })
    }

    pub async fn get_moderation_record(
        &self,
        resource_type: v2::ModerationResourceType,
        id: Uuid,
    ) -> anyhow::Result<v2::ModerationRecord> {
        let row = match resource_type {
            v2::ModerationResourceType::Restriction => sqlx::query(
                "SELECT id, subject_type, subject_id, scope_type::text, scope_id, \
                 restriction_type, NULL::text AS infraction_type, status::text, reason, \
                 created_by, created_at, expires_at, version, NULL::uuid AS enforcement_restriction_id, \
                 source_report_id, 'RESTRICTION'::text AS resource_type, 'BLACKLIST'::text AS kind \
                 FROM trust_safety.restriction \
                 WHERE id = $1 AND scope_type = 'PLATFORM'::trust_safety.scope_type \
                   AND restriction_type = 'BLACKLIST'",
            )
            .bind(id)
            .fetch_one(&self.db)
            .await?,
            v2::ModerationResourceType::Infraction => sqlx::query(
                "SELECT id, subject_type, subject_id, scope_type::text, scope_id, \
                 NULL::text AS restriction_type, infraction_type, status::text, reason, \
                 created_by, created_at, expires_at, version, enforcement_restriction_id, \
                 source_report_id, 'INFRACTION'::text AS resource_type, \
                 CASE WHEN infraction_type = 'WARNING' \
                      AND scope_type = 'LOBBY'::trust_safety.scope_type \
                   THEN 'LOBBY_WARNING' WHEN infraction_type = 'BAN' \
                      AND scope_type = 'PRODUCT'::trust_safety.scope_type \
                   THEN 'LOBBY_BAN' ELSE 'WARNING' END AS kind \
                 FROM trust_safety.infraction \
                 WHERE id = $1 AND (infraction_type = 'WARNING' \
                   OR (infraction_type = 'BAN' AND scope_type = 'PRODUCT'::trust_safety.scope_type))",
            )
            .bind(id)
            .fetch_one(&self.db)
            .await?,
            v2::ModerationResourceType::Unspecified => {
                anyhow::bail!("moderation resource type is required")
            }
        };
        moderation_record_from_row(&row)
    }

    pub async fn link_moderation_record_report(
        &self,
        context: &v2::RequestContext,
        resource_type: v2::ModerationResourceType,
        record_id: Uuid,
        report_id: Uuid,
        expected_version: i64,
    ) -> anyhow::Result<v2::ModerationRecord> {
        anyhow::ensure!(expected_version > 0, "expected_version is required");
        let (resource_name, operation) = match resource_type {
            v2::ModerationResourceType::Restriction => {
                ("RESTRICTION", "LINK_MODERATION_RECORD_REPORT_RESTRICTION")
            }
            v2::ModerationResourceType::Infraction => {
                ("INFRACTION", "LINK_MODERATION_RECORD_REPORT_INFRACTION")
            }
            v2::ModerationResourceType::Unspecified => {
                anyhow::bail!("moderation resource type is required")
            }
        };

        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, operation, record_id).await?
        {
            tx.rollback().await?;
            return self.get_moderation_record(resource_type, existing).await;
        }

        let row = match resource_type {
            v2::ModerationResourceType::Restriction => sqlx::query(
                "SELECT id, subject_type, subject_id, scope_type::text, scope_id, \
                 restriction_type, NULL::text AS infraction_type, status::text, reason, \
                 created_by, created_at, expires_at, version, NULL::uuid AS enforcement_restriction_id, \
                 source_report_id, 'RESTRICTION'::text AS resource_type, 'BLACKLIST'::text AS kind \
                 FROM trust_safety.restriction \
                 WHERE id = $1 AND scope_type = 'PLATFORM'::trust_safety.scope_type \
                   AND restriction_type = 'BLACKLIST' FOR UPDATE",
            )
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await?,
            v2::ModerationResourceType::Infraction => sqlx::query(
                "SELECT id, subject_type, subject_id, scope_type::text, scope_id, \
                 NULL::text AS restriction_type, infraction_type, status::text, reason, \
                 created_by, created_at, expires_at, version, enforcement_restriction_id, \
                 source_report_id, 'INFRACTION'::text AS resource_type, \
                 CASE WHEN infraction_type = 'WARNING' \
                      AND scope_type = 'LOBBY'::trust_safety.scope_type \
                   THEN 'LOBBY_WARNING' WHEN infraction_type = 'BAN' \
                      AND scope_type = 'PRODUCT'::trust_safety.scope_type \
                   THEN 'LOBBY_BAN' ELSE 'WARNING' END AS kind \
                 FROM trust_safety.infraction \
                 WHERE id = $1 AND (infraction_type = 'WARNING' \
                   OR (infraction_type = 'BAN' AND scope_type = 'PRODUCT'::trust_safety.scope_type)) \
                 FOR UPDATE",
            )
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await?,
            v2::ModerationResourceType::Unspecified => unreachable!(),
        };
        let target = moderation_link_target_from_row(&row, resource_type)?;
        anyhow::ensure!(
            target.version == expected_version,
            "moderation record version conflict"
        );

        let report = sqlx::query(
            "SELECT subject_type, subject_id, scope_type::text, scope_id \
             FROM trust_safety.report WHERE id = $1 FOR SHARE",
        )
        .bind(report_id)
        .fetch_one(&mut *tx)
        .await?;
        let report_subject_type: String = report.try_get("subject_type")?;
        let report_subject_id: String = report.try_get("subject_id")?;
        let report_scope_type: String = report.try_get("scope_type")?;
        let report_scope_id: String = report.try_get("scope_id")?;
        validate_moderation_record_report_link(
            &target,
            &report_subject_type,
            &report_subject_id,
            &report_scope_type,
            &report_scope_id,
        )?;

        let mut paired = Vec::new();
        match resource_type {
            v2::ModerationResourceType::Restriction => {
                let rows = sqlx::query(
                    "SELECT id, subject_type, subject_id, scope_type::text, scope_id, \
                     NULL::text AS restriction_type, infraction_type, status::text, reason, \
                     created_by, created_at, expires_at, version, enforcement_restriction_id, \
                     source_report_id, 'INFRACTION'::text AS resource_type, \
                     CASE WHEN infraction_type = 'WARNING' \
                          AND scope_type = 'LOBBY'::trust_safety.scope_type \
                       THEN 'LOBBY_WARNING' WHEN infraction_type = 'BAN' \
                          AND scope_type = 'PRODUCT'::trust_safety.scope_type \
                       THEN 'LOBBY_BAN' ELSE 'WARNING' END AS kind \
                     FROM trust_safety.infraction \
                     WHERE enforcement_restriction_id = $1 FOR UPDATE",
                )
                .bind(record_id)
                .fetch_all(&mut *tx)
                .await?;
                for row in rows {
                    paired.push(moderation_link_target_from_row(
                        &row,
                        v2::ModerationResourceType::Infraction,
                    )?);
                }
            }
            v2::ModerationResourceType::Infraction => {
                if let Some(enforcement_id) = target.enforcement_restriction_id
                    && let Some(row) = sqlx::query(
                        "SELECT id, subject_type, subject_id, scope_type::text, scope_id, \
                         restriction_type, NULL::text AS infraction_type, status::text, reason, \
                         created_by, created_at, expires_at, version, NULL::uuid AS enforcement_restriction_id, \
                         source_report_id, 'RESTRICTION'::text AS resource_type, 'BLACKLIST'::text AS kind \
                         FROM trust_safety.restriction WHERE id = $1 FOR UPDATE",
                    )
                    .bind(enforcement_id)
                    .fetch_optional(&mut *tx)
                    .await?
                {
                    paired.push(moderation_link_target_from_row(
                        &row,
                        v2::ModerationResourceType::Restriction,
                    )?);
                }
            }
            v2::ModerationResourceType::Unspecified => unreachable!(),
        }
        for pair in &paired {
            anyhow::ensure!(
                pair.subject_type == target.subject_type && pair.subject_id == target.subject_id,
                "paired enforcement resource subject must match moderation record subject"
            );
        }

        ensure_report_link_is_compatible(target.source_report_id, report_id, "record")?;
        for pair in &paired {
            ensure_report_link_is_compatible(pair.source_report_id, report_id, "paired resource")?;
        }

        if target.source_report_id.is_none() {
            let updated = match resource_type {
                v2::ModerationResourceType::Restriction => {
                    sqlx::query(
                        "UPDATE trust_safety.restriction SET source_report_id = $1, \
                     version = version + 1, updated_at = clock_timestamp() \
                     WHERE id = $2 AND version = $3 AND source_report_id IS NULL",
                    )
                    .bind(report_id)
                    .bind(target.id)
                    .bind(target.version)
                    .execute(&mut *tx)
                    .await?
                }
                v2::ModerationResourceType::Infraction => {
                    sqlx::query(
                        "UPDATE trust_safety.infraction SET source_report_id = $1, \
                     version = version + 1, updated_at = clock_timestamp() \
                     WHERE id = $2 AND version = $3 AND source_report_id IS NULL",
                    )
                    .bind(report_id)
                    .bind(target.id)
                    .bind(target.version)
                    .execute(&mut *tx)
                    .await?
                }
                v2::ModerationResourceType::Unspecified => unreachable!(),
            };
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "moderation record version conflict"
            );
            insert_audit(
                &mut tx,
                context,
                "LINK_MODERATION_RECORD_REPORT",
                resource_name,
                target.id,
            )
            .await?;
        }

        for pair in &paired {
            if pair.source_report_id.is_some() {
                continue;
            }
            let updated = match pair.resource_type {
                "RESTRICTION" => {
                    sqlx::query(
                        "UPDATE trust_safety.restriction SET source_report_id = $1, \
                         version = version + 1, updated_at = clock_timestamp() \
                         WHERE id = $2 AND version = $3 AND source_report_id IS NULL",
                    )
                    .bind(report_id)
                    .bind(pair.id)
                    .bind(pair.version)
                    .execute(&mut *tx)
                    .await?
                }
                "INFRACTION" => {
                    sqlx::query(
                        "UPDATE trust_safety.infraction SET source_report_id = $1, \
                         version = version + 1, updated_at = clock_timestamp() \
                         WHERE id = $2 AND version = $3 AND source_report_id IS NULL",
                    )
                    .bind(report_id)
                    .bind(pair.id)
                    .bind(pair.version)
                    .execute(&mut *tx)
                    .await?
                }
                _ => unreachable!(),
            };
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "paired enforcement resource version conflict"
            );
            insert_audit(
                &mut tx,
                context,
                "LINK_MODERATION_RECORD_REPORT",
                pair.resource_type,
                pair.id,
            )
            .await?;
        }
        tx.commit().await?;
        self.get_moderation_record(resource_type, record_id).await
    }

    pub async fn list_execution_traces(
        &self,
        scope: &v2::Scope,
        subject: Option<&v2::Subject>,
        decision: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<ExecutionTrace>> {
        let (subject_type, subject_id) = subject
            .map(|subject| primary_subject(subject, true))
            .transpose()?
            .map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let rows = sqlx::query(
            "SELECT trace.id, trace.trace FROM trust_safety.execution_trace trace \
             JOIN trust_safety.action_inbox inbox ON inbox.action_id = trace.action_id \
             WHERE inbox.scope_type = $1::trust_safety.scope_type AND inbox.scope_id = $2 \
               AND ($3::text IS NULL OR inbox.subject_type = $3) \
               AND ($4::text IS NULL OR inbox.subject_id = $4) \
               AND ($5::text IS NULL OR trace.final_decision = $5::trust_safety.decision) \
               AND ($6::uuid IS NULL OR trace.id < $6) \
             ORDER BY trace.id DESC LIMIT $7",
        )
        .bind(scope_name(scope.r#type)?)
        .bind(&scope.id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(decision)
        .bind(cursor)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        let next_cursor = page_cursor(&rows, limit, "id")?;
        let items = rows
            .into_iter()
            .map(|row| Ok(serde_json::from_value(row.try_get("trace")?)?))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_reports(
        &self,
        scope: Option<&v2::Scope>,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
        query: Option<&str>,
        reporter_id: Option<&str>,
        reported_user_id: Option<&str>,
        reported_server_id: Option<&str>,
        report_type: Option<&str>,
    ) -> anyhow::Result<Page<v2::Report>> {
        let query_pattern = query.map(|q| format!("%{q}%"));
        let rows = sqlx::query(
            "SELECT report.id, scope_type::text, scope_id, subject_type, subject_id, reporter_id, report_type, \
             description, status::text, context, report.created_at AS created_at, resolved_by, resolved_at, version, \
             claimed_by, claimed_at, claim_expires_at, last_claim_change_at, \
             evidence.lobby_id AS evidence_lobby_id, evidence.first_sequence, evidence.last_sequence, \
             evidence.entry_count, evidence.terminal_action_id \
             FROM trust_safety.report report LEFT JOIN trust_safety.report_evidence_snapshot evidence \
               ON evidence.report_id = report.id \
             WHERE ($1::text IS NULL OR scope_type = $1::trust_safety.scope_type) \
               AND ($2::text IS NULL OR scope_id = $2) \
               AND ($3::text IS NULL OR status = $3::trust_safety.resource_status) \
               AND ($4::uuid IS NULL OR report.id < $4) \
               AND ($5::text IS NULL OR (description ILIKE $5 OR reporter_id ILIKE $5 \
                    OR (context->>'reported_user_id') ILIKE $5 \
                    OR (context->>'reported_server_id') ILIKE $5)) \
               AND ($6::text IS NULL OR reporter_id = $6) \
               AND ($7::text IS NULL OR (context->>'reported_user_id') = $7) \
               AND ($8::text IS NULL OR (context->>'reported_server_id') = $8) \
               AND ($9::text IS NULL OR report_type = $9) \
               ORDER BY report.id DESC LIMIT $10",
        )
        .bind(scope.map(|scope| scope_name(scope.r#type)).transpose()?)
        .bind(scope.map(|scope| scope.id.as_str()))
        .bind(status)
        .bind(cursor)
        .bind(query_pattern.as_deref())
        .bind(reporter_id)
        .bind(reported_user_id)
        .bind(reported_server_id)
        .bind(report_type)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        let next_cursor = page_cursor(&rows, limit, "id")?;
        let items = rows
            .iter()
            .map(report_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }

    pub async fn create_report(
        &self,
        context: &v2::RequestContext,
        scope: &v2::Scope,
        subject: &v2::Subject,
        report_type: &str,
        description: &str,
        submission: ReportSubmissionData,
    ) -> anyhow::Result<v2::Report> {
        let scope_type = scope_name(scope.r#type)?;
        let (subject_type, subject_id) = primary_subject(subject, true)?;
        let report_type = report_type.trim();
        anyhow::ensure!(
            !report_type.is_empty() && report_type.len() <= 100,
            "report type must be between 1 and 100 characters"
        );
        anyhow::ensure!(
            description.len() <= 4000,
            "report description exceeds 4000 characters"
        );
        anyhow::ensure!(
            serde_json::to_vec(&submission.context)?.len() <= 65_536,
            "report context exceeds 64 KiB"
        );
        let id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "CREATE_REPORT", id).await?
        {
            tx.rollback().await?;
            return self.get_report(existing).await;
        }
        sqlx::query(
            "INSERT INTO trust_safety.report \
             (id, scope_type, scope_id, reporter_id, subject_type, subject_id, report_type, description, context) \
             VALUES ($1, $2::trust_safety.scope_type, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(&context.actor_id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(report_type)
        .bind(description.trim())
        .bind(submission.context)
        .execute(&mut *tx)
        .await?;
        if let Some(terminal_action_id) = submission.terminal_action_id {
            anyhow::ensure!(
                scope_type == "LOBBY",
                "call evidence is only valid for Lobby reports"
            );
            let terminal = sqlx::query(
                "SELECT event.sequence, inbox.action_type \
                 FROM trust_safety.call_evidence_event event \
                 JOIN trust_safety.action_inbox inbox ON inbox.action_id = event.action_id \
                 WHERE event.lobby_id = $1 AND event.action_id = $2",
            )
            .bind(&scope.id)
            .bind(terminal_action_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| anyhow::anyhow!("terminal call evidence is not available yet"))?;
            anyhow::ensure!(
                terminal.try_get::<String, _>("action_type")? == "lobby.call.ended",
                "terminal_action_id must reference CALL_ENDED"
            );
            let last_sequence: i64 = terminal.try_get("sequence")?;
            let bounds = sqlx::query(
                "SELECT MIN(sequence) AS first_sequence, COUNT(*) AS entry_count \
                 FROM trust_safety.call_evidence_event \
                 WHERE lobby_id = $1 AND sequence <= $2",
            )
            .bind(&scope.id)
            .bind(last_sequence)
            .fetch_one(&mut *tx)
            .await?;
            let first_sequence: i64 = bounds
                .try_get::<Option<i64>, _>("first_sequence")?
                .ok_or_else(|| anyhow::anyhow!("call evidence is empty"))?;
            let entry_count: i64 = bounds.try_get("entry_count")?;
            anyhow::ensure!(
                entry_count == last_sequence - first_sequence + 1,
                "call evidence has a sequence gap"
            );
            sqlx::query(
                "INSERT INTO trust_safety.report_evidence_snapshot \
                 (report_id, lobby_id, first_sequence, last_sequence, entry_count, terminal_action_id) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(id)
            .bind(&scope.id)
            .bind(first_sequence)
            .bind(last_sequence)
            .bind(entry_count)
            .bind(terminal_action_id)
            .execute(&mut *tx)
            .await?;
        }
        if matches!(subject_type, "USER" | "SERVER") {
            let (observation_id, assessment_id) = insert_derived_safety_observation_tx(
                &mut tx,
                subject_type,
                subject_id,
                scope_type,
                &scope.id,
                "REPORT_SUBMITTED",
                3.0,
                false,
                serde_json::json!({"report_id": id, "report_type": report_type}),
            )
            .await?;
            insert_audit(
                &mut tx,
                context,
                "DERIVE_SAFETY_OBSERVATION",
                "SAFETY_OBSERVATION",
                observation_id,
            )
            .await?;
            insert_audit(
                &mut tx,
                context,
                "RECALCULATE_SAFETY_ASSESSMENT",
                "SAFETY_ASSESSMENT",
                assessment_id,
            )
            .await?;
        }
        insert_audit(&mut tx, context, "CREATE_REPORT", "REPORT", id).await?;
        tx.commit().await?;
        self.get_report(id).await
    }

    pub async fn resolve_report(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        resolution: &str,
        expected_version: i64,
    ) -> anyhow::Result<v2::Report> {
        anyhow::ensure!(
            matches!(resolution, "RESOLVED" | "DISMISSED"),
            "invalid report resolution"
        );
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "RESOLVE_REPORT", id).await?
        {
            tx.rollback().await?;
            return self.get_report(existing).await;
        }
        let updated = sqlx::query(
            "UPDATE trust_safety.report SET status = $2::trust_safety.resource_status, resolution = $2, \
             resolved_by = $3, resolved_at = clock_timestamp(), version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $4 AND status = 'PENDING' \
               AND (scope_type='HUB' OR (claimed_by = $3 AND claim_expires_at > clock_timestamp())) \
             RETURNING subject_type, subject_id, scope_type::text, scope_id",
        ).bind(id).bind(resolution).bind(&context.actor_id).bind(expected_version).fetch_optional(&mut *tx).await?;
        let updated = updated.ok_or_else(|| anyhow::anyhow!("report version conflict"))?;
        let subject_type: String = updated.try_get("subject_type")?;
        if matches!(subject_type.as_str(), "USER" | "SERVER") {
            let (observation_id, assessment_id) = insert_derived_safety_observation_tx(
                &mut tx,
                &subject_type,
                updated.try_get("subject_id")?,
                updated.try_get("scope_type")?,
                updated.try_get("scope_id")?,
                if resolution == "RESOLVED" {
                    "REPORT_SUBSTANTIATED"
                } else {
                    "REPORT_DISMISSED"
                },
                if resolution == "RESOLVED" { 5.0 } else { 3.0 },
                resolution == "DISMISSED",
                serde_json::json!({"report_id": id}),
            )
            .await?;
            insert_audit(
                &mut tx,
                context,
                "DERIVE_SAFETY_OBSERVATION",
                "SAFETY_OBSERVATION",
                observation_id,
            )
            .await?;
            insert_audit(
                &mut tx,
                context,
                "RECALCULATE_SAFETY_ASSESSMENT",
                "SAFETY_ASSESSMENT",
                assessment_id,
            )
            .await?;
        }
        insert_audit(&mut tx, context, "RESOLVE_REPORT", "REPORT", id).await?;
        tx.commit().await?;
        self.get_report(id).await
    }

    pub async fn get_report(&self, id: Uuid) -> anyhow::Result<v2::Report> {
        let row = sqlx::query(
            "SELECT report.id, scope_type::text, scope_id, subject_type, subject_id, reporter_id, report_type, \
             description, status::text, context, report.created_at AS created_at, resolved_by, resolved_at, version, \
             claimed_by, claimed_at, claim_expires_at, last_claim_change_at, \
             evidence.lobby_id AS evidence_lobby_id, evidence.first_sequence, evidence.last_sequence, \
             evidence.entry_count, evidence.terminal_action_id \
             FROM trust_safety.report report LEFT JOIN trust_safety.report_evidence_snapshot evidence \
               ON evidence.report_id = report.id WHERE report.id = $1",
        ).bind(id).fetch_one(&self.db).await?;
        report_from_row(&row)
    }

    pub async fn list_report_evidence(
        &self,
        report_id: Uuid,
        after_sequence: Option<i64>,
        limit: i64,
    ) -> anyhow::Result<ReportEvidencePage> {
        let snapshot_row = sqlx::query(
            "SELECT lobby_id, first_sequence, last_sequence, entry_count, terminal_action_id \
             FROM trust_safety.report_evidence_snapshot WHERE report_id = $1",
        )
        .bind(report_id)
        .fetch_one(&self.db)
        .await?;
        let lobby_id: String = snapshot_row.try_get("lobby_id")?;
        let first_sequence: i64 = snapshot_row.try_get("first_sequence")?;
        let last_sequence: i64 = snapshot_row.try_get("last_sequence")?;
        let entry_count: i64 = snapshot_row.try_get("entry_count")?;
        let terminal_action_id: Uuid = snapshot_row.try_get("terminal_action_id")?;
        let rows = sqlx::query(
            "SELECT sequence, action_id FROM trust_safety.call_evidence_event \
             WHERE lobby_id = $1 AND sequence BETWEEN $2 AND $3 \
               AND ($4::bigint IS NULL OR sequence > $4) \
             ORDER BY sequence ASC LIMIT $5",
        )
        .bind(&lobby_id)
        .bind(first_sequence)
        .bind(last_sequence)
        .bind(after_sequence)
        .bind(limit.clamp(1, 100))
        .fetch_all(&self.db)
        .await?;
        let action_ids = rows
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("sequence")? as u64,
                    row.try_get("action_id")?,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let next_cursor = if action_ids.len() == limit.clamp(1, 100) as usize
            && action_ids
                .last()
                .is_some_and(|(sequence, _)| *sequence < last_sequence as u64)
        {
            action_ids
                .last()
                .map(|(sequence, _)| sequence.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(ReportEvidencePage {
            action_ids,
            next_cursor,
            snapshot: v2::ReportEvidenceSnapshot {
                lobby_id,
                first_sequence: first_sequence as u64,
                last_sequence: last_sequence as u64,
                entry_count: entry_count as u64,
                terminal_action_id: terminal_action_id.to_string(),
            },
        })
    }

    pub async fn claim_report(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        expected_version: i64,
        lease_seconds: i64,
        cooldown_seconds: i64,
        bypass_cooldown: bool,
    ) -> anyhow::Result<v2::Report> {
        let mut tx = self.db.begin().await?;
        let updated = sqlx::query("UPDATE trust_safety.report SET claimed_by=$2,claimed_at=clock_timestamp(),claim_expires_at=clock_timestamp()+make_interval(secs=>$3::double precision),last_claim_change_at=clock_timestamp(),updated_at=clock_timestamp(),version=version+1 WHERE id=$1 AND version=$4 AND status='PENDING' AND (claimed_by IS NULL OR claim_expires_at<=clock_timestamp()) AND ($5 OR last_claim_change_at IS NULL OR claim_expires_at<=clock_timestamp() OR last_claim_change_at<=clock_timestamp()-make_interval(secs=>$6::double precision)) RETURNING id")
            .bind(id).bind(&context.actor_id).bind(lease_seconds).bind(expected_version).bind(bypass_cooldown).bind(cooldown_seconds).fetch_optional(&mut *tx).await?;
        anyhow::ensure!(updated.is_some(), "report claim conflict");
        insert_audit(&mut tx, context, "CLAIM_REPORT", "REPORT", id).await?;
        tx.commit().await?;
        self.get_report(id).await
    }

    pub async fn renew_report_claim(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        expected_version: i64,
        lease_seconds: i64,
    ) -> anyhow::Result<v2::Report> {
        let mut tx = self.db.begin().await?;
        let updated=sqlx::query("UPDATE trust_safety.report SET claim_expires_at=clock_timestamp()+make_interval(secs=>$3::double precision),updated_at=clock_timestamp(),version=version+1 WHERE id=$1 AND version=$2 AND claimed_by=$4 AND claim_expires_at>clock_timestamp() AND updated_at<=clock_timestamp()-interval '5 minutes' RETURNING id")
            .bind(id).bind(expected_version).bind(lease_seconds).bind(&context.actor_id).fetch_optional(&mut *tx).await?;
        anyhow::ensure!(
            updated.is_some(),
            "report renewal conflict or renewal is too frequent"
        );
        insert_audit(&mut tx, context, "RENEW_REPORT_CLAIM", "REPORT", id).await?;
        tx.commit().await?;
        self.get_report(id).await
    }

    pub async fn unclaim_report(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        expected_version: i64,
    ) -> anyhow::Result<v2::Report> {
        let mut tx = self.db.begin().await?;
        let updated=sqlx::query("UPDATE trust_safety.report SET claimed_by=NULL,claimed_at=NULL,claim_expires_at=NULL,last_claim_change_at=clock_timestamp(),updated_at=clock_timestamp(),version=version+1 WHERE id=$1 AND version=$2 AND claimed_by=$3 AND claim_expires_at>clock_timestamp() RETURNING id").bind(id).bind(expected_version).bind(&context.actor_id).fetch_optional(&mut *tx).await?;
        anyhow::ensure!(
            updated.is_some(),
            "report claim ownership or version conflict"
        );
        sqlx::query("UPDATE trust_safety.staff_action_request SET status='CANCELLED',decided_by=$2,decision_reason='case unclaimed',decided_at=clock_timestamp(),version=version+1 WHERE report_id=$1 AND status='PENDING'").bind(id).bind(&context.actor_id).execute(&mut *tx).await?;
        insert_audit(&mut tx, context, "UNCLAIM_REPORT", "REPORT", id).await?;
        tx.commit().await?;
        self.get_report(id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn transfer_report(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        assignee: &str,
        expected_version: i64,
        lease_seconds: i64,
        cooldown_seconds: i64,
        require_unclaimed: bool,
        bypass_cooldown: bool,
    ) -> anyhow::Result<v2::Report> {
        let mut tx = self.db.begin().await?;
        let updated=sqlx::query("UPDATE trust_safety.report SET claimed_by=$2,claimed_at=clock_timestamp(),claim_expires_at=clock_timestamp()+make_interval(secs=>$3::double precision),last_claim_change_at=clock_timestamp(),updated_at=clock_timestamp(),version=version+1 WHERE id=$1 AND version=$4 AND status='PENDING' AND (NOT $5 OR claimed_by IS NULL OR claim_expires_at<=clock_timestamp()) AND ($6 OR last_claim_change_at IS NULL OR last_claim_change_at<=clock_timestamp()-make_interval(secs=>$7::double precision)) RETURNING id").bind(id).bind(assignee).bind(lease_seconds).bind(expected_version).bind(require_unclaimed).bind(bypass_cooldown).bind(cooldown_seconds).fetch_optional(&mut *tx).await?;
        anyhow::ensure!(updated.is_some(), "report assignment or version conflict");
        sqlx::query("UPDATE trust_safety.staff_action_request SET status='CANCELLED',decided_by=$2,decision_reason='case ownership changed',decided_at=clock_timestamp(),version=version+1 WHERE report_id=$1 AND status='PENDING' AND requested_by<>$3").bind(id).bind(&context.actor_id).bind(assignee).execute(&mut *tx).await?;
        insert_audit(
            &mut tx,
            context,
            if require_unclaimed {
                "ASSIGN_REPORT"
            } else {
                "TRANSFER_REPORT"
            },
            "REPORT",
            id,
        )
        .await?;
        tx.commit().await?;
        self.get_report(id).await
    }

    pub async fn get_staff_action_request(
        &self,
        id: Uuid,
    ) -> anyhow::Result<v2::StaffActionRequest> {
        let row=sqlx::query("SELECT id,action_type,subject_type,subject_id,scope_type::text,scope_id,report_id,requested_reason,requested_expires_at,requested_by,requested_at,status,decided_by,decision_reason,decided_at,executed_infraction_id,executed_restriction_id,expires_at,version FROM trust_safety.staff_action_request WHERE id=$1").bind(id).fetch_one(&self.db).await?;
        staff_action_request_from_row(&row)
    }
    pub async fn list_staff_action_requests(
        &self,
        status: Option<&str>,
        requested_by: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<v2::StaffActionRequest>> {
        let rows=sqlx::query("SELECT id,action_type,subject_type,subject_id,scope_type::text,scope_id,report_id,requested_reason,requested_expires_at,requested_by,requested_at,status,decided_by,decision_reason,decided_at,executed_infraction_id,executed_restriction_id,expires_at,version FROM trust_safety.staff_action_request WHERE ($1::text IS NULL OR status=$1) AND ($2::text IS NULL OR requested_by=$2) ORDER BY requested_at DESC LIMIT $3").bind(status).bind(requested_by).bind(limit).fetch_all(&self.db).await?;
        rows.iter().map(staff_action_request_from_row).collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn create_staff_action_request(
        &self,
        context: &v2::RequestContext,
        action_type: &str,
        subject_type: &str,
        subject_id: &str,
        scope_type: &str,
        scope_id: &str,
        report_id: Option<Uuid>,
        reason: &str,
        requested_expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<v2::StaffActionRequest> {
        let id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "CREATE_STAFF_ACTION_REQUEST", id).await?
        {
            tx.rollback().await?;
            return self.get_staff_action_request(existing).await;
        }
        if let Some(report_id) = report_id {
            let live_owner = sqlx::query(
                "SELECT id FROM trust_safety.report
                 WHERE id=$1 AND status='PENDING' AND claimed_by=$2
                   AND claim_expires_at>clock_timestamp() FOR UPDATE",
            )
            .bind(report_id)
            .bind(&context.actor_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            anyhow::ensure!(live_owner, "action request requires a live report claim");
        }
        sqlx::query("INSERT INTO trust_safety.staff_action_request(id,action_type,subject_type,subject_id,scope_type,scope_id,report_id,requested_reason,requested_expires_at,requested_by) VALUES($1,$2,$3,$4,$5::trust_safety.scope_type,$6,$7,$8,$9,$10)").bind(id).bind(action_type).bind(subject_type).bind(subject_id).bind(scope_type).bind(scope_id).bind(report_id).bind(reason).bind(requested_expires_at).bind(&context.actor_id).execute(&mut *tx).await?;
        insert_audit(
            &mut tx,
            context,
            "CREATE_STAFF_ACTION_REQUEST",
            "STAFF_ACTION_REQUEST",
            id,
        )
        .await?;
        tx.commit().await?;
        self.get_staff_action_request(id).await
    }
    pub async fn resolve_staff_action_request(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        approve: bool,
        reason: &str,
        expected_version: i64,
    ) -> anyhow::Result<v2::StaffActionRequest> {
        let mut tx = self.db.begin().await?;
        let row=sqlx::query("SELECT requested_by,expires_at,action_type,subject_type,subject_id,scope_type::text,scope_id,report_id,requested_reason,requested_expires_at FROM trust_safety.staff_action_request WHERE id=$1 AND status='PENDING' AND version=$2 FOR UPDATE").bind(id).bind(expected_version).fetch_optional(&mut *tx).await?.ok_or_else(||anyhow::anyhow!("action request version conflict or no longer pending"))?;
        let requester: String = row.try_get("requested_by")?;
        let expires: DateTime<Utc> = row.try_get("expires_at")?;
        anyhow::ensure!(
            requester != context.actor_id,
            "requester cannot approve their own action"
        );
        anyhow::ensure!(expires > Utc::now(), "action request expired");
        let report_id: Option<Uuid> = row.try_get("report_id")?;
        if let Some(report_id) = report_id {
            let live_owner = sqlx::query(
                "SELECT id FROM trust_safety.report WHERE id=$1 AND status='PENDING'
                 AND claimed_by=$2 AND claim_expires_at>clock_timestamp() FOR UPDATE",
            )
            .bind(report_id)
            .bind(&requester)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            anyhow::ensure!(live_owner, "requester no longer owns a live report claim");
        }
        let mut executed_infraction_id = None;
        let mut executed_restriction_id = None;
        if approve {
            let action_type: &str = row.try_get("action_type")?;
            let subject_type: &str = row.try_get("subject_type")?;
            let subject_id: &str = row.try_get("subject_id")?;
            let scope_type: &str = row.try_get("scope_type")?;
            let scope_id: &str = row.try_get("scope_id")?;
            let requested_reason: &str = row.try_get("requested_reason")?;
            let requested_expires_at: Option<DateTime<Utc>> =
                row.try_get("requested_expires_at")?;
            let restriction_id = Uuid::now_v7();
            sqlx::query("INSERT INTO trust_safety.restriction(id,subject_type,subject_id,scope_type,scope_id,restriction_type,reason,created_by,expires_at,source_report_id) VALUES($1,$2,$3,$4::trust_safety.scope_type,$5,$6,$7,$8,$9,$10)")
                .bind(restriction_id).bind(subject_type).bind(subject_id).bind(scope_type).bind(scope_id)
                .bind(if action_type=="GLOBAL_BLACKLIST"{"BLACKLIST"}else{"BAN"}).bind(requested_reason).bind(&requester).bind(requested_expires_at).bind(report_id).execute(&mut *tx).await?;
            let infraction_id = Uuid::now_v7();
            sqlx::query("INSERT INTO trust_safety.infraction(id,subject_type,subject_id,scope_type,scope_id,infraction_type,reason,created_by,expires_at,enforcement_restriction_id,source_report_id) VALUES($1,$2,$3,$4::trust_safety.scope_type,$5,'BAN',$6,$7,$8,$9,$10)")
                .bind(infraction_id).bind(subject_type).bind(subject_id).bind(scope_type).bind(scope_id).bind(requested_reason).bind(&requester).bind(requested_expires_at).bind(restriction_id).bind(report_id).execute(&mut *tx).await?;
            insert_audit(
                &mut tx,
                context,
                "CREATE_APPROVED_ENFORCEMENT_RESTRICTION",
                "RESTRICTION",
                restriction_id,
            )
            .await?;
            insert_audit(
                &mut tx,
                context,
                "CREATE_APPROVED_INFRACTION",
                "INFRACTION",
                infraction_id,
            )
            .await?;
            if subject_type == "USER" {
                let notice_scope = scope_from_parts(scope_type.to_owned(), scope_id.to_owned())?;
                self.insert_manual_moderation_notice(
                    &mut tx,
                    infraction_id,
                    subject_id,
                    &notice_scope,
                    "BAN",
                    requested_reason,
                    requested_expires_at,
                    Some(restriction_id),
                )
                .await?;
            }
            executed_infraction_id = Some(infraction_id);
            executed_restriction_id = Some(restriction_id);
        }
        sqlx::query("UPDATE trust_safety.staff_action_request SET status=$2,decided_by=$3,decision_reason=$4,decided_at=clock_timestamp(),executed_infraction_id=$5,executed_restriction_id=$6,version=version+1 WHERE id=$1").bind(id).bind(if approve{"EXECUTED"}else{"REJECTED"}).bind(&context.actor_id).bind(reason).bind(executed_infraction_id).bind(executed_restriction_id).execute(&mut *tx).await?;
        insert_audit(
            &mut tx,
            context,
            if approve {
                "APPROVE_STAFF_ACTION_REQUEST"
            } else {
                "REJECT_STAFF_ACTION_REQUEST"
            },
            "STAFF_ACTION_REQUEST",
            id,
        )
        .await?;
        tx.commit().await?;
        self.get_staff_action_request(id).await
    }

    pub async fn list_appeals(
        &self,
        scope: &v2::Scope,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<v2::Appeal>> {
        let rows = sqlx::query(
            "SELECT appeal.id, appeal.infraction_id, appeal.appellant_id, appeal.reason, appeal.status::text, \
             appeal.resolution, appeal.created_at, appeal.resolved_at, appeal.version \
             FROM trust_safety.appeal appeal JOIN trust_safety.infraction infraction ON infraction.id = appeal.infraction_id \
             WHERE infraction.scope_type = $1::trust_safety.scope_type AND infraction.scope_id = $2 \
             AND ($3::text IS NULL OR appeal.status = $3::trust_safety.resource_status) \
             AND ($4::uuid IS NULL OR appeal.id < $4) ORDER BY appeal.id DESC LIMIT $5",
        ).bind(scope_name(scope.r#type)?).bind(&scope.id).bind(status).bind(cursor).bind(limit.clamp(1, 100)).fetch_all(&self.db).await?;
        let next_cursor = page_cursor(&rows, limit, "id")?;
        let items = rows
            .iter()
            .map(appeal_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }

    pub async fn create_appeal(
        &self,
        context: &v2::RequestContext,
        infraction_id: Uuid,
        reason: &str,
        evidence: serde_json::Value,
    ) -> anyhow::Result<v2::Appeal> {
        let reason = reason.trim();
        anyhow::ensure!(
            !reason.is_empty() && reason.len() <= 4000,
            "appeal reason must be between 1 and 4000 characters"
        );
        anyhow::ensure!(
            serde_json::to_vec(&evidence)?.len() <= 65_536,
            "appeal evidence exceeds 64 KiB"
        );
        let id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "CREATE_APPEAL", id).await?
        {
            tx.rollback().await?;
            return self.get_appeal(existing).await;
        }
        let infraction = sqlx::query(
            "SELECT subject_type, subject_id, status::text FROM trust_safety.infraction \
             WHERE id = $1 FOR SHARE",
        )
        .bind(infraction_id)
        .fetch_one(&mut *tx)
        .await?;
        let subject_type: String = infraction.try_get("subject_type")?;
        let subject_id: String = infraction.try_get("subject_id")?;
        let status: String = infraction.try_get("status")?;
        anyhow::ensure!(
            subject_type == "USER" && subject_id == context.actor_id,
            "only the affected user may appeal this infraction"
        );
        anyhow::ensure!(
            status == "ACTIVE",
            "only active infractions may be appealed"
        );
        sqlx::query(
            "INSERT INTO trust_safety.appeal (id, infraction_id, appellant_id, reason, evidence) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(infraction_id)
        .bind(&context.actor_id)
        .bind(reason)
        .bind(evidence)
        .execute(&mut *tx)
        .await?;
        insert_audit(&mut tx, context, "CREATE_APPEAL", "APPEAL", id).await?;
        tx.commit().await?;
        self.get_appeal(id).await
    }

    pub async fn resolve_appeal(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        resolution: &str,
        response: &str,
        expected_version: i64,
    ) -> anyhow::Result<v2::Appeal> {
        anyhow::ensure!(
            matches!(resolution, "RESOLVED" | "DISMISSED"),
            "invalid appeal resolution"
        );
        anyhow::ensure!(!response.trim().is_empty(), "appeal response is required");
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "RESOLVE_APPEAL", id).await?
        {
            tx.rollback().await?;
            return self.get_appeal(existing).await;
        }
        let updated = sqlx::query(
            "UPDATE trust_safety.appeal SET status = $2::trust_safety.resource_status, resolution = $3, \
             resolved_by = $4, resolved_at = clock_timestamp(), version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $5 AND status = 'PENDING' RETURNING infraction_id",
        ).bind(id).bind(resolution).bind(response.trim()).bind(&context.actor_id).bind(expected_version)
        .fetch_optional(&mut *tx).await?;
        let updated = updated.ok_or_else(|| anyhow::anyhow!("appeal version conflict"))?;
        if resolution == "RESOLVED" {
            let infraction_id: Uuid = updated.try_get("infraction_id")?;
            let infraction = sqlx::query(
                "UPDATE trust_safety.infraction SET status = 'REVOKED', revoked_by = $2, revoked_reason = $3, \
                 version = version + 1, updated_at = clock_timestamp() WHERE id = $1 AND status = 'ACTIVE' \
                 RETURNING enforcement_restriction_id, subject_type, subject_id, scope_type::text, scope_id, infraction_type",
            )
            .bind(infraction_id)
            .bind(&context.actor_id)
            .bind(format!("Appeal accepted: {}", response.trim()))
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(infraction) = infraction {
                if let Some(restriction_id) =
                    infraction.try_get::<Option<Uuid>, _>("enforcement_restriction_id")?
                {
                    let restriction = sqlx::query(
                        "UPDATE trust_safety.restriction SET status = 'REVOKED', revoked_by = $2, \
                         revoked_reason = $3, version = version + 1, updated_at = clock_timestamp() \
                         WHERE id = $1 AND status = 'ACTIVE'",
                    )
                    .bind(restriction_id)
                    .bind(&context.actor_id)
                    .bind(format!("Appeal accepted: {}", response.trim()))
                    .execute(&mut *tx)
                    .await?;
                    if restriction.rows_affected() == 1 {
                        insert_audit(
                            &mut tx,
                            context,
                            "REVOKE_RESTRICTION_FROM_APPEAL",
                            "RESTRICTION",
                            restriction_id,
                        )
                        .await?;
                    }
                }
                let infraction_type: String = infraction.try_get("infraction_type")?;
                let signal_value = match infraction_type.as_str() {
                    "WARNING" => 5.0,
                    "MUTE" => 15.0,
                    "BAN" => 30.0,
                    "CONTENT" => 10.0,
                    _ => 0.0,
                };
                let (observation_id, assessment_id) = insert_derived_safety_observation_tx(
                    &mut tx,
                    infraction.try_get("subject_type")?,
                    infraction.try_get("subject_id")?,
                    infraction.try_get("scope_type")?,
                    infraction.try_get("scope_id")?,
                    "APPEAL_ACCEPTED",
                    signal_value,
                    true,
                    serde_json::json!({"appeal_id": id, "infraction_id": infraction_id}),
                )
                .await?;
                insert_audit(
                    &mut tx,
                    context,
                    "DERIVE_SAFETY_OBSERVATION",
                    "SAFETY_OBSERVATION",
                    observation_id,
                )
                .await?;
                insert_audit(
                    &mut tx,
                    context,
                    "RECALCULATE_SAFETY_ASSESSMENT",
                    "SAFETY_ASSESSMENT",
                    assessment_id,
                )
                .await?;
                insert_audit(
                    &mut tx,
                    context,
                    "REVOKE_INFRACTION_FROM_APPEAL",
                    "INFRACTION",
                    infraction_id,
                )
                .await?;
            }
        }
        insert_audit(&mut tx, context, "RESOLVE_APPEAL", "APPEAL", id).await?;
        tx.commit().await?;
        self.get_appeal(id).await
    }

    pub async fn appeal_scope(&self, id: Uuid) -> anyhow::Result<v2::Scope> {
        let row = sqlx::query(
            "SELECT infraction.scope_type::text, infraction.scope_id FROM trust_safety.appeal appeal \
             JOIN trust_safety.infraction infraction ON infraction.id = appeal.infraction_id WHERE appeal.id = $1",
        ).bind(id).fetch_one(&self.db).await?;
        scope_from_parts(row.try_get("scope_type")?, row.try_get("scope_id")?)
    }

    pub async fn get_appeal(&self, id: Uuid) -> anyhow::Result<v2::Appeal> {
        let row = sqlx::query(
            "SELECT id, infraction_id, appellant_id, reason, status::text, resolution, created_at, resolved_at, version \
             FROM trust_safety.appeal WHERE id = $1",
        ).bind(id).fetch_one(&self.db).await?;
        appeal_from_row(&row)
    }

    pub async fn list_review_items(
        &self,
        scope: &v2::Scope,
        queue: Option<&str>,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<v2::ReviewItem>> {
        let rows = sqlx::query(
            "SELECT id, queue, scope_type::text, scope_id, subject_type, subject_id, priority, status::text, \
             reason_codes, decision_id, assigned_to, created_at, version FROM trust_safety.review_item \
             WHERE scope_type = $1::trust_safety.scope_type AND scope_id = $2 \
             AND ($3::text IS NULL OR queue = $3) AND ($4::text IS NULL OR status = $4::trust_safety.resource_status) \
             AND ($5::uuid IS NULL OR id < $5) ORDER BY priority ASC, id DESC LIMIT $6",
        ).bind(scope_name(scope.r#type)?).bind(&scope.id).bind(queue).bind(status).bind(cursor)
        .bind(limit.clamp(1, 100)).fetch_all(&self.db).await?;
        let next_cursor = page_cursor(&rows, limit, "id")?;
        let items = rows
            .iter()
            .map(review_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }

    pub async fn get_review_item(&self, id: Uuid) -> anyhow::Result<v2::ReviewItem> {
        let row = sqlx::query(
            "SELECT id, queue, scope_type::text, scope_id, subject_type, subject_id, priority, status::text, \
             reason_codes, decision_id, assigned_to, created_at, version FROM trust_safety.review_item WHERE id = $1",
        ).bind(id).fetch_one(&self.db).await?;
        review_from_row(&row)
    }

    pub async fn resolve_review_item(
        &self,
        context: &v2::RequestContext,
        id: Uuid,
        resolution: &str,
        expected_version: i64,
    ) -> anyhow::Result<v2::ReviewItem> {
        anyhow::ensure!(
            matches!(resolution, "RESOLVED" | "DISMISSED"),
            "invalid review resolution"
        );
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "RESOLVE_REVIEW_ITEM", id).await?
        {
            tx.rollback().await?;
            return self.get_review_item(existing).await;
        }
        let updated = sqlx::query(
            "UPDATE trust_safety.review_item SET status = $2::trust_safety.resource_status, resolution = $2, \
             resolved_by = $3, version = version + 1, updated_at = clock_timestamp() \
             WHERE id = $1 AND version = $4 AND status = 'PENDING'",
        ).bind(id).bind(resolution).bind(&context.actor_id).bind(expected_version).execute(&mut *tx).await?;
        anyhow::ensure!(updated.rows_affected() == 1, "review item version conflict");
        insert_audit(&mut tx, context, "RESOLVE_REVIEW_ITEM", "REVIEW_ITEM", id).await?;
        tx.commit().await?;
        self.get_review_item(id).await
    }

    pub async fn record_safety_observation(
        &self,
        context: &v2::RequestContext,
        scope: &v2::Scope,
        subject: &v2::Subject,
        signal: v2::SafetySignal,
        metadata: serde_json::Value,
    ) -> anyhow::Result<v2::SafetyAssessment> {
        let (subject_type, subject_id) = primary_subject(subject, false)?;
        let scope_type = scope_name(scope.r#type)?;
        let signal_type = signal.r#type.trim().to_uppercase();
        anyhow::ensure!(
            !signal_type.is_empty() && signal_type.len() <= 100,
            "signal type must be between 1 and 100 characters"
        );
        anyhow::ensure!(
            signal.value.is_finite() && (0.0..=100.0).contains(&signal.value),
            "signal value must be between 0 and 100"
        );
        anyhow::ensure!(
            signal.confidence.is_finite() && (0.0..=1.0).contains(&signal.confidence),
            "signal confidence must be between 0 and 1"
        );
        anyhow::ensure!(
            signal.weight.is_finite() && (0.0..=10.0).contains(&signal.weight),
            "signal weight must be between 0 and 10"
        );
        anyhow::ensure!(
            serde_json::to_vec(&metadata)?.len() <= 16_384,
            "signal metadata exceeds 16 KiB"
        );
        let observed_at = signal
            .observed_at
            .map(datetime)
            .transpose()?
            .unwrap_or_else(Utc::now);
        anyhow::ensure!(
            observed_at <= Utc::now() + chrono::Duration::minutes(5),
            "signal observation time is too far in the future"
        );
        let expires_at = signal.expires_at.map(datetime).transpose()?;
        anyhow::ensure!(
            expires_at.is_none_or(|expiry| expiry > observed_at),
            "signal expiry must be after its observation time"
        );
        let source_action_id = (!signal.source_action_id.is_empty())
            .then(|| Uuid::parse_str(&signal.source_action_id))
            .transpose()?;
        let observation_id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(_) = claim_idempotency(
            &mut tx,
            context,
            "RECORD_SAFETY_OBSERVATION",
            observation_id,
        )
        .await?
        {
            tx.rollback().await?;
            return self.get_safety_assessment(scope, subject).await;
        }
        sqlx::query(
            "INSERT INTO trust_safety.safety_observation \
             (id, subject_type, subject_id, scope_type, scope_id, signal_type, value, confidence, weight, \
              mitigating, source_action_id, metadata, observed_at, expires_at) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(observation_id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(signal_type)
        .bind(signal.value)
        .bind(signal.confidence)
        .bind(signal.weight)
        .bind(signal.mitigating)
        .bind(source_action_id)
        .bind(metadata)
        .bind(observed_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        let assessment_id = recalculate_safety_assessment_tx(
            &mut tx,
            subject_type,
            subject_id,
            scope_type,
            &scope.id,
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "RECORD_SAFETY_OBSERVATION",
            "SAFETY_OBSERVATION",
            observation_id,
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "RECALCULATE_SAFETY_ASSESSMENT",
            "SAFETY_ASSESSMENT",
            assessment_id,
        )
        .await?;
        tx.commit().await?;
        self.get_safety_assessment(scope, subject).await
    }

    pub async fn recalculate_safety_assessment(
        &self,
        context: &v2::RequestContext,
        scope: &v2::Scope,
        subject: &v2::Subject,
    ) -> anyhow::Result<v2::SafetyAssessment> {
        let (subject_type, subject_id) = primary_subject(subject, false)?;
        let scope_type = scope_name(scope.r#type)?;
        let operation_id = Uuid::now_v7();
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(_) = claim_idempotency(
            &mut tx,
            context,
            "RECALCULATE_SAFETY_ASSESSMENT",
            operation_id,
        )
        .await?
        {
            tx.rollback().await?;
            return self.get_safety_assessment(scope, subject).await;
        }
        let assessment_id = recalculate_safety_assessment_tx(
            &mut tx,
            subject_type,
            subject_id,
            scope_type,
            &scope.id,
        )
        .await?;
        insert_audit(
            &mut tx,
            context,
            "RECALCULATE_SAFETY_ASSESSMENT",
            "SAFETY_ASSESSMENT",
            assessment_id,
        )
        .await?;
        tx.commit().await?;
        self.get_safety_assessment(scope, subject).await
    }

    pub async fn get_safety_assessment(
        &self,
        scope: &v2::Scope,
        subject: &v2::Subject,
    ) -> anyhow::Result<v2::SafetyAssessment> {
        let (subject_type, subject_id) = primary_subject(subject, false)?;
        let scope_type = scope_name(scope.r#type)?;
        let assessment = sqlx::query(
            "SELECT id, score, tier, assessed_at, algorithm_version, version FROM trust_safety.safety_assessment \
             WHERE subject_type = $1 AND subject_id = $2 AND scope_type = $3::trust_safety.scope_type AND scope_id = $4",
        ).bind(subject_type).bind(subject_id).bind(scope_type).bind(&scope.id).fetch_one(&self.db).await?;
        let observations = sqlx::query(
            "SELECT id, signal_type, value, confidence, weight, mitigating, source_action_id, metadata, observed_at, expires_at \
             FROM trust_safety.safety_observation WHERE subject_type = $1 AND subject_id = $2 \
             AND scope_type = $3::trust_safety.scope_type AND scope_id = $4 \
             AND (expires_at IS NULL OR expires_at > clock_timestamp()) ORDER BY observed_at DESC",
        ).bind(subject_type).bind(subject_id).bind(scope_type).bind(&scope.id).fetch_all(&self.db).await?;
        Ok(v2::SafetyAssessment {
            id: assessment.try_get::<Uuid, _>("id")?.to_string(),
            subject: Some(subject.clone()),
            score: assessment.try_get("score")?,
            tier: assessment.try_get("tier")?,
            signals: observations
                .into_iter()
                .map(|row| {
                    Ok(v2::SafetySignal {
                        id: row.try_get::<Uuid, _>("id")?.to_string(),
                        r#type: row.try_get("signal_type")?,
                        value: row.try_get("value")?,
                        confidence: row.try_get("confidence")?,
                        weight: row.try_get("weight")?,
                        mitigating: row.try_get("mitigating")?,
                        observed_at: Some(timestamp(row.try_get("observed_at")?)),
                        expires_at: row
                            .try_get::<Option<DateTime<Utc>>, _>("expires_at")?
                            .map(timestamp),
                        source_action_id: row
                            .try_get::<Option<Uuid>, _>("source_action_id")?
                            .map(|id| id.to_string())
                            .unwrap_or_default(),
                        metadata: Some(json_to_struct(&row.try_get("metadata")?)),
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
            assessed_at: Some(timestamp(assessment.try_get("assessed_at")?)),
            algorithm_version: assessment.try_get("algorithm_version")?,
            version: assessment.try_get::<i64, _>("version")? as u64,
            scope: Some(scope.clone()),
        })
    }

    pub async fn moderation_statistics(
        &self,
        scope: &v2::Scope,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> anyhow::Result<v2::ModerationStatistics> {
        anyhow::ensure!(from < to, "statistics range is invalid");
        let row = sqlx::query(
            "SELECT COUNT(*) AS evaluated_actions, \
             COUNT(*) FILTER (WHERE decision.decision = 'ALLOW') AS allowed, \
             COUNT(*) FILTER (WHERE decision.decision = 'CENSOR') AS censored, \
             COUNT(*) FILTER (WHERE decision.decision = 'HOLD') AS held, \
             COUNT(*) FILTER (WHERE decision.decision = 'BLOCK') AS blocked \
             FROM trust_safety.decision_record decision JOIN trust_safety.action_inbox inbox ON inbox.action_id = decision.action_id \
             WHERE inbox.scope_type = $1::trust_safety.scope_type AND inbox.scope_id = $2 \
             AND decision.decided_at >= $3 AND decision.decided_at < $4 AND decision.shadow = FALSE",
        ).bind(scope_name(scope.r#type)?).bind(&scope.id).bind(from).bind(to).fetch_one(&self.db).await?;
        let review_items: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM trust_safety.review_item WHERE scope_type = $1::trust_safety.scope_type \
             AND scope_id = $2 AND created_at >= $3 AND created_at < $4",
        ).bind(scope_name(scope.r#type)?).bind(&scope.id).bind(from).bind(to).fetch_one(&self.db).await?;
        let reasons = sqlx::query(
            "SELECT reason, COUNT(*) AS count FROM trust_safety.decision_record decision \
             JOIN trust_safety.action_inbox inbox ON inbox.action_id = decision.action_id, \
             LATERAL unnest(decision.reason_codes) AS reason \
             WHERE inbox.scope_type = $1::trust_safety.scope_type AND inbox.scope_id = $2 \
             AND decision.decided_at >= $3 AND decision.decided_at < $4 AND decision.shadow = FALSE GROUP BY reason",
        ).bind(scope_name(scope.r#type)?).bind(&scope.id).bind(from).bind(to).fetch_all(&self.db).await?;
        Ok(v2::ModerationStatistics {
            evaluated_actions: row.try_get::<i64, _>("evaluated_actions")? as u64,
            allowed: row.try_get::<i64, _>("allowed")? as u64,
            censored: row.try_get::<i64, _>("censored")? as u64,
            held: row.try_get::<i64, _>("held")? as u64,
            blocked: row.try_get::<i64, _>("blocked")? as u64,
            review_items: review_items as u64,
            reason_counts: reasons
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get("reason")?,
                        row.try_get::<i64, _>("count")? as u64,
                    ))
                })
                .collect::<anyhow::Result<_>>()?,
        })
    }

    pub async fn get_restriction(&self, id: Uuid) -> anyhow::Result<v2::Restriction> {
        let row = sqlx::query(
            "SELECT id, subject_type, subject_id, scope_type::text, scope_id, restriction_type, \
             status::text, reason, created_by, created_at, expires_at, version, source_report_id \
             FROM trust_safety.restriction WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?;
        restriction_from_row(&row)
    }

    pub async fn get_infraction(&self, id: Uuid) -> anyhow::Result<v2::Infraction> {
        let row = sqlx::query(
            "SELECT id, subject_type, subject_id, scope_type::text, scope_id, infraction_type, \
             status::text, reason, created_by, created_at, expires_at, version, enforcement_restriction_id, source_report_id \
             FROM trust_safety.infraction WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await?;
        infraction_from_row(&row)
    }
}

async fn recalculate_safety_assessment_tx(
    tx: &mut Transaction<'_, Postgres>,
    subject_type: &str,
    subject_id: &str,
    scope_type: &str,
    scope_id: &str,
) -> anyhow::Result<Uuid> {
    let lock_key = format!("{subject_type}:{subject_id}:{scope_type}:{scope_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **tx)
        .await?;
    let observations = sqlx::query(
        "SELECT signal_type, value, confidence, weight, mitigating \
         FROM trust_safety.safety_observation WHERE subject_type = $1 AND subject_id = $2 \
         AND scope_type = $3::trust_safety.scope_type AND scope_id = $4 \
         AND (expires_at IS NULL OR expires_at > clock_timestamp())",
    )
    .bind(subject_type)
    .bind(subject_id)
    .bind(scope_type)
    .bind(scope_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut contributions = Vec::with_capacity(observations.len());
    for observation in observations {
        let signal_type: String = observation.try_get("signal_type")?;
        let value: f64 = observation.try_get("value")?;
        let confidence: f64 = observation.try_get("confidence")?;
        let weight: f64 = observation.try_get("weight")?;
        let mitigating: bool = observation.try_get("mitigating")?;
        contributions.push((signal_type, value, confidence, weight, mitigating));
    }
    let (score, tier, breakdown) = calculate_safety_score(contributions);
    let breakdown = serde_json::Value::Object(
        breakdown
            .into_iter()
            .map(|(signal_type, (count, contribution))| {
                (
                    signal_type,
                    serde_json::json!({
                        "count": count,
                        "contribution": contribution,
                    }),
                )
            })
            .collect(),
    );
    let assessment_id: Uuid = sqlx::query_scalar(
        "INSERT INTO trust_safety.safety_assessment \
         (subject_type, subject_id, scope_type, scope_id, score, tier, signal_breakdown, algorithm_version) \
         VALUES ($1, $2, $3::trust_safety.scope_type, $4, $5, $6, $7, 'risk-weighted-v1') \
         ON CONFLICT (subject_type, subject_id, scope_type, scope_id) DO UPDATE SET \
           score = EXCLUDED.score, tier = EXCLUDED.tier, signal_breakdown = EXCLUDED.signal_breakdown, \
           algorithm_version = EXCLUDED.algorithm_version, assessed_at = clock_timestamp(), \
           version = trust_safety.safety_assessment.version + 1 RETURNING id",
    )
    .bind(subject_type)
    .bind(subject_id)
    .bind(scope_type)
    .bind(scope_id)
    .bind(score)
    .bind(tier)
    .bind(breakdown)
    .fetch_one(&mut **tx)
    .await?;
    Ok(assessment_id)
}

fn calculate_safety_score(
    observations: impl IntoIterator<Item = (String, f64, f64, f64, bool)>,
) -> (f64, &'static str, BTreeMap<String, (usize, f64)>) {
    let mut breakdown: BTreeMap<String, (usize, f64)> = BTreeMap::new();
    let mut score = 0.0_f64;
    for (signal_type, value, confidence, weight, mitigating) in observations {
        let contribution = value * confidence * weight * if mitigating { -1.0 } else { 1.0 };
        score += contribution;
        let aggregate = breakdown.entry(signal_type).or_default();
        aggregate.0 += 1;
        aggregate.1 += contribution;
    }
    let score = score.clamp(0.0, 100.0);
    let tier = if score >= 60.0 {
        "HIGH_RISK"
    } else if score >= 30.0 {
        "MEDIUM_RISK"
    } else if score >= 10.0 {
        "LOW_RISK"
    } else {
        "SAFE"
    };
    (score, tier, breakdown)
}

// These fields form the durable observation identity and value written within
// the caller's transaction; grouping them would only duplicate the domain row.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_derived_safety_observation_tx(
    tx: &mut Transaction<'_, Postgres>,
    subject_type: &str,
    subject_id: &str,
    scope_type: &str,
    scope_id: &str,
    signal_type: &str,
    value: f64,
    mitigating: bool,
    metadata: serde_json::Value,
) -> anyhow::Result<(Uuid, Uuid)> {
    let observation_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO trust_safety.safety_observation \
         (id, subject_type, subject_id, scope_type, scope_id, signal_type, value, confidence, weight, mitigating, metadata) \
         VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, 1.0, 1.0, $8, $9)",
    )
    .bind(observation_id)
    .bind(subject_type)
    .bind(subject_id)
    .bind(scope_type)
    .bind(scope_id)
    .bind(signal_type)
    .bind(value)
    .bind(mitigating)
    .bind(metadata)
    .execute(&mut **tx)
    .await?;
    let assessment_id =
        recalculate_safety_assessment_tx(tx, subject_type, subject_id, scope_type, scope_id)
            .await?;
    Ok((observation_id, assessment_id))
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
         (service_principal, actor_id, idempotency_key, operation, resource_id) VALUES ($1, $2, $3, $4, $5) \
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
    resource_type: &str,
    resource_id: Uuid,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO trust_safety.audit_log \
         (request_id, actor_id, actor_type, action, resource_type, resource_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&context.request_id)
    .bind(&context.actor_id)
    .bind(actor_type_name(context.actor_type))
    .bind(action)
    .bind(resource_type)
    .bind(resource_id.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn restriction_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::Restriction> {
    let status: &str = row.try_get("status")?;
    let expires: Option<DateTime<Utc>> = row.try_get("expires_at")?;
    let is_active = status == "ACTIVE" && expires.is_none_or(|e| e > Utc::now());
    Ok(v2::Restriction {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        subject: Some(subject_from_parts(
            row.try_get("subject_type")?,
            row.try_get("subject_id")?,
        )),
        scope: Some(scope_from_parts(
            row.try_get("scope_type")?,
            row.try_get("scope_id")?,
        )?),
        r#type: restriction_type_proto(row.try_get("restriction_type")?) as i32,
        status: status_proto(status) as i32,
        reason: row.try_get("reason")?,
        created_by: row.try_get("created_by")?,
        created_at: Some(timestamp(row.try_get("created_at")?)),
        expires_at: expires.map(timestamp),
        version: row.try_get::<i64, _>("version")? as u64,
        is_active,
        source_report_id: row
            .try_get::<Option<Uuid>, _>("source_report_id")
            .unwrap_or_default()
            .map(|id| id.to_string())
            .unwrap_or_default(),
    })
}

fn infraction_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::Infraction> {
    let status: &str = row.try_get("status")?;
    let expires: Option<DateTime<Utc>> = row.try_get("expires_at")?;
    let is_active = status == "ACTIVE" && expires.is_none_or(|e| e > Utc::now());
    Ok(v2::Infraction {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        subject: Some(subject_from_parts(
            row.try_get("subject_type")?,
            row.try_get("subject_id")?,
        )),
        scope: Some(scope_from_parts(
            row.try_get("scope_type")?,
            row.try_get("scope_id")?,
        )?),
        r#type: infraction_type_proto(row.try_get("infraction_type")?) as i32,
        status: status_proto(status) as i32,
        reason: row.try_get("reason")?,
        created_by: row.try_get("created_by")?,
        created_at: Some(timestamp(row.try_get("created_at")?)),
        expires_at: expires.map(timestamp),
        version: row.try_get::<i64, _>("version")? as u64,
        enforcement_restriction_id: row
            .try_get::<Option<Uuid>, _>("enforcement_restriction_id")?
            .map(|id| id.to_string())
            .unwrap_or_default(),
        is_active,
        source_report_id: row
            .try_get::<Option<Uuid>, _>("source_report_id")
            .unwrap_or_default()
            .map(|id| id.to_string())
            .unwrap_or_default(),
    })
}

fn report_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::Report> {
    let evidence_snapshot = row
        .try_get::<Option<String>, _>("evidence_lobby_id")?
        .map(|lobby_id| -> anyhow::Result<v2::ReportEvidenceSnapshot> {
            Ok(v2::ReportEvidenceSnapshot {
                lobby_id,
                first_sequence: row.try_get::<i64, _>("first_sequence")? as u64,
                last_sequence: row.try_get::<i64, _>("last_sequence")? as u64,
                entry_count: row.try_get::<i64, _>("entry_count")? as u64,
                terminal_action_id: row.try_get::<Uuid, _>("terminal_action_id")?.to_string(),
            })
        })
        .transpose()?;
    Ok(v2::Report {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        scope: Some(scope_from_parts(
            row.try_get("scope_type")?,
            row.try_get("scope_id")?,
        )?),
        subject: Some(subject_from_parts(
            row.try_get("subject_type")?,
            row.try_get("subject_id")?,
        )),
        reporter_id: row.try_get("reporter_id")?,
        r#type: row.try_get("report_type")?,
        description: row.try_get("description")?,
        status: status_proto(row.try_get("status")?) as i32,
        context: Some(json_to_struct(&row.try_get("context")?)),
        created_at: Some(timestamp(row.try_get("created_at")?)),
        resolved_by: row
            .try_get::<Option<String>, _>("resolved_by")?
            .unwrap_or_default(),
        resolved_at: row
            .try_get::<Option<DateTime<Utc>>, _>("resolved_at")?
            .map(timestamp),
        version: row.try_get::<i64, _>("version")? as u64,
        claimed_by: row
            .try_get::<Option<String>, _>("claimed_by")
            .unwrap_or_default()
            .unwrap_or_default(),
        claimed_at: row
            .try_get::<Option<DateTime<Utc>>, _>("claimed_at")
            .unwrap_or_default()
            .map(timestamp),
        claim_expires_at: row
            .try_get::<Option<DateTime<Utc>>, _>("claim_expires_at")
            .unwrap_or_default()
            .map(timestamp),
        last_claim_change_at: row
            .try_get::<Option<DateTime<Utc>>, _>("last_claim_change_at")
            .unwrap_or_default()
            .map(timestamp),
        evidence_snapshot,
    })
}

fn optional_uuid(value: &str, field: &str) -> anyhow::Result<Option<Uuid>> {
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        Uuid::parse_str(value).map_err(|_| anyhow::anyhow!("{field} must be a UUID"))?,
    ))
}

fn staff_action_request_from_row(
    row: &sqlx::postgres::PgRow,
) -> anyhow::Result<v2::StaffActionRequest> {
    let action_type: &str = row.try_get("action_type")?;
    let status: &str = row.try_get("status")?;
    Ok(v2::StaffActionRequest {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        action_type: match action_type {
            "LOBBY_BAN" => v2::StaffActionType::LobbyBan,
            "GLOBAL_BLACKLIST" => v2::StaffActionType::GlobalBlacklist,
            _ => v2::StaffActionType::Unspecified,
        } as i32,
        subject: Some(subject_from_parts(
            row.try_get("subject_type")?,
            row.try_get("subject_id")?,
        )),
        scope: Some(scope_from_parts(
            row.try_get("scope_type")?,
            row.try_get("scope_id")?,
        )?),
        report_id: row
            .try_get::<Option<Uuid>, _>("report_id")?
            .map(|id| id.to_string())
            .unwrap_or_default(),
        requested_reason: row.try_get("requested_reason")?,
        requested_expires_at: row
            .try_get::<Option<DateTime<Utc>>, _>("requested_expires_at")?
            .map(timestamp),
        requested_by: row.try_get("requested_by")?,
        requested_at: Some(timestamp(row.try_get("requested_at")?)),
        status: match status {
            "PENDING" => v2::StaffActionRequestStatus::Pending,
            "REJECTED" => v2::StaffActionRequestStatus::Rejected,
            "EXPIRED" => v2::StaffActionRequestStatus::Expired,
            "EXECUTED" => v2::StaffActionRequestStatus::Executed,
            "CANCELLED" => v2::StaffActionRequestStatus::Cancelled,
            _ => v2::StaffActionRequestStatus::Unspecified,
        } as i32,
        decided_by: row
            .try_get::<Option<String>, _>("decided_by")?
            .unwrap_or_default(),
        decision_reason: row
            .try_get::<Option<String>, _>("decision_reason")?
            .unwrap_or_default(),
        decided_at: row
            .try_get::<Option<DateTime<Utc>>, _>("decided_at")?
            .map(timestamp),
        executed_infraction_id: row
            .try_get::<Option<Uuid>, _>("executed_infraction_id")?
            .map(|id| id.to_string())
            .unwrap_or_default(),
        executed_restriction_id: row
            .try_get::<Option<Uuid>, _>("executed_restriction_id")?
            .map(|id| id.to_string())
            .unwrap_or_default(),
        expires_at: Some(timestamp(row.try_get("expires_at")?)),
        version: row.try_get::<i64, _>("version")? as u64,
    })
}

fn appeal_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::Appeal> {
    Ok(v2::Appeal {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        infraction_id: row.try_get::<Uuid, _>("infraction_id")?.to_string(),
        appellant_id: row.try_get("appellant_id")?,
        reason: row.try_get("reason")?,
        status: status_proto(row.try_get("status")?) as i32,
        resolution: row
            .try_get::<Option<String>, _>("resolution")?
            .unwrap_or_default(),
        created_at: Some(timestamp(row.try_get("created_at")?)),
        resolved_at: row
            .try_get::<Option<DateTime<Utc>>, _>("resolved_at")?
            .map(timestamp),
        version: row.try_get::<i64, _>("version")? as u64,
    })
}

fn review_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::ReviewItem> {
    Ok(v2::ReviewItem {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        queue: row.try_get("queue")?,
        scope: Some(scope_from_parts(
            row.try_get("scope_type")?,
            row.try_get("scope_id")?,
        )?),
        subject: Some(subject_from_parts(
            row.try_get("subject_type")?,
            row.try_get("subject_id")?,
        )),
        priority: row.try_get("priority")?,
        status: status_proto(row.try_get("status")?) as i32,
        reason_codes: row.try_get("reason_codes")?,
        decision_id: row
            .try_get::<Option<Uuid>, _>("decision_id")?
            .map(|id| id.to_string())
            .unwrap_or_default(),
        assigned_to: row
            .try_get::<Option<String>, _>("assigned_to")?
            .unwrap_or_default(),
        created_at: Some(timestamp(row.try_get("created_at")?)),
        version: row.try_get::<i64, _>("version")? as u64,
    })
}

fn json_to_struct(value: &serde_json::Value) -> prost_types::Struct {
    prost_types::Struct {
        fields: value
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), json_to_value(value)))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_value(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(*value),
        serde_json::Value::Number(value) => Kind::NumberValue(value.as_f64().unwrap_or_default()),
        serde_json::Value::String(value) => Kind::StringValue(value.clone()),
        serde_json::Value::Array(values) => Kind::ListValue(prost_types::ListValue {
            values: values.iter().map(json_to_value).collect(),
        }),
        serde_json::Value::Object(_) => Kind::StructValue(json_to_struct(value)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn primary_subject(
    subject: &v2::Subject,
    allow_message: bool,
) -> anyhow::Result<(&'static str, &str)> {
    if !subject.user_id.is_empty() {
        return Ok(("USER", &subject.user_id));
    }
    if !subject.server_id.is_empty() {
        return Ok(("SERVER", &subject.server_id));
    }
    if allow_message && !subject.message_id.is_empty() {
        return Ok(("MESSAGE", &subject.message_id));
    }
    anyhow::bail!("subject has no supported identifier")
}

fn subject_from_parts(subject_type: String, id: String) -> v2::Subject {
    let mut subject = v2::Subject::default();
    match subject_type.as_str() {
        "USER" => subject.user_id = id,
        "SERVER" => subject.server_id = id,
        "MESSAGE" => subject.message_id = id,
        "REPORT" => subject.report_id = id,
        _ => {}
    }
    subject
}

fn scope_name(value: i32) -> anyhow::Result<&'static str> {
    Ok(match v2::ScopeType::try_from(value)? {
        v2::ScopeType::Platform => "PLATFORM",
        v2::ScopeType::Product => "PRODUCT",
        v2::ScopeType::Hub => "HUB",
        v2::ScopeType::Lobby => "LOBBY",
        v2::ScopeType::IncidentOverlay => "INCIDENT_OVERLAY",
        v2::ScopeType::Unspecified => anyhow::bail!("scope type is required"),
    })
}

fn scope_from_parts(scope_type: String, id: String) -> anyhow::Result<v2::Scope> {
    Ok(v2::Scope {
        r#type: match scope_type.as_str() {
            "PLATFORM" => v2::ScopeType::Platform,
            "PRODUCT" => v2::ScopeType::Product,
            "HUB" => v2::ScopeType::Hub,
            "LOBBY" => v2::ScopeType::Lobby,
            "INCIDENT_OVERLAY" => v2::ScopeType::IncidentOverlay,
            _ => anyhow::bail!("invalid stored scope type"),
        } as i32,
        id,
        product: v2::Product::Unspecified as i32,
    })
}

fn restriction_type_name(value: i32) -> anyhow::Result<&'static str> {
    Ok(match v2::RestrictionType::try_from(value)? {
        v2::RestrictionType::Mute => "MUTE",
        v2::RestrictionType::Ban => "BAN",
        v2::RestrictionType::Blacklist => "BLACKLIST",
        v2::RestrictionType::ContentQuarantine => "CONTENT_QUARANTINE",
        v2::RestrictionType::Unspecified => anyhow::bail!("restriction type is required"),
    })
}

fn infraction_type_name(value: i32) -> anyhow::Result<&'static str> {
    Ok(match v2::InfractionType::try_from(value)? {
        v2::InfractionType::Warning => "WARNING",
        v2::InfractionType::Mute => "MUTE",
        v2::InfractionType::Ban => "BAN",
        v2::InfractionType::Content => "CONTENT",
        v2::InfractionType::Unspecified => anyhow::bail!("infraction type is required"),
    })
}

fn restriction_type_proto(value: String) -> v2::RestrictionType {
    match value.as_str() {
        "MUTE" => v2::RestrictionType::Mute,
        "BAN" => v2::RestrictionType::Ban,
        "BLACKLIST" => v2::RestrictionType::Blacklist,
        "CONTENT_QUARANTINE" => v2::RestrictionType::ContentQuarantine,
        _ => v2::RestrictionType::Unspecified,
    }
}

fn infraction_type_proto(value: String) -> v2::InfractionType {
    match value.as_str() {
        "WARNING" => v2::InfractionType::Warning,
        "MUTE" => v2::InfractionType::Mute,
        "BAN" => v2::InfractionType::Ban,
        "CONTENT" => v2::InfractionType::Content,
        _ => v2::InfractionType::Unspecified,
    }
}

fn status_proto(value: &str) -> v2::ResourceStatus {
    match value {
        "ACTIVE" => v2::ResourceStatus::Active,
        "REVOKED" => v2::ResourceStatus::Revoked,
        "EXPIRED" => v2::ResourceStatus::Expired,
        "PENDING" => v2::ResourceStatus::Pending,
        "RESOLVED" => v2::ResourceStatus::Resolved,
        "DISMISSED" => v2::ResourceStatus::Dismissed,
        _ => v2::ResourceStatus::Unspecified,
    }
}

fn actor_type_name(value: i32) -> &'static str {
    match v2::ActorType::try_from(value).unwrap_or_default() {
        v2::ActorType::Human => "HUMAN",
        v2::ActorType::Service => "SERVICE",
        v2::ActorType::Policy => "POLICY",
        v2::ActorType::Unspecified => "UNSPECIFIED",
    }
}

fn datetime(value: prost_types::Timestamp) -> anyhow::Result<DateTime<Utc>> {
    DateTime::from_timestamp(value.seconds, value.nanos as u32)
        .ok_or_else(|| anyhow::anyhow!("timestamp is out of range"))
}

fn timestamp(value: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_restriction_filters<'args>(
    query: &mut QueryBuilder<'args, Postgres>,
    scope_type: &'args str,
    scope_id: &'args str,
    status: Option<&'args str>,
    restriction_type: Option<&'args str>,
    subject_type: Option<&'args str>,
    subject_id: Option<&'args str>,
    created_by: Option<&'args str>,
    search: Option<&'args str>,
) {
    query
        .push(" WHERE scope_type = ")
        .push_bind(scope_type)
        .push("::trust_safety.scope_type AND scope_id = ")
        .push_bind(scope_id);
    if let Some(subject_type) = subject_type {
        query.push(" AND subject_type = ").push_bind(subject_type);
    }
    if let Some(subject_id) = subject_id {
        query.push(" AND subject_id = ").push_bind(subject_id);
    }
    if let Some(status) = status {
        query
            .push(" AND status = ")
            .push_bind(status)
            .push("::trust_safety.resource_status");
    }
    if let Some(restriction_type) = restriction_type {
        query
            .push(" AND restriction_type = ")
            .push_bind(restriction_type);
    }
    if let Some(created_by) = created_by {
        query.push(" AND created_by = ").push_bind(created_by);
    }
    if let Some(search) = search {
        query
            .push(" AND (subject_id ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!' OR reason ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!' OR created_by ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!')");
    }
}

fn like_pattern(value: &str) -> String {
    format!(
        "%{}%",
        value
            .replace('!', "!!")
            .replace('%', "!%")
            .replace('_', "!_")
    )
}

fn normalize_restriction_sort(value: &str) -> anyhow::Result<&'static str> {
    match value {
        "" => Ok("id_desc"),
        "created_at_desc" => Ok("created_at_desc"),
        "created_at_asc" => Ok("created_at_asc"),
        "expires_at_asc" => Ok("expires_at_asc"),
        _ => anyhow::bail!("unsupported restriction sort: {value}"),
    }
}

fn restriction_sort_sql(sort: &str) -> &'static str {
    match sort {
        "id_desc" => "id DESC",
        "created_at_asc" => "created_at ASC, id ASC",
        "expires_at_asc" => "(expires_at IS NULL) ASC, expires_at ASC NULLS LAST, id ASC",
        _ => "created_at DESC, id DESC",
    }
}

fn parse_restriction_cursor(value: &str, sort: &str) -> anyhow::Result<Option<RestrictionCursor>> {
    if value.is_empty() {
        return Ok(None);
    }
    if sort == "id_desc" {
        return Ok(Some(RestrictionCursor {
            sort: sort.to_owned(),
            created_at: None,
            expires_at: None,
            id: Uuid::parse_str(value)?,
        }));
    }
    let cursor: RestrictionCursor = serde_json::from_str(value)?;
    anyhow::ensure!(
        cursor.sort == sort,
        "restriction cursor sort does not match request"
    );
    Ok(Some(cursor))
}

fn push_restriction_cursor(
    query: &mut QueryBuilder<'_, Postgres>,
    sort: &str,
    cursor: Option<&RestrictionCursor>,
) {
    let Some(cursor) = cursor else {
        return;
    };
    match sort {
        "created_at_desc" => {
            query
                .push(" AND (created_at, id) < (")
                .push_bind(cursor.created_at)
                .push(", ")
                .push_bind(cursor.id)
                .push(")");
        }
        "created_at_asc" => {
            query
                .push(" AND (created_at, id) > (")
                .push_bind(cursor.created_at)
                .push(", ")
                .push_bind(cursor.id)
                .push(")");
        }
        "expires_at_asc" => {
            if let Some(expires_at) = cursor.expires_at {
                query
                    .push(" AND ((expires_at IS NOT NULL AND (expires_at, id) > (")
                    .push_bind(expires_at)
                    .push(", ")
                    .push_bind(cursor.id)
                    .push(")) OR expires_at IS NULL)");
            } else {
                query
                    .push(" AND expires_at IS NULL AND id > ")
                    .push_bind(cursor.id);
            }
        }
        _ => {
            query.push(" AND id < ").push_bind(cursor.id);
        }
    }
}

fn restriction_page_cursor(rows: &[sqlx::postgres::PgRow], sort: &str) -> anyhow::Result<String> {
    let Some(row) = rows.last() else {
        return Ok(String::new());
    };
    let id = row.try_get::<Uuid, _>("id")?;
    if sort == "id_desc" {
        return Ok(id.to_string());
    }
    Ok(serde_json::to_string(&RestrictionCursor {
        sort: sort.to_owned(),
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        id,
    })?)
}

fn moderation_kind_names(values: &[i32]) -> anyhow::Result<BTreeSet<&'static str>> {
    let values = if values.is_empty() {
        vec![
            v2::ModerationRecordKind::Blacklist,
            v2::ModerationRecordKind::Warning,
            v2::ModerationRecordKind::LobbyWarning,
            v2::ModerationRecordKind::LobbyBan,
        ]
    } else {
        values
            .iter()
            .map(|value| v2::ModerationRecordKind::try_from(*value))
            .collect::<Result<Vec<_>, _>>()?
    };
    values
        .into_iter()
        .map(|value| match value {
            v2::ModerationRecordKind::Blacklist => Ok("BLACKLIST"),
            v2::ModerationRecordKind::Warning => Ok("WARNING"),
            v2::ModerationRecordKind::LobbyWarning => Ok("LOBBY_WARNING"),
            v2::ModerationRecordKind::LobbyBan => Ok("LOBBY_BAN"),
            v2::ModerationRecordKind::Unspecified => {
                anyhow::bail!("moderation record kind is required")
            }
        })
        .collect()
}

fn moderation_record_kind(value: &str) -> anyhow::Result<v2::ModerationRecordKind> {
    Ok(match value {
        "BLACKLIST" => v2::ModerationRecordKind::Blacklist,
        "WARNING" => v2::ModerationRecordKind::Warning,
        "LOBBY_WARNING" => v2::ModerationRecordKind::LobbyWarning,
        "LOBBY_BAN" => v2::ModerationRecordKind::LobbyBan,
        _ => anyhow::bail!("invalid stored moderation record kind"),
    })
}

fn classify_infraction_moderation_kind(
    infraction_type: &str,
    scope_type: &str,
) -> Option<&'static str> {
    match (infraction_type, scope_type) {
        ("WARNING", "LOBBY") => Some("LOBBY_WARNING"),
        ("WARNING", _) => Some("WARNING"),
        ("BAN", "PRODUCT") => Some("LOBBY_BAN"),
        _ => None,
    }
}

fn moderation_record_kind_from_values(
    resource_type: &str,
    stored_kind: &str,
    infraction_type: Option<&str>,
    scope_type: &str,
) -> anyhow::Result<v2::ModerationRecordKind> {
    let kind = if resource_type == "INFRACTION" {
        infraction_type
            .and_then(|infraction_type| {
                classify_infraction_moderation_kind(infraction_type, scope_type)
            })
            .unwrap_or(stored_kind)
    } else {
        stored_kind
    };
    moderation_record_kind(kind)
}

fn moderation_record_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::ModerationRecord> {
    let resource_type: String = row.try_get("resource_type")?;
    let stored_kind: String = row.try_get("kind")?;
    let infraction_type: Option<String> = row.try_get("infraction_type")?;
    let scope_type: String = row.try_get("scope_type")?;
    let kind = moderation_record_kind_from_values(
        &resource_type,
        &stored_kind,
        infraction_type.as_deref(),
        &scope_type,
    )?;
    let resource = match resource_type.as_str() {
        "RESTRICTION" => v2::moderation_record::Resource::Restriction(restriction_from_row(row)?),
        "INFRACTION" => v2::moderation_record::Resource::Infraction(infraction_from_row(row)?),
        _ => anyhow::bail!("invalid stored moderation resource type"),
    };
    Ok(v2::ModerationRecord {
        kind: kind as i32,
        resource: Some(resource),
    })
}

fn moderation_link_target_from_row(
    row: &sqlx::postgres::PgRow,
    resource_type: v2::ModerationResourceType,
) -> anyhow::Result<ModerationLinkTarget> {
    let resource_type_name = match resource_type {
        v2::ModerationResourceType::Restriction => "RESTRICTION",
        v2::ModerationResourceType::Infraction => "INFRACTION",
        v2::ModerationResourceType::Unspecified => {
            anyhow::bail!("moderation resource type is required")
        }
    };
    let stored_kind: String = row.try_get("kind")?;
    let infraction_type: Option<String> = row.try_get("infraction_type")?;
    let scope_type: String = row.try_get("scope_type")?;
    let kind = moderation_record_kind_from_values(
        resource_type_name,
        &stored_kind,
        infraction_type.as_deref(),
        &scope_type,
    )?;
    Ok(ModerationLinkTarget {
        resource_type: resource_type_name,
        id: row.try_get("id")?,
        subject_type: row.try_get("subject_type")?,
        subject_id: row.try_get("subject_id")?,
        scope_type: row.try_get("scope_type")?,
        scope_id: row.try_get("scope_id")?,
        kind: match kind {
            v2::ModerationRecordKind::Blacklist => "BLACKLIST",
            v2::ModerationRecordKind::Warning => "WARNING",
            v2::ModerationRecordKind::LobbyWarning => "LOBBY_WARNING",
            v2::ModerationRecordKind::LobbyBan => "LOBBY_BAN",
            v2::ModerationRecordKind::Unspecified => unreachable!(),
        },
        source_report_id: row.try_get("source_report_id")?,
        version: row.try_get("version")?,
        enforcement_restriction_id: row.try_get("enforcement_restriction_id")?,
    })
}

fn validate_moderation_record_report_link(
    target: &ModerationLinkTarget,
    report_subject_type: &str,
    report_subject_id: &str,
    report_scope_type: &str,
    report_scope_id: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        target.subject_type == report_subject_type && target.subject_id == report_subject_id,
        "report subject must match moderation record subject"
    );
    if matches!(target.kind, "WARNING" | "LOBBY_WARNING") {
        anyhow::ensure!(
            target.scope_type == report_scope_type && target.scope_id == report_scope_id,
            "warning report scope must match moderation record scope"
        );
    }
    Ok(())
}

fn ensure_report_link_is_compatible(
    existing_report_id: Option<Uuid>,
    report_id: Uuid,
    resource_label: &str,
) -> anyhow::Result<()> {
    if let Some(existing_report_id) = existing_report_id {
        anyhow::ensure!(
            existing_report_id == report_id,
            "moderation record link conflict: {resource_label} is linked to a different report"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_moderation_record_filters<'args>(
    query: &mut QueryBuilder<'args, Postgres>,
    subject_type: Option<&'args str>,
    subject_id: Option<&'args str>,
    created_by: Option<&'args str>,
    search: Option<&'args str>,
    status: Option<&'args str>,
) {
    if let Some(subject_type) = subject_type {
        query.push(" AND subject_type = ").push_bind(subject_type);
    }
    if let Some(subject_id) = subject_id {
        query.push(" AND subject_id = ").push_bind(subject_id);
    }
    if let Some(created_by) = created_by {
        query.push(" AND created_by = ").push_bind(created_by);
    }
    if let Some(search) = search {
        query
            .push(" AND (subject_id ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!' OR scope_id ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!' OR reason ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!' OR created_by ILIKE ")
            .push_bind(search)
            .push(" ESCAPE '!')");
    }
    if let Some(status) = status {
        query
            .push(" AND status = ")
            .push_bind(status)
            .push("::trust_safety.resource_status");
    }
}

fn normalize_moderation_record_sort(value: &str) -> anyhow::Result<&'static str> {
    match value {
        "" | "created_at_desc" => Ok("created_at_desc"),
        "created_at_asc" => Ok("created_at_asc"),
        "expires_at_asc" => Ok("expires_at_asc"),
        _ => anyhow::bail!("unsupported moderation record sort: {value}"),
    }
}

fn moderation_record_sort_sql(sort: &str) -> &'static str {
    match sort {
        "created_at_asc" => "created_at ASC, id ASC",
        "expires_at_asc" => "(expires_at IS NULL) ASC, expires_at ASC NULLS LAST, id ASC",
        _ => "created_at DESC, id DESC",
    }
}

fn parse_moderation_record_cursor(
    value: &str,
    sort: &str,
) -> anyhow::Result<Option<ModerationRecordCursor>> {
    if value.is_empty() {
        return Ok(None);
    }
    let cursor: ModerationRecordCursor = serde_json::from_str(value)?;
    anyhow::ensure!(
        cursor.sort == sort,
        "moderation record cursor sort does not match request"
    );
    if matches!(sort, "created_at_desc" | "created_at_asc") {
        anyhow::ensure!(
            cursor.created_at.is_some(),
            "moderation record cursor is missing created_at"
        );
    }
    Ok(Some(cursor))
}

fn push_moderation_record_cursor(
    query: &mut QueryBuilder<'_, Postgres>,
    sort: &str,
    cursor: Option<&ModerationRecordCursor>,
) {
    let Some(cursor) = cursor else {
        return;
    };
    match sort {
        "created_at_desc" => {
            query
                .push(" AND (created_at, id) < (")
                .push_bind(cursor.created_at)
                .push(", ")
                .push_bind(cursor.id)
                .push(")");
        }
        "created_at_asc" => {
            query
                .push(" AND (created_at, id) > (")
                .push_bind(cursor.created_at)
                .push(", ")
                .push_bind(cursor.id)
                .push(")");
        }
        "expires_at_asc" => {
            if let Some(expires_at) = cursor.expires_at {
                query
                    .push(" AND ((expires_at IS NOT NULL AND (expires_at, id) > (")
                    .push_bind(expires_at)
                    .push(", ")
                    .push_bind(cursor.id)
                    .push(")) OR expires_at IS NULL)");
            } else {
                query
                    .push(" AND expires_at IS NULL AND id > ")
                    .push_bind(cursor.id);
            }
        }
        _ => unreachable!(),
    }
}

fn moderation_record_page_cursor(
    rows: &[sqlx::postgres::PgRow],
    sort: &str,
) -> anyhow::Result<String> {
    let Some(row) = rows.last() else {
        return Ok(String::new());
    };
    Ok(serde_json::to_string(&ModerationRecordCursor {
        sort: sort.to_owned(),
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        id: row.try_get("id")?,
    })?)
}

fn page_cursor(
    rows: &[sqlx::postgres::PgRow],
    requested_limit: i64,
    field: &str,
) -> anyhow::Result<String> {
    if rows.len() == requested_limit.clamp(1, 100) as usize {
        Ok(rows
            .last()
            .map(|row| row.try_get::<Uuid, _>(field).map(|id| id.to_string()))
            .transpose()?
            .unwrap_or_default())
    } else {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ModerationLinkTarget, ModerationRecordCursor, calculate_safety_score,
        classify_infraction_moderation_kind, ensure_report_link_is_compatible, like_pattern,
        moderation_kind_names, moderation_record_kind_from_values,
        normalize_moderation_record_sort, normalize_restriction_sort,
        parse_moderation_record_cursor, parse_restriction_cursor,
        validate_moderation_record_report_link,
    };
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    #[test]
    fn safety_score_aggregates_repeated_signals_and_mitigation() {
        let (score, tier, breakdown) = calculate_safety_score([
            ("REPORT".to_owned(), 20.0, 0.5, 1.0, false),
            ("REPORT".to_owned(), 10.0, 1.0, 1.0, false),
            ("APPEAL_ACCEPTED".to_owned(), 5.0, 1.0, 1.0, true),
        ]);

        assert_eq!(score, 15.0);
        assert_eq!(tier, "LOW_RISK");
        assert_eq!(breakdown["REPORT"], (2, 20.0));
        assert_eq!(breakdown["APPEAL_ACCEPTED"], (1, -5.0));
    }

    #[test]
    fn safety_score_is_bounded() {
        let (high, high_tier, _) =
            calculate_safety_score([("SEVERE".to_owned(), 100.0, 1.0, 10.0, false)]);
        let (low, low_tier, _) = calculate_safety_score([
            ("RISK".to_owned(), 5.0, 1.0, 1.0, false),
            ("MITIGATION".to_owned(), 100.0, 1.0, 1.0, true),
        ]);

        assert_eq!((high, high_tier), (100.0, "HIGH_RISK"));
        assert_eq!((low, low_tier), (0.0, "SAFE"));
    }

    #[test]
    fn restriction_listing_accepts_only_supported_sorts() {
        assert_eq!(normalize_restriction_sort("").unwrap(), "id_desc");
        assert_eq!(
            normalize_restriction_sort("created_at_desc").unwrap(),
            "created_at_desc"
        );
        assert!(normalize_restriction_sort("random").is_err());
    }

    #[test]
    fn legacy_id_cursor_is_still_accepted_for_unfiltered_callers() {
        let id = uuid::Uuid::now_v7();
        let cursor = parse_restriction_cursor(&id.to_string(), "id_desc").unwrap();
        assert_eq!(cursor.expect("cursor").id, id);
    }

    #[test]
    fn restriction_search_treats_like_metacharacters_literally() {
        assert_eq!(like_pattern("100%_done!"), "%100!%!_done!!%");
    }

    #[test]
    fn moderation_record_kinds_default_to_all_supported_sources() {
        let kinds = moderation_kind_names(&[]).expect("all kinds");
        assert_eq!(kinds.len(), 4);
        assert!(kinds.contains("BLACKLIST"));
        assert!(kinds.contains("WARNING"));
        assert!(kinds.contains("LOBBY_WARNING"));
        assert!(kinds.contains("LOBBY_BAN"));
    }

    #[test]
    fn moderation_record_kind_classifies_warning_sources_by_scope() {
        assert_eq!(
            classify_infraction_moderation_kind("WARNING", "LOBBY"),
            Some("LOBBY_WARNING")
        );
        assert_eq!(
            classify_infraction_moderation_kind("WARNING", "HUB"),
            Some("WARNING")
        );
        assert_eq!(
            classify_infraction_moderation_kind("BAN", "PRODUCT"),
            Some("LOBBY_BAN")
        );
        assert_eq!(classify_infraction_moderation_kind("BAN", "LOBBY"), None);
        assert_eq!(
            moderation_record_kind_from_values("INFRACTION", "WARNING", Some("BAN"), "PRODUCT")
                .expect("product ban"),
            crate::contract::v2::ModerationRecordKind::LobbyBan
        );
    }

    #[test]
    fn moderation_record_sort_accepts_only_documented_orders() {
        assert_eq!(
            normalize_moderation_record_sort("").unwrap(),
            "created_at_desc"
        );
        assert_eq!(
            normalize_moderation_record_sort("expires_at_asc").unwrap(),
            "expires_at_asc"
        );
        assert!(normalize_moderation_record_sort("random").is_err());
    }

    #[test]
    fn moderation_record_cursor_requires_matching_sort_and_created_at() {
        let id = Uuid::now_v7();
        let cursor = ModerationRecordCursor {
            sort: "created_at_desc".to_owned(),
            created_at: Some(Utc.timestamp_opt(1_700_000_000, 0).single().unwrap()),
            expires_at: None,
            id,
        };
        let encoded = serde_json::to_string(&cursor).expect("cursor encoding");
        let decoded = parse_moderation_record_cursor(&encoded, "created_at_desc")
            .expect("cursor decoding")
            .expect("cursor");
        assert_eq!(decoded.id, id);
        assert!(parse_moderation_record_cursor(&encoded, "created_at_asc").is_err());

        let missing_created_at = serde_json::json!({
            "sort": "created_at_desc",
            "created_at": null,
            "expires_at": null,
            "id": id,
        })
        .to_string();
        assert!(parse_moderation_record_cursor(&missing_created_at, "created_at_desc").is_err());
    }

    fn link_target(kind: &'static str, scope_type: &str, scope_id: &str) -> ModerationLinkTarget {
        ModerationLinkTarget {
            resource_type: "INFRACTION",
            id: Uuid::now_v7(),
            subject_type: "USER".to_owned(),
            subject_id: "user-1".to_owned(),
            scope_type: scope_type.to_owned(),
            scope_id: scope_id.to_owned(),
            kind,
            source_report_id: None,
            version: 1,
            enforcement_restriction_id: None,
        }
    }

    #[test]
    fn moderation_record_report_link_checks_subject_and_warning_scope() {
        let blacklist = link_target("BLACKLIST", "PLATFORM", "platform");
        assert!(
            validate_moderation_record_report_link(
                &blacklist, "USER", "user-1", "LOBBY", "lobby-1",
            )
            .is_ok()
        );

        let lobby_ban = link_target("LOBBY_BAN", "PRODUCT", "product");
        assert!(
            validate_moderation_record_report_link(
                &lobby_ban, "USER", "user-1", "LOBBY", "lobby-1",
            )
            .is_ok()
        );

        let warning = link_target("WARNING", "HUB", "hub-1");
        assert!(
            validate_moderation_record_report_link(&warning, "USER", "user-1", "HUB", "hub-1",)
                .is_ok()
        );
        assert!(
            validate_moderation_record_report_link(&warning, "USER", "user-1", "LOBBY", "lobby-1",)
                .is_err()
        );
        assert!(
            validate_moderation_record_report_link(&warning, "USER", "user-2", "HUB", "hub-1",)
                .is_err()
        );
    }

    #[test]
    fn moderation_record_report_link_is_idempotent_but_rejects_conflicts() {
        let report_id = Uuid::now_v7();
        assert!(ensure_report_link_is_compatible(None, report_id, "record").is_ok());
        assert!(ensure_report_link_is_compatible(Some(report_id), report_id, "record").is_ok());

        let different_report_id = Uuid::now_v7();
        let error = ensure_report_link_is_compatible(
            Some(report_id),
            different_report_id,
            "paired resource",
        )
        .expect_err("different report links must conflict");
        assert!(error.to_string().contains("different report"));
    }
}
