use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{contract::v2, policy::model::ExecutionTrace};

pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: String,
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
}

impl ModerationRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
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
             (id, subject_type, subject_id, scope_type, scope_id, restriction_type, reason, created_by, expires_at) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(subject_type)
        .bind(subject_id)
        .bind(scope_type)
        .bind(&scope.id)
        .bind(restriction_type)
        .bind(restriction.reason.trim())
        .bind(&context.actor_id)
        .bind(restriction.expires_at.map(datetime).transpose()?)
        .execute(&mut *tx)
        .await?;
        insert_audit(&mut tx, context, "CREATE_RESTRICTION", "RESTRICTION", id).await?;
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
        tx.commit().await?;
        self.get_restriction(id).await
    }

    pub async fn list_restrictions(
        &self,
        scope: &v2::Scope,
        subject: Option<&v2::Subject>,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<v2::Restriction>> {
        let (subject_type, subject_id) = subject
            .map(|subject| primary_subject(subject, false))
            .transpose()?
            .map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let rows = sqlx::query(
            "SELECT id, subject_type, subject_id, scope_type::text, scope_id, restriction_type, \
             status::text, reason, created_by, created_at, expires_at, version \
             FROM trust_safety.restriction WHERE scope_type = $1::trust_safety.scope_type AND scope_id = $2 \
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
            .map(restriction_from_row)
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
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
        let mut tx = self.db.begin().await?;
        if let IdempotencyClaim::Existing(existing) =
            claim_idempotency(&mut tx, context, "CREATE_INFRACTION", id).await?
        {
            tx.rollback().await?;
            return self.get_infraction(existing).await;
        }
        if let Some(enforcement) = &enforcement {
            sqlx::query(
                "INSERT INTO trust_safety.restriction \
                 (id, subject_type, subject_id, scope_type, scope_id, restriction_type, reason, created_by, expires_at) \
                 VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9)",
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
             (id, subject_type, subject_id, scope_type, scope_id, infraction_type, reason, created_by, expires_at, enforcement_restriction_id) \
             VALUES ($1, $2, $3, $4::trust_safety.scope_type, $5, $6, $7, $8, $9, $10)",
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
        tx.commit().await?;
        self.get_infraction(id).await
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
             status::text, reason, created_by, created_at, expires_at, version, enforcement_restriction_id \
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
             status::text, reason, created_by, created_at, expires_at, version, enforcement_restriction_id \
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

    pub async fn list_reports(
        &self,
        scope: Option<&v2::Scope>,
        status: Option<&str>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Page<v2::Report>> {
        let rows = sqlx::query(
            "SELECT id, scope_type::text, scope_id, subject_type, subject_id, reporter_id, report_type, \
             description, status::text, context, created_at, resolved_by, resolved_at, version \
             FROM trust_safety.report WHERE ($1::text IS NULL OR scope_type = $1::trust_safety.scope_type) \
               AND ($2::text IS NULL OR scope_id = $2) \
               AND ($3::text IS NULL OR status = $3::trust_safety.resource_status) \
               AND ($4::uuid IS NULL OR id < $4) ORDER BY id DESC LIMIT $5",
        )
        .bind(scope.map(|scope| scope_name(scope.r#type)).transpose()?)
        .bind(scope.map(|scope| scope.id.as_str()))
        .bind(status)
        .bind(cursor)
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
        report_context: serde_json::Value,
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
            serde_json::to_vec(&report_context)?.len() <= 65_536,
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
        .bind(report_context)
        .execute(&mut *tx)
        .await?;
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
            "SELECT id, scope_type::text, scope_id, subject_type, subject_id, reporter_id, report_type, \
             description, status::text, context, created_at, resolved_by, resolved_at, version \
             FROM trust_safety.report WHERE id = $1",
        ).bind(id).fetch_one(&self.db).await?;
        report_from_row(&row)
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
             status::text, reason, created_by, created_at, expires_at, version \
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
             status::text, reason, created_by, created_at, expires_at, version, enforcement_restriction_id \
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
        status: status_proto(row.try_get("status")?) as i32,
        reason: row.try_get("reason")?,
        created_by: row.try_get("created_by")?,
        created_at: Some(timestamp(row.try_get("created_at")?)),
        expires_at: row
            .try_get::<Option<DateTime<Utc>>, _>("expires_at")?
            .map(timestamp),
        version: row.try_get::<i64, _>("version")? as u64,
    })
}

fn infraction_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::Infraction> {
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
        status: status_proto(row.try_get("status")?) as i32,
        reason: row.try_get("reason")?,
        created_by: row.try_get("created_by")?,
        created_at: Some(timestamp(row.try_get("created_at")?)),
        expires_at: row
            .try_get::<Option<DateTime<Utc>>, _>("expires_at")?
            .map(timestamp),
        version: row.try_get::<i64, _>("version")? as u64,
        enforcement_restriction_id: row
            .try_get::<Option<Uuid>, _>("enforcement_restriction_id")?
            .map(|id| id.to_string())
            .unwrap_or_default(),
    })
}

fn report_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<v2::Report> {
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

fn status_proto(value: String) -> v2::ResourceStatus {
    match value.as_str() {
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
    use super::calculate_safety_score;

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
}
