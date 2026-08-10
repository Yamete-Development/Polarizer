use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use prost::Message;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::model::{
    Authority, ContentPolicy, PolicyAction, PolicyActionType, PolicyRule, PolicyScope, RulePattern,
    Surface, WildcardPatternType,
};
use super::{
    compiler::CompiledPolicySnapshot,
    invalidation::{CONTENT_POLICY_INVALIDATED_EVENT_TYPE, ContentPolicyInvalidated},
    validation::{parse_pattern, validate_and_classify_policy},
};
use crate::{
    contract::v2,
    policy::repository::{
        PolicyIdempotencyClaim, claim_policy_idempotency, insert_audit, insert_outbox,
    },
};

#[async_trait]
pub trait ContentPolicySource: Send + Sync {
    /// Load every configured scope during startup/reconciliation. The returned
    /// values are database definitions, not hot-path runtime snapshots.
    async fn load_all(&self) -> anyhow::Result<Vec<ContentPolicy>>;
    /// Reload exactly one invalidated scope.
    async fn load_scope(&self, scope: &PolicyScope) -> anyhow::Result<Option<ContentPolicy>>;
}

#[derive(Clone)]
pub struct PostgresContentPolicyRepository {
    db: PgPool,
    invalidation_topic: String,
}

impl PostgresContentPolicyRepository {
    pub fn new(db: PgPool, invalidation_topic: impl Into<String>) -> Self {
        Self {
            db,
            invalidation_topic: invalidation_topic.into(),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.db
    }

    /// Atomically replace one scope definition. This deliberately favors a
    /// simple full-scope rewrite because policy changes are rare and a complete
    /// replacement can be validated/compiled before it becomes authoritative.
    pub async fn replace_policy(
        &self,
        definition: &ContentPolicy,
        expected_version: u64,
        limits: super::model::PolicyLimits,
        context: &v2::RequestContext,
    ) -> anyhow::Result<ContentPolicy> {
        let mut definition = definition.clone();
        validate_and_classify_policy(&mut definition, limits)?;
        if definition.enabled {
            // Refuse a database mutation unless its complete replacement
            // matcher is already known to compile successfully.
            CompiledPolicySnapshot::compile(&definition)?;
        }
        let next_version = expected_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("content policy version overflow"))?;
        anyhow::ensure!(
            definition.version == next_version,
            "replacement version must be exactly expected_version + 1"
        );

        let before = self.load_scope(&definition.scope).await?;
        let mut tx = self.db.begin().await?;
        if let PolicyIdempotencyClaim::Existing(existing) =
            claim_policy_idempotency(&mut tx, context, "REPLACE_CONTENT_POLICY", definition.id)
                .await?
        {
            tx.rollback().await?;
            let policy = self
                .load_scope(&definition.scope)
                .await?
                .ok_or_else(|| anyhow::anyhow!("idempotent content policy no longer exists"))?;
            anyhow::ensure!(
                policy.id == existing,
                "idempotency key belongs to another policy"
            );
            return Ok(policy);
        }

        let current = sqlx::query(
            "SELECT id, version FROM trust_safety.content_policy \
             WHERE authority = $1::trust_safety.content_policy_authority AND scope_id = $2 \
             FOR UPDATE",
        )
        .bind(authority_name(definition.scope.authority))
        .bind(&definition.scope.id)
        .fetch_optional(&mut *tx)
        .await?;
        match current {
            Some(row) => {
                let current_id: Uuid = row.try_get("id")?;
                let current_version: i64 = row.try_get("version")?;
                anyhow::ensure!(
                    current_id == definition.id,
                    "content policy id is immutable"
                );
                anyhow::ensure!(
                    u64::try_from(current_version).ok() == Some(expected_version),
                    "content policy version conflict"
                );
                sqlx::query(
                    "UPDATE trust_safety.content_policy \
                     SET enabled = $2, version = $3, updated_by = $4, updated_at = clock_timestamp() \
                     WHERE id = $1",
                )
                .bind(definition.id)
                .bind(definition.enabled)
                .bind(i64::try_from(next_version)?)
                .bind(&context.actor_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM trust_safety.content_policy_rule WHERE policy_id = $1")
                    .bind(definition.id)
                    .execute(&mut *tx)
                    .await?;
            }
            None => {
                anyhow::ensure!(expected_version == 0, "content policy does not exist");
                sqlx::query(
                    "INSERT INTO trust_safety.content_policy \
                     (id, authority, scope_id, enabled, version, created_by, updated_by) \
                     VALUES ($1, $2::trust_safety.content_policy_authority, $3, $4, $5, $6, $6)",
                )
                .bind(definition.id)
                .bind(authority_name(definition.scope.authority))
                .bind(&definition.scope.id)
                .bind(definition.enabled)
                .bind(i64::try_from(next_version)?)
                .bind(&context.actor_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        for rule in &definition.rules {
            sqlx::query(
                "INSERT INTO trust_safety.content_policy_rule \
                 (id, policy_id, name, description, enabled, custom_reason, created_by, updated_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(rule.id)
            .bind(definition.id)
            .bind(rule.name.trim())
            .bind(rule.description.trim())
            .bind(rule.enabled)
            .bind(rule.custom_reason.as_deref().map(str::trim))
            .bind(&context.actor_id)
            .bind(&context.actor_id)
            .execute(&mut *tx)
            .await?;
            for pattern in &rule.patterns {
                let parsed = parse_pattern(&pattern.pattern)
                    .expect("replacement policy patterns were validated");
                sqlx::query(
                    "INSERT INTO trust_safety.content_rule_pattern \
                     (id, rule_id, pattern, normalized_pattern, pattern_type) \
                     VALUES ($1, $2, $3, $4, $5::trust_safety.content_policy_pattern_type)",
                )
                .bind(pattern.id)
                .bind(rule.id)
                .bind(pattern.pattern.trim())
                .bind(parsed.normalized)
                .bind(pattern_type_name(parsed.pattern_type))
                .execute(&mut *tx)
                .await?;
            }
            for surface in &rule.surfaces {
                sqlx::query(
                    "INSERT INTO trust_safety.content_rule_surface (rule_id, surface) \
                     VALUES ($1, $2::trust_safety.content_policy_surface)",
                )
                .bind(rule.id)
                .bind(surface_name(*surface))
                .execute(&mut *tx)
                .await?;
            }
            for action in &rule.actions {
                sqlx::query(
                    "INSERT INTO trust_safety.content_rule_action \
                     (id, rule_id, action_type, duration_seconds, replacement) \
                     VALUES ($1, $2, $3::trust_safety.content_policy_action_type, $4, $5)",
                )
                .bind(action.id)
                .bind(rule.id)
                .bind(action_type_name(action.action_type))
                .bind(action.duration_seconds.map(i64::try_from).transpose()?)
                .bind(action.replacement.as_deref())
                .execute(&mut *tx)
                .await?;
            }
        }

        insert_audit(
            &mut tx,
            context,
            "REPLACE_CONTENT_POLICY",
            "CONTENT_POLICY",
            &definition.id.to_string(),
            before.as_ref().map(serde_json::to_value).transpose()?,
            Some(serde_json::to_value(&definition)?),
        )
        .await?;
        let event = ContentPolicyInvalidated {
            authority: authority_name(definition.scope.authority).to_owned(),
            scope_id: definition.scope.id.clone(),
            version: next_version,
            occurred_at: Some(now_timestamp()),
        };
        insert_outbox(
            &mut tx,
            "CONTENT_POLICY",
            definition.id,
            &self.invalidation_topic,
            CONTENT_POLICY_INVALIDATED_EVENT_TYPE,
            &format!(
                "{}:{}",
                authority_name(definition.scope.authority),
                definition.scope.id
            ),
            event.encode_to_vec(),
        )
        .await?;
        tx.commit().await?;

        self.load_scope(&definition.scope)
            .await?
            .ok_or_else(|| anyhow::anyhow!("content policy disappeared after replacement"))
    }

    async fn load(&self, scope: Option<&PolicyScope>) -> anyhow::Result<Vec<ContentPolicy>> {
        let authority = scope.map(|scope| authority_name(scope.authority));
        let scope_id = scope.map(|scope| scope.id.as_str());

        // Five bounded bulk queries avoid both a pattern/surface/action
        // Cartesian product and per-rule N+1 reads.
        let policy_rows = sqlx::query(
            "SELECT id, authority::text, scope_id, enabled, version \
             FROM trust_safety.content_policy \
             WHERE ($1::text IS NULL OR (authority = $1::trust_safety.content_policy_authority AND scope_id = $2)) \
             ORDER BY authority, scope_id, id",
        )
        .bind(authority)
        .bind(scope_id)
        .fetch_all(&self.db)
        .await?;
        if policy_rows.is_empty() {
            return Ok(Vec::new());
        }

        let policy_ids = policy_rows
            .iter()
            .map(|row| row.try_get::<Uuid, _>("id"))
            .collect::<Result<Vec<_>, _>>()?;
        let rule_rows = sqlx::query(
            "SELECT id, policy_id, name, description, enabled, custom_reason, created_by \
             FROM trust_safety.content_policy_rule \
             WHERE policy_id = ANY($1) ORDER BY policy_id, id",
        )
        .bind(&policy_ids)
        .fetch_all(&self.db)
        .await?;
        let rule_ids = rule_rows
            .iter()
            .map(|row| row.try_get::<Uuid, _>("id"))
            .collect::<Result<Vec<_>, _>>()?;

        let (pattern_rows, surface_rows, action_rows) = if rule_ids.is_empty() {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            tokio::try_join!(
                sqlx::query(
                    "SELECT id, rule_id, pattern, pattern_type::text \
                     FROM trust_safety.content_rule_pattern \
                     WHERE rule_id = ANY($1) ORDER BY rule_id, id",
                )
                .bind(&rule_ids)
                .fetch_all(&self.db),
                sqlx::query(
                    "SELECT rule_id, surface::text \
                     FROM trust_safety.content_rule_surface \
                     WHERE rule_id = ANY($1) ORDER BY rule_id, surface",
                )
                .bind(&rule_ids)
                .fetch_all(&self.db),
                sqlx::query(
                    "SELECT id, rule_id, action_type::text, duration_seconds, replacement \
                     FROM trust_safety.content_rule_action \
                     WHERE rule_id = ANY($1) ORDER BY rule_id, action_type, id",
                )
                .bind(&rule_ids)
                .fetch_all(&self.db),
            )?
        };

        let mut policies = BTreeMap::<Uuid, ContentPolicy>::new();
        for row in policy_rows {
            let id: Uuid = row.try_get("id")?;
            let authority = parse_authority(row.try_get("authority")?)?;
            let version: i64 = row.try_get("version")?;
            policies.insert(
                id,
                ContentPolicy {
                    id,
                    scope: PolicyScope {
                        authority,
                        id: row.try_get("scope_id")?,
                    },
                    enabled: row.try_get("enabled")?,
                    version: u64::try_from(version)
                        .map_err(|_| anyhow::anyhow!("content policy {id} has invalid version"))?,
                    rules: Vec::new(),
                },
            );
        }

        let mut rules = HashMap::<Uuid, (Uuid, PolicyRule)>::new();
        for row in rule_rows {
            let id: Uuid = row.try_get("id")?;
            let policy_id: Uuid = row.try_get("policy_id")?;
            anyhow::ensure!(
                policies.contains_key(&policy_id),
                "rule references unknown policy"
            );
            rules.insert(
                id,
                (
                    policy_id,
                    PolicyRule {
                        id,
                        name: row.try_get("name")?,
                        description: row.try_get("description")?,
                        enabled: row.try_get("enabled")?,
                        custom_reason: row.try_get("custom_reason")?,
                        created_by: row.try_get("created_by")?,
                        patterns: Vec::new(),
                        surfaces: Default::default(),
                        actions: Vec::new(),
                    },
                ),
            );
        }

        for row in pattern_rows {
            let rule_id: Uuid = row.try_get("rule_id")?;
            let (_, rule) = rules
                .get_mut(&rule_id)
                .ok_or_else(|| anyhow::anyhow!("pattern references unknown rule"))?;
            rule.patterns.push(RulePattern {
                id: row.try_get("id")?,
                pattern: row.try_get("pattern")?,
                pattern_type: parse_pattern_type(row.try_get("pattern_type")?)?,
            });
        }
        for row in surface_rows {
            let rule_id: Uuid = row.try_get("rule_id")?;
            let (_, rule) = rules
                .get_mut(&rule_id)
                .ok_or_else(|| anyhow::anyhow!("surface references unknown rule"))?;
            rule.surfaces
                .insert(parse_surface(row.try_get("surface")?)?);
        }
        for row in action_rows {
            let rule_id: Uuid = row.try_get("rule_id")?;
            let (_, rule) = rules
                .get_mut(&rule_id)
                .ok_or_else(|| anyhow::anyhow!("action references unknown rule"))?;
            let duration: Option<i64> = row.try_get("duration_seconds")?;
            rule.actions.push(PolicyAction {
                id: row.try_get("id")?,
                action_type: parse_action_type(row.try_get("action_type")?)?,
                duration_seconds: duration
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| anyhow::anyhow!("rule action has a negative duration"))?,
                replacement: row.try_get("replacement")?,
            });
        }

        let mut ordered_rules = rules.into_iter().collect::<Vec<_>>();
        ordered_rules.sort_by_key(|(rule_id, _)| *rule_id);
        for (_, (policy_id, mut rule)) in ordered_rules {
            rule.patterns.sort_by_key(|pattern| pattern.id);
            rule.actions.sort_by_key(|action| action.id);
            policies
                .get_mut(&policy_id)
                .expect("policy membership checked above")
                .rules
                .push(rule);
        }

        Ok(policies.into_values().collect())
    }
}

#[async_trait]
impl ContentPolicySource for PostgresContentPolicyRepository {
    async fn load_all(&self) -> anyhow::Result<Vec<ContentPolicy>> {
        self.load(None).await
    }

    async fn load_scope(&self, scope: &PolicyScope) -> anyhow::Result<Option<ContentPolicy>> {
        scope.validate().map_err(|error| anyhow::anyhow!(error))?;
        let mut policies = self.load(Some(scope)).await?;
        anyhow::ensure!(policies.len() <= 1, "content policy scope is not unique");
        Ok(policies.pop())
    }
}

pub const fn authority_name(authority: Authority) -> &'static str {
    match authority {
        Authority::Global => "GLOBAL",
        Authority::Hub => "HUB",
        Authority::Server => "SERVER",
    }
}

const fn pattern_type_name(pattern_type: WildcardPatternType) -> &'static str {
    match pattern_type {
        WildcardPatternType::ExactWord => "EXACT_WORD",
        WildcardPatternType::Prefix => "PREFIX",
        WildcardPatternType::Suffix => "SUFFIX",
        WildcardPatternType::Contains => "CONTAINS",
        WildcardPatternType::Phrase => "PHRASE",
    }
}

const fn surface_name(surface: Surface) -> &'static str {
    match surface {
        Surface::MessageContent => "MESSAGE_CONTENT",
        Surface::DisplayName => "DISPLAY_NAME",
        Surface::Username => "USERNAME",
        Surface::ServerName => "SERVER_NAME",
        Surface::HubName => "HUB_NAME",
        Surface::UrlDomain => "URL_DOMAIN",
    }
}

const fn action_type_name(action_type: PolicyActionType) -> &'static str {
    match action_type {
        PolicyActionType::Allow => "ALLOW",
        PolicyActionType::Block => "BLOCK",
        PolicyActionType::CensorMatch => "CENSOR_MATCH",
        PolicyActionType::StripLink => "STRIP_LINK",
        PolicyActionType::SuppressLinks => "SUPPRESS_LINKS",
        PolicyActionType::ReplaceName => "REPLACE_NAME",
        PolicyActionType::Log => "LOG",
        PolicyActionType::LobbyWarn => "LOBBY_WARN",
        PolicyActionType::LobbyBan => "LOBBY_BAN",
        PolicyActionType::Blacklist => "BLACKLIST",
        PolicyActionType::HubWarn => "HUB_WARN",
        PolicyActionType::HubMute => "HUB_MUTE",
        PolicyActionType::HubBan => "HUB_BAN",
    }
}

fn now_timestamp() -> prost_types::Timestamp {
    let now = chrono::Utc::now();
    prost_types::Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    }
}

fn parse_authority(value: &str) -> anyhow::Result<Authority> {
    match value {
        "GLOBAL" => Ok(Authority::Global),
        "HUB" => Ok(Authority::Hub),
        "SERVER" => Ok(Authority::Server),
        _ => anyhow::bail!("unknown content policy authority {value}"),
    }
}

fn parse_pattern_type(value: &str) -> anyhow::Result<WildcardPatternType> {
    match value {
        "EXACT_WORD" => Ok(WildcardPatternType::ExactWord),
        "PREFIX" => Ok(WildcardPatternType::Prefix),
        "SUFFIX" => Ok(WildcardPatternType::Suffix),
        "CONTAINS" => Ok(WildcardPatternType::Contains),
        "PHRASE" => Ok(WildcardPatternType::Phrase),
        _ => anyhow::bail!("unknown content pattern type {value}"),
    }
}

fn parse_surface(value: &str) -> anyhow::Result<Surface> {
    match value {
        "MESSAGE_CONTENT" => Ok(Surface::MessageContent),
        "DISPLAY_NAME" => Ok(Surface::DisplayName),
        "USERNAME" => Ok(Surface::Username),
        "SERVER_NAME" => Ok(Surface::ServerName),
        "HUB_NAME" => Ok(Surface::HubName),
        "URL_DOMAIN" => Ok(Surface::UrlDomain),
        _ => anyhow::bail!("unknown content policy surface {value}"),
    }
}

fn parse_action_type(value: &str) -> anyhow::Result<PolicyActionType> {
    match value {
        "ALLOW" => Ok(PolicyActionType::Allow),
        "BLOCK" => Ok(PolicyActionType::Block),
        "CENSOR_MATCH" => Ok(PolicyActionType::CensorMatch),
        "STRIP_LINK" => Ok(PolicyActionType::StripLink),
        "SUPPRESS_LINKS" => Ok(PolicyActionType::SuppressLinks),
        "REPLACE_NAME" => Ok(PolicyActionType::ReplaceName),
        "LOG" => Ok(PolicyActionType::Log),
        "LOBBY_WARN" => Ok(PolicyActionType::LobbyWarn),
        "LOBBY_BAN" => Ok(PolicyActionType::LobbyBan),
        "BLACKLIST" => Ok(PolicyActionType::Blacklist),
        "HUB_WARN" => Ok(PolicyActionType::HubWarn),
        "HUB_MUTE" => Ok(PolicyActionType::HubMute),
        "HUB_BAN" => Ok(PolicyActionType::HubBan),
        _ => anyhow::bail!("unknown content policy action {value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_enum_parsers_are_explicit() {
        assert_eq!(parse_authority("SERVER").unwrap(), Authority::Server);
        assert_eq!(parse_surface("URL_DOMAIN").unwrap(), Surface::UrlDomain);
        assert_eq!(
            parse_pattern_type("EXACT_WORD").unwrap(),
            WildcardPatternType::ExactWord
        );
        assert_eq!(
            parse_action_type("HUB_MUTE").unwrap(),
            PolicyActionType::HubMute
        );
        assert!(parse_action_type("REGEX").is_err());
    }
}
