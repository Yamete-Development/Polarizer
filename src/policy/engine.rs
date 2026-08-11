use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Instant,
};

use prost::Message;
use rand::Rng;
use uuid::Uuid;

use crate::{
    content_policy::{
        AnalyzedContent, ContentPolicyEvaluator, ContentPolicyPlan, Destination, PolicyActionType,
        Presentation, SenderFeedback, SideEffectRequest,
    },
    contract::prism,
};

use super::{
    features::FeatureRegistry,
    merge::merge_effects,
    model::{
        Action, Decision, Effect, EffectOrigin, EmittedEffect, ErrorBehavior, EvaluationResult,
        ExecutionTrace, PolicyLanguage, RuleTrace, ScopeType,
    },
    repository::{PersistOutcome, PolicyRepository, validate_effect_for_action},
    runtime::{
        CompiledArtifact, Diagnostic, DiagnosticSeverity, PolicyRuntime, RuntimeError,
        RuntimeEvaluation,
    },
};

pub struct PolicyEngine {
    repository: Arc<dyn PolicyRepository>,
    features: Arc<FeatureRegistry>,
    runtimes: HashMap<PolicyLanguage, Arc<dyn PolicyRuntime>>,
    content_policy: Option<Arc<ContentPolicyEvaluator>>,
    clean_allow_sample_rate: f64,
}

impl PolicyEngine {
    pub fn new(
        repository: Arc<dyn PolicyRepository>,
        features: Arc<FeatureRegistry>,
        clean_allow_sample_rate: f64,
    ) -> Self {
        Self {
            repository,
            features,
            runtimes: HashMap::new(),
            content_policy: None,
            clean_allow_sample_rate,
        }
    }

    pub fn register_content_policy(&mut self, evaluator: Arc<ContentPolicyEvaluator>) {
        self.content_policy = Some(evaluator);
    }

    pub fn register_runtime(&mut self, runtime: Arc<dyn PolicyRuntime>) {
        self.runtimes.insert(runtime.language(), runtime);
    }

    pub fn features(&self) -> &Arc<FeatureRegistry> {
        &self.features
    }

    pub async fn provider_activation_issues(
        &self,
        version: &super::model::PolicyVersion,
    ) -> Vec<String> {
        let required = version
            .manifest
            .required_features
            .iter()
            .map(|requirement| requirement.name.as_str())
            .collect::<BTreeSet<_>>();
        if required.is_empty() {
            return Vec::new();
        }
        let health = self.features.health().await;
        let known = health
            .iter()
            .map(|provider| provider.name.as_str())
            .collect::<BTreeSet<_>>();
        let mut issues = health
            .iter()
            .filter(|provider| required.contains(provider.name.as_str()) && !provider.healthy)
            .map(|provider| format!("{} is unhealthy", provider.name))
            .collect::<Vec<_>>();
        issues.extend(
            required
                .difference(&known)
                .map(|provider| format!("{provider} is not registered")),
        );
        issues
    }

    pub async fn validate_and_compile(
        &self,
        language: PolicyLanguage,
        source: &str,
        manifest: &super::model::PolicyManifest,
    ) -> Result<(Vec<Diagnostic>, Option<CompiledArtifact>), RuntimeError> {
        let Some(runtime) = self.runtimes.get(&language) else {
            return Ok((
                vec![Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "RUNTIME_UNAVAILABLE".into(),
                    message: "the requested policy runtime is not registered".into(),
                    line: None,
                    column: None,
                }],
                None,
            ));
        };
        let diagnostics = runtime.validate(source, manifest).await;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        {
            return Ok((diagnostics, None));
        }
        let artifact = runtime.compile(source, manifest).await?;
        Ok((diagnostics, Some(artifact)))
    }

    pub async fn evaluate_policy_version(
        &self,
        version: &super::model::PolicyVersion,
        action: &Action,
        features: &super::model::FeatureSnapshot,
    ) -> Result<Vec<RuntimeEvaluation>, RuntimeError> {
        let runtime = self
            .runtimes
            .get(&version.language)
            .ok_or_else(|| RuntimeError::Worker("runtime is not registered".into()))?;
        runtime
            .evaluate(
                &CompiledArtifact {
                    language: version.language,
                    runtime_version: version.runtime_version.clone(),
                    content_sha256: version.artifact_sha256.clone(),
                    bytes: version.compiled_artifact.clone(),
                },
                action,
                features,
            )
            .await
    }

    pub async fn evaluate(
        &self,
        action: &Action,
        shadow_only: bool,
    ) -> anyhow::Result<(EvaluationResult, PersistOutcome)> {
        let result = self.evaluate_result(action, shadow_only).await?;
        let outcome = if shadow_only {
            PersistOutcome::Applied
        } else {
            self.repository.persist_and_apply(action, &result).await?
        };
        Ok((result, outcome))
    }

    pub async fn evaluate_with_shadow(
        &self,
        action: &Action,
    ) -> anyhow::Result<(EvaluationResult, Option<EvaluationResult>, PersistOutcome)> {
        let active = self.evaluate_result(action, false).await?;
        let outcome = self.repository.persist_and_apply(action, &active).await?;
        if outcome == PersistOutcome::Duplicate {
            return Ok((active, None, outcome));
        }
        // Native message policy is authoritative for Hub/Call content. Do not
        // query or execute the legacy script-policy shadow path for the same
        // action after the hot-path snapshot evaluation has completed.
        if active.content_policy.is_some() {
            return Ok((active, None, outcome));
        }
        let shadow = self.evaluate_result(action, true).await?;
        if shadow.trace.policy_versions.is_empty() {
            return Ok((active, None, outcome));
        }
        self.repository
            .persist_shadow_comparison(action, &active, &shadow)
            .await?;
        Ok((active, Some(shadow), outcome))
    }

    async fn evaluate_result(
        &self,
        action: &Action,
        shadow_only: bool,
    ) -> anyhow::Result<EvaluationResult> {
        let started = Instant::now();
        let content_policy = if shadow_only {
            None
        } else {
            self.evaluate_content_policy(action)?
        };
        let policies = if content_policy.is_some() {
            Vec::new()
        } else {
            self.repository.active_policies(action).await?
        };
        let mut requirements = policies
            .iter()
            .filter(|policy| policy.shadow == shadow_only)
            .filter(|policy| policy.version.manifest.accepts(action))
            .flat_map(|policy| policy.version.manifest.required_features.clone())
            .collect::<Vec<_>>();

        let is_message_action = action.action_type.starts_with("hub.message.")
            || action.action_type.starts_with("lobby.message.");
        if is_message_action {
            requirements.push(crate::policy::model::FeatureRequirement {
                name: "restrictions.active".into(),
                error_behavior: crate::policy::model::ErrorBehavior::Hold,
                deadline_ms: 500,
                maximum_data_handling: action.data_handling,
                configuration: serde_json::Value::Null,
            });
        }

        let resolved_features = self.features.resolve(action, &requirements).await;
        let mut emitted = Vec::new();
        let mut rule_traces = Vec::new();
        let mut policy_versions = Vec::new();
        let mut terminal_global_block = false;
        let mut terminal_restriction_hold = false;
        let mut had_error = false;

        let active_restriction = if is_message_action {
            let reqs = vec![crate::policy::model::FeatureRequirement {
                name: "restrictions.active".into(),
                error_behavior: crate::policy::model::ErrorBehavior::Hold,
                deadline_ms: 500,
                maximum_data_handling: action.data_handling,
                configuration: serde_json::Value::Null,
            }];
            let snapshot = resolved_features.runtime_snapshot(&reqs);
            match snapshot.get("restrictions.active") {
                Some(feature) if feature.error.is_none() => {
                    match active_restriction_from_snapshot(&snapshot) {
                        Ok(restriction) => restriction,
                        Err(_) => {
                            had_error = true;
                            terminal_restriction_hold = true;
                            emitted.push(EmittedEffect {
                                origin: EffectOrigin {
                                    policy_bundle_id: Uuid::nil(),
                                    policy_version_id: Uuid::nil(),
                                    rule_id: "builtin.moderation".into(),
                                    scope: action.scope.clone(),
                                    priority: 1_001,
                                    mandatory: true,
                                },
                                effect: Effect::Hold {
                                    effect_id: format!("{}:restrictions-active", action.id),
                                    reason_codes: vec!["ACTIVE_RESTRICTIONS_UNAVAILABLE".into()],
                                    maximum_duration_ms: None,
                                },
                            });
                            None
                        }
                    }
                }
                Some(_) | None => {
                    had_error = true;
                    terminal_restriction_hold = true;
                    emitted.push(EmittedEffect {
                        origin: EffectOrigin {
                            policy_bundle_id: Uuid::nil(),
                            policy_version_id: Uuid::nil(),
                            rule_id: "builtin.moderation".into(),
                            scope: action.scope.clone(),
                            priority: 1_001,
                            mandatory: true,
                        },
                        effect: Effect::Hold {
                            effect_id: format!("{}:restrictions-active", action.id),
                            reason_codes: vec!["ACTIVE_RESTRICTIONS_UNAVAILABLE".into()],
                            maximum_duration_ms: None,
                        },
                    });
                    None
                }
            }
        } else {
            None
        };

        if let Some(restriction) = active_restriction.clone() {
            terminal_global_block = true;
            emitted.push(EmittedEffect {
                origin: EffectOrigin {
                    policy_bundle_id: Uuid::nil(),
                    policy_version_id: Uuid::nil(),
                    rule_id: "builtin.moderation".into(),
                    scope: action.scope.clone(),
                    priority: 1000,
                    mandatory: true,
                },
                effect: Effect::Block {
                    effect_id: Uuid::new_v4().to_string(),
                    reason_codes: vec![format!("ACTIVE_{}", restriction.restriction_type)],
                    public_reason: restriction.public_reason.clone(),
                    active_restriction: Some(restriction),
                },
            });
        } else if !terminal_restriction_hold && let Some(plan) = content_policy.as_ref() {
            emitted.extend(content_policy_effects(action, plan));
        }

        for policy in policies {
            if shadow_only && !policy.shadow {
                continue;
            }
            if !shadow_only && policy.shadow {
                continue;
            }
            policy_versions.push(policy.version.id);
            if terminal_global_block || terminal_restriction_hold {
                rule_traces.push(RuleTrace {
                    policy_version_id: policy.version.id,
                    rule_id: "*".into(),
                    skipped: true,
                    skip_reason: Some(if terminal_global_block {
                        "terminal global mandatory block".into()
                    } else {
                        "active restriction state unavailable".into()
                    }),
                    conditions: Vec::new(),
                    emitted_effects: Vec::new(),
                    error: None,
                    latency_micros: 0,
                });
                continue;
            }
            if !policy.version.manifest.accepts(action) {
                rule_traces.push(RuleTrace {
                    policy_version_id: policy.version.id,
                    rule_id: "*".into(),
                    skipped: true,
                    skip_reason: Some("action type or schema version not accepted".into()),
                    conditions: Vec::new(),
                    emitted_effects: Vec::new(),
                    error: None,
                    latency_micros: 0,
                });
                continue;
            }

            let features =
                resolved_features.runtime_snapshot(&policy.version.manifest.required_features);

            let policy_started = Instant::now();
            let failed_requirement =
                policy
                    .version
                    .manifest
                    .required_features
                    .iter()
                    .find(|requirement| {
                        features
                            .get(&requirement.name)
                            .is_some_and(|value| value.error.is_some())
                    });
            if let Some(requirement) = failed_requirement {
                had_error = true;
                let effects = fallback_effects(
                    policy.version.id,
                    &requirement.name,
                    requirement.error_behavior,
                );
                let traced_effects = effects
                    .into_iter()
                    .map(|effect| EmittedEffect {
                        origin: origin(&policy, "feature.error"),
                        effect,
                    })
                    .collect::<Vec<_>>();
                emitted.extend(traced_effects.iter().cloned());
                rule_traces.push(RuleTrace {
                    policy_version_id: policy.version.id,
                    rule_id: "feature.error".into(),
                    skipped: false,
                    skip_reason: None,
                    conditions: Vec::new(),
                    emitted_effects: traced_effects,
                    error: Some(format!("required feature {} failed", requirement.name)),
                    latency_micros: elapsed_micros(policy_started),
                });
                continue;
            }

            let Some(runtime) = self.runtimes.get(&policy.version.language) else {
                had_error = true;
                let effects = fallback_effects(
                    policy.version.id,
                    "runtime.unregistered",
                    policy.version.manifest.runtime_error_behavior,
                );
                let traced_effects = effects
                    .into_iter()
                    .map(|effect| EmittedEffect {
                        origin: origin(&policy, "runtime.error"),
                        effect,
                    })
                    .collect::<Vec<_>>();
                emitted.extend(traced_effects.iter().cloned());
                rule_traces.push(RuleTrace {
                    policy_version_id: policy.version.id,
                    rule_id: "runtime.error".into(),
                    skipped: false,
                    skip_reason: None,
                    conditions: Vec::new(),
                    emitted_effects: traced_effects,
                    error: Some("runtime is not registered".into()),
                    latency_micros: elapsed_micros(policy_started),
                });
                continue;
            };
            let artifact = CompiledArtifact {
                language: policy.version.language,
                runtime_version: policy.version.runtime_version.clone(),
                content_sha256: policy.version.artifact_sha256.clone(),
                bytes: policy.version.compiled_artifact.clone(),
            };
            match runtime.evaluate(&artifact, action, &features).await {
                Ok(evaluations) => {
                    for evaluation in evaluations {
                        if let Some(error) = evaluation.effects.iter().find_map(|effect| {
                            validate_effect_for_action(effect, action)
                                .err()
                                .map(|error| error.to_string())
                        }) {
                            had_error = true;
                            let traced_effects = fallback_effects(
                                policy.version.id,
                                "malformed_effect",
                                policy.version.manifest.runtime_error_behavior,
                            )
                            .into_iter()
                            .map(|effect| EmittedEffect {
                                origin: origin(&policy, &evaluation.rule_id),
                                effect,
                            })
                            .collect::<Vec<_>>();
                            emitted.extend(traced_effects.iter().cloned());
                            rule_traces.push(RuleTrace {
                                policy_version_id: policy.version.id,
                                rule_id: evaluation.rule_id,
                                skipped: false,
                                skip_reason: None,
                                conditions: evaluation.conditions,
                                emitted_effects: traced_effects,
                                error: Some(format!("malformed policy effect: {error}")),
                                latency_micros: elapsed_micros(policy_started),
                            });
                            continue;
                        }
                        let has_global_block = policy.bundle.scope.scope_type
                            == ScopeType::Platform
                            && policy.bundle.mandatory
                            && evaluation
                                .effects
                                .iter()
                                .any(|effect| matches!(effect, Effect::Block { .. }));
                        let traced_effects = evaluation
                            .effects
                            .into_iter()
                            .map(|effect| EmittedEffect {
                                origin: origin(&policy, &evaluation.rule_id),
                                effect,
                            })
                            .collect::<Vec<_>>();
                        emitted.extend(traced_effects.iter().cloned());
                        rule_traces.push(RuleTrace {
                            policy_version_id: policy.version.id,
                            rule_id: evaluation.rule_id,
                            skipped: false,
                            skip_reason: None,
                            conditions: evaluation.conditions,
                            emitted_effects: traced_effects,
                            error: None,
                            latency_micros: elapsed_micros(policy_started),
                        });
                        terminal_global_block |= has_global_block;
                    }
                }
                Err(error) => {
                    had_error = true;
                    let effects = fallback_effects(
                        policy.version.id,
                        "runtime.error",
                        policy.version.manifest.runtime_error_behavior,
                    );
                    let traced_effects = effects
                        .into_iter()
                        .map(|effect| EmittedEffect {
                            origin: origin(&policy, "runtime.error"),
                            effect,
                        })
                        .collect::<Vec<_>>();
                    emitted.extend(traced_effects.iter().cloned());
                    rule_traces.push(RuleTrace {
                        policy_version_id: policy.version.id,
                        rule_id: "runtime.error".into(),
                        skipped: false,
                        skip_reason: None,
                        conditions: Vec::new(),
                        emitted_effects: traced_effects,
                        error: Some(error.to_string()),
                        latency_micros: elapsed_micros(policy_started),
                    });
                }
            }
        }

        let merged = merge_effects(emitted);
        let review = merged
            .accepted
            .iter()
            .any(|item| matches!(item.effect, Effect::RouteReview { .. }));
        let sampled = had_error
            || review
            || matches!(merged.decision, Decision::Block | Decision::Hold)
            || rand::thread_rng().gen_bool(self.clean_allow_sample_rate.clamp(0.0, 1.0));
        let trace_id = Uuid::now_v7();
        let result = EvaluationResult {
            id: Uuid::now_v7(),
            action_id: action.id,
            decision: merged.decision,
            reason_codes: merged.reason_codes.clone(),
            accepted_effects: merged.accepted.clone(),
            rejected_effects: merged.rejected.clone(),
            shadow: shadow_only,
            trace: ExecutionTrace {
                id: trace_id,
                action_id: action.id,
                action_schema_version: action.schema_version,
                policy_versions,
                features: resolved_features.trace_snapshot(),
                rules: rule_traces,
                accepted_effect_ids: merged
                    .accepted
                    .iter()
                    .map(|item| item.effect.id().to_owned())
                    .collect(),
                rejected_effects: merged.rejected,
                final_decision: merged.decision,
                reason_codes: merged.reason_codes,
                total_latency_micros: elapsed_micros(started),
                created_at: chrono::Utc::now(),
                sampled,
            },
            content_policy,
        };
        Ok(result)
    }

    fn evaluate_content_policy(
        &self,
        action: &Action,
    ) -> anyhow::Result<Option<ContentPolicyPlan>> {
        let Some(evaluator) = self.content_policy.as_ref() else {
            return Ok(None);
        };
        let is_hub_message = action.action_type.starts_with("hub.message.");
        let is_call_message = action.action_type.starts_with("lobby.message.");
        if (!is_hub_message && !is_call_message)
            || action
                .attributes
                .get("content")
                .and_then(serde_json::Value::as_str)
                .is_none()
        {
            return Ok(None);
        }

        let presentation = presentation_from_action(action);
        let analyzed = AnalyzedContent::from_presentation(&presentation);
        let subject_id = action.subject.user_id.as_deref().unwrap_or("anonymous");
        let destinations = action
            .prism_payload
            .as_deref()
            .map(prism::PrismStreamPayload::decode)
            .transpose()?
            .map(|payload| {
                payload
                    .targets
                    .into_iter()
                    .enumerate()
                    .map(|(target_index, target)| Destination {
                        target_index,
                        server_id: target.guild_id.unwrap_or_default(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if is_call_message {
            return Ok(Some(ContentPolicyPlan::Call(
                evaluator.evaluate_call_for_destinations(
                    subject_id,
                    &presentation,
                    &analyzed,
                    &destinations,
                )?,
            )));
        }

        Ok(Some(ContentPolicyPlan::Hub(evaluator.evaluate_hub(
            subject_id,
            &action.scope.id,
            &presentation,
            &analyzed,
            &destinations,
        )?)))
    }
}

fn presentation_from_action(action: &Action) -> Presentation {
    let field = |name: &str| {
        Arc::<str>::from(
            action
                .attributes
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
        )
    };
    Presentation {
        message_content: field("content"),
        display_name: field("display_name"),
        username: field("username"),
        server_name: field("server_name"),
        hub_name: field("hub_name"),
        ..Presentation::default()
    }
}

fn active_restriction_from_snapshot(
    snapshot: &crate::policy::model::FeatureSnapshot,
) -> anyhow::Result<Option<crate::policy::model::ActiveRestriction>> {
    let value = snapshot
        .get("restrictions.active")
        .and_then(|feature| feature.value.as_ref())
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("active restriction feature is malformed"))?;

    let restrictions = value
        .iter()
        .map(|restriction| {
            let restriction = restriction
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("active restriction entry is malformed"))?;
            let restriction_type = restriction
                .get("restriction_type")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("active restriction type is missing"))?;
            if !matches!(restriction_type, "BAN" | "MUTE" | "BLACKLIST") {
                return Ok(None);
            }
            let scope_type = restriction
                .get("scope_type")
                .or_else(|| restriction.get("scope").and_then(|scope| scope.get("type")))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("PLATFORM");
            let scope_id = restriction
                .get("scope_id")
                .or_else(|| restriction.get("scope").and_then(|scope| scope.get("id")))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let scope_type = match scope_type {
                "HUB" => ScopeType::Hub,
                "LOBBY" => ScopeType::Lobby,
                "PRODUCT" => ScopeType::Product,
                "INCIDENT_OVERLAY" => ScopeType::IncidentOverlay,
                _ => ScopeType::Platform,
            };
            let product = restriction
                .get("scope_product")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| match value {
                    "HUB" => Some(crate::policy::model::Product::Hub),
                    "LOBBY" => Some(crate::policy::model::Product::Lobby),
                    _ => None,
                })
                .or(match scope_type {
                    ScopeType::Hub => Some(crate::policy::model::Product::Hub),
                    ScopeType::Lobby => Some(crate::policy::model::Product::Lobby),
                    _ => None,
                });
            let expires_at = restriction
                .get("expires_at")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&chrono::Utc));
            Ok(Some(crate::policy::model::ActiveRestriction {
                id: restriction
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                restriction_type: restriction_type.to_owned(),
                scope: crate::policy::model::Scope {
                    scope_type,
                    id: scope_id.to_owned(),
                    product,
                },
                public_reason: restriction
                    .get("public_reason")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                expires_at,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .min_by_key(|restriction| {
            let type_rank = match restriction.restriction_type.as_str() {
                "BLACKLIST" => 0,
                "BAN" => 1,
                "MUTE" => 2,
                _ => 3,
            };
            let scope_rank = match restriction.scope.scope_type {
                ScopeType::Platform => 0,
                ScopeType::Product => 1,
                ScopeType::Hub | ScopeType::Lobby => 2,
                ScopeType::IncidentOverlay => 3,
            };
            (type_rank, scope_rank, restriction.id.clone())
        });
    Ok(restrictions)
}

fn content_policy_effects(action: &Action, plan: &ContentPolicyPlan) -> Vec<EmittedEffect> {
    let (blocked_by, side_effects, feedback_attribution) = match plan {
        ContentPolicyPlan::Hub(plan) => {
            let blocked_by = if plan.global.delivery.is_blocked() {
                &plan.global.delivery.blocked_by
            } else {
                &plan.hub.delivery.blocked_by
            };
            let feedback_attribution = blocked_by.first().or_else(|| {
                plan.destinations
                    .iter()
                    .find_map(|destination| destination.blocked_by.first())
            });
            (
                blocked_by.as_slice(),
                plan.side_effects.as_slice(),
                feedback_attribution,
            )
        }
        ContentPolicyPlan::Call(plan) => {
            let blocked_by = plan.global.delivery.blocked_by.as_slice();
            let feedback_attribution = blocked_by.first().or_else(|| {
                plan.destinations
                    .iter()
                    .find_map(|destination| destination.blocked_by.first())
            });
            (
                blocked_by,
                plan.side_effects.as_slice(),
                feedback_attribution,
            )
        }
    };

    let mut emitted = Vec::new();
    if let Some(attribution) = blocked_by.first() {
        emitted.push(native_emitted(
            attribution,
            scope_from_native(&attribution.scope),
            Effect::Block {
                effect_id: format!("content-policy:block:{}", attribution.rule_id),
                reason_codes: vec![format!(
                    "CONTENT_POLICY_{}_BLOCK",
                    authority_name(attribution.scope.authority)
                )],
                public_reason: attribution.custom_reason.clone(),
                active_restriction: None,
            },
        ));
    }
    let server_filtered = match plan {
        ContentPolicyPlan::Hub(plan) => plan.sender_feedback.as_ref(),
        ContentPolicyPlan::Call(plan) => plan.sender_feedback.as_ref(),
    };
    if matches!(server_filtered, Some(SenderFeedback::ServerFilters { .. }))
        && let Some(attribution) = feedback_attribution
    {
        emitted.push(native_emitted(
            attribution,
            action.scope.clone(),
            Effect::Allow {
                effect_id: format!("content-policy:server-filter:{}", action.id),
                reason_codes: vec!["CONTENT_POLICY_SERVER_FILTERED".into()],
            },
        ));
    }
    for request in side_effects {
        emitted.extend(native_side_effects(action, request, plan));
    }
    emitted
}

fn native_side_effects(
    action: &Action,
    request: &SideEffectRequest,
    plan: &ContentPolicyPlan,
) -> Vec<EmittedEffect> {
    let duration_ms = request
        .duration_seconds
        .and_then(|value| value.checked_mul(1_000));
    let reason = request
        .attribution
        .custom_reason
        .clone()
        .unwrap_or_else(|| {
            format!(
                "Matched content policy rule {}",
                request.attribution.rule_name
            )
        });
    let subject = action.subject.clone();
    let action_scope = action.scope.clone();
    let platform_scope = super::model::Scope {
        scope_type: ScopeType::Platform,
        id: String::new(),
        product: None,
    };
    let make =
        |scope: super::model::Scope, effect| native_emitted(&request.attribution, scope, effect);
    let id = |suffix: &str| {
        format!(
            "content-policy:{}:{}:{suffix}",
            request.attribution.rule_id, action.id
        )
    };

    match request.action_type {
        PolicyActionType::Log => vec![make(
            action_scope,
            Effect::Flag {
                effect_id: id("log"),
                flag_type: "CONTENT_POLICY_LOG".into(),
                severity: 50.0,
                evidence: serde_json::json!({
                    "policy_id": request.attribution.policy_id,
                    "policy_version": request.attribution.policy_version,
                    "rule_id": request.attribution.rule_id,
                    "rule_name": request.attribution.rule_name,
                    "custom_reason": request.attribution.custom_reason,
                    "action": policy_action_name(request.action_type),
                    "original_content": action.attributes
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    "transformed_content": representative_transformed_content(plan),
                    "scope_authority": authority_name(request.attribution.scope.authority),
                    "scope_id": request.attribution.scope.id,
                }),
            },
        )],
        PolicyActionType::HubWarn if action.scope.scope_type == ScopeType::Hub => vec![make(
            action_scope,
            Effect::CreateInfraction {
                effect_id: id("hub-warning"),
                subject,
                infraction_type: "WARNING".into(),
                reason,
                duration_ms,
                enforcement: None,
            },
        )],
        PolicyActionType::HubMute if action.scope.scope_type == ScopeType::Hub => vec![make(
            action_scope.clone(),
            Effect::CreateInfraction {
                effect_id: id("hub-mute-infraction"),
                subject: subject.clone(),
                infraction_type: "MUTE".into(),
                reason: reason.clone(),
                duration_ms,
                enforcement: Some(crate::policy::model::Enforcement {
                    subject,
                    restriction_type: "MUTE".into(),
                    reason,
                    duration_ms,
                }),
            },
        )],
        PolicyActionType::HubBan if action.scope.scope_type == ScopeType::Hub => vec![make(
            action_scope.clone(),
            Effect::CreateInfraction {
                effect_id: id("hub-ban-infraction"),
                subject: subject.clone(),
                infraction_type: "BAN".into(),
                reason: reason.clone(),
                duration_ms,
                enforcement: Some(crate::policy::model::Enforcement {
                    subject,
                    restriction_type: "BAN".into(),
                    reason,
                    duration_ms,
                }),
            },
        )],
        PolicyActionType::LobbyWarn if action.scope.scope_type == ScopeType::Lobby => vec![make(
            action_scope,
            Effect::CreateInfraction {
                effect_id: id("lobby-warning"),
                subject,
                infraction_type: "WARNING".into(),
                reason,
                duration_ms,
                enforcement: None,
            },
        )],
        PolicyActionType::LobbyBan if action.scope.scope_type == ScopeType::Lobby => vec![make(
            action_scope.clone(),
            Effect::CreateInfraction {
                effect_id: id("lobby-ban-infraction"),
                subject: subject.clone(),
                infraction_type: "BAN".into(),
                reason: reason.clone(),
                duration_ms,
                enforcement: Some(crate::policy::model::Enforcement {
                    subject,
                    restriction_type: "BAN".into(),
                    reason,
                    duration_ms,
                }),
            },
        )],
        PolicyActionType::Blacklist => vec![make(
            platform_scope,
            Effect::CreateInfraction {
                effect_id: id("blacklist-infraction"),
                subject: subject.clone(),
                infraction_type: "BAN".into(),
                reason: reason.clone(),
                duration_ms,
                enforcement: Some(crate::policy::model::Enforcement {
                    subject,
                    restriction_type: "BLACKLIST".into(),
                    reason,
                    duration_ms,
                }),
            },
        )],
        _ => Vec::new(),
    }
}

fn representative_transformed_content(plan: &ContentPolicyPlan) -> String {
    match plan {
        ContentPolicyPlan::Call(plan) => plan
            .variants
            .values()
            .next()
            .map(|variant| variant.message_content.to_string())
            .unwrap_or_default(),
        ContentPolicyPlan::Hub(plan) => {
            let mut variants = plan.variants.values();
            let Some(first) = variants.next() else {
                return String::new();
            };
            if variants
                .all(|variant| variant.message_content.as_ref() == first.message_content.as_ref())
            {
                first.message_content.to_string()
            } else {
                "<varies by destination policy>".to_owned()
            }
        }
    }
}

const fn policy_action_name(action: PolicyActionType) -> &'static str {
    match action {
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

fn native_emitted(
    attribution: &crate::content_policy::resolver::EffectAttribution,
    scope: super::model::Scope,
    effect: Effect,
) -> EmittedEffect {
    EmittedEffect {
        origin: EffectOrigin {
            policy_bundle_id: attribution.policy_id,
            policy_version_id: Uuid::nil(),
            rule_id: attribution.rule_id.to_string(),
            scope,
            priority: 2_000 - i32::from(attribution.scope.authority.precedence()),
            mandatory: true,
        },
        effect,
    }
}

fn scope_from_native(scope: &crate::content_policy::PolicyScope) -> super::model::Scope {
    match scope.authority {
        crate::content_policy::Authority::Global => super::model::Scope {
            scope_type: ScopeType::Platform,
            id: String::new(),
            product: None,
        },
        crate::content_policy::Authority::Hub => super::model::Scope {
            scope_type: ScopeType::Hub,
            id: scope.id.clone(),
            product: Some(super::model::Product::Hub),
        },
        crate::content_policy::Authority::Server => super::model::Scope {
            scope_type: ScopeType::Platform,
            id: scope.id.clone(),
            product: None,
        },
    }
}

fn authority_name(authority: crate::content_policy::Authority) -> &'static str {
    match authority {
        crate::content_policy::Authority::Global => "GLOBAL",
        crate::content_policy::Authority::Hub => "HUB",
        crate::content_policy::Authority::Server => "SERVER",
    }
}

fn origin(policy: &super::repository::ActivePolicy, rule_id: &str) -> EffectOrigin {
    EffectOrigin {
        policy_bundle_id: policy.bundle.id,
        policy_version_id: policy.version.id,
        rule_id: rule_id.to_owned(),
        scope: policy.bundle.scope.clone(),
        priority: policy.bundle.priority,
        mandatory: policy.bundle.mandatory,
    }
}

fn fallback_effects(
    policy_version_id: Uuid,
    component: &str,
    behavior: ErrorBehavior,
) -> Vec<Effect> {
    let prefix = format!("{policy_version_id}:{component}");
    match behavior {
        ErrorBehavior::Hold => vec![Effect::Hold {
            effect_id: format!("{prefix}:hold"),
            reason_codes: vec!["POLICY_DEPENDENCY_UNAVAILABLE".into()],
            maximum_duration_ms: None,
        }],
        ErrorBehavior::Review => vec![
            Effect::Hold {
                effect_id: format!("{prefix}:hold"),
                reason_codes: vec!["POLICY_REVIEW_REQUIRED".into()],
                maximum_duration_ms: None,
            },
            Effect::RouteReview {
                effect_id: format!("{prefix}:review"),
                queue: "policy-errors".into(),
                priority: 0,
                reason_codes: vec!["POLICY_REVIEW_REQUIRED".into()],
            },
        ],
        ErrorBehavior::Continue => Vec::new(),
    }
}

fn elapsed_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_policy::DestinationDecision;
    use crate::policy::{
        features::{
            FeatureProvider, FeatureRegistry, ProviderCategory, ProviderOutput,
            text::NormalizedTextProvider,
        },
        ir::{POLICY_IR_RUNTIME_VERSION, PolicyIrRuntime},
        model::{
            DataHandlingClass, ErrorBehavior, FeatureRequirement, PolicyBundle, PolicyManifest,
            PolicyState, PolicyVersion, Product, Scope, Subject,
        },
        repository::{ActivePolicy, InMemoryPolicyRepository},
        runtime::PolicyRuntime,
    };
    use chrono::Utc;
    use std::collections::BTreeSet;

    struct ActiveRestrictionProvider {
        restriction_type: &'static str,
    }

    #[test]
    fn native_content_feedback_has_no_notify_or_destination_details() {
        let attribution = crate::content_policy::resolver::EffectAttribution {
            policy_id: Uuid::from_u128(1),
            policy_version: 1,
            scope: crate::content_policy::PolicyScope::server("server-a"),
            rule_id: Uuid::from_u128(2),
            rule_name: "server-block".into(),
            custom_reason: None,
        };
        let plan = ContentPolicyPlan::Call(crate::content_policy::CallPolicyPlan {
            global: crate::content_policy::ResolvedScopeDecision {
                scope: crate::content_policy::PolicyScope::global(),
                matched_rules: Vec::new(),
                delivery: crate::content_policy::DeliveryEffects::default(),
                side_effects: Vec::new(),
            },
            variant: None,
            destinations: vec![DestinationDecision {
                target_index: 0,
                server_id: "server-a".into(),
                policy_id: Some(attribution.policy_id),
                policy_version: Some(attribution.policy_version),
                matched_rule_ids: vec![attribution.rule_id],
                blocked_by: vec![attribution],
                variant_fingerprint: None,
            }],
            variants: std::collections::BTreeMap::new(),
            side_effects: Vec::new(),
            sender_feedback: Some(SenderFeedback::ServerFilters {
                destination_count: 1,
            }),
            evaluated_server_profiles: 1,
        });
        let action = Action {
            id: Uuid::now_v7(),
            action_type: "lobby.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Lobby,
                id: "lobby-1".into(),
                product: Some(Product::Lobby),
            },
            subject: Subject {
                user_id: Some("user-1".into()),
                ..Subject::default()
            },
            occurred_at: Utc::now(),
            attributes: serde_json::json!({}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        };

        let effects = content_policy_effects(&action, &plan);
        assert!(
            effects
                .iter()
                .any(|item| matches!(item.effect, Effect::Allow { .. }))
        );
        assert!(
            !effects
                .iter()
                .any(|item| matches!(item.effect, Effect::Notify { .. }))
        );
        let serialized = serde_json::to_string(&effects).unwrap();
        assert!(!serialized.contains("filtered_destinations"));
    }

    #[async_trait::async_trait]
    impl FeatureProvider for ActiveRestrictionProvider {
        fn name(&self) -> &str {
            "restrictions.active"
        }

        fn version(&self) -> &str {
            "test"
        }

        fn category(&self) -> ProviderCategory {
            ProviderCategory::State
        }

        async fn resolve(
            &self,
            _action: &Action,
            _configuration: &serde_json::Value,
        ) -> Result<ProviderOutput, crate::policy::features::ProviderError> {
            Ok(ProviderOutput {
                value: serde_json::json!([{"restriction_type": self.restriction_type}]),
                cache_hit: false,
                input_hash: None,
            })
        }
    }

    #[tokio::test]
    async fn message_actions_block_active_bans_and_mutes_without_policy_bundle() {
        for restriction_type in ["BAN", "MUTE"] {
            let repo = Arc::new(InMemoryPolicyRepository::default());
            let features = Arc::new(
                FeatureRegistry::from_providers([Arc::new(ActiveRestrictionProvider {
                    restriction_type,
                }) as Arc<dyn FeatureProvider>])
                .unwrap(),
            );
            let mut engine = PolicyEngine::new(repo, features, 0.0);
            engine.register_runtime(Arc::new(PolicyIrRuntime));

            let action = Action {
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
                    ..Subject::default()
                },
                occurred_at: Utc::now(),
                attributes: serde_json::json!({}),
                data_handling: DataHandlingClass::Sensitive,
                prism_payload: None,
            };

            let (result, _) = engine.evaluate(&action, false).await.unwrap();

            assert_eq!(
                result.decision,
                Decision::Block,
                "{restriction_type} must block"
            );
            assert!(
                result
                    .reason_codes
                    .contains(&format!("ACTIVE_{restriction_type}"))
            );
        }
    }

    #[tokio::test]
    async fn message_actions_hold_when_active_restrictions_are_unavailable() {
        let repo = Arc::new(InMemoryPolicyRepository::default());
        let mut engine = PolicyEngine::new(repo, Arc::new(FeatureRegistry::default()), 0.0);
        engine.register_runtime(Arc::new(PolicyIrRuntime));

        let action = Action {
            id: Uuid::now_v7(),
            action_type: "lobby.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Lobby,
                id: "lobby-1".into(),
                product: Some(Product::Lobby),
            },
            subject: Subject {
                user_id: Some("user-1".into()),
                ..Subject::default()
            },
            occurred_at: Utc::now(),
            attributes: serde_json::json!({}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        };

        let (result, _) = engine.evaluate(&action, false).await.unwrap();

        assert_eq!(result.decision, Decision::Hold);
        assert!(
            result
                .reason_codes
                .contains(&"ACTIVE_RESTRICTIONS_UNAVAILABLE".to_owned())
        );
    }

    #[test]
    fn product_restriction_snapshot_preserves_lobby_product() {
        let mut snapshot = crate::policy::model::FeatureSnapshot::new();
        snapshot.insert(
            "restrictions.active".into(),
            crate::policy::model::FeatureValue {
                provider: "postgres".into(),
                provider_version: "postgres-v2".into(),
                value: Some(serde_json::json!([{
                    "id": "restriction-1",
                    "restriction_type": "BAN",
                    "scope_type": "PRODUCT",
                    "scope_id": "",
                    "scope_product": "LOBBY",
                    "reason": "lobby ban",
                    "expires_at": null
                }])),
                error: None,
                latency_micros: 0,
                cache_hit: false,
                input_hash: None,
            },
        );

        let restriction = active_restriction_from_snapshot(&snapshot)
            .expect("valid restriction snapshot")
            .expect("restriction exists");

        assert_eq!(restriction.scope.scope_type, ScopeType::Product);
        assert_eq!(
            restriction.scope.product,
            Some(crate::policy::model::Product::Lobby)
        );
    }

    #[tokio::test]
    async fn engine_enforces_global_precedence_and_persists_once() {
        let repo = Arc::new(InMemoryPolicyRepository::default());
        let manifest = PolicyManifest {
            accepted_action_types: BTreeSet::new(),
            accepted_schema_versions: BTreeSet::new(),
            required_features: vec![],
            capabilities: BTreeSet::new(),
            runtime_error_behavior: ErrorBehavior::Hold,
        };
        let runtime = Arc::new(PolicyIrRuntime);
        let global_source = r#"{"rules":[{"id":"global","effects":[{"type":"BLOCK","effect_id":"global-block","reason_codes":["GLOBAL"],"public_reason":null}]}]}"#;
        let hub_source = r#"{"rules":[{"id":"hub","effects":[{"type":"ALLOW","effect_id":"hub-allow","reason_codes":[]}]}]}"#;
        let global_artifact = runtime.compile(global_source, &manifest).await.unwrap();
        let hub_artifact = runtime.compile(hub_source, &manifest).await.unwrap();
        repo.policies.write().await.extend([
            active_policy(
                ScopeType::Platform,
                true,
                global_source,
                global_artifact.bytes,
                &manifest,
            ),
            active_policy(
                ScopeType::Hub,
                false,
                hub_source,
                hub_artifact.bytes,
                &manifest,
            ),
        ]);
        let features = FeatureRegistry::from_providers([Arc::new(ActiveRestrictionProvider {
            restriction_type: "",
        }) as Arc<dyn FeatureProvider>])
        .unwrap();
        let mut engine = PolicyEngine::new(repo.clone(), Arc::new(features), 0.0);
        engine.register_runtime(runtime);
        let action = Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub".into(),
                product: Some(Product::Hub),
            },
            subject: Subject::default(),
            occurred_at: Utc::now(),
            attributes: serde_json::json!({}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        };
        let (result, outcome) = engine.evaluate(&action, false).await.unwrap();
        assert_eq!(result.decision, Decision::Block);
        assert_eq!(outcome, PersistOutcome::Applied);
        let (_, duplicate) = engine.evaluate(&action, false).await.unwrap();
        assert_eq!(duplicate, PersistOutcome::Duplicate);
    }

    #[tokio::test]
    async fn malformed_runtime_effect_uses_declared_fail_closed_behavior() {
        let repo = Arc::new(InMemoryPolicyRepository::default());
        let manifest = PolicyManifest {
            accepted_action_types: BTreeSet::new(),
            accepted_schema_versions: BTreeSet::new(),
            required_features: vec![],
            capabilities: BTreeSet::new(),
            runtime_error_behavior: ErrorBehavior::Hold,
        };
        let runtime = Arc::new(PolicyIrRuntime);
        let source = r#"{"rules":[{"id":"cross-entity","effects":[{"type":"CREATE_RESTRICTION","effect_id":"bad","subject":{"user_id":"different-user"},"restriction_type":"BAN","reason":"unsafe target","duration_ms":null}]}]}"#;
        let artifact = runtime.compile(source, &manifest).await.unwrap();
        repo.policies.write().await.push(active_policy(
            ScopeType::Hub,
            true,
            source,
            artifact.bytes,
            &manifest,
        ));
        let features = FeatureRegistry::from_providers([Arc::new(ActiveRestrictionProvider {
            restriction_type: "",
        }) as Arc<dyn FeatureProvider>])
        .unwrap();
        let mut engine = PolicyEngine::new(repo, Arc::new(features), 0.0);
        engine.register_runtime(runtime);
        let action = Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub".into(),
                product: Some(Product::Hub),
            },
            subject: Subject {
                user_id: Some("action-user".into()),
                ..Subject::default()
            },
            occurred_at: Utc::now(),
            attributes: serde_json::json!({}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        };

        let (result, _) = engine.evaluate(&action, false).await.unwrap();

        assert_eq!(result.decision, Decision::Hold);
        assert!(
            result.trace.rules[0]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("malformed policy effect"))
        );
        assert!(
            result
                .accepted_effects
                .iter()
                .any(|effect| { matches!(effect.effect, Effect::Hold { .. }) })
        );
    }

    #[tokio::test]
    async fn engine_trace_uses_provider_redaction_without_changing_runtime_values() {
        let repo = Arc::new(InMemoryPolicyRepository::default());
        let manifest = PolicyManifest {
            accepted_action_types: BTreeSet::from(["hub.message.created".into()]),
            accepted_schema_versions: BTreeSet::from([1]),
            required_features: vec![FeatureRequirement {
                name: "text.normalized".into(),
                error_behavior: ErrorBehavior::Hold,
                deadline_ms: 25,
                maximum_data_handling: DataHandlingClass::Sensitive,
                configuration: serde_json::json!({}),
            }],
            capabilities: BTreeSet::new(),
            runtime_error_behavior: ErrorBehavior::Hold,
        };
        let runtime = Arc::new(PolicyIrRuntime);
        let source = r#"{"rules":[{"id":"read-normalized","when":{"operator":"eq","left":{"source":"feature","name":"text.normalized","path":"text"},"right":{"source":"literal","value":"private phrase"}},"effects":[{"type":"BLOCK","effect_id":"matched-private-phrase","reason_codes":["MATCHED"],"public_reason":null}]}]}"#;
        let artifact = runtime.compile(source, &manifest).await.unwrap();
        repo.policies.write().await.push(active_policy(
            ScopeType::Hub,
            true,
            source,
            artifact.bytes,
            &manifest,
        ));
        let features = Arc::new(FeatureRegistry::default());
        features
            .register(Arc::new(NormalizedTextProvider))
            .await
            .unwrap();
        features
            .register(Arc::new(ActiveRestrictionProvider {
                restriction_type: "",
            }))
            .await
            .unwrap();
        let mut engine = PolicyEngine::new(repo, features, 0.0);
        engine.register_runtime(runtime);
        let action = Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub".into(),
                product: Some(Product::Hub),
            },
            subject: Subject::default(),
            occurred_at: Utc::now(),
            attributes: serde_json::json!({"content": "Private Phrase"}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        };

        let (result, _) = engine.evaluate(&action, false).await.unwrap();

        assert_eq!(result.decision, Decision::Block);
        let persisted_trace = serde_json::to_string(&result.trace).unwrap();
        assert!(!persisted_trace.contains("Private Phrase"));
        assert!(!persisted_trace.contains("private phrase"));
        assert!(persisted_trace.contains("normalized_text_sha256"));
    }

    fn active_policy(
        scope_type: ScopeType,
        mandatory: bool,
        source: &str,
        bytes: Vec<u8>,
        manifest: &PolicyManifest,
    ) -> ActivePolicy {
        let bundle_id = Uuid::now_v7();
        let version_id = Uuid::now_v7();
        ActivePolicy {
            bundle: PolicyBundle {
                id: bundle_id,
                name: "test".into(),
                description: String::new(),
                scope: Scope {
                    scope_type,
                    id: if scope_type == ScopeType::Hub {
                        "hub".into()
                    } else {
                        String::new()
                    },
                    product: None,
                },
                mandatory,
                priority: 1,
                active_version_id: Some(version_id),
                shadow_version_id: None,
                state: crate::policy::model::PolicyBundleState::Active,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            },
            version: PolicyVersion {
                id: version_id,
                bundle_id,
                version: 1,
                language: PolicyLanguage::PolicyIrV1,
                runtime_version: POLICY_IR_RUNTIME_VERSION.into(),
                source: source.into(),
                compiled_artifact: bytes,
                source_sha256: String::new(),
                artifact_sha256: String::new(),
                manifest: manifest.clone(),
                state: PolicyState::Active,
            },
            shadow: false,
        }
    }
}
