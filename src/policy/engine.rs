use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Instant,
};

use rand::Rng;
use uuid::Uuid;

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
            clean_allow_sample_rate,
        }
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
        let policies = self.repository.active_policies(action).await?;
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
                error_behavior: crate::policy::model::ErrorBehavior::Continue,
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
        let mut had_error = false;

        if is_message_action {
            let reqs = vec![crate::policy::model::FeatureRequirement {
                name: "restrictions.active".into(),
                error_behavior: crate::policy::model::ErrorBehavior::Continue,
                deadline_ms: 500,
                maximum_data_handling: action.data_handling,
                configuration: serde_json::Value::Null,
            }];
            let snapshot = resolved_features.runtime_snapshot(&reqs);
            if let Some(val) = snapshot.get("restrictions.active") {
                if let Some(arr) = val.value.as_ref().and_then(|v| v.as_array()) {
                    for r in arr {
                        if let Some(rtype) = r.get("restriction_type").and_then(|v| v.as_str()) {
                            if rtype == "BAN" || rtype == "MUTE" || rtype == "BLACKLIST" {
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
                                        reason_codes: vec![format!("ACTIVE_{}", rtype)],
                                        public_reason: Some(format!(
                                            "You have an active {}.",
                                            rtype.to_lowercase()
                                        )),
                                    },
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        for policy in policies {
            if shadow_only && !policy.shadow {
                continue;
            }
            if !shadow_only && policy.shadow {
                continue;
            }
            policy_versions.push(policy.version.id);
            if terminal_global_block {
                rule_traces.push(RuleTrace {
                    policy_version_id: policy.version.id,
                    rule_id: "*".into(),
                    skipped: true,
                    skip_reason: Some("terminal global mandatory block".into()),
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
        };
        Ok(result)
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
    use crate::policy::{
        features::text::NormalizedTextProvider,
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
        let mut engine = PolicyEngine::new(repo.clone(), Arc::new(FeatureRegistry::default()), 0.0);
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
        let mut engine = PolicyEngine::new(repo, Arc::new(FeatureRegistry::default()), 0.0);
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
