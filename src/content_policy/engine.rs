use std::{collections::BTreeMap, sync::Arc};

use uuid::Uuid;

use super::{
    analysis::AnalyzedContent,
    compiler::{CompiledPolicySnapshot, PolicyMatchError},
    cooldown::SideEffectCooldown,
    delivery::{DeliveryVariant, Presentation, materialize_variant},
    model::PolicyScope,
    resolver::{
        EffectAttribution, ResolvedScopeDecision, SideEffectRequest, compose_delivery,
        resolve_scope,
    },
    snapshot::PolicySnapshotStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Opaque caller-owned target position (for example a Prism target index).
    pub target_index: usize,
    pub server_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationDecision {
    pub target_index: usize,
    pub server_id: String,
    pub policy_id: Option<Uuid>,
    pub policy_version: Option<u64>,
    pub matched_rule_ids: Vec<Uuid>,
    pub blocked_by: Vec<EffectAttribution>,
    pub variant_fingerprint: Option<[u8; 32]>,
}

impl DestinationDecision {
    pub fn is_blocked(&self) -> bool {
        !self.blocked_by.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderFeedback {
    GlobalSafetyBlock,
    CallSafetyBlock,
    HubModerationBlock { custom_reason: Option<String> },
    ServerFilters { destination_count: usize },
}

#[derive(Debug, Clone)]
pub struct HubPolicyPlan {
    pub global: ResolvedScopeDecision,
    pub hub: ResolvedScopeDecision,
    pub destinations: Vec<DestinationDecision>,
    /// One materialized presentation per unique transformation result.
    pub variants: BTreeMap<[u8; 32], DeliveryVariant>,
    pub side_effects: Vec<SideEffectRequest>,
    pub sender_feedback: Option<SenderFeedback>,
    pub evaluated_server_profiles: usize,
}

#[derive(Debug, Clone)]
pub struct CallPolicyPlan {
    pub global: ResolvedScopeDecision,
    pub variant: Option<DeliveryVariant>,
    pub side_effects: Vec<SideEffectRequest>,
    pub sender_feedback: Option<SenderFeedback>,
}

#[derive(Debug, Clone)]
pub enum ContentPolicyPlan {
    Hub(HubPolicyPlan),
    Call(CallPolicyPlan),
}

#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    #[error(transparent)]
    Match(#[from] PolicyMatchError),
    #[error(transparent)]
    Transform(#[from] super::delivery::TransformationError),
}

pub struct ContentPolicyEvaluator {
    snapshots: Arc<PolicySnapshotStore>,
    cooldowns: Arc<SideEffectCooldown>,
}

impl ContentPolicyEvaluator {
    pub fn new(snapshots: Arc<PolicySnapshotStore>, cooldowns: Arc<SideEffectCooldown>) -> Self {
        Self {
            snapshots,
            cooldowns,
        }
    }

    pub fn evaluate_call(
        &self,
        subject_id: &str,
        canonical: &Presentation,
        analyzed: &AnalyzedContent,
    ) -> Result<CallPolicyPlan, EvaluationError> {
        let global = evaluate_snapshot(PolicyScope::global(), self.snapshots.global(), analyzed)?;
        let side_effects = self.cooldown_side_effects(subject_id, &global.side_effects);
        if global.delivery.is_blocked() {
            return Ok(CallPolicyPlan {
                global,
                variant: None,
                side_effects,
                sender_feedback: Some(SenderFeedback::CallSafetyBlock),
            });
        }

        let presentation = with_analyzed_urls(canonical, analyzed);
        let delivery = compose_delivery([&global.delivery]);
        Ok(CallPolicyPlan {
            global,
            variant: Some(materialize_variant(&presentation, &delivery)?),
            side_effects,
            sender_feedback: None,
        })
    }

    pub fn evaluate_hub(
        &self,
        subject_id: &str,
        hub_id: &str,
        canonical: &Presentation,
        analyzed: &AnalyzedContent,
        destinations: &[Destination],
    ) -> Result<HubPolicyPlan, EvaluationError> {
        let global = evaluate_snapshot(PolicyScope::global(), self.snapshots.global(), analyzed)?;
        if global.delivery.is_blocked() {
            let side_effects = self.cooldown_side_effects(subject_id, &global.side_effects);
            return Ok(terminal_hub_plan(
                global,
                empty_scope_decision(PolicyScope::hub(hub_id)),
                destinations,
                SenderFeedback::GlobalSafetyBlock,
                side_effects,
            ));
        }

        let hub = evaluate_snapshot(
            PolicyScope::hub(hub_id),
            self.snapshots.hub(hub_id),
            analyzed,
        )?;
        let mut side_effects = self.cooldown_side_effects(subject_id, &global.side_effects);
        side_effects.extend(self.cooldown_side_effects(subject_id, &hub.side_effects));
        if hub.delivery.is_blocked() {
            let custom_reason = hub
                .delivery
                .blocked_by
                .iter()
                .find_map(|item| item.custom_reason.clone());
            return Ok(terminal_hub_plan(
                global,
                hub,
                destinations,
                SenderFeedback::HubModerationBlock { custom_reason },
                side_effects,
            ));
        }

        let shared_delivery = compose_delivery([&global.delivery, &hub.delivery]);
        let presentation = with_analyzed_urls(canonical, analyzed);
        let mut profiles =
            BTreeMap::<[u8; 32], Vec<(Destination, Arc<CompiledPolicySnapshot>)>>::new();
        let mut without_policy = Vec::new();
        for destination in destinations {
            if let Some(snapshot) = self.snapshots.server(&destination.server_id) {
                profiles
                    .entry(snapshot.profile_fingerprint)
                    .or_default()
                    .push((destination.clone(), snapshot));
            } else {
                without_policy.push(destination.clone());
            }
        }

        let mut decisions = Vec::with_capacity(destinations.len());
        let mut variants = BTreeMap::new();
        if !without_policy.is_empty() {
            let variant = materialize_variant(&presentation, &shared_delivery)?;
            let fingerprint = variant.fingerprint;
            variants.insert(fingerprint, variant);
            decisions.extend(
                without_policy
                    .into_iter()
                    .map(|destination| DestinationDecision {
                        target_index: destination.target_index,
                        server_id: destination.server_id,
                        policy_id: None,
                        policy_version: None,
                        matched_rule_ids: Vec::new(),
                        blocked_by: Vec::new(),
                        variant_fingerprint: Some(fingerprint),
                    }),
            );
        }

        let evaluated_server_profiles = profiles.len();
        for members in profiles.into_values() {
            let representative = Arc::clone(&members[0].1);
            let representative_matches =
                representative.evaluate_normalized(analyzed.normalized_surfaces())?;
            let representative_scope =
                resolve_scope(representative.scope.clone(), representative_matches.clone());
            let composed = compose_delivery([&shared_delivery, &representative_scope.delivery]);
            let variant = if composed.is_blocked() {
                None
            } else {
                Some(materialize_variant(&presentation, &composed)?)
            };
            let fingerprint = variant.as_ref().map(|variant| variant.fingerprint);
            if let Some(variant) = variant {
                variants.entry(variant.fingerprint).or_insert(variant);
            }

            for (destination, snapshot) in members {
                let local_matches = if snapshot.policy_id == representative.policy_id {
                    representative_matches.clone()
                } else {
                    snapshot.remap_equivalent_matches(&representative_matches)?
                };
                let local = resolve_scope(snapshot.scope.clone(), local_matches);
                let blocked_by = if local.delivery.is_blocked() {
                    local.delivery.blocked_by.clone()
                } else {
                    Vec::new()
                };
                decisions.push(DestinationDecision {
                    target_index: destination.target_index,
                    server_id: destination.server_id,
                    policy_id: Some(snapshot.policy_id),
                    policy_version: Some(snapshot.version),
                    matched_rule_ids: local
                        .matched_rules
                        .iter()
                        .map(|rule| rule.rule_id)
                        .collect(),
                    blocked_by,
                    variant_fingerprint: fingerprint.filter(|_| !local.delivery.is_blocked()),
                });
            }
        }

        decisions.sort_by_key(|decision| decision.target_index);
        let filtered = decisions
            .iter()
            .filter(|decision| decision.is_blocked())
            .count();
        Ok(HubPolicyPlan {
            global,
            hub,
            destinations: decisions,
            variants,
            side_effects,
            sender_feedback: (filtered > 0).then_some(SenderFeedback::ServerFilters {
                destination_count: filtered,
            }),
            evaluated_server_profiles,
        })
    }

    fn cooldown_side_effects(
        &self,
        subject_id: &str,
        side_effects: &[SideEffectRequest],
    ) -> Vec<SideEffectRequest> {
        side_effects
            .iter()
            .filter(|effect| {
                self.cooldowns.allow(
                    subject_id,
                    &effect.attribution.scope,
                    effect.attribution.rule_id,
                    effect.action_type,
                )
            })
            .cloned()
            .collect()
    }
}

fn evaluate_snapshot(
    scope: PolicyScope,
    snapshot: Option<Arc<CompiledPolicySnapshot>>,
    analyzed: &AnalyzedContent,
) -> Result<ResolvedScopeDecision, PolicyMatchError> {
    match snapshot {
        Some(snapshot) => Ok(resolve_scope(
            snapshot.scope.clone(),
            snapshot.evaluate_normalized(analyzed.normalized_surfaces())?,
        )),
        None => Ok(empty_scope_decision(scope)),
    }
}

fn empty_scope_decision(scope: PolicyScope) -> ResolvedScopeDecision {
    resolve_scope(scope, Vec::new())
}

fn terminal_hub_plan(
    global: ResolvedScopeDecision,
    hub: ResolvedScopeDecision,
    destinations: &[Destination],
    feedback: SenderFeedback,
    side_effects: Vec<SideEffectRequest>,
) -> HubPolicyPlan {
    let blocked_by = if global.delivery.is_blocked() {
        global.delivery.blocked_by.clone()
    } else {
        hub.delivery.blocked_by.clone()
    };
    HubPolicyPlan {
        global,
        hub,
        destinations: destinations
            .iter()
            .map(|destination| DestinationDecision {
                target_index: destination.target_index,
                server_id: destination.server_id.clone(),
                policy_id: None,
                policy_version: None,
                matched_rule_ids: Vec::new(),
                blocked_by: blocked_by.clone(),
                variant_fingerprint: None,
            })
            .collect(),
        variants: BTreeMap::new(),
        side_effects,
        sender_feedback: Some(feedback),
        evaluated_server_profiles: 0,
    }
}

fn with_analyzed_urls(canonical: &Presentation, analyzed: &AnalyzedContent) -> Presentation {
    let mut presentation = canonical.clone();
    presentation.url_spans = analyzed.url_spans.clone();
    presentation
}
