use std::collections::{BTreeSet, HashMap};

use super::model::{Decision, EmittedEffect, RejectedEffect};

#[derive(Debug)]
pub struct MergedEffects {
    pub decision: Decision,
    pub accepted: Vec<EmittedEffect>,
    pub rejected: Vec<RejectedEffect>,
    pub reason_codes: Vec<String>,
}

pub fn merge_effects(effects: Vec<EmittedEffect>) -> MergedEffects {
    let winning = effects
        .iter()
        .filter_map(|emitted| {
            emitted
                .effect
                .decision()
                .map(|decision| (decision, emitted))
        })
        .max_by(|(left_decision, left), (right_decision, right)| {
            left_decision
                .cmp(right_decision)
                .then_with(|| {
                    right
                        .origin
                        .scope
                        .precedence()
                        .cmp(&left.origin.scope.precedence())
                })
                .then_with(|| right.origin.priority.cmp(&left.origin.priority))
        })
        .map(|(_, effect)| effect.effect.id().to_owned());

    let final_decision = winning
        .as_deref()
        .and_then(|id| effects.iter().find(|effect| effect.effect.id() == id))
        .and_then(|effect| effect.effect.decision())
        .unwrap_or(Decision::Allow);

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = HashMap::<String, String>::new();
    let mut reasons = BTreeSet::new();

    for emitted in effects {
        let effect_id = emitted.effect.id().to_owned();
        if let Some(first_id) = seen.get(&effect_id) {
            rejected.push(RejectedEffect {
                effect: emitted,
                reason: "duplicate effect id".to_owned(),
                superseded_by: Some(first_id.clone()),
            });
            continue;
        }
        seen.insert(effect_id.clone(), effect_id.clone());

        if emitted.effect.decision().is_some() && winning.as_deref() != Some(&effect_id) {
            rejected.push(RejectedEffect {
                effect: emitted,
                reason: "superseded by a higher-precedence decision effect".to_owned(),
                superseded_by: winning.clone(),
            });
            continue;
        }

        reasons.extend(emitted.effect.reason_codes().iter().cloned());
        accepted.push(emitted);
    }

    MergedEffects {
        decision: final_decision,
        accepted,
        rejected,
        reason_codes: reasons.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::{Effect, EffectOrigin, Scope, ScopeType};
    use uuid::Uuid;

    fn emitted(effect: Effect, scope_type: ScopeType, mandatory: bool) -> EmittedEffect {
        EmittedEffect {
            origin: EffectOrigin {
                policy_bundle_id: Uuid::now_v7(),
                policy_version_id: Uuid::now_v7(),
                rule_id: "rule".into(),
                scope: Scope {
                    scope_type,
                    id: String::new(),
                    product: None,
                },
                priority: 100,
                mandatory,
            },
            effect,
        }
    }

    #[test]
    fn global_block_cannot_be_weakened_by_hub_allow() {
        let merged = merge_effects(vec![
            emitted(
                Effect::Block {
                    effect_id: "global-block".into(),
                    reason_codes: vec!["GLOBAL".into()],
                    public_reason: None,
                },
                ScopeType::Platform,
                true,
            ),
            emitted(
                Effect::Allow {
                    effect_id: "hub-allow".into(),
                    reason_codes: vec![],
                },
                ScopeType::Hub,
                false,
            ),
        ]);
        assert_eq!(merged.decision, Decision::Block);
        assert_eq!(merged.accepted[0].effect.id(), "global-block");
    }

    #[test]
    fn non_decision_effects_accumulate_once() {
        let flag = Effect::Flag {
            effect_id: "same".into(),
            flag_type: "risk".into(),
            severity: 0.8,
            evidence: serde_json::json!({}),
        };
        let merged = merge_effects(vec![
            emitted(flag.clone(), ScopeType::Platform, true),
            emitted(flag, ScopeType::Hub, false),
        ]);
        assert_eq!(merged.accepted.len(), 1);
        assert_eq!(merged.rejected.len(), 1);
    }
}
