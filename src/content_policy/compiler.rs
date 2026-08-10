use std::collections::{BTreeMap, HashMap, HashSet};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    matcher::{CompiledMatcher, MatchDetails, MatchOptions, MatcherBuildError, PatternDefinition},
    model::{ContentPolicy, PolicyActionType, PolicyRule, Surface},
    normalization::{NormalizedText, normalize_pattern},
    resolver::{MatchedRule, MatchedSurface},
};

#[derive(Debug)]
struct SurfaceMatcher {
    matcher: CompiledMatcher,
    detailed_rules: HashSet<Uuid>,
}

/// Complete immutable runtime representation of one authority scope. A valid
/// replacement is fully built before the snapshot store publishes it.
#[derive(Debug)]
pub struct CompiledPolicySnapshot {
    pub policy_id: Uuid,
    pub scope: super::model::PolicyScope,
    pub version: u64,
    /// Stable behavior/metadata fingerprint used for destination grouping.
    pub profile_fingerprint: [u8; 32],
    rules: HashMap<Uuid, PolicyRule>,
    rule_names: HashMap<String, Uuid>,
    surfaces: BTreeMap<Surface, SurfaceMatcher>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyMatchError {
    #[error(transparent)]
    Matcher(#[from] MatcherBuildError),
    #[error("matcher returned unknown rule {0}")]
    UnknownRule(Uuid),
}

impl CompiledPolicySnapshot {
    /// Compile an already-validated database definition. Validation and
    /// normalization happen on the policy-change path, never during messages.
    pub fn compile(policy: &ContentPolicy) -> Result<Self, PolicyMatchError> {
        Self::compile_with_match_details(policy, false)
    }

    /// Compile a cold-path diagnostic snapshot that retains pattern/span
    /// attribution for every matched rule. Production snapshots deliberately
    /// collect this richer data only for actions that require it.
    pub fn compile_diagnostic(policy: &ContentPolicy) -> Result<Self, PolicyMatchError> {
        Self::compile_with_match_details(policy, true)
    }

    fn compile_with_match_details(
        policy: &ContentPolicy,
        all_match_details: bool,
    ) -> Result<Self, PolicyMatchError> {
        let rules = policy
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .cloned()
            .map(|rule| (rule.id, rule))
            .collect::<HashMap<_, _>>();
        let mut surfaces = BTreeMap::new();
        let rule_names = rules
            .values()
            .map(|rule| (rule.name.clone(), rule.id))
            .collect();
        for surface in Surface::ALL {
            let surface_rules = rules
                .values()
                .filter(|rule| rule.surfaces.contains(&surface))
                .collect::<Vec<_>>();
            if surface_rules.is_empty() {
                continue;
            }
            let definitions = surface_rules.iter().flat_map(|rule| {
                rule.patterns
                    .iter()
                    .map(|pattern| PatternDefinition::from_rule_pattern(rule.id, pattern))
            });
            let detailed_rules = surface_rules
                .iter()
                .filter(|rule| all_match_details || rule_needs_match_details(rule))
                .map(|rule| rule.id)
                .collect();
            surfaces.insert(
                surface,
                SurfaceMatcher {
                    matcher: CompiledMatcher::compile(definitions)?,
                    detailed_rules,
                },
            );
        }

        Ok(Self {
            policy_id: policy.id,
            scope: policy.scope.clone(),
            version: policy.version,
            profile_fingerprint: profile_fingerprint(policy),
            rules,
            rule_names,
            surfaces,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Match all supplied normalized surfaces. The same `NormalizedText`
    /// values can be reused for GLOBAL, HUB, and every unique SERVER profile.
    pub fn evaluate_normalized(
        &self,
        normalized: &BTreeMap<Surface, NormalizedText>,
    ) -> Result<Vec<MatchedRule>, PolicyMatchError> {
        let mut matched = BTreeMap::<Uuid, Vec<MatchedSurface>>::new();

        for (surface, surface_matcher) in &self.surfaces {
            let Some(text) = normalized.get(surface) else {
                continue;
            };
            let fast = surface_matcher
                .matcher
                .match_normalized(text, MatchOptions::default());
            if fast.is_empty() {
                continue;
            }

            let needs_details = fast
                .rule_ids()
                .any(|rule_id| surface_matcher.detailed_rules.contains(&rule_id));
            let detailed = needs_details.then(|| {
                surface_matcher.matcher.match_normalized(
                    text,
                    MatchOptions {
                        details: MatchDetails::PatternsAndSpans,
                    },
                )
            });
            let details_by_rule = detailed
                .as_ref()
                .map(|report| {
                    report
                        .triggers
                        .iter()
                        .map(|trigger| (trigger.rule_id, &trigger.matches))
                        .collect::<HashMap<_, _>>()
                })
                .unwrap_or_default();

            for trigger in fast.triggers {
                let details = details_by_rule
                    .get(&trigger.rule_id)
                    .copied()
                    .filter(|_| surface_matcher.detailed_rules.contains(&trigger.rule_id));
                let mut spans = details
                    .into_iter()
                    .flatten()
                    .map(|item| item.original_span)
                    .collect::<Vec<_>>();
                spans.sort_unstable();
                spans.dedup();
                let mut pattern_ids = details
                    .into_iter()
                    .flatten()
                    .map(|item| item.pattern_id)
                    .collect::<Vec<_>>();
                pattern_ids.sort_unstable();
                pattern_ids.dedup();
                matched
                    .entry(trigger.rule_id)
                    .or_default()
                    .push(MatchedSurface {
                        surface: *surface,
                        spans,
                        pattern_ids,
                    });
            }
        }

        matched
            .into_iter()
            .map(|(rule_id, mut surfaces)| {
                let rule = self
                    .rules
                    .get(&rule_id)
                    .ok_or(PolicyMatchError::UnknownRule(rule_id))?;
                surfaces.sort_by_key(|item| item.surface);
                Ok(MatchedRule {
                    policy_id: self.policy_id,
                    policy_version: self.version,
                    scope: self.scope.clone(),
                    rule_id,
                    rule_name: rule.name.clone(),
                    custom_reason: rule.custom_reason.clone(),
                    surfaces,
                    actions: rule.actions.clone(),
                })
            })
            .collect()
    }

    /// Re-attribute a result evaluated once for an equivalent compiled
    /// profile to this scope's own policy/rule IDs. Profile fingerprints include
    /// rule names and complete behavior, so a missing name is a hard mismatch.
    pub fn remap_equivalent_matches(
        &self,
        representative: &[MatchedRule],
    ) -> Result<Vec<MatchedRule>, PolicyMatchError> {
        representative
            .iter()
            .map(|matched| {
                let rule_id = self
                    .rule_names
                    .get(&matched.rule_name)
                    .copied()
                    .ok_or(PolicyMatchError::UnknownRule(matched.rule_id))?;
                let rule = self
                    .rules
                    .get(&rule_id)
                    .ok_or(PolicyMatchError::UnknownRule(rule_id))?;
                Ok(MatchedRule {
                    policy_id: self.policy_id,
                    policy_version: self.version,
                    scope: self.scope.clone(),
                    rule_id,
                    rule_name: rule.name.clone(),
                    custom_reason: rule.custom_reason.clone(),
                    surfaces: matched.surfaces.clone(),
                    actions: rule.actions.clone(),
                })
            })
            .collect()
    }
}

fn rule_needs_match_details(rule: &PolicyRule) -> bool {
    rule.actions.iter().any(|action| {
        matches!(
            action.action_type,
            PolicyActionType::CensorMatch | PolicyActionType::Log
        )
    })
}

fn profile_fingerprint(policy: &ContentPolicy) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut rules = policy
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    for rule in rules {
        hash_field(&mut hasher, rule.name.as_bytes());
        hash_field(&mut hasher, rule.description.as_bytes());
        hash_field(
            &mut hasher,
            rule.custom_reason.as_deref().unwrap_or_default().as_bytes(),
        );
        for surface in &rule.surfaces {
            hasher.update([*surface as u8]);
        }
        let mut patterns = rule.patterns.iter().collect::<Vec<_>>();
        patterns.sort_by_key(|pattern| {
            (
                pattern.pattern_type as u8,
                normalize_pattern(&pattern.pattern),
                pattern.id,
            )
        });
        for pattern in patterns {
            hasher.update([pattern.pattern_type as u8]);
            hash_field(&mut hasher, normalize_pattern(&pattern.pattern).as_bytes());
        }
        let mut actions = rule.actions.iter().collect::<Vec<_>>();
        actions.sort_by_key(|action| (action.action_type, action.id));
        for action in actions {
            hasher.update([action.action_type as u8]);
            hasher.update(action.duration_seconds.unwrap_or_default().to_be_bytes());
            hash_field(
                &mut hasher,
                action.replacement.as_deref().unwrap_or_default().as_bytes(),
            );
        }
    }
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::content_policy::model::{
        PolicyAction, PolicyScope, RulePattern, WildcardPatternType,
    };
    use crate::content_policy::resolver::ByteSpan;

    fn policy(actions: Vec<PolicyActionType>) -> ContentPolicy {
        ContentPolicy {
            id: Uuid::from_u128(1),
            scope: PolicyScope::global(),
            enabled: true,
            version: 4,
            rules: vec![PolicyRule {
                id: Uuid::from_u128(2),
                name: "blocked terms".into(),
                description: String::new(),
                enabled: true,
                custom_reason: None,
                created_by: "staff".into(),
                patterns: vec![RulePattern {
                    id: Uuid::from_u128(3),
                    pattern: "bad".into(),
                    pattern_type: WildcardPatternType::ExactWord,
                }],
                surfaces: BTreeSet::from([Surface::MessageContent]),
                actions: actions
                    .into_iter()
                    .enumerate()
                    .map(|(index, action_type)| PolicyAction {
                        id: Uuid::from_u128(10 + index as u128),
                        action_type,
                        duration_seconds: None,
                        replacement: None,
                    })
                    .collect(),
            }],
        }
    }

    #[test]
    fn no_match_fast_path_returns_no_rules() {
        let snapshot =
            CompiledPolicySnapshot::compile(&policy(vec![PolicyActionType::Block])).unwrap();
        let input = BTreeMap::from([(
            Surface::MessageContent,
            NormalizedText::new("ordinary message"),
        )]);
        assert!(snapshot.evaluate_normalized(&input).unwrap().is_empty());
    }

    #[test]
    fn multiple_patterns_still_create_one_rule_result() {
        let mut definition = policy(vec![PolicyActionType::Block]);
        definition.rules[0].patterns.push(RulePattern {
            id: Uuid::from_u128(4),
            pattern: "awful".into(),
            pattern_type: WildcardPatternType::ExactWord,
        });
        let snapshot = CompiledPolicySnapshot::compile(&definition).unwrap();
        let input = BTreeMap::from([(
            Surface::MessageContent,
            NormalizedText::new("bad and awful"),
        )]);
        assert_eq!(snapshot.evaluate_normalized(&input).unwrap().len(), 1);
    }

    #[test]
    fn censor_collects_original_spans_but_block_does_not_pay_for_details() {
        let censor =
            CompiledPolicySnapshot::compile(&policy(vec![PolicyActionType::CensorMatch])).unwrap();
        let block =
            CompiledPolicySnapshot::compile(&policy(vec![PolicyActionType::Block])).unwrap();
        let input = BTreeMap::from([(Surface::MessageContent, NormalizedText::new("BAD"))]);
        assert_eq!(
            censor.evaluate_normalized(&input).unwrap()[0].surfaces[0].spans,
            vec![ByteSpan { start: 0, end: 3 }]
        );
        assert!(
            block.evaluate_normalized(&input).unwrap()[0].surfaces[0]
                .spans
                .is_empty()
        );
    }

    #[test]
    fn diagnostic_snapshot_collects_details_for_block_rules() {
        let snapshot =
            CompiledPolicySnapshot::compile_diagnostic(&policy(vec![PolicyActionType::Block]))
                .unwrap();
        let input = BTreeMap::from([(Surface::MessageContent, NormalizedText::new("BAD"))]);
        let matched = snapshot.evaluate_normalized(&input).unwrap();

        assert_eq!(
            matched[0].surfaces[0].spans,
            vec![ByteSpan { start: 0, end: 3 }]
        );
        assert_eq!(matched[0].surfaces[0].pattern_ids, vec![Uuid::from_u128(3)]);
    }

    #[test]
    fn disabled_rules_are_absent_from_snapshot() {
        let mut definition = policy(vec![PolicyActionType::Block]);
        definition.rules[0].enabled = false;
        let snapshot = CompiledPolicySnapshot::compile(&definition).unwrap();
        assert!(snapshot.is_empty());
    }
}
