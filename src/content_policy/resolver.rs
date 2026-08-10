use std::collections::BTreeMap;

use uuid::Uuid;

use super::model::{PolicyAction, PolicyActionType, PolicyScope, Surface};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub fn new(start: usize, end: usize) -> Option<Self> {
        (start < end).then_some(Self { start, end })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedSurface {
    pub surface: Surface,
    pub spans: Vec<ByteSpan>,
    /// Populated only when logging or diagnostic attribution requested rich
    /// details from the matcher.
    pub pattern_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub policy_id: Uuid,
    pub policy_version: u64,
    pub scope: PolicyScope,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub custom_reason: Option<String>,
    pub surfaces: Vec<MatchedSurface>,
    pub actions: Vec<PolicyAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectAttribution {
    pub policy_id: Uuid,
    pub policy_version: u64,
    pub scope: PolicyScope,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub custom_reason: Option<String>,
}

impl From<&MatchedRule> for EffectAttribution {
    fn from(rule: &MatchedRule) -> Self {
        Self {
            policy_id: rule.policy_id,
            policy_version: rule.policy_version,
            scope: rule.scope.clone(),
            rule_id: rule.rule_id,
            rule_name: rule.rule_name.clone(),
            custom_reason: rule.custom_reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameReplacement {
    pub replacement: String,
    pub attribution: EffectAttribution,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryEffects {
    pub blocked_by: Vec<EffectAttribution>,
    pub censor_spans: BTreeMap<Surface, Vec<ByteSpan>>,
    pub strip_links: bool,
    pub suppress_links: bool,
    pub name_replacements: BTreeMap<Surface, NameReplacement>,
}

impl DeliveryEffects {
    pub fn is_blocked(&self) -> bool {
        !self.blocked_by.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideEffectRequest {
    pub action_type: PolicyActionType,
    pub duration_seconds: Option<u64>,
    pub attribution: EffectAttribution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedScopeDecision {
    pub scope: PolicyScope,
    pub matched_rules: Vec<MatchedRule>,
    pub delivery: DeliveryEffects,
    pub side_effects: Vec<SideEffectRequest>,
}

/// Resolve one authority layer. Rule vector order has no semantic meaning;
/// every tie is resolved with stable IDs and action strength.
pub fn resolve_scope(
    scope: PolicyScope,
    mut matched_rules: Vec<MatchedRule>,
) -> ResolvedScopeDecision {
    matched_rules.sort_by_key(|rule| rule.rule_id);

    let mut delivery = DeliveryEffects::default();
    let mut side_effects = Vec::new();
    for rule in &matched_rules {
        let attribution = EffectAttribution::from(rule);
        for action in &rule.actions {
            match action.action_type {
                PolicyActionType::Allow => {}
                PolicyActionType::Block => delivery.blocked_by.push(attribution.clone()),
                PolicyActionType::CensorMatch => {
                    for matched in &rule.surfaces {
                        delivery
                            .censor_spans
                            .entry(matched.surface)
                            .or_default()
                            .extend(matched.spans.iter().copied());
                    }
                }
                PolicyActionType::StripLink => delivery.strip_links = true,
                PolicyActionType::SuppressLinks => delivery.suppress_links = true,
                PolicyActionType::ReplaceName => {
                    let replacement = action
                        .replacement
                        .clone()
                        .unwrap_or_else(|| "InterChat User".to_owned());
                    for matched in rule.surfaces.iter().filter(|item| item.surface.is_name()) {
                        // Rules are sorted by UUID, so first insertion is a
                        // deterministic tie-break independent of DB row order.
                        delivery
                            .name_replacements
                            .entry(matched.surface)
                            .or_insert_with(|| NameReplacement {
                                replacement: replacement.clone(),
                                attribution: attribution.clone(),
                            });
                    }
                }
                action_type => side_effects.push(SideEffectRequest {
                    action_type,
                    duration_seconds: action.duration_seconds,
                    attribution: attribution.clone(),
                }),
            }
        }
    }

    delivery.blocked_by.sort_by_key(|item| item.rule_id);
    if delivery.is_blocked() {
        // BLOCK wins over CENSOR for this delivery path. Other presentation
        // metadata is retained for internal diagnostics but is never rendered.
        delivery.censor_spans.clear();
    } else {
        for spans in delivery.censor_spans.values_mut() {
            *spans = merge_spans(std::mem::take(spans));
        }
    }

    ResolvedScopeDecision {
        scope,
        matched_rules,
        delivery,
        side_effects: strongest_side_effects(side_effects),
    }
}

/// Compose compatible authority layers without allowing a lower layer to
/// weaken a higher one. The caller controls which layers apply to a path (for
/// Calls: GLOBAL only; for Hub delivery: GLOBAL, HUB, optional SERVER).
pub fn compose_delivery<'a>(
    layers: impl IntoIterator<Item = &'a DeliveryEffects>,
) -> DeliveryEffects {
    let mut output = DeliveryEffects::default();
    for layer in layers {
        output.blocked_by.extend(layer.blocked_by.iter().cloned());
        output.strip_links |= layer.strip_links;
        output.suppress_links |= layer.suppress_links;
        for (surface, spans) in &layer.censor_spans {
            output
                .censor_spans
                .entry(*surface)
                .or_default()
                .extend(spans.iter().copied());
        }
        for (surface, replacement) in &layer.name_replacements {
            // Higher-authority layers are provided first and keep precedence.
            output
                .name_replacements
                .entry(*surface)
                .or_insert_with(|| replacement.clone());
        }
    }
    output.blocked_by.sort_by_key(|item| {
        (
            item.scope.authority.precedence(),
            item.policy_id,
            item.rule_id,
        )
    });
    if output.is_blocked() {
        output.censor_spans.clear();
    } else {
        for spans in output.censor_spans.values_mut() {
            *spans = merge_spans(std::mem::take(spans));
        }
    }
    output
}

fn strongest_side_effects(requests: Vec<SideEffectRequest>) -> Vec<SideEffectRequest> {
    let mut logs = BTreeMap::<Uuid, SideEffectRequest>::new();
    let mut strongest_global: Option<SideEffectRequest> = None;
    let mut strongest_hub: Option<SideEffectRequest> = None;

    for request in requests {
        match request.action_type {
            PolicyActionType::Log => {
                logs.entry(request.attribution.rule_id).or_insert(request);
            }
            PolicyActionType::LobbyWarn
            | PolicyActionType::LobbyBan
            | PolicyActionType::Blacklist => select_strongest(&mut strongest_global, request),
            PolicyActionType::HubWarn | PolicyActionType::HubMute | PolicyActionType::HubBan => {
                select_strongest(&mut strongest_hub, request)
            }
            _ => {}
        }
    }

    let mut output = logs.into_values().collect::<Vec<_>>();
    output.extend(strongest_global);
    output.extend(strongest_hub);
    output.sort_by_key(|item| {
        (
            side_effect_family(item.action_type),
            item.attribution.rule_id,
        )
    });
    output
}

fn select_strongest(slot: &mut Option<SideEffectRequest>, candidate: SideEffectRequest) {
    let replace = slot.as_ref().is_none_or(|current| {
        let candidate_strength = side_effect_strength(candidate.action_type);
        let current_strength = side_effect_strength(current.action_type);
        candidate_strength > current_strength
            || (candidate_strength == current_strength
                && candidate.duration_seconds.unwrap_or(0) > current.duration_seconds.unwrap_or(0))
            || (candidate_strength == current_strength
                && candidate.duration_seconds == current.duration_seconds
                && candidate.attribution.rule_id < current.attribution.rule_id)
    });
    if replace {
        *slot = Some(candidate);
    }
}

const fn side_effect_family(action: PolicyActionType) -> u8 {
    match action {
        PolicyActionType::Log => 0,
        PolicyActionType::LobbyWarn | PolicyActionType::LobbyBan | PolicyActionType::Blacklist => 1,
        PolicyActionType::HubWarn | PolicyActionType::HubMute | PolicyActionType::HubBan => 2,
        _ => 3,
    }
}

const fn side_effect_strength(action: PolicyActionType) -> u8 {
    match action {
        PolicyActionType::LobbyWarn | PolicyActionType::HubWarn => 1,
        PolicyActionType::LobbyBan | PolicyActionType::HubMute => 2,
        PolicyActionType::Blacklist | PolicyActionType::HubBan => 3,
        _ => 0,
    }
}

fn merge_spans(mut spans: Vec<ByteSpan>) -> Vec<ByteSpan> {
    spans.sort_unstable();
    let mut merged = Vec::<ByteSpan>::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = merged.last_mut()
            && span.start <= last.end
        {
            last.end = last.end.max(span.end);
            continue;
        }
        merged.push(span);
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::content_policy::model::{Authority, PolicyAction};

    fn matched_rule(
        scope: PolicyScope,
        rule_id: Uuid,
        actions: Vec<(PolicyActionType, Option<u64>)>,
        spans: Vec<ByteSpan>,
    ) -> MatchedRule {
        MatchedRule {
            policy_id: Uuid::from_u128(1),
            policy_version: 3,
            scope,
            rule_id,
            rule_name: "rule".into(),
            custom_reason: None,
            surfaces: vec![MatchedSurface {
                surface: Surface::MessageContent,
                spans,
                pattern_ids: Vec::new(),
            }],
            actions: actions
                .into_iter()
                .enumerate()
                .map(|(index, (action_type, duration_seconds))| PolicyAction {
                    id: Uuid::from_u128(index as u128 + 10),
                    action_type,
                    duration_seconds,
                    replacement: None,
                })
                .collect(),
        }
    }

    #[test]
    fn block_wins_over_censor_at_same_scope() {
        let scope = PolicyScope::hub("hub");
        let result = resolve_scope(
            scope,
            vec![matched_rule(
                PolicyScope::hub("hub"),
                Uuid::from_u128(2),
                vec![
                    (PolicyActionType::CensorMatch, None),
                    (PolicyActionType::Block, None),
                ],
                vec![ByteSpan { start: 1, end: 4 }],
            )],
        );
        assert!(result.delivery.is_blocked());
        assert!(result.delivery.censor_spans.is_empty());
    }

    #[test]
    fn compatible_transformations_compose_and_merge_spans() {
        let global = DeliveryEffects {
            censor_spans: BTreeMap::from([(
                Surface::MessageContent,
                vec![ByteSpan { start: 1, end: 4 }],
            )]),
            ..DeliveryEffects::default()
        };
        let hub = DeliveryEffects {
            censor_spans: BTreeMap::from([(
                Surface::MessageContent,
                vec![ByteSpan { start: 3, end: 8 }],
            )]),
            suppress_links: true,
            ..DeliveryEffects::default()
        };
        let result = compose_delivery([&global, &hub]);
        assert_eq!(
            result.censor_spans[&Surface::MessageContent],
            vec![ByteSpan { start: 1, end: 8 }]
        );
        assert!(result.suppress_links);
    }

    #[test]
    fn strongest_punishment_and_longest_duration_win_deterministically() {
        let scope = PolicyScope::hub("hub");
        let result = resolve_scope(
            scope.clone(),
            vec![
                matched_rule(
                    scope.clone(),
                    Uuid::from_u128(3),
                    vec![(PolicyActionType::HubWarn, None)],
                    vec![ByteSpan { start: 0, end: 1 }],
                ),
                matched_rule(
                    scope.clone(),
                    Uuid::from_u128(4),
                    vec![(PolicyActionType::HubMute, Some(60))],
                    vec![ByteSpan { start: 0, end: 1 }],
                ),
                matched_rule(
                    scope,
                    Uuid::from_u128(5),
                    vec![(PolicyActionType::HubMute, Some(300))],
                    vec![ByteSpan { start: 0, end: 1 }],
                ),
            ],
        );
        assert_eq!(result.side_effects.len(), 1);
        assert_eq!(
            result.side_effects[0].action_type,
            PolicyActionType::HubMute
        );
        assert_eq!(result.side_effects[0].duration_seconds, Some(300));
    }

    #[test]
    fn lower_scope_allow_cannot_weaken_global_block() {
        let block = resolve_scope(
            PolicyScope::global(),
            vec![matched_rule(
                PolicyScope::global(),
                Uuid::from_u128(1),
                vec![(PolicyActionType::Block, None)],
                vec![ByteSpan { start: 0, end: 1 }],
            )],
        );
        let allow = resolve_scope(
            PolicyScope::server("server"),
            vec![matched_rule(
                PolicyScope::server("server"),
                Uuid::from_u128(2),
                vec![(PolicyActionType::Allow, None)],
                vec![ByteSpan { start: 0, end: 1 }],
            )],
        );
        assert!(compose_delivery([&block.delivery, &allow.delivery]).is_blocked());
        assert_eq!(block.scope.authority, Authority::Global);
    }

    #[test]
    fn multiple_log_rules_remain_visible_while_punishments_dedupe() {
        let scope = PolicyScope::hub("hub");
        let result = resolve_scope(
            scope.clone(),
            vec![
                matched_rule(
                    scope.clone(),
                    Uuid::from_u128(1),
                    vec![
                        (PolicyActionType::Log, None),
                        (PolicyActionType::HubWarn, None),
                    ],
                    vec![ByteSpan { start: 0, end: 1 }],
                ),
                matched_rule(
                    scope,
                    Uuid::from_u128(2),
                    vec![
                        (PolicyActionType::Log, None),
                        (PolicyActionType::HubBan, None),
                    ],
                    vec![ByteSpan { start: 2, end: 3 }],
                ),
            ],
        );
        let kinds = result
            .side_effects
            .iter()
            .map(|effect| effect.action_type)
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains(&PolicyActionType::Log));
        assert!(kinds.contains(&PolicyActionType::HubBan));
        assert!(!kinds.contains(&PolicyActionType::HubWarn));
        assert_eq!(
            result
                .side_effects
                .iter()
                .filter(|effect| effect.action_type == PolicyActionType::Log)
                .count(),
            2
        );
    }
}
