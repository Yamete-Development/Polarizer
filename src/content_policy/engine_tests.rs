use std::{collections::BTreeSet, sync::Arc};

use uuid::Uuid;

use super::delivery::Presentation;
use super::{
    AnalyzedContent, Authority, CompiledPolicySnapshot, ContentPolicy, ContentPolicyEvaluator,
    Destination, DestinationDecision, PolicyAction, PolicyActionType, PolicyRule, PolicyScope,
    PolicySnapshotStore, RulePattern, SenderFeedback, SideEffectCooldown, Surface,
    WildcardPatternType,
};

fn policy(id: u128, scope: PolicyScope, version: u64, rules: Vec<PolicyRule>) -> ContentPolicy {
    ContentPolicy {
        id: Uuid::from_u128(id),
        scope,
        enabled: true,
        version,
        rules,
    }
}

fn rule(
    id: u128,
    name: &str,
    pattern: &str,
    surface: Surface,
    actions: Vec<PolicyAction>,
) -> PolicyRule {
    rule_with_reason(id, name, pattern, surface, None, actions)
}

fn rule_with_reason(
    id: u128,
    name: &str,
    pattern: &str,
    surface: Surface,
    custom_reason: Option<&str>,
    actions: Vec<PolicyAction>,
) -> PolicyRule {
    PolicyRule {
        id: Uuid::from_u128(id),
        name: name.into(),
        description: "engine test rule".into(),
        enabled: true,
        custom_reason: custom_reason.map(str::to_owned),
        created_by: "engine-tests".into(),
        patterns: vec![RulePattern {
            id: Uuid::from_u128(id + 1_000),
            pattern: pattern.into(),
            pattern_type: WildcardPatternType::ExactWord,
        }],
        surfaces: BTreeSet::from([surface]),
        actions,
    }
}

fn action(id: u128, action_type: PolicyActionType) -> PolicyAction {
    action_with_replacement(id, action_type, None)
}

fn action_with_replacement(
    id: u128,
    action_type: PolicyActionType,
    replacement: Option<&str>,
) -> PolicyAction {
    PolicyAction {
        id: Uuid::from_u128(id),
        action_type,
        duration_seconds: None,
        replacement: replacement.map(str::to_owned),
    }
}

fn presentation(message_content: &str) -> Presentation {
    Presentation {
        message_content: Arc::from(message_content),
        display_name: Arc::from("Alice"),
        username: Arc::from("alice"),
        server_name: Arc::from("Example Server"),
        hub_name: Arc::from("Example Hub"),
        ..Presentation::default()
    }
}

async fn evaluator(policies: impl IntoIterator<Item = ContentPolicy>) -> ContentPolicyEvaluator {
    let snapshots = Arc::new(PolicySnapshotStore::new());
    for policy in policies {
        let snapshot = Arc::new(CompiledPolicySnapshot::compile(&policy).unwrap());
        snapshots.replace(snapshot).await;
    }
    ContentPolicyEvaluator::new(snapshots, Arc::new(SideEffectCooldown::new()))
}

fn destination(target_index: usize, server_id: &str) -> Destination {
    Destination {
        target_index,
        server_id: server_id.into(),
    }
}

#[tokio::test]
async fn calls_without_destinations_evaluate_global_policy() {
    let evaluator = evaluator([
        policy(
            1,
            PolicyScope::global(),
            1,
            vec![rule(
                2,
                "global-censor",
                "bad",
                Surface::MessageContent,
                vec![action(3, PolicyActionType::CensorMatch)],
            )],
        ),
        policy(
            4,
            PolicyScope::hub("hub-1"),
            1,
            vec![rule(
                5,
                "hub-block",
                "bad",
                Surface::MessageContent,
                vec![action(6, PolicyActionType::Block)],
            )],
        ),
        policy(
            7,
            PolicyScope::server("server-1"),
            1,
            vec![rule(
                8,
                "server-block",
                "bad",
                Surface::MessageContent,
                vec![action(9, PolicyActionType::Block)],
            )],
        ),
    ])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-2")],
        )
        .unwrap();

    assert_eq!(result.global.scope.authority, Authority::Global);
    assert_eq!(result.global.matched_rules.len(), 1);
    assert_eq!(
        &*result.variants.values().next().unwrap().message_content,
        "b#d"
    );
    assert!(result.sender_feedback.is_none());
}

#[tokio::test]
async fn call_server_censor_applies_only_to_matching_destination() {
    let evaluator = evaluator([policy(
        90,
        PolicyScope::server("server-a"),
        1,
        vec![rule(
            91,
            "server-censor",
            "bad",
            Surface::MessageContent,
            vec![action(92, PolicyActionType::CensorMatch)],
        )],
    )])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-a"), destination(1, "server-b")],
        )
        .unwrap();

    let variants = &result.variants;
    let server_a = &result.destinations[0];
    let server_b = &result.destinations[1];
    assert_eq!(
        &*variants[&server_a.variant_fingerprint.unwrap()].message_content,
        "b#d"
    );
    assert_eq!(
        &*variants[&server_b.variant_fingerprint.unwrap()].message_content,
        "bad"
    );
    assert!(result.sender_feedback.is_none());
}

#[tokio::test]
async fn call_server_block_withholds_only_matching_destination() {
    let evaluator = evaluator([policy(
        100,
        PolicyScope::server("blocked-server"),
        1,
        vec![rule(
            101,
            "server-block",
            "bad",
            Surface::MessageContent,
            vec![action(102, PolicyActionType::Block)],
        )],
    )])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[
                destination(0, "blocked-server"),
                destination(1, "allowed-server"),
            ],
        )
        .unwrap();

    assert!(result.destinations[0].is_blocked());
    assert!(result.destinations[0].variant_fingerprint.is_none());
    assert!(!result.destinations[1].is_blocked());
    assert_eq!(result.variants.len(), 1);
    assert_eq!(
        result.sender_feedback,
        Some(SenderFeedback::ServerFilters {
            destination_count: 1,
        })
    );
}

#[tokio::test]
async fn call_global_block_is_terminal_for_every_destination_with_attribution() {
    let evaluator = evaluator([policy(
        105,
        PolicyScope::global(),
        1,
        vec![rule_with_reason(
            106,
            "global-block",
            "bad",
            Surface::MessageContent,
            Some("global reason"),
            vec![action(107, PolicyActionType::Block)],
        )],
    )])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-a"), destination(1, "server-b")],
        )
        .unwrap();

    assert!(result.variants.is_empty());
    assert!(
        result
            .destinations
            .iter()
            .all(DestinationDecision::is_blocked)
    );
    assert!(result.destinations.iter().all(|destination| {
        destination.blocked_by[0].custom_reason.as_deref() == Some("global reason")
    }));
    assert_eq!(result.evaluated_server_profiles, 0);
    assert_eq!(
        result.sender_feedback,
        Some(SenderFeedback::CallSafetyBlock)
    );
}

#[tokio::test]
async fn call_server_name_replacement_uses_safe_legacy_compatibility_value() {
    let evaluator = evaluator([policy(
        110,
        PolicyScope::server("server-a"),
        1,
        vec![rule(
            111,
            "server-replace-name",
            "Alice",
            Surface::DisplayName,
            vec![action_with_replacement(
                112,
                PolicyActionType::ReplaceName,
                Some("Legacy replacement"),
            )],
        )],
    )])
    .await;
    let canonical = presentation("hello");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-a"), destination(1, "server-b")],
        )
        .unwrap();
    let server_a = &result.destinations[0];
    let server_b = &result.destinations[1];

    let server_a_variant = &result.variants[&server_a.variant_fingerprint.unwrap()];
    assert_eq!(
        &*server_a_variant.display_name,
        crate::content_policy::delivery::DEFAULT_SAFE_NAME
    );
    assert_eq!(&*server_a_variant.username, "alice");
    let server_b_variant = &result.variants[&server_b.variant_fingerprint.unwrap()];
    assert_eq!(&*server_b_variant.display_name, "Alice");
    assert_eq!(&*server_b_variant.username, "alice");
}

#[tokio::test]
async fn hub_name_replacement_ignores_legacy_configured_custom_replacement() {
    let evaluator = evaluator([
        policy(115, PolicyScope::global(), 1, Vec::new()),
        policy(
            116,
            PolicyScope::hub("hub-1"),
            1,
            vec![rule(
                117,
                "hub-replace-name",
                "Alice",
                Surface::DisplayName,
                vec![action_with_replacement(
                    118,
                    PolicyActionType::ReplaceName,
                    Some("Legacy replacement"),
                )],
            )],
        ),
    ])
    .await;
    let canonical = presentation("hello");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[destination(0, "server-1")],
        )
        .unwrap();
    let variant = &result.variants[&result.destinations[0].variant_fingerprint.unwrap()];

    assert_eq!(
        &*variant.display_name,
        crate::content_policy::delivery::DEFAULT_SAFE_NAME
    );
}

#[tokio::test]
async fn global_block_is_terminal_for_hub_evaluation() {
    let evaluator = evaluator([
        policy(
            10,
            PolicyScope::global(),
            1,
            vec![rule(
                11,
                "global-block",
                "bad",
                Surface::MessageContent,
                vec![
                    action(12, PolicyActionType::Block),
                    action(13, PolicyActionType::Log),
                ],
            )],
        ),
        policy(
            14,
            PolicyScope::hub("hub-1"),
            1,
            vec![rule(
                15,
                "hub-block",
                "bad",
                Surface::MessageContent,
                vec![action(16, PolicyActionType::Block)],
            )],
        ),
        policy(
            17,
            PolicyScope::server("server-1"),
            1,
            vec![rule(
                18,
                "server-block",
                "bad",
                Surface::MessageContent,
                vec![action(19, PolicyActionType::Block)],
            )],
        ),
    ])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[destination(0, "server-1")],
        )
        .unwrap();

    assert!(result.global.delivery.is_blocked());
    assert!(result.hub.matched_rules.is_empty());
    assert_eq!(result.evaluated_server_profiles, 0);
    assert!(result.variants.is_empty());
    assert_eq!(result.side_effects.len(), 1);
    assert_eq!(result.side_effects[0].action_type, PolicyActionType::Log);
    assert_eq!(result.destinations[0].policy_id, None);
    assert!(result.destinations[0].is_blocked());
    assert_eq!(
        result.sender_feedback,
        Some(SenderFeedback::GlobalSafetyBlock)
    );
}

#[tokio::test]
async fn hub_block_is_terminal_for_server_evaluation() {
    let evaluator = evaluator([
        policy(20, PolicyScope::global(), 1, Vec::new()),
        policy(
            21,
            PolicyScope::hub("hub-1"),
            1,
            vec![rule_with_reason(
                22,
                "hub-block",
                "bad",
                Surface::MessageContent,
                Some("hub reason"),
                vec![
                    action(23, PolicyActionType::Block),
                    action(24, PolicyActionType::HubWarn),
                ],
            )],
        ),
        policy(
            25,
            PolicyScope::server("server-1"),
            1,
            vec![rule(
                26,
                "server-block",
                "bad",
                Surface::MessageContent,
                vec![action(27, PolicyActionType::Block)],
            )],
        ),
    ])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[destination(0, "server-1")],
        )
        .unwrap();

    assert!(result.global.matched_rules.is_empty());
    assert_eq!(result.hub.matched_rules.len(), 1);
    assert_eq!(result.evaluated_server_profiles, 0);
    assert_eq!(result.side_effects.len(), 1);
    assert_eq!(
        result.side_effects[0].action_type,
        PolicyActionType::HubWarn
    );
    assert_eq!(result.destinations[0].policy_id, None);
    assert!(result.destinations[0].is_blocked());
    assert_eq!(
        result.sender_feedback,
        Some(SenderFeedback::HubModerationBlock {
            custom_reason: Some("hub reason".into()),
        })
    );
}

#[tokio::test]
async fn equivalent_server_profiles_group_evaluation_but_remap_attribution() {
    let evaluator = evaluator([
        policy(
            30,
            PolicyScope::server("server-a"),
            1,
            vec![rule(
                31,
                "server-block",
                "bad",
                Surface::MessageContent,
                vec![action(32, PolicyActionType::Block)],
            )],
        ),
        policy(
            40,
            PolicyScope::server("server-b"),
            1,
            vec![rule(
                41,
                "server-block",
                "bad",
                Surface::MessageContent,
                vec![action(42, PolicyActionType::Block)],
            )],
        ),
    ])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[destination(9, "server-a"), destination(3, "server-b")],
        )
        .unwrap();

    assert_eq!(result.evaluated_server_profiles, 1);
    assert!(result.variants.is_empty());
    assert_eq!(
        result
            .destinations
            .iter()
            .map(|destination| destination.target_index)
            .collect::<Vec<_>>(),
        vec![3, 9]
    );
    let server_b = &result.destinations[0];
    let server_a = &result.destinations[1];
    assert_eq!(server_a.server_id, "server-a");
    assert_eq!(server_a.policy_id, Some(Uuid::from_u128(30)));
    assert_eq!(server_a.matched_rule_ids, vec![Uuid::from_u128(31)]);
    assert_eq!(server_a.blocked_by[0].policy_id, Uuid::from_u128(30));
    assert_eq!(server_a.blocked_by[0].rule_id, Uuid::from_u128(31));
    assert_eq!(server_b.server_id, "server-b");
    assert_eq!(server_b.policy_id, Some(Uuid::from_u128(40)));
    assert_eq!(server_b.matched_rule_ids, vec![Uuid::from_u128(41)]);
    assert_eq!(server_b.blocked_by[0].policy_id, Uuid::from_u128(40));
    assert_eq!(server_b.blocked_by[0].rule_id, Uuid::from_u128(41));
}

#[tokio::test]
async fn server_block_withholds_one_destination_and_reports_filtered_count() {
    let evaluator = evaluator([policy(
        50,
        PolicyScope::server("blocked-server"),
        1,
        vec![rule(
            51,
            "server-block",
            "bad",
            Surface::MessageContent,
            vec![action(52, PolicyActionType::Block)],
        )],
    )])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[
                destination(0, "blocked-server"),
                destination(1, "unfiltered-server"),
            ],
        )
        .unwrap();

    assert!(result.destinations[0].is_blocked());
    assert!(result.destinations[0].variant_fingerprint.is_none());
    assert!(!result.destinations[1].is_blocked());
    assert!(result.destinations[1].variant_fingerprint.is_some());
    assert_eq!(result.variants.len(), 1);
    assert_eq!(
        result.sender_feedback,
        Some(SenderFeedback::ServerFilters {
            destination_count: 1,
        })
    );
}

#[tokio::test]
async fn transforms_compose_across_global_hub_and_server_layers() {
    let evaluator = evaluator([
        policy(
            60,
            PolicyScope::global(),
            1,
            vec![rule(
                61,
                "global-censor",
                "bad",
                Surface::MessageContent,
                vec![action(62, PolicyActionType::CensorMatch)],
            )],
        ),
        policy(
            63,
            PolicyScope::hub("hub-1"),
            1,
            vec![rule(
                64,
                "hub-transform",
                "awful",
                Surface::MessageContent,
                vec![
                    action(65, PolicyActionType::CensorMatch),
                    action(66, PolicyActionType::StripLink),
                ],
            )],
        ),
        policy(
            67,
            PolicyScope::server("server-1"),
            1,
            vec![rule(
                68,
                "server-transform",
                "Alice",
                Surface::DisplayName,
                vec![
                    action_with_replacement(69, PolicyActionType::ReplaceName, Some("Masked")),
                    action(70, PolicyActionType::SuppressLinks),
                ],
            )],
        ),
    ])
    .await;
    let canonical = presentation("bad https://example.test awful");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[destination(0, "server-1")],
        )
        .unwrap();
    let variant = result.variants.values().next().unwrap();

    assert_eq!(&*variant.message_content, "b#d  a###l");
    assert_eq!(
        &*variant.display_name,
        crate::content_policy::delivery::DEFAULT_SAFE_NAME
    );
    assert!(variant.suppress_links);
    assert!(!result.destinations[0].is_blocked());
}

#[tokio::test]
async fn delivery_actions_are_not_suppressed_by_side_effect_cooldown() {
    let evaluator = evaluator([policy(
        80,
        PolicyScope::global(),
        1,
        vec![rule(
            81,
            "censor-and-log",
            "bad",
            Surface::MessageContent,
            vec![
                action(82, PolicyActionType::CensorMatch),
                action(83, PolicyActionType::Log),
            ],
        )],
    )])
    .await;
    let canonical = presentation("bad");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let first = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-1")],
        )
        .unwrap();
    let second = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-1")],
        )
        .unwrap();

    assert_eq!(
        &*first.variants.values().next().unwrap().message_content,
        "b#d"
    );
    assert_eq!(
        &*second.variants.values().next().unwrap().message_content,
        "b#d"
    );
    assert_eq!(first.side_effects.len(), 1);
    assert!(second.side_effects.is_empty());
}

#[tokio::test]
async fn obfuscated_native_censor_keeps_complete_span_and_server_destination_filtering() {
    let evaluator = evaluator([
        policy(
            120,
            PolicyScope::global(),
            1,
            vec![rule(
                121,
                "global-censor",
                "wumpus",
                Surface::MessageContent,
                vec![action(122, PolicyActionType::CensorMatch)],
            )],
        ),
        policy(
            123,
            PolicyScope::server("blocked-server"),
            1,
            vec![rule(
                124,
                "server-block",
                "wumpus",
                Surface::MessageContent,
                vec![action(125, PolicyActionType::Block)],
            )],
        ),
    ])
    .await;
    let canonical = presentation("wum-pus");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_hub(
            "subject",
            "hub-1",
            &canonical,
            &analyzed,
            &[
                destination(0, "blocked-server"),
                destination(1, "allowed-server"),
            ],
        )
        .unwrap();

    assert_eq!(result.global.matched_rules.len(), 1);
    assert_eq!(
        result.global.matched_rules[0].surfaces[0].spans,
        vec![crate::content_policy::ByteSpan { start: 0, end: 7 }]
    );
    assert!(result.destinations[0].is_blocked());
    assert!(!result.destinations[1].is_blocked());
    let allowed = &result.variants[&result.destinations[1].variant_fingerprint.unwrap()];
    assert_eq!(&*allowed.message_content, "w#####s");
}

#[tokio::test]
async fn obfuscated_global_block_remains_terminal_for_all_destinations() {
    let evaluator = evaluator([policy(
        130,
        PolicyScope::global(),
        1,
        vec![rule(
            131,
            "global-block",
            "wumpus",
            Surface::MessageContent,
            vec![action(132, PolicyActionType::Block)],
        )],
    )])
    .await;
    let canonical = presentation("w\u{e002e}u\u{e002e}m\u{e002e}p\u{e002e}u\u{e002e}s");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-a"), destination(1, "server-b")],
        )
        .unwrap();

    assert_eq!(result.global.matched_rules.len(), 1);
    assert!(
        result
            .destinations
            .iter()
            .all(DestinationDecision::is_blocked)
    );
    assert!(result.variants.is_empty());
}

#[tokio::test]
async fn security_matching_applies_to_names_without_leaking_auxiliary_text() {
    let evaluator = evaluator([policy(
        140,
        PolicyScope::global(),
        1,
        vec![
            rule(
                141,
                "name-block",
                "wumpus",
                Surface::DisplayName,
                vec![action(142, PolicyActionType::Block)],
            ),
            rule(
                143,
                "log-obfuscated",
                "wumpus",
                Surface::MessageContent,
                vec![action(144, PolicyActionType::Log)],
            ),
        ],
    )])
    .await;
    let mut canonical = presentation("wum-pus");
    canonical.display_name = Arc::from("wum-pus");
    let analyzed = AnalyzedContent::from_presentation(&canonical);

    let result = evaluator
        .evaluate_call_for_destinations(
            "subject",
            &canonical,
            &analyzed,
            &[destination(0, "server-a")],
        )
        .unwrap();

    assert!(result.global.delivery.is_blocked());
    assert_eq!(result.side_effects.len(), 1);
    assert!(!format!("{:?}", result.side_effects).contains("wumpus"));
}
