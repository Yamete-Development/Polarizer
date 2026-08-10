use std::{collections::BTreeSet, sync::Arc};

use uuid::Uuid;

use super::delivery::Presentation;
use super::{
    AnalyzedContent, Authority, CompiledPolicySnapshot, ContentPolicy, ContentPolicyEvaluator,
    Destination, PolicyAction, PolicyActionType, PolicyRule, PolicyScope, PolicySnapshotStore,
    RulePattern, SenderFeedback, SideEffectCooldown, Surface, WildcardPatternType,
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
async fn calls_evaluate_global_only() {
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
        .evaluate_call("subject", &canonical, &analyzed)
        .unwrap();

    assert_eq!(result.global.scope.authority, Authority::Global);
    assert_eq!(result.global.matched_rules.len(), 1);
    assert_eq!(&*result.variant.unwrap().message_content, "b#d");
    assert!(result.sender_feedback.is_none());
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
    assert_eq!(&*variant.display_name, "Masked");
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
        .evaluate_call("subject", &canonical, &analyzed)
        .unwrap();
    let second = evaluator
        .evaluate_call("subject", &canonical, &analyzed)
        .unwrap();

    assert_eq!(&*first.variant.unwrap().message_content, "b#d");
    assert_eq!(&*second.variant.unwrap().message_content, "b#d");
    assert_eq!(first.side_effects.len(), 1);
    assert!(second.side_effects.is_empty());
}
