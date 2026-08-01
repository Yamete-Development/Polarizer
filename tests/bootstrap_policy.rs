use std::collections::{BTreeMap, BTreeSet, HashSet};

use polarizer::policy::{
    ir::PolicyIrRuntime,
    model::{
        Action, DataHandlingClass, Effect, ErrorBehavior, FeatureRequirement, FeatureValue,
        PolicyManifest, Product, Scope, ScopeType, Subject,
    },
    runtime::{PolicyRuntime, sha256_hex},
};
use uuid::Uuid;

const SOURCE: &str = r#"{"rules":[{"id":"shadow-hub-nsfw-review","when":{"operator":"exists","value":{"source":"feature","name":"media.nsfw","path":"0"}},"effects":[{"type":"ROUTE_REVIEW","effect_id":"hub-nsfw-shadow-review","queue":"nsfw-media","priority":50,"reason_codes":["NSFW_MEDIA_SHADOW_MATCH"]}]}]}"#;
const SOURCE_SHA256: &str = "050b1402119333a6748a8f00579cd89d20c1105bfd3bf16ed4c9d6de568c0f98";
const ACTIVE_RESTRICTION_SOURCE: &str = r#"{"rules":[{"id":"block-active-restriction","when":{"operator":"exists","value":{"source":"feature","name":"restrictions.active","path":"0"}},"effects":[{"type":"BLOCK","effect_id":"global-active-restriction","reason_codes":["ACTIVE_RESTRICTION"],"public_reason":"This account or server is restricted."}]}]}"#;
const ACTIVE_RESTRICTION_SOURCE_SHA256: &str =
    "10584793fca13585f164955263086966361ed3c66656ef01d9d105952df491e5";

#[tokio::test]
async fn bootstrap_nsfw_policy_is_valid_shadow_only_policy_ir() {
    let manifest = PolicyManifest {
        accepted_action_types: BTreeSet::from([
            "hub.message.created".into(),
            "hub.message.edited".into(),
        ]),
        accepted_schema_versions: BTreeSet::from([1]),
        required_features: vec![FeatureRequirement {
            name: "media.nsfw".into(),
            error_behavior: ErrorBehavior::Continue,
            deadline_ms: 1_000,
            maximum_data_handling: DataHandlingClass::Sensitive,
            configuration: serde_json::json!({}),
        }],
        capabilities: BTreeSet::from(["ROUTE_REVIEW".into()]),
        runtime_error_behavior: ErrorBehavior::Continue,
    };
    assert_eq!(sha256_hex(SOURCE.as_bytes()), SOURCE_SHA256);
    let runtime = PolicyIrRuntime;
    let diagnostics = runtime.validate(SOURCE, &manifest).await;
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let compiled = runtime.compile(SOURCE, &manifest).await.expect("compiles");
    assert_eq!(compiled.content_sha256, SOURCE_SHA256);

    let source: serde_json::Value = serde_json::from_str(SOURCE).expect("source JSON");
    let effect_types = source["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .flat_map(|rule| rule["effects"].as_array().expect("effects"))
        .filter_map(|effect| effect["type"].as_str())
        .collect::<HashSet<_>>();
    assert_eq!(effect_types, HashSet::from(["ROUTE_REVIEW"]));

    let migration = include_str!("../migrations/20260714000001_trust_safety_v2_baseline.sql");
    assert!(migration.contains(SOURCE));
    assert!(migration.contains(SOURCE_SHA256));
    assert!(migration.contains("'SHADOW_START'"));
    assert!(migration.contains("'bootstrap-hub-nsfw-shadow'"));
}

#[tokio::test]
async fn bootstrap_active_restriction_policy_blocks_lobby_messages() {
    let manifest = PolicyManifest {
        accepted_action_types: BTreeSet::from(["lobby.message.created".into()]),
        accepted_schema_versions: BTreeSet::from([1]),
        required_features: vec![FeatureRequirement {
            name: "restrictions.active".into(),
            error_behavior: ErrorBehavior::Hold,
            deadline_ms: 100,
            maximum_data_handling: DataHandlingClass::Restricted,
            configuration: serde_json::json!({}),
        }],
        capabilities: BTreeSet::new(),
        runtime_error_behavior: ErrorBehavior::Hold,
    };
    let runtime = PolicyIrRuntime;
    let artifact = runtime
        .compile(ACTIVE_RESTRICTION_SOURCE, &manifest)
        .await
        .expect("active restriction policy compiles");
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
            user_id: Some("blacklisted-user".into()),
            ..Subject::default()
        },
        occurred_at: chrono::Utc::now(),
        attributes: serde_json::json!({"content": "hello"}),
        data_handling: DataHandlingClass::Sensitive,
        prism_payload: None,
    };
    let features = BTreeMap::from([(
        "restrictions.active".into(),
        FeatureValue {
            provider: "restrictions.active".into(),
            provider_version: "postgres-v2".into(),
            value: Some(serde_json::json!([{
                "subject_type": "USER",
                "subject_id": "blacklisted-user",
                "restriction_type": "BLACKLIST",
                "scope_type": "PLATFORM",
                "scope_id": ""
            }])),
            error: None,
            latency_micros: 0,
            cache_hit: false,
            input_hash: None,
        },
    )]);

    let evaluations = runtime
        .evaluate(&artifact, &action, &features)
        .await
        .expect("active restriction policy evaluates");

    assert!(matches!(
        evaluations[0].effects.as_slice(),
        [Effect::Block { .. }]
    ));
    assert_eq!(
        sha256_hex(ACTIVE_RESTRICTION_SOURCE.as_bytes()),
        ACTIVE_RESTRICTION_SOURCE_SHA256
    );
    let migration = include_str!("../migrations/20260714000001_trust_safety_v2_baseline.sql");
    assert!(migration.contains(ACTIVE_RESTRICTION_SOURCE));
    assert!(migration.contains(ACTIVE_RESTRICTION_SOURCE_SHA256));
}
