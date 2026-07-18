use std::collections::{BTreeSet, HashSet};

use polarizer::policy::{
    ir::PolicyIrRuntime,
    model::{DataHandlingClass, ErrorBehavior, FeatureRequirement, PolicyManifest},
    runtime::{PolicyRuntime, sha256_hex},
};

const SOURCE: &str = r#"{"rules":[{"id":"shadow-hub-nsfw-review","when":{"operator":"exists","value":{"source":"feature","name":"media.nsfw","path":"0"}},"effects":[{"type":"ROUTE_REVIEW","effect_id":"hub-nsfw-shadow-review","queue":"nsfw-media","priority":50,"reason_codes":["NSFW_MEDIA_SHADOW_MATCH"]}]}]}"#;
const SOURCE_SHA256: &str = "050b1402119333a6748a8f00579cd89d20c1105bfd3bf16ed4c9d6de568c0f98";

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
