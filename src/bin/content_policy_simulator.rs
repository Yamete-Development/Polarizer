use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, ensure};
use polarizer::{
    content_policy::{
        AnalyzedContent, Authority, CompiledPolicySnapshot, ContentPolicyEvaluator, Destination,
        MatchedRule, PolicyAction, PolicyActionType, PolicyLimits, PolicyRule, PolicyScope,
        PolicySnapshotStore, Presentation, ResolvedScopeDecision, SenderFeedback,
        SideEffectCooldown, Surface,
        repository::{ContentPolicySource, PostgresContentPolicyRepository},
        validate_and_classify_policy,
    },
    db,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimulationMode {
    Call,
    Hub,
}

struct Arguments {
    mode: SimulationMode,
    hub_id: String,
    server_ids: Vec<String>,
    subject_id: String,
    content: String,
    display_name: String,
    username: String,
    server_name: String,
    hub_name: String,
}

#[derive(Default)]
struct DiagnosticCatalog {
    patterns: HashMap<Uuid, String>,
    rules: HashMap<Uuid, PolicyRule>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("content-policy simulator failed: {error:#}");
        std::process::exit(2);
    }
}

async fn run() -> anyhow::Result<()> {
    let Some(arguments) = parse_arguments()? else {
        return Ok(());
    };
    ensure!(
        matches!(
            std::env::var("POLARIZER_INTERNAL_DIAGNOSTICS").as_deref(),
            Ok("enabled")
        ),
        "set POLARIZER_INTERNAL_DIAGNOSTICS=enabled to acknowledge this sensitive internal diagnostic"
    );
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required; use a read-only Polarizer database role")?;
    let pool = db::init_pool(&database_url, 2)
        .await
        .context("failed to connect to the Polarizer policy database")?;
    let repository = PostgresContentPolicyRepository::new(pool.clone(), "diagnostic-only");
    let snapshots = Arc::new(PolicySnapshotStore::new());
    let mut catalog = DiagnosticCatalog::default();

    load_diagnostic_scope(
        &repository,
        &snapshots,
        &PolicyScope::global(),
        &mut catalog,
    )
    .await?;
    if arguments.mode == SimulationMode::Hub {
        load_diagnostic_scope(
            &repository,
            &snapshots,
            &PolicyScope::hub(&arguments.hub_id),
            &mut catalog,
        )
        .await?;
        let mut unique_servers = arguments.server_ids.clone();
        unique_servers.sort();
        unique_servers.dedup();
        for server_id in unique_servers {
            load_diagnostic_scope(
                &repository,
                &snapshots,
                &PolicyScope::server(server_id),
                &mut catalog,
            )
            .await?;
        }
    }

    let presentation = Presentation {
        message_content: Arc::from(arguments.content.as_str()),
        display_name: Arc::from(arguments.display_name.as_str()),
        username: Arc::from(arguments.username.as_str()),
        server_name: Arc::from(arguments.server_name.as_str()),
        hub_name: Arc::from(arguments.hub_name.as_str()),
        ..Presentation::default()
    };
    let analyzed = AnalyzedContent::from_presentation(&presentation);
    let evaluator = ContentPolicyEvaluator::new(snapshots, Arc::new(SideEffectCooldown::new()));

    let result = match arguments.mode {
        SimulationMode::Call => {
            let plan = evaluator.evaluate_call(&arguments.subject_id, &presentation, &analyzed)?;
            json!({
                "mode": "CALL",
                "input": input_json(&arguments),
                "normalization": normalization_json(&analyzed),
                "global": resolved_scope_json(&plan.global, &catalog),
                "delivery_variant": plan.variant.as_ref().map(delivery_variant_json),
                "side_effects": plan.side_effects.iter().map(side_effect_json).collect::<Vec<_>>(),
                "sender_feedback": plan.sender_feedback.as_ref().map(sender_feedback_json),
            })
        }
        SimulationMode::Hub => {
            let destinations = arguments
                .server_ids
                .iter()
                .enumerate()
                .map(|(target_index, server_id)| Destination {
                    target_index,
                    server_id: server_id.clone(),
                })
                .collect::<Vec<_>>();
            let plan = evaluator.evaluate_hub(
                &arguments.subject_id,
                &arguments.hub_id,
                &presentation,
                &analyzed,
                &destinations,
            )?;
            json!({
                "mode": "HUB",
                "input": input_json(&arguments),
                "normalization": normalization_json(&analyzed),
                "global": resolved_scope_json(&plan.global, &catalog),
                "hub": resolved_scope_json(&plan.hub, &catalog),
                "destinations": plan.destinations.iter().map(|decision| json!({
                    "target_index": decision.target_index,
                    "server_id": decision.server_id,
                    "policy_id": decision.policy_id,
                    "policy_version": decision.policy_version,
                    "blocked": decision.is_blocked(),
                    "blocked_by": decision.blocked_by.iter().map(attribution_json).collect::<Vec<_>>(),
                    "matched_rules": decision.matched_rule_ids.iter().map(|rule_id| {
                        catalog.rules.get(rule_id).map(rule_definition_json).unwrap_or_else(|| json!({
                            "rule_id": rule_id,
                            "unavailable": true,
                        }))
                    }).collect::<Vec<_>>(),
                    "variant_fingerprint": decision.variant_fingerprint.map(hex::encode),
                })).collect::<Vec<_>>(),
                "delivery_variants": plan.variants.iter().map(|(fingerprint, variant)| json!({
                    "fingerprint": hex::encode(fingerprint),
                    "presentation": delivery_variant_json(variant),
                })).collect::<Vec<_>>(),
                "side_effects": plan.side_effects.iter().map(side_effect_json).collect::<Vec<_>>(),
                "sender_feedback": plan.sender_feedback.as_ref().map(sender_feedback_json),
                "evaluated_server_profiles": plan.evaluated_server_profiles,
            })
        }
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    pool.close().await;
    Ok(())
}

async fn load_diagnostic_scope(
    repository: &PostgresContentPolicyRepository,
    snapshots: &PolicySnapshotStore,
    scope: &PolicyScope,
    catalog: &mut DiagnosticCatalog,
) -> anyhow::Result<()> {
    let Some(mut policy) = repository.load_scope(scope).await? else {
        return Ok(());
    };
    validate_and_classify_policy(&mut policy, PolicyLimits::default())
        .with_context(|| format!("invalid policy for {}", scope_label(scope)))?;
    for rule in &policy.rules {
        catalog.rules.insert(rule.id, rule.clone());
        for pattern in &rule.patterns {
            catalog.patterns.insert(pattern.id, pattern.pattern.clone());
        }
    }
    if policy.enabled {
        snapshots
            .replace(Arc::new(CompiledPolicySnapshot::compile_diagnostic(
                &policy,
            )?))
            .await;
    }
    Ok(())
}

fn parse_arguments() -> anyhow::Result<Option<Arguments>> {
    let mut mode = None;
    let mut hub_id = String::new();
    let mut server_ids = Vec::new();
    let mut subject_id = "diagnostic-subject".to_owned();
    let mut content = None;
    let mut display_name = String::new();
    let mut username = String::new();
    let mut server_name = String::new();
    let mut hub_name = String::new();
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        if matches!(argument.as_str(), "--help" | "-h") {
            print_help();
            return Ok(None);
        }
        let value = arguments
            .next()
            .with_context(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--mode" => {
                mode = Some(match value.to_ascii_lowercase().as_str() {
                    "call" => SimulationMode::Call,
                    "hub" => SimulationMode::Hub,
                    _ => anyhow::bail!("--mode must be call or hub"),
                });
            }
            "--hub-id" => hub_id = value,
            "--server-id" => server_ids.push(value),
            "--subject-id" => subject_id = value,
            "--content" => content = Some(value),
            "--display-name" => display_name = value,
            "--username" => username = value,
            "--server-name" => server_name = value,
            "--hub-name" => hub_name = value,
            _ => anyhow::bail!("unknown argument {argument}; use --help for usage"),
        }
    }

    let mode = mode.context("--mode is required")?;
    let content = content.context("--content is required")?;
    match mode {
        SimulationMode::Call => ensure!(
            hub_id.is_empty() && server_ids.is_empty(),
            "Call simulation accepts GLOBAL policy only; omit --hub-id and --server-id"
        ),
        SimulationMode::Hub => ensure!(
            !hub_id.trim().is_empty(),
            "--hub-id is required for Hub mode"
        ),
    }
    Ok(Some(Arguments {
        mode,
        hub_id,
        server_ids,
        subject_id,
        content,
        display_name,
        username,
        server_name,
        hub_name,
    }))
}

fn print_help() {
    println!(
        "Read-only Polarizer content-policy simulator\n\n\
         Authorization:\n  Use a read-only DATABASE_URL and set \
         POLARIZER_INTERNAL_DIAGNOSTICS=enabled.\n\n\
         Usage:\n  cargo run --bin content_policy_simulator -- \
         --mode call --content \"message\" [surface options]\n\
           cargo run --bin content_policy_simulator -- --mode hub --hub-id HUB \
         --server-id SERVER --content \"message\" [surface options]\n\n\
         Options:\n  --mode call|hub\n  --hub-id ID\n  --server-id ID (repeatable)\n  \
         --subject-id ID\n  --content TEXT\n  --display-name TEXT\n  --username TEXT\n  \
         --server-name TEXT\n  --hub-name TEXT"
    );
}

fn input_json(arguments: &Arguments) -> Value {
    json!({
        "subject_id": arguments.subject_id,
        "hub_id": arguments.hub_id,
        "server_ids": arguments.server_ids,
        "message_content": arguments.content,
        "display_name": arguments.display_name,
        "username": arguments.username,
        "server_name": arguments.server_name,
        "hub_name": arguments.hub_name,
    })
}

fn normalization_json(analyzed: &AnalyzedContent) -> Value {
    Value::Array(
        analyzed
            .normalized_surfaces()
            .iter()
            .map(|(surface, text)| {
                json!({
                    "surface": surface_name(*surface),
                    "normalized": text.as_str(),
                })
            })
            .collect(),
    )
}

fn resolved_scope_json(decision: &ResolvedScopeDecision, catalog: &DiagnosticCatalog) -> Value {
    json!({
        "scope": scope_json(&decision.scope),
        "matched_rules": decision.matched_rules.iter().map(|rule| matched_rule_json(rule, catalog)).collect::<Vec<_>>(),
        "delivery": {
            "blocked": decision.delivery.is_blocked(),
            "blocked_by": decision.delivery.blocked_by.iter().map(attribution_json).collect::<Vec<_>>(),
            "censor_spans": decision.delivery.censor_spans.iter().map(|(surface, spans)| json!({
                "surface": surface_name(*surface),
                "spans": spans.iter().map(|span| json!({"start": span.start, "end": span.end})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "strip_links": decision.delivery.strip_links,
            "suppress_links": decision.delivery.suppress_links,
            "name_replacements": decision.delivery.name_replacements.iter().map(|(surface, replacement)| json!({
                "surface": surface_name(*surface),
                "replacement": replacement.replacement,
                "attribution": attribution_json(&replacement.attribution),
            })).collect::<Vec<_>>(),
        },
        "side_effects": decision.side_effects.iter().map(side_effect_json).collect::<Vec<_>>(),
    })
}

fn matched_rule_json(rule: &MatchedRule, catalog: &DiagnosticCatalog) -> Value {
    json!({
        "policy_id": rule.policy_id,
        "policy_version": rule.policy_version,
        "scope": scope_json(&rule.scope),
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "custom_reason": rule.custom_reason,
        "actions": rule.actions.iter().map(action_json).collect::<Vec<_>>(),
        "matches": rule.surfaces.iter().map(|matched| json!({
            "surface": surface_name(matched.surface),
            "spans": matched.spans.iter().map(|span| json!({"start": span.start, "end": span.end})).collect::<Vec<_>>(),
            "patterns": matched.pattern_ids.iter().map(|pattern_id| json!({
                "pattern_id": pattern_id,
                "pattern": catalog.patterns.get(pattern_id),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn rule_definition_json(rule: &PolicyRule) -> Value {
    json!({
        "rule_id": rule.id,
        "rule_name": rule.name,
        "custom_reason": rule.custom_reason,
        "actions": rule.actions.iter().map(action_json).collect::<Vec<_>>(),
    })
}

fn action_json(action: &PolicyAction) -> Value {
    json!({
        "action": action_name(action.action_type),
        "duration_seconds": action.duration_seconds,
        "replacement": action.replacement,
    })
}

fn side_effect_json(effect: &polarizer::content_policy::SideEffectRequest) -> Value {
    json!({
        "action": action_name(effect.action_type),
        "duration_seconds": effect.duration_seconds,
        "attribution": attribution_json(&effect.attribution),
    })
}

fn attribution_json(attribution: &polarizer::content_policy::resolver::EffectAttribution) -> Value {
    json!({
        "policy_id": attribution.policy_id,
        "policy_version": attribution.policy_version,
        "scope": scope_json(&attribution.scope),
        "rule_id": attribution.rule_id,
        "rule_name": attribution.rule_name,
        "custom_reason": attribution.custom_reason,
    })
}

fn delivery_variant_json(variant: &polarizer::content_policy::DeliveryVariant) -> Value {
    json!({
        "message_content": variant.message_content.as_ref(),
        "display_name": variant.display_name.as_ref(),
        "username": variant.username.as_ref(),
        "server_name": variant.server_name.as_ref(),
        "hub_name": variant.hub_name.as_ref(),
        "suppress_links": variant.suppress_links,
        "fingerprint": hex::encode(variant.fingerprint),
    })
}

fn sender_feedback_json(feedback: &SenderFeedback) -> Value {
    match feedback {
        SenderFeedback::GlobalSafetyBlock => json!({"type": "GLOBAL_SAFETY_BLOCK"}),
        SenderFeedback::CallSafetyBlock => json!({"type": "CALL_SAFETY_BLOCK"}),
        SenderFeedback::HubModerationBlock { custom_reason } => json!({
            "type": "HUB_MODERATION_BLOCK",
            "custom_reason": custom_reason,
        }),
        SenderFeedback::ServerFilters { destination_count } => json!({
            "type": "SERVER_FILTERS",
            "destination_count": destination_count,
        }),
    }
}

fn scope_json(scope: &PolicyScope) -> Value {
    json!({
        "authority": authority_name(scope.authority),
        "scope_id": scope.id,
    })
}

fn scope_label(scope: &PolicyScope) -> String {
    format!("{}:{}", authority_name(scope.authority), scope.id)
}

const fn authority_name(authority: Authority) -> &'static str {
    match authority {
        Authority::Global => "GLOBAL",
        Authority::Hub => "HUB",
        Authority::Server => "SERVER",
    }
}

const fn surface_name(surface: Surface) -> &'static str {
    match surface {
        Surface::MessageContent => "MESSAGE_CONTENT",
        Surface::DisplayName => "DISPLAY_NAME",
        Surface::Username => "USERNAME",
        Surface::ServerName => "SERVER_NAME",
        Surface::HubName => "HUB_NAME",
        Surface::UrlDomain => "URL_DOMAIN",
    }
}

const fn action_name(action: PolicyActionType) -> &'static str {
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
