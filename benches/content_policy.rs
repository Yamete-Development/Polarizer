use std::{
    collections::BTreeSet,
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

use polarizer::content_policy::{
    AnalyzedContent, CompiledPolicySnapshot, ContentPolicy, ContentPolicyEvaluator, Destination,
    PolicyAction, PolicyActionType, PolicyRule, PolicyScope, PolicySnapshotStore, Presentation,
    RulePattern, SideEffectCooldown, Surface, WildcardPatternType,
};
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

const DEFAULT_SAMPLE_MILLIS: u64 = 200;

struct BenchmarkResult {
    name: &'static str,
    iterations: u64,
    elapsed: Duration,
}

impl BenchmarkResult {
    fn nanos_per_iteration(&self) -> f64 {
        self.elapsed.as_nanos() as f64 / self.iterations as f64
    }
}

struct EvaluatorFixture {
    evaluator: ContentPolicyEvaluator,
    presentation: Presentation,
    analyzed: AnalyzedContent,
    destinations: Vec<Destination>,
}

fn main() {
    let sample_duration = Duration::from_millis(
        std::env::var("POLARIZER_BENCH_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_SAMPLE_MILLIS)
            .max(1),
    );
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime");

    let mut results = Vec::new();
    for pattern_count in [10, 100, 500, 1_000] {
        let snapshot = CompiledPolicySnapshot::compile(&single_rule_policy(
            PolicyScope::global(),
            pattern_count,
            0,
            PolicyActionType::Block,
        ))
        .expect("valid matcher fixture");
        let no_match =
            AnalyzedContent::from_presentation(&presentation("an ordinary short message"));
        let single_match = AnalyzedContent::from_presentation(&presentation(&format!(
            "ordinary text term_0_{}",
            pattern_count - 1
        )));

        results.push(run_benchmark(
            matcher_name(pattern_count, "no_match_short"),
            sample_duration,
            || {
                black_box(
                    snapshot
                        .evaluate_normalized(no_match.normalized_surfaces())
                        .unwrap(),
                )
            },
        ));
        results.push(run_benchmark(
            matcher_name(pattern_count, "single_match_short"),
            sample_duration,
            || {
                black_box(
                    snapshot
                        .evaluate_normalized(single_match.normalized_surfaces())
                        .unwrap(),
                )
            },
        ));
    }

    let security_snapshot = CompiledPolicySnapshot::compile(&security_workload_policy(1_000))
        .expect("valid security matcher fixture");
    let security_no_match = AnalyzedContent::from_presentation(&presentation(
        "an ordinary message with no configured security pattern",
    ));
    results.push(run_benchmark(
        "matcher/security_1000/no_match",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(security_no_match.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let punctuation_match =
        AnalyzedContent::from_presentation(&presentation("ordinary w.u.m.p.u.s message"));
    results.push(run_benchmark(
        "matcher/security/punctuation_match",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(punctuation_match.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let invisible_match =
        AnalyzedContent::from_presentation(&presentation("ordinary wum\u{200b}pus message"));
    results.push(run_benchmark(
        "matcher/security/invisible_match",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(invisible_match.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let markdown_match = AnalyzedContent::from_presentation(&presentation(
        "ordinary wu[m](https://example.com)pus message",
    ));
    results.push(run_benchmark(
        "matcher/security/discord_markdown_match",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(markdown_match.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let mixed_script_match =
        AnalyzedContent::from_presentation(&presentation("ordinary pαypal message"));
    results.push(run_benchmark(
        "matcher/security/mixed_script_match",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(mixed_script_match.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let genuine_non_latin_no_match =
        AnalyzedContent::from_presentation(&presentation("مرحبا こんにちは привет мир"));
    results.push(run_benchmark(
        "matcher/security/genuine_non_latin_no_match",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(genuine_non_latin_no_match.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let long_unicode_control_message = format!(
        "{}{}",
        "👩‍👩‍👧‍👦 👩‍💻 👍🏽 🇺🇳 ❤️ ".repeat(64),
        "ordinary\u{200b} text\u{2060} with\u{feff} controls\u{202e}"
    );
    let long_unicode_control =
        AnalyzedContent::from_presentation(&presentation(&long_unicode_control_message));
    results.push(run_benchmark(
        "matcher/security/long_unicode_control_message",
        sample_duration,
        || {
            black_box(
                security_snapshot
                    .evaluate_normalized(long_unicode_control.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let maximum_message = "ordinary ".repeat(222);
    let maximum_snapshot = CompiledPolicySnapshot::compile(&single_rule_policy(
        PolicyScope::global(),
        1_000,
        1,
        PolicyActionType::Block,
    ))
    .expect("valid maximum-message fixture");
    let maximum_analyzed = AnalyzedContent::from_presentation(&presentation(&maximum_message));
    results.push(run_benchmark(
        "matcher/1000/no_match_2000_chars",
        sample_duration,
        || {
            black_box(
                maximum_snapshot
                    .evaluate_normalized(maximum_analyzed.normalized_surfaces())
                    .unwrap(),
            )
        },
    ));

    let many_matches = many_match_fixture(&runtime, 100);
    results.push(run_benchmark(
        "evaluator/100_simultaneous_censors",
        sample_duration,
        || {
            black_box(
                many_matches
                    .evaluator
                    .evaluate_call(
                        "benchmark-user",
                        &many_matches.presentation,
                        &many_matches.analyzed,
                    )
                    .unwrap(),
            )
        },
    ));

    let transformation = transformation_fixture(&runtime);
    results.push(run_benchmark(
        "evaluator/censor_strip_suppress",
        sample_duration,
        || {
            black_box(
                transformation
                    .evaluator
                    .evaluate_call(
                        "benchmark-user",
                        &transformation.presentation,
                        &transformation.analyzed,
                    )
                    .unwrap(),
            )
        },
    ));

    for (destinations, profiles) in [(1, 0), (100, 12), (500, 12), (700, 12)] {
        let fixture = destination_fixture(&runtime, destinations, profiles);
        results.push(run_benchmark(
            fanout_name(destinations, profiles),
            sample_duration,
            || {
                black_box(
                    fixture
                        .evaluator
                        .evaluate_hub(
                            "benchmark-user",
                            "benchmark-hub",
                            &fixture.presentation,
                            &fixture.analyzed,
                            &fixture.destinations,
                        )
                        .unwrap(),
                )
            },
        ));
    }

    for destinations in [100, 700] {
        let fixture = destination_fixture(&runtime, destinations, destinations);
        results.push(run_benchmark(
            distinct_fanout_name(destinations),
            sample_duration,
            || {
                black_box(
                    fixture
                        .evaluator
                        .evaluate_hub(
                            "benchmark-user",
                            "benchmark-hub",
                            &fixture.presentation,
                            &fixture.analyzed,
                            &fixture.destinations,
                        )
                        .unwrap(),
                )
            },
        ));
    }

    println!("scenario,iterations,total_ms,ns_per_iteration");
    for result in results {
        println!(
            "{},{},{:.3},{:.1}",
            result.name,
            result.iterations,
            result.elapsed.as_secs_f64() * 1_000.0,
            result.nanos_per_iteration(),
        );
    }
}

fn run_benchmark<F, T>(
    name: &'static str,
    sample_duration: Duration,
    mut operation: F,
) -> BenchmarkResult
where
    F: FnMut() -> T,
{
    for _ in 0..32 {
        black_box(operation());
    }
    let started = Instant::now();
    let mut iterations = 0u64;
    while started.elapsed() < sample_duration {
        for _ in 0..16 {
            black_box(operation());
            iterations += 1;
        }
    }
    BenchmarkResult {
        name,
        iterations,
        elapsed: started.elapsed(),
    }
}

fn presentation(content: &str) -> Presentation {
    Presentation {
        message_content: Arc::from(content),
        display_name: Arc::from("Benchmark User"),
        username: Arc::from("benchmark_user"),
        server_name: Arc::from("Benchmark Server"),
        hub_name: Arc::from("Benchmark Hub"),
        ..Presentation::default()
    }
}

fn single_rule_policy(
    scope: PolicyScope,
    pattern_count: usize,
    profile: usize,
    action_type: PolicyActionType,
) -> ContentPolicy {
    ContentPolicy {
        id: fixture_uuid(1, scope_identity(&scope)),
        scope,
        enabled: true,
        version: 1,
        rules: vec![PolicyRule {
            id: fixture_uuid(2, profile as u128),
            name: format!("profile-{profile}"),
            description: String::new(),
            enabled: true,
            custom_reason: None,
            created_by: "benchmark".into(),
            patterns: (0..pattern_count)
                .map(|index| RulePattern {
                    id: fixture_uuid(10, (profile * 10_000 + index) as u128),
                    pattern: format!("term_{profile}_{index}"),
                    pattern_type: WildcardPatternType::ExactWord,
                })
                .collect(),
            surfaces: BTreeSet::from([Surface::MessageContent]),
            actions: vec![PolicyAction {
                id: fixture_uuid(3, profile as u128),
                action_type,
                duration_seconds: None,
                replacement: None,
            }],
        }],
    }
}

fn security_workload_policy(pattern_count: usize) -> ContentPolicy {
    let mut policy = single_rule_policy(
        PolicyScope::global(),
        pattern_count,
        777,
        PolicyActionType::Block,
    );
    let mut patterns = ["wumpus", "paypal", "unicodeprobe"]
        .into_iter()
        .enumerate()
        .map(|(index, pattern)| RulePattern {
            id: fixture_uuid(7_000, index as u128),
            pattern: pattern.into(),
            pattern_type: WildcardPatternType::ExactWord,
        })
        .collect::<Vec<_>>();
    patterns.extend((patterns.len()..pattern_count).map(|index| RulePattern {
        id: fixture_uuid(7_000, index as u128),
        pattern: format!("term{}", alphabetic_suffix(index)),
        pattern_type: WildcardPatternType::ExactWord,
    }));
    policy.rules[0].patterns = patterns;
    policy
}

fn alphabetic_suffix(mut value: usize) -> String {
    let mut result = Vec::new();
    loop {
        result.push((b'a' + (value % 26) as u8) as char);
        if value < 26 {
            break;
        }
        value = value / 26 - 1;
    }
    result.into_iter().rev().collect()
}

fn many_match_fixture(runtime: &Runtime, count: usize) -> EvaluatorFixture {
    let policy = ContentPolicy {
        id: fixture_uuid(100, 0),
        scope: PolicyScope::global(),
        enabled: true,
        version: 1,
        rules: (0..count)
            .map(|index| PolicyRule {
                id: fixture_uuid(101, index as u128),
                name: format!("censor-{index}"),
                description: String::new(),
                enabled: true,
                custom_reason: None,
                created_by: "benchmark".into(),
                patterns: vec![RulePattern {
                    id: fixture_uuid(102, index as u128),
                    pattern: format!("hit{index}"),
                    pattern_type: WildcardPatternType::ExactWord,
                }],
                surfaces: BTreeSet::from([Surface::MessageContent]),
                actions: vec![PolicyAction {
                    id: fixture_uuid(103, index as u128),
                    action_type: PolicyActionType::CensorMatch,
                    duration_seconds: None,
                    replacement: None,
                }],
            })
            .collect(),
    };
    let content = (0..count)
        .map(|index| format!("hit{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    evaluator_fixture(runtime, policy, &content)
}

fn transformation_fixture(runtime: &Runtime) -> EvaluatorFixture {
    let mut policy =
        single_rule_policy(PolicyScope::global(), 1, 999, PolicyActionType::CensorMatch);
    policy.rules[0].patterns[0].pattern = "unsafe".into();
    policy.rules[0].actions.extend([
        PolicyAction {
            id: fixture_uuid(200, 1),
            action_type: PolicyActionType::StripLink,
            duration_seconds: None,
            replacement: None,
        },
        PolicyAction {
            id: fixture_uuid(200, 2),
            action_type: PolicyActionType::SuppressLinks,
            duration_seconds: None,
            replacement: None,
        },
    ]);
    evaluator_fixture(
        runtime,
        policy,
        "unsafe content links to https://example.com/path for context",
    )
}

fn evaluator_fixture(runtime: &Runtime, policy: ContentPolicy, content: &str) -> EvaluatorFixture {
    let snapshots = Arc::new(PolicySnapshotStore::new());
    runtime.block_on(snapshots.replace(Arc::new(
        CompiledPolicySnapshot::compile(&policy).expect("valid evaluator fixture"),
    )));
    let presentation = presentation(content);
    let analyzed = AnalyzedContent::from_presentation(&presentation);
    EvaluatorFixture {
        evaluator: ContentPolicyEvaluator::new(snapshots, Arc::new(SideEffectCooldown::new())),
        presentation,
        analyzed,
        destinations: Vec::new(),
    }
}

fn destination_fixture(
    runtime: &Runtime,
    destination_count: usize,
    profiles: usize,
) -> EvaluatorFixture {
    let snapshots = Arc::new(PolicySnapshotStore::new());
    let destinations = (0..destination_count)
        .map(|index| Destination {
            target_index: index,
            server_id: format!("server-{index}"),
        })
        .collect::<Vec<_>>();

    if profiles > 0 {
        for index in 0..destination_count {
            let profile = index % profiles;
            let mut policy = single_rule_policy(
                PolicyScope::server(format!("server-{index}")),
                20,
                profile,
                PolicyActionType::CensorMatch,
            );
            policy.id = fixture_uuid(300 + index as u128, profile as u128);
            policy.rules[0].id = fixture_uuid(400 + index as u128, profile as u128);
            for (pattern_index, pattern) in policy.rules[0].patterns.iter_mut().enumerate() {
                pattern.id = fixture_uuid(500 + index as u128, pattern_index as u128);
            }
            policy.rules[0].actions[0].id = fixture_uuid(600 + index as u128, profile as u128);
            runtime.block_on(snapshots.replace(Arc::new(
                CompiledPolicySnapshot::compile(&policy).expect("valid destination policy fixture"),
            )));
        }
    }

    let presentation = presentation("ordinary fanout message with no configured match");
    let analyzed = AnalyzedContent::from_presentation(&presentation);
    EvaluatorFixture {
        evaluator: ContentPolicyEvaluator::new(snapshots, Arc::new(SideEffectCooldown::new())),
        presentation,
        analyzed,
        destinations,
    }
}

fn fixture_uuid(namespace: u128, value: u128) -> Uuid {
    Uuid::from_u128((namespace << 64) ^ value)
}

fn scope_identity(scope: &PolicyScope) -> u128 {
    match scope.authority {
        polarizer::content_policy::Authority::Global => 1,
        polarizer::content_policy::Authority::Hub => 2,
        polarizer::content_policy::Authority::Server => 3,
    }
}

fn matcher_name(patterns: usize, suffix: &str) -> &'static str {
    Box::leak(format!("matcher/{patterns}/{suffix}").into_boxed_str())
}

fn fanout_name(destinations: usize, profiles: usize) -> &'static str {
    Box::leak(format!("fanout/{destinations}_destinations/{profiles}_profiles").into_boxed_str())
}

fn distinct_fanout_name(destinations: usize) -> &'static str {
    Box::leak(
        format!("fanout/{destinations}_destinations/{destinations}_distinct_profiles")
            .into_boxed_str(),
    )
}
