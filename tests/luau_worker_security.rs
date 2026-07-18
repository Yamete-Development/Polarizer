use std::{
    collections::BTreeSet,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use chrono::Utc;
use polarizer::policy::{
    luau::LuauRuntime,
    model::{
        Action, DataHandlingClass, ErrorBehavior, FeatureSnapshot, PolicyManifest, Product, Scope,
        ScopeType, Subject,
    },
    runtime::PolicyRuntime,
    worker_protocol::{WorkerLimits, WorkerRequest, WorkerResponse},
};
use uuid::Uuid;

fn request(source: &str, heap_bytes: usize, interrupt_limit: u64) -> WorkerRequest {
    WorkerRequest::Evaluate {
        bytecode: mlua::Compiler::new()
            .set_mutable_globals(
                [
                    "os", "io", "package", "debug", "require", "load", "loadfile", "dofile",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            )
            .compile(source)
            .expect("test policy must compile"),
        action: Box::new(Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub-1".into(),
                product: Some(Product::Hub),
            },
            subject: Subject {
                user_id: Some("user-1".into()),
                ..Subject::default()
            },
            occurred_at: Utc::now(),
            attributes: serde_json::json!({"content": "test"}),
            data_handling: DataHandlingClass::Internal,
            prism_payload: None,
        }),
        features: Box::new(FeatureSnapshot::new()),
        limits: WorkerLimits {
            heap_bytes,
            interrupt_limit,
            cpu_millis: 25,
            output_bytes: 256 * 1024,
        },
    }
}

fn run(requests: &[WorkerRequest]) -> Vec<WorkerResponse> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_polarizer-policy-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("policy worker must start");
    {
        let stdin = child.stdin.as_mut().expect("worker stdin must be piped");
        for request in requests {
            serde_json::to_writer(&mut *stdin, request).expect("request must serialize");
            stdin
                .write_all(b"\n")
                .expect("request delimiter must write");
        }
    }
    let output = child.wait_with_output().expect("worker must exit");
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("worker output must be UTF-8 JSONL")
        .lines()
        .map(|line| serde_json::from_str(line).expect("worker response must deserialize"))
        .collect()
}

#[test]
fn forbidden_process_and_module_globals_are_unavailable() {
    let responses = run(&[request(
        r#"
        if os ~= nil then return { effects.block("os", {"SANDBOX_BYPASS"}, nil) } end
        if io ~= nil then return { effects.block("io", {"SANDBOX_BYPASS"}, nil) } end
        if package ~= nil then return { effects.block("package", {"SANDBOX_BYPASS"}, nil) } end
        if debug ~= nil then return { effects.block("debug", {"SANDBOX_BYPASS"}, nil) } end
        if require ~= nil then return { effects.block("require", {"SANDBOX_BYPASS"}, nil) } end
        if load ~= nil then return { effects.block("load", {"SANDBOX_BYPASS"}, nil) } end
        if loadfile ~= nil then return { effects.block("loadfile", {"SANDBOX_BYPASS"}, nil) } end
        if dofile ~= nil then return { effects.block("dofile", {"SANDBOX_BYPASS"}, nil) } end
        return { effects.allow("sandbox-ok", {"SANDBOX_OK"}) }
        "#,
        4 * 1024 * 1024,
        100_000,
    )]);
    assert_eq!(responses.len(), 1);
    let response = &responses[0];
    assert!(response.error_code.is_none());
    assert!(
        matches!(
            response.evaluations[0].effects[0],
            polarizer::policy::model::Effect::Allow { .. }
        ),
        "sandbox returned an unexpected effect: {:?}",
        response.evaluations[0].effects[0]
    );
}

#[test]
fn infinite_loop_is_interrupted() {
    let responses = run(&[request("while true do end", 4 * 1024 * 1024, 1_000)]);
    assert_eq!(responses.len(), 1);
    let response = &responses[0];
    assert_eq!(response.error_code.as_deref(), Some("TIMEOUT"));
}

#[test]
fn allocation_bomb_is_stopped_by_heap_limit() {
    let responses = run(&[request(
        r#"
        local values = {}
        while true do
            table.insert(values, string.rep("x", 4096))
        end
        "#,
        128 * 1024,
        10_000_000,
    )]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].error_code.as_deref(), Some("MEMORY_LIMIT"));
}

#[test]
fn oversized_effect_output_is_rejected() {
    let responses = run(&[request(
        r#"
        return { effects.block("large", {"LARGE"}, string.rep("x", 300000)) }
        "#,
        4 * 1024 * 1024,
        100_000,
    )]);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].error_code.as_deref(), Some("OUTPUT_LIMIT"));
}

#[test]
fn evaluation_globals_do_not_leak_between_requests() {
    let responses = run(&[
        request(
            "leaked_policy_state = true; return {}",
            4 * 1024 * 1024,
            100_000,
        ),
        request(
            r#"
            if leaked_policy_state ~= nil then
                return { effects.block("leaked", {"GLOBAL_LEAK"}, nil) }
            end
            return { effects.allow("isolated", {"ISOLATED"}) }
            "#,
            4 * 1024 * 1024,
            100_000,
        ),
    ]);
    assert_eq!(responses.len(), 2);
    assert!(matches!(
        responses[1].evaluations[0].effects[0],
        polarizer::policy::model::Effect::Allow { .. }
    ));
}

#[test]
fn advanced_policies_can_emit_every_typed_effect() {
    let responses = run(&[request(
        r#"
        local subject = { user_id = "user-1" }
        local scope = { scope_type = "HUB", id = "hub-1", product = "HUB" }
        return {
            effects.censor("censor", {{start_character = 0, end_character = 4}}, "****", {"MATCH"}),
            effects.flag("flag", "spam", 0.8, {pattern = "p1"}),
            effects.notify("notify", "moderators", "flagged", {severity = "high"}),
            effects.create_infraction("infraction", subject, "WARNING", "test", nil),
            effects.create_restriction("restriction", subject, "MUTE", "test", 60000),
            effects.route_review("review", "urgent", 10, {"REVIEW"}),
            effects.label_entity("label", subject, "trusted", {value = true}),
            effects.increment_counter("counter", subject, scope, "messages", 1, 60000, false),
            effects.delete("delete", "message-1", "channel-1", {"DELETE"}),
            effects.kick("kick", "user-1", "server-1", {"KICK"}),
        }
        "#,
        4 * 1024 * 1024,
        100_000,
    )]);
    assert_eq!(responses.len(), 1);
    let response = &responses[0];
    assert_eq!(response.error_code, None, "{:?}", response.safe_error);
    assert_eq!(response.evaluations[0].effects.len(), 10);
}

#[tokio::test]
async fn production_compiler_cannot_reintroduce_forbidden_globals() {
    let runtime = LuauRuntime::new(
        PathBuf::from(env!("CARGO_BIN_EXE_polarizer-policy-worker")),
        1,
        64 * 1024,
        4 * 1024 * 1024,
        100_000,
        // The production budget applies after a warm worker is available. CI
        // may need longer for the first debug worker process to initialize.
        Duration::from_secs(2),
        256 * 1024,
    );
    let manifest = PolicyManifest {
        accepted_action_types: BTreeSet::new(),
        accepted_schema_versions: BTreeSet::new(),
        required_features: Vec::new(),
        capabilities: BTreeSet::new(),
        runtime_error_behavior: ErrorBehavior::Hold,
    };
    let source = r#"
        if os ~= nil or io ~= nil or package ~= nil or debug ~= nil
            or require ~= nil or load ~= nil or loadfile ~= nil or dofile ~= nil then
            return { effects.block("sandbox-bypass", {"SANDBOX_BYPASS"}, nil) }
        end
        return { effects.allow("sandbox-ok", {"SANDBOX_OK"}) }
    "#;
    let artifact = runtime
        .compile(source, &manifest)
        .await
        .expect("policy must compile");
    let WorkerRequest::Evaluate {
        action, features, ..
    } = request("return {}", 4 * 1024 * 1024, 100_000)
    else {
        unreachable!("request helper always builds an evaluation")
    };
    let evaluations = runtime
        .evaluate(&artifact, &action, &features)
        .await
        .expect("policy must evaluate");
    assert!(matches!(
        evaluations[0].effects[0],
        polarizer::policy::model::Effect::Allow { .. }
    ));
}
