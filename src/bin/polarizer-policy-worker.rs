use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use mlua::{Lua, LuaOptions, LuaSerdeExt, StdLib, Table, Value, VmState};
use polarizer::policy::{
    model::{ConditionTrace, Effect, Scope, Subject, TextSpan},
    runtime::{Diagnostic, DiagnosticSeverity},
    worker_protocol::{SerializableRuntimeEvaluation, WorkerLimits, WorkerRequest, WorkerResponse},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<WorkerRequest>(&line) {
            Ok(request) => handle(request),
            Err(_) => WorkerResponse::failure("INVALID_PROTOCOL", "invalid worker request"),
        };
        let encoded = serde_json::to_vec(&response)?;
        stdout.write_all(&encoded).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

fn handle(request: WorkerRequest) -> WorkerResponse {
    match request {
        WorkerRequest::Validate {
            source,
            source_limit,
        } => {
            let diagnostics = if source.len() > source_limit {
                vec![Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "LUAU_SOURCE_TOO_LARGE".into(),
                    message: "source exceeds configured limit".into(),
                    line: None,
                    column: None,
                }]
            } else {
                match sandbox_compiler().compile(&source) {
                    Ok(_) => Vec::new(),
                    Err(error) => vec![Diagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: "LUAU_COMPILE_ERROR".into(),
                        message: error.to_string(),
                        line: None,
                        column: None,
                    }],
                }
            };
            WorkerResponse {
                diagnostics,
                evaluations: Vec::new(),
                error_code: None,
                safe_error: None,
            }
        }
        WorkerRequest::Evaluate {
            bytecode,
            action,
            features,
            limits,
        } => evaluate(&bytecode, *action, *features, &limits),
    }
}

fn evaluate(
    bytecode: &[u8],
    action: polarizer::policy::model::Action,
    features: polarizer::policy::model::FeatureSnapshot,
    limits: &WorkerLimits,
) -> WorkerResponse {
    let libraries = StdLib::COROUTINE
        | StdLib::TABLE
        | StdLib::STRING
        | StdLib::UTF8
        | StdLib::BIT
        | StdLib::MATH
        | StdLib::BUFFER
        | StdLib::VECTOR;
    let lua = match Lua::new_with(libraries, LuaOptions::default()) {
        Ok(lua) => lua,
        Err(_) => {
            return WorkerResponse::failure(
                "SANDBOX_INITIALIZATION",
                "policy sandbox could not be initialized",
            );
        }
    };
    if let Err(error) = configure_sandbox(&lua, limits) {
        return classify_error(&error);
    }

    let action_value = match lua.to_value(&action) {
        Ok(value) => value,
        Err(error) => return classify_error(&error),
    };
    let feature_values: std::collections::BTreeMap<_, _> = features
        .iter()
        .filter_map(|(name, value)| value.value.clone().map(|resolved| (name.clone(), resolved)))
        .collect();
    let features_value = match lua.to_value(&feature_values) {
        Ok(value) => value,
        Err(error) => return classify_error(&error),
    };

    if let Err(error) = freeze_value(action_value.clone())
        .and_then(|_| freeze_value(features_value.clone()))
        .and_then(|_| lua.globals().set("action", action_value))
        .and_then(|_| lua.globals().set("features", features_value))
        .and_then(|_| install_effect_constructors(&lua))
    {
        return classify_error(&error);
    }

    let returned: Value = match lua.load(bytecode).set_name("policy").eval() {
        Ok(value) => value,
        Err(error) => return classify_error(&error),
    };
    let effects: Vec<Effect> = match lua.from_value(returned) {
        Ok(effects) => effects,
        Err(_) => {
            return WorkerResponse::failure(
                "MALFORMED_EFFECTS",
                "policy must return an array of typed effects",
            );
        }
    };
    match serde_json::to_vec(&effects) {
        Ok(encoded) if encoded.len() <= limits.output_bytes => {
            WorkerResponse::success(vec![SerializableRuntimeEvaluation {
                rule_id: "luau.main".into(),
                effects,
                conditions: vec![ConditionTrace {
                    path: "luau.return".into(),
                    result: serde_json::Value::Bool(true),
                }],
            }])
        }
        Ok(_) => WorkerResponse::failure("OUTPUT_LIMIT", "policy output exceeded its limit"),
        Err(_) => WorkerResponse::failure(
            "MALFORMED_EFFECTS",
            "policy returned unserializable effects",
        ),
    }
}

fn configure_sandbox(lua: &Lua, limits: &WorkerLimits) -> mlua::Result<()> {
    lua.sandbox(true)?;
    lua.set_memory_limit(limits.heap_bytes)?;
    for forbidden in [
        "os", "io", "package", "debug", "require", "load", "loadfile", "dofile",
    ] {
        lua.globals().set(forbidden, Value::Nil)?;
    }
    let started = Instant::now();
    let interrupt_count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&interrupt_count);
    let interrupt_limit = limits.interrupt_limit;
    let cpu_limit = Duration::from_millis(limits.cpu_millis);
    lua.set_interrupt(move |_| {
        if counter.fetch_add(1, Ordering::Relaxed) >= interrupt_limit
            || started.elapsed() >= cpu_limit
        {
            return Err(mlua::Error::runtime("POLICY_EXECUTION_LIMIT"));
        }
        Ok(VmState::Continue)
    });
    Ok(())
}

fn sandbox_compiler() -> mlua::Compiler {
    mlua::Compiler::new().set_mutable_globals(
        [
            "os", "io", "package", "debug", "require", "load", "loadfile", "dofile",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    )
}

fn install_effect_constructors(lua: &Lua) -> mlua::Result<()> {
    let effects = lua.create_table()?;
    effects.set(
        "allow",
        lua.create_function(|lua, (effect_id, reason_codes): (String, Vec<String>)| {
            lua.to_value(&Effect::Allow {
                effect_id,
                reason_codes,
            })
        })?,
    )?;
    effects.set("block", lua.create_function(|lua, (effect_id, reason_codes, public_reason): (String, Vec<String>, Option<String>)| {
        lua.to_value(&Effect::Block { effect_id, reason_codes, public_reason })
    })?)?;
    effects.set("hold", lua.create_function(|lua, (effect_id, reason_codes, maximum_duration_ms): (String, Vec<String>, Option<u64>)| {
        lua.to_value(&Effect::Hold { effect_id, reason_codes, maximum_duration_ms })
    })?)?;
    effects.set(
        "censor",
        lua.create_function(
            |lua,
             (effect_id, spans, replacement, reason_codes): (
                String,
                Value,
                String,
                Vec<String>,
            )| {
                lua.to_value(&Effect::Censor {
                    effect_id,
                    spans: lua.from_value::<Vec<TextSpan>>(spans)?,
                    replacement,
                    reason_codes,
                })
            },
        )?,
    )?;
    effects.set(
        "flag",
        lua.create_function(
            |lua, (effect_id, flag_type, severity, evidence): (String, String, f64, Value)| {
                lua.to_value(&Effect::Flag {
                    effect_id,
                    flag_type,
                    severity,
                    evidence: lua.from_value(evidence)?,
                })
            },
        )?,
    )?;
    effects.set(
        "notify",
        lua.create_function(
            |lua, (effect_id, recipient, template, parameters): (String, String, String, Value)| {
                lua.to_value(&Effect::Notify {
                    effect_id,
                    recipient,
                    template,
                    parameters: lua.from_value(parameters)?,
                })
            },
        )?,
    )?;
    effects.set(
        "create_infraction",
        lua.create_function(
            |lua,
             (effect_id, subject, infraction_type, reason, duration_ms): (
                String,
                Value,
                String,
                String,
                Option<u64>,
            )| {
                lua.to_value(&Effect::CreateInfraction {
                    effect_id,
                    subject: lua.from_value::<Subject>(subject)?,
                    infraction_type,
                    reason,
                    duration_ms,
                })
            },
        )?,
    )?;
    effects.set(
        "create_restriction",
        lua.create_function(
            |lua,
             (effect_id, subject, restriction_type, reason, duration_ms): (
                String,
                Value,
                String,
                String,
                Option<u64>,
            )| {
                lua.to_value(&Effect::CreateRestriction {
                    effect_id,
                    subject: lua.from_value::<Subject>(subject)?,
                    restriction_type,
                    reason,
                    duration_ms,
                })
            },
        )?,
    )?;
    effects.set("route_review", lua.create_function(|lua, (effect_id, queue, priority, reason_codes): (String, String, i32, Vec<String>)| {
        lua.to_value(&Effect::RouteReview { effect_id, queue, priority, reason_codes })
    })?)?;
    effects.set(
        "label_entity",
        lua.create_function(
            |lua, (effect_id, subject, label, value): (String, Value, String, Value)| {
                lua.to_value(&Effect::LabelEntity {
                    effect_id,
                    subject: lua.from_value::<Subject>(subject)?,
                    label,
                    value: lua.from_value(value)?,
                })
            },
        )?,
    )?;
    effects.set(
        "increment_counter",
        lua.create_function(
            |lua,
             (effect_id, subject, scope, counter_type, delta, window_ms, reset): (
                String,
                Value,
                Value,
                String,
                i64,
                u64,
                bool,
            )| {
                lua.to_value(&Effect::IncrementCounter {
                    effect_id,
                    subject: lua.from_value::<Subject>(subject)?,
                    scope: lua.from_value::<Scope>(scope)?,
                    counter_type,
                    delta,
                    window_ms,
                    reset,
                })
            },
        )?,
    )?;
    effects.set(
        "delete",
        lua.create_function(
            |lua,
             (effect_id, message_id, channel_id, reason_codes): (
                String,
                String,
                String,
                Vec<String>,
            )| {
                lua.to_value(&Effect::Delete {
                    effect_id,
                    message_id,
                    channel_id,
                    reason_codes,
                })
            },
        )?,
    )?;
    effects.set(
        "kick",
        lua.create_function(
            |lua,
             (effect_id, user_id, server_id, reason_codes): (
                String,
                String,
                String,
                Vec<String>,
            )| {
                lua.to_value(&Effect::Kick {
                    effect_id,
                    user_id,
                    server_id,
                    reason_codes,
                })
            },
        )?,
    )?;
    effects.set_readonly(true);
    lua.globals().set("effects", effects)
}

fn freeze_value(value: Value) -> mlua::Result<()> {
    if let Value::Table(table) = value {
        freeze_table(&table)?;
    }
    Ok(())
}

fn freeze_table(table: &Table) -> mlua::Result<()> {
    for pair in table.clone().pairs::<Value, Value>() {
        let (_, value) = pair?;
        if let Value::Table(child) = value {
            freeze_table(&child)?;
        }
    }
    table.set_readonly(true);
    Ok(())
}

fn classify_error(error: &mlua::Error) -> WorkerResponse {
    let safe = error.to_string();
    if safe.contains("memory") {
        WorkerResponse::failure("MEMORY_LIMIT", "policy exceeded its memory limit")
    } else if safe.contains("POLICY_EXECUTION_LIMIT") {
        WorkerResponse::failure("TIMEOUT", "policy exceeded its execution limit")
    } else {
        WorkerResponse::failure("RUNTIME_ERROR", "policy execution failed")
    }
}
