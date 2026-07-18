use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use async_trait::async_trait;
use mlua::Compiler;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};

use super::{
    model::{Action, FeatureSnapshot, PolicyLanguage, PolicyManifest},
    runtime::{
        CompiledArtifact, Diagnostic, DiagnosticSeverity, PolicyRuntime, RuntimeError,
        RuntimeEvaluation, sha256_hex,
    },
    worker_protocol::{WorkerLimits, WorkerRequest, WorkerResponse},
};

pub const LUAU_RUNTIME_VERSION: &str = "luau-v1.0.0";

fn policy_compiler() -> Compiler {
    Compiler::new().set_mutable_globals(
        [
            "os", "io", "package", "debug", "require", "load", "loadfile", "dofile",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    )
}

pub struct LuauRuntime {
    worker_bin: PathBuf,
    slots: Vec<Mutex<Option<WorkerProcess>>>,
    next_slot: AtomicUsize,
    source_limit: usize,
    wall_timeout: Duration,
    limits: WorkerLimits,
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl LuauRuntime {
    pub fn new(
        worker_bin: PathBuf,
        worker_count: usize,
        source_limit: usize,
        heap_limit: usize,
        interrupt_limit: u64,
        wall_timeout: Duration,
        output_limit: usize,
    ) -> Self {
        let worker_count = worker_count.max(1);
        Self {
            worker_bin,
            slots: (0..worker_count).map(|_| Mutex::new(None)).collect(),
            next_slot: AtomicUsize::new(0),
            source_limit,
            wall_timeout,
            limits: WorkerLimits {
                heap_bytes: heap_limit,
                interrupt_limit,
                cpu_millis: 10,
                output_bytes: output_limit,
            },
        }
    }

    async fn request(&self, request: &WorkerRequest) -> Result<WorkerResponse, RuntimeError> {
        let index = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let mut slot = self.slots[index].lock().await;
        if slot.is_none() {
            *slot = Some(spawn_worker(&self.worker_bin).await?);
        }

        let exchange = exchange(
            slot.as_mut().expect("worker initialized"),
            request,
            self.limits.output_bytes,
        );
        match tokio::time::timeout(self.wall_timeout, exchange).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                terminate(&mut slot).await;
                Err(error)
            }
            Err(_) => {
                terminate(&mut slot).await;
                Err(RuntimeError::Timeout)
            }
        }
    }
}

#[async_trait]
impl PolicyRuntime for LuauRuntime {
    fn language(&self) -> PolicyLanguage {
        PolicyLanguage::LuauV1
    }

    fn runtime_version(&self) -> &str {
        LUAU_RUNTIME_VERSION
    }

    async fn validate(&self, source: &str, _manifest: &PolicyManifest) -> Vec<Diagnostic> {
        if source.len() > self.source_limit {
            return vec![Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "LUAU_SOURCE_TOO_LARGE".into(),
                message: format!("source exceeds the {} byte limit", self.source_limit),
                line: None,
                column: None,
            }];
        }

        match policy_compiler().compile(source) {
            Ok(_) => Vec::new(),
            Err(error) => vec![Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "LUAU_COMPILE_ERROR".into(),
                message: error.to_string(),
                line: None,
                column: None,
            }],
        }
    }

    async fn compile(
        &self,
        source: &str,
        manifest: &PolicyManifest,
    ) -> Result<CompiledArtifact, RuntimeError> {
        let diagnostics = self.validate(source, manifest).await;
        if diagnostics
            .iter()
            .any(|item| item.severity == DiagnosticSeverity::Error)
        {
            return Err(RuntimeError::Validation(diagnostics));
        }
        let bytes = policy_compiler().compile(source).map_err(|error| {
            RuntimeError::Validation(vec![Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "LUAU_COMPILE_ERROR".into(),
                message: error.to_string(),
                line: None,
                column: None,
            }])
        })?;
        Ok(CompiledArtifact {
            language: self.language(),
            runtime_version: self.runtime_version().into(),
            content_sha256: sha256_hex(&bytes),
            bytes,
        })
    }

    async fn evaluate(
        &self,
        artifact: &CompiledArtifact,
        action: &Action,
        features: &FeatureSnapshot,
    ) -> Result<Vec<RuntimeEvaluation>, RuntimeError> {
        let response = self
            .request(&WorkerRequest::Evaluate {
                bytecode: artifact.bytes.clone(),
                action: Box::new(action.clone()),
                features: Box::new(features.clone()),
                limits: self.limits.clone(),
            })
            .await?;

        if let Some(code) = response.error_code {
            return Err(match code.as_str() {
                "TIMEOUT" => RuntimeError::Timeout,
                "MEMORY_LIMIT" => RuntimeError::MemoryLimit,
                "MALFORMED_EFFECTS" => {
                    RuntimeError::MalformedEffects(response.safe_error.unwrap_or_default())
                }
                _ => RuntimeError::Worker(
                    response.safe_error.unwrap_or_else(|| "worker error".into()),
                ),
            });
        }
        Ok(response.evaluations.into_iter().map(Into::into).collect())
    }
}

async fn spawn_worker(path: &Path) -> Result<WorkerProcess, RuntimeError> {
    let mut command = Command::new(path);
    command
        .arg("serve")
        .env_clear()
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| RuntimeError::Worker(format!("unable to start worker: {error}")))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| RuntimeError::Worker("worker stdin unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RuntimeError::Worker("worker stdout unavailable".into()))?;
    Ok(WorkerProcess {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

async fn exchange(
    process: &mut WorkerProcess,
    request: &WorkerRequest,
    output_limit: usize,
) -> Result<WorkerResponse, RuntimeError> {
    let mut encoded =
        serde_json::to_vec(request).map_err(|error| RuntimeError::Worker(error.to_string()))?;
    encoded.push(b'\n');
    process
        .stdin
        .write_all(&encoded)
        .await
        .map_err(|error| RuntimeError::Worker(error.to_string()))?;
    process
        .stdin
        .flush()
        .await
        .map_err(|error| RuntimeError::Worker(error.to_string()))?;

    let mut response = String::new();
    let mut limited = (&mut process.stdout).take((output_limit + 1) as u64);
    let read = limited
        .read_line(&mut response)
        .await
        .map_err(|error| RuntimeError::Worker(error.to_string()))?;
    if read == 0 {
        return Err(RuntimeError::Worker(
            "worker exited without a response".into(),
        ));
    }
    if response.len() > output_limit {
        return Err(RuntimeError::Worker(
            "worker response exceeded the output limit".into(),
        ));
    }
    serde_json::from_str(&response)
        .map_err(|error| RuntimeError::Worker(format!("invalid worker response: {error}")))
}

async fn terminate(slot: &mut Option<WorkerProcess>) {
    if let Some(mut process) = slot.take() {
        let _ = process.child.kill().await;
        let _ = process.child.wait().await;
    }
}
