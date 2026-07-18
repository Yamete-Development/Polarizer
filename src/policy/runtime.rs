use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::model::{
    Action, ConditionTrace, Effect, FeatureSnapshot, PolicyLanguage, PolicyManifest,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledArtifact {
    pub language: PolicyLanguage,
    pub runtime_version: String,
    pub content_sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RuntimeEvaluation {
    pub rule_id: String,
    pub effects: Vec<Effect>,
    pub conditions: Vec<ConditionTrace>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("policy validation failed")]
    Validation(Vec<Diagnostic>),
    #[error("policy execution timed out")]
    Timeout,
    #[error("policy exceeded its memory limit")]
    MemoryLimit,
    #[error("policy returned malformed effects: {0}")]
    MalformedEffects(String),
    #[error("policy worker failed: {0}")]
    Worker(String),
}

#[async_trait]
pub trait PolicyRuntime: Send + Sync {
    fn language(&self) -> PolicyLanguage;
    fn runtime_version(&self) -> &str;
    async fn validate(&self, source: &str, manifest: &PolicyManifest) -> Vec<Diagnostic>;
    async fn compile(
        &self,
        source: &str,
        manifest: &PolicyManifest,
    ) -> Result<CompiledArtifact, RuntimeError>;
    async fn evaluate(
        &self,
        artifact: &CompiledArtifact,
        action: &Action,
        features: &FeatureSnapshot,
    ) -> Result<Vec<RuntimeEvaluation>, RuntimeError>;
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
