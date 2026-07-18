use serde::{Deserialize, Serialize};

use super::{
    model::{Action, FeatureSnapshot},
    runtime::{Diagnostic, RuntimeEvaluation},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerLimits {
    pub heap_bytes: usize,
    pub interrupt_limit: u64,
    pub cpu_millis: u64,
    pub output_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum WorkerRequest {
    Validate {
        source: String,
        source_limit: usize,
    },
    Evaluate {
        bytecode: Vec<u8>,
        action: Box<Action>,
        features: Box<FeatureSnapshot>,
        limits: WorkerLimits,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub diagnostics: Vec<Diagnostic>,
    pub evaluations: Vec<SerializableRuntimeEvaluation>,
    pub error_code: Option<String>,
    pub safe_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializableRuntimeEvaluation {
    pub rule_id: String,
    pub effects: Vec<super::model::Effect>,
    pub conditions: Vec<super::model::ConditionTrace>,
}

impl From<SerializableRuntimeEvaluation> for RuntimeEvaluation {
    fn from(value: SerializableRuntimeEvaluation) -> Self {
        Self {
            rule_id: value.rule_id,
            effects: value.effects,
            conditions: value.conditions,
        }
    }
}

impl WorkerResponse {
    pub fn success(evaluations: Vec<SerializableRuntimeEvaluation>) -> Self {
        Self {
            diagnostics: Vec::new(),
            evaluations,
            error_code: None,
            safe_error: None,
        }
    }

    pub fn failure(code: impl Into<String>, safe_error: impl Into<String>) -> Self {
        Self {
            diagnostics: Vec::new(),
            evaluations: Vec::new(),
            error_code: Some(code.into()),
            safe_error: Some(safe_error.into()),
        }
    }
}
