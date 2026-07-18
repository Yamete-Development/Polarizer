use std::collections::HashSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{
    model::{Action, ConditionTrace, Effect, FeatureSnapshot, PolicyLanguage, PolicyManifest},
    runtime::{
        CompiledArtifact, Diagnostic, DiagnosticSeverity, PolicyRuntime, RuntimeError,
        RuntimeEvaluation, sha256_hex,
    },
};

pub const POLICY_IR_RUNTIME_VERSION: &str = "policy-ir-v1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrProgram {
    pub rules: Vec<IrRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrRule {
    pub id: String,
    #[serde(default = "default_true")]
    pub when: Condition,
    pub effects: Vec<Effect>,
}

fn default_true() -> Condition {
    Condition::Literal { value: true }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operator", rename_all = "snake_case")]
pub enum Condition {
    Literal {
        value: bool,
    },
    All {
        conditions: Vec<Condition>,
    },
    Any {
        conditions: Vec<Condition>,
    },
    Not {
        condition: Box<Condition>,
    },
    Exists {
        value: ValueRef,
    },
    Eq {
        left: ValueRef,
        right: ValueRef,
    },
    NotEq {
        left: ValueRef,
        right: ValueRef,
    },
    GreaterThan {
        left: ValueRef,
        right: ValueRef,
    },
    GreaterThanOrEqual {
        left: ValueRef,
        right: ValueRef,
    },
    LessThan {
        left: ValueRef,
        right: ValueRef,
    },
    LessThanOrEqual {
        left: ValueRef,
        right: ValueRef,
    },
    Contains {
        container: ValueRef,
        value: ValueRef,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ValueRef {
    Action {
        path: String,
    },
    Feature {
        name: String,
        #[serde(default)]
        path: String,
    },
    Literal {
        value: serde_json::Value,
    },
}

#[derive(Debug, Default)]
pub struct PolicyIrRuntime;

#[async_trait]
impl PolicyRuntime for PolicyIrRuntime {
    fn language(&self) -> PolicyLanguage {
        PolicyLanguage::PolicyIrV1
    }

    fn runtime_version(&self) -> &str {
        POLICY_IR_RUNTIME_VERSION
    }

    async fn validate(&self, source: &str, manifest: &PolicyManifest) -> Vec<Diagnostic> {
        let program: IrProgram = match serde_json::from_str(source) {
            Ok(program) => program,
            Err(error) => {
                return vec![Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "IR_INVALID_JSON".into(),
                    message: error.to_string(),
                    line: Some(error.line() as u32),
                    column: Some(error.column() as u32),
                }];
            }
        };

        let mut diagnostics = Vec::new();
        if program.rules.is_empty() {
            diagnostics.push(error(
                "IR_NO_RULES",
                "a policy must contain at least one rule",
            ));
        }
        let mut rule_ids = HashSet::new();
        let mut effect_ids = HashSet::new();
        let declared_features: HashSet<_> = manifest
            .required_features
            .iter()
            .map(|f| f.name.as_str())
            .collect();

        for rule in &program.rules {
            if rule.id.trim().is_empty() {
                diagnostics.push(error("IR_EMPTY_RULE_ID", "rule ids may not be empty"));
            } else if !rule_ids.insert(rule.id.as_str()) {
                diagnostics.push(error(
                    "IR_DUPLICATE_RULE_ID",
                    &format!("duplicate rule id {}", rule.id),
                ));
            }
            if rule.effects.is_empty() {
                diagnostics.push(error(
                    "IR_NO_EFFECTS",
                    &format!("rule {} has no effects", rule.id),
                ));
            }
            for effect in &rule.effects {
                if effect.id().is_empty() {
                    diagnostics.push(error(
                        "IR_EMPTY_EFFECT_ID",
                        &format!("rule {} has an empty effect id", rule.id),
                    ));
                } else if !effect_ids.insert(effect.id()) {
                    diagnostics.push(error(
                        "IR_DUPLICATE_EFFECT_ID",
                        &format!("duplicate effect id {}", effect.id()),
                    ));
                }
            }
            validate_condition(&rule.when, &declared_features, &mut diagnostics);
        }
        diagnostics
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
        let program: IrProgram = serde_json::from_str(source)
            .map_err(|error| RuntimeError::MalformedEffects(error.to_string()))?;
        let bytes = serde_json::to_vec(&program)
            .map_err(|error| RuntimeError::MalformedEffects(error.to_string()))?;
        Ok(CompiledArtifact {
            language: self.language(),
            runtime_version: self.runtime_version().to_owned(),
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
        let program: IrProgram = serde_json::from_slice(&artifact.bytes)
            .map_err(|error| RuntimeError::MalformedEffects(error.to_string()))?;
        let action_json = serde_json::to_value(action)
            .map_err(|error| RuntimeError::MalformedEffects(error.to_string()))?;
        let mut output = Vec::new();
        for rule in program.rules {
            let mut conditions = Vec::new();
            if evaluate_condition(
                &rule.when,
                &action_json,
                features,
                &mut conditions,
                &rule.id,
            )? {
                output.push(RuntimeEvaluation {
                    rule_id: rule.id,
                    effects: rule.effects,
                    conditions,
                });
            } else {
                output.push(RuntimeEvaluation {
                    rule_id: rule.id,
                    effects: Vec::new(),
                    conditions,
                });
            }
        }
        Ok(output)
    }
}

fn error(code: &str, message: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: code.into(),
        message: message.into(),
        line: None,
        column: None,
    }
}

fn validate_condition(
    condition: &Condition,
    features: &HashSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match condition {
        Condition::All { conditions } | Condition::Any { conditions } => {
            for condition in conditions {
                validate_condition(condition, features, diagnostics);
            }
        }
        Condition::Not { condition } => validate_condition(condition, features, diagnostics),
        Condition::Exists { value } => validate_value_ref(value, features, diagnostics),
        Condition::Eq { left, right }
        | Condition::NotEq { left, right }
        | Condition::GreaterThan { left, right }
        | Condition::GreaterThanOrEqual { left, right }
        | Condition::LessThan { left, right }
        | Condition::LessThanOrEqual { left, right } => {
            validate_value_ref(left, features, diagnostics);
            validate_value_ref(right, features, diagnostics);
        }
        Condition::Contains { container, value } => {
            validate_value_ref(container, features, diagnostics);
            validate_value_ref(value, features, diagnostics);
        }
        Condition::Literal { .. } => {}
    }
}

fn validate_value_ref(
    value: &ValueRef,
    features: &HashSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let ValueRef::Feature { name, .. } = value
        && !features.contains(name.as_str())
    {
        diagnostics.push(error(
            "IR_UNDECLARED_FEATURE",
            &format!("feature {name} is used but not declared in the manifest"),
        ));
    }
}

fn evaluate_condition(
    condition: &Condition,
    action: &serde_json::Value,
    features: &FeatureSnapshot,
    trace: &mut Vec<ConditionTrace>,
    path: &str,
) -> Result<bool, RuntimeError> {
    let next = |suffix: &str| format!("{path}.{suffix}");
    let result = match condition {
        Condition::Literal { value } => *value,
        Condition::All { conditions } => {
            let mut all = true;
            for (index, condition) in conditions.iter().enumerate() {
                all &= evaluate_condition(
                    condition,
                    action,
                    features,
                    trace,
                    &next(&format!("all[{index}]")),
                )?;
            }
            all
        }
        Condition::Any { conditions } => {
            let mut any = false;
            for (index, condition) in conditions.iter().enumerate() {
                any |= evaluate_condition(
                    condition,
                    action,
                    features,
                    trace,
                    &next(&format!("any[{index}]")),
                )?;
            }
            any
        }
        Condition::Not { condition } => {
            !evaluate_condition(condition, action, features, trace, &next("not"))?
        }
        Condition::Exists { value } => resolve(value, action, features).is_some(),
        Condition::Eq { left, right } => {
            resolve(left, action, features) == resolve(right, action, features)
        }
        Condition::NotEq { left, right } => {
            resolve(left, action, features) != resolve(right, action, features)
        }
        Condition::GreaterThan { left, right } => {
            compare_numbers(left, right, action, features, |a, b| a > b)?
        }
        Condition::GreaterThanOrEqual { left, right } => {
            compare_numbers(left, right, action, features, |a, b| a >= b)?
        }
        Condition::LessThan { left, right } => {
            compare_numbers(left, right, action, features, |a, b| a < b)?
        }
        Condition::LessThanOrEqual { left, right } => {
            compare_numbers(left, right, action, features, |a, b| a <= b)?
        }
        Condition::Contains { container, value } => {
            let container = resolve(container, action, features);
            let needle = resolve(value, action, features);
            match (container, needle) {
                (
                    Some(serde_json::Value::String(haystack)),
                    Some(serde_json::Value::String(needle)),
                ) => haystack.contains(&needle),
                (Some(serde_json::Value::Array(values)), Some(needle)) => values.contains(&needle),
                _ => false,
            }
        }
    };
    trace.push(ConditionTrace {
        path: path.to_owned(),
        result: serde_json::Value::Bool(result),
    });
    Ok(result)
}

fn resolve(
    value: &ValueRef,
    action: &serde_json::Value,
    features: &FeatureSnapshot,
) -> Option<serde_json::Value> {
    match value {
        ValueRef::Literal { value } => Some(value.clone()),
        ValueRef::Action { path } => json_path(action, path).cloned(),
        ValueRef::Feature { name, path } => {
            let value = features.get(name)?.value.as_ref()?;
            json_path(value, path).cloned()
        }
    }
}

fn json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    if path.is_empty() {
        return Some(value);
    }
    path.trim_start_matches('/')
        .split(['.', '/'])
        .filter(|part| !part.is_empty())
        .try_fold(value, |current, part| match current {
            serde_json::Value::Object(map) => map.get(part),
            serde_json::Value::Array(values) => part
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index)),
            _ => None,
        })
}

fn compare_numbers(
    left: &ValueRef,
    right: &ValueRef,
    action: &serde_json::Value,
    features: &FeatureSnapshot,
    compare: impl FnOnce(f64, f64) -> bool,
) -> Result<bool, RuntimeError> {
    let left = resolve(left, action, features).and_then(|value| value.as_f64());
    let right = resolve(right, action, features).and_then(|value| value.as_f64());
    Ok(match (left, right) {
        (Some(left), Some(right)) => compare(left, right),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::model::{DataHandlingClass, ErrorBehavior, Scope, ScopeType, Subject};
    use chrono::Utc;
    use std::collections::{BTreeMap, BTreeSet};
    use uuid::Uuid;

    fn manifest() -> PolicyManifest {
        PolicyManifest {
            accepted_action_types: BTreeSet::from(["hub.message.created".into()]),
            accepted_schema_versions: BTreeSet::from([1]),
            required_features: vec![],
            capabilities: BTreeSet::new(),
            runtime_error_behavior: ErrorBehavior::Hold,
        }
    }

    #[tokio::test]
    async fn evaluates_typed_rule_tree() {
        let source = serde_json::json!({
            "rules": [{
                "id": "block-high-risk",
                "when": {"operator":"eq", "left":{"source":"action","path":"attributes.risky"}, "right":{"source":"literal","value":true}},
                "effects": [{"type":"BLOCK","effect_id":"block","reason_codes":["HIGH_RISK"],"public_reason":null}]
            }]
        }).to_string();
        let runtime = PolicyIrRuntime;
        let artifact = runtime.compile(&source, &manifest()).await.unwrap();
        let action = Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub".into(),
                product: None,
            },
            subject: Subject::default(),
            occurred_at: Utc::now(),
            attributes: serde_json::json!({"risky": true}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        };
        let evaluated = runtime
            .evaluate(&artifact, &action, &BTreeMap::new())
            .await
            .unwrap();
        assert_eq!(evaluated[0].effects[0].id(), "block");
    }
}
