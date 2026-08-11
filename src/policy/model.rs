use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Product {
    Hub,
    Lobby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeType {
    Platform,
    Product,
    Hub,
    Lobby,
    IncidentOverlay,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    pub scope_type: ScopeType,
    #[serde(default)]
    pub id: String,
    pub product: Option<Product>,
}

impl Scope {
    pub fn precedence(&self) -> u8 {
        match self.scope_type {
            ScopeType::Platform => 0,
            ScopeType::Product => 1,
            ScopeType::Hub | ScopeType::Lobby => 2,
            ScopeType::IncidentOverlay => 3,
        }
    }

    pub fn applies_to(&self, action: &Action) -> bool {
        match self.scope_type {
            ScopeType::Platform => true,
            ScopeType::Product => self.product == action.scope.product,
            ScopeType::Hub | ScopeType::Lobby => {
                self.scope_type == action.scope.scope_type && self.id == action.scope.id
            }
            ScopeType::IncidentOverlay => self.id == action.scope.id || self.id.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub user_id: Option<String>,
    pub server_id: Option<String>,
    pub message_id: Option<String>,
    pub channel_id: Option<String>,
    pub report_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataHandlingClass {
    Public,
    Internal,
    Sensitive,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: Uuid,
    pub action_type: String,
    pub schema_version: u32,
    pub scope: Scope,
    pub subject: Subject,
    pub occurred_at: DateTime<Utc>,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub data_handling: DataHandlingClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prism_payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorBehavior {
    Hold,
    Review,
    Continue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureRequirement {
    pub name: String,
    pub error_behavior: ErrorBehavior,
    pub deadline_ms: u64,
    pub maximum_data_handling: DataHandlingClass,
    #[serde(default)]
    pub configuration: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub accepted_action_types: BTreeSet<String>,
    pub accepted_schema_versions: BTreeSet<u32>,
    #[serde(default)]
    pub required_features: Vec<FeatureRequirement>,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    pub runtime_error_behavior: ErrorBehavior,
}

impl PolicyManifest {
    pub fn accepts(&self, action: &Action) -> bool {
        (self.accepted_action_types.is_empty()
            || self.accepted_action_types.contains(&action.action_type))
            && (self.accepted_schema_versions.is_empty()
                || self
                    .accepted_schema_versions
                    .contains(&action.schema_version))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFailure {
    pub code: String,
    pub safe_message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureValue {
    pub provider: String,
    pub provider_version: String,
    pub value: Option<serde_json::Value>,
    pub error: Option<FeatureFailure>,
    pub latency_micros: u64,
    pub cache_hit: bool,
    pub input_hash: Option<String>,
}

pub type FeatureSnapshot = BTreeMap<String, FeatureValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyLanguage {
    PolicyIrV1,
    LuauV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyState {
    Draft,
    Validated,
    Shadow,
    Active,
    Disabled,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyBundleState {
    Active,
    Disabled,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub scope: Scope,
    pub mandatory: bool,
    pub priority: i32,
    pub active_version_id: Option<Uuid>,
    pub shadow_version_id: Option<Uuid>,
    pub state: PolicyBundleState,
    pub version: i64,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub id: Uuid,
    pub bundle_id: Uuid,
    pub version: i32,
    pub language: PolicyLanguage,
    pub runtime_version: String,
    pub source: String,
    pub compiled_artifact: Vec<u8>,
    pub source_sha256: String,
    pub artifact_sha256: String,
    pub manifest: PolicyManifest,
    pub state: PolicyState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextSpan {
    pub start_character: u32,
    pub end_character: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveRestriction {
    pub id: String,
    pub restriction_type: String,
    pub scope: Scope,
    pub public_reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Enforcement {
    pub subject: Subject,
    pub restriction_type: String,
    pub reason: String,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    Allow {
        effect_id: String,
        reason_codes: Vec<String>,
    },
    Block {
        effect_id: String,
        reason_codes: Vec<String>,
        public_reason: Option<String>,
        active_restriction: Option<ActiveRestriction>,
    },
    Hold {
        effect_id: String,
        reason_codes: Vec<String>,
        maximum_duration_ms: Option<u64>,
    },
    Censor {
        effect_id: String,
        spans: Vec<TextSpan>,
        replacement: String,
        reason_codes: Vec<String>,
    },
    Flag {
        effect_id: String,
        flag_type: String,
        severity: f64,
        evidence: serde_json::Value,
    },
    Notify {
        effect_id: String,
        recipient: String,
        template: String,
        parameters: serde_json::Value,
    },
    CreateInfraction {
        effect_id: String,
        subject: Subject,
        infraction_type: String,
        reason: String,
        duration_ms: Option<u64>,
        enforcement: Option<Enforcement>,
    },
    CreateRestriction {
        effect_id: String,
        subject: Subject,
        restriction_type: String,
        reason: String,
        duration_ms: Option<u64>,
    },
    RouteReview {
        effect_id: String,
        queue: String,
        priority: i32,
        reason_codes: Vec<String>,
    },
    LabelEntity {
        effect_id: String,
        subject: Subject,
        label: String,
        value: serde_json::Value,
    },
    IncrementCounter {
        effect_id: String,
        subject: Subject,
        scope: Scope,
        counter_type: String,
        delta: i64,
        window_ms: u64,
        reset: bool,
    },
    Delete {
        effect_id: String,
        message_id: String,
        channel_id: String,
        reason_codes: Vec<String>,
    },
    Kick {
        effect_id: String,
        user_id: String,
        server_id: String,
        reason_codes: Vec<String>,
    },
}

impl Effect {
    pub fn id(&self) -> &str {
        match self {
            Self::Allow { effect_id, .. }
            | Self::Block { effect_id, .. }
            | Self::Hold { effect_id, .. }
            | Self::Censor { effect_id, .. }
            | Self::Flag { effect_id, .. }
            | Self::Notify { effect_id, .. }
            | Self::CreateInfraction { effect_id, .. }
            | Self::CreateRestriction { effect_id, .. }
            | Self::RouteReview { effect_id, .. }
            | Self::LabelEntity { effect_id, .. }
            | Self::IncrementCounter { effect_id, .. }
            | Self::Delete { effect_id, .. }
            | Self::Kick { effect_id, .. } => effect_id,
        }
    }

    pub fn decision(&self) -> Option<Decision> {
        match self {
            Self::Allow { .. } => Some(Decision::Allow),
            Self::Censor { .. } => Some(Decision::Censor),
            Self::Hold { .. } => Some(Decision::Hold),
            Self::Block { .. } => Some(Decision::Block),
            _ => None,
        }
    }

    pub fn reason_codes(&self) -> &[String] {
        match self {
            Self::Allow { reason_codes, .. }
            | Self::Block { reason_codes, .. }
            | Self::Hold { reason_codes, .. }
            | Self::Censor { reason_codes, .. }
            | Self::RouteReview { reason_codes, .. }
            | Self::Delete { reason_codes, .. }
            | Self::Kick { reason_codes, .. } => reason_codes,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Censor,
    Hold,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectOrigin {
    pub policy_bundle_id: Uuid,
    pub policy_version_id: Uuid,
    pub rule_id: String,
    pub scope: Scope,
    pub priority: i32,
    pub mandatory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmittedEffect {
    pub origin: EffectOrigin,
    pub effect: Effect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedEffect {
    pub effect: EmittedEffect,
    pub reason: String,
    pub superseded_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionTrace {
    pub path: String,
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTrace {
    pub policy_version_id: Uuid,
    pub rule_id: String,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub conditions: Vec<ConditionTrace>,
    pub emitted_effects: Vec<EmittedEffect>,
    pub error: Option<String>,
    pub latency_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub id: Uuid,
    pub action_id: Uuid,
    pub action_schema_version: u32,
    pub policy_versions: Vec<Uuid>,
    pub features: FeatureSnapshot,
    pub rules: Vec<RuleTrace>,
    pub accepted_effect_ids: Vec<String>,
    pub rejected_effects: Vec<RejectedEffect>,
    pub final_decision: Decision,
    pub reason_codes: Vec<String>,
    pub total_latency_micros: u64,
    pub created_at: DateTime<Utc>,
    pub sampled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub id: Uuid,
    pub action_id: Uuid,
    pub decision: Decision,
    pub reason_codes: Vec<String>,
    pub accepted_effects: Vec<EmittedEffect>,
    pub rejected_effects: Vec<RejectedEffect>,
    pub trace: ExecutionTrace,
    pub shadow: bool,
    /// Runtime-only delivery plan produced by the native content engine. Its
    /// relational attribution is persisted through accepted effects and the
    /// transformed variants are applied only while building the Prism job.
    #[serde(skip, default)]
    pub content_policy: Option<crate::content_policy::ContentPolicyPlan>,
}
