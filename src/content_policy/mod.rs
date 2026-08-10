//! Native, compiled content policies for InterChat-controlled presentation surfaces.
//!
//! This subsystem is deliberately separate from the general `policy-ir-v1` and
//! `luau-v1` runtimes. Native content rules have a normalized relational model
//! and a purpose-built matcher so ordinary message evaluation never loads or
//! compiles policy configuration.

pub mod analysis;
pub mod compiler;
pub mod cooldown;
pub mod delivery;
pub mod engine;
#[cfg(test)]
mod engine_tests;
pub mod invalidation;
pub mod matcher;
pub mod model;
pub mod normalization;
pub mod repository;
pub mod resolver;
pub mod service;
pub mod snapshot;
pub mod validation;

pub use analysis::AnalyzedContent;
pub use compiler::{CompiledPolicySnapshot, PolicyMatchError};
pub use cooldown::{CooldownConfig, SideEffectCooldown};
pub use delivery::{DeliveryVariant, Presentation};
pub use engine::{
    CallPolicyPlan, ContentPolicyEvaluator, ContentPolicyPlan, Destination, DestinationDecision,
    HubPolicyPlan, SenderFeedback,
};
pub use invalidation::ContentPolicyInvalidated;
pub use matcher::{CompiledMatcher, MatchDetails, MatchOptions, MatchReport, PatternDefinition};
pub use model::{
    Authority, ContentPolicy, PolicyAction, PolicyActionType, PolicyLimits, PolicyRule,
    PolicyScope, RulePattern, RuleSurface, Surface, WildcardPatternType,
};
pub use normalization::{NormalizedText, normalize_pattern};
pub use resolver::{
    ByteSpan, DeliveryEffects, MatchedRule, MatchedSurface, ResolvedScopeDecision,
    SideEffectRequest,
};
pub use service::{ContentPolicyRuntime, ReloadError};
pub use snapshot::{PolicySnapshotStore, SnapshotUpdate};
pub use validation::{
    ParsedPattern, PatternError, PolicyValidationError, PolicyValidationErrors,
    ValidationErrorCode, classify_pattern, parse_pattern, validate_and_classify_policy,
    validate_policy,
};
