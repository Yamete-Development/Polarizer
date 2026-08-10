// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestContext {
    #[prost(string, tag="1")]
    pub request_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub actor_id: ::prost::alloc::string::String,
    #[prost(enumeration="ActorType", tag="3")]
    pub actor_type: i32,
    #[prost(string, tag="4")]
    pub service_principal: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub idempotency_key: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub trace_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Scope {
    #[prost(enumeration="ScopeType", tag="1")]
    pub r#type: i32,
    #[prost(string, tag="2")]
    pub id: ::prost::alloc::string::String,
    #[prost(enumeration="Product", tag="3")]
    pub product: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Subject {
    #[prost(string, tag="1")]
    pub user_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub server_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub message_id: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub channel_id: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub report_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Action {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(uint32, tag="3")]
    pub schema_version: u32,
    #[prost(message, optional, tag="4")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="5")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="6")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="7")]
    pub attributes: ::core::option::Option<::prost_types::Struct>,
    #[prost(enumeration="DataHandlingClass", tag="8")]
    pub data_handling: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FeatureValue {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub provider_version: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub value: ::core::option::Option<::prost_types::Value>,
    #[prost(message, optional, tag="4")]
    pub error: ::core::option::Option<FeatureError>,
    #[prost(message, optional, tag="5")]
    pub latency: ::core::option::Option<::prost_types::Duration>,
    #[prost(bool, tag="6")]
    pub cache_hit: bool,
    #[prost(string, tag="7")]
    pub input_hash: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FeatureError {
    #[prost(enumeration="FeatureErrorCode", tag="1")]
    pub code: i32,
    #[prost(string, tag="2")]
    pub safe_message: ::prost::alloc::string::String,
    #[prost(bool, tag="3")]
    pub retryable: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FeatureSnapshot {
    #[prost(message, repeated, tag="1")]
    pub values: ::prost::alloc::vec::Vec<FeatureValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyEffect {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub rule_id: ::prost::alloc::string::String,
    #[prost(oneof="policy_effect::Effect", tags="10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22")]
    pub effect: ::core::option::Option<policy_effect::Effect>,
}
/// Nested message and enum types in `PolicyEffect`.
pub mod policy_effect {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Effect {
        #[prost(message, tag="10")]
        Allow(super::AllowEffect),
        #[prost(message, tag="11")]
        Block(super::BlockEffect),
        #[prost(message, tag="12")]
        Hold(super::HoldEffect),
        #[prost(message, tag="13")]
        Censor(super::CensorEffect),
        #[prost(message, tag="14")]
        Flag(super::FlagEffect),
        #[prost(message, tag="15")]
        Notify(super::NotifyEffect),
        #[prost(message, tag="16")]
        CreateInfraction(super::CreateInfractionEffect),
        #[prost(message, tag="17")]
        CreateRestriction(super::CreateRestrictionEffect),
        #[prost(message, tag="18")]
        RouteReview(super::RouteReviewEffect),
        #[prost(message, tag="19")]
        LabelEntity(super::LabelEntityEffect),
        #[prost(message, tag="20")]
        IncrementCounter(super::IncrementCounterEffect),
        #[prost(message, tag="21")]
        Delete(super::DeleteEffect),
        #[prost(message, tag="22")]
        Kick(super::KickEffect),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AllowEffect {
    #[prost(string, repeated, tag="1")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockEffect {
    #[prost(string, repeated, tag="1")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag="2")]
    pub public_reason: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HoldEffect {
    #[prost(string, repeated, tag="1")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub maximum_duration: ::core::option::Option<::prost_types::Duration>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CensorEffect {
    #[prost(message, repeated, tag="1")]
    pub spans: ::prost::alloc::vec::Vec<TextSpan>,
    #[prost(string, tag="2")]
    pub replacement: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="3")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlagEffect {
    #[prost(string, tag="1")]
    pub flag_type: ::prost::alloc::string::String,
    #[prost(double, tag="2")]
    pub severity: f64,
    #[prost(message, optional, tag="3")]
    pub evidence: ::core::option::Option<::prost_types::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotifyEffect {
    #[prost(string, tag="1")]
    pub recipient: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub template: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub parameters: ::core::option::Option<::prost_types::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RouteReviewEffect {
    #[prost(string, tag="1")]
    pub queue: ::prost::alloc::string::String,
    #[prost(int32, tag="2")]
    pub priority: i32,
    #[prost(string, repeated, tag="3")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LabelEntityEffect {
    #[prost(message, optional, tag="1")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(string, tag="2")]
    pub label: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub value: ::core::option::Option<::prost_types::Value>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteEffect {
    #[prost(string, tag="1")]
    pub message_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub channel_id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="3")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KickEffect {
    #[prost(string, tag="1")]
    pub user_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub server_id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="3")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TextSpan {
    #[prost(uint32, tag="1")]
    pub start_character: u32,
    #[prost(uint32, tag="2")]
    pub end_character: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateInfractionEffect {
    #[prost(message, optional, tag="1")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(enumeration="InfractionType", tag="2")]
    pub r#type: i32,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub duration: ::core::option::Option<::prost_types::Duration>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateRestrictionEffect {
    #[prost(message, optional, tag="1")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(enumeration="RestrictionType", tag="2")]
    pub r#type: i32,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub duration: ::core::option::Option<::prost_types::Duration>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IncrementCounterEffect {
    #[prost(message, optional, tag="1")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(string, tag="3")]
    pub counter_type: ::prost::alloc::string::String,
    #[prost(int64, tag="4")]
    pub delta: i64,
    #[prost(message, optional, tag="5")]
    pub window: ::core::option::Option<::prost_types::Duration>,
    #[prost(bool, tag="6")]
    pub reset: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyDecision {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(enumeration="Decision", tag="3")]
    pub decision: i32,
    #[prost(string, repeated, tag="4")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="5")]
    pub accepted_effects: ::prost::alloc::vec::Vec<PolicyEffect>,
    #[prost(message, repeated, tag="6")]
    pub rejected_effects: ::prost::alloc::vec::Vec<RejectedEffect>,
    #[prost(string, tag="7")]
    pub execution_trace_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="8")]
    pub decided_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(bool, tag="9")]
    pub shadow: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectedEffect {
    #[prost(message, optional, tag="1")]
    pub effect: ::core::option::Option<PolicyEffect>,
    #[prost(string, tag="2")]
    pub reason: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub superseded_by_effect_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Restriction {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(enumeration="RestrictionType", tag="4")]
    pub r#type: i32,
    #[prost(enumeration="ResourceStatus", tag="5")]
    pub status: i32,
    #[prost(string, tag="6")]
    pub reason: ::prost::alloc::string::String,
    #[prost(string, tag="7")]
    pub created_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="8")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="9")]
    pub expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="10")]
    pub version: u64,
    #[prost(bool, tag="11")]
    pub is_active: bool,
    #[prost(string, tag="12")]
    pub source_report_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Infraction {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(enumeration="InfractionType", tag="4")]
    pub r#type: i32,
    #[prost(enumeration="ResourceStatus", tag="5")]
    pub status: i32,
    #[prost(string, tag="6")]
    pub reason: ::prost::alloc::string::String,
    #[prost(string, tag="7")]
    pub created_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="8")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="9")]
    pub expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="10")]
    pub version: u64,
    #[prost(string, tag="11")]
    pub enforcement_restriction_id: ::prost::alloc::string::String,
    #[prost(bool, tag="12")]
    pub is_active: bool,
    #[prost(string, tag="13")]
    pub source_report_id: ::prost::alloc::string::String,
}
/// A moderation-history entry backed by its canonical resource. The oneof
/// avoids copying report data or maintaining a second moderation ledger.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModerationRecord {
    #[prost(enumeration="ModerationRecordKind", tag="1")]
    pub kind: i32,
    #[prost(oneof="moderation_record::Resource", tags="2, 3")]
    pub resource: ::core::option::Option<moderation_record::Resource>,
}
/// Nested message and enum types in `ModerationRecord`.
pub mod moderation_record {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Resource {
        #[prost(message, tag="2")]
        Restriction(super::Restriction),
        #[prost(message, tag="3")]
        Infraction(super::Infraction),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NsfwOverride {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub exact_sha256: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub perceptual_hash: ::prost::alloc::string::String,
    #[prost(enumeration="NsfwOverrideClassification", tag="4")]
    pub classification: i32,
    #[prost(string, tag="5")]
    pub reason: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub created_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="7")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="8")]
    pub updated_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="9")]
    pub updated_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="10")]
    pub version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Report {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(string, tag="4")]
    pub reporter_id: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub description: ::prost::alloc::string::String,
    #[prost(enumeration="ResourceStatus", tag="7")]
    pub status: i32,
    #[prost(message, optional, tag="8")]
    pub context: ::core::option::Option<::prost_types::Struct>,
    #[prost(message, optional, tag="9")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="10")]
    pub resolved_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="11")]
    pub resolved_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="12")]
    pub version: u64,
    #[prost(string, tag="13")]
    pub claimed_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="14")]
    pub claimed_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="15")]
    pub claim_expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="16")]
    pub last_claim_change_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="17")]
    pub evidence_snapshot: ::core::option::Option<ReportEvidenceSnapshot>,
}
/// Immutable evidence range pinned to a report. Transcript entries are kept
/// outside Report.context so reports are not constrained by Struct/JSON limits.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReportEvidenceSnapshot {
    #[prost(string, tag="1")]
    pub lobby_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub first_sequence: u64,
    #[prost(uint64, tag="3")]
    pub last_sequence: u64,
    #[prost(uint64, tag="4")]
    pub entry_count: u64,
    #[prost(string, tag="5")]
    pub terminal_action_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranscriptEntry {
    #[prost(uint64, tag="1")]
    pub sequence: u64,
    #[prost(string, tag="2")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(enumeration="TranscriptEntryKind", tag="3")]
    pub kind: i32,
    #[prost(message, optional, tag="4")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="5")]
    pub message_id: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub author_id: ::prost::alloc::string::String,
    #[prost(string, tag="7")]
    pub author_display_name: ::prost::alloc::string::String,
    #[prost(string, tag="8")]
    pub author_username: ::prost::alloc::string::String,
    #[prost(string, tag="9")]
    pub original_content: ::prost::alloc::string::String,
    #[prost(string, tag="10")]
    pub approved_content: ::prost::alloc::string::String,
    #[prost(string, tag="11")]
    pub delivery_content: ::prost::alloc::string::String,
    #[prost(string, tag="12")]
    pub reply_to_message_id: ::prost::alloc::string::String,
    #[prost(string, tag="13")]
    pub reply_author_id: ::prost::alloc::string::String,
    #[prost(string, tag="14")]
    pub reply_author_display_name: ::prost::alloc::string::String,
    #[prost(string, tag="15")]
    pub reply_content: ::prost::alloc::string::String,
    #[prost(enumeration="LobbySystemEventType", tag="16")]
    pub system_event_type: i32,
    #[prost(string, tag="17")]
    pub system_event_reason: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StaffActionRequest {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(enumeration="StaffActionType", tag="2")]
    pub action_type: i32,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="4")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(string, tag="5")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub requested_reason: ::prost::alloc::string::String,
    #[prost(message, optional, tag="7")]
    pub requested_expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="8")]
    pub requested_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="9")]
    pub requested_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(enumeration="StaffActionRequestStatus", tag="10")]
    pub status: i32,
    #[prost(string, tag="11")]
    pub decided_by: ::prost::alloc::string::String,
    #[prost(string, tag="12")]
    pub decision_reason: ::prost::alloc::string::String,
    #[prost(message, optional, tag="13")]
    pub decided_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="14")]
    pub executed_infraction_id: ::prost::alloc::string::String,
    #[prost(string, tag="15")]
    pub executed_restriction_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="16")]
    pub expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="17")]
    pub version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Appeal {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub infraction_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub appellant_id: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub reason: ::prost::alloc::string::String,
    #[prost(enumeration="ResourceStatus", tag="5")]
    pub status: i32,
    #[prost(string, tag="6")]
    pub resolution: ::prost::alloc::string::String,
    #[prost(message, optional, tag="7")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="8")]
    pub resolved_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="9")]
    pub version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SafetyAssessment {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(double, tag="3")]
    pub score: f64,
    #[prost(string, tag="4")]
    pub tier: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="5")]
    pub signals: ::prost::alloc::vec::Vec<SafetySignal>,
    #[prost(message, optional, tag="6")]
    pub assessed_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="7")]
    pub algorithm_version: ::prost::alloc::string::String,
    #[prost(uint64, tag="8")]
    pub version: u64,
    #[prost(message, optional, tag="9")]
    pub scope: ::core::option::Option<Scope>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SafetySignal {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(double, tag="3")]
    pub value: f64,
    #[prost(double, tag="4")]
    pub confidence: f64,
    #[prost(double, tag="5")]
    pub weight: f64,
    #[prost(bool, tag="6")]
    pub mitigating: bool,
    #[prost(message, optional, tag="7")]
    pub observed_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="8")]
    pub expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="9")]
    pub source_action_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="10")]
    pub metadata: ::core::option::Option<::prost_types::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReviewItem {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub queue: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="4")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(int32, tag="5")]
    pub priority: i32,
    #[prost(enumeration="ResourceStatus", tag="6")]
    pub status: i32,
    #[prost(string, repeated, tag="7")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag="8")]
    pub decision_id: ::prost::alloc::string::String,
    #[prost(string, tag="9")]
    pub assigned_to: ::prost::alloc::string::String,
    #[prost(message, optional, tag="10")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="11")]
    pub version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CursorPage {
    #[prost(uint32, tag="1")]
    pub page_size: u32,
    #[prost(string, tag="2")]
    pub cursor: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CursorPageResult {
    #[prost(string, tag="1")]
    pub next_cursor: ::prost::alloc::string::String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ActorType {
    Unspecified = 0,
    Human = 1,
    Service = 2,
    Policy = 3,
}
impl ActorType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ActorType::Unspecified => "ACTOR_TYPE_UNSPECIFIED",
            ActorType::Human => "ACTOR_TYPE_HUMAN",
            ActorType::Service => "ACTOR_TYPE_SERVICE",
            ActorType::Policy => "ACTOR_TYPE_POLICY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ACTOR_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "ACTOR_TYPE_HUMAN" => Some(Self::Human),
            "ACTOR_TYPE_SERVICE" => Some(Self::Service),
            "ACTOR_TYPE_POLICY" => Some(Self::Policy),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ScopeType {
    Unspecified = 0,
    Platform = 1,
    Product = 2,
    Hub = 3,
    Lobby = 4,
    IncidentOverlay = 5,
}
impl ScopeType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ScopeType::Unspecified => "SCOPE_TYPE_UNSPECIFIED",
            ScopeType::Platform => "SCOPE_TYPE_PLATFORM",
            ScopeType::Product => "SCOPE_TYPE_PRODUCT",
            ScopeType::Hub => "SCOPE_TYPE_HUB",
            ScopeType::Lobby => "SCOPE_TYPE_LOBBY",
            ScopeType::IncidentOverlay => "SCOPE_TYPE_INCIDENT_OVERLAY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SCOPE_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "SCOPE_TYPE_PLATFORM" => Some(Self::Platform),
            "SCOPE_TYPE_PRODUCT" => Some(Self::Product),
            "SCOPE_TYPE_HUB" => Some(Self::Hub),
            "SCOPE_TYPE_LOBBY" => Some(Self::Lobby),
            "SCOPE_TYPE_INCIDENT_OVERLAY" => Some(Self::IncidentOverlay),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Product {
    Unspecified = 0,
    Hub = 1,
    Lobby = 2,
}
impl Product {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Product::Unspecified => "PRODUCT_UNSPECIFIED",
            Product::Hub => "PRODUCT_HUB",
            Product::Lobby => "PRODUCT_LOBBY",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PRODUCT_UNSPECIFIED" => Some(Self::Unspecified),
            "PRODUCT_HUB" => Some(Self::Hub),
            "PRODUCT_LOBBY" => Some(Self::Lobby),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DataHandlingClass {
    Unspecified = 0,
    Public = 1,
    Internal = 2,
    Sensitive = 3,
    Restricted = 4,
}
impl DataHandlingClass {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            DataHandlingClass::Unspecified => "DATA_HANDLING_CLASS_UNSPECIFIED",
            DataHandlingClass::Public => "DATA_HANDLING_CLASS_PUBLIC",
            DataHandlingClass::Internal => "DATA_HANDLING_CLASS_INTERNAL",
            DataHandlingClass::Sensitive => "DATA_HANDLING_CLASS_SENSITIVE",
            DataHandlingClass::Restricted => "DATA_HANDLING_CLASS_RESTRICTED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DATA_HANDLING_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
            "DATA_HANDLING_CLASS_PUBLIC" => Some(Self::Public),
            "DATA_HANDLING_CLASS_INTERNAL" => Some(Self::Internal),
            "DATA_HANDLING_CLASS_SENSITIVE" => Some(Self::Sensitive),
            "DATA_HANDLING_CLASS_RESTRICTED" => Some(Self::Restricted),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FeatureErrorCode {
    Unspecified = 0,
    Unavailable = 1,
    Timeout = 2,
    RateLimited = 3,
    InvalidInput = 4,
    ProviderRejected = 5,
    Internal = 6,
}
impl FeatureErrorCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            FeatureErrorCode::Unspecified => "FEATURE_ERROR_CODE_UNSPECIFIED",
            FeatureErrorCode::Unavailable => "FEATURE_ERROR_CODE_UNAVAILABLE",
            FeatureErrorCode::Timeout => "FEATURE_ERROR_CODE_TIMEOUT",
            FeatureErrorCode::RateLimited => "FEATURE_ERROR_CODE_RATE_LIMITED",
            FeatureErrorCode::InvalidInput => "FEATURE_ERROR_CODE_INVALID_INPUT",
            FeatureErrorCode::ProviderRejected => "FEATURE_ERROR_CODE_PROVIDER_REJECTED",
            FeatureErrorCode::Internal => "FEATURE_ERROR_CODE_INTERNAL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FEATURE_ERROR_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "FEATURE_ERROR_CODE_UNAVAILABLE" => Some(Self::Unavailable),
            "FEATURE_ERROR_CODE_TIMEOUT" => Some(Self::Timeout),
            "FEATURE_ERROR_CODE_RATE_LIMITED" => Some(Self::RateLimited),
            "FEATURE_ERROR_CODE_INVALID_INPUT" => Some(Self::InvalidInput),
            "FEATURE_ERROR_CODE_PROVIDER_REJECTED" => Some(Self::ProviderRejected),
            "FEATURE_ERROR_CODE_INTERNAL" => Some(Self::Internal),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Decision {
    Unspecified = 0,
    Allow = 1,
    Censor = 2,
    Hold = 3,
    Block = 4,
}
impl Decision {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Decision::Unspecified => "DECISION_UNSPECIFIED",
            Decision::Allow => "DECISION_ALLOW",
            Decision::Censor => "DECISION_CENSOR",
            Decision::Hold => "DECISION_HOLD",
            Decision::Block => "DECISION_BLOCK",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DECISION_UNSPECIFIED" => Some(Self::Unspecified),
            "DECISION_ALLOW" => Some(Self::Allow),
            "DECISION_CENSOR" => Some(Self::Censor),
            "DECISION_HOLD" => Some(Self::Hold),
            "DECISION_BLOCK" => Some(Self::Block),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RestrictionType {
    Unspecified = 0,
    Mute = 1,
    Ban = 2,
    Blacklist = 3,
    ContentQuarantine = 4,
}
impl RestrictionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RestrictionType::Unspecified => "RESTRICTION_TYPE_UNSPECIFIED",
            RestrictionType::Mute => "RESTRICTION_TYPE_MUTE",
            RestrictionType::Ban => "RESTRICTION_TYPE_BAN",
            RestrictionType::Blacklist => "RESTRICTION_TYPE_BLACKLIST",
            RestrictionType::ContentQuarantine => "RESTRICTION_TYPE_CONTENT_QUARANTINE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RESTRICTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "RESTRICTION_TYPE_MUTE" => Some(Self::Mute),
            "RESTRICTION_TYPE_BAN" => Some(Self::Ban),
            "RESTRICTION_TYPE_BLACKLIST" => Some(Self::Blacklist),
            "RESTRICTION_TYPE_CONTENT_QUARANTINE" => Some(Self::ContentQuarantine),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ModerationRecordKind {
    Unspecified = 0,
    Blacklist = 1,
    Warning = 2,
    LobbyWarning = 3,
    LobbyBan = 4,
}
impl ModerationRecordKind {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ModerationRecordKind::Unspecified => "MODERATION_RECORD_KIND_UNSPECIFIED",
            ModerationRecordKind::Blacklist => "MODERATION_RECORD_KIND_BLACKLIST",
            ModerationRecordKind::Warning => "MODERATION_RECORD_KIND_WARNING",
            ModerationRecordKind::LobbyWarning => "MODERATION_RECORD_KIND_LOBBY_WARNING",
            ModerationRecordKind::LobbyBan => "MODERATION_RECORD_KIND_LOBBY_BAN",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "MODERATION_RECORD_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "MODERATION_RECORD_KIND_BLACKLIST" => Some(Self::Blacklist),
            "MODERATION_RECORD_KIND_WARNING" => Some(Self::Warning),
            "MODERATION_RECORD_KIND_LOBBY_WARNING" => Some(Self::LobbyWarning),
            "MODERATION_RECORD_KIND_LOBBY_BAN" => Some(Self::LobbyBan),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ModerationResourceType {
    Unspecified = 0,
    Restriction = 1,
    Infraction = 2,
}
impl ModerationResourceType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ModerationResourceType::Unspecified => "MODERATION_RESOURCE_TYPE_UNSPECIFIED",
            ModerationResourceType::Restriction => "MODERATION_RESOURCE_TYPE_RESTRICTION",
            ModerationResourceType::Infraction => "MODERATION_RESOURCE_TYPE_INFRACTION",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "MODERATION_RESOURCE_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "MODERATION_RESOURCE_TYPE_RESTRICTION" => Some(Self::Restriction),
            "MODERATION_RESOURCE_TYPE_INFRACTION" => Some(Self::Infraction),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum InfractionType {
    Unspecified = 0,
    Warning = 1,
    Mute = 2,
    Ban = 3,
    Content = 4,
}
impl InfractionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            InfractionType::Unspecified => "INFRACTION_TYPE_UNSPECIFIED",
            InfractionType::Warning => "INFRACTION_TYPE_WARNING",
            InfractionType::Mute => "INFRACTION_TYPE_MUTE",
            InfractionType::Ban => "INFRACTION_TYPE_BAN",
            InfractionType::Content => "INFRACTION_TYPE_CONTENT",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "INFRACTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "INFRACTION_TYPE_WARNING" => Some(Self::Warning),
            "INFRACTION_TYPE_MUTE" => Some(Self::Mute),
            "INFRACTION_TYPE_BAN" => Some(Self::Ban),
            "INFRACTION_TYPE_CONTENT" => Some(Self::Content),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ResourceStatus {
    Unspecified = 0,
    Active = 1,
    Revoked = 2,
    Expired = 3,
    Pending = 4,
    Resolved = 5,
    Dismissed = 6,
}
impl ResourceStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ResourceStatus::Unspecified => "RESOURCE_STATUS_UNSPECIFIED",
            ResourceStatus::Active => "RESOURCE_STATUS_ACTIVE",
            ResourceStatus::Revoked => "RESOURCE_STATUS_REVOKED",
            ResourceStatus::Expired => "RESOURCE_STATUS_EXPIRED",
            ResourceStatus::Pending => "RESOURCE_STATUS_PENDING",
            ResourceStatus::Resolved => "RESOURCE_STATUS_RESOLVED",
            ResourceStatus::Dismissed => "RESOURCE_STATUS_DISMISSED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RESOURCE_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "RESOURCE_STATUS_ACTIVE" => Some(Self::Active),
            "RESOURCE_STATUS_REVOKED" => Some(Self::Revoked),
            "RESOURCE_STATUS_EXPIRED" => Some(Self::Expired),
            "RESOURCE_STATUS_PENDING" => Some(Self::Pending),
            "RESOURCE_STATUS_RESOLVED" => Some(Self::Resolved),
            "RESOURCE_STATUS_DISMISSED" => Some(Self::Dismissed),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NsfwOverrideClassification {
    Unspecified = 0,
    Safe = 1,
    Unsafe = 2,
}
impl NsfwOverrideClassification {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NsfwOverrideClassification::Unspecified => "NSFW_OVERRIDE_CLASSIFICATION_UNSPECIFIED",
            NsfwOverrideClassification::Safe => "NSFW_OVERRIDE_CLASSIFICATION_SAFE",
            NsfwOverrideClassification::Unsafe => "NSFW_OVERRIDE_CLASSIFICATION_UNSAFE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NSFW_OVERRIDE_CLASSIFICATION_UNSPECIFIED" => Some(Self::Unspecified),
            "NSFW_OVERRIDE_CLASSIFICATION_SAFE" => Some(Self::Safe),
            "NSFW_OVERRIDE_CLASSIFICATION_UNSAFE" => Some(Self::Unsafe),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TranscriptEntryKind {
    Unspecified = 0,
    UserMessage = 1,
    SystemEvent = 2,
}
impl TranscriptEntryKind {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            TranscriptEntryKind::Unspecified => "TRANSCRIPT_ENTRY_KIND_UNSPECIFIED",
            TranscriptEntryKind::UserMessage => "TRANSCRIPT_ENTRY_KIND_USER_MESSAGE",
            TranscriptEntryKind::SystemEvent => "TRANSCRIPT_ENTRY_KIND_SYSTEM_EVENT",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "TRANSCRIPT_ENTRY_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "TRANSCRIPT_ENTRY_KIND_USER_MESSAGE" => Some(Self::UserMessage),
            "TRANSCRIPT_ENTRY_KIND_SYSTEM_EVENT" => Some(Self::SystemEvent),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum LobbySystemEventType {
    Unspecified = 0,
    CallConnected = 1,
    ParticipantJoined = 2,
    ParticipantLeft = 3,
    ReportSubmitted = 4,
    CallEnded = 5,
}
impl LobbySystemEventType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            LobbySystemEventType::Unspecified => "LOBBY_SYSTEM_EVENT_TYPE_UNSPECIFIED",
            LobbySystemEventType::CallConnected => "LOBBY_SYSTEM_EVENT_TYPE_CALL_CONNECTED",
            LobbySystemEventType::ParticipantJoined => "LOBBY_SYSTEM_EVENT_TYPE_PARTICIPANT_JOINED",
            LobbySystemEventType::ParticipantLeft => "LOBBY_SYSTEM_EVENT_TYPE_PARTICIPANT_LEFT",
            LobbySystemEventType::ReportSubmitted => "LOBBY_SYSTEM_EVENT_TYPE_REPORT_SUBMITTED",
            LobbySystemEventType::CallEnded => "LOBBY_SYSTEM_EVENT_TYPE_CALL_ENDED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "LOBBY_SYSTEM_EVENT_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "LOBBY_SYSTEM_EVENT_TYPE_CALL_CONNECTED" => Some(Self::CallConnected),
            "LOBBY_SYSTEM_EVENT_TYPE_PARTICIPANT_JOINED" => Some(Self::ParticipantJoined),
            "LOBBY_SYSTEM_EVENT_TYPE_PARTICIPANT_LEFT" => Some(Self::ParticipantLeft),
            "LOBBY_SYSTEM_EVENT_TYPE_REPORT_SUBMITTED" => Some(Self::ReportSubmitted),
            "LOBBY_SYSTEM_EVENT_TYPE_CALL_ENDED" => Some(Self::CallEnded),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StaffActionType {
    Unspecified = 0,
    LobbyBan = 1,
    GlobalBlacklist = 2,
}
impl StaffActionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            StaffActionType::Unspecified => "STAFF_ACTION_TYPE_UNSPECIFIED",
            StaffActionType::LobbyBan => "STAFF_ACTION_TYPE_LOBBY_BAN",
            StaffActionType::GlobalBlacklist => "STAFF_ACTION_TYPE_GLOBAL_BLACKLIST",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "STAFF_ACTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "STAFF_ACTION_TYPE_LOBBY_BAN" => Some(Self::LobbyBan),
            "STAFF_ACTION_TYPE_GLOBAL_BLACKLIST" => Some(Self::GlobalBlacklist),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StaffActionRequestStatus {
    Unspecified = 0,
    Pending = 1,
    Rejected = 2,
    Expired = 3,
    Executed = 4,
    Cancelled = 5,
}
impl StaffActionRequestStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            StaffActionRequestStatus::Unspecified => "STAFF_ACTION_REQUEST_STATUS_UNSPECIFIED",
            StaffActionRequestStatus::Pending => "STAFF_ACTION_REQUEST_STATUS_PENDING",
            StaffActionRequestStatus::Rejected => "STAFF_ACTION_REQUEST_STATUS_REJECTED",
            StaffActionRequestStatus::Expired => "STAFF_ACTION_REQUEST_STATUS_EXPIRED",
            StaffActionRequestStatus::Executed => "STAFF_ACTION_REQUEST_STATUS_EXECUTED",
            StaffActionRequestStatus::Cancelled => "STAFF_ACTION_REQUEST_STATUS_CANCELLED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "STAFF_ACTION_REQUEST_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "STAFF_ACTION_REQUEST_STATUS_PENDING" => Some(Self::Pending),
            "STAFF_ACTION_REQUEST_STATUS_REJECTED" => Some(Self::Rejected),
            "STAFF_ACTION_REQUEST_STATUS_EXPIRED" => Some(Self::Expired),
            "STAFF_ACTION_REQUEST_STATUS_EXECUTED" => Some(Self::Executed),
            "STAFF_ACTION_REQUEST_STATUS_CANCELLED" => Some(Self::Cancelled),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActionRequested {
    #[prost(message, optional, tag="1")]
    pub action: ::core::option::Option<Action>,
    #[prost(message, optional, tag="2")]
    pub prism_payload: ::core::option::Option<super::super::super::prism::PrismStreamPayload>,
    #[prost(message, optional, tag="3")]
    pub requested_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecisionPublished {
    #[prost(message, optional, tag="1")]
    pub decision: ::core::option::Option<PolicyDecision>,
    #[prost(message, optional, tag="2")]
    pub approved_prism_payload: ::core::option::Option<super::super::super::prism::PrismStreamPayload>,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="4")]
    pub subject: ::core::option::Option<Subject>,
    /// Canonical presentation-free content after accepted policy effects.
    /// Consumers must never recover canonical content from the delivery payload.
    #[prost(string, optional, tag="5")]
    pub approved_content: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommandEnvelope {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub decision_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub idempotency_key: ::prost::alloc::string::String,
    #[prost(oneof="command_envelope::Command", tags="10, 11, 12")]
    pub command: ::core::option::Option<command_envelope::Command>,
}
/// Nested message and enum types in `CommandEnvelope`.
pub mod command_envelope {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Command {
        #[prost(message, tag="10")]
        Notify(super::NotifyCommand),
        #[prost(message, tag="11")]
        Delete(super::DeleteCommand),
        #[prost(message, tag="12")]
        Kick(super::KickCommand),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommandResult {
    #[prost(string, tag="1")]
    pub command_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub decision_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub idempotency_key: ::prost::alloc::string::String,
    #[prost(bool, tag="4")]
    pub success: bool,
    #[prost(string, tag="5")]
    pub result_code: ::prost::alloc::string::String,
    #[prost(message, optional, tag="6")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag="7")]
    pub command_type: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotifyCommand {
    #[prost(string, tag="1")]
    pub user_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub template: ::prost::alloc::string::String,
    #[prost(map="string, string", tag="3")]
    pub parameters: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteCommand {
    #[prost(string, tag="1")]
    pub message_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub channel_id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="3")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KickCommand {
    #[prost(string, tag="1")]
    pub user_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub server_id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="3")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrismDeliveryCallback {
    #[prost(string, tag="1")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub message_id: ::prost::alloc::string::String,
    #[prost(enumeration="MessageState", tag="3")]
    pub state: i32,
    #[prost(string, tag="4")]
    pub failure_code: ::prost::alloc::string::String,
    #[prost(message, optional, tag="5")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyCacheInvalidated {
    #[prost(string, tag="1")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub active_policy_version_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub bundle_version: u64,
    #[prost(message, optional, tag="4")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
}
/// Cold-path notification that one native content-policy scope has a newer
/// authoritative relational definition in Polarizer Postgres. Rule data is
/// intentionally omitted; every replica reloads and compiles only this scope.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContentPolicyInvalidated {
    /// GLOBAL, HUB, or SERVER. Kept textual so future authorities can be added
    /// without renumbering an event enum consumed by older replicas.
    #[prost(string, tag="1")]
    pub authority: ::prost::alloc::string::String,
    /// Empty for GLOBAL; the Hub/server identifier otherwise.
    #[prost(string, tag="2")]
    pub scope_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub version: u64,
    #[prost(message, optional, tag="4")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReportCreated {
    #[prost(string, tag="1")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(string, tag="4")]
    pub reporter_id: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub report_type: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub description: ::prost::alloc::string::String,
    #[prost(message, optional, tag="7")]
    pub context: ::core::option::Option<::prost_types::Struct>,
    #[prost(message, optional, tag="8")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MessageState {
    Unspecified = 0,
    PendingModeration = 1,
    ApprovedPendingDelivery = 2,
    Active = 3,
    Blocked = 4,
    Held = 5,
    Expired = 6,
    DeliveryFailed = 7,
}
impl MessageState {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            MessageState::Unspecified => "MESSAGE_STATE_UNSPECIFIED",
            MessageState::PendingModeration => "MESSAGE_STATE_PENDING_MODERATION",
            MessageState::ApprovedPendingDelivery => "MESSAGE_STATE_APPROVED_PENDING_DELIVERY",
            MessageState::Active => "MESSAGE_STATE_ACTIVE",
            MessageState::Blocked => "MESSAGE_STATE_BLOCKED",
            MessageState::Held => "MESSAGE_STATE_HELD",
            MessageState::Expired => "MESSAGE_STATE_EXPIRED",
            MessageState::DeliveryFailed => "MESSAGE_STATE_DELIVERY_FAILED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "MESSAGE_STATE_UNSPECIFIED" => Some(Self::Unspecified),
            "MESSAGE_STATE_PENDING_MODERATION" => Some(Self::PendingModeration),
            "MESSAGE_STATE_APPROVED_PENDING_DELIVERY" => Some(Self::ApprovedPendingDelivery),
            "MESSAGE_STATE_ACTIVE" => Some(Self::Active),
            "MESSAGE_STATE_BLOCKED" => Some(Self::Blocked),
            "MESSAGE_STATE_HELD" => Some(Self::Held),
            "MESSAGE_STATE_EXPIRED" => Some(Self::Expired),
            "MESSAGE_STATE_DELIVERY_FAILED" => Some(Self::DeliveryFailed),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FeatureRequirement {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(enumeration="ErrorBehavior", tag="2")]
    pub error_behavior: i32,
    #[prost(message, optional, tag="3")]
    pub deadline: ::core::option::Option<::prost_types::Duration>,
    #[prost(enumeration="DataHandlingClass", tag="4")]
    pub maximum_data_handling: i32,
    #[prost(message, optional, tag="5")]
    pub configuration: ::core::option::Option<::prost_types::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyManifest {
    #[prost(string, repeated, tag="1")]
    pub accepted_action_types: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint32, repeated, tag="2")]
    pub accepted_schema_versions: ::prost::alloc::vec::Vec<u32>,
    #[prost(message, repeated, tag="3")]
    pub required_features: ::prost::alloc::vec::Vec<FeatureRequirement>,
    #[prost(string, repeated, tag="4")]
    pub capabilities: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(enumeration="ErrorBehavior", tag="5")]
    pub runtime_error_behavior: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyBundle {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub description: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(bool, tag="5")]
    pub mandatory: bool,
    #[prost(int32, tag="6")]
    pub priority: i32,
    #[prost(string, tag="7")]
    pub active_version_id: ::prost::alloc::string::String,
    #[prost(string, tag="8")]
    pub shadow_version_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="9")]
    pub version: u64,
    #[prost(message, optional, tag="10")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="11")]
    pub updated_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(enumeration="PolicyBundleState", tag="12")]
    pub state: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyVersion {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(uint32, tag="3")]
    pub version: u32,
    #[prost(enumeration="PolicyLanguage", tag="4")]
    pub language: i32,
    #[prost(string, tag="5")]
    pub runtime_version: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub source: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="7")]
    pub compiled_artifact: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="8")]
    pub source_sha256: ::prost::alloc::string::String,
    #[prost(string, tag="9")]
    pub artifact_sha256: ::prost::alloc::string::String,
    #[prost(message, optional, tag="10")]
    pub manifest: ::core::option::Option<PolicyManifest>,
    #[prost(enumeration="PolicyVersionState", tag="11")]
    pub state: i32,
    #[prost(string, tag="12")]
    pub created_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="13")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="14")]
    pub published_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyFixture {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub action: ::core::option::Option<Action>,
    #[prost(message, optional, tag="5")]
    pub features: ::core::option::Option<FeatureSnapshot>,
    #[prost(message, repeated, tag="6")]
    pub expected_effects: ::prost::alloc::vec::Vec<PolicyEffect>,
    #[prost(message, optional, tag="7")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="8")]
    pub version: u64,
    #[prost(message, optional, tag="9")]
    pub updated_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PolicyApproval {
    #[prost(string, tag="1")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub administrator_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub approved_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Diagnostic {
    #[prost(enumeration="DiagnosticSeverity", tag="1")]
    pub severity: i32,
    #[prost(string, tag="2")]
    pub code: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub message: ::prost::alloc::string::String,
    #[prost(uint32, tag="4")]
    pub line: u32,
    #[prost(uint32, tag="5")]
    pub column: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuleTrace {
    #[prost(string, tag="1")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub rule_id: ::prost::alloc::string::String,
    #[prost(bool, tag="3")]
    pub skipped: bool,
    #[prost(string, tag="4")]
    pub skip_reason: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="5")]
    pub conditions: ::prost::alloc::vec::Vec<ConditionTrace>,
    #[prost(message, repeated, tag="6")]
    pub emitted_effects: ::prost::alloc::vec::Vec<PolicyEffect>,
    #[prost(message, repeated, tag="7")]
    pub rejected_effects: ::prost::alloc::vec::Vec<RejectedEffect>,
    #[prost(string, tag="8")]
    pub error: ::prost::alloc::string::String,
    #[prost(message, optional, tag="9")]
    pub latency: ::core::option::Option<::prost_types::Duration>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConditionTrace {
    #[prost(string, tag="1")]
    pub path: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub result: ::core::option::Option<::prost_types::Value>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionTrace {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(uint32, tag="3")]
    pub action_schema_version: u32,
    #[prost(message, repeated, tag="4")]
    pub rules: ::prost::alloc::vec::Vec<RuleTrace>,
    #[prost(message, optional, tag="5")]
    pub feature_snapshot: ::core::option::Option<FeatureSnapshot>,
    #[prost(enumeration="Decision", tag="6")]
    pub final_decision: i32,
    #[prost(string, repeated, tag="7")]
    pub reason_codes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag="8")]
    pub total_latency: ::core::option::Option<::prost_types::Duration>,
    #[prost(message, optional, tag="9")]
    pub created_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(bool, tag="10")]
    pub sampled: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProviderHealth {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub version: ::prost::alloc::string::String,
    #[prost(bool, tag="3")]
    pub healthy: bool,
    #[prost(string, tag="4")]
    pub status: ::prost::alloc::string::String,
    #[prost(message, optional, tag="5")]
    pub checked_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ShadowComparison {
    #[prost(string, tag="1")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub active_decision_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub shadow_decision_id: ::prost::alloc::string::String,
    #[prost(bool, tag="4")]
    pub decision_changed: bool,
    #[prost(string, repeated, tag="5")]
    pub effect_differences: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PolicyLanguage {
    Unspecified = 0,
    IrV1 = 1,
    LuauV1 = 2,
}
impl PolicyLanguage {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PolicyLanguage::Unspecified => "POLICY_LANGUAGE_UNSPECIFIED",
            PolicyLanguage::IrV1 => "POLICY_LANGUAGE_IR_V1",
            PolicyLanguage::LuauV1 => "POLICY_LANGUAGE_LUAU_V1",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "POLICY_LANGUAGE_UNSPECIFIED" => Some(Self::Unspecified),
            "POLICY_LANGUAGE_IR_V1" => Some(Self::IrV1),
            "POLICY_LANGUAGE_LUAU_V1" => Some(Self::LuauV1),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PolicyVersionState {
    Unspecified = 0,
    Draft = 1,
    Validated = 2,
    Shadow = 3,
    Active = 4,
    Disabled = 5,
    Retired = 6,
}
impl PolicyVersionState {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PolicyVersionState::Unspecified => "POLICY_VERSION_STATE_UNSPECIFIED",
            PolicyVersionState::Draft => "POLICY_VERSION_STATE_DRAFT",
            PolicyVersionState::Validated => "POLICY_VERSION_STATE_VALIDATED",
            PolicyVersionState::Shadow => "POLICY_VERSION_STATE_SHADOW",
            PolicyVersionState::Active => "POLICY_VERSION_STATE_ACTIVE",
            PolicyVersionState::Disabled => "POLICY_VERSION_STATE_DISABLED",
            PolicyVersionState::Retired => "POLICY_VERSION_STATE_RETIRED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "POLICY_VERSION_STATE_UNSPECIFIED" => Some(Self::Unspecified),
            "POLICY_VERSION_STATE_DRAFT" => Some(Self::Draft),
            "POLICY_VERSION_STATE_VALIDATED" => Some(Self::Validated),
            "POLICY_VERSION_STATE_SHADOW" => Some(Self::Shadow),
            "POLICY_VERSION_STATE_ACTIVE" => Some(Self::Active),
            "POLICY_VERSION_STATE_DISABLED" => Some(Self::Disabled),
            "POLICY_VERSION_STATE_RETIRED" => Some(Self::Retired),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PolicyBundleState {
    Unspecified = 0,
    Active = 1,
    Disabled = 2,
    Retired = 3,
}
impl PolicyBundleState {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PolicyBundleState::Unspecified => "POLICY_BUNDLE_STATE_UNSPECIFIED",
            PolicyBundleState::Active => "POLICY_BUNDLE_STATE_ACTIVE",
            PolicyBundleState::Disabled => "POLICY_BUNDLE_STATE_DISABLED",
            PolicyBundleState::Retired => "POLICY_BUNDLE_STATE_RETIRED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "POLICY_BUNDLE_STATE_UNSPECIFIED" => Some(Self::Unspecified),
            "POLICY_BUNDLE_STATE_ACTIVE" => Some(Self::Active),
            "POLICY_BUNDLE_STATE_DISABLED" => Some(Self::Disabled),
            "POLICY_BUNDLE_STATE_RETIRED" => Some(Self::Retired),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ErrorBehavior {
    Unspecified = 0,
    Hold = 1,
    Review = 2,
    Continue = 3,
}
impl ErrorBehavior {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ErrorBehavior::Unspecified => "ERROR_BEHAVIOR_UNSPECIFIED",
            ErrorBehavior::Hold => "ERROR_BEHAVIOR_HOLD",
            ErrorBehavior::Review => "ERROR_BEHAVIOR_REVIEW",
            ErrorBehavior::Continue => "ERROR_BEHAVIOR_CONTINUE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ERROR_BEHAVIOR_UNSPECIFIED" => Some(Self::Unspecified),
            "ERROR_BEHAVIOR_HOLD" => Some(Self::Hold),
            "ERROR_BEHAVIOR_REVIEW" => Some(Self::Review),
            "ERROR_BEHAVIOR_CONTINUE" => Some(Self::Continue),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DiagnosticSeverity {
    Unspecified = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
}
impl DiagnosticSeverity {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            DiagnosticSeverity::Unspecified => "DIAGNOSTIC_SEVERITY_UNSPECIFIED",
            DiagnosticSeverity::Info => "DIAGNOSTIC_SEVERITY_INFO",
            DiagnosticSeverity::Warning => "DIAGNOSTIC_SEVERITY_WARNING",
            DiagnosticSeverity::Error => "DIAGNOSTIC_SEVERITY_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DIAGNOSTIC_SEVERITY_UNSPECIFIED" => Some(Self::Unspecified),
            "DIAGNOSTIC_SEVERITY_INFO" => Some(Self::Info),
            "DIAGNOSTIC_SEVERITY_WARNING" => Some(Self::Warning),
            "DIAGNOSTIC_SEVERITY_ERROR" => Some(Self::Error),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContentPolicyScope {
    #[prost(enumeration="ContentPolicyAuthority", tag="1")]
    pub authority: i32,
    #[prost(string, tag="2")]
    pub id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NativeContentPattern {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub pattern: ::prost::alloc::string::String,
    /// Output classification. Polarizer derives this from pattern syntax on write.
    #[prost(enumeration="ContentPatternType", tag="3")]
    pub pattern_type: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NativeContentAction {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(enumeration="ContentPolicyActionType", tag="2")]
    pub r#type: i32,
    #[prost(message, optional, tag="3")]
    pub duration: ::core::option::Option<::prost_types::Duration>,
    #[prost(string, tag="4")]
    pub replacement: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NativeContentRule {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub description: ::prost::alloc::string::String,
    #[prost(bool, tag="4")]
    pub enabled: bool,
    #[prost(string, tag="5")]
    pub custom_reason: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub created_by: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="7")]
    pub patterns: ::prost::alloc::vec::Vec<NativeContentPattern>,
    #[prost(enumeration="ContentPolicySurface", repeated, tag="8")]
    pub surfaces: ::prost::alloc::vec::Vec<i32>,
    #[prost(message, repeated, tag="9")]
    pub actions: ::prost::alloc::vec::Vec<NativeContentAction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NativeContentPolicy {
    #[prost(string, tag="1")]
    pub id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<ContentPolicyScope>,
    #[prost(bool, tag="3")]
    pub enabled: bool,
    #[prost(uint64, tag="4")]
    pub version: u64,
    #[prost(message, repeated, tag="5")]
    pub rules: ::prost::alloc::vec::Vec<NativeContentRule>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetContentPolicyRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<ContentPolicyScope>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetContentPolicyResponse {
    #[prost(message, optional, tag="1")]
    pub policy: ::core::option::Option<NativeContentPolicy>,
    #[prost(uint32, tag="2")]
    pub pattern_limit: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplaceContentPolicyRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub policy: ::core::option::Option<NativeContentPolicy>,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplaceContentPolicyResponse {
    #[prost(message, optional, tag="1")]
    pub policy: ::core::option::Option<NativeContentPolicy>,
    #[prost(uint32, tag="2")]
    pub pattern_limit: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContentPolicyAuthority {
    Unspecified = 0,
    Global = 1,
    Hub = 2,
    Server = 3,
}
impl ContentPolicyAuthority {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ContentPolicyAuthority::Unspecified => "CONTENT_POLICY_AUTHORITY_UNSPECIFIED",
            ContentPolicyAuthority::Global => "CONTENT_POLICY_AUTHORITY_GLOBAL",
            ContentPolicyAuthority::Hub => "CONTENT_POLICY_AUTHORITY_HUB",
            ContentPolicyAuthority::Server => "CONTENT_POLICY_AUTHORITY_SERVER",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONTENT_POLICY_AUTHORITY_UNSPECIFIED" => Some(Self::Unspecified),
            "CONTENT_POLICY_AUTHORITY_GLOBAL" => Some(Self::Global),
            "CONTENT_POLICY_AUTHORITY_HUB" => Some(Self::Hub),
            "CONTENT_POLICY_AUTHORITY_SERVER" => Some(Self::Server),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContentPolicySurface {
    Unspecified = 0,
    MessageContent = 1,
    DisplayName = 2,
    Username = 3,
    ServerName = 4,
    HubName = 5,
    UrlDomain = 6,
}
impl ContentPolicySurface {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ContentPolicySurface::Unspecified => "CONTENT_POLICY_SURFACE_UNSPECIFIED",
            ContentPolicySurface::MessageContent => "CONTENT_POLICY_SURFACE_MESSAGE_CONTENT",
            ContentPolicySurface::DisplayName => "CONTENT_POLICY_SURFACE_DISPLAY_NAME",
            ContentPolicySurface::Username => "CONTENT_POLICY_SURFACE_USERNAME",
            ContentPolicySurface::ServerName => "CONTENT_POLICY_SURFACE_SERVER_NAME",
            ContentPolicySurface::HubName => "CONTENT_POLICY_SURFACE_HUB_NAME",
            ContentPolicySurface::UrlDomain => "CONTENT_POLICY_SURFACE_URL_DOMAIN",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONTENT_POLICY_SURFACE_UNSPECIFIED" => Some(Self::Unspecified),
            "CONTENT_POLICY_SURFACE_MESSAGE_CONTENT" => Some(Self::MessageContent),
            "CONTENT_POLICY_SURFACE_DISPLAY_NAME" => Some(Self::DisplayName),
            "CONTENT_POLICY_SURFACE_USERNAME" => Some(Self::Username),
            "CONTENT_POLICY_SURFACE_SERVER_NAME" => Some(Self::ServerName),
            "CONTENT_POLICY_SURFACE_HUB_NAME" => Some(Self::HubName),
            "CONTENT_POLICY_SURFACE_URL_DOMAIN" => Some(Self::UrlDomain),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContentPatternType {
    Unspecified = 0,
    ExactWord = 1,
    Prefix = 2,
    Suffix = 3,
    Contains = 4,
    Phrase = 5,
}
impl ContentPatternType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ContentPatternType::Unspecified => "CONTENT_PATTERN_TYPE_UNSPECIFIED",
            ContentPatternType::ExactWord => "CONTENT_PATTERN_TYPE_EXACT_WORD",
            ContentPatternType::Prefix => "CONTENT_PATTERN_TYPE_PREFIX",
            ContentPatternType::Suffix => "CONTENT_PATTERN_TYPE_SUFFIX",
            ContentPatternType::Contains => "CONTENT_PATTERN_TYPE_CONTAINS",
            ContentPatternType::Phrase => "CONTENT_PATTERN_TYPE_PHRASE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONTENT_PATTERN_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "CONTENT_PATTERN_TYPE_EXACT_WORD" => Some(Self::ExactWord),
            "CONTENT_PATTERN_TYPE_PREFIX" => Some(Self::Prefix),
            "CONTENT_PATTERN_TYPE_SUFFIX" => Some(Self::Suffix),
            "CONTENT_PATTERN_TYPE_CONTAINS" => Some(Self::Contains),
            "CONTENT_PATTERN_TYPE_PHRASE" => Some(Self::Phrase),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ContentPolicyActionType {
    Unspecified = 0,
    Allow = 1,
    Block = 2,
    CensorMatch = 3,
    StripLink = 4,
    SuppressLinks = 5,
    ReplaceName = 6,
    Log = 7,
    LobbyWarn = 8,
    LobbyBan = 9,
    Blacklist = 10,
    HubWarn = 11,
    HubMute = 12,
    HubBan = 13,
}
impl ContentPolicyActionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ContentPolicyActionType::Unspecified => "CONTENT_POLICY_ACTION_TYPE_UNSPECIFIED",
            ContentPolicyActionType::Allow => "CONTENT_POLICY_ACTION_TYPE_ALLOW",
            ContentPolicyActionType::Block => "CONTENT_POLICY_ACTION_TYPE_BLOCK",
            ContentPolicyActionType::CensorMatch => "CONTENT_POLICY_ACTION_TYPE_CENSOR_MATCH",
            ContentPolicyActionType::StripLink => "CONTENT_POLICY_ACTION_TYPE_STRIP_LINK",
            ContentPolicyActionType::SuppressLinks => "CONTENT_POLICY_ACTION_TYPE_SUPPRESS_LINKS",
            ContentPolicyActionType::ReplaceName => "CONTENT_POLICY_ACTION_TYPE_REPLACE_NAME",
            ContentPolicyActionType::Log => "CONTENT_POLICY_ACTION_TYPE_LOG",
            ContentPolicyActionType::LobbyWarn => "CONTENT_POLICY_ACTION_TYPE_LOBBY_WARN",
            ContentPolicyActionType::LobbyBan => "CONTENT_POLICY_ACTION_TYPE_LOBBY_BAN",
            ContentPolicyActionType::Blacklist => "CONTENT_POLICY_ACTION_TYPE_BLACKLIST",
            ContentPolicyActionType::HubWarn => "CONTENT_POLICY_ACTION_TYPE_HUB_WARN",
            ContentPolicyActionType::HubMute => "CONTENT_POLICY_ACTION_TYPE_HUB_MUTE",
            ContentPolicyActionType::HubBan => "CONTENT_POLICY_ACTION_TYPE_HUB_BAN",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONTENT_POLICY_ACTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "CONTENT_POLICY_ACTION_TYPE_ALLOW" => Some(Self::Allow),
            "CONTENT_POLICY_ACTION_TYPE_BLOCK" => Some(Self::Block),
            "CONTENT_POLICY_ACTION_TYPE_CENSOR_MATCH" => Some(Self::CensorMatch),
            "CONTENT_POLICY_ACTION_TYPE_STRIP_LINK" => Some(Self::StripLink),
            "CONTENT_POLICY_ACTION_TYPE_SUPPRESS_LINKS" => Some(Self::SuppressLinks),
            "CONTENT_POLICY_ACTION_TYPE_REPLACE_NAME" => Some(Self::ReplaceName),
            "CONTENT_POLICY_ACTION_TYPE_LOG" => Some(Self::Log),
            "CONTENT_POLICY_ACTION_TYPE_LOBBY_WARN" => Some(Self::LobbyWarn),
            "CONTENT_POLICY_ACTION_TYPE_LOBBY_BAN" => Some(Self::LobbyBan),
            "CONTENT_POLICY_ACTION_TYPE_BLACKLIST" => Some(Self::Blacklist),
            "CONTENT_POLICY_ACTION_TYPE_HUB_WARN" => Some(Self::HubWarn),
            "CONTENT_POLICY_ACTION_TYPE_HUB_MUTE" => Some(Self::HubMute),
            "CONTENT_POLICY_ACTION_TYPE_HUB_BAN" => Some(Self::HubBan),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvaluateActionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub action: ::core::option::Option<Action>,
    #[prost(bool, tag="3")]
    pub shadow_only: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvaluateActionResponse {
    #[prost(message, optional, tag="1")]
    pub decision: ::core::option::Option<PolicyDecision>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimCommandRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub command_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub claimant_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub requested_lease: ::core::option::Option<::prost_types::Duration>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimCommandResponse {
    #[prost(enumeration="CommandClaimState", tag="1")]
    pub state: i32,
    #[prost(message, optional, tag="2")]
    pub command: ::core::option::Option<CommandEnvelope>,
    #[prost(string, tag="3")]
    pub lease_token: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub lease_expires_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint32, tag="5")]
    pub attempt_count: u32,
    #[prost(uint64, tag="6")]
    pub version: u64,
    #[prost(message, optional, tag="7")]
    pub completed_result: ::core::option::Option<CommandResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompleteCommandRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub command_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub lease_token: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
    #[prost(bool, tag="5")]
    pub success: bool,
    #[prost(string, tag="6")]
    pub result_code: ::prost::alloc::string::String,
    #[prost(message, optional, tag="7")]
    pub occurred_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompleteCommandResponse {
    #[prost(message, optional, tag="1")]
    pub result: ::core::option::Option<CommandResult>,
    #[prost(uint64, tag="2")]
    pub version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreatePolicyBundleRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub description: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(bool, tag="5")]
    pub mandatory: bool,
    #[prost(int32, tag="6")]
    pub priority: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetPolicyBundleRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListPolicyBundlesRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(enumeration="PolicyBundleState", tag="3")]
    pub state: i32,
    #[prost(message, optional, tag="4")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListPolicyBundlesResponse {
    #[prost(message, repeated, tag="1")]
    pub bundles: ::prost::alloc::vec::Vec<PolicyBundle>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdatePolicyBundleRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub bundle: ::core::option::Option<PolicyBundle>,
    #[prost(message, optional, tag="3")]
    pub update_mask: ::core::option::Option<::prost_types::FieldMask>,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DisablePolicyBundleRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RetirePolicyBundleRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreatePolicyDraftRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(enumeration="PolicyLanguage", tag="3")]
    pub language: i32,
    #[prost(string, tag="4")]
    pub source: ::prost::alloc::string::String,
    #[prost(message, optional, tag="5")]
    pub manifest: ::core::option::Option<PolicyManifest>,
    #[prost(uint64, tag="6")]
    pub expected_bundle_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidatePolicyRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidatePolicyResponse {
    #[prost(message, repeated, tag="1")]
    pub diagnostics: ::prost::alloc::vec::Vec<Diagnostic>,
    #[prost(message, optional, tag="2")]
    pub policy_version: ::core::option::Option<PolicyVersion>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RunPolicyTestsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="3")]
    pub ad_hoc_fixtures: ::prost::alloc::vec::Vec<PolicyFixture>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FixtureResult {
    #[prost(string, tag="1")]
    pub fixture_id: ::prost::alloc::string::String,
    #[prost(bool, tag="2")]
    pub passed: bool,
    #[prost(string, repeated, tag="3")]
    pub differences: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag="4")]
    pub trace: ::core::option::Option<ExecutionTrace>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RunPolicyTestsResponse {
    #[prost(message, repeated, tag="1")]
    pub results: ::prost::alloc::vec::Vec<FixtureResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreatePolicyFixtureRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub fixture: ::core::option::Option<PolicyFixture>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdatePolicyFixtureRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub fixture: ::core::option::Option<PolicyFixture>,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeletePolicyFixtureRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub fixture_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListPolicyFixturesRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListPolicyFixturesResponse {
    #[prost(message, repeated, tag="1")]
    pub fixtures: ::prost::alloc::vec::Vec<PolicyFixture>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetShadowModeRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(bool, tag="4")]
    pub enabled: bool,
    #[prost(uint64, tag="5")]
    pub expected_bundle_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublishPolicyVersionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub expected_bundle_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApprovePolicyVersionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub policy_version_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActivatePolicyVersionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub policy_version_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub activate_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="5")]
    pub expected_bundle_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RollbackPolicyRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub target_policy_version_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub expected_bundle_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListPolicyVersionsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub bundle_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListPolicyVersionsResponse {
    #[prost(message, repeated, tag="1")]
    pub versions: ::prost::alloc::vec::Vec<PolicyVersion>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetExecutionTraceRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub trace_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListExecutionTracesRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(enumeration="Decision", tag="4")]
    pub decision: i32,
    #[prost(message, optional, tag="5")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListExecutionTracesResponse {
    #[prost(message, repeated, tag="1")]
    pub traces: ::prost::alloc::vec::Vec<ExecutionTrace>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProviderHealthRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProviderHealthResponse {
    #[prost(message, repeated, tag="1")]
    pub providers: ::prost::alloc::vec::Vec<ProviderHealth>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateNsfwOverrideRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub r#override: ::core::option::Option<NsfwOverride>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNsfwOverrideRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub override_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNsfwOverridesRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="NsfwOverrideClassification", tag="2")]
    pub classification: i32,
    #[prost(message, optional, tag="3")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNsfwOverridesResponse {
    #[prost(message, repeated, tag="1")]
    pub overrides: ::prost::alloc::vec::Vec<NsfwOverride>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateNsfwOverrideRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub r#override: ::core::option::Option<NsfwOverride>,
    #[prost(message, optional, tag="3")]
    pub update_mask: ::core::option::Option<::prost_types::FieldMask>,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteNsfwOverrideRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub override_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateRestrictionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub restriction: ::core::option::Option<Restriction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRestrictionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub restriction_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateRestrictionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub restriction: ::core::option::Option<Restriction>,
    #[prost(message, optional, tag="3")]
    pub update_mask: ::core::option::Option<::prost_types::FieldMask>,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeRestrictionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub restriction_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListRestrictionsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(enumeration="ResourceStatus", tag="4")]
    pub status: i32,
    #[prost(message, optional, tag="5")]
    pub page: ::core::option::Option<CursorPage>,
    #[prost(enumeration="RestrictionType", tag="6")]
    pub restriction_type: i32,
    /// Optional restriction subject kind: USER or SERVER.
    #[prost(string, tag="7")]
    pub subject_type: ::prost::alloc::string::String,
    #[prost(string, tag="8")]
    pub subject_id: ::prost::alloc::string::String,
    #[prost(string, tag="9")]
    pub created_by: ::prost::alloc::string::String,
    /// Case-insensitive search across subject_id, reason, and created_by.
    #[prost(string, tag="10")]
    pub query: ::prost::alloc::string::String,
    #[prost(bool, tag="11")]
    pub include_total_count: bool,
    /// created_at_desc, created_at_asc, or expires_at_asc.
    #[prost(string, tag="12")]
    pub sort: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListRestrictionsResponse {
    #[prost(message, repeated, tag="1")]
    pub restrictions: ::prost::alloc::vec::Vec<Restriction>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
    #[prost(uint64, tag="3")]
    pub total_count: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateInfractionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub infraction: ::core::option::Option<Infraction>,
    #[prost(message, optional, tag="3")]
    pub enforcement: ::core::option::Option<Restriction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetInfractionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub infraction_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeInfractionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub infraction_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeInfractionsByTypeRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(enumeration="InfractionType", tag="4")]
    pub r#type: i32,
    #[prost(string, tag="5")]
    pub reason: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeInfractionsByTypeResponse {
    #[prost(message, repeated, tag="1")]
    pub revoked_infractions: ::prost::alloc::vec::Vec<Infraction>,
    #[prost(message, repeated, tag="2")]
    pub revoked_restrictions: ::prost::alloc::vec::Vec<Restriction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListInfractionsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(enumeration="ResourceStatus", tag="4")]
    pub status: i32,
    #[prost(message, optional, tag="5")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListMyInfractionsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="ResourceStatus", tag="2")]
    pub status: i32,
    #[prost(message, optional, tag="3")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListInfractionsResponse {
    #[prost(message, repeated, tag="1")]
    pub infractions: ::prost::alloc::vec::Vec<Infraction>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListModerationRecordsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="ModerationRecordKind", repeated, tag="2")]
    pub kinds: ::prost::alloc::vec::Vec<i32>,
    #[prost(string, tag="3")]
    pub subject_type: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub subject_id: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub created_by: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub query: ::prost::alloc::string::String,
    /// created_at_desc, created_at_asc, or expires_at_asc.
    #[prost(string, tag="7")]
    pub sort: ::prost::alloc::string::String,
    #[prost(message, optional, tag="8")]
    pub page: ::core::option::Option<CursorPage>,
    #[prost(bool, tag="9")]
    pub include_total_count: bool,
    #[prost(enumeration="ResourceStatus", tag="10")]
    pub status: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListModerationRecordsResponse {
    #[prost(message, repeated, tag="1")]
    pub records: ::prost::alloc::vec::Vec<ModerationRecord>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
    #[prost(uint64, tag="3")]
    pub total_count: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LinkModerationRecordReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="ModerationResourceType", tag="2")]
    pub resource_type: i32,
    #[prost(string, tag="3")]
    pub record_id: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="5")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(string, tag="4")]
    pub r#type: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub description: ::prost::alloc::string::String,
    #[prost(message, optional, tag="6")]
    pub report_context: ::core::option::Option<::prost_types::Struct>,
    /// For Lobby reports, pins all durable call evidence through this action.
    #[prost(string, tag="7")]
    pub terminal_action_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListReportsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(enumeration="ResourceStatus", tag="3")]
    pub status: i32,
    #[prost(message, optional, tag="4")]
    pub page: ::core::option::Option<CursorPage>,
    #[prost(string, tag="5")]
    pub query: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub reporter_id: ::prost::alloc::string::String,
    #[prost(string, tag="7")]
    pub reported_user_id: ::prost::alloc::string::String,
    #[prost(string, tag="8")]
    pub reported_server_id: ::prost::alloc::string::String,
    #[prost(string, tag="9")]
    pub report_type: ::prost::alloc::string::String,
    #[prost(message, optional, tag="10")]
    pub created_after: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="11")]
    pub created_before: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListReportsResponse {
    #[prost(message, repeated, tag="1")]
    pub reports: ::prost::alloc::vec::Vec<Report>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListReportTranscriptRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListReportTranscriptResponse {
    #[prost(message, repeated, tag="1")]
    pub entries: ::prost::alloc::vec::Vec<TranscriptEntry>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
    #[prost(uint64, tag="3")]
    pub total_count: u64,
    #[prost(message, optional, tag="4")]
    pub snapshot: ::core::option::Option<ReportEvidenceSnapshot>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResolveReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(enumeration="ResourceStatus", tag="3")]
    pub resolution: i32,
    #[prost(message, optional, tag="4")]
    pub update_mask: ::core::option::Option<::prost_types::FieldMask>,
    #[prost(uint64, tag="5")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateAppealRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub infraction_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub evidence: ::core::option::Option<::prost_types::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAppealRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub appeal_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListAppealsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(enumeration="ResourceStatus", tag="3")]
    pub status: i32,
    #[prost(message, optional, tag="4")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListAppealsResponse {
    #[prost(message, repeated, tag="1")]
    pub appeals: ::prost::alloc::vec::Vec<Appeal>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResolveAppealRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub appeal_id: ::prost::alloc::string::String,
    #[prost(enumeration="ResourceStatus", tag="3")]
    pub resolution: i32,
    #[prost(string, tag="4")]
    pub response: ::prost::alloc::string::String,
    #[prost(uint64, tag="5")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListReviewItemsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(string, tag="3")]
    pub queue: ::prost::alloc::string::String,
    #[prost(enumeration="ResourceStatus", tag="4")]
    pub status: i32,
    #[prost(message, optional, tag="5")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListReviewItemsResponse {
    #[prost(message, repeated, tag="1")]
    pub items: ::prost::alloc::vec::Vec<ReviewItem>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResolveReviewItemRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub review_item_id: ::prost::alloc::string::String,
    #[prost(enumeration="ResourceStatus", tag="3")]
    pub resolution: i32,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AdjudicateHeldActionRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="HeldActionResolution", tag="3")]
    pub resolution: i32,
    #[prost(string, tag="4")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="5")]
    pub expected_version: u64,
    #[prost(oneof="adjudicate_held_action_request::Target", tags="2, 6")]
    pub target: ::core::option::Option<adjudicate_held_action_request::Target>,
}
/// Nested message and enum types in `AdjudicateHeldActionRequest`.
pub mod adjudicate_held_action_request {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Target {
        #[prost(string, tag="2")]
        ActionId(::prost::alloc::string::String),
        #[prost(string, tag="6")]
        ReviewItemId(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HeldAction {
    #[prost(string, tag="1")]
    pub action_id: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub decision_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(enumeration="MessageState", tag="4")]
    pub state: i32,
    #[prost(message, optional, tag="5")]
    pub hold_until: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(uint64, tag="6")]
    pub version: u64,
    #[prost(string, tag="7")]
    pub resolved_by: ::prost::alloc::string::String,
    #[prost(string, tag="8")]
    pub resolution_reason: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="9")]
    pub resolved_review_item_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSafetyAssessmentRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecordSafetyObservationRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="4")]
    pub signal: ::core::option::Option<SafetySignal>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RecalculateSafetyAssessmentRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="3")]
    pub scope: ::core::option::Option<Scope>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetModerationStatisticsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(message, optional, tag="2")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(message, optional, tag="3")]
    pub from: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(message, optional, tag="4")]
    pub to: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModerationStatistics {
    #[prost(uint64, tag="1")]
    pub evaluated_actions: u64,
    #[prost(uint64, tag="2")]
    pub allowed: u64,
    #[prost(uint64, tag="3")]
    pub censored: u64,
    #[prost(uint64, tag="4")]
    pub held: u64,
    #[prost(uint64, tag="5")]
    pub blocked: u64,
    #[prost(uint64, tag="6")]
    pub review_items: u64,
    #[prost(map="string, uint64", tag="7")]
    pub reason_counts: ::std::collections::HashMap<::prost::alloc::string::String, u64>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStaffActionRequestRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub action_request_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListStaffActionRequestsRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="StaffActionRequestStatus", tag="2")]
    pub status: i32,
    #[prost(string, tag="3")]
    pub requested_by: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub page: ::core::option::Option<CursorPage>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListStaffActionRequestsResponse {
    #[prost(message, repeated, tag="1")]
    pub requests: ::prost::alloc::vec::Vec<StaffActionRequest>,
    #[prost(message, optional, tag="2")]
    pub page: ::core::option::Option<CursorPageResult>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
    #[prost(string, tag="4")]
    pub bypass_reason: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RenewReportClaimRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(uint64, tag="3")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnclaimReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AssignReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub assignee_id: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="5")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferReportRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub assignee_id: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub reason: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub bypass_reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="6")]
    pub expected_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateStaffActionRequestRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(enumeration="StaffActionType", tag="2")]
    pub action_type: i32,
    #[prost(message, optional, tag="3")]
    pub subject: ::core::option::Option<Subject>,
    #[prost(message, optional, tag="4")]
    pub scope: ::core::option::Option<Scope>,
    #[prost(string, tag="5")]
    pub report_id: ::prost::alloc::string::String,
    #[prost(string, tag="6")]
    pub reason: ::prost::alloc::string::String,
    #[prost(message, optional, tag="7")]
    pub requested_expires_at: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResolveStaffActionRequestRequest {
    #[prost(message, optional, tag="1")]
    pub context: ::core::option::Option<RequestContext>,
    #[prost(string, tag="2")]
    pub action_request_id: ::prost::alloc::string::String,
    #[prost(bool, tag="3")]
    pub approve: bool,
    #[prost(string, tag="4")]
    pub reason: ::prost::alloc::string::String,
    #[prost(uint64, tag="5")]
    pub expected_version: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CommandClaimState {
    Unspecified = 0,
    Acquired = 1,
    Busy = 2,
    Completed = 3,
    RecoveryRequired = 4,
}
impl CommandClaimState {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CommandClaimState::Unspecified => "COMMAND_CLAIM_STATE_UNSPECIFIED",
            CommandClaimState::Acquired => "COMMAND_CLAIM_STATE_ACQUIRED",
            CommandClaimState::Busy => "COMMAND_CLAIM_STATE_BUSY",
            CommandClaimState::Completed => "COMMAND_CLAIM_STATE_COMPLETED",
            CommandClaimState::RecoveryRequired => "COMMAND_CLAIM_STATE_RECOVERY_REQUIRED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "COMMAND_CLAIM_STATE_UNSPECIFIED" => Some(Self::Unspecified),
            "COMMAND_CLAIM_STATE_ACQUIRED" => Some(Self::Acquired),
            "COMMAND_CLAIM_STATE_BUSY" => Some(Self::Busy),
            "COMMAND_CLAIM_STATE_COMPLETED" => Some(Self::Completed),
            "COMMAND_CLAIM_STATE_RECOVERY_REQUIRED" => Some(Self::RecoveryRequired),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HeldActionResolution {
    Unspecified = 0,
    Approve = 1,
    Reject = 2,
    Expire = 3,
}
impl HeldActionResolution {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            HeldActionResolution::Unspecified => "HELD_ACTION_RESOLUTION_UNSPECIFIED",
            HeldActionResolution::Approve => "HELD_ACTION_RESOLUTION_APPROVE",
            HeldActionResolution::Reject => "HELD_ACTION_RESOLUTION_REJECT",
            HeldActionResolution::Expire => "HELD_ACTION_RESOLUTION_EXPIRE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "HELD_ACTION_RESOLUTION_UNSPECIFIED" => Some(Self::Unspecified),
            "HELD_ACTION_RESOLUTION_APPROVE" => Some(Self::Approve),
            "HELD_ACTION_RESOLUTION_REJECT" => Some(Self::Reject),
            "HELD_ACTION_RESOLUTION_EXPIRE" => Some(Self::Expire),
            _ => None,
        }
    }
}
include!("interchat.trust_and_safety.v2.tonic.rs");
// @@protoc_insertion_point(module)