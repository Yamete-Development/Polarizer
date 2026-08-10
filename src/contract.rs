pub mod prism {
    include!("generated/prism.rs");
}

pub mod interchat {
    pub mod trust_and_safety {
        pub mod v2 {
            // The message module already ends with an `include!` of the
            // generated client/server file, so don't pull it in a second time.
            include!("generated/interchat.trust_and_safety.v2.rs");
        }
    }
}

pub mod authz {
    pub mod v1 {
        include!("generated/authz.v1.rs");
    }
    pub mod v2 {
        include!("generated/authz.v2.rs");
    }
}

pub use interchat::trust_and_safety::v2;

use crate::policy::model::{Effect, EmittedEffect, Product, Scope, ScopeType, Subject};

pub fn emitted_effect_to_proto(emitted: &EmittedEffect) -> v2::PolicyEffect {
    v2::PolicyEffect {
        id: emitted.effect.id().to_owned(),
        policy_version_id: emitted.origin.policy_version_id.to_string(),
        rule_id: emitted.origin.rule_id.clone(),
        effect: Some(effect_body_to_proto(&emitted.effect)),
    }
}

pub fn effect_to_proto(effect: &Effect) -> v2::PolicyEffect {
    v2::PolicyEffect {
        id: effect.id().to_owned(),
        policy_version_id: String::new(),
        rule_id: String::new(),
        effect: Some(effect_body_to_proto(effect)),
    }
}

fn effect_body_to_proto(effect: &Effect) -> v2::policy_effect::Effect {
    use v2::policy_effect::Effect as ProtoEffect;
    match effect {
        Effect::Allow { reason_codes, .. } => ProtoEffect::Allow(v2::AllowEffect {
            reason_codes: reason_codes.clone(),
        }),
        Effect::Block {
            reason_codes,
            public_reason,
            ..
        } => ProtoEffect::Block(v2::BlockEffect {
            reason_codes: reason_codes.clone(),
            public_reason: public_reason.clone().unwrap_or_default(),
        }),
        Effect::Hold {
            reason_codes,
            maximum_duration_ms,
            ..
        } => ProtoEffect::Hold(v2::HoldEffect {
            reason_codes: reason_codes.clone(),
            maximum_duration: maximum_duration_ms.map(duration_from_millis),
        }),
        Effect::Censor {
            spans,
            replacement,
            reason_codes,
            ..
        } => ProtoEffect::Censor(v2::CensorEffect {
            spans: spans
                .iter()
                .map(|span| v2::TextSpan {
                    start_character: span.start_character,
                    end_character: span.end_character,
                })
                .collect(),
            replacement: replacement.clone(),
            reason_codes: reason_codes.clone(),
        }),
        Effect::Flag {
            flag_type,
            severity,
            evidence,
            ..
        } => ProtoEffect::Flag(v2::FlagEffect {
            flag_type: flag_type.clone(),
            severity: *severity,
            evidence: Some(json_to_struct(evidence)),
        }),
        Effect::Notify {
            recipient,
            template,
            parameters,
            ..
        } => ProtoEffect::Notify(v2::NotifyEffect {
            recipient: recipient.clone(),
            template: template.clone(),
            parameters: Some(json_to_struct(parameters)),
        }),
        Effect::CreateInfraction {
            subject,
            infraction_type,
            reason,
            duration_ms,
            ..
        } => ProtoEffect::CreateInfraction(v2::CreateInfractionEffect {
            subject: Some(subject_to_proto(subject)),
            r#type: match infraction_type.as_str() {
                "WARNING" => v2::InfractionType::Warning,
                "MUTE" => v2::InfractionType::Mute,
                "BAN" => v2::InfractionType::Ban,
                "CONTENT" => v2::InfractionType::Content,
                _ => v2::InfractionType::Unspecified,
            } as i32,
            reason: reason.clone(),
            duration: duration_ms.map(duration_from_millis),
        }),
        Effect::CreateRestriction {
            subject,
            restriction_type,
            reason,
            duration_ms,
            ..
        } => ProtoEffect::CreateRestriction(v2::CreateRestrictionEffect {
            subject: Some(subject_to_proto(subject)),
            r#type: match restriction_type.as_str() {
                "MUTE" => v2::RestrictionType::Mute,
                "BAN" => v2::RestrictionType::Ban,
                "BLACKLIST" => v2::RestrictionType::Blacklist,
                "CONTENT_QUARANTINE" => v2::RestrictionType::ContentQuarantine,
                _ => v2::RestrictionType::Unspecified,
            } as i32,
            reason: reason.clone(),
            duration: duration_ms.map(duration_from_millis),
        }),
        Effect::RouteReview {
            queue,
            priority,
            reason_codes,
            ..
        } => ProtoEffect::RouteReview(v2::RouteReviewEffect {
            queue: queue.clone(),
            priority: *priority,
            reason_codes: reason_codes.clone(),
        }),
        Effect::LabelEntity {
            subject,
            label,
            value,
            ..
        } => ProtoEffect::LabelEntity(v2::LabelEntityEffect {
            subject: Some(subject_to_proto(subject)),
            label: label.clone(),
            value: Some(json_to_value(value)),
        }),
        Effect::IncrementCounter {
            subject,
            scope,
            counter_type,
            delta,
            window_ms,
            reset,
            ..
        } => ProtoEffect::IncrementCounter(v2::IncrementCounterEffect {
            subject: Some(subject_to_proto(subject)),
            scope: Some(scope_to_proto(scope)),
            counter_type: counter_type.clone(),
            delta: *delta,
            window: Some(duration_from_millis(*window_ms)),
            reset: *reset,
        }),
        Effect::Delete {
            message_id,
            channel_id,
            reason_codes,
            ..
        } => ProtoEffect::Delete(v2::DeleteEffect {
            message_id: message_id.clone(),
            channel_id: channel_id.clone(),
            reason_codes: reason_codes.clone(),
        }),
        Effect::Kick {
            user_id,
            server_id,
            reason_codes,
            ..
        } => ProtoEffect::Kick(v2::KickEffect {
            user_id: user_id.clone(),
            server_id: server_id.clone(),
            reason_codes: reason_codes.clone(),
        }),
    }
}

pub(crate) fn scope_to_proto(scope: &Scope) -> v2::Scope {
    v2::Scope {
        r#type: match scope.scope_type {
            ScopeType::Platform => v2::ScopeType::Platform,
            ScopeType::Product => v2::ScopeType::Product,
            ScopeType::Hub => v2::ScopeType::Hub,
            ScopeType::Lobby => v2::ScopeType::Lobby,
            ScopeType::IncidentOverlay => v2::ScopeType::IncidentOverlay,
        } as i32,
        id: scope.id.clone(),
        product: match scope.product {
            Some(Product::Hub) => v2::Product::Hub,
            Some(Product::Lobby) => v2::Product::Lobby,
            None => v2::Product::Unspecified,
        } as i32,
    }
}

pub(crate) fn subject_to_proto(subject: &Subject) -> v2::Subject {
    v2::Subject {
        user_id: subject.user_id.clone().unwrap_or_default(),
        server_id: subject.server_id.clone().unwrap_or_default(),
        message_id: subject.message_id.clone().unwrap_or_default(),
        channel_id: subject.channel_id.clone().unwrap_or_default(),
        report_id: subject.report_id.clone().unwrap_or_default(),
    }
}

fn duration_from_millis(value: u64) -> prost_types::Duration {
    prost_types::Duration {
        seconds: (value / 1_000).min(i64::MAX as u64) as i64,
        nanos: ((value % 1_000) * 1_000_000) as i32,
    }
}

fn json_to_struct(value: &serde_json::Value) -> prost_types::Struct {
    prost_types::Struct {
        fields: value
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), json_to_value(value)))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn json_to_value(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(*value),
        serde_json::Value::Number(value) => Kind::NumberValue(value.as_f64().unwrap_or_default()),
        serde_json::Value::String(value) => Kind::StringValue(value.clone()),
        serde_json::Value::Array(values) => Kind::ListValue(prost_types::ListValue {
            values: values.iter().map(json_to_value).collect(),
        }),
        serde_json::Value::Object(_) => Kind::StructValue(json_to_struct(value)),
    };
    prost_types::Value { kind: Some(kind) }
}
