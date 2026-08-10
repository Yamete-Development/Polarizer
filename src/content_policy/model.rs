use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authority is ordered from the mandatory network floor to local delivery
/// controls. The enum is intentionally generic: adding Call or User later does
/// not require changing matcher or resolver interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Authority {
    Global,
    Hub,
    Server,
}

impl Authority {
    pub const fn precedence(self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Hub => 1,
            Self::Server => 2,
        }
    }

    pub const fn may_punish(self) -> bool {
        !matches!(self, Self::Server)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyScope {
    pub authority: Authority,
    /// Empty only for the singleton GLOBAL scope.
    pub id: String,
}

impl PolicyScope {
    pub fn global() -> Self {
        Self {
            authority: Authority::Global,
            id: String::new(),
        }
    }

    pub fn hub(id: impl Into<String>) -> Self {
        Self {
            authority: Authority::Hub,
            id: id.into(),
        }
    }

    pub fn server(id: impl Into<String>) -> Self {
        Self {
            authority: Authority::Server,
            id: id.into(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match self.authority {
            Authority::Global if self.id.is_empty() => Ok(()),
            Authority::Global => Err("GLOBAL scope must not have an id"),
            Authority::Hub | Authority::Server if self.id.trim().is_empty() => {
                Err("non-GLOBAL scope requires an id")
            }
            Authority::Hub | Authority::Server => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Surface {
    MessageContent,
    DisplayName,
    Username,
    ServerName,
    HubName,
    UrlDomain,
}

impl Surface {
    pub const ALL: [Self; 6] = [
        Self::MessageContent,
        Self::DisplayName,
        Self::Username,
        Self::ServerName,
        Self::HubName,
        Self::UrlDomain,
    ];

    pub const fn is_name(self) -> bool {
        matches!(
            self,
            Self::DisplayName | Self::Username | Self::ServerName | Self::HubName
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WildcardPatternType {
    ExactWord,
    Prefix,
    Suffix,
    Contains,
    Phrase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyActionType {
    Allow,
    Block,
    CensorMatch,
    StripLink,
    SuppressLinks,
    ReplaceName,
    Log,
    LobbyWarn,
    LobbyBan,
    Blacklist,
    HubWarn,
    HubMute,
    HubBan,
}

impl PolicyActionType {
    pub const fn is_delivery(self) -> bool {
        matches!(
            self,
            Self::Allow
                | Self::Block
                | Self::CensorMatch
                | Self::StripLink
                | Self::SuppressLinks
                | Self::ReplaceName
        )
    }

    pub const fn is_side_effect(self) -> bool {
        !self.is_delivery()
    }

    pub const fn is_hub_specific(self) -> bool {
        matches!(
            self,
            Self::Log | Self::HubWarn | Self::HubMute | Self::HubBan
        )
    }

    pub const fn is_global_specific(self) -> bool {
        matches!(self, Self::LobbyWarn | Self::LobbyBan | Self::Blacklist)
    }

    pub const fn needs_duration(self) -> bool {
        matches!(self, Self::LobbyBan | Self::Blacklist | Self::HubMute)
    }

    pub const fn allows_duration(self) -> bool {
        self.needs_duration()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePattern {
    pub id: Uuid,
    /// Original administrator-authored syntax.
    pub pattern: String,
    /// Explicitly classified at validation time; runtime compilation never
    /// reparses wildcard syntax.
    pub pattern_type: WildcardPatternType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleSurface {
    pub surface: Surface,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAction {
    pub id: Uuid,
    pub action_type: PolicyActionType,
    /// Duration-bearing actions store an explicit bounded duration. Permanent
    /// Hub bans intentionally have no duration; permanent global punishments
    /// are rejected during validation.
    pub duration_seconds: Option<u64>,
    /// Optional safe replacement for name presentation. Other delivery
    /// transformations use deterministic built-in behavior.
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub custom_reason: Option<String>,
    pub created_by: String,
    pub patterns: Vec<RulePattern>,
    pub surfaces: BTreeSet<Surface>,
    pub actions: Vec<PolicyAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentPolicy {
    pub id: Uuid,
    pub scope: PolicyScope,
    pub enabled: bool,
    /// Monotonically increases whenever any rule, pattern, surface, or action
    /// in the scope changes.
    pub version: u64,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub hub_patterns: usize,
    pub server_patterns: usize,
    pub global_patterns: usize,
    pub pattern_characters: usize,
    pub rule_name_characters: usize,
    pub rule_description_characters: usize,
    pub custom_reason_characters: usize,
    pub replacement_characters: usize,
    pub maximum_duration_seconds: u64,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            hub_patterns: 1_000,
            server_patterns: 500,
            global_patterns: 10_000,
            pattern_characters: 100,
            rule_name_characters: 100,
            rule_description_characters: 1_000,
            custom_reason_characters: 500,
            replacement_characters: 100,
            maximum_duration_seconds: 365 * 24 * 60 * 60,
        }
    }
}

impl PolicyLimits {
    pub const fn maximum_patterns(self, authority: Authority) -> usize {
        match authority {
            Authority::Global => self.global_patterns,
            Authority::Hub => self.hub_patterns,
            Authority::Server => self.server_patterns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_ids_follow_authority_rules() {
        assert!(PolicyScope::global().validate().is_ok());
        assert!(PolicyScope::hub("hub").validate().is_ok());
        assert!(PolicyScope::server("server").validate().is_ok());
        assert!(PolicyScope::hub("").validate().is_err());
        assert!(
            PolicyScope {
                authority: Authority::Global,
                id: "unexpected".into(),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn server_never_has_punitive_authority() {
        assert!(!Authority::Server.may_punish());
        assert!(PolicyActionType::HubMute.is_side_effect());
        assert!(PolicyActionType::Block.is_delivery());
    }
}
