//! In-memory suppression of repeated content-policy side effects.
//!
//! Delivery transformations are intentionally not represented in this gate:
//! every delivery action must be evaluated for every message.  Only effects
//! that cause an external side effect are recorded here.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use uuid::Uuid;

use super::{PolicyActionType, PolicyScope};

/// The default period for which an already-triggered side effect is muted.
pub const DEFAULT_COOLDOWN_DURATION: Duration = Duration::from_secs(60);

/// The maximum number of subject/rule cooldowns retained by a default gate.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// The side-effect categories that can be suppressed independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionFamily {
    Log,
    Punishment,
}

impl ActionFamily {
    /// Return the cooldown family for an action, or `None` for delivery-only
    /// actions.  All punishment strengths share one family so, for example,
    /// `HubWarn` and `HubBan` cannot repeatedly fire the same rule.
    pub const fn for_action(action_type: PolicyActionType) -> Option<Self> {
        match action_type {
            PolicyActionType::Log => Some(Self::Log),
            PolicyActionType::LobbyWarn
            | PolicyActionType::LobbyBan
            | PolicyActionType::Blacklist
            | PolicyActionType::HubWarn
            | PolicyActionType::HubMute
            | PolicyActionType::HubBan => Some(Self::Punishment),
            _ => None,
        }
    }
}

/// The complete identity of one suppressible side effect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CooldownKey {
    pub subject: String,
    pub scope: PolicyScope,
    pub rule_id: Uuid,
    pub action_family: ActionFamily,
}

/// Configuration for a [`SideEffectCooldown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CooldownConfig {
    pub duration: Duration,
    pub max_entries: usize,
}

impl Default for CooldownConfig {
    fn default() -> Self {
        Self {
            duration: DEFAULT_COOLDOWN_DURATION,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// A bounded, concurrency-safe cooldown registry for policy side effects.
///
/// The small mutex makes the check-and-record operation atomic and keeps the
/// configured bound strict even when many evaluations arrive concurrently.
/// The actual registry remains a `DashMap`, so inspection and removal remain
/// safe for callers that share the gate across workers.
#[derive(Debug)]
pub struct SideEffectCooldown {
    entries: DashMap<CooldownKey, Instant>,
    config: CooldownConfig,
    update: Mutex<()>,
}

impl Default for SideEffectCooldown {
    fn default() -> Self {
        Self::with_config(CooldownConfig::default())
    }
}

impl SideEffectCooldown {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(mut config: CooldownConfig) -> Self {
        // A zero-sized registry cannot remember a side effect, so normalize it
        // to the smallest useful bounded registry.
        config.max_entries = config.max_entries.max(1);
        Self {
            entries: DashMap::new(),
            config,
            update: Mutex::new(()),
        }
    }

    pub fn with_duration(duration: Duration, max_entries: usize) -> Self {
        Self::with_config(CooldownConfig {
            duration,
            max_entries,
        })
    }

    pub const fn config(&self) -> CooldownConfig {
        self.config
    }

    /// Atomically check and record a side effect using the system clock.
    ///
    /// Returns `true` when the effect should be delivered.  Delivery actions
    /// always return `true` and never consume a cooldown entry.
    pub fn allow(
        &self,
        subject: impl Into<String>,
        scope: &PolicyScope,
        rule_id: Uuid,
        action_type: PolicyActionType,
    ) -> bool {
        self.allow_at(subject, scope, rule_id, action_type, Instant::now())
    }

    /// Deterministic form of [`Self::allow`] for tests and callers with an
    /// already captured clock value.
    pub fn allow_at(
        &self,
        subject: impl Into<String>,
        scope: &PolicyScope,
        rule_id: Uuid,
        action_type: PolicyActionType,
        now: Instant,
    ) -> bool {
        let Some(action_family) = ActionFamily::for_action(action_type) else {
            return true;
        };

        let _update = self
            .update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_expired(now);

        let key = CooldownKey {
            subject: subject.into(),
            scope: scope.clone(),
            rule_id,
            action_family,
        };
        if self
            .entries
            .get(&key)
            .is_some_and(|expires_at| *expires_at > now)
        {
            return false;
        }

        if self.entries.len() >= self.config.max_entries {
            self.evict_earliest();
        }
        let expires_at = now.checked_add(self.config.duration).unwrap_or(now);
        self.entries.insert(key, expires_at);
        true
    }

    /// Remove expired entries using the system clock.
    pub fn prune(&self) -> usize {
        self.prune_at(Instant::now())
    }

    /// Deterministic form of [`Self::prune`]. Returns the number removed.
    pub fn prune_at(&self, now: Instant) -> usize {
        let _update = self
            .update
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_expired(now)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn prune_expired(&self, now: Instant) -> usize {
        let expired = self
            .entries
            .iter()
            .filter(|entry| *entry.value() <= now)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut removed = 0;
        for key in expired {
            if self.entries.remove(&key).is_some() {
                removed += 1;
            }
        }
        removed
    }

    fn evict_earliest(&self) {
        let earliest = self
            .entries
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .min_by_key(|(_, expires_at)| *expires_at)
            .map(|(key, _)| key);
        if let Some(key) = earliest {
            self.entries.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: Uuid = Uuid::from_u128(1);

    fn scope() -> PolicyScope {
        PolicyScope::hub("hub-a")
    }

    fn allow_at(
        gate: &SideEffectCooldown,
        subject: &str,
        scope: &PolicyScope,
        rule_id: Uuid,
        action_type: PolicyActionType,
        now: Instant,
    ) -> bool {
        gate.allow_at(subject, scope, rule_id, action_type, now)
    }

    #[test]
    fn suppresses_repeated_effect_until_expiry() {
        let gate = SideEffectCooldown::with_duration(Duration::from_secs(10), 16);
        let now = Instant::now();

        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::HubWarn,
            now,
        ));
        assert!(!allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::HubBan,
            now + Duration::from_secs(9),
        ));
        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::HubBan,
            now + Duration::from_secs(10),
        ));
    }

    #[test]
    fn rule_scope_and_subject_are_isolated() {
        let gate = SideEffectCooldown::with_duration(Duration::from_secs(10), 16);
        let now = Instant::now();
        let other_scope = PolicyScope::hub("hub-b");

        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::HubMute,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-2",
            &scope(),
            RULE,
            PolicyActionType::HubMute,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-1",
            &other_scope,
            RULE,
            PolicyActionType::HubMute,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            Uuid::from_u128(2),
            PolicyActionType::HubMute,
            now,
        ));
    }

    #[test]
    fn logs_have_a_separate_family() {
        let gate = SideEffectCooldown::with_duration(Duration::from_secs(10), 16);
        let now = Instant::now();

        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::Log,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::HubWarn,
            now,
        ));
        assert!(!allow_at(
            &gate,
            "user-1",
            &scope(),
            RULE,
            PolicyActionType::Log,
            now,
        ));
    }

    #[test]
    fn delivery_actions_are_always_allowed_and_not_recorded() {
        let gate = SideEffectCooldown::with_duration(Duration::from_secs(10), 16);
        let now = Instant::now();
        for action_type in [
            PolicyActionType::Allow,
            PolicyActionType::Block,
            PolicyActionType::CensorMatch,
            PolicyActionType::StripLink,
            PolicyActionType::SuppressLinks,
            PolicyActionType::ReplaceName,
        ] {
            assert!(allow_at(&gate, "user-1", &scope(), RULE, action_type, now));
            assert!(allow_at(&gate, "user-1", &scope(), RULE, action_type, now));
        }
        assert!(gate.is_empty());
    }

    #[test]
    fn pruning_and_capacity_keep_registry_bounded() {
        let gate = SideEffectCooldown::with_duration(Duration::from_secs(10), 2);
        let now = Instant::now();

        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            Uuid::from_u128(1),
            PolicyActionType::Log,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-2",
            &scope(),
            Uuid::from_u128(2),
            PolicyActionType::Log,
            now,
        ));
        assert_eq!(gate.len(), 2);
        assert_eq!(gate.prune_at(now + Duration::from_secs(10)), 2);
        assert!(gate.is_empty());

        assert!(allow_at(
            &gate,
            "user-1",
            &scope(),
            Uuid::from_u128(1),
            PolicyActionType::Log,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-2",
            &scope(),
            Uuid::from_u128(2),
            PolicyActionType::Log,
            now,
        ));
        assert!(allow_at(
            &gate,
            "user-3",
            &scope(),
            Uuid::from_u128(3),
            PolicyActionType::Log,
            now,
        ));
        assert_eq!(gate.len(), 2);
    }
}
