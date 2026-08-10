use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use tokio::sync::Mutex;

use super::{
    compiler::CompiledPolicySnapshot,
    model::{Authority, PolicyScope},
};

#[derive(Debug)]
struct SnapshotSlot {
    current: ArcSwapOption<CompiledPolicySnapshot>,
    last_version: AtomicU64,
    update: Mutex<()>,
}

impl SnapshotSlot {
    fn empty() -> Self {
        Self {
            current: ArcSwapOption::empty(),
            last_version: AtomicU64::new(0),
            update: Mutex::new(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotUpdate {
    Replaced,
    Removed,
    Unchanged,
    Stale,
}

/// Read-optimized registry of immutable compiled scope policies. Message
/// evaluation performs no SQL/network access and never takes the update mutex.
#[derive(Debug)]
pub struct PolicySnapshotStore {
    global: Arc<SnapshotSlot>,
    scoped: DashMap<PolicyScope, Arc<SnapshotSlot>>,
}

impl Default for PolicySnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicySnapshotStore {
    pub fn new() -> Self {
        Self {
            global: Arc::new(SnapshotSlot::empty()),
            scoped: DashMap::new(),
        }
    }

    /// Lock-free snapshot load after the small sharded scope-map lookup.
    pub fn load(&self, scope: &PolicyScope) -> Option<Arc<CompiledPolicySnapshot>> {
        match scope.authority {
            Authority::Global => self.global.current.load_full(),
            Authority::Hub | Authority::Server => self
                .scoped
                .get(scope)
                .and_then(|slot| slot.current.load_full()),
        }
    }

    pub fn global(&self) -> Option<Arc<CompiledPolicySnapshot>> {
        self.global.current.load_full()
    }

    pub fn hub(&self, id: &str) -> Option<Arc<CompiledPolicySnapshot>> {
        self.load(&PolicyScope::hub(id))
    }

    pub fn server(&self, id: &str) -> Option<Arc<CompiledPolicySnapshot>> {
        self.load(&PolicyScope::server(id))
    }

    pub async fn replace(&self, snapshot: Arc<CompiledPolicySnapshot>) -> SnapshotUpdate {
        let slot = self.slot(&snapshot.scope);
        let _guard = slot.update.lock().await;
        let last_version = slot.last_version.load(Ordering::Acquire);
        if snapshot.version < last_version {
            return SnapshotUpdate::Stale;
        }
        if snapshot.version == last_version {
            return match slot.current.load_full() {
                Some(current)
                    if current.profile_fingerprint == snapshot.profile_fingerprint
                        && current.policy_id == snapshot.policy_id =>
                {
                    SnapshotUpdate::Unchanged
                }
                _ => SnapshotUpdate::Stale,
            };
        }
        slot.current.store(Some(snapshot.clone()));
        slot.last_version.store(snapshot.version, Ordering::Release);
        SnapshotUpdate::Replaced
    }

    /// Apply a versioned deletion/disable event. The retained version tombstone
    /// prevents an older delayed invalidation from restoring stale policy.
    pub async fn remove(&self, scope: &PolicyScope, version: u64) -> SnapshotUpdate {
        let slot = self.slot(scope);
        let _guard = slot.update.lock().await;
        let last_version = slot.last_version.load(Ordering::Acquire);
        if version < last_version {
            return SnapshotUpdate::Stale;
        }
        if version == last_version && slot.current.load_full().is_none() {
            return SnapshotUpdate::Unchanged;
        }
        slot.current.store(None);
        slot.last_version.store(version, Ordering::Release);
        SnapshotUpdate::Removed
    }

    pub fn loaded_scope_count(&self) -> usize {
        usize::from(self.global.current.load().is_some())
            + self
                .scoped
                .iter()
                .filter(|entry| entry.current.load().is_some())
                .count()
    }

    pub fn loaded_scopes(&self) -> Vec<PolicyScope> {
        let mut scopes = Vec::new();
        if self.global.current.load().is_some() {
            scopes.push(PolicyScope::global());
        }
        scopes.extend(
            self.scoped
                .iter()
                .filter(|entry| entry.current.load().is_some())
                .map(|entry| entry.key().clone()),
        );
        scopes.sort_by_key(|scope| (scope.authority, scope.id.clone()));
        scopes
    }

    fn slot(&self, scope: &PolicyScope) -> Arc<SnapshotSlot> {
        match scope.authority {
            Authority::Global => self.global.clone(),
            Authority::Hub | Authority::Server => self
                .scoped
                .entry(scope.clone())
                .or_insert_with(|| Arc::new(SnapshotSlot::empty()))
                .clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use uuid::Uuid;

    use super::*;
    use crate::content_policy::{
        ContentPolicy, PolicyAction, PolicyActionType, PolicyRule, RulePattern, Surface,
        WildcardPatternType,
    };

    fn snapshot(scope: PolicyScope, version: u64, pattern: &str) -> Arc<CompiledPolicySnapshot> {
        Arc::new(
            CompiledPolicySnapshot::compile(&ContentPolicy {
                id: Uuid::from_u128(1),
                scope,
                enabled: true,
                version,
                rules: vec![PolicyRule {
                    id: Uuid::from_u128(2),
                    name: "rule".into(),
                    description: String::new(),
                    enabled: true,
                    custom_reason: None,
                    created_by: "staff".into(),
                    patterns: vec![RulePattern {
                        id: Uuid::from_u128(3),
                        pattern: pattern.into(),
                        pattern_type: WildcardPatternType::ExactWord,
                    }],
                    surfaces: BTreeSet::from([Surface::MessageContent]),
                    actions: vec![PolicyAction {
                        id: Uuid::from_u128(4),
                        action_type: PolicyActionType::Block,
                        duration_seconds: None,
                        replacement: None,
                    }],
                }],
            })
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn replacement_is_atomic_and_rejects_stale_versions() {
        let store = PolicySnapshotStore::new();
        let scope = PolicyScope::hub("hub");
        assert_eq!(
            store.replace(snapshot(scope.clone(), 2, "new")).await,
            SnapshotUpdate::Replaced
        );
        assert_eq!(
            store.replace(snapshot(scope.clone(), 1, "old")).await,
            SnapshotUpdate::Stale
        );
        assert_eq!(store.load(&scope).unwrap().version, 2);
    }

    #[tokio::test]
    async fn versioned_removal_prevents_delayed_restore() {
        let store = PolicySnapshotStore::new();
        let scope = PolicyScope::server("server");
        store.replace(snapshot(scope.clone(), 2, "value")).await;
        assert_eq!(store.remove(&scope, 3).await, SnapshotUpdate::Removed);
        assert!(store.load(&scope).is_none());
        assert_eq!(
            store.replace(snapshot(scope.clone(), 2, "stale")).await,
            SnapshotUpdate::Stale
        );
    }
}
