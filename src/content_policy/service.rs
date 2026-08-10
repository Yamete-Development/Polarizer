use std::{collections::BTreeSet, sync::Arc};

use super::{
    compiler::{CompiledPolicySnapshot, PolicyMatchError},
    model::{ContentPolicy, PolicyLimits, PolicyScope},
    repository::ContentPolicySource,
    snapshot::{PolicySnapshotStore, SnapshotUpdate},
    validation::{PolicyValidationErrors, validate_and_classify_policy},
};

#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error(transparent)]
    Load(#[from] anyhow::Error),
    #[error(transparent)]
    Validation(#[from] PolicyValidationErrors),
    #[error(transparent)]
    Compile(#[from] PolicyMatchError),
    #[error(
        "content policy {scope:?} version {loaded} is older than invalidated version {expected}"
    )]
    VersionNotVisible {
        scope: PolicyScope,
        expected: u64,
        loaded: u64,
    },
}

/// Cold-path orchestration for loading, validating, compiling, and atomically
/// publishing native content policies.
pub struct ContentPolicyRuntime {
    source: Arc<dyn ContentPolicySource>,
    snapshots: Arc<PolicySnapshotStore>,
    limits: PolicyLimits,
}

impl ContentPolicyRuntime {
    pub fn new(
        source: Arc<dyn ContentPolicySource>,
        snapshots: Arc<PolicySnapshotStore>,
        limits: PolicyLimits,
    ) -> Self {
        Self {
            source,
            snapshots,
            limits,
        }
    }

    pub fn snapshots(&self) -> &Arc<PolicySnapshotStore> {
        &self.snapshots
    }

    /// Startup is all-or-nothing: compile every enabled policy before any
    /// snapshot becomes visible.
    pub async fn bootstrap(&self) -> Result<usize, ReloadError> {
        let definitions = self.source.load_all().await?;
        let compiled = self.compile_all(&definitions)?;
        for snapshot in compiled {
            self.snapshots.replace(snapshot).await;
        }
        for definition in definitions.iter().filter(|policy| !policy.enabled) {
            self.snapshots
                .remove(&definition.scope, definition.version)
                .await;
        }
        Ok(self.snapshots.loaded_scope_count())
    }

    pub async fn reload_scope(
        &self,
        scope: &PolicyScope,
        expected_version: u64,
    ) -> Result<SnapshotUpdate, ReloadError> {
        let Some(definition) = self.source.load_scope(scope).await? else {
            return Ok(self.snapshots.remove(scope, expected_version).await);
        };
        if definition.version < expected_version {
            return Err(ReloadError::VersionNotVisible {
                scope: scope.clone(),
                expected: expected_version,
                loaded: definition.version,
            });
        }
        if !definition.enabled {
            return Ok(self
                .snapshots
                .remove(&definition.scope, definition.version)
                .await);
        }
        let snapshot = self.compile_one(&definition)?;
        Ok(self.snapshots.replace(snapshot).await)
    }

    /// Periodic reconciliation recovers missed invalidation events. Normal
    /// propagation still uses the low-latency event consumer.
    pub async fn reconcile(&self) -> Result<usize, ReloadError> {
        let definitions = self.source.load_all().await?;
        let compiled = self.compile_all(&definitions)?;
        let present = definitions
            .iter()
            .map(|policy| policy.scope.clone())
            .collect::<BTreeSet<_>>();

        for snapshot in compiled {
            self.snapshots.replace(snapshot).await;
        }
        for definition in definitions.iter().filter(|policy| !policy.enabled) {
            self.snapshots
                .remove(&definition.scope, definition.version)
                .await;
        }
        for scope in self.snapshots.loaded_scopes() {
            if !present.contains(&scope) {
                let next_version = self
                    .snapshots
                    .load(&scope)
                    .map_or(1, |snapshot| snapshot.version.saturating_add(1));
                self.snapshots.remove(&scope, next_version).await;
            }
        }
        Ok(self.snapshots.loaded_scope_count())
    }

    fn compile_all(
        &self,
        definitions: &[ContentPolicy],
    ) -> Result<Vec<Arc<CompiledPolicySnapshot>>, ReloadError> {
        definitions
            .iter()
            .filter(|policy| policy.enabled)
            .map(|policy| self.compile_one(policy))
            .collect()
    }

    fn compile_one(
        &self,
        definition: &ContentPolicy,
    ) -> Result<Arc<CompiledPolicySnapshot>, ReloadError> {
        let mut definition = definition.clone();
        validate_and_classify_policy(&mut definition, self.limits)?;
        Ok(Arc::new(CompiledPolicySnapshot::compile(&definition)?))
    }
}
