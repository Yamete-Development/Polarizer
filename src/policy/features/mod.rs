pub mod checks;
pub mod media;
pub mod postgres;
pub mod text;

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::config::AppConfig;
use sqlx::PgPool;

use super::{
    model::{
        Action, DataHandlingClass, FeatureFailure, FeatureRequirement, FeatureSnapshot,
        FeatureValue,
    },
    runtime::sha256_hex,
};

#[derive(Debug, Clone)]
pub struct ProviderOutput {
    pub value: serde_json::Value,
    pub cache_hit: bool,
    pub input_hash: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ProviderError {
    #[error("provider is unavailable")]
    Unavailable,
    #[error("provider timed out")]
    Timeout,
    #[error("provider rate limit reached")]
    RateLimited,
    #[error("provider rejected the input")]
    Rejected,
    #[error("provider received invalid input: {0}")]
    InvalidInput(String),
    #[error("provider failed")]
    Internal,
}

impl ProviderError {
    fn feature_failure(&self) -> FeatureFailure {
        let (code, retryable) = match self {
            Self::Unavailable => ("UNAVAILABLE", true),
            Self::Timeout => ("TIMEOUT", true),
            Self::RateLimited => ("RATE_LIMITED", true),
            Self::Rejected => ("PROVIDER_REJECTED", false),
            Self::InvalidInput(_) => ("INVALID_INPUT", false),
            Self::Internal => ("INTERNAL", true),
        };
        FeatureFailure {
            code: code.into(),
            safe_message: self.to_string(),
            retryable,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderHealth {
    pub name: String,
    pub version: String,
    pub healthy: bool,
    pub status: String,
    pub checked_at: DateTime<Utc>,
}

/// Stable operational metadata shared by every read-only policy feature.
/// `Check` providers classify an action, while enrichments and state providers
/// supply derived or authoritative context. Policies refer only to `name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCategory {
    Enrichment,
    State,
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCachePolicy {
    None,
    ProviderManaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDescriptor {
    pub name: String,
    pub version: String,
    pub category: ProviderCategory,
    pub cache: ProviderCachePolicy,
    pub external: bool,
}

#[async_trait]
pub trait FeatureProvider: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn category(&self) -> ProviderCategory {
        ProviderCategory::Enrichment
    }
    fn cache_policy(&self) -> ProviderCachePolicy {
        ProviderCachePolicy::None
    }
    fn is_external(&self) -> bool {
        false
    }
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            name: self.name().into(),
            version: self.version().into(),
            category: self.category(),
            cache: self.cache_policy(),
            external: self.is_external(),
        }
    }
    async fn resolve(
        &self,
        action: &Action,
        configuration: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError>;
    /// Return the provider-owned representation that may be persisted in an
    /// execution trace. Providers that expose content or other sensitive
    /// inputs must override this method and return only redacted metadata.
    fn redact_for_trace(&self, output: &ProviderOutput) -> serde_json::Value {
        output.value.clone()
    }
    async fn health(&self) -> ProviderHealth {
        ProviderHealth {
            name: self.name().into(),
            version: self.version().into(),
            healthy: true,
            status: "READY".into(),
            checked_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeatureInvocationKey {
    name: String,
    fingerprint: String,
}

impl FeatureInvocationKey {
    fn from_requirement(requirement: &FeatureRequirement) -> Self {
        let controls = serde_json::json!({
            "configuration": canonical_json(&requirement.configuration),
            "deadline_ms": requirement.deadline_ms,
            "maximum_data_handling": data_handling_name(requirement.maximum_data_handling),
        });
        Self {
            name: requirement.name.clone(),
            fingerprint: sha256_hex(
                &serde_json::to_vec(&controls).expect("feature invocation controls serialize"),
            ),
        }
    }

    fn trace_name(&self) -> String {
        format!("{}@{}", self.name, &self.fingerprint[..12])
    }
}

#[derive(Debug, Clone)]
struct ResolvedFeatureValue {
    runtime: FeatureValue,
    trace: FeatureValue,
}

/// Results for all distinct feature invocations needed by one evaluation.
/// Runtime snapshots are projected back to provider names per policy, while
/// trace snapshots retain an invocation fingerprint so different policy
/// configurations cannot overwrite one another.
#[derive(Debug, Clone, Default)]
pub struct ResolvedFeatures {
    values: BTreeMap<FeatureInvocationKey, ResolvedFeatureValue>,
}

impl ResolvedFeatures {
    pub fn runtime_snapshot(&self, requirements: &[FeatureRequirement]) -> FeatureSnapshot {
        requirements
            .iter()
            .filter_map(|requirement| {
                self.values
                    .get(&FeatureInvocationKey::from_requirement(requirement))
                    .map(|resolved| (requirement.name.clone(), resolved.runtime.clone()))
            })
            .collect()
    }

    pub fn trace_snapshot(&self) -> FeatureSnapshot {
        self.values
            .iter()
            .map(|(key, resolved)| (key.trace_name(), resolved.trace.clone()))
            .collect()
    }
}

#[derive(Default)]
pub struct FeatureRegistry {
    providers: RwLock<HashMap<String, Arc<dyn FeatureProvider>>>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("feature provider `{0}` is registered more than once")]
    DuplicateProvider(String),
}

impl FeatureRegistry {
    pub fn from_providers(
        providers: impl IntoIterator<Item = Arc<dyn FeatureProvider>>,
    ) -> Result<Self, RegistryError> {
        let mut registered = HashMap::new();
        for provider in providers {
            let name = provider.name().to_owned();
            if registered.insert(name.clone(), provider).is_some() {
                return Err(RegistryError::DuplicateProvider(name));
            }
        }
        Ok(Self {
            providers: RwLock::new(registered),
        })
    }

    pub async fn register(&self, provider: Arc<dyn FeatureProvider>) -> Result<(), RegistryError> {
        let name = provider.name().to_owned();
        let mut providers = self.providers.write().await;
        if providers.contains_key(&name) {
            return Err(RegistryError::DuplicateProvider(name));
        }
        providers.insert(name, provider);
        Ok(())
    }

    pub async fn descriptors(&self) -> Vec<ProviderDescriptor> {
        let mut descriptors = self
            .providers
            .read()
            .await
            .values()
            .map(|provider| provider.descriptor())
            .collect::<Vec<_>>();
        descriptors.sort_by(|left, right| left.name.cmp(&right.name));
        descriptors
    }

    pub async fn resolve(
        &self,
        action: &Action,
        requirements: &[FeatureRequirement],
    ) -> ResolvedFeatures {
        let providers = self.providers.read().await;
        let mut unique = BTreeMap::<FeatureInvocationKey, &FeatureRequirement>::new();
        for requirement in requirements {
            unique
                .entry(FeatureInvocationKey::from_requirement(requirement))
                .or_insert(requirement);
        }
        let mut futures = Vec::with_capacity(unique.len());
        for (key, requirement) in unique {
            let provider = providers.get(&key.name).cloned();
            futures.push(async move {
                let started = Instant::now();
                let result = if action.data_handling > requirement.maximum_data_handling {
                    Err(ProviderError::Rejected)
                } else if let Some(provider) = provider.as_ref() {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(requirement.deadline_ms.max(1)),
                        provider.resolve(action, &requirement.configuration),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err(ProviderError::Timeout),
                    }
                } else {
                    Err(ProviderError::Unavailable)
                };
                let elapsed = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
                let version = provider
                    .as_ref()
                    .map(|item| item.version())
                    .unwrap_or("unregistered")
                    .to_owned();
                let value = match result {
                    Ok(output) => {
                        let trace_value = provider
                            .as_ref()
                            .expect("registered provider produced output")
                            .redact_for_trace(&output);
                        let runtime = FeatureValue {
                            provider: key.name.clone(),
                            provider_version: version.clone(),
                            value: Some(output.value),
                            error: None,
                            latency_micros: elapsed,
                            cache_hit: output.cache_hit,
                            input_hash: output.input_hash.clone(),
                        };
                        let trace = FeatureValue {
                            value: Some(trace_value),
                            ..runtime.clone()
                        };
                        ResolvedFeatureValue { runtime, trace }
                    }
                    Err(error) => {
                        let value = FeatureValue {
                            provider: key.name.clone(),
                            provider_version: version,
                            value: None,
                            error: Some(error.feature_failure()),
                            latency_micros: elapsed,
                            cache_hit: false,
                            input_hash: None,
                        };
                        ResolvedFeatureValue {
                            runtime: value.clone(),
                            trace: value,
                        }
                    }
                };
                (key, value)
            });
        }
        drop(providers);
        ResolvedFeatures {
            values: futures::future::join_all(futures)
                .await
                .into_iter()
                .collect(),
        }
    }

    pub async fn health(&self) -> Vec<ProviderHealth> {
        let providers: Vec<_> = self.providers.read().await.values().cloned().collect();
        futures::future::join_all(
            providers
                .into_iter()
                .map(|provider| async move { provider.health().await }),
        )
        .await
    }
}

/// Construct the complete production catalog in one place. Adding a future
/// classifier should require only a provider implementation and one entry in
/// `checks::configured`; service bootstrap remains vendor-neutral.
pub fn production_registry(db: PgPool, config: &AppConfig) -> anyhow::Result<FeatureRegistry> {
    use postgres::{
        CounterProvider, EntityLabelProvider, RestrictionProvider, SafetyAssessmentProvider,
    };
    use text::NormalizedTextProvider;

    let mut providers: Vec<Arc<dyn FeatureProvider>> = vec![
        Arc::new(NormalizedTextProvider),
        Arc::new(RestrictionProvider::new(db.clone())),
        Arc::new(CounterProvider::new(db.clone())),
        Arc::new(SafetyAssessmentProvider::new(db.clone())),
        Arc::new(EntityLabelProvider::new(db.clone())),
    ];
    providers.extend(checks::configured(db, config)?);
    FeatureRegistry::from_providers(providers).map_err(Into::into)
}

fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json).collect())
        }
        _ => value.clone(),
    }
}

fn data_handling_name(value: DataHandlingClass) -> &'static str {
    match value {
        DataHandlingClass::Public => "PUBLIC",
        DataHandlingClass::Internal => "INTERNAL",
        DataHandlingClass::Sensitive => "SENSITIVE",
        DataHandlingClass::Restricted => "RESTRICTED",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::policy::{
        features::text::NormalizedTextProvider,
        model::{ErrorBehavior, Product, Scope, ScopeType, Subject},
    };
    use chrono::Utc;
    use uuid::Uuid;

    struct EchoConfigurationProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl FeatureProvider for EchoConfigurationProvider {
        fn name(&self) -> &str {
            "configured.feature"
        }

        fn version(&self) -> &str {
            "test-v1"
        }

        async fn resolve(
            &self,
            _action: &Action,
            configuration: &serde_json::Value,
        ) -> Result<ProviderOutput, ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(ProviderOutput {
                value: configuration.clone(),
                cache_hit: false,
                input_hash: None,
            })
        }
    }

    fn action(content: &str) -> Action {
        Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub-1".into(),
                product: Some(Product::Hub),
            },
            subject: Subject::default(),
            occurred_at: Utc::now(),
            attributes: serde_json::json!({"content": content}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        }
    }

    fn requirement(name: &str, configuration: serde_json::Value) -> FeatureRequirement {
        FeatureRequirement {
            name: name.into(),
            error_behavior: ErrorBehavior::Hold,
            deadline_ms: 25,
            maximum_data_handling: DataHandlingClass::Sensitive,
            configuration,
        }
    }

    #[tokio::test]
    async fn same_provider_with_different_policy_configuration_is_isolated() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = FeatureRegistry::default();
        registry
            .register(Arc::new(EchoConfigurationProvider {
                calls: calls.clone(),
            }))
            .await
            .unwrap();
        let global = requirement(
            "configured.feature",
            serde_json::json!({"patterns": ["global"]}),
        );
        let hub = requirement(
            "configured.feature",
            serde_json::json!({"patterns": ["hub"], "whitelist": ["hub-safe"]}),
        );

        let resolved = registry
            .resolve(
                &action("message"),
                &[global.clone(), hub.clone(), global.clone()],
            )
            .await;

        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            resolved.runtime_snapshot(&[global])["configured.feature"].value,
            Some(serde_json::json!({"patterns": ["global"]}))
        );
        assert_eq!(
            resolved.runtime_snapshot(&[hub])["configured.feature"].value,
            Some(serde_json::json!({"patterns": ["hub"], "whitelist": ["hub-safe"]}))
        );
        assert_eq!(resolved.trace_snapshot().len(), 2);
    }

    #[tokio::test]
    async fn normalized_text_is_available_at_runtime_but_redacted_from_trace() {
        let registry = FeatureRegistry::default();
        registry
            .register(Arc::new(NormalizedTextProvider))
            .await
            .unwrap();
        let requirement = requirement("text.normalized", serde_json::json!({}));
        let resolved = registry
            .resolve(
                &action("SuperSecret Phrase"),
                std::slice::from_ref(&requirement),
            )
            .await;

        let runtime = resolved.runtime_snapshot(&[requirement]);
        assert_eq!(
            runtime["text.normalized"]
                .value
                .as_ref()
                .and_then(|value| value.get("text"))
                .and_then(serde_json::Value::as_str),
            Some("supersecret phrase")
        );

        let trace = serde_json::to_string(&resolved.trace_snapshot()).unwrap();
        assert!(!trace.contains("SuperSecret"));
        assert!(!trace.contains("supersecret"));
        assert!(trace.contains("normalized_text_sha256"));
        assert!(trace.contains("normalized_character_count"));
    }

    #[tokio::test]
    async fn automod_matches_trace_contains_metadata_not_content_or_security_views() {
        use crate::policy::features::text::AutomodMatchProvider;

        let registry = FeatureRegistry::default();
        registry
            .register(Arc::new(AutomodMatchProvider))
            .await
            .unwrap();
        let requirement = requirement(
            "automod.matches",
            serde_json::json!({
                "literals": [{"id": "wumpus", "pattern": "wumpus"}],
                "regexes": [],
                "whitelist_pattern_ids": []
            }),
        );
        let source = "Wum.pus";
        let resolved = registry
            .resolve(&action(source), std::slice::from_ref(&requirement))
            .await;

        let runtime = resolved.runtime_snapshot(std::slice::from_ref(&requirement));
        assert_eq!(
            runtime["automod.matches"]
                .value
                .as_ref()
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1)
        );

        let trace = serde_json::to_string(&resolved.trace_snapshot()).unwrap();
        assert!(trace.contains("match_count"));
        assert!(!trace.contains(source));
        assert!(!trace.contains("wum pus"));
        assert!(!trace.contains("wumpus"));
        assert!(!trace.contains("Wum"));
    }

    #[tokio::test]
    async fn duplicate_provider_names_are_rejected_instead_of_replaced() {
        let registry = FeatureRegistry::default();
        registry
            .register(Arc::new(NormalizedTextProvider))
            .await
            .unwrap();

        let error = registry
            .register(Arc::new(NormalizedTextProvider))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            RegistryError::DuplicateProvider("text.normalized".into())
        );
        assert_eq!(registry.descriptors().await.len(), 1);
    }

    #[tokio::test]
    async fn catalog_exposes_typed_check_metadata() {
        use crate::policy::features::text::AutomodMatchProvider;

        let registry = FeatureRegistry::from_providers([
            Arc::new(NormalizedTextProvider) as Arc<dyn FeatureProvider>,
            Arc::new(AutomodMatchProvider) as Arc<dyn FeatureProvider>,
        ])
        .unwrap();
        let descriptors = registry.descriptors().await;

        assert_eq!(descriptors[0].name, "automod.matches");
        assert_eq!(descriptors[0].category, ProviderCategory::Check);
        assert_eq!(descriptors[0].cache, ProviderCachePolicy::None);
        assert!(!descriptors[0].external);
        assert_eq!(descriptors[1].category, ProviderCategory::Enrichment);
    }
}
