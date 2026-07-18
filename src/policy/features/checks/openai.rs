//! OpenAI's moderation classifier exposed as a read-only policy check.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use dashmap::DashMap;
use futures::StreamExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};
use unicode_normalization::UnicodeNormalization;

use super::super::{
    FeatureProvider, ProviderCachePolicy, ProviderCategory, ProviderError, ProviderHealth,
    ProviderOutput,
};
use crate::policy::{model::Action, runtime::sha256_hex};

#[derive(Clone, Serialize)]
struct ModerationRequest {
    model: String,
    input: ModerationInput,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum ModerationInput {
    Text(String),
    Multi(Vec<ModerationInputPart>),
}

#[derive(Clone, Serialize)]
#[serde(tag = "type")]
enum ModerationInputPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: ImageUrl },
}

#[derive(Clone, Serialize)]
struct ImageUrl {
    url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProviderConfiguration {
    external_images: bool,
}

#[derive(Debug, Deserialize)]
struct ModerationResponse {
    id: Option<String>,
    model: String,
    results: Vec<ModerationResult>,
}

#[derive(Debug, Deserialize)]
struct ModerationResult {
    flagged: bool,
    categories: BTreeMap<String, bool>,
    category_scores: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiModerationSignal {
    pub provider_request_id: Option<String>,
    pub response_id: Option<String>,
    pub model_snapshot: String,
    pub flagged: bool,
    pub categories: BTreeMap<String, bool>,
    pub category_scores: BTreeMap<String, f64>,
    pub input_modality: String,
    pub latency_millis: u64,
    pub cache_hit: bool,
}

struct CachedSignal {
    expires_at: Instant,
    signal: OpenAiModerationSignal,
}

#[derive(Default)]
struct CircuitState {
    consecutive_failures: u32,
    opened_until: Option<Instant>,
}

struct TransportResponse {
    status: u16,
    request_id: Option<String>,
    body: Vec<u8>,
}

enum TransportError {
    Timeout,
    Unavailable,
    InvalidResponse,
}

#[async_trait]
trait ModerationTransport: Send + Sync {
    async fn send(&self, request: &ModerationRequest) -> Result<TransportResponse, TransportError>;
}

struct HttpModerationTransport {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
}

#[async_trait]
impl ModerationTransport for HttpModerationTransport {
    async fn send(&self, request: &ModerationRequest) -> Result<TransportResponse, TransportError> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    TransportError::Timeout
                } else {
                    TransportError::Unavailable
                }
            })?;
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .or_else(|| response.headers().get("openai-request-id"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if !(200..300).contains(&status) {
            return Ok(TransportResponse {
                status,
                request_id,
                body: Vec::new(),
            });
        }
        const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                if error.is_timeout() {
                    TransportError::Timeout
                } else {
                    TransportError::Unavailable
                }
            })?;
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(TransportError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(TransportResponse {
            status,
            request_id,
            body,
        })
    }
}

pub struct OpenAiModerationProvider {
    transport: Arc<dyn ModerationTransport>,
    model: String,
    external_images: bool,
    concurrency: Arc<Semaphore>,
    circuit: Mutex<CircuitState>,
    cache: DashMap<String, CachedSignal>,
    cache_ttl: Duration,
    retry_attempts: u32,
    retry_base_delay: Duration,
    retry_jitter: Duration,
    circuit_failure_threshold: u32,
    circuit_open_duration: Duration,
}

impl OpenAiModerationProvider {
    pub fn new(
        api_key: String,
        model: String,
        connect_timeout: Duration,
        request_timeout: Duration,
        concurrency: usize,
        external_images: bool,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self::build_with_transport(
            Arc::new(HttpModerationTransport {
                client,
                endpoint: "https://api.openai.com/v1/moderations".to_owned(),
                api_key,
            }),
            model,
            concurrency,
            external_images,
            Duration::from_secs(3600),
            3,
            Duration::from_millis(100),
            Duration::from_millis(75),
            5,
            Duration::from_secs(30),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_with_transport(
        transport: Arc<dyn ModerationTransport>,
        model: String,
        concurrency: usize,
        external_images: bool,
        cache_ttl: Duration,
        retry_attempts: u32,
        retry_base_delay: Duration,
        retry_jitter: Duration,
        circuit_failure_threshold: u32,
        circuit_open_duration: Duration,
    ) -> Self {
        Self {
            transport,
            model,
            external_images,
            concurrency: Arc::new(Semaphore::new(concurrency.max(1))),
            circuit: Mutex::new(CircuitState::default()),
            cache: DashMap::new(),
            cache_ttl,
            retry_attempts: retry_attempts.max(1),
            retry_base_delay,
            retry_jitter,
            circuit_failure_threshold: circuit_failure_threshold.max(1),
            circuit_open_duration,
        }
    }

    async fn request(
        &self,
        content: Option<&str>,
        image_urls: &[String],
    ) -> Result<OpenAiModerationSignal, ProviderError> {
        {
            let circuit = self.circuit.lock().await;
            if circuit
                .opened_until
                .is_some_and(|until| until > Instant::now())
            {
                return Err(ProviderError::Unavailable);
            }
        }
        let _permit = self
            .concurrency
            .acquire()
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        let started = Instant::now();
        let mut last_error = ProviderError::Unavailable;
        let request = ModerationRequest {
            model: self.model.clone(),
            input: moderation_input(content, image_urls),
        };
        for attempt in 0..self.retry_attempts {
            let response = self.transport.send(&request).await;
            match response {
                Ok(response) if (200..300).contains(&response.status) => {
                    let body: ModerationResponse = match serde_json::from_slice(&response.body) {
                        Ok(body) => body,
                        Err(_) => {
                            last_error = ProviderError::Internal;
                            break;
                        }
                    };
                    let Some(result) = body.results.into_iter().next() else {
                        last_error = ProviderError::Internal;
                        break;
                    };
                    let mut circuit = self.circuit.lock().await;
                    circuit.consecutive_failures = 0;
                    circuit.opened_until = None;
                    return Ok(OpenAiModerationSignal {
                        provider_request_id: response.request_id,
                        response_id: body.id,
                        model_snapshot: body.model,
                        flagged: result.flagged,
                        categories: result.categories,
                        category_scores: result.category_scores,
                        input_modality: input_modality(content, image_urls).into(),
                        latency_millis: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        cache_hit: false,
                    });
                }
                Ok(response) if response.status == 429 => last_error = ProviderError::RateLimited,
                Ok(response) if (500..600).contains(&response.status) => {
                    last_error = ProviderError::Unavailable
                }
                Ok(_) => return Err(ProviderError::Rejected),
                Err(TransportError::Timeout) => last_error = ProviderError::Timeout,
                Err(TransportError::Unavailable) => last_error = ProviderError::Unavailable,
                Err(TransportError::InvalidResponse) => {
                    last_error = ProviderError::Internal;
                    break;
                }
            }
            if attempt + 1 < self.retry_attempts {
                let jitter = if self.retry_jitter.is_zero() {
                    Duration::ZERO
                } else {
                    Duration::from_millis(
                        rand::thread_rng().gen_range(0..=self.retry_jitter.as_millis() as u64),
                    )
                };
                let multiplier = 1u32.checked_shl(attempt.min(20)).unwrap_or(u32::MAX);
                tokio::time::sleep(self.retry_base_delay.saturating_mul(multiplier) + jitter).await;
            }
        }
        if !matches!(
            last_error,
            ProviderError::Rejected | ProviderError::InvalidInput(_)
        ) {
            let mut circuit = self.circuit.lock().await;
            circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
            if circuit.consecutive_failures >= self.circuit_failure_threshold {
                circuit.opened_until = Some(Instant::now() + self.circuit_open_duration);
            }
        }
        Err(last_error)
    }
}

fn moderation_input(content: Option<&str>, image_urls: &[String]) -> ModerationInput {
    if image_urls.is_empty() {
        return ModerationInput::Text(content.expect("validated moderation text").to_owned());
    }
    let mut parts = Vec::with_capacity(image_urls.len() + usize::from(content.is_some()));
    if let Some(content) = content {
        parts.push(ModerationInputPart::Text {
            text: content.to_owned(),
        });
    }
    parts.extend(image_urls.iter().map(|url| ModerationInputPart::ImageUrl {
        image_url: ImageUrl { url: url.clone() },
    }));
    ModerationInput::Multi(parts)
}

fn input_modality(content: Option<&str>, image_urls: &[String]) -> &'static str {
    match (content.is_some(), image_urls.is_empty()) {
        (true, true) => "text",
        (true, false) => "text+image",
        (false, false) => "image",
        (false, true) => unreachable!("moderation input was validated"),
    }
}

#[async_trait]
impl FeatureProvider for OpenAiModerationProvider {
    fn name(&self) -> &str {
        "openai.moderation"
    }
    fn version(&self) -> &str {
        &self.model
    }

    fn category(&self) -> ProviderCategory {
        ProviderCategory::Check
    }
    fn cache_policy(&self) -> ProviderCachePolicy {
        ProviderCachePolicy::ProviderManaged
    }
    fn is_external(&self) -> bool {
        true
    }

    async fn resolve(
        &self,
        action: &Action,
        configuration: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let configuration: ProviderConfiguration = serde_json::from_value(configuration.clone())
            .map_err(|_| ProviderError::InvalidInput("invalid provider configuration".into()))?;
        let content = action
            .attributes
            .get("content")
            .and_then(|value| value.as_str())
            .filter(|content| !content.is_empty());
        let image_urls = if self.external_images && configuration.external_images {
            action
                .attributes
                .get("attachment_urls")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str())
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if content.is_none() && image_urls.is_empty() {
            return Err(ProviderError::InvalidInput(
                "action has no permitted moderation input".into(),
            ));
        }
        let normalized_content = content.map(|value| value.nfkc().collect::<String>());
        let key_material = serde_json::json!({
            "model": self.model,
            "modality": input_modality(content, &image_urls),
            "content": normalized_content,
            "image_urls": image_urls,
        });
        let key = format!(
            "openai.moderation:{}",
            sha256_hex(&serde_json::to_vec(&key_material).map_err(|_| ProviderError::Internal)?)
        );
        if let Some(cached) = self.cache.get(&key)
            && cached.expires_at > Instant::now()
        {
            let mut signal = cached.signal.clone();
            signal.cache_hit = true;
            return Ok(ProviderOutput {
                value: serde_json::to_value(signal).map_err(|_| ProviderError::Internal)?,
                cache_hit: true,
                input_hash: Some(key),
            });
        }
        self.cache
            .remove_if(&key, |_, cached| cached.expires_at <= Instant::now());
        let signal = self.request(content, &image_urls).await?;
        self.cache.insert(
            key.clone(),
            CachedSignal {
                expires_at: Instant::now() + self.cache_ttl,
                signal: signal.clone(),
            },
        );
        Ok(ProviderOutput {
            value: serde_json::to_value(signal).map_err(|_| ProviderError::Internal)?,
            cache_hit: false,
            input_hash: Some(key),
        })
    }

    async fn health(&self) -> ProviderHealth {
        let circuit = self.circuit.lock().await;
        let open = circuit
            .opened_until
            .is_some_and(|until| until > Instant::now());
        ProviderHealth {
            name: self.name().into(),
            version: self.version().into(),
            healthy: !open,
            status: if open {
                "CIRCUIT_OPEN".into()
            } else {
                "READY".into()
            },
            checked_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc as StdArc, Mutex as StdMutex},
    };

    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::policy::{
        features::FeatureRegistry,
        model::{
            DataHandlingClass, ErrorBehavior, FeatureRequirement, Product, Scope, ScopeType,
            Subject,
        },
    };

    const MODEL: &str = "omni-moderation-2024-09-26";

    struct MockReply {
        result: Result<TransportResponse, TransportError>,
    }

    impl MockReply {
        fn json(status: u16, body: serde_json::Value) -> Self {
            Self {
                result: Ok(TransportResponse {
                    status,
                    body: body.to_string().into_bytes(),
                    request_id: Some("req_mock_1".into()),
                }),
            }
        }

        fn raw(status: u16, body: &str) -> Self {
            Self {
                result: Ok(TransportResponse {
                    status,
                    body: body.as_bytes().to_vec(),
                    request_id: None,
                }),
            }
        }

        fn timeout() -> Self {
            Self {
                result: Err(TransportError::Timeout),
            }
        }
    }

    #[derive(Default)]
    struct MockState {
        replies: VecDeque<MockReply>,
        bodies: Vec<serde_json::Value>,
        calls: usize,
    }

    struct MockTransport {
        state: StdArc<StdMutex<MockState>>,
    }

    impl MockTransport {
        fn new(replies: impl IntoIterator<Item = MockReply>) -> StdArc<Self> {
            StdArc::new(Self {
                state: StdArc::new(StdMutex::new(MockState {
                    replies: replies.into_iter().collect(),
                    ..MockState::default()
                })),
            })
        }

        fn calls(&self) -> usize {
            self.state.lock().unwrap().calls
        }

        fn bodies(&self) -> Vec<serde_json::Value> {
            self.state.lock().unwrap().bodies.clone()
        }
    }

    #[async_trait]
    impl ModerationTransport for MockTransport {
        async fn send(
            &self,
            request: &ModerationRequest,
        ) -> Result<TransportResponse, TransportError> {
            let mut state = self.state.lock().unwrap();
            state.calls += 1;
            state.bodies.push(serde_json::to_value(request).unwrap());
            state
                .replies
                .pop_front()
                .unwrap_or(MockReply {
                    result: Err(TransportError::Unavailable),
                })
                .result
        }
    }

    fn provider(
        transport: &StdArc<MockTransport>,
        retry_attempts: u32,
        circuit_failure_threshold: u32,
        external_images: bool,
    ) -> OpenAiModerationProvider {
        OpenAiModerationProvider::build_with_transport(
            transport.clone(),
            MODEL.into(),
            2,
            external_images,
            Duration::from_secs(60),
            retry_attempts,
            Duration::ZERO,
            Duration::ZERO,
            circuit_failure_threshold,
            Duration::from_secs(60),
        )
    }

    #[test]
    fn provider_is_a_cached_external_check() {
        let transport = MockTransport::new([]);
        let provider = provider(&transport, 1, 5, false);
        let descriptor = provider.descriptor();

        assert_eq!(descriptor.name, "openai.moderation");
        assert_eq!(descriptor.category, ProviderCategory::Check);
        assert_eq!(descriptor.cache, ProviderCachePolicy::ProviderManaged);
        assert!(descriptor.external);
    }

    fn moderation_response() -> serde_json::Value {
        serde_json::json!({
            "id": "modr_1",
            "model": MODEL,
            "results": [{
                "flagged": true,
                "categories": {"violence": true, "harassment": false},
                "category_scores": {"violence": 0.91, "harassment": 0.02}
            }]
        })
    }

    fn action(
        content: Option<&str>,
        attachment_urls: &[&str],
        data_handling: DataHandlingClass,
    ) -> Action {
        Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub-1".into(),
                product: Some(Product::Hub),
            },
            subject: Subject {
                user_id: Some("user-1".into()),
                server_id: None,
                message_id: Some("message-1".into()),
                channel_id: None,
                report_id: None,
            },
            occurred_at: Utc::now(),
            attributes: serde_json::json!({
                "content": content,
                "attachment_urls": attachment_urls,
            }),
            data_handling,
            prism_payload: None,
        }
    }

    #[test]
    fn parses_all_returned_categories_and_scores() {
        let response: ModerationResponse = serde_json::from_value(serde_json::json!({
            "id": "modr_1", "model": "omni-moderation-2024-09-26",
            "results": [{"flagged": true, "categories": {"violence": true, "harassment": false}, "category_scores": {"violence": 0.91, "harassment": 0.02}}]
        })).unwrap();
        assert_eq!(response.results[0].categories.len(), 2);
        assert_eq!(response.results[0].category_scores["violence"], 0.91);
    }

    #[tokio::test]
    async fn rejects_non_success_without_retrying_or_exposing_content() {
        let transport = MockTransport::new([MockReply::raw(400, "bad input")]);
        let provider = provider(&transport, 3, 5, false);
        let secret = "private submitted text 3e5d2a";

        let error = provider
            .resolve(
                &action(Some(secret), &[], DataHandlingClass::Sensitive),
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::Rejected));
        assert_eq!(transport.calls(), 1);
        assert!(!format!("{error:?} {error}").contains(secret));
    }

    #[tokio::test]
    async fn malformed_json_is_typed_internal_and_not_retried() {
        let transport = MockTransport::new([MockReply::raw(200, "not-json")]);
        let provider = provider(&transport, 3, 5, false);

        let error = provider
            .resolve(
                &action(Some("content"), &[], DataHandlingClass::Sensitive),
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::Internal));
        assert_eq!(transport.calls(), 1);
    }

    #[tokio::test]
    async fn timeouts_use_a_bounded_retry_budget() {
        let transport = MockTransport::new([
            MockReply::timeout(),
            MockReply::timeout(),
            MockReply::timeout(),
        ]);
        let provider = provider(&transport, 3, 5, false);

        let error = provider
            .resolve(
                &action(Some("content"), &[], DataHandlingClass::Sensitive),
                &serde_json::json!({}),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::Timeout));
        assert_eq!(transport.calls(), 3);
    }

    #[tokio::test]
    async fn retries_429_and_5xx_then_returns_typed_signal() {
        let transport = MockTransport::new([
            MockReply::raw(429, "slow down"),
            MockReply::raw(502, "upstream unavailable"),
            MockReply::json(200, moderation_response()),
        ]);
        let provider = provider(&transport, 3, 5, false);

        let output = provider
            .resolve(
                &action(Some("content"), &[], DataHandlingClass::Sensitive),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        let signal: OpenAiModerationSignal = serde_json::from_value(output.value).unwrap();

        assert_eq!(transport.calls(), 3);
        assert!(signal.flagged);
        assert!(signal.categories["violence"]);
        assert_eq!(signal.category_scores["harassment"], 0.02);
        assert_eq!(signal.provider_request_id.as_deref(), Some("req_mock_1"));
    }

    #[tokio::test]
    async fn circuit_opens_after_configured_failed_requests() {
        let transport = MockTransport::new([
            MockReply::raw(503, "down"),
            MockReply::raw(503, "still down"),
            MockReply::json(200, moderation_response()),
        ]);
        let provider = provider(&transport, 1, 2, false);
        let action = action(Some("content"), &[], DataHandlingClass::Sensitive);

        assert!(matches!(
            provider.resolve(&action, &serde_json::json!({})).await,
            Err(ProviderError::Unavailable)
        ));
        assert!(matches!(
            provider.resolve(&action, &serde_json::json!({})).await,
            Err(ProviderError::Unavailable)
        ));
        assert!(matches!(
            provider.resolve(&action, &serde_json::json!({})).await,
            Err(ProviderError::Unavailable)
        ));

        assert_eq!(transport.calls(), 2);
        assert!(!provider.health().await.healthy);
        assert_eq!(provider.health().await.status, "CIRCUIT_OPEN");
    }

    #[tokio::test]
    async fn caches_by_model_and_input_and_records_response_snapshot() {
        let transport = MockTransport::new([MockReply::json(200, moderation_response())]);
        let provider = provider(&transport, 3, 5, false);
        let action = action(Some("content"), &[], DataHandlingClass::Sensitive);

        let first = provider
            .resolve(&action, &serde_json::json!({}))
            .await
            .unwrap();
        let second = provider
            .resolve(&action, &serde_json::json!({}))
            .await
            .unwrap();
        let first_signal: OpenAiModerationSignal = serde_json::from_value(first.value).unwrap();
        let second_signal: OpenAiModerationSignal = serde_json::from_value(second.value).unwrap();

        assert_eq!(transport.calls(), 1);
        assert_eq!(provider.version(), MODEL);
        assert_eq!(first_signal.model_snapshot, MODEL);
        assert!(!first_signal.cache_hit);
        assert!(second.cache_hit);
        assert!(second_signal.cache_hit);
        assert_eq!(first.input_hash, second.input_hash);
        assert_eq!(transport.bodies()[0]["model"], MODEL);
    }

    #[tokio::test]
    async fn images_require_both_deployment_and_policy_opt_in() {
        let transport = MockTransport::new([
            MockReply::json(200, moderation_response()),
            MockReply::json(200, moderation_response()),
            MockReply::json(200, moderation_response()),
        ]);
        let image = "https://cdn.discordapp.com/attachment.png";
        let action = action(Some("caption"), &[image], DataHandlingClass::Sensitive);

        provider(&transport, 1, 5, false)
            .resolve(&action, &serde_json::json!({"external_images": true}))
            .await
            .unwrap();
        provider(&transport, 1, 5, true)
            .resolve(&action, &serde_json::json!({"external_images": false}))
            .await
            .unwrap();
        let output = provider(&transport, 1, 5, true)
            .resolve(&action, &serde_json::json!({"external_images": true}))
            .await
            .unwrap();
        let signal: OpenAiModerationSignal = serde_json::from_value(output.value).unwrap();
        let bodies = transport.bodies();

        assert!(bodies[0]["input"].is_string());
        assert!(bodies[1]["input"].is_string());
        assert_eq!(bodies[2]["input"][0]["type"], "text");
        assert_eq!(bodies[2]["input"][1]["type"], "image_url");
        assert_eq!(bodies[2]["input"][1]["image_url"]["url"], image);
        assert_eq!(signal.input_modality, "text+image");
    }

    #[tokio::test]
    async fn local_media_remains_default_for_image_only_actions() {
        let transport = MockTransport::new([]);
        let provider = provider(&transport, 1, 5, false);

        let error = provider
            .resolve(
                &action(
                    None,
                    &["https://cdn.discordapp.com/attachment.png"],
                    DataHandlingClass::Sensitive,
                ),
                &serde_json::json!({"external_images": true}),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::InvalidInput(_)));
        assert_eq!(transport.calls(), 0);
    }

    #[tokio::test]
    async fn data_handling_gate_runs_before_external_provider() {
        let transport = MockTransport::new([MockReply::json(200, moderation_response())]);
        let registry = FeatureRegistry::default();
        registry
            .register(StdArc::new(provider(&transport, 1, 5, true)))
            .await
            .unwrap();
        let requirement = FeatureRequirement {
            name: "openai.moderation".into(),
            error_behavior: ErrorBehavior::Hold,
            deadline_ms: 500,
            maximum_data_handling: DataHandlingClass::Internal,
            configuration: serde_json::json!({"external_images": true}),
        };

        let resolved = registry
            .resolve(
                &action(
                    Some("sensitive content"),
                    &["https://cdn.discordapp.com/attachment.png"],
                    DataHandlingClass::Sensitive,
                ),
                std::slice::from_ref(&requirement),
            )
            .await;
        let value = resolved.runtime_snapshot(&[requirement]);

        assert_eq!(transport.calls(), 0);
        assert_eq!(
            value["openai.moderation"].error.as_ref().unwrap().code,
            "PROVIDER_REJECTED"
        );
    }
}
