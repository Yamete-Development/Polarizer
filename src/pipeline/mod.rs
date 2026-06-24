mod download;
mod hasher;
mod inference;

pub use download::ImageDownloader;
pub use hasher::PerceptualHasher;
pub use inference::OnnxInference;

use reqwest::Url;
use std::sync::Arc;
use std::time::Instant;

use redis::AsyncCommands;
use tracing::{debug, instrument, warn};

use crate::config::AppConfig;
use crate::error::{PipelineError, PipelineResult};
use crate::eventbus::{self, EventBus};

/// The fully-assembled processing pipeline.
///
/// Held behind an `Arc` so it can be shared across worker tasks cheaply.
pub struct Pipeline {
    pub downloader: ImageDownloader,
    pub hasher: PerceptualHasher,
    pub inference: OnnxInference,
    pub redis: redis::aio::ConnectionManager,
    pub eventbus: Arc<dyn EventBus>,
    pub config: AppConfig,
}

/// The output of a single pipeline run.
#[derive(Debug, serde::Serialize)]
pub struct PipelineOutput {
    /// The original image URL that was processed.
    pub url: String,
    /// Fast non-cryptographic hash (XXH3_64) of the exact downloaded bytes.
    pub xxh3: String,
    /// Perceptual hash (base64-encoded).
    pub phash: String,
    /// Probability for the target label (0.0–1.0).
    pub score: f32,
    /// Human-readable label name (e.g. "nsfw").
    pub label: String,
    /// Whether the score came from the pHash cache.
    pub cache_hit: bool,
    /// Wall-clock processing time in milliseconds.
    pub elapsed_ms: u64,
}

impl Pipeline {
    /// Construct a new pipeline. This loads the ONNX model and connects to Redis.
    pub async fn new(config: &AppConfig) -> PipelineResult<Self> {
        let redis = redis::Client::open(config.redis_uri.as_str())
            .map_err(PipelineError::Redis)?
            .get_connection_manager()
            .await
            .map_err(PipelineError::Redis)?;

        let inference = OnnxInference::new(config)?;
        let downloader = ImageDownloader::new(config.max_download_bytes);
        let hasher = PerceptualHasher::new();

        let eventbus = Arc::new(eventbus::RedisEventBus::new(
            redis.clone(),
            config.events_stream_key.clone(),
            config.events_stream_maxlen,
        ));

        Ok(Self {
            downloader,
            hasher,
            inference,
            redis,
            eventbus,
            config: config.clone(),
        })
    }

    /// Execute the full pipeline for a single image URL.
    ///
    /// 1. Download → 2. Decode → 3. pHash → 4. Cache check → 5. ONNX → 6. Cache write
    #[instrument(skip(self), fields(url = %url))]
    pub async fn process(self: &Arc<Self>, url: &str) -> PipelineResult<PipelineOutput> {
        let start = Instant::now();
        let mut conn = self.redis.clone();

        // ── Step 0: Check URL cache ─────────────────────────────────────
        let normalized_url = match Url::parse(url) {
            Ok(mut parsed) => {
                parsed.set_query(None);
                parsed.to_string()
            }
            Err(_) => url.to_owned(),
        };

        let url_cache_key = format!("{}{}", self.config.url_prefix, normalized_url);
        let url_cached: Option<String> = conn.get(&url_cache_key).await.ok().flatten();

        if let Some(cached_json) = url_cached {
            let parts: Vec<&str> = cached_json.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(score) = parts[0].parse::<f32>() {
                    let label = parts[1];
                    let phash = parts[2];
                    let xxh3 = if parts.len() >= 4 { parts[3].to_owned() } else { "".to_owned() };
                    debug!(url = %normalized_url, score, label, "url cache hit — skipping entirely");
                    return Ok(PipelineOutput {
                        url: url.to_owned(),
                        xxh3,
                        phash: phash.to_owned(),
                        score,
                        label: label.to_owned(),
                        cache_hit: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // ── Step 1: Download ────────────────────────────────────────────
        let bytes = self.downloader.fetch(url).await?;

        // ── Step 2: Compute XXH3 byte hash and check cache ──────────────
        let xxh3_val = xxhash_rust::xxh3::xxh3_64(&bytes);
        let xxh3 = format!("{:016x}", xxh3_val);
        let xxh3_cache_key = format!("{}{}", self.config.xxh3_prefix, xxh3);

        let xxh3_cached: Option<String> = conn.get(&xxh3_cache_key).await.ok().flatten();

        if let Some(cached_json) = xxh3_cached {
            let parts: Vec<&str> = cached_json.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(score) = parts[0].parse::<f32>() {
                    let label = parts[1];
                    let phash = parts[2];
                    debug!(xxh3 = %xxh3, score, label, "xxh3 cache hit — skipping decode and inference");

                    let url_cache_value = format!("{}:{}:{}:{}", score, label, phash, xxh3);
                    let ttl_secs = self.config.phash_cache_ttl.as_secs();
                    let _: () = conn
                        .set_ex(&url_cache_key, &url_cache_value, ttl_secs)
                        .await
                        .unwrap_or(());

                    return Ok(PipelineOutput {
                        url: url.to_owned(),
                        xxh3,
                        phash: phash.to_owned(),
                        score,
                        label: label.to_owned(),
                        cache_hit: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // ── Step 3: Decode image ────────────────────────────────────────
        let img = image::load_from_memory(&bytes)?;
        debug!(width = img.width(), height = img.height(), "image decoded");

        // ── Step 4: Compute perceptual hash ─────────────────────────────
        let phash = self.hasher.hash(&img);
        let phash_cache_key = format!("{}{}", self.config.phash_prefix, phash);

        // ── Step 4: Check pHash cache ───────────────────────────────────
        let phash_cached: Option<String> = conn.get(&phash_cache_key).await.ok().flatten();

        if let Some(cached_json) = phash_cached {
            if let Some((score_str, label)) = cached_json.split_once(':') {
                if let Ok(score) = score_str.parse::<f32>() {
                    debug!(phash = %phash, score, label, "phash cache hit — skipping inference");

                    let ttl_secs = self.config.phash_cache_ttl.as_secs();

                    let xxh3_cache_value = format!("{}:{}:{}", score, label, phash);
                    let _: () = conn
                        .set_ex(&xxh3_cache_key, &xxh3_cache_value, ttl_secs)
                        .await
                        .unwrap_or(());

                    let url_cache_value = format!("{}:{}:{}:{}", score, label, phash, xxh3);
                    let _: () = conn
                        .set_ex(&url_cache_key, &url_cache_value, ttl_secs)
                        .await
                        .unwrap_or(());

                    return Ok(PipelineOutput {
                        url: url.to_owned(),
                        xxh3,
                        phash,
                        score,
                        label: label.to_owned(),
                        cache_hit: true,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // ── Step 5: Run ONNX inference ──────────────────────────────────
        let result = self.inference.predict(&img).await?;

        debug!(
            phash = %phash,
            score = result.score,
            label = %result.label,
            logits = ?result.logits,
            "inference complete"
        );

        // ── Step 6: Cache the result ────────────────────────────────────
        let ttl_secs = self.config.phash_cache_ttl.as_secs();

        let phash_cache_value = format!("{}:{}", result.score, result.label);
        let _: () = conn
            .set_ex(&phash_cache_key, &phash_cache_value, ttl_secs)
            .await
            .map_err(|e| {
                warn!(error = %e, key = %phash_cache_key, "failed to cache phash score");
                e
            })?;

        let xxh3_cache_value = format!("{}:{}:{}", result.score, result.label, phash);
        let _: () = conn
            .set_ex(&xxh3_cache_key, &xxh3_cache_value, ttl_secs)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, key = %xxh3_cache_key, "failed to cache xxh3 score");
            });

        let url_cache_value = format!("{}:{}:{}:{}", result.score, result.label, phash, xxh3);
        let _: () = conn
            .set_ex(&url_cache_key, &url_cache_value, ttl_secs)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, key = %url_cache_key, "failed to cache url score");
            });

        Ok(PipelineOutput {
            url: url.to_owned(),
            xxh3,
            phash,
            score: result.score,
            label: result.label,
            cache_hit: false,
            elapsed_ms: start.elapsed().as_millis() as u64,
        })
    }
}
