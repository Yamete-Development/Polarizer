use std::env;
use std::time::Duration;

use anyhow::{Context, Result};

/// Application configuration sourced entirely from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    // ── Redis ───────────────────────────────────────────────────────────
    /// Redis connection URI (e.g. `redis://127.0.0.1:6379`).
    pub redis_uri: String,

    /// Name of the Redis stream to consume from.
    pub stream_key: String,

    /// Consumer group name.
    pub consumer_group: String,

    /// Unique consumer name within the group (defaults to hostname).
    pub consumer_name: String,

    /// How many messages to pull per `XREADGROUP` call.
    pub batch_size: usize,

    /// Block timeout for `XREADGROUP`.
    pub block_timeout: Duration,

    // ── Pipeline ────────────────────────────────────────────────────────
    /// Path to the ONNX model file.
    pub model_path: String,

    /// Number of concurrent worker tasks.
    pub worker_count: usize,

    /// Maximum allowed download size in bytes (defense against oversized payloads).
    pub max_download_bytes: u64,

    /// Redis key prefix for pHash cache entries.
    pub phash_prefix: String,

    /// Redis key prefix for URL cache entries.
    pub url_prefix: String,

    /// Redis key prefix for XXH3 byte hash cache entries.
    pub xxh3_prefix: String,

    /// TTL for cached pHash → score mappings.
    pub phash_cache_ttl: Duration,

    /// Redis stream key to push results into.
    pub result_stream_key: String,

    /// Redis stream key for CloudEvents (inter-service event bus).
    pub events_stream_key: String,

    /// Approximate MAXLEN for the events stream.
    pub events_stream_maxlen: usize,

    // ── Model / Inference ───────────────────────────────────────────────
    /// ONNX input tensor name (must match the model's expected input).
    pub model_input_name: String,

    /// Image size the model expects (both width and height — models use square inputs).
    pub model_image_size: u32,

    /// Per-channel mean for image normalization, comma-separated (e.g. "0.5,0.5,0.5").
    pub model_image_mean: [f32; 3],

    /// Per-channel std for image normalization, comma-separated (e.g. "0.5,0.5,0.5").
    pub model_image_std: [f32; 3],

    /// Comma-separated label names matching the model's output indices.
    /// Used for human-readable output (e.g. "nsfw,normal").
    pub model_labels: Vec<String>,

    /// Number of ONNX Runtime intra-op threads (parallelism within a single operator).
    pub model_intra_threads: usize,

    // ── Health ──────────────────────────────────────────────────────────
    /// Port for the health / readiness HTTP server.
    pub health_port: u16,

    // ── Logging ─────────────────────────────────────────────────────────
    /// `tracing` env-filter directive (e.g. `info`, `polarizer=debug`).
    pub log_level: String,
}

impl AppConfig {
    /// Build config from environment variables, applying sensible defaults.
    ///
    /// Defaults are tuned for [`Falconsai/nsfw_image_detection_26`](https://huggingface.co/Falconsai/nsfw_image_detection_26)
    /// with the `quantized_model.onnx` variant.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            // Required
            redis_uri: required("REDIS_URI")?,
            model_path: optional("MODEL_PATH", "./quantized_model.onnx"),

            // Optional with defaults
            stream_key: optional("STREAM_KEY", "polarizer.jobs"),
            consumer_group: optional("CONSUMER_GROUP", "polarizer-workers"),
            consumer_name: optional(
                "CONSUMER_NAME",
                &hostname::get()
                    .map(|h| h.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "worker-0".into()),
            ),
            batch_size: optional("BATCH_SIZE", "10")
                .parse()
                .context("BATCH_SIZE must be a valid usize")?,
            block_timeout: Duration::from_millis(
                optional("BLOCK_TIMEOUT_MS", "5000")
                    .parse()
                    .context("BLOCK_TIMEOUT_MS must be a valid u64")?,
            ),
            worker_count: optional("WORKER_COUNT", "4")
                .parse()
                .context("WORKER_COUNT must be a valid usize")?,
            max_download_bytes: optional("MAX_DOWNLOAD_BYTES", "20971520") // 20 MiB
                .parse()
                .context("MAX_DOWNLOAD_BYTES must be a valid u64")?,
            phash_prefix: optional("PHASH_PREFIX", "phash:"),
            url_prefix: optional("URL_PREFIX", "url:"),
            xxh3_prefix: optional("XXH3_PREFIX", "xxh3:"),
            phash_cache_ttl: Duration::from_secs(
                optional("PHASH_CACHE_TTL_SECS", "604800") // 7 days
                    .parse()
                    .context("PHASH_CACHE_TTL_SECS must be a valid u64")?,
            ),
            result_stream_key: optional("RESULT_STREAM_KEY", "polarizer.results"),
            events_stream_key: optional("EVENTS_STREAM_KEY", "events.polarizer"),
            events_stream_maxlen: optional("EVENTS_STREAM_MAXLEN", "100000")
                .parse()
                .context("EVENTS_STREAM_MAXLEN must be a valid usize")?,

            // Model / inference knobs
            model_input_name: optional("MODEL_INPUT_NAME", "pixel_values"),
            model_image_size: optional("MODEL_IMAGE_SIZE", "224")
                .parse()
                .context("MODEL_IMAGE_SIZE must be a valid u32")?,
            model_image_mean: parse_f32_triple(&optional("MODEL_IMAGE_MEAN", "0.5,0.5,0.5"))
                .context(
                    "MODEL_IMAGE_MEAN must be three comma-separated floats (e.g. 0.5,0.5,0.5)",
                )?,
            model_image_std: parse_f32_triple(&optional("MODEL_IMAGE_STD", "0.5,0.5,0.5"))
                .context(
                    "MODEL_IMAGE_STD must be three comma-separated floats (e.g. 0.5,0.5,0.5)",
                )?,
            model_labels: optional("MODEL_LABELS", "nsfw,normal")
                .split(',')
                .map(|s| s.trim().to_owned())
                .collect(),
            model_intra_threads: optional("MODEL_INTRA_THREADS", "4")
                .parse()
                .context("MODEL_INTRA_THREADS must be a valid usize")?,

            health_port: optional("HEALTH_PORT", "9090")
                .parse()
                .context("HEALTH_PORT must be a valid u16")?,
            log_level: optional("LOG_LEVEL", "info,ort=warn"),
        })
    }
}

fn required(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("missing required environment variable: {key}"))
}

fn optional(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Parse a comma-separated triple of floats (e.g. "0.5,0.5,0.5") into `[f32; 3]`.
fn parse_f32_triple(s: &str) -> Result<[f32; 3]> {
    let parts: Vec<f32> = s
        .split(',')
        .map(|p| p.trim().parse::<f32>())
        .collect::<Result<Vec<_>, _>>()
        .context("each value must be a valid float")?;

    anyhow::ensure!(
        parts.len() == 3,
        "expected exactly 3 values, got {}",
        parts.len()
    );
    Ok([parts[0], parts[1], parts[2]])
}
