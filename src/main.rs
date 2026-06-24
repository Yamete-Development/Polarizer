mod config;
mod error;
mod eventbus;
mod health;
mod pipeline;
mod redis_stream;
mod telemetry;

use std::sync::Arc;

use anyhow::Context as _;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::AppConfig;
use crate::health::HealthState;
use crate::pipeline::Pipeline;
use crate::redis_stream::StreamConsumer;
use crate::telemetry::init_tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present (non-fatal if missing).
    let _ = dotenvy::dotenv();

    let config = AppConfig::from_env().context("failed to load configuration")?;
    init_tracing(&config.log_level);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        workers = config.worker_count,
        "polarizer starting"
    );

    // ── Shared resources ────────────────────────────────────────────────
    let cancel = CancellationToken::new();
    let health = Arc::new(HealthState::new());

    // Build the processing pipeline (loads ONNX model, connects to Redis).
    let pipeline = Arc::new(
        Pipeline::new(&config)
            .await
            .context("failed to initialize pipeline")?,
    );

    // ── Health / readiness HTTP server ──────────────────────────────────
    let health_handle = tokio::spawn(health::serve(
        config.health_port,
        Arc::clone(&health),
        cancel.clone(),
    ));

    // ── Consumer workers ────────────────────────────────────────────────
    let consumer = StreamConsumer::new(
        Arc::clone(&pipeline),
        config.clone(),
        Arc::clone(&health),
        cancel.clone(),
    );

    // Mark service as ready once all components are initialized.
    health.set_ready(true);
    info!(port = config.health_port, "service ready");

    // ── Graceful shutdown wiring ────────────────────────────────────────
    let cancel_on_signal = cancel.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("shutdown signal received — draining workers");
        cancel_on_signal.cancel();
    });

    // Run the consumer loop until cancellation.
    if let Err(e) = consumer.run().await {
        error!(error = %e, "consumer loop exited with error");
    }

    // Wait for the health server to wind down.
    let _ = health_handle.await;

    info!("polarizer shut down cleanly");
    Ok(())
}

/// Waits for SIGINT or SIGTERM (unix) / Ctrl-C (all platforms).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
