use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct HealthState {
    live: AtomicBool,
    ready: AtomicBool,
    evaluated: AtomicU64,
    failed: AtomicU64,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            live: AtomicBool::new(true),
            ..Self::default()
        }
    }
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
    pub fn record_evaluation(&self, success: bool) {
        self.evaluated.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub async fn serve(
    address: SocketAddr,
    state: Arc<HealthState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;
    Ok(())
}

async fn live(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    if state.live.load(Ordering::Acquire) {
        (StatusCode::OK, "live")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not live")
    }
}
async fn ready(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    if state.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}
async fn metrics(State(state): State<Arc<HealthState>>) -> String {
    format!(
        "# TYPE polarizer_evaluations_total counter\npolarizer_evaluations_total {}\n# TYPE polarizer_evaluation_failures_total counter\npolarizer_evaluation_failures_total {}\n",
        state.evaluated.load(Ordering::Relaxed),
        state.failed.load(Ordering::Relaxed),
    )
}
