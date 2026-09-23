//! Prometheus metrics via the `metrics` facade, served on a separate,
//! independently configurable listener.
//!
//! Labels are kept low-cardinality and free of request content: route,
//! outcome, status class, KEM and key ID (0-255, so bounded) only. No URLs,
//! headers, bodies, seeds or client identifiers are recorded.

use std::net::SocketAddr;
use std::time::Instant;

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::error::StartupError;

async fn render(State(handle): State<PrometheusHandle>) -> String {
    handle.render()
}

/// Install the global Prometheus recorder and serve it on its own listener
/// and path. Must be called from within a Tokio runtime; the listener
/// itself is spawned as a background task and outlives this function.
///
/// # Errors
///
/// Returns [`StartupError::Config`] if `listen_addr` doesn't parse as a
/// socket address, or if installing the global Prometheus recorder fails
/// (e.g. one is already installed). Returns [`StartupError::Io`] if the
/// listener cannot bind; the recorder is not installed in that case.
pub async fn install(listen_addr: &str, path: &str) -> Result<(), StartupError> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| StartupError::Config(format!("invalid metrics listen_addr: {e}")))?;

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let handle = PrometheusBuilder::new()
        .set_buckets(&[
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
        ])
        .map_err(|e| StartupError::Config(format!("configuring histogram buckets: {e}")))?
        .install_recorder()
        .map_err(|e| StartupError::Config(format!("installing Prometheus recorder: {e}")))?;

    let app = Router::new().route(path, get(render)).with_state(handle);
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(error = %err, "metrics listener stopped");
        }
    });

    Ok(())
}

/// RAII guard that records the gateway request counter, duration histogram
/// and in-flight gauge exactly once per outer request, regardless of which
/// return path is taken. Every label is a fixed, bounded string (outcome
/// names, KEM names, key IDs 0-255): none of them carry request content.
pub struct RequestMetrics {
    route: &'static str,
    started_at: Instant,
    outcome: &'static str,
    outer_status: u16,
    kem: &'static str,
    key_id: Option<u8>,
}

impl RequestMetrics {
    /// Start timing one request to `route`, incrementing its in-flight
    /// gauge. The counters/histogram are recorded on drop.
    #[must_use]
    pub fn start(route: &'static str) -> Self {
        metrics::gauge!("ohttp_gateway_in_flight", "route" => route).increment(1.0);
        Self {
            route,
            started_at: Instant::now(),
            outcome: "unknown",
            outer_status: 0,
            kem: "unknown",
            key_id: None,
        }
    }

    /// Record why the request ended the way it did.
    pub fn set_outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }

    /// Record which KEM the request's key used.
    pub fn set_kem(&mut self, kem: &'static str) {
        self.kem = kem;
    }

    /// Record which Key Identifier the request used.
    pub fn set_key_id(&mut self, key_id: u8) {
        self.key_id = Some(key_id);
    }

    /// Record the plaintext outer HTTP status ultimately returned.
    pub fn set_outer_status(&mut self, status: u16) {
        self.outer_status = status;
    }
}

impl Drop for RequestMetrics {
    fn drop(&mut self) {
        metrics::gauge!("ohttp_gateway_in_flight", "route" => self.route).decrement(1.0);

        let outer_status = self.outer_status.to_string();
        let key_id = self
            .key_id
            .map_or_else(|| "none".to_string(), |id| id.to_string());

        metrics::counter!(
            "ohttp_gateway_requests_total",
            "route" => self.route,
            "outcome" => self.outcome,
            "outer_status" => outer_status,
            "kem" => self.kem,
            "key_id" => key_id.clone(),
        )
        .increment(1);

        metrics::histogram!(
            "ohttp_gateway_request_duration_seconds",
            "route" => self.route,
            "outcome" => self.outcome,
            "kem" => self.kem,
            "key_id" => key_id,
        )
        .record(self.started_at.elapsed().as_secs_f64());
    }
}

/// Records one upstream (target) request's duration and the encrypted
/// payload's target status class, tracked separately from the outer HTTP
/// status.
pub fn record_upstream(duration_secs: f64, outcome: &'static str) {
    metrics::histogram!("ohttp_gateway_upstream_duration_seconds", "outcome" => outcome)
        .record(duration_secs);
}

/// Record the target's response status class (`2xx`..`5xx`/`other`),
/// tracked separately from the outer HTTP status.
pub fn record_target_status(status: u16) {
    let class = match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    metrics::counter!("ohttp_gateway_target_status_total", "status_class" => class).increment(1);
}

/// Set the loaded/advertised key gauges from the current [`KeyRing`](crate::keys::KeyRing).
pub fn set_key_gauges(loaded: usize, advertised_x25519: usize, advertised_xwing: usize) {
    metrics::gauge!("ohttp_gateway_keys_loaded_total").set(loaded as f64);
    metrics::gauge!("ohttp_gateway_keys_advertised", "kem" => "x25519")
        .set(advertised_x25519 as f64);
    metrics::gauge!("ohttp_gateway_keys_advertised", "kem" => "xwing").set(advertised_xwing as f64);
}
