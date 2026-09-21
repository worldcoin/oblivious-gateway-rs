//! Prometheus metrics via the `metrics` facade (DESIGN.md: "Use the Rust
//! `metrics` facade with a Prometheus scrape exporter"), served on a
//! separate, independently configurable listener.
//!
//! Labels are kept low-cardinality and free of request content: route,
//! outcome, status class, KEM and key ID only. No URLs, headers, bodies,
//! seeds or client identifiers are recorded.

use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::error::StartupError;

async fn render(State(handle): State<PrometheusHandle>) -> String {
    handle.render()
}

/// Install the global Prometheus recorder and serve it on its own listener
/// and path (DESIGN.md: "Serve `/metrics` on a separate configurable
/// listener"). Must be called from within a Tokio runtime; the listener
/// itself is spawned as a background task and outlives this function.
pub fn install(listen_addr: &str, path: &str) -> Result<(), StartupError> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| StartupError::Config(format!("invalid metrics listen_addr: {e}")))?;

    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| StartupError::Config(format!("installing Prometheus recorder: {e}")))?;

    let app = Router::new().route(path, get(render)).with_state(handle);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                if let Err(err) = axum::serve(listener, app).await {
                    tracing::error!(error = %err, "metrics listener stopped");
                }
            }
            Err(err) => tracing::error!(error = %err, %addr, "failed to bind metrics listener"),
        }
    });

    Ok(())
}

/// RAII guard that records the gateway request counter, duration histogram
/// and in-flight gauge exactly once per outer request, regardless of which
/// return path is taken.
pub struct RequestMetrics {
    route: &'static str,
    started_at: Instant,
    outcome: String,
    outer_status: u16,
    kem: String,
}

impl RequestMetrics {
    pub fn start(route: &'static str) -> Self {
        metrics::gauge!("ohttp_gateway_in_flight", "route" => route).increment(1.0);
        Self {
            route,
            started_at: Instant::now(),
            outcome: "unknown".to_string(),
            outer_status: 0,
            kem: "unknown".to_string(),
        }
    }

    pub fn set_outcome(&mut self, outcome: &str) {
        self.outcome = outcome.to_string();
    }

    pub fn set_kem(&mut self, kem: &str) {
        self.kem = kem.to_string();
    }

    pub fn set_outer_status(&mut self, status: u16) {
        self.outer_status = status;
    }
}

impl Drop for RequestMetrics {
    fn drop(&mut self) {
        metrics::gauge!("ohttp_gateway_in_flight", "route" => self.route).decrement(1.0);

        let status = self.outer_status.to_string();
        metrics::counter!(
            "ohttp_gateway_requests_total",
            "route" => self.route,
            "outcome" => self.outcome.clone(),
            "outer_status" => status.clone(),
            "kem" => self.kem.clone(),
        )
        .increment(1);

        metrics::histogram!(
            "ohttp_gateway_request_duration_seconds",
            "route" => self.route,
            "outcome" => self.outcome.clone(),
            "kem" => self.kem.clone(),
        )
        .record(self.started_at.elapsed().as_secs_f64());
    }
}

/// Records one upstream (target) request's duration and the encrypted
/// payload's target status class, tracked separately from the outer HTTP
/// status per DESIGN.md.
pub fn record_upstream(duration_secs: f64, outcome: &str) {
    metrics::histogram!("ohttp_gateway_upstream_duration_seconds", "outcome" => outcome.to_string())
        .record(duration_secs);
}

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

pub fn set_key_gauges(loaded: usize, advertised_x25519: usize, advertised_xwing: usize) {
    metrics::gauge!("ohttp_gateway_keys_loaded_total").set(loaded as f64);
    metrics::gauge!("ohttp_gateway_keys_advertised", "kem" => "x25519")
        .set(advertised_x25519 as f64);
    metrics::gauge!("ohttp_gateway_keys_advertised", "kem" => "xwing").set(advertised_xwing as f64);
}
