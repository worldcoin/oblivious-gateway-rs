pub mod bhttp;
pub mod config;
pub mod error;
pub mod forward;
pub mod gateway;
pub mod keys;
pub mod metrics;
pub mod tls;

use std::sync::Arc;

use axum::routing::{any, post};
use axum::Router;

use crate::config::ServerConfig;
use crate::gateway::AppState;

/// Build the gateway's router: `/gateway`, `/ohttp-keys` and `/health` at
/// their configured paths. Unknown routes fall through to axum's default
/// 404 (DESIGN.md).
pub fn build_router(state: Arc<AppState>, server: &ServerConfig) -> Router {
    Router::new()
        .route(&server.gateway_path, post(gateway::gateway_handler))
        .route(&server.keys_path, any(gateway::keys_handler))
        .route(&server.health_path, any(gateway::health_handler))
        .with_state(state)
}
