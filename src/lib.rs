//! A standalone [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)
//! Oblivious HTTP (OHTTP) gateway.
//!
//! The gateway decapsulates an encrypted OHTTP request, translates the
//! [Binary HTTP](https://www.rfc-editor.org/rfc/rfc9292.html) message it
//! protects into an ordinary HTTP request, forwards that request to an
//! allowlisted [`Target Resource`](https://www.rfc-editor.org/rfc/rfc9458.html#name-terminology),
//! and encapsulates the response. See the repository's `README.md` for
//! operating documentation and `GLOSSARY.md` for terminology.
//!
//! # Module map
//!
//! - [`keys`]: master-seed key derivation and the decryption/advertisement
//!   [`keys::KeyRing`].
//! - [`config`]: the TOML startup configuration schema.
//! - [`gateway`]: the `/gateway`, `/ohttp-keys` and `/health` HTTP
//!   handlers, built into a [`Router`] by [`build_router`].
//! - [`bhttp`]: translation between the wire format and ordinary HTTP.
//! - [`forward`]: outbound allowlisting, rewrites, and the HTTP client
//!   used to reach the Target Resource.
//! - [`tls`]: incoming HTTPS configuration.
//! - [`metrics`]: Prometheus metrics via the `metrics` facade.
//! - [`error`]: the outer/payload error split described in `GLOSSARY.md`.
#![warn(missing_docs)]

pub mod bhttp;
pub mod config;
pub mod error;
pub mod forward;
pub mod gateway;
pub mod keys;
pub mod metrics;
pub mod tls;

use std::sync::Arc;

use axum::Router;
use axum::routing::{any, post};

use crate::config::ServerConfig;
use crate::gateway::AppState;

/// Build the gateway's router: `/gateway`, `/ohttp-keys` and `/health` at
/// their configured paths. Unknown routes fall through to axum's default
/// 404.
pub fn build_router(state: Arc<AppState>, server: &ServerConfig) -> Router {
    Router::new()
        .route(
            &server.gateway_path,
            post(gateway::gateway_handler).fallback(gateway::method_not_allowed),
        )
        .route(&server.keys_path, any(gateway::keys_handler))
        .route(&server.health_path, any(gateway::health_handler))
        .with_state(state)
}
