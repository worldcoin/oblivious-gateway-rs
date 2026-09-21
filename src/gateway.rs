//! The `/gateway`, `/ohttp-keys` and `/health` HTTP handlers.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::bhttp;
use crate::error::{OuterError, PayloadError};
use crate::forward::Forwarder;
use crate::keys::KeyRing;
use crate::metrics::RequestMetrics;

pub struct AppState {
    pub key_ring: KeyRing,
    pub forwarder: Forwarder,
}

const OHTTP_REQUEST_CONTENT_TYPE: &str = "message/ohttp-req";
const OHTTP_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-res";

fn outer_error(metrics: &mut RequestMetrics, err: OuterError) -> Response {
    let status = err.status();
    metrics.set_outcome(err.outcome());
    metrics.set_outer_status(status);
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    (code, code.canonical_reason().unwrap_or("error")).into_response()
}

/// `POST /gateway`: decapsulate, translate BHTTP, forward, translate back
/// and encapsulate. Errors before decapsulation succeeds are plaintext outer
/// errors; errors afterwards are carried inside the encrypted response with
/// the outer status held at 200 (DESIGN.md, matching the Go reference).
pub async fn gateway_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut metrics = RequestMetrics::start("gateway");

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if content_type != Some(OHTTP_REQUEST_CONTENT_TYPE) {
        return outer_error(&mut metrics, OuterError::InvalidContentType);
    }

    let Some(&key_id) = body.first() else {
        return outer_error(&mut metrics, OuterError::InvalidContent);
    };

    let Some(server) = state.key_ring.server_for(key_id) else {
        return outer_error(&mut metrics, OuterError::ConfigMismatch);
    };
    metrics.set_kem(state.key_ring.kem_label(key_id));

    let (request_bytes, response_context) = match server.decapsulate(&body) {
        Ok(v) => v,
        Err(_) => return outer_error(&mut metrics, OuterError::DecapsulationFailed),
    };

    let response_bytes = handle_inner_request(&state, &request_bytes, &mut metrics).await;

    let encapsulated = match response_context.encapsulate(&response_bytes) {
        Ok(v) => v,
        Err(_) => return outer_error(&mut metrics, OuterError::EncapsulationFailed),
    };

    metrics.set_outer_status(200);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, OHTTP_RESPONSE_CONTENT_TYPE),
            (header::CONNECTION, "keep-alive"),
        ],
        encapsulated,
    )
        .into_response()
}

/// Decode the inner BHTTP request, forward it, and encode the BHTTP
/// response bytes to be encapsulated. Never returns an outer-visible error:
/// all failures after decapsulation are encoded as a BHTTP error response.
async fn handle_inner_request(
    state: &AppState,
    request_bytes: &[u8],
    metrics: &mut RequestMetrics,
) -> Vec<u8> {
    let inner = match bhttp::decode_request(request_bytes) {
        Ok(inner) => inner,
        Err(err) => {
            metrics.set_outcome(err.outcome());
            return bhttp::encode_error_response(err.status(), &err.to_string());
        }
    };

    let started_at = Instant::now();
    let result = state.forwarder.forward(&inner).await;
    let upstream_outcome = match &result {
        Ok(_) => "success",
        Err(PayloadError::Forbidden) => "forbidden",
        Err(_) => "failed",
    };
    crate::metrics::record_upstream(started_at.elapsed().as_secs_f64(), upstream_outcome);

    match result {
        Ok((status, headers, response_body)) => {
            metrics.set_outcome("success");
            crate::metrics::record_target_status(status);
            bhttp::encode_response(status, &headers, &response_body)
        }
        Err(err) => {
            metrics.set_outcome(err.outcome());
            crate::metrics::record_target_status(err.status());
            bhttp::encode_error_response(err.status(), &err.to_string())
        }
    }
}

/// `GET /ohttp-keys`: the RFC 9458 `application/ohttp-keys` list of
/// currently advertised public key configurations.
pub async fn keys_handler(State(state): State<Arc<AppState>>) -> Response {
    let mut metrics = RequestMetrics::start("keys");
    metrics.set_outcome("success");
    metrics.set_outer_status(200);

    // Randomized 12-36h private cache lifetime, matching the Go reference.
    let max_age = 12 * 3600 + rand::random_range(0..24 * 3600);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/ohttp-keys".to_string()),
            (header::CACHE_CONTROL, format!("max-age={max_age}, private")),
        ],
        state.key_ring.advertised_configs().to_vec(),
    )
        .into_response()
}

/// `GET /health`: local liveness only. Succeeds once the process has
/// completed startup validation and key loading; it does not poll
/// backends (DESIGN.md).
pub async fn health_handler() -> Response {
    (StatusCode::OK, "ok").into_response()
}
