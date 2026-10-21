//! The `/gateway`, `/ohttp-keys` and `/health` HTTP handlers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::bhttp;
use crate::error::{OuterError, PayloadError};
use crate::forward::Forwarder;
use crate::keys::KeyRing;
use crate::metrics::RequestMetrics;

/// Shared state for the `/gateway`, `/ohttp-keys` and `/health` handlers.
pub struct AppState {
    /// Loaded/advertised keys, used to decapsulate requests and serve
    /// `/ohttp-keys`.
    pub key_ring: KeyRing,
    /// Outbound allowlist/rewrite/client used to reach the target.
    pub forwarder: Forwarder,
}

const OHTTP_REQUEST_CONTENT_TYPE: &str = "message/ohttp-req";
const OHTTP_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-res";

/// Matches axum's own default `Bytes` extractor limit (documented in
/// README.md's "Known limitations"): 2 MiB.
const MAX_ENCAPSULATED_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// Upper bound on reading the Encapsulated Request body, so a client that
/// trickles its body cannot hold a request open indefinitely. Matches the
/// outbound request timeout in `forward.rs`.
const ENCAPSULATED_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

fn is_ohttp_request_content_type(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case(OHTTP_REQUEST_CONTENT_TYPE))
}

pub(crate) async fn method_not_allowed() -> Response {
    let mut metrics = RequestMetrics::start("gateway");
    metrics.set_outcome("invalid_method");
    metrics.set_outer_status(405);
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

fn outer_error(metrics: &mut RequestMetrics, err: OuterError) -> Response {
    let status = err.status();
    metrics.set_outcome(err.outcome());
    metrics.set_outer_status(status);
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
    (code, code.canonical_reason().unwrap_or("error")).into_response()
}

/// `POST /gateway`: decapsulate the Encapsulated Request, translate the
/// enclosed binary HTTP request, forward it, translate the target's
/// response back to binary HTTP, and encapsulate it as the Encapsulated
/// Response. Errors before decapsulation succeeds are plaintext outer
/// errors; errors afterwards are carried inside the encrypted response with
/// the outer status held at 200
pub async fn gateway_handler(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let mut metrics = RequestMetrics::start("gateway");
    let (parts, body) = request.into_parts();

    // RFC 9458 §5.1's ban on 100-continue applies to the encapsulated
    // request (enforced in `bhttp::decode_request`). An outer `Expect` is
    // ordinary hop-by-hop HTTP between the relay and this gateway, so the
    // server answers it normally when the body is read.
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if !is_ohttp_request_content_type(content_type) {
        return outer_error(&mut metrics, OuterError::InvalidContentType);
    }

    let Ok(Ok(encapsulated_request)) = tokio::time::timeout(
        ENCAPSULATED_REQUEST_READ_TIMEOUT,
        to_bytes(body, MAX_ENCAPSULATED_REQUEST_BYTES),
    )
    .await
    else {
        return outer_error(&mut metrics, OuterError::InvalidContent);
    };

    let Some(&key_id) = encapsulated_request.first() else {
        return outer_error(&mut metrics, OuterError::InvalidContent);
    };

    let Some(server) = state.key_ring.server_for(key_id) else {
        return outer_error(&mut metrics, OuterError::ConfigMismatch);
    };

    metrics.set_kem(state.key_ring.kem_label(key_id));
    metrics.set_key_id(key_id);

    let (binary_request_bytes, response_context) = match server.decapsulate(&encapsulated_request) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = ?err, key_id, "OHTTP decapsulation failed");
            return outer_error(&mut metrics, OuterError::DecapsulationFailed);
        }
    };

    let binary_response_bytes =
        forward_binary_http_request(&state, &binary_request_bytes, &mut metrics).await;

    let encapsulated_response = match response_context.encapsulate(&binary_response_bytes) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = ?err, key_id, "OHTTP encapsulation failed");
            return outer_error(&mut metrics, OuterError::EncapsulationFailed);
        }
    };

    metrics.set_outer_status(200);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, OHTTP_RESPONSE_CONTENT_TYPE)],
        encapsulated_response,
    )
        .into_response()
}

/// Decode the binary HTTP request, forward it, and encode the target's
/// response as a binary HTTP response to be encapsulated. Never returns an
/// outer-visible error: all failures after decapsulation are encoded as a
/// BHTTP error response.
async fn forward_binary_http_request(
    state: &AppState,
    binary_request_bytes: &[u8],
    metrics: &mut RequestMetrics,
) -> Vec<u8> {
    let binary_request = match bhttp::decode_request(binary_request_bytes) {
        Ok(request) => request,
        Err(err) => {
            metrics.set_outcome(err.outcome());
            metrics.set_inner_status(err.status());
            return bhttp::encode_error_response(err.status(), &err.to_string());
        }
    };

    metrics.set_request_context(
        state.forwarder.target_label(&binary_request.authority),
        binary_request.method.as_str(),
    );
    let started_at = Instant::now();
    let result = state.forwarder.forward(&binary_request).await;
    let upstream_outcome = match &result {
        Ok(_) => "success",
        Err(PayloadError::Forbidden) => "forbidden",
        Err(_) => "failed",
    };
    crate::metrics::record_upstream(started_at.elapsed().as_secs_f64(), upstream_outcome);

    match result {
        Ok((status, headers, response_body)) => {
            metrics.set_outcome("success");
            metrics.set_inner_status(status);
            crate::metrics::record_target_status(status);
            bhttp::encode_response(status, &headers, &response_body)
        }
        Err(err) => {
            metrics.set_outcome(err.outcome());
            metrics.set_inner_status(err.status());
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

    // Randomized 12-36h private cache lifetime
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
/// backends.
pub async fn health_handler() -> Response {
    (StatusCode::OK, "ok").into_response()
}

#[cfg(test)]
mod tests {
    use super::is_ohttp_request_content_type;

    #[test]
    fn ohttp_request_media_type_is_case_insensitive() {
        assert!(is_ohttp_request_content_type(Some("Message/OHTTP-Req")));
        assert!(!is_ohttp_request_content_type(Some("message/ohttp-res")));
    }
}
