//! End-to-end tests against the in-process router: full OHTTP round trips
//! (X25519 and X-Wing), allowlist/forbidden-target behavior, telemetry
//! outcomes, and the `/ohttp-keys` and `/health` endpoints. No live network
//! services are used; the "target" is a local Tokio listener.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ohttp::ClientRequest;
use tower::ServiceExt;

use oblivious_gateway::config::{ForwardingConfig, GenerationConfig, SeedSource};
use oblivious_gateway::forward::Forwarder;
use oblivious_gateway::gateway::AppState;
use oblivious_gateway::keys::KeyRing;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn test_generations() -> Vec<GenerationConfig> {
    vec![GenerationConfig {
        x25519_key_id: 0,
        xwing_key_id: 1,
        advertise: true,
        seed: SeedSource::Hex(SEED_HEX.to_string()),
    }]
}

/// A minimal target server that echoes the request method/path/body back
/// as the response body and sets a hop-by-hop `Connection` header that the
/// gateway must strip.
async fn spawn_target() -> SocketAddr {
    use axum::routing::any;
    use axum::Router;

    async fn echo(req: Request<Body>) -> axum::response::Response {
        use axum::body::to_bytes;
        use axum::http::header;
        use axum::response::IntoResponse;

        let path = req.uri().path().to_string();
        let body = to_bytes(req.into_body(), usize::MAX).await.unwrap();
        let mut response = format!("{path}:{}", String::from_utf8_lossy(&body)).into_response();
        response
            .headers_mut()
            .insert(header::CONNECTION, "close".parse().unwrap());
        response
            .headers_mut()
            .insert("x-echo", "1".parse().unwrap());
        response
    }

    let app = Router::new()
        .route("/*path", any(echo))
        .route("/", any(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn build_app(allowed_targets: Vec<String>) -> axum::Router {
    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let forwarding = ForwardingConfig {
        allowed_targets,
        rewrites: Default::default(),
    };
    let forwarder = Forwarder::new(&forwarding, false);
    let state = Arc::new(AppState {
        key_ring,
        forwarder,
    });
    let server_config = oblivious_gateway::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        gateway_path: "/gateway".to_string(),
        keys_path: "/ohttp-keys".to_string(),
        health_path: "/health".to_string(),
        shutdown_grace_seconds: 1,
        tls: None,
    };
    oblivious_gateway::build_router(state, &server_config)
}

async fn encrypted_gateway_request(
    app: axum::Router,
    key_config_bytes: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    authority: &str,
) -> (StatusCode, Vec<u8>) {
    let client = ClientRequest::from_encoded_config(key_config_bytes).unwrap();
    let mut bhttp_msg = bhttp::Message::request(
        method.as_bytes().to_vec(),
        b"http".to_vec(),
        authority.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    );
    bhttp_msg.write_content(body);
    let mut inner = Vec::new();
    bhttp_msg
        .write_bhttp(bhttp::Mode::KnownLength, &mut inner)
        .unwrap();

    let (enc_request, client_response) = client.encapsulate(&inner).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway")
                .header("content-type", "message/ohttp-req")
                .body(Body::from(enc_request))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    if status != StatusCode::OK {
        return (status, body_bytes.to_vec());
    }

    let decrypted = client_response.decapsulate(&body_bytes).unwrap();
    (status, decrypted)
}

fn decode_bhttp_response(bytes: &[u8]) -> (u16, Vec<u8>) {
    let mut cursor = std::io::Cursor::new(bytes);
    let msg = bhttp::Message::read_bhttp(&mut cursor).unwrap();
    let status = msg.control().status().unwrap().code();
    (status, msg.content().to_vec())
}

fn key_config_for(key_ring: &KeyRing, key_id: u8) -> Vec<u8> {
    // Decode the advertised list and pick out the one matching key_id.
    let configs = ohttp::KeyConfig::decode_list(key_ring.advertised_configs()).unwrap();
    configs
        .into_iter()
        .find(|c| c.encode().unwrap()[0] == key_id)
        .unwrap()
        .encode()
        .unwrap()
}

#[tokio::test]
async fn allowed_target_round_trip_x25519_and_xwing() {
    let target_addr = spawn_target().await;
    let authority = target_addr.to_string();

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let x25519_config = key_config_for(&key_ring, 0);
    let xwing_config = key_config_for(&key_ring, 1);

    for (label, config_bytes) in [("x25519", x25519_config), ("xwing", xwing_config)] {
        let app = build_app(vec![authority.clone()]);
        let (status, response_bytes) =
            encrypted_gateway_request(app, &config_bytes, "GET", "/hello", b"", &authority).await;
        assert_eq!(status, StatusCode::OK, "outer status for {label}");

        let (inner_status, inner_body) = decode_bhttp_response(&response_bytes);
        assert_eq!(inner_status, 200, "inner status for {label}");
        assert_eq!(String::from_utf8_lossy(&inner_body), "/hello:");
    }
}

#[tokio::test]
async fn forbidden_target_returns_encrypted_403() {
    let target_addr = spawn_target().await;
    let authority = target_addr.to_string();

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let x25519_config = key_config_for(&key_ring, 0);

    // Allowlist a different host, so `authority` is forbidden.
    let app = build_app(vec!["other.example.invalid".to_string()]);
    let (status, response_bytes) =
        encrypted_gateway_request(app, &x25519_config, "GET", "/", b"", &authority).await;

    assert_eq!(status, StatusCode::OK, "outer status stays 200");
    let (inner_status, _) = decode_bhttp_response(&response_bytes);
    assert_eq!(inner_status, 403);
}

#[tokio::test]
async fn unknown_key_id_is_outer_error() {
    let app = build_app(vec!["example.invalid".to_string()]);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway")
                .header("content-type", "message/ohttp-req")
                .body(Body::from(vec![255u8; 64]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_content_type_is_outer_bad_request() {
    let app = build_app(vec!["example.invalid".to_string()]);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway")
                .header("content-type", "text/plain")
                .body(Body::from(vec![0u8; 4]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn keys_endpoint_returns_advertised_configs() {
    let app = build_app(vec!["example.invalid".to_string()]);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ohttp-keys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/ohttp-keys"
    );
    let cache_control = response
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(cache_control.starts_with("max-age="));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let configs = ohttp::KeyConfig::decode_list(&body).unwrap();
    assert_eq!(configs.len(), 2, "both X25519 and X-Wing are advertised");
}

#[tokio::test]
async fn health_endpoint_is_unconditionally_ok() {
    let app = build_app(vec!["example.invalid".to_string()]);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_is_404() {
    let app = build_app(vec!["example.invalid".to_string()]);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
