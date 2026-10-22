use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ohttp::ClientRequest;
use tower::ServiceExt;

use oblivious_gateway::config::{
    ForwardingConfig, GenerationConfig, KemSlot, RequiredKemSlot, SeedSource,
};
use oblivious_gateway::forward::Forwarder;
use oblivious_gateway::gateway::AppState;
use oblivious_gateway::keys::KeyRing;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn completion_logs_are_debug_only_and_do_not_leak_request_content() {
    use tracing::instrument::WithSubscriber;

    let authority = spawn_target().await.to_string();
    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let config = key_config_for(&key_ring, 0);
    let app = build_app_with_forwarding(
        key_ring,
        ForwardingConfig {
            allowed_targets: vec![authority.clone()],
            ..Default::default()
        },
    );
    for level in [tracing::Level::INFO, tracing::Level::DEBUG] {
        let buffer = LogBuffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(level)
            .with_writer(move || writer.clone())
            .finish();
        async {
            for (target, method, expected) in [
                (authority.as_str(), "GET", 200),
                ("secret-host.invalid", "SECRET-METHOD", 403),
            ] {
                let (status, body) = encrypted_gateway_request(
                    app.clone(),
                    &config,
                    method,
                    "/secret-path?token=secret-query",
                    b"secret-body",
                    target,
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(decode_bhttp_response(&body).0, expected);
            }
            let response = app
                .clone()
                .oneshot(Request::post("/gateway").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        .with_subscriber(subscriber)
        .await;

        let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let entries: Vec<_> = logs
            .lines()
            .filter(|line| line.contains("gateway request completed"))
            .collect();
        if level == tracing::Level::INFO {
            assert!(entries.is_empty());
            continue;
        }
        assert_eq!(entries.len(), 3);
        for field in [
            format!("\"target_host\":\"{authority}\""),
            "\"method\":\"GET\"".to_string(),
            "\"inner_status\":200".to_string(),
            "\"outer_status\":200".to_string(),
            "\"duration_ms\":".to_string(),
            "\"outcome\":\"success\"".to_string(),
        ] {
            assert!(
                entries[0].contains(&field),
                "missing {field}: {}",
                entries[0]
            );
        }
        assert!(entries[1].contains("\"method\":\"OTHER\""));
        assert!(entries[1].contains("\"inner_status\":403"));
        assert!(!entries[1].contains("\"target_host\":"));
        assert!(entries[2].contains("\"outer_status\":400"));
        assert!(!entries[2].contains("\"inner_status\":"));
        for secret in [
            "secret-host",
            "SECRET-METHOD",
            "secret-path",
            "secret-query",
            "secret-body",
            "secret-header",
        ] {
            assert!(!entries.join("\n").contains(secret), "leaked {secret}");
        }
    }
}

fn test_generations() -> Vec<GenerationConfig> {
    vec![GenerationConfig {
        x25519: RequiredKemSlot { key_id: 0 },
        xwing: KemSlot { key_id: Some(1) },
        advertise: true,
        seed: SeedSource::Hex(SEED_HEX.to_string()),
    }]
}

async fn spawn_target() -> SocketAddr {
    use axum::Router;
    use axum::routing::any;

    let app = Router::new().fallback(any(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn build_app_with_forwarding(key_ring: KeyRing, forwarding: ForwardingConfig) -> axum::Router {
    let forwarder = Forwarder::new(&forwarding, false);
    let state = Arc::new(AppState {
        key_ring,
        forwarder,
    });
    oblivious_gateway::build_router(state)
}

async fn encrypted_gateway_request(
    app: axum::Router,
    key_config_bytes: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    authority: &str,
) -> (StatusCode, Vec<u8>) {
    let mut bhttp_msg = bhttp::Message::request(
        method.as_bytes().to_vec(),
        b"http".to_vec(),
        authority.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    );
    bhttp_msg.write_content(body);
    bhttp_msg.put_header(b"authorization".to_vec(), b"Bearer secret-header".to_vec());
    encrypted_binary_gateway_request(app, key_config_bytes, &bhttp_msg).await
}

async fn encrypted_binary_gateway_request(
    app: axum::Router,
    key_config_bytes: &[u8],
    bhttp_msg: &bhttp::Message,
) -> (StatusCode, Vec<u8>) {
    let client = ClientRequest::from_encoded_config(key_config_bytes).unwrap();
    let mut binary_request_bytes = Vec::new();
    bhttp_msg
        .write_bhttp(bhttp::Mode::KnownLength, &mut binary_request_bytes)
        .unwrap();

    let (enc_request, client_response) = client.encapsulate(&binary_request_bytes).unwrap();

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
