//! End-to-end tests against the in-process router: full OHTTP round trips
//! (X25519 and X-Wing), allowlist/forbidden-target behavior, telemetry
//! outcomes, and the `/ohttp-keys` and `/health` endpoints. No live network
//! services are used; the "target" is a local Tokio listener.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ohttp::ClientRequest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use oblivious_gateway::config::{
    ForwardingConfig, GenerationConfig, KemSlot, RequiredKemSlot, SeedSource,
};
use oblivious_gateway::forward::Forwarder;
use oblivious_gateway::gateway::AppState;
use oblivious_gateway::keys::KeyRing;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn test_generations() -> Vec<GenerationConfig> {
    vec![GenerationConfig {
        x25519: RequiredKemSlot { key_id: 0 },
        xwing: KemSlot { key_id: Some(1) },
        advertise: true,
        seed: SeedSource::Hex(SEED_HEX.to_string()),
    }]
}

/// A minimal target server that echoes the request method/path/body back
/// as the response body and sets a hop-by-hop `Connection` header that the
/// gateway must strip.
async fn spawn_target() -> SocketAddr {
    use axum::Router;
    use axum::routing::any;

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
    build_app_with(KeyRing::load(&test_generations()).unwrap(), allowed_targets)
}

fn build_app_with_forwarding(key_ring: KeyRing, forwarding: ForwardingConfig) -> axum::Router {
    let forwarder = Forwarder::new(&forwarding, false);
    let state = Arc::new(AppState {
        key_ring,
        forwarder,
    });
    oblivious_gateway::build_router(state)
}

fn build_app_with(key_ring: KeyRing, allowed_targets: Vec<String>) -> axum::Router {
    build_app_with_forwarding(
        key_ring,
        ForwardingConfig {
            allowed_targets,
            rewrites: Default::default(),
        },
    )
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

#[tokio::test]
async fn host_only_requests_use_the_same_allowlist() {
    let authority = spawn_target().await.to_string();
    let key_ring = KeyRing::load(&test_generations()).unwrap();
    for key_id in [0, 1] {
        let key_config = key_config_for(&key_ring, key_id);
        for (hosts, expected) in [
            (vec![authority.as_str()], 200),
            (vec!["forbidden.example"], 403),
            (vec![], 400),
            (vec![""], 400),
            (vec![authority.as_str(), "forbidden.example"], 400),
        ] {
            let mut message = bhttp::Message::request(
                b"GET".to_vec(),
                b"http".to_vec(),
                vec![],
                b"/host-only".to_vec(),
            );
            for host in hosts {
                message.put_header(b"Host".to_vec(), host.as_bytes().to_vec());
            }
            let (outer_status, response) = encrypted_binary_gateway_request(
                build_app(vec![authority.clone()]),
                &key_config,
                &message,
            )
            .await;
            assert_eq!(outer_status, StatusCode::OK);
            let (status, body) = decode_bhttp_response(&response);
            assert_eq!(status, expected);
            if expected == 200 {
                assert_eq!(body, b"/host-only:");
            }
        }
    }
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
async fn decoded_continue_expectation_is_rejected_without_contacting_target() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let contacts = Arc::new(AtomicUsize::new(0));
    let target_contacts = contacts.clone();
    let target = axum::Router::new().route(
        "/",
        axum::routing::post(move || {
            let contacts = target_contacts.clone();
            async move {
                contacts.fetch_add(1, Ordering::SeqCst);
                "unexpected forwarding"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move { axum::serve(listener, target).await.unwrap() });
    let key_ring = KeyRing::load(&test_generations()).unwrap();

    for key_id in [0, 1] {
        for expectations in [
            vec!["100-continue"],
            vec![" 100-CoNtInUe "],
            vec!["other, 100-continue"],
            vec!["other", "100-continue"],
        ] {
            let mut message = bhttp::Message::request(
                b"POST".to_vec(),
                b"http".to_vec(),
                authority.as_bytes().to_vec(),
                b"/".to_vec(),
            );
            for value in expectations {
                message.put_header(b"expect".to_vec(), value.as_bytes().to_vec());
            }
            message.write_content(b"already encrypted body");
            let mut encoded = Vec::new();
            message
                .write_bhttp(bhttp::Mode::KnownLength, &mut encoded)
                .unwrap();
            let client =
                ClientRequest::from_encoded_config(&key_config_for(&key_ring, key_id)).unwrap();
            let (encapsulated, context) = client.encapsulate(&encoded).unwrap();
            let response = build_app(vec![authority.clone()])
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/gateway")
                        .header("content-type", "message/ohttp-req")
                        .body(Body::from(encapsulated))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["content-type"], "message/ohttp-res");
            let encrypted = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let decoded = context.decapsulate(&encrypted).unwrap();
            let (status, body) = decode_bhttp_response(&decoded);
            assert_eq!(status, 400);
            assert_eq!(body, b"unsupported expectation");
        }
    }
    assert_eq!(contacts.load(Ordering::SeqCst), 0);
    server.abort();
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

        let (binary_status, binary_body) = decode_bhttp_response(&response_bytes);
        assert_eq!(binary_status, 200, "binary HTTP status for {label}");
        assert_eq!(String::from_utf8_lossy(&binary_body), "/hello:");
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
    let (binary_status, _) = decode_bhttp_response(&response_bytes);
    assert_eq!(binary_status, 403);
}

#[tokio::test]
async fn unknown_key_id_is_outer_error() {
    // 400, per RFC 9458 §9.5's registered `ohttp-key` problem type and its
    // own example (not the Go reference's 401).
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
        .clone()
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

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
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

/// A target that always redirects to `landing_authority`, used to exercise
/// ADR 0002: the allowlist is checked only on the initial destination, and
/// the redirect is followed without re-validating it.
async fn spawn_redirecting_target(landing_authority: String) -> SocketAddr {
    use axum::Router;
    use axum::extract::State;
    use axum::routing::any;

    async fn redirect(State(landing): State<String>) -> axum::response::Response {
        use axum::http::header;
        use axum::response::IntoResponse;

        (
            StatusCode::FOUND,
            [(header::LOCATION, format!("http://{landing}/landed"))],
        )
            .into_response()
    }

    let app = Router::new()
        .route("/*path", any(redirect))
        .route("/", any(redirect))
        .with_state(landing_authority);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn redirect_target_is_followed_without_reallowlisting() {
    let landing_addr = spawn_target().await;
    let landing_authority = landing_addr.to_string();
    let redirecting_addr = spawn_redirecting_target(landing_authority.clone()).await;
    let redirecting_authority = redirecting_addr.to_string();

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let x25519_config = key_config_for(&key_ring, 0);

    // Only the redirecting host is allowlisted; the landing host is not.
    let app = build_app(vec![redirecting_authority.clone()]);
    let (status, response_bytes) = encrypted_gateway_request(
        app,
        &x25519_config,
        "GET",
        "/start",
        b"",
        &redirecting_authority,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (binary_status, binary_body) = decode_bhttp_response(&response_bytes);
    assert_eq!(
        binary_status, 200,
        "the redirect must be followed, not blocked"
    );
    assert_eq!(String::from_utf8_lossy(&binary_body), "/landed:");
}

#[tokio::test]
async fn crafted_path_cannot_bypass_allowlist_or_override_rewrite() {
    let forbidden_target = spawn_target().await;
    let rewritten_target = spawn_target().await;
    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let authority = "allowed.example";

    for key_id in [0, 1] {
        let key_config = key_config_for(&key_ring, key_id);
        for with_rewrite in [false, true] {
            let mut rewrites = std::collections::HashMap::new();
            if with_rewrite {
                rewrites.insert(
                    authority.to_string(),
                    oblivious_gateway::config::RewriteTarget {
                        scheme: "http".to_string(),
                        host: rewritten_target.to_string(),
                    },
                );
            }
            let app = build_app_with_forwarding(
                KeyRing::load(&test_generations()).unwrap(),
                ForwardingConfig {
                    allowed_targets: vec![authority.to_string()],
                    rewrites,
                },
            );
            let (outer_status, response) = encrypted_gateway_request(
                app,
                &key_config,
                "GET",
                &format!("@{forbidden_target}/private"),
                b"",
                authority,
            )
            .await;
            assert_eq!(outer_status, StatusCode::OK);
            assert_eq!(decode_bhttp_response(&response).0, 400);
        }
    }
}

/// A client-supplied `Host` header must never reach the target verbatim:
/// the TCP destination is already locked to the allowlisted authority, but
/// forwarding an attacker-chosen `Host` on top of that connection would
/// let them request a different virtual host on a multi-tenant target than
/// the one the operator actually allowlisted.
#[tokio::test]
async fn spoofed_host_header_is_not_forwarded_to_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let captured = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = connection.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") || n == 0 {
                break;
            }
        }
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        String::from_utf8_lossy(&request).into_owned()
    });

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let key_config = key_config_for(&key_ring, 0);
    let app = build_app(vec![authority.clone()]);

    let mut message = bhttp::Message::request(
        b"GET".to_vec(),
        b"http".to_vec(),
        authority.as_bytes().to_vec(),
        b"/".to_vec(),
    );
    message.put_header(b"Host".to_vec(), b"evil-vhost.example".to_vec());
    let (outer_status, response) =
        encrypted_binary_gateway_request(app, &key_config, &message).await;
    assert_eq!(outer_status, StatusCode::OK);
    assert_eq!(decode_bhttp_response(&response).0, 200);

    let raw_request = captured.await.unwrap();
    assert!(
        !raw_request.to_ascii_lowercase().contains("evil-vhost"),
        "spoofed Host header reached the target:\n{raw_request}"
    );
    let host_line = raw_request
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .expect("request must carry a Host header");
    assert!(
        host_line.contains(&authority),
        "Host header should be the resolved target, got: {host_line}"
    );
}

#[tokio::test]
async fn rewrite_routes_request_to_configured_target() {
    let real_target = spawn_target().await;
    let real_authority = real_target.to_string();

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let x25519_config = key_config_for(&key_ring, 0);

    let mut rewrites = std::collections::HashMap::new();
    rewrites.insert(
        "public.example.invalid".to_string(),
        oblivious_gateway::config::RewriteTarget {
            scheme: "http".to_string(),
            host: real_authority.clone(),
        },
    );
    let app = build_app_with_forwarding(
        key_ring,
        ForwardingConfig {
            allowed_targets: vec!["public.example.invalid".to_string()],
            rewrites,
        },
    );

    let (status, response_bytes) = encrypted_gateway_request(
        app,
        &x25519_config,
        "GET",
        "/via-rewrite",
        b"",
        "public.example.invalid",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (binary_status, binary_body) = decode_bhttp_response(&response_bytes);
    assert_eq!(binary_status, 200);
    assert_eq!(String::from_utf8_lossy(&binary_body), "/via-rewrite:");
}

#[tokio::test]
async fn decrypt_only_generation_still_decrypts_but_is_not_advertised() {
    let target_addr = spawn_target().await;
    let authority = target_addr.to_string();

    let generations = vec![
        GenerationConfig {
            x25519: RequiredKemSlot { key_id: 0 },
            xwing: KemSlot { key_id: Some(1) },
            advertise: true,
            seed: SeedSource::Hex(SEED_HEX.to_string()),
        },
        GenerationConfig {
            x25519: RequiredKemSlot { key_id: 2 },
            xwing: KemSlot { key_id: Some(3) },
            advertise: false,
            seed: SeedSource::Hex(
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".to_string(),
            ),
        },
    ];
    let key_ring = KeyRing::load(&generations).unwrap();
    assert_eq!(key_ring.loaded_key_count(), 4);

    let advertised_x25519 = key_config_for(&key_ring, 0);
    let advertised_xwing = key_config_for(&key_ring, 1);
    let expected_advertised = ohttp::KeyConfig::encode_list(&[
        ohttp::KeyConfig::decode(&advertised_x25519).unwrap(),
        ohttp::KeyConfig::decode(&advertised_xwing).unwrap(),
    ])
    .unwrap();
    assert_eq!(key_ring.advertised_configs(), expected_advertised);

    // A client that already holds either retired public config can still
    // decrypt through it, even though neither is advertised to new clients.
    // Derive both retired configs independently, from Go's inputs: the
    // seed with its last byte flipped for X25519, and additionally its
    // second-to-last byte for X-Wing.
    let suites = || {
        vec![ohttp::SymmetricSuite::new(
            ohttp::hpke::Kdf::HkdfSha256,
            ohttp::hpke::Aead::Aes128Gcm,
        )]
    };
    let mut retired_seed =
        hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
    retired_seed[31] ^= 0xFF;
    let retired_x25519_config =
        ohttp::KeyConfig::derive(2, ohttp::hpke::Kem::X25519Sha256, suites(), &retired_seed)
            .unwrap()
            .encode()
            .unwrap();
    retired_seed[30] ^= 0xFF;
    let retired_xwing_config =
        ohttp::KeyConfig::derive(3, ohttp::hpke::Kem::XWing, suites(), &retired_seed)
            .unwrap()
            .encode()
            .unwrap();

    let app = build_app_with(key_ring, vec![authority.clone()]);
    for retired_config in [&retired_x25519_config, &retired_xwing_config] {
        let (status, response_bytes) =
            encrypted_gateway_request(app.clone(), retired_config, "GET", "/", b"", &authority)
                .await;
        assert_eq!(status, StatusCode::OK);
        let (binary_status, _) = decode_bhttp_response(&response_bytes);
        assert_eq!(binary_status, 200);
    }
}

#[tokio::test]
async fn malformed_binary_http_request_is_encrypted_400() {
    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let x25519_config = key_config_for(&key_ring, 0);
    let app = build_app_with(key_ring, vec!["example.invalid".to_string()]);

    let client = ClientRequest::from_encoded_config(&x25519_config).unwrap();
    let (enc_request, client_response) = client.encapsulate(b"not a valid bhttp message").unwrap();

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
    assert_eq!(response.status(), StatusCode::OK, "outer status stays 200");
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypted = client_response.decapsulate(&body_bytes).unwrap();
    let (binary_status, _) = decode_bhttp_response(&decrypted);
    assert_eq!(binary_status, 400);
}

/// RFC 9458 §5.1 forbids 100-continue inside the encapsulated request only.
/// An outer `Expect: 100-continue` (e.g. from a relay or curl on a large
/// body) is ordinary HTTP and must be honored. Needs a real connection:
/// `oneshot` bypasses hyper, which is what sends the interim response.
#[tokio::test]
async fn outer_expect_100_continue_is_honored() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let client = ClientRequest::from_encoded_config(&key_config_for(&key_ring, 1)).unwrap();
    let app = build_app_with(key_ring, vec!["example.invalid".to_string()]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let message = bhttp::Message::request(
        b"GET".to_vec(),
        b"https".to_vec(),
        b"not-allowed.example".to_vec(),
        b"/".to_vec(),
    );
    let mut encoded = Vec::new();
    message
        .write_bhttp(bhttp::Mode::KnownLength, &mut encoded)
        .unwrap();
    let (body, context) = client.encapsulate(&encoded).unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /gateway HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: message/ohttp-req\r\n\
         Expect: 100-continue\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // A compliant client waits for the interim response before sending.
    let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
    let mut received = vec![0; interim.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, interim);
    stream.write_all(&body).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("complete response head");
    let head = String::from_utf8_lossy(&response[..split]);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let decrypted = context.decapsulate(&response[split + 4..]).unwrap();
    let (inner_status, _) = decode_bhttp_response(&decrypted);
    assert_eq!(inner_status, 403);
}

/// A client that sends the right content type and then never finishes its
/// body must get an outer 400 once the read deadline passes, rather than
/// holding the request open indefinitely.
#[tokio::test(start_paused = true)]
async fn stalled_request_body_times_out() {
    let app = build_app(vec!["example.invalid".to_string()]);
    let never_finishes =
        futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/gateway")
                .header("content-type", "message/ohttp-req")
                .body(Body::from_stream(never_finishes))
                .unwrap(),
        ),
    )
    .await
    .expect("gateway must stop waiting for a stalled body")
    .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(start_paused = true)]
async fn admission_bounds_uploads_and_releases_capacity() {
    assert_admission_limit(128).await;
}

#[tokio::test(start_paused = true)]
async fn configured_admission_limit_above_default_is_enforced() {
    assert_admission_limit(192).await;
}

async fn assert_admission_limit(limit: usize) {
    use futures_util::{poll, stream};
    let authority = spawn_target().await.to_string();
    let app = if limit == 128 {
        build_app(vec![authority.clone()])
    } else {
        let state = Arc::new(AppState {
            key_ring: KeyRing::load(&test_generations()).unwrap(),
            forwarder: Forwarder::new(
                &ForwardingConfig {
                    allowed_targets: vec![authority.clone()],
                    rewrites: Default::default(),
                },
                false,
            ),
        });
        oblivious_gateway::build_router_with_concurrency_limit(state, limit)
    };
    let mut pending = Vec::new();
    for _ in 0..limit {
        let request = Request::builder()
            .method("POST")
            .uri("/gateway")
            .header("content-type", "message/ohttp-req")
            .body(Body::from_stream(stream::pending::<
                Result<Vec<u8>, std::io::Error>,
            >()))
            .unwrap();
        let mut response = Box::pin(app.clone().oneshot(request));
        assert!(poll!(&mut response).is_pending());
        pending.push(response);
    }
    let request = Request::builder()
        .method("POST")
        .uri("/gateway")
        .body(Body::from_stream(stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
                panic!("overload must not poll the body")
            },
        )))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for path in ["/health", "/ohttp-keys"] {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }
    let invalid = || {
        Request::builder()
            .method("POST")
            .uri("/gateway")
            .body(Body::empty())
            .unwrap()
    };
    let independent = build_app(vec!["allowed.example".to_string()]);
    assert_eq!(
        independent.oneshot(invalid()).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    drop(pending.pop());
    for _ in 0..2 {
        assert_eq!(
            app.clone().oneshot(invalid()).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    for response in pending {
        assert_eq!(response.await.unwrap().status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        app.clone().oneshot(invalid()).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    tokio::time::resume();
    let ring = KeyRing::load(&test_generations()).unwrap();
    let config = key_config_for(&ring, 0);
    let (outer, response) =
        encrypted_gateway_request(app, &config, "POST", "/control", b"ok", &authority).await;
    assert_eq!(outer, StatusCode::OK);
    assert_eq!(
        decode_bhttp_response(&response),
        (200, b"/control:ok".to_vec())
    );
}
