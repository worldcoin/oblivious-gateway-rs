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
    build_app_with(KeyRing::load(&test_generations()).unwrap(), allowed_targets)
}

fn build_app_with_forwarding(key_ring: KeyRing, forwarding: ForwardingConfig) -> axum::Router {
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

/// A target that always redirects to `landing_authority`, used to exercise
/// ADR 0002: the allowlist is checked only on the initial destination, and
/// the redirect is followed without re-validating it.
async fn spawn_redirecting_target(landing_authority: String) -> SocketAddr {
    use axum::extract::State;
    use axum::routing::any;
    use axum::Router;

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
            x25519_key_id: 0,
            xwing_key_id: 1,
            advertise: true,
            seed: SeedSource::Hex(SEED_HEX.to_string()),
        },
        GenerationConfig {
            x25519_key_id: 2,
            xwing_key_id: 3,
            advertise: false,
            seed: SeedSource::Hex(
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f".to_string(),
            ),
        },
    ];
    let key_ring = KeyRing::load(&generations).unwrap();
    assert_eq!(key_ring.loaded_key_count(), 4);

    // The retired generation's key is not in the advertised list...
    let advertised = ohttp::KeyConfig::decode_list(key_ring.advertised_configs()).unwrap();
    assert_eq!(advertised.len(), 2);
    assert!(advertised.iter().all(|c| {
        let id = c.encode().unwrap()[0];
        id == 0 || id == 1
    }));

    // ...but a client that already holds its (out-of-band-distributed)
    // public config can still successfully decrypt through it.
    let mut retired_seed =
        hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
    if let Some(last) = retired_seed.last_mut() {
        *last ^= 0xFF;
    }
    let retired_config = ohttp::KeyConfig::derive(
        2,
        ohttp::hpke::Kem::X25519Sha256,
        vec![ohttp::SymmetricSuite::new(
            ohttp::hpke::Kdf::HkdfSha256,
            ohttp::hpke::Aead::Aes128Gcm,
        )],
        &retired_seed,
    )
    .unwrap()
    .encode()
    .unwrap();

    let app = build_app_with(key_ring, vec![authority.clone()]);
    let (status, response_bytes) =
        encrypted_gateway_request(app, &retired_config, "GET", "/", b"", &authority).await;
    assert_eq!(status, StatusCode::OK);
    let (binary_status, _) = decode_bhttp_response(&response_bytes);
    assert_eq!(binary_status, 200);
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

/// RFC 9458 §5.1.2: "Clients MUST NOT construct a request that includes a
/// 100-continue expectation; the Oblivious Gateway Resource MUST generate
/// an error if a 100-continue expectation is received." This can only be
/// verified over a real connection: axum's `oneshot` test helper calls the
/// router as an in-process Tower service and never touches hyper's
/// transport layer, which is what answers "100 Continue" automatically the
/// moment a body is first polled - before application code can object.
#[tokio::test]
async fn expect_100_continue_is_rejected_without_sending_the_interim_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key_ring = KeyRing::load(&test_generations()).unwrap();
    let app = build_app_with(key_ring, vec!["example.invalid".to_string()]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = b"not real ohttp bytes but long enough to matter";
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
    // Deliberately do NOT write the body: a compliant rejection must not
    // require it, since the point is to reject before reading further.

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);

    assert!(
        response.starts_with("HTTP/1.1 400"),
        "expected an immediate 400 with no interim response, got:\n{response}"
    );
    assert!(
        !response.contains("100 Continue"),
        "must never send the 100-continue interim response:\n{response}"
    );
}
