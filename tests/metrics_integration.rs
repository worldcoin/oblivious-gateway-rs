//! Telemetry accounting: the Prometheus scrape output must carry the
//! request counter, duration histogram and target-status metrics after a
//! request, with only bounded labels — no URLs, headers, bodies, seeds or
//! client identifiers in telemetry.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use ohttp::ClientRequest;
use tower::ServiceExt;

use oblivious_gateway::config::{ForwardingConfig, GenerationConfig, SeedSource};
use oblivious_gateway::forward::Forwarder;
use oblivious_gateway::gateway::AppState;
use oblivious_gateway::keys::KeyRing;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[tokio::test]
async fn gateway_request_updates_prometheus_counters() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let metrics_addr = reservation.local_addr().unwrap();
    drop(reservation);
    oblivious_gateway::metrics::install(&metrics_addr.to_string(), "/metrics")
        .await
        .unwrap();

    let key_ring = KeyRing::load(&[GenerationConfig {
        x25519_key_id: 0,
        xwing_key_id: 1,
        advertise: true,
        seed: SeedSource::Hex(SEED_HEX.to_string()),
    }])
    .unwrap();
    let x25519_config = {
        let configs = ohttp::KeyConfig::decode_list(key_ring.advertised_configs()).unwrap();
        configs
            .into_iter()
            .find(|c| c.encode().unwrap()[0] == 0)
            .unwrap()
            .encode()
            .unwrap()
    };

    let forwarder = Forwarder::new(
        &ForwardingConfig {
            allowed_targets: vec!["example.invalid".to_string()],
            rewrites: Default::default(),
        },
        false,
    );
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
    let app = oblivious_gateway::build_router(state, &server_config);

    // A request to a target that isn't reachable: this only exercises
    // telemetry accounting, not a successful forward.
    let client = ClientRequest::from_encoded_config(&x25519_config).unwrap();
    let bhttp_msg = bhttp::Message::request(
        b"GET".to_vec(),
        b"http".to_vec(),
        b"example.invalid".to_vec(),
        b"/".to_vec(),
    );
    let mut binary_request_bytes = Vec::new();
    bhttp_msg
        .write_bhttp(bhttp::Mode::KnownLength, &mut binary_request_bytes)
        .unwrap();
    let (enc_request, _client_response) = client.encapsulate(&binary_request_bytes).unwrap();

    let response = app
        .clone()
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
    assert_eq!(response.status(), 200);

    let wrong_method = app
        .oneshot(
            Request::builder()
                .uri("/gateway")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), 405);
    assert_eq!(wrong_method.headers()["allow"], "POST");

    let rendered = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for metric in [
        "ohttp_gateway_request_duration_seconds",
        "ohttp_gateway_upstream_duration_seconds",
    ] {
        assert!(rendered.contains(&format!("# TYPE {metric} histogram")));
        assert!(rendered.contains(&format!("{metric}_bucket{{")));
        assert!(!rendered.contains("quantile="));
    }
    let counters: Vec<_> = rendered
        .lines()
        .filter(|line| line.starts_with("ohttp_gateway_requests_total{"))
        .collect();
    assert_eq!(counters.len(), 2);
    assert!(counters.iter().all(|line| line.ends_with(" 1")));
    assert!(counters.iter().any(|line| {
        line.contains("outcome=\"invalid_method\"") && line.contains("outer_status=\"405\"")
    }));
    assert!(rendered.lines().any(|line| {
        line.starts_with("ohttp_gateway_request_duration_seconds_count{")
            && line.contains("outcome=\"invalid_method\"")
            && line.ends_with(" 1")
    }));
    assert!(
        rendered.contains("ohttp_gateway_requests_total"),
        "missing request counter:\n{rendered}"
    );
    assert!(
        rendered.contains("ohttp_gateway_request_duration_seconds"),
        "missing duration histogram:\n{rendered}"
    );
    assert!(
        rendered.contains("route=\"gateway\""),
        "missing route label:\n{rendered}"
    );
    assert!(
        rendered.contains("kem=\"x25519\""),
        "missing kem label:\n{rendered}"
    );
    assert!(
        rendered.contains("key_id=\"0\""),
        "missing key_id label:\n{rendered}"
    );

    // No request content should ever appear in telemetry.
    assert!(!rendered.contains("example.invalid"));
}
