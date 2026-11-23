use std::sync::{Arc, Mutex};
use std::time::Duration;

use oblivious_gateway::bhttp::BinaryHttpRequest;
use oblivious_gateway::config::ForwardingConfig;
use oblivious_gateway::error::PayloadError;
use oblivious_gateway::forward::Forwarder;
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn forwarder(log_forbidden_targets: bool) -> Forwarder {
    Forwarder::new(
        &ForwardingConfig {
            allowed_targets: vec!["allowed.example".to_string()],
            log_forbidden_targets,
            ..Default::default()
        },
        false,
    )
}

fn request(authority: &str) -> BinaryHttpRequest {
    BinaryHttpRequest {
        method: reqwest::Method::GET,
        scheme: "https".into(),
        authority: authority.into(),
        path: "/secret-path?token=secret-query".into(),
        headers: Default::default(),
        body: b"secret-body".to_vec(),
    }
}

/// Runs `body` under a JSON subscriber and returns the forbidden-target lines.
async fn forbidden_logs(body: impl std::future::Future<Output = ()>) -> Vec<String> {
    let buffer = LogBuffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    body.with_subscriber(subscriber).await;
    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    logs.lines()
        .filter(|line| line.contains("target forbidden by allowlist"))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn forbidden_targets_are_not_logged_by_default() {
    let forwarder = forwarder(false);
    let logs = forbidden_logs(async {
        let result = forwarder.forward(&request("probe.example")).await;
        assert!(matches!(result, Err(PayloadError::Forbidden)));
    })
    .await;
    assert!(logs.is_empty(), "{logs:?}");
}

#[tokio::test]
async fn forbidden_target_is_logged_sanitized_without_request_content() {
    let forwarder = forwarder(true);
    let long_host = "a".repeat(400);
    let logs = forbidden_logs(async {
        for authority in [
            "probe.example:8080",
            "evil\"host\n{json}",
            long_host.as_str(),
        ] {
            let result = forwarder.forward(&request(authority)).await;
            assert!(matches!(result, Err(PayloadError::Forbidden)));
        }
    })
    .await;

    assert_eq!(logs.len(), 3, "{logs:?}");
    assert!(logs[0].contains("\"level\":\"WARN\""), "{}", logs[0]);
    assert!(logs[0].contains("\"target_host\":\"probe.example:8080\""));
    assert!(logs[1].contains("\"target_host\":\"evil?host??json?\""));
    assert!(logs[2].contains(&format!("\"target_host\":\"{}\"", "a".repeat(260))));
    assert!(!logs[2].contains(&"a".repeat(261)));
    for secret in ["secret-path", "secret-query", "secret-body"] {
        assert!(!logs.join("\n").contains(secret), "leaked {secret}");
    }
}

#[tokio::test]
async fn forbidden_target_logs_are_rate_limited() {
    let forwarder = forwarder(true);
    let logs = forbidden_logs(async {
        for _ in 0..15 {
            let _ = forwarder.forward(&request("flood.example")).await;
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let _ = forwarder.forward(&request("flood.example")).await;
    })
    .await;

    assert_eq!(logs.len(), 11, "{logs:?}");
    assert!(logs[0].contains("\"suppressed\":0"));
    assert!(logs[10].contains("\"suppressed\":5"), "{}", logs[10]);
}
