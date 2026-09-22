use std::io::Write;
use std::sync::{Arc, Mutex};

use oblivious_gateway::bhttp::BinaryHttpRequest;
use oblivious_gateway::config::ForwardingConfig;
use oblivious_gateway::forward::Forwarder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn forwarding_failures_log_categories_without_request_content() {
    let buffer = LogBuffer(Arc::new(Mutex::new(Vec::new())));
    let writer = buffer.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let target = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut chunk = [0; 1024];
            let count = connection.read(&mut chunk).await.unwrap();
            assert!(count > 0, "connection closed before request headers");
            request.extend_from_slice(&chunk[..count]);
        }
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
            .await
            .unwrap();
    });
    let forwarder = Forwarder::new(
        &ForwardingConfig {
            allowed_targets: vec![authority.clone()],
            rewrites: Default::default(),
        },
        false,
    );
    let request = BinaryHttpRequest {
        method: reqwest::Method::GET,
        scheme: "http".into(),
        authority: authority.clone(),
        path: "/private-account?token=secret-marker".into(),
        headers: Default::default(),
        body: vec![],
    };

    assert!(forwarder.forward(&request).await.is_err());
    target.await.unwrap();
    // The closed listener makes the second request fail while connecting.
    assert!(forwarder.forward(&request).await.is_err());

    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("reading target response body failed"));
    assert!(logs.contains("target request failed"));
    assert!(logs.contains("\"is_connect\":true"));
    for sensitive in ["private-account", "secret-marker", "http://", &authority] {
        assert!(!logs.contains(sensitive), "request content leaked: {logs}");
    }
}
