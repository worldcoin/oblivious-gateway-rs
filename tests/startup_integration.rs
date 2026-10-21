use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct GatewayProcess {
    child: Child,
    _directory: tempfile::TempDir,
}

impl GatewayProcess {
    fn start(metrics_addr: SocketAddr) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("gateway.toml");
        std::fs::write(
            &config,
            format!(
                r#"
[server]
listen_addr = "127.0.0.1:0"
[metrics]
listen_addr = "{metrics_addr}"
[forwarding]
allowed_targets = ["example.invalid"]
[[generations]]
x25519 = {{ key_id = 0 }}
xwing = {{ key_id = 1 }}
seed = {{ hex = "{}" }}
[[generations]]
x25519 = {{ key_id = 2 }}
xwing = {{ key_id = 3 }}
advertise = false
seed = {{ hex = "{}" }}
"#,
                "42".repeat(32),
                "43".repeat(32),
            ),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_oblivious-gateway"))
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            _directory: directory,
        }
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn binary_exports_key_gauges_without_gateway_requests() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut gateway = GatewayProcess::start(address);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                gateway.child.try_wait().unwrap().is_none(),
                "gateway exited"
            );
            if let Ok(response) = client.get(format!("http://{address}/metrics")).send().await {
                let body = response.text().await.unwrap();
                if body.contains("ohttp_gateway_keys_loaded_total 4") {
                    assert!(body.contains("ohttp_gateway_keys_advertised{kem=\"x25519\"} 1"));
                    assert!(body.contains("ohttp_gateway_keys_advertised{kem=\"xwing\"} 1"));
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("startup key gauges did not appear");
}

#[tokio::test]
async fn binary_exits_unsuccessfully_when_metrics_port_is_occupied() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut gateway = GatewayProcess::start(occupied.local_addr().unwrap());
    let status = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = gateway.child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("gateway stayed alive without its configured metrics listener");
    assert!(!status.success());
}
