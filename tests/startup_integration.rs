use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct GatewayProcess {
    child: Child,
    _directory: tempfile::TempDir,
}

impl GatewayProcess {
    fn start(metrics_addr: SocketAddr) -> Self {
        Self::spawn(metrics_addr, "", |command| {
            command.stdout(Stdio::null());
        })
    }

    fn spawn(
        metrics_addr: SocketAddr,
        server_settings: &str,
        configure: impl FnOnce(&mut Command),
    ) -> Self {
        let server_settings = if server_settings.is_empty() {
            r#"listen_addr = "127.0.0.1:0""#
        } else {
            server_settings
        };
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("gateway.toml");
        std::fs::write(
            &config,
            format!(
                r#"
[server]
{server_settings}
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_oblivious-gateway"));
        command.arg("--config").arg(config).stderr(Stdio::null());
        configure(&mut command);
        let child = command.spawn().unwrap();
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

#[test]
fn trace_logging_omits_ohttp_secret_material() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut gateway = GatewayProcess::spawn(address, "", |command| {
        command.env("RUST_LOG", "trace").stdout(Stdio::piped());
    });
    // Without filtering, `ohttp` traces each key derivation during startup.
    let stdout = BufReader::new(gateway.child.stdout.take().unwrap());
    for line in stdout.lines() {
        let line = line.unwrap();
        assert!(!line.contains(r#""target":"ohttp"#), "{line}");
        if line.contains("listening") {
            return;
        }
    }
    panic!("gateway exited before listening");
}

#[cfg(unix)]
#[tokio::test]
async fn binary_keeps_serving_during_shutdown_delay() {
    let listen = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let metrics = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let settings = format!("listen_addr = \"{listen}\"\nshutdown_delay_seconds = 2");
    let mut gateway = GatewayProcess::spawn(metrics, &settings, |command| {
        command.stdout(Stdio::null());
    });
    // A new connection per request, as a load balancer would open.
    let healthy = || async move {
        let client = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0);
        let response = client
            .build()
            .unwrap()
            .get(format!("http://{listen}/health"))
            .send()
            .await;
        response.is_ok_and(|r| r.status().is_success())
    };
    while !healthy().await {
        assert!(
            gateway.child.try_wait().unwrap().is_none(),
            "gateway exited"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let pid = gateway.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(healthy().await, "stopped serving during the shutdown delay");

    let status = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = gateway.child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("gateway did not exit after the delay");
    assert!(status.success());
}
