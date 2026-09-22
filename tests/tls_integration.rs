//! Incoming TLS acceptance. Uses the self-signed fixtures under
//! `tests/fixtures/tls/`, generated once for local testing only.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use oblivious_gateway::config::TlsConfig;
use oblivious_gateway::gateway::AppState;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/tls/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Accept whatever the server offers; this verifier only exists to
        // skip certificate-chain validation against our self-signed test
        // fixtures, not to exercise signature-scheme negotiation.
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

async fn start_gateway_tls(tls_config: &TlsConfig) -> SocketAddr {
    let rustls_config = oblivious_gateway::tls::build(tls_config).unwrap();

    let key_ring =
        oblivious_gateway::keys::KeyRing::load(&[oblivious_gateway::config::GenerationConfig {
            x25519: oblivious_gateway::config::KemSlot { key_id: Some(0) },
            xwing: oblivious_gateway::config::KemSlot { key_id: Some(1) },
            advertise: true,
            seed: oblivious_gateway::config::SeedSource::Hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string(),
            ),
        }])
        .unwrap();
    let forwarder = oblivious_gateway::forward::Forwarder::new(
        &oblivious_gateway::config::ForwardingConfig {
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

    let handle = axum_server::Handle::new();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_handle = handle.clone();
    tokio::spawn(async move {
        axum_server::bind_rustls(bind_addr, rustls_config)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    handle.listening().await.unwrap()
}

async fn attempt_handshake(addr: SocketAddr) -> Result<(), String> {
    let root_verifier = Arc::new(AcceptAnyServerCert);
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(root_verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let server_name = ServerName::try_from("localhost").unwrap();

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| e.to_string())?;

    tls_stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    tls_stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    if String::from_utf8_lossy(&response).contains("200") {
        Ok(())
    } else {
        Err("unexpected response".to_string())
    }
}

#[tokio::test]
async fn https_health_endpoint_responds() {
    let tls_config = TlsConfig {
        cert_file: fixture("server-cert.pem"),
        key_file: fixture("server-key.pem"),
    };
    let addr = start_gateway_tls(&tls_config).await;
    attempt_handshake(addr)
        .await
        .expect("HTTPS health endpoint should respond successfully");
}
