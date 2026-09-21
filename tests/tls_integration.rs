//! Incoming TLS acceptance and rejection, including optional direct mTLS
//! (DESIGN.md: "Support optional incoming HTTPS ... Optional direct
//! incoming mTLS is accepted: configuring a client CA requires a verified
//! client certificate"). Uses the self-signed fixtures under
//! `tests/fixtures/tls/`, generated once for local testing only.

use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
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

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let file = std::fs::File::open(path).unwrap();
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn load_key(path: &str) -> PrivateKeyDer<'static> {
    let file = std::fs::File::open(path).unwrap();
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .unwrap()
        .unwrap()
}

async fn start_gateway_tls(tls_config: &TlsConfig) -> SocketAddr {
    let rustls_config = oblivious_gateway::tls::build(tls_config).await.unwrap();

    let key_ring =
        oblivious_gateway::keys::KeyRing::load(&[oblivious_gateway::config::GenerationConfig {
            x25519_key_id: 0,
            xwing_key_id: 1,
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

async fn attempt_handshake(
    addr: SocketAddr,
    client_identity: Option<(&str, &str)>,
) -> Result<(), String> {
    let root_verifier = Arc::new(AcceptAnyServerCert);
    let builder = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(root_verifier);

    let config = match client_identity {
        Some((cert_path, key_path)) => builder
            .with_client_auth_cert(load_certs(cert_path), load_key(key_path))
            .map_err(|e| e.to_string())?,
        None => builder.with_no_client_auth(),
    };

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
async fn plain_tls_accepts_connection_without_client_cert() {
    let tls_config = TlsConfig {
        cert_file: fixture("server-cert.pem"),
        key_file: fixture("server-key.pem"),
        client_ca_file: None,
    };
    let addr = start_gateway_tls(&tls_config).await;
    attempt_handshake(addr, None)
        .await
        .expect("plain TLS should accept a client with no certificate");
}

#[tokio::test]
async fn mtls_rejects_connection_without_client_cert() {
    let tls_config = TlsConfig {
        cert_file: fixture("server-cert.pem"),
        key_file: fixture("server-key.pem"),
        client_ca_file: Some(fixture("client-ca-cert.pem")),
    };
    let addr = start_gateway_tls(&tls_config).await;
    let result = attempt_handshake(addr, None).await;
    assert!(
        result.is_err(),
        "mTLS must reject a client presenting no certificate"
    );
}

#[tokio::test]
async fn mtls_rejects_untrusted_client_cert() {
    let tls_config = TlsConfig {
        cert_file: fixture("server-cert.pem"),
        key_file: fixture("server-key.pem"),
        client_ca_file: Some(fixture("client-ca-cert.pem")),
    };
    let addr = start_gateway_tls(&tls_config).await;
    let result = attempt_handshake(
        addr,
        Some((
            &fixture("untrusted-client-cert.pem"),
            &fixture("untrusted-client-key.pem"),
        )),
    )
    .await;
    assert!(
        result.is_err(),
        "mTLS must reject a client certificate not signed by the configured CA"
    );
}

#[tokio::test]
async fn mtls_accepts_trusted_client_cert() {
    let tls_config = TlsConfig {
        cert_file: fixture("server-cert.pem"),
        key_file: fixture("server-key.pem"),
        client_ca_file: Some(fixture("client-ca-cert.pem")),
    };
    let addr = start_gateway_tls(&tls_config).await;
    attempt_handshake(
        addr,
        Some((&fixture("client-cert.pem"), &fixture("client-key.pem"))),
    )
    .await
    .expect("mTLS should accept a client certificate signed by the configured CA");
}
