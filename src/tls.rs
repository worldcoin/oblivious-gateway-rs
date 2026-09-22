//! Incoming TLS configuration: ordinary HTTPS, or optional direct mTLS when
//! a client CA is configured. This extends the Go reference, which only
//! offers `http.ListenAndServeTLS` with no client-certificate support.

use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::TlsConfig;
use crate::error::StartupError;

// Uses `rustls_pki_types::pem::PemObject` directly rather than the
// `rustls-pemfile` crate: RUSTSEC-2025-0134 flags rustls-pemfile as
// unmaintained and recommends this replacement, which is the code
// rustls-pemfile itself now wraps.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, StartupError> {
    let iter = CertificateDer::pem_file_iter(path)
        .map_err(|e| StartupError::Tls(format!("opening {path}: {e}")))?;
    iter.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StartupError::Tls(format!("reading certificates from {path}: {e}")))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, StartupError> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| StartupError::Tls(format!("reading private key from {path}: {e}")))
}

/// Build the incoming TLS acceptor configuration. When `client_ca_file` is
/// set, presenting a certificate signed by that CA is required to complete
/// the handshake (direct mTLS).
pub async fn build(config: &TlsConfig) -> Result<RustlsConfig, StartupError> {
    let certs = load_certs(&config.cert_file)?;
    let key = load_private_key(&config.key_file)?;

    let builder = rustls::ServerConfig::builder();

    let mut server_config = if let Some(ca_path) = &config.client_ca_file {
        let ca_certs = load_certs(ca_path)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| StartupError::Tls(format!("loading client CA: {e}")))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| StartupError::Tls(format!("building client verifier: {e}")))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| StartupError::Tls(format!("invalid server certificate/key: {e}")))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| StartupError::Tls(format!("invalid server certificate/key: {e}")))?
    };

    // axum-server does not set ALPN protocols for a manually built
    // `rustls::ServerConfig` (see its `RustlsConfig::from_config` docs).
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}
