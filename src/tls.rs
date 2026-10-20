//! Incoming TLS configuration: ordinary HTTPS with a server certificate.
//! Matches the Go reference's `http.ListenAndServeTLS`.

use axum_server::tls_rustls::RustlsConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

use crate::config::TlsConfig;
use eyre::WrapErr;

// Uses `rustls_pki_types::pem::PemObject` directly rather than the
// `rustls-pemfile` crate: RUSTSEC-2025-0134 flags rustls-pemfile as
// unmaintained and recommends this replacement, which is the code
// rustls-pemfile itself now wraps.
fn load_certs(path: &str) -> eyre::Result<Vec<CertificateDer<'static>>> {
    let iter = CertificateDer::pem_file_iter(path)
        .wrap_err_with(|| format!("opening TLS certificate file {path}"))?;
    iter.collect::<Result<Vec<_>, _>>()
        .wrap_err_with(|| format!("reading TLS certificates from {path}"))
}

fn load_private_key(path: &str) -> eyre::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .wrap_err_with(|| format!("reading TLS private key from {path}"))
}

/// Build the incoming TLS acceptor configuration.
///
/// # Errors
///
/// Fails if the certificate or key files can't be read or parsed, or if
/// building the underlying `rustls::ServerConfig` fails.
pub fn build(config: &TlsConfig) -> eyre::Result<RustlsConfig> {
    let certs = load_certs(&config.cert_file)?;
    let key = load_private_key(&config.key_file)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .wrap_err("invalid TLS server certificate/key")?;

    // axum-server does not set ALPN protocols for a manually built
    // `rustls::ServerConfig` (see its `RustlsConfig::from_config` docs).
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}
