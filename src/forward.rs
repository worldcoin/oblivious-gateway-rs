//! Outbound forwarding to the Target Resource: allowlisting, scheme/host
//! rewrites, and the HTTP client used to reach the target.
//!
//! The allowlist is checked only against the initial destination; redirects
//! are followed using the HTTP client's own (finite, default) redirect
//! handling without re-validating each hop. Operators who allowlist a
//! target are trusting it to choose subsequent destinations, including
//! internal ones — see GLOSSARY.md's "Where we differ from the Go reference"
//! section.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::http::uri::{Authority, PathAndQuery};
use reqwest::{Client, Url};

use crate::bhttp::BinaryHttpRequest;
use crate::config::{ForwardingConfig, RewriteTarget};
use crate::error::PayloadError;

/// Bounded upper limits on an outbound request, so one slow or unresponsive
/// target cannot hold a connection (and its in-flight request) open
/// indefinitely. The Go reference and reqwest's own defaults have no such
/// bound; this is a deliberate departure from "use library defaults" for
/// this one setting, per the organization's mandatory bounded-remote-call
/// timeout rule. Not currently operator-configurable; only the hardcoded
/// default changes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TARGET_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn target_url(scheme: &str, authority: &str, path: &str) -> Result<Url, PayloadError> {
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(PayloadError::Malformed);
    }
    authority
        .parse::<Authority>()
        .map_err(|_| PayloadError::Malformed)?;
    if authority.contains(['@', '\\']) || !path.starts_with('/') || path.contains('#') {
        return Err(PayloadError::Malformed);
    }
    let path_and_query = path
        .parse::<PathAndQuery>()
        .map_err(|_| PayloadError::Malformed)?;
    let mut url =
        Url::parse(&format!("{scheme}://{authority}/")).map_err(|_| PayloadError::Malformed)?;

    // Set components separately: joining or concatenating an untrusted path
    // can reinterpret it as credentials or a different destination.
    url.set_path(path_and_query.path());
    url.set_query(path_and_query.query());
    Ok(url)
}

/// Forwards decapsulated binary HTTP requests to their allowlisted target.
pub struct Forwarder {
    client: Client,
    allowed_targets: Option<HashSet<String>>,
    rewrites: HashMap<String, RewriteTarget>,
    target_labels: HashMap<String, String>,
}

impl Forwarder {
    /// Build a `Forwarder` from `[forwarding]` config. `allow_any_target`
    /// (from `--allow-any-target`) disables the allowlist entirely,
    /// regardless of `config.allowed_targets`.
    ///
    /// # Panics
    ///
    /// Never in practice: the only fallible step is building a `reqwest`
    /// client with a fixed, always-valid configuration.
    #[must_use]
    pub fn new(config: &ForwardingConfig, allow_any_target: bool) -> Self {
        // Rely on the client's own default redirect policy (reqwest:
        // `Policy::limited(10)`, verified against 0.13.5 source) rather than
        // reimplementing redirect handling. Outbound HTTPS uses reqwest's
        // normal certificate validation.
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("reqwest client with default configuration cannot fail to build");

        let allowed_targets = if allow_any_target {
            None
        } else {
            Some(config.allowed_targets.iter().cloned().collect())
        };

        Self {
            client,
            allowed_targets,
            rewrites: config.rewrites.clone(),
            target_labels: config.target_labels.clone(),
        }
    }

    /// Return only an operator-configured label, never the supplied authority.
    pub fn target_label(&self, authority: &str) -> Option<&str> {
        self.target_labels.get(authority).map(String::as_str)
    }

    async fn send(&self, request: &BinaryHttpRequest) -> Result<reqwest::Response, PayloadError> {
        if let Some(allowed) = &self.allowed_targets
            && !allowed.contains(&request.authority)
        {
            return Err(PayloadError::Forbidden);
        }

        let (scheme, host) = match self.rewrites.get(&request.authority) {
            Some(rewrite) => (rewrite.scheme.clone(), rewrite.host.clone()),
            None => (
                if request.scheme.is_empty() {
                    "https".to_string()
                } else {
                    request.scheme.clone()
                },
                request.authority.clone(),
            ),
        };

        let url = target_url(&scheme, &host, &request.path)?;

        let outbound_request = self
            .client
            .request(request.method.clone(), url)
            .headers(request.headers.clone())
            .body(request.body.clone());

        outbound_request.send().await.map_err(|err| {
            tracing::warn!(
                timed_out = err.is_timeout(),
                is_connect = err.is_connect(),
                is_redirect = err.is_redirect(),
                is_request = err.is_request(),
                "target request failed"
            );
            if err.is_timeout() {
                PayloadError::TargetTimedOut
            } else {
                PayloadError::TargetFailed
            }
        })
    }

    /// Forward the binary HTTP request to its target, returning the
    /// upstream status, headers and body on success.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::Forbidden`] if the target isn't allowlisted,
    /// [`PayloadError::Malformed`] if its target components are invalid,
    /// [`PayloadError::TargetTimedOut`] if the target didn't respond in
    /// time, or [`PayloadError::TargetFailed`] if the request couldn't be
    /// sent or its response couldn't be read.
    pub async fn forward(
        &self,
        request: &BinaryHttpRequest,
    ) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>), PayloadError> {
        let mut response = self.send(request).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_TARGET_RESPONSE_BYTES as u64)
        {
            tracing::warn!("target response body exceeds limit");
            return Err(PayloadError::TargetFailed);
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|err| {
            tracing::warn!(
                timed_out = err.is_timeout(),
                is_body = err.is_body(),
                is_decode = err.is_decode(),
                "reading target response body failed"
            );
            if err.is_timeout() {
                PayloadError::TargetTimedOut
            } else {
                PayloadError::TargetFailed
            }
        })? {
            if chunk.len() > MAX_TARGET_RESPONSE_BYTES.saturating_sub(body.len()) {
                tracing::warn!("target response body exceeds limit");
                return Err(PayloadError::TargetFailed);
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, headers, body))
    }
}

#[cfg(test)]
mod tests {
    use super::{Forwarder, MAX_TARGET_RESPONSE_BYTES, target_url};
    use crate::bhttp::BinaryHttpRequest;
    use crate::config::ForwardingConfig;
    use crate::error::PayloadError;

    #[test]
    fn paths_cannot_change_the_destination() {
        for path in [
            "/ordinary",
            "//other.example/private",
            "/\\other.example/private",
            "/@other.example/private",
            "/%2f%2fother.example/private?next=http://other.example/",
        ] {
            let url = target_url("https", "allowed.example:8443", path).unwrap();
            assert_eq!(url.host_str(), Some("allowed.example"), "{path}");
            assert_eq!(url.port(), Some(8443), "{path}");
            assert!(url.username().is_empty());
        }
    }

    #[test]
    fn invalid_target_components_are_rejected() {
        for (scheme, authority, path) in [
            ("http", "allowed.example", "@127.0.0.1:8080/private"),
            ("http", "allowed.example", "http://other.example/private"),
            ("http", "allowed.example", "relative"),
            ("http", "allowed.example", "/path#fragment"),
            ("http", "allowed.example", "/path\r\nheader"),
            ("http", "user@other.example", "/"),
            ("http", "allowed.example/path", "/"),
            ("http", "allowed.example\\other.example", "/"),
            ("file", "allowed.example", "/"),
        ] {
            assert!(target_url(scheme, authority, path).is_err());
        }
    }

    #[test]
    fn target_preserves_encoded_path_query_and_ipv6_port() {
        let url = target_url("http", "[::1]:8080", "/a%2Fb?value=%2F&next=@host").unwrap();
        assert_eq!(url.as_str(), "http://[::1]:8080/a%2Fb?value=%2F&next=@host");
    }

    #[tokio::test]
    async fn rejects_target_response_larger_than_limit() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let target = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            connection
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        MAX_TARGET_RESPONSE_BYTES + 1
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let forwarder = Forwarder::new(
            &ForwardingConfig {
                target_labels: Default::default(),
                allowed_targets: vec![authority.clone()],
                rewrites: Default::default(),
            },
            false,
        );
        let request = BinaryHttpRequest {
            method: reqwest::Method::GET,
            scheme: "http".to_string(),
            authority,
            path: "/".to_string(),
            headers: Default::default(),
            body: Vec::new(),
        };

        assert!(matches!(
            forwarder.forward(&request).await,
            Err(PayloadError::TargetFailed)
        ));
        target.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_target_is_reported_as_gateway_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        // Accept the connection and hold it open without ever responding.
        let target = tokio::spawn(async move {
            let (connection, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(connection);
        });
        let forwarder = Forwarder::new(
            &ForwardingConfig {
                target_labels: Default::default(),
                allowed_targets: vec![authority.clone()],
                rewrites: Default::default(),
            },
            false,
        );
        let request = BinaryHttpRequest {
            method: reqwest::Method::GET,
            scheme: "http".to_string(),
            authority,
            path: "/".to_string(),
            headers: Default::default(),
            body: Vec::new(),
        };

        let err = forwarder.forward(&request).await.unwrap_err();
        assert!(matches!(err, PayloadError::TargetTimedOut), "{err:?}");
        assert_eq!(err.status(), 504);
        target.abort();
    }
}
