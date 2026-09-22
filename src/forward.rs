//! Outbound forwarding to the Target Resource: allowlisting, scheme/host
//! rewrites, and the HTTP client used to reach the target.
//!
//! Per `docs/adr/0002-trust-allowed-targets-to-redirect.md`, the allowlist is
//! checked only against the initial destination; redirects are followed
//! using the HTTP client's own (finite, default) redirect handling without
//! re-validating each hop. Operators who allowlist a target are trusting it
//! to choose subsequent destinations, including internal ones.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use reqwest::{Client, Method};

use crate::bhttp::InnerRequest;
use crate::config::{ForwardingConfig, RewriteTarget};
use crate::error::PayloadError;

/// Bounded upper limits on an outbound request, so one slow or unresponsive
/// target cannot hold a connection (and its in-flight request) open
/// indefinitely. The Go reference and reqwest's own defaults have no such
/// bound; this is a deliberate departure from "use library defaults" for
/// this one setting, per the organization's mandatory bounded-remote-call
/// timeout rule. Not currently operator-configurable (v0 keeps timeout
/// *configuration* deferred, per DESIGN.md); only the hardcoded default
/// changes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Forwarder {
    client: Client,
    allowed_targets: Option<HashSet<String>>,
    rewrites: HashMap<String, RewriteTarget>,
}

impl Forwarder {
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
        }
    }

    async fn send(&self, inner: &InnerRequest) -> Result<reqwest::Response, PayloadError> {
        if let Some(allowed) = &self.allowed_targets {
            if !allowed.contains(&inner.authority) {
                return Err(PayloadError::Forbidden);
            }
        }

        let (scheme, host) = match self.rewrites.get(&inner.authority) {
            Some(rewrite) => (rewrite.scheme.clone(), rewrite.host.clone()),
            None => (
                if inner.scheme.is_empty() {
                    "https".to_string()
                } else {
                    inner.scheme.clone()
                },
                inner.authority.clone(),
            ),
        };

        let url = format!("{scheme}://{host}{}", inner.path);
        let method = Method::from_bytes(inner.method.as_str().as_bytes())
            .map_err(|_| PayloadError::Malformed)?;

        let request = self
            .client
            .request(method, &url)
            .headers(inner.headers.clone())
            .body(inner.body.clone());

        request.send().await.map_err(|err| {
            tracing::warn!(
                error = %err,
                authority = %inner.authority,
                timed_out = err.is_timeout(),
                is_connect = err.is_connect(),
                "target request failed"
            );
            PayloadError::TargetFailed
        })
    }

    /// Forward the decapsulated request to its target, returning the
    /// upstream status, headers and body on success.
    pub async fn forward(
        &self,
        inner: &InnerRequest,
    ) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>), PayloadError> {
        let response = self.send(inner).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(|err| {
            tracing::warn!(error = %err, authority = %inner.authority, "reading target response body failed");
            PayloadError::TargetFailed
        })?;
        Ok((status, headers, body.to_vec()))
    }
}
