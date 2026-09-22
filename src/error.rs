//! Error types split by the two places DESIGN.md requires distinct handling:
//! failures before decapsulation succeeds are reported as plaintext outer HTTP
//! errors, while failures after decapsulation are reported inside the
//! encrypted response (the Encapsulated Response) with the outer HTTP
//! status held at 200.

use thiserror::Error;

/// A failure that occurs before an Encapsulated Response can be produced:
/// either the plain HTTP POST carrying the Encapsulated Request was itself
/// invalid (`InvalidContentType`, `InvalidContent`), or decapsulating/
/// encapsulating the Encapsulated Request/Response failed. RFC 9458 has no
/// collective name for this bucket — it only names the two encapsulated
/// wire values, not "the POST request that carries them" — so grouping
/// them as one plaintext-outer-error type is a project convention; see
/// `docs/CONTEXT.md`'s "Outer Request/Response" entry.
///
/// Status codes follow RFC 9458 rather than the Go reference: an unknown
/// key identifier is a 400, per the RFC's registered `ohttp-key` problem
/// type and its own example (RFC 9458 §9.5, §5.3 Figure 7) — not the Go
/// gateway's 401.
#[derive(Debug, Error)]
pub enum OuterError {
    #[error("unsupported content type")]
    InvalidContentType,
    #[error("failed to read request body")]
    InvalidContent,
    /// RFC 9458 §5.1.2: "Clients MUST NOT construct a request that
    /// includes a 100-continue expectation; the Oblivious Gateway
    /// Resource MUST generate an error if a 100-continue expectation is
    /// received."
    #[error("unsupported expectation")]
    UnsupportedExpectation,
    #[error("unknown key configuration")]
    ConfigMismatch,
    #[error("failed to decapsulate the Encapsulated Request")]
    DecapsulationFailed,
    #[error("failed to encapsulate the Encapsulated Response")]
    EncapsulationFailed,
}

impl OuterError {
    /// Outer HTTP status code. Every current variant is 400; kept as a
    /// method rather than a constant so a future variant needing a
    /// different code (e.g. RFC 9458 §6.4's optional 422 for a replaced
    /// key) doesn't have to change every call site.
    #[must_use]
    pub fn status(&self) -> u16 {
        400
    }

    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::InvalidContentType => "invalid_content_type",
            Self::InvalidContent => "invalid_content",
            Self::UnsupportedExpectation => "unsupported_expectation",
            Self::ConfigMismatch => "config_mismatch",
            Self::DecapsulationFailed => "decapsulation_failed",
            Self::EncapsulationFailed => "encapsulation_failed",
        }
    }
}

/// A failure while handling the decapsulated binary HTTP request. These are
/// reported to the client inside the encrypted response body, with the
/// outer HTTP response remaining 200.
#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("malformed binary HTTP request")]
    Malformed,
    #[error("target forbidden")]
    Forbidden,
    #[error("target request failed")]
    TargetFailed,
}

impl PayloadError {
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::Malformed => 400,
            Self::Forbidden => 403,
            Self::TargetFailed => 500,
        }
    }

    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Malformed => "content_decode_failed",
            Self::Forbidden => "request_forbidden",
            Self::TargetFailed => "request_failed",
        }
    }
}

/// Startup-time configuration or key-material errors. These abort the
/// process before it starts serving traffic.
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("key material error: {0}")]
    Key(String),
    #[error("TLS configuration error: {0}")]
    Tls(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
