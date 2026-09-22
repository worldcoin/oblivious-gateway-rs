//! Error types split by the two places DESIGN.md requires distinct handling:
//! failures before decapsulation succeeds are reported as plaintext outer HTTP
//! errors, while failures after decapsulation are reported inside the
//! encrypted response with the outer HTTP status held at 200.

use thiserror::Error;

/// A failure while producing or validating the OHTTP encapsulation itself.
/// These map to a plaintext outer HTTP error.
///
/// Status codes follow RFC 9458 rather than the Go reference: an unknown
/// key identifier is a 400, per the RFC's registered `ohttp-key` problem
/// type and its own example (RFC 9458 §9.5, §5.3 Figure 7) — not the Go
/// gateway's 401. See `docs/CONTEXT.md` for the rest of the terminology
/// this project aligns to RFC 9458.
#[derive(Debug, Error)]
pub enum OuterError {
    #[error("unsupported content type")]
    InvalidContentType,
    #[error("failed to read request body")]
    InvalidContent,
    #[error("unknown key configuration")]
    ConfigMismatch,
    #[error("decapsulation failed")]
    DecapsulationFailed,
    #[error("encapsulation failed")]
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
            Self::ConfigMismatch => "config_mismatch",
            Self::DecapsulationFailed => "decapsulation_failed",
            Self::EncapsulationFailed => "encapsulation_failed",
        }
    }
}

/// A failure while handling the decapsulated inner request. These are
/// reported to the client inside the encrypted response body, with the
/// outer HTTP response remaining 200.
#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("malformed inner request")]
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
