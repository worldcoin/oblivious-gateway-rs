//! TOML startup configuration. Loaded once at startup; there is no hot
//! reload.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::StartupError;

/// Minimum seed length
/// (32 bytes: as many bits of entropy as an X25519 secret key).
pub const MIN_SEED_LEN: usize = 32;

fn default_gateway_path() -> String {
    "/gateway".to_string()
}
fn default_keys_path() -> String {
    "/ohttp-keys".to_string()
}
fn default_health_path() -> String {
    "/health".to_string()
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}
fn default_advertise() -> bool {
    true
}
fn default_shutdown_grace_seconds() -> u64 {
    30
}

fn validate_route_path(name: &str, path: &str) -> Result<(), StartupError> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(StartupError::Config(format!(
            "{name} must start with '/': {path:?}"
        )))
    }
}

/// The parsed contents of the TOML startup configuration file.
#[derive(Debug, Deserialize)]
pub struct FileConfig {
    /// Listener, endpoint path, and optional TLS settings.
    pub server: ServerConfig,
    /// Prometheus metrics listener. Omit to disable metrics entirely.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// Target allowlist and rewrites.
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    /// One or more key generations. At least one is required.
    pub generations: Vec<GenerationConfig>,
}

/// `[server]`: the gateway's own HTTP listener.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on, e.g. `"0.0.0.0:8080"`.
    pub listen_addr: String,
    /// Path serving `POST /gateway`. Defaults to `/gateway`.
    #[serde(default = "default_gateway_path")]
    pub gateway_path: String,
    /// Path serving `GET /ohttp-keys`. Defaults to `/ohttp-keys`.
    #[serde(default = "default_keys_path")]
    pub keys_path: String,
    /// Path serving `GET /health`. Defaults to `/health`.
    #[serde(default = "default_health_path")]
    pub health_path: String,
    /// How long to wait for in-flight requests to finish during shutdown,
    /// before forcing the process to exit. Defaults to 30 seconds.
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
    /// Optional incoming TLS configuration. Omit to serve plaintext HTTP,
    /// e.g. when TLS terminates at an upstream load balancer.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// `[server.tls]`: incoming HTTPS.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded server certificate (chain).
    pub cert_file: String,
    /// Path to the PEM-encoded server private key.
    pub key_file: String,
}

/// `[metrics]`: the separate Prometheus scrape listener.
#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    /// Address to listen on, e.g. `"127.0.0.1:9090"`. Kept separate from
    /// `server.listen_addr` so it can be bound to a different, typically
    /// non-public, interface.
    pub listen_addr: String,
    /// Scrape path. Defaults to `/metrics`.
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

/// `[forwarding]`: which targets the gateway will forward decapsulated
/// requests to, and how.
#[derive(Debug, Deserialize, Default)]
pub struct ForwardingConfig {
    /// Exact `host[:port]` allowlist, matched against the binary HTTP
    /// request's Host.
    /// Required to be non-empty unless the process is started with
    /// `--allow-any-target`.
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    /// Scheme/host rewrites applied after the allowlist check
    #[serde(default)]
    pub rewrites: std::collections::HashMap<String, RewriteTarget>,
}

/// One `[forwarding.rewrites]` entry: replace the request's scheme and
/// host with these before forwarding.
#[derive(Debug, Deserialize, Clone)]
pub struct RewriteTarget {
    /// Replacement scheme, e.g. `"https"`.
    pub scheme: String,
    /// Replacement `host[:port]`.
    pub host: String,
}

/// One `[[generations]]` entry: a Key Generation (see `GLOSSARY.md`) —
/// one X25519 key and one X-Wing key derived from a single master seed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationConfig {
    /// Required, stable X25519 Key Identifier for this generation.
    pub x25519: RequiredKemSlot,
    /// X-Wing Key Identifier settings for this generation. Omit entirely
    /// (or omit its `key_id`) to derive it from the X25519 Key Identifier
    /// — see [`GenerationConfig::xwing_key_id`].
    #[serde(default)]
    pub xwing: KemSlot,
    /// Whether this generation's public Key Configurations appear in
    /// `/ohttp-keys`. Every loaded generation can still decrypt regardless
    /// of this flag; setting it to `false` supports decrypt-only rotation.
    /// Defaults to `true`.
    #[serde(default = "default_advertise")]
    pub advertise: bool,
    /// Where this generation's master seed comes from.
    pub seed: SeedSource,
}

/// Explicit key identity, independent of generation ordering.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredKemSlot {
    /// Must be unique across all loaded keys, including decrypt-only keys.
    pub key_id: u8,
}

/// Optional X-Wing key identifier override.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KemSlot {
    /// Explicit Key Identifier override. See
    /// [`GenerationConfig::x25519_key_id`]/[`GenerationConfig::xwing_key_id`]
    /// for what happens when this is omitted.
    #[serde(default)]
    pub key_id: Option<u8>,
}

impl GenerationConfig {
    /// This generation's X25519 Key Identifier.
    ///
    /// Remains unchanged when other generations are removed or reordered.
    #[must_use]
    pub fn x25519_key_id(&self) -> u8 {
        self.x25519.key_id
    }

    /// This generation's X-Wing Key Identifier.
    ///
    /// Explicit `xwing.key_id` if set. Otherwise derived from
    /// [`Self::x25519_key_id`] by adding 128 (wrapping) — the same shape
    /// as the Go reference's own legacy-configuration formula
    /// (`(configID - 128) % 255`; see `GLOSSARY.md`), adapted to a
    /// two-argument (not fixed-pair) key model. Collisions across
    /// generations are still caught at startup, same as an explicit ID
    /// would be.
    #[must_use]
    pub fn xwing_key_id(&self) -> u8 {
        self.xwing
            .key_id
            .unwrap_or_else(|| self.x25519_key_id().wrapping_add(128))
    }
}

/// Where a generation's master seed comes from. Ordinary settings live in
/// the TOML file, but seed material may still come from an environment
/// variable or a mounted file so it need not be written to disk in the
/// configuration itself.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeedSource {
    /// Hex-encoded seed inline in the configuration file. Intended for local
    /// testing only; production seeds should use `env` or `file`.
    Hex(String),
    /// Name of an environment variable containing a hex-encoded seed.
    Env(String),
    /// Path to a file containing a hex-encoded seed (optionally with
    /// trailing whitespace/newline).
    File(String),
}

impl SeedSource {
    /// Resolve this source to the raw seed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError::Key`] if the environment variable is unset,
    /// the file can't be read, or the resolved text isn't valid hex.
    pub fn resolve(&self) -> Result<Vec<u8>, StartupError> {
        let hex_str = match self {
            Self::Hex(s) => s.clone(),
            Self::Env(name) => std::env::var(name).map_err(|_| {
                StartupError::Key(format!("environment variable {name} is not set"))
            })?,
            Self::File(path) => fs::read_to_string(path)
                .map_err(|e| StartupError::Key(format!("reading seed file {path}: {e}")))?,
        };
        let trimmed = hex_str.trim();
        hex::decode(trimmed).map_err(|e| StartupError::Key(format!("seed is not valid hex: {e}")))
    }
}

impl FileConfig {
    /// Load and validate the TOML configuration file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError::Config`] if the file can't be read or
    /// parsed, or if it fails validation (duplicate key IDs, an empty
    /// generation list, colliding endpoint paths). Returns
    /// [`StartupError::Tls`] if `[server.tls]` references a missing
    /// certificate or key file.
    pub fn load(path: &Path) -> Result<Self, StartupError> {
        let raw = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&raw)
            .map_err(|e| StartupError::Config(format!("parsing {}: {e}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), StartupError> {
        if self.generations.is_empty() {
            return Err(StartupError::Config(
                "at least one key generation is required".to_string(),
            ));
        }

        let mut seen_ids: HashSet<u8> = HashSet::new();
        for generation in &self.generations {
            let (x25519_id, xwing_id) = (generation.x25519_key_id(), generation.xwing_key_id());
            if x25519_id == xwing_id {
                return Err(StartupError::Config(format!(
                    "generation has identical x25519 and xwing key IDs ({x25519_id}); set an \
                     explicit key_id for at least one of them"
                )));
            }
            for id in [x25519_id, xwing_id] {
                if !seen_ids.insert(id) {
                    return Err(StartupError::Config(format!(
                        "duplicate key identifier {id} across generations; set an explicit \
                         key_id to resolve the conflict"
                    )));
                }
            }
        }

        let paths = [
            &self.server.gateway_path,
            &self.server.keys_path,
            &self.server.health_path,
        ];
        let unique_paths: HashSet<&String> = paths.iter().copied().collect();
        if unique_paths.len() != paths.len() {
            return Err(StartupError::Config(
                "gateway_path, keys_path and health_path must be distinct".to_string(),
            ));
        }

        validate_route_path("gateway_path", &self.server.gateway_path)?;
        validate_route_path("keys_path", &self.server.keys_path)?;
        validate_route_path("health_path", &self.server.health_path)?;
        if let Some(metrics) = &self.metrics {
            validate_route_path("metrics.path", &metrics.path)?;
        }

        if let Some(tls) = &self.server.tls {
            if !Path::new(&tls.cert_file).is_file() {
                return Err(StartupError::Tls(format!(
                    "cert_file not found: {}",
                    tls.cert_file
                )));
            }
            if !Path::new(&tls.key_file).is_file() {
                return Err(StartupError::Tls(format!(
                    "key_file not found: {}",
                    tls.key_file
                )));
            }
        }

        Ok(())
    }
}
