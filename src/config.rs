//! TOML startup configuration. Loaded once at startup; there is no hot
//! reload.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use eyre::{WrapErr, bail};
use serde::Deserialize;

/// Minimum seed length
/// (32 bytes: as many bits of entropy as an X25519 secret key).
pub const MIN_SEED_LEN: usize = 32;

fn default_advertise() -> bool {
    true
}
fn default_shutdown_grace_seconds() -> u64 {
    30
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
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to listen on, e.g. `"0.0.0.0:8080"`.
    pub listen_addr: String,
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

/// `[metrics]`: the separate Prometheus scrape listener, serving
/// `GET /metrics`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address to listen on, e.g. `"127.0.0.1:9090"`. Kept separate from
    /// `server.listen_addr` so it can be bound to a different, typically
    /// non-public, interface.
    pub listen_addr: String,
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
    /// Fails if the environment variable is unset, the file can't be read,
    /// or the resolved text isn't valid hex.
    pub fn resolve(&self) -> eyre::Result<Vec<u8>> {
        let hex_str = match self {
            Self::Hex(s) => s.clone(),
            Self::Env(name) => std::env::var(name)
                .wrap_err_with(|| format!("reading seed from environment variable {name}"))?,
            Self::File(path) => {
                fs::read_to_string(path).wrap_err_with(|| format!("reading seed file {path}"))?
            }
        };
        hex::decode(hex_str.trim()).wrap_err("seed is not valid hex")
    }
}

impl FileConfig {
    /// Load and validate the TOML configuration file at `path`.
    ///
    /// # Errors
    ///
    /// Fails if the file can't be read or parsed, or if it fails
    /// validation (duplicate key IDs, an empty generation list, or a
    /// `[server.tls]` section referencing a missing certificate or key
    /// file).
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let raw = fs::read_to_string(path)
            .wrap_err_with(|| format!("reading config file {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .wrap_err_with(|| format!("parsing config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> eyre::Result<()> {
        if self.generations.is_empty() {
            bail!("at least one key generation is required");
        }

        let mut seen_ids: HashSet<u8> = HashSet::new();
        for generation in &self.generations {
            let (x25519_id, xwing_id) = (generation.x25519_key_id(), generation.xwing_key_id());
            if x25519_id == xwing_id {
                bail!(
                    "generation has identical x25519 and xwing key IDs ({x25519_id}); set an \
                     explicit key_id for at least one of them"
                );
            }
            for id in [x25519_id, xwing_id] {
                if !seen_ids.insert(id) {
                    bail!(
                        "duplicate key identifier {id} across generations; set an explicit \
                         key_id to resolve the conflict"
                    );
                }
            }
        }

        if let Some(tls) = &self.server.tls {
            if !Path::new(&tls.cert_file).is_file() {
                bail!("TLS cert_file not found: {}", tls.cert_file);
            }
            if !Path::new(&tls.key_file).is_file() {
                bail!("TLS key_file not found: {}", tls.key_file);
            }
        }

        Ok(())
    }
}
