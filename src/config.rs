//! TOML startup configuration (DESIGN.md: "Use a startup TOML configuration
//! file for v0"). Configuration is loaded once at startup; there is no
//! hot reload.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::StartupError;

/// Minimum seed length, matching the Go reference's `defaultSeedLength`
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

#[derive(Debug, Deserialize)]
pub struct FileConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    pub generations: Vec<GenerationConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_gateway_path")]
    pub gateway_path: String,
    #[serde(default = "default_keys_path")]
    pub keys_path: String,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
    /// When set, incoming connections must present a certificate signed by
    /// this CA (direct mTLS). This extends the Go reference, which has no
    /// client-certificate configuration.
    #[serde(default)]
    pub client_ca_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    pub listen_addr: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct ForwardingConfig {
    /// Exact `host[:port]` allowlist, matched against the binary HTTP
    /// request's Host, matching the Go reference's `req.Host` comparison.
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    /// Scheme/host rewrites applied after the allowlist check, matching the
    /// Go reference's `TARGET_REWRITES`.
    #[serde(default)]
    pub rewrites: std::collections::HashMap<String, RewriteTarget>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RewriteTarget {
    pub scheme: String,
    pub host: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerationConfig {
    pub x25519_key_id: u8,
    pub xwing_key_id: u8,
    #[serde(default = "default_advertise")]
    pub advertise: bool,
    pub seed: SeedSource,
}

/// Where a generation's master seed comes from. Ordinary settings live in
/// the TOML file, but per ADR context, seed material may still come from an
/// environment variable or a mounted file so it need not be written to disk
/// in the configuration itself.
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
            if generation.x25519_key_id == generation.xwing_key_id {
                return Err(StartupError::Config(format!(
                    "generation has identical x25519_key_id and xwing_key_id ({})",
                    generation.x25519_key_id
                )));
            }
            for id in [generation.x25519_key_id, generation.xwing_key_id] {
                if !seen_ids.insert(id) {
                    return Err(StartupError::Config(format!(
                        "duplicate key identifier {id} across generations"
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
            if let Some(ca) = &tls.client_ca_file {
                if !Path::new(ca).is_file() {
                    return Err(StartupError::Tls(format!("client_ca_file not found: {ca}")));
                }
            }
        }

        Ok(())
    }
}
