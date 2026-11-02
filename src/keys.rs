//! Key generation loading and the decryption/advertisement key ring.
//!
//! Each generation feeds its keys the same inputs as the Go gateway: X25519
//! derives from a copy of the master seed with the final byte `XORed` with
//! `0xff`, X-Wing from a copy with the final two bytes flipped. For X25519
//! this reproduces Go's key byte-for-byte, so embedded client configurations
//! keep working when operators reuse the same seed and key identifier. For
//! X-Wing only the input matches; Go's derivation function differs (see
//! GLOSSARY.md). Both KEMs use HKDF-SHA256 + AES-128-GCM.

use std::sync::Arc;

use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, KeyId, Server, SymmetricSuite};

use crate::config::{GenerationConfig, MIN_SEED_LEN};
use eyre::{WrapErr, bail};

fn symmetric_suites() -> Vec<SymmetricSuite> {
    vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)]
}

/// Copy the seed and flip its final `count` bytes, matching the Go
/// gateway's derivation inputs: 1 for X25519, 2 for X-Wing. See module docs
/// above.
fn go_seed_transform(seed: &[u8], count: usize) -> Vec<u8> {
    let mut transformed = seed.to_vec();
    for b in transformed.iter_mut().rev().take(count) {
        *b ^= 0xFF;
    }
    transformed
}

/// One operator-managed pair of gateway keys derived from a single master
/// seed ("Key Generation" in GLOSSARY.md).
pub struct Generation {
    /// Key Identifier of this generation's X25519 key.
    pub x25519_key_id: KeyId,
    /// Key Identifier of this generation's X-Wing key.
    pub xwing_key_id: KeyId,
    /// Whether this generation's Key Configurations are advertised.
    pub advertise: bool,
    /// This generation's X25519 Key Configuration (with private key).
    pub x25519_config: KeyConfig,
    /// This generation's X-Wing Key Configuration (with private key).
    pub xwing_config: KeyConfig,
}

impl Generation {
    /// Resolve the seed and derive both keys for one `[[generations]]`
    /// entry.
    ///
    /// # Errors
    ///
    /// Fails if the seed can't be resolved, is shorter than
    /// [`MIN_SEED_LEN`], or either key fails to derive.
    fn from_config(cfg: &GenerationConfig) -> eyre::Result<Self> {
        let x25519_key_id = cfg.x25519_key_id();
        let xwing_key_id = cfg.xwing_key_id();

        let seed = cfg
            .seed
            .resolve()
            .wrap_err_with(|| format!("loading seed for generation {x25519_key_id}"))?;
        if seed.len() < MIN_SEED_LEN {
            bail!(
                "generation {x25519_key_id} seed is {} bytes, need at least {MIN_SEED_LEN}",
                seed.len()
            );
        }

        let x25519_seed = go_seed_transform(&seed, 1);
        let x25519_config = KeyConfig::derive(
            x25519_key_id,
            Kem::X25519Sha256,
            symmetric_suites(),
            &x25519_seed,
        )
        .wrap_err("deriving X25519 key")?;

        let xwing_seed = go_seed_transform(&seed, 2);
        let xwing_config =
            KeyConfig::derive(xwing_key_id, Kem::XWing, symmetric_suites(), &xwing_seed)
                .wrap_err("deriving X-Wing key")?;

        Ok(Self {
            x25519_key_id,
            xwing_key_id,
            advertise: cfg.advertise,
            x25519_config,
            xwing_config,
        })
    }
}

/// One loaded key: its identifier, KEM label, decryption server, and
/// whether it's currently advertised. The single source of truth backing
/// `KeyRing` — every other view (`server_for`, `kem_label`, the advertised
/// counts) is derived from a list of these rather than tracked separately.
struct LoadedKey {
    key_id: KeyId,
    kem: &'static str,
    advertise: bool,
    server: Arc<Server>,
}

/// The full set of decryption servers plus the currently advertised public
/// configuration list. Every loaded generation can decrypt; only advertised
/// generations are published, supporting decrypt-only rotation.
pub struct KeyRing {
    keys: Vec<LoadedKey>,
    advertised_configs: Vec<u8>,
}

impl KeyRing {
    /// Derive every generation's keys and build the key ring.
    ///
    /// # Errors
    ///
    /// Fails if any generation's seed or key derivation fails, or if
    /// encoding the advertised configuration list fails.
    pub fn load(generations: &[GenerationConfig]) -> eyre::Result<Self> {
        let mut keys = Vec::new();
        // Publish in configuration order, X25519 then X-Wing per generation,
        // so operators control preference by ordering generations with
        // newer ones last. `keys`' order doubles as this list's order, so
        // no separate ordered structure is needed to encode it below.
        let mut advertise_list: Vec<KeyConfig> = Vec::new();

        for gen_cfg in generations {
            let generation = Generation::from_config(gen_cfg)?;

            keys.push(LoadedKey {
                key_id: generation.x25519_key_id,
                kem: "x25519",
                advertise: generation.advertise,
                server: Arc::new(
                    Server::new(generation.x25519_config.clone())
                        .wrap_err("creating X25519 server")?,
                ),
            });
            keys.push(LoadedKey {
                key_id: generation.xwing_key_id,
                kem: "xwing",
                advertise: generation.advertise,
                server: Arc::new(
                    Server::new(generation.xwing_config.clone())
                        .wrap_err("creating X-Wing server")?,
                ),
            });

            if generation.advertise {
                advertise_list.push(generation.x25519_config);
                advertise_list.push(generation.xwing_config);
            }
        }

        let advertised_configs =
            KeyConfig::encode_list(&advertise_list).wrap_err("encoding advertised configs")?;

        Ok(Self {
            keys,
            advertised_configs,
        })
    }

    /// Number of X25519 Key Configurations currently advertised.
    #[must_use]
    pub fn advertised_x25519_count(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| k.advertise && k.kem == "x25519")
            .count()
    }

    /// Number of X-Wing Key Configurations currently advertised.
    #[must_use]
    pub fn advertised_xwing_count(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| k.advertise && k.kem == "xwing")
            .count()
    }

    /// Look up the decryption server for a request's key identifier. The
    /// caller has only peeked the identifier; `Server::decapsulate` still
    /// independently validates the identifier, KEM and symmetric suite
    /// carried in the request header.
    #[must_use]
    pub fn server_for(&self, key_id: KeyId) -> Option<Arc<Server>> {
        self.keys
            .iter()
            .find(|k| k.key_id == key_id)
            .map(|k| k.server.clone())
    }

    /// `"x25519"`, `"xwing"`, or `"unknown"` — a bounded label for metrics.
    #[must_use]
    pub fn kem_label(&self, key_id: KeyId) -> &'static str {
        self.keys
            .iter()
            .find(|k| k.key_id == key_id)
            .map_or("unknown", |k| k.kem)
    }

    /// RFC 9458 `application/ohttp-keys` wire format for every advertised
    /// generation.
    #[must_use]
    pub fn advertised_configs(&self) -> &[u8] {
        &self.advertised_configs
    }

    /// Total number of loaded keys (both KEMs, across every generation),
    /// regardless of whether they're advertised.
    #[must_use]
    pub fn loaded_key_count(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go-derived fixture: for seed `0x00..=0x1f` (`XORing` the last byte to
    /// `0xff` per the legacy transform) and key identifier 7, the Go
    /// reference (`ohttp-go` + CIRCL 1.6.3, `KEM_X25519_HKDF_SHA256`)
    /// produces this exact `PublicConfig.Marshal()` output. Captured by
    /// building the vendored Go module directly and calling
    /// `ohttp.NewConfigFromSeed` with this seed, then hex-encoding
    /// `PublicConfig.Marshal()`.
    const GO_X25519_FIXTURE_HEX: &str =
        "070020cdaed74e78bad692aa8125c176aed5513a071c06cda792472e1728db92efe356000400010001";

    #[test]
    fn x25519_derivation_matches_go_fixture() {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let transformed = go_seed_transform(&seed, 1);

        let config =
            KeyConfig::derive(7, Kem::X25519Sha256, symmetric_suites(), &transformed).unwrap();
        let encoded = hex::encode(config.encode().unwrap());

        assert_eq!(encoded, GO_X25519_FIXTURE_HEX);
    }

    #[test]
    fn seed_transform_flips_only_the_final_bytes() {
        let seed = vec![0x01u8; 32];
        let one = go_seed_transform(&seed, 1);
        assert_eq!(&one[..31], &seed[..31]);
        assert_eq!(one[31], 0x01 ^ 0xFF);
        let two = go_seed_transform(&seed, 2);
        assert_eq!(&two[..30], &seed[..30]);
        assert_eq!(&two[30..], &[0x01 ^ 0xFF; 2]);
    }
}
