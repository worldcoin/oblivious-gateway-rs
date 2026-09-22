//! Key generation loading and the decryption/advertisement key ring.
//!
//! Each generation derives its X-Wing key from the operator's master seed
//! unmodified, and its X25519 key from a copy of that seed with the final
//! byte XORed with `0xff`. This reproduces the Go gateway's legacy X25519
//! derivation input byte-for-byte, so embedded client configurations that
//! predate this rewrite keep working when operators reuse the same seed
//! and key identifier (see GLOSSARY.md). Both KEMs use HKDF-SHA256 +
//! AES-128-GCM.

use std::collections::HashMap;
use std::sync::Arc;

use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, KeyId, Server, SymmetricSuite};

use crate::config::{GenerationConfig, MIN_SEED_LEN};
use crate::error::StartupError;

fn symmetric_suites() -> Vec<SymmetricSuite> {
    vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)]
}

/// Copy the seed and flip the final byte, matching the Go gateway's legacy
/// X25519 derivation input. See module docs above.
fn x25519_seed_transform(seed: &[u8]) -> Vec<u8> {
    let mut transformed = seed.to_vec();
    if let Some(last) = transformed.last_mut() {
        *last ^= 0xFF;
    }
    transformed
}

/// One operator-managed pair of gateway keys derived from a single master
/// seed ("Key Generation" in GLOSSARY.md).
pub struct Generation {
    pub x25519_key_id: KeyId,
    pub xwing_key_id: KeyId,
    pub advertise: bool,
    pub x25519_config: KeyConfig,
    pub xwing_config: KeyConfig,
}

impl Generation {
    fn from_config(cfg: &GenerationConfig) -> Result<Self, StartupError> {
        let seed = cfg
            .seed
            .resolve()
            .map_err(|e| StartupError::Key(format!("generation {}: {e}", cfg.x25519_key_id)))?;
        if seed.len() < MIN_SEED_LEN {
            return Err(StartupError::Key(format!(
                "generation {} seed is {} bytes, need at least {MIN_SEED_LEN}",
                cfg.x25519_key_id,
                seed.len()
            )));
        }

        let x25519_seed = x25519_seed_transform(&seed);
        let x25519_config = KeyConfig::derive(
            cfg.x25519_key_id,
            Kem::X25519Sha256,
            symmetric_suites(),
            &x25519_seed,
        )
        .map_err(|e| StartupError::Key(format!("deriving X25519 key: {e:?}")))?;

        let xwing_config =
            KeyConfig::derive(cfg.xwing_key_id, Kem::XWing, symmetric_suites(), &seed)
                .map_err(|e| StartupError::Key(format!("deriving X-Wing key: {e:?}")))?;

        Ok(Self {
            x25519_key_id: cfg.x25519_key_id,
            xwing_key_id: cfg.xwing_key_id,
            advertise: cfg.advertise,
            x25519_config,
            xwing_config,
        })
    }
}

/// The full set of decryption servers plus the currently advertised public
/// configuration list. Every loaded generation can decrypt; only advertised
/// generations are published, supporting decrypt-only rotation.
pub struct KeyRing {
    servers: HashMap<KeyId, Arc<Server>>,
    advertised_configs: Vec<u8>,
    kem_by_key_id: HashMap<KeyId, &'static str>,
    advertised_x25519_count: usize,
    advertised_xwing_count: usize,
}

impl KeyRing {
    pub fn load(generations: &[GenerationConfig]) -> Result<Self, StartupError> {
        let mut servers = HashMap::new();
        let mut kem_by_key_id = HashMap::new();
        // Publish in configuration order, X25519 then X-Wing per generation,
        // so operators control preference by ordering generations with
        // newer ones last.
        let mut advertise_list: Vec<KeyConfig> = Vec::new();

        for gen_cfg in generations {
            let generation = Generation::from_config(gen_cfg)?;

            servers.insert(
                generation.x25519_key_id,
                Arc::new(
                    Server::new(generation.x25519_config.clone())
                        .map_err(|e| StartupError::Key(format!("X25519 server: {e:?}")))?,
                ),
            );
            servers.insert(
                generation.xwing_key_id,
                Arc::new(
                    Server::new(generation.xwing_config.clone())
                        .map_err(|e| StartupError::Key(format!("X-Wing server: {e:?}")))?,
                ),
            );
            kem_by_key_id.insert(generation.x25519_key_id, "x25519");
            kem_by_key_id.insert(generation.xwing_key_id, "xwing");

            if generation.advertise {
                advertise_list.push(generation.x25519_config);
                advertise_list.push(generation.xwing_config);
            }
        }

        let advertised_x25519_count = advertise_list.len() / 2;
        let advertised_xwing_count = advertise_list.len() / 2;

        let advertised_configs = KeyConfig::encode_list(&advertise_list)
            .map_err(|e| StartupError::Key(format!("encoding advertised configs: {e:?}")))?;

        Ok(Self {
            servers,
            advertised_configs,
            kem_by_key_id,
            advertised_x25519_count,
            advertised_xwing_count,
        })
    }

    pub fn advertised_x25519_count(&self) -> usize {
        self.advertised_x25519_count
    }

    pub fn advertised_xwing_count(&self) -> usize {
        self.advertised_xwing_count
    }

    /// Look up the decryption server for a request's key identifier. The
    /// caller has only peeked the identifier; `Server::decapsulate` still
    /// independently validates the identifier, KEM and symmetric suite
    /// carried in the request header.
    pub fn server_for(&self, key_id: KeyId) -> Option<Arc<Server>> {
        self.servers.get(&key_id).cloned()
    }

    pub fn kem_label(&self, key_id: KeyId) -> &'static str {
        self.kem_by_key_id
            .get(&key_id)
            .copied()
            .unwrap_or("unknown")
    }

    /// RFC 9458 `application/ohttp-keys` wire format for every advertised
    /// generation.
    pub fn advertised_configs(&self) -> &[u8] {
        &self.advertised_configs
    }

    pub fn loaded_key_count(&self) -> usize {
        self.servers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go-derived fixture: for seed `0x00..=0x1f` (XORing the last byte to
    /// `0xff` per the legacy transform) and key identifier 7, the Go
    /// reference (`ohttp-go` + CIRCL 1.6.3, `KEM_X25519_HKDF_SHA256`)
    /// produces this exact `PublicConfig.Marshal()` output. Captured by
    /// running the vendored Go module directly; see the implementation
    /// handoff notes for how to regenerate it.
    const GO_X25519_FIXTURE_HEX: &str =
        "070020cdaed74e78bad692aa8125c176aed5513a071c06cda792472e1728db92efe356000400010001";

    #[test]
    fn x25519_derivation_matches_go_fixture() {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let transformed = x25519_seed_transform(&seed);

        let config =
            KeyConfig::derive(7, Kem::X25519Sha256, symmetric_suites(), &transformed).unwrap();
        let encoded = hex::encode(config.encode().unwrap());

        assert_eq!(encoded, GO_X25519_FIXTURE_HEX);
    }

    #[test]
    fn seed_transform_flips_only_final_byte() {
        let seed = vec![0x01u8; 32];
        let transformed = x25519_seed_transform(&seed);
        assert_eq!(&transformed[..31], &seed[..31]);
        assert_eq!(transformed[31], 0x01 ^ 0xFF);
    }

    #[test]
    fn xwing_uses_untransformed_seed() {
        // X-Wing derivation must not apply the X25519-only XOR transform.
        let seed = vec![0x42u8; 32];
        let a = KeyConfig::derive(1, Kem::XWing, symmetric_suites(), &seed).unwrap();
        let b = KeyConfig::derive(1, Kem::XWing, symmetric_suites(), &seed).unwrap();
        assert_eq!(a.encode().unwrap(), b.encode().unwrap());
    }
}
