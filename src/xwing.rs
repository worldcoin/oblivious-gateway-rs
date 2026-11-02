//! Go-compatible X-Wing keys and their RFC 9458 server side.
//!
//! The Go gateway (`privacy-gateway-server-go` v0.0.4, via `ohttp-go` and
//! CIRCL) derives its X-Wing key as `SHAKE256(seed)[..32]` and uses that
//! as the X-Wing decapsulation key directly. The `ohttp` crate only offers
//! HPKE's labeled `DeriveKeyPair`, which yields a different key from the
//! same input and cannot import a raw private key. So X-Wing keys are held
//! and decapsulated here with the `hpke` crate, following RFC 9458
//! §4.3–4.4 exactly as `ohttp::Server` does for X25519.

use aes_gcm::aead::{Aead as _, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use ohttp::{KeyConfig, KeyId};
use sha2::Sha256;
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroize;

type PrivateKey = <XWing as hpke::Kem>::PrivateKey;
type EncappedKey = <XWing as hpke::Kem>::EncappedKey;

const KEM_ID: u16 = 0x647a;
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
const AEAD_ID: u16 = 0x0001; // AES-128-GCM
const HEADER_LEN: usize = 7; // key ID, KEM, KDF, AEAD
const ENC_LEN: usize = 1120; // X-Wing encapsulated key
const SK_LEN: usize = 32; // X-Wing decapsulation key (seed form)
const AEAD_KEY_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
/// `max(Nn, Nk)` for AES-128-GCM: response secret and nonce length (RFC 9458 §4.4).
const ENTROPY_LEN: usize = 16;
const INFO_REQUEST: &[u8] = b"message/bhttp request";
const LABEL_RESPONSE: &[u8] = b"message/bhttp response";

/// Copy the seed and flip its last two bytes, as Go does before deriving
/// X-Wing (cumulatively: last byte for X25519, then the second-to-last).
fn xwing_seed_transform(seed: &[u8]) -> Vec<u8> {
    let mut transformed = seed.to_vec();
    for b in transformed.iter_mut().rev().take(2) {
        *b ^= 0xFF;
    }
    transformed
}

/// One X-Wing key: its private key and public Key Configuration.
pub struct XWingKey {
    key_id: KeyId,
    sk: PrivateKey,
    config: KeyConfig,
}

impl XWingKey {
    /// Derive the key the Go gateway derives from the same master seed.
    ///
    /// # Errors
    ///
    /// Fails only if the derived key cannot be encoded as a Key
    /// Configuration, which would indicate a bug.
    pub fn derive(key_id: KeyId, seed: &[u8]) -> eyre::Result<Self> {
        let mut ikm = xwing_seed_transform(seed);
        let mut sk_bytes = [0u8; SK_LEN];
        let mut shake = Shake256::default();
        shake.update(&ikm);
        shake.finalize_xof().read(&mut sk_bytes);
        ikm.zeroize();
        let sk = PrivateKey::from_bytes(&sk_bytes);
        sk_bytes.zeroize();
        let sk = sk.map_err(|e| eyre::eyre!("X-Wing private key: {e:?}"))?;

        let pk = XWing::sk_to_pk(&sk).to_bytes();
        let mut encoded = Vec::with_capacity(HEADER_LEN + pk.len() + 2);
        encoded.push(key_id);
        encoded.extend_from_slice(&KEM_ID.to_be_bytes());
        encoded.extend_from_slice(&pk);
        encoded.extend_from_slice(&4u16.to_be_bytes());
        encoded.extend_from_slice(&KDF_ID.to_be_bytes());
        encoded.extend_from_slice(&AEAD_ID.to_be_bytes());
        let config = KeyConfig::decode(&encoded)?;

        Ok(Self { key_id, sk, config })
    }

    /// Public Key Configuration (no private key) for `/ohttp-keys`.
    #[must_use]
    pub fn config(&self) -> &KeyConfig {
        &self.config
    }

    /// Decapsulate an Encapsulated Request (RFC 9458 §4.3).
    ///
    /// # Errors
    ///
    /// Fails if the header does not name this key and suite, the request
    /// is truncated, or decryption fails.
    pub fn decapsulate(&self, enc_request: &[u8]) -> eyre::Result<(Vec<u8>, XWingResponse)> {
        if enc_request.len() <= HEADER_LEN + ENC_LEN {
            eyre::bail!("truncated X-Wing request");
        }
        let (header, rest) = enc_request.split_at(HEADER_LEN);
        let mut expected = [0u8; HEADER_LEN];
        expected[0] = self.key_id;
        expected[1..3].copy_from_slice(&KEM_ID.to_be_bytes());
        expected[3..5].copy_from_slice(&KDF_ID.to_be_bytes());
        expected[5..7].copy_from_slice(&AEAD_ID.to_be_bytes());
        if header != expected {
            eyre::bail!("request header does not match X-Wing key {}", self.key_id);
        }
        let (enc, ct) = rest.split_at(ENC_LEN);

        let mut info = Vec::with_capacity(INFO_REQUEST.len() + 1 + HEADER_LEN);
        info.extend_from_slice(INFO_REQUEST);
        info.push(0);
        info.extend_from_slice(header);

        let encapped =
            EncappedKey::from_bytes(enc).map_err(|e| eyre::eyre!("X-Wing enc: {e:?}"))?;
        let mut ctx = hpke::setup_receiver::<AesGcm128, HkdfSha256, XWing>(
            &OpModeR::Base,
            &self.sk,
            &encapped,
            &info,
        )
        .map_err(|e| eyre::eyre!("HPKE setup: {e:?}"))?;
        let request = ctx
            .open(ct, &[])
            .map_err(|e| eyre::eyre!("HPKE open: {e:?}"))?;

        let mut secret = [0u8; ENTROPY_LEN];
        ctx.export(LABEL_RESPONSE, &mut secret)
            .map_err(|e| eyre::eyre!("HPKE export: {e:?}"))?;
        let mut response_nonce = [0u8; ENTROPY_LEN];
        rand::fill(&mut response_nonce);
        let response = XWingResponse::new(&secret, enc, response_nonce);
        secret.zeroize();
        Ok((request, response))
    }
}

/// Response encryption state for one decapsulated X-Wing request.
pub struct XWingResponse {
    response_nonce: [u8; ENTROPY_LEN],
    key: [u8; AEAD_KEY_LEN],
    nonce: [u8; AEAD_NONCE_LEN],
}

impl XWingResponse {
    fn new(secret: &[u8], enc: &[u8], response_nonce: [u8; ENTROPY_LEN]) -> Self {
        let mut salt = enc.to_vec();
        salt.extend_from_slice(&response_nonce);
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&salt), secret);
        let mut key = [0u8; AEAD_KEY_LEN];
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        // Output lengths are far below HKDF-SHA256's limit.
        hkdf.expand(b"key", &mut key).expect("valid HKDF length");
        hkdf.expand(b"nonce", &mut nonce)
            .expect("valid HKDF length");
        Self {
            response_nonce,
            key,
            nonce,
        }
    }

    /// Encapsulate the response (RFC 9458 §4.4).
    ///
    /// # Errors
    ///
    /// Fails if AES-GCM encryption fails.
    pub fn encapsulate(mut self, response: &[u8]) -> eyre::Result<Vec<u8>> {
        let cipher = Aes128Gcm::new(&self.key.into());
        let ct = cipher
            .encrypt(&Nonce::from(self.nonce), response)
            .map_err(|e| eyre::eyre!("AES-GCM seal: {e:?}"));
        self.key.zeroize();
        let mut out = self.response_nonce.to_vec();
        out.extend_from_slice(&ct?);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go fixture: `privacy-gateway-server-go` v0.0.4 (d63adf6) started with
    /// `SEED_SECRET_KEY=000102…1f` and default `CONFIGURATION_ID=0` serves
    /// this X-Wing entry (key ID 64) in `/ohttp-keys`. Captured by building
    /// the tagged repository's Dockerfile and fetching `/ohttp-keys`.
    const GO_XWING_FIXTURE_HEX: &str = include_str!("../tests/fixtures/go-v0.0.4-xwing-config.hex");

    #[test]
    fn xwing_derivation_matches_go_fixture() {
        let seed: Vec<u8> = (0u8..32).collect();
        let key = XWingKey::derive(64, &seed).unwrap();
        assert_eq!(
            hex::encode(key.config().encode().unwrap()),
            GO_XWING_FIXTURE_HEX.trim()
        );
    }

    #[test]
    fn seed_transform_flips_last_two_bytes() {
        let seed = vec![0x01u8; 32];
        let transformed = xwing_seed_transform(&seed);
        assert_eq!(&transformed[..30], &seed[..30]);
        assert_eq!(&transformed[30..], &[0x01 ^ 0xFF, 0x01 ^ 0xFF]);
    }
}
