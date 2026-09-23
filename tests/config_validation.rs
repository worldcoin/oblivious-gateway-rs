//! Startup configuration validation: duplicate key identifiers, missing
//! generations, colliding routes, and missing TLS material must all fail
//! fast with a clear error before the gateway starts serving traffic.

use oblivious_gateway::config::FileConfig;

fn write_temp(contents: &str) -> tempfile_like::TempFile {
    tempfile_like::TempFile::new(contents)
}

/// Minimal stand-in for a temp file so this test suite doesn't need an
/// extra dependency: writes to a unique path under `std::env::temp_dir()`
/// and removes it on drop.
mod tempfile_like {
    use std::path::PathBuf;

    pub struct TempFile {
        pub path: PathBuf,
    }

    impl TempFile {
        pub fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "oblivious-gateway-test-{}-{}.toml",
                std::process::id(),
                super::unique_id()
            ));
            std::fs::write(&path, contents).unwrap();
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn unique_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

const VALID_BASE: &str = r#"
[server]
listen_addr = "127.0.0.1:0"

[forwarding]
allowed_targets = ["example.invalid"]

[[generations]]
x25519 = { key_id = 0 }
xwing = { key_id = 1 }
[generations.seed]
hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
"#;

#[test]
fn valid_config_loads() {
    let file = write_temp(VALID_BASE);
    let config = FileConfig::load(&file.path).expect("valid config should load");
    assert_eq!(config.generations.len(), 1);
}

#[test]
fn rejects_empty_generations() {
    let file = write_temp(
        r#"
generations = []

[server]
listen_addr = "127.0.0.1:0"

[forwarding]
allowed_targets = ["example.invalid"]
"#,
    );
    let err = FileConfig::load(&file.path).unwrap_err();
    assert!(format!("{err}").contains("at least one key generation"));
}

#[test]
fn rejects_duplicate_key_ids_within_generation() {
    let file = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[forwarding]
allowed_targets = ["example.invalid"]

[[generations]]
x25519 = { key_id = 5 }
xwing = { key_id = 5 }
[generations.seed]
hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
"#,
    );
    let err = FileConfig::load(&file.path).unwrap_err();
    assert!(format!("{err}").contains("identical"));
}

#[test]
fn rejects_duplicate_key_ids_across_generations() {
    let file = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[forwarding]
allowed_targets = ["example.invalid"]

[[generations]]
x25519 = { key_id = 0 }
xwing = { key_id = 1 }
[generations.seed]
hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

[[generations]]
x25519 = { key_id = 1 }
xwing = { key_id = 2 }
[generations.seed]
hex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
"#,
    );
    let err = FileConfig::load(&file.path).unwrap_err();
    assert!(format!("{err}").contains("duplicate key identifier"));
}

#[test]
fn rejects_colliding_route_paths() {
    let file = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"
gateway_path = "/same"
keys_path = "/same"

[forwarding]
allowed_targets = ["example.invalid"]

[[generations]]
x25519 = { key_id = 0 }
xwing = { key_id = 1 }
[generations.seed]
hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
"#,
    );
    let err = FileConfig::load(&file.path).unwrap_err();
    assert!(format!("{err}").contains("distinct"));
}

#[test]
fn rejects_missing_tls_cert_file() {
    let file = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"
[server.tls]
cert_file = "/nonexistent/cert.pem"
key_file = "/nonexistent/key.pem"

[forwarding]
allowed_targets = ["example.invalid"]

[[generations]]
x25519 = { key_id = 0 }
xwing = { key_id = 1 }
[generations.seed]
hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
"#,
    );
    let err = FileConfig::load(&file.path).unwrap_err();
    assert!(format!("{err}").contains("cert_file not found"));
}

#[test]
fn rejects_short_seed_at_key_ring_load_time() {
    use oblivious_gateway::keys::KeyRing;

    let file = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"

[forwarding]
allowed_targets = ["example.invalid"]

[[generations]]
x25519 = { key_id = 0 }
xwing = { key_id = 1 }
[generations.seed]
hex = "0001020304"
"#,
    );
    let config = FileConfig::load(&file.path).expect("TOML shape is valid");
    let err = KeyRing::load(&config.generations).err().unwrap();
    assert!(format!("{err}").contains("need at least"));
}

#[test]
fn xwing_key_id_defaults_and_can_be_overridden() {
    let defaulted = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"
[forwarding]
allowed_targets = ["example.invalid"]
[[generations]]
x25519 = { key_id = 0 }
seed = { hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" }
"#,
    );
    let config = FileConfig::load(&defaulted.path).unwrap();
    assert_eq!(config.generations[0].x25519_key_id(), 0);
    assert_eq!(config.generations[0].xwing_key_id(), 128);
    assert!(config.generations[0].advertise);

    // x25519 explicit, xwing omitted: xwing still derives from x25519.
    let derived = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"
[forwarding]
allowed_targets = ["example.invalid"]
[[generations]]
x25519 = { key_id = 5 }
seed = { hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" }
"#,
    );
    let config = FileConfig::load(&derived.path).unwrap();
    assert_eq!(config.generations[0].x25519_key_id(), 5);
    assert_eq!(config.generations[0].xwing_key_id(), 133);

    // Both explicit: no defaulting/derivation kicks in at all.
    let explicit = write_temp(
        r#"
[server]
listen_addr = "127.0.0.1:0"
[forwarding]
allowed_targets = ["example.invalid"]
[[generations]]
x25519 = { key_id = 5 }
xwing = { key_id = 200 }
seed = { hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" }
"#,
    );
    let config = FileConfig::load(&explicit.path).unwrap();
    assert_eq!(config.generations[0].x25519_key_id(), 5);
    assert_eq!(config.generations[0].xwing_key_id(), 200);
}

#[test]
fn every_generation_requires_an_x25519_key_id() {
    for (setting, missing) in [("", "x25519"), ("x25519 = {}", "key_id")] {
        let invalid = VALID_BASE.replace("x25519 = { key_id = 0 }", setting);
        let generation = invalid.split_once("[[generations]]").unwrap().1;
        for contents in [
            invalid.clone(),
            format!("{VALID_BASE}\n[[generations]]{generation}"),
        ] {
            let file = write_temp(&contents);
            let err = FileConfig::load(&file.path).unwrap_err();
            assert!(format!("{err}").contains(&format!("missing field `{missing}`")));
        }
    }
}
