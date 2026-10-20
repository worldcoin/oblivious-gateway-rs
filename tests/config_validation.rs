//! Startup configuration validation: duplicate key identifiers, missing
//! generations, colliding routes, and missing TLS material must all fail
//! fast with a clear error before the gateway starts serving traffic.

use oblivious_gateway::config::FileConfig;

fn write_temp(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
    file
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
    let config = FileConfig::load(file.path()).expect("valid config should load");
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
    let err = FileConfig::load(file.path()).unwrap_err();
    assert!(format!("{err:#}").contains("at least one key generation"));
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
    let err = FileConfig::load(file.path()).unwrap_err();
    assert!(format!("{err:#}").contains("identical"));
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
    let err = FileConfig::load(file.path()).unwrap_err();
    assert!(format!("{err:#}").contains("duplicate key identifier"));
}

#[test]
fn rejects_removed_route_path_settings() {
    for (section, setting) in [
        (
            "listen_addr = \"127.0.0.1:0\"",
            "gateway_path = \"/custom\"",
        ),
        ("listen_addr = \"127.0.0.1:0\"", "health_path = \"/custom\""),
    ] {
        let file = write_temp(&VALID_BASE.replace(section, &format!("{section}\n{setting}")));
        let err = FileConfig::load(file.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown field"),
            "{setting}: {err:#}"
        );
    }
    let file = write_temp(&format!(
        "{VALID_BASE}\n[metrics]\nlisten_addr = \"127.0.0.1:9090\"\npath = \"/custom\""
    ));
    let err = FileConfig::load(file.path()).unwrap_err();
    assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
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
    let err = FileConfig::load(file.path()).unwrap_err();
    assert!(format!("{err:#}").contains("cert_file not found"));
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
    let config = FileConfig::load(file.path()).expect("TOML shape is valid");
    let err = KeyRing::load(&config.generations).err().unwrap();
    assert!(format!("{err:#}").contains("need at least"));
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
    let config = FileConfig::load(defaulted.path()).unwrap();
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
    let config = FileConfig::load(derived.path()).unwrap();
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
    let config = FileConfig::load(explicit.path()).unwrap();
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
            let err = FileConfig::load(file.path()).unwrap_err();
            assert!(format!("{err:#}").contains(&format!("missing field `{missing}`")));
        }
    }
}
