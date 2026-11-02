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
x25519 = { key_id = 128 }
seed = { hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" }
"#,
    );
    // Go's layout for CONFIGURATION_ID 0: X25519 128, X-Wing 64.
    let config = FileConfig::load(defaulted.path()).unwrap();
    assert_eq!(config.generations[0].x25519_key_id(), 128);
    assert_eq!(config.generations[0].xwing_key_id(), 64);
    assert!(config.generations[0].advertise);

    // The X-Wing default wraps below zero.
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
    assert_eq!(config.generations[0].xwing_key_id(), 197);

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
fn default_xwing_ids_follow_consecutive_x25519_ids() {
    let generations = |ids: [u8; 2]| {
        let mut config = String::from(
            "[server]\nlisten_addr = \"127.0.0.1:0\"\n[forwarding]\nallowed_targets = [\"example.invalid\"]\n",
        );
        for (i, id) in ids.iter().enumerate() {
            config.push_str(&format!(
                "[[generations]]\nx25519 = {{ key_id = {id} }}\nseed = {{ hex = \"{}\" }}\n",
                format!("{i:02x}").repeat(32)
            ));
        }
        write_temp(&config)
    };

    // Rotating to the next X25519 ID, as Go increments CONFIGURATION_ID.
    let file = generations([128, 129]);
    let config = FileConfig::load(file.path()).unwrap();
    let ids: Vec<_> = config
        .generations
        .iter()
        .map(|g| (g.x25519_key_id(), g.xwing_key_id()))
        .collect();
    assert_eq!(ids, [(128, 64), (129, 65)]);

    // X25519 IDs 64 apart collide through the default and fail startup.
    let file = generations([128, 192]);
    let err = FileConfig::load(file.path()).unwrap_err();
    assert!(format!("{err:#}").contains("duplicate key identifier 128"));
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

#[test]
fn admission_limit_defaults_and_accepts_operator_value() {
    let file = write_temp(VALID_BASE);
    assert_eq!(
        FileConfig::load(file.path())
            .unwrap()
            .server
            .max_in_flight_requests,
        128
    );
    let file =
        write_temp(&VALID_BASE.replace("[server]", "[server]\nmax_in_flight_requests = 512"));
    assert_eq!(
        FileConfig::load(file.path())
            .unwrap()
            .server
            .max_in_flight_requests,
        512
    );
}

#[test]
fn invalid_admission_limits_fail_startup() {
    for value in [
        "0".to_string(),
        (tokio::sync::Semaphore::MAX_PERMITS + 1).to_string(),
    ] {
        let file = write_temp(&VALID_BASE.replace(
            "[server]",
            &format!("[server]\nmax_in_flight_requests = {value}"),
        ));
        assert!(
            format!("{:#}", FileConfig::load(file.path()).unwrap_err())
                .contains("server.max_in_flight_requests")
        );
    }
}
