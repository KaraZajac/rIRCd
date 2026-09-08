//! draft/webpush: capability gating and configuration defaults.

use rircd::capability::build_cap_list;
use rircd::config::Config;

fn config_from(toml_src: &str) -> Config {
    toml::from_str(toml_src).expect("config parses")
}

fn caps(cfg: &Config) -> Vec<String> {
    build_cap_list(cfg, false, false)
        .join(" ")
        .split(' ')
        .map(|s| s.split('=').next().unwrap_or(s).to_string())
        .collect()
}

const CONFIGURED: &str = r#"
    [webpush]
    contact = "mailto:admin@example.com"
"#;

#[test]
fn capability_is_advertised_only_when_configured() {
    assert!(
        !caps(&config_from("")).contains(&"draft/webpush".to_string()),
        "must not offer push when no [webpush] section exists"
    );
    assert!(caps(&config_from(CONFIGURED)).contains(&"draft/webpush".to_string()));
}

#[test]
fn webpush_config_defaults() {
    let cfg = config_from(CONFIGURED);
    let wp = cfg.webpush.expect("section parsed");

    assert_eq!(wp.contact, "mailto:admin@example.com");
    assert_eq!(wp.key_file, "/etc/rIRCd/vapid.key");
    assert_eq!(wp.max_subscriptions_per_account, 5);
    assert_eq!(wp.ttl_secs, 3600);
    assert_eq!(wp.max_failures, 5);
    assert!(
        !wp.allow_private_endpoints,
        "endpoints on private networks must be refused unless asked for"
    );
}

#[test]
fn vapid_key_is_generated_once_and_reused() {
    let dir = std::env::temp_dir().join(format!("rircd-vapid-{}", std::process::id()));
    let path = dir.join("vapid.key");
    let _ = std::fs::remove_dir_all(&dir);

    let first = rircd::webpush::VapidKey::load_or_create(&path).expect("generates a key");
    let stored = std::fs::read_to_string(&path).expect("key file written");
    let second = rircd::webpush::VapidKey::load_or_create(&path).expect("reads the key back");

    assert_eq!(first.public_b64(), second.public_b64());
    assert!(!stored.trim().is_empty());
    // Uncompressed P-256 public key: 65 bytes -> 87 base64url characters.
    assert_eq!(first.public_b64().len(), 87);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "private key must not be world-readable"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
