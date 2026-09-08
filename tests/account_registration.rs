//! draft/account-registration: capability advertisement and verification-code rules.

use rircd::capability::build_cap_list;
use rircd::config::Config;
use rircd::mail::{generate_code, is_valid_email};

fn config_from(toml_src: &str) -> Config {
    toml::from_str(toml_src).expect("config parses")
}

/// The single CAP LS line for a non-302 client.
fn cap_line(cfg: &Config) -> String {
    build_cap_list(cfg, false, false).join(" ")
}

/// Value of one CAP LS token, e.g. `sasl=PLAIN` -> `Some("PLAIN")`.
fn cap_value(cfg: &Config, name: &str) -> Option<String> {
    cap_line(cfg)
        .split(' ')
        .find(|token| token.split('=').next() == Some(name))
        .map(|token| {
            token
                .split_once('=')
                .map(|(_, v)| v)
                .unwrap_or("")
                .to_string()
        })
}

#[test]
fn email_required_is_advertised_only_when_mail_is_configured() {
    let without = config_from("");
    let value = cap_value(&without, "draft/account-registration").expect("cap is advertised");
    assert!(!value.contains("email-required"), "got {value}");
    assert!(value.contains("min-password-length=6"));

    let with = config_from(
        r#"
        [email]
        smtp_host = "smtp.example.com"
        from = "ExampleNet <noreply@example.com>"
        "#,
    );
    let value = cap_value(&with, "draft/account-registration").expect("cap is advertised");
    assert!(value.contains("email-required"), "got {value}");
}

#[test]
fn email_config_defaults() {
    let cfg = config_from(
        r#"
        [email]
        smtp_host = "smtp.example.com"
        from = "ExampleNet <noreply@example.com>"
        "#,
    );
    let email = cfg.email.expect("section parsed");

    assert_eq!(email.smtp_port, 587);
    assert_eq!(email.encryption, "starttls");
    assert_eq!(email.code_expiry_secs, 86_400);
    assert!(email.smtp_user.is_none());
}

#[test]
fn sts_is_advertised_only_with_tls_configured() {
    let plain = config_from("");
    assert!(cap_value(&plain, "sts").is_none());

    let tls = config_from(
        r#"
        [server]
        listen_tls = [":6697"]

        [tls]
        cert = "/etc/rIRCd/cert.pem"
        key = "/etc/rIRCd/key.pem"
        "#,
    );
    assert_eq!(cap_value(&tls, "sts").as_deref(), Some("port=6697"));
    assert_eq!(
        build_cap_list(&tls, false, true)
            .join(" ")
            .split(' ')
            .find(|t| t.starts_with("sts=")),
        Some("sts=duration=2592000")
    );
}

#[test]
fn sasl_external_needs_client_certs() {
    let tls_only = config_from(
        r#"
        [tls]
        cert = "/etc/rIRCd/cert.pem"
        key = "/etc/rIRCd/key.pem"
        "#,
    );
    assert_eq!(
        cap_value(&tls_only, "sasl").as_deref(),
        Some("PLAIN,SCRAM-SHA-256")
    );

    let with_client_certs = config_from(
        r#"
        [tls]
        cert = "/etc/rIRCd/cert.pem"
        key = "/etc/rIRCd/key.pem"
        client_certs = true
        "#,
    );
    assert_eq!(
        cap_value(&with_client_certs, "sasl").as_deref(),
        Some("PLAIN,SCRAM-SHA-256,EXTERNAL")
    );
}

#[test]
fn verification_codes_are_unambiguous_and_random() {
    let code = generate_code();
    assert_eq!(code.len(), 8);
    assert!(
        code.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
        "unexpected characters in {code}"
    );
    assert!(
        !code.contains(['0', 'O', '1', 'I']),
        "code {code} contains characters that are easy to misread"
    );

    let codes: std::collections::HashSet<String> = (0..50).map(|_| generate_code()).collect();
    assert!(codes.len() > 45, "codes repeat too often: {}", codes.len());
}

#[test]
fn email_validation_rejects_the_wildcard_placeholder() {
    assert!(is_valid_email("user@example.com"));
    assert!(is_valid_email("first.last+tag@sub.example.org"));

    assert!(!is_valid_email("*"), "REGISTER's \"no email\" placeholder");
    assert!(!is_valid_email(""));
    assert!(!is_valid_email("not-an-address"));
    assert!(!is_valid_email("@example.com"));
    assert!(!is_valid_email("user@"));
}
