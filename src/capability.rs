use crate::config::Config;
use std::collections::HashSet;

/// All IRCv3 capabilities we support.
///
/// Every name here is either registered or carries the `draft/` prefix the
/// work-in-progress specification asks for. Features advertised through an
/// ISUPPORT token instead — WHOX, UTF8ONLY, BOT, ACCOUNTEXTBAN — do not belong here.
pub const CAPS: &[&str] = &[
    "capability-negotiation", // Implicit
    "message-tags",
    "server-time",
    "batch",
    "echo-message",
    "multi-prefix",
    "extended-join",
    "account-tag",
    "account-notify",
    "chghost",
    "setname",
    "away-notify",
    "invite-notify",
    "labeled-response",
    "standard-replies",
    "no-implicit-names",
    "userhost-in-names",
    "sasl",
    "cap-notify",
    "draft/extended-isupport",
    "draft/message-redaction",
    "monitor",
    "extended-monitor",
    "draft/channel-rename",
    "draft/chathistory",
    "draft/read-marker",
    "draft/metadata-2",
    "draft/account-registration",
    "draft/multiline",
    "draft/pre-away",
    "draft/message-edit",
    "draft/react",
    "draft/unreact",
    "typing",
    "reply",
    "draft/channel-context",
    "draft/client-batch",
    "draft/event-playback",
    "draft/auto-join",
    "draft/webpush",
    "draft/oper-tag",
    "sts",
];

/// Names rIRCd used to advertise, still accepted in CAP REQ so clients written
/// against an earlier release keep working. Each maps to what it means now, or
/// to itself when the feature no longer needs a capability at all.
const LEGACY_CAP_ALIASES: &[(&str, Option<&str>)] = &[
    // Renamed: the specification requires the draft/ prefix while it is WIP.
    ("message-redaction", Some("draft/message-redaction")),
    // Never capabilities: these features are advertised with an ISUPPORT token
    // (WHOX, UTF8ONLY, BOT=B, ACCOUNTEXTBAN=~a) and work for every client
    // regardless of what it negotiated.
    ("whox", None),
    ("utf8only", None),
    ("bot", None),
    ("account-extban", None),
];

/// Capabilities that depend on message-tags
pub const TAGS_DEPENDENT: &[&str] = &["server-time", "batch", "account-tag"];

/// Build CAP LS reply value (space-separated list).
/// `sts` is advertised only when TLS is configured, and SASL EXTERNAL only when
/// TLS client certificates are enabled.
/// `client_is_tls` indicates whether the requesting client is on a TLS connection:
///   - plaintext clients get `sts=port=<N>` (upgrade directive)
///   - TLS clients get `sts=duration=<N>` (persistence policy)
pub fn build_cap_list(cfg: &Config, version_302: bool, client_is_tls: bool) -> Vec<String> {
    let tls_port = cfg.tls_port();
    let sasl_external = cfg.tls.client_certs && cfg.tls_enabled();
    // No custom-account-name: REGISTER still requires the account name to match the
    // current nick, because channel op/voice lists match a nick or an account name
    // interchangeably, so a freely chosen account name could inherit someone else's ops.
    // email-required: [email] is configured, so REGISTER needs a mailable address.
    // The advertised minimum is the one REGISTER actually enforces, so a client
    // is never told a password is acceptable and then refused.
    let mut registration_values: Vec<String> = Vec::new();
    if cfg.server.register_before_connect {
        registration_values.push("before-connect".into());
    }
    if cfg.email.is_some() {
        registration_values.push("email-required".into());
    }
    registration_values.push(format!(
        "min-password-length={}",
        cfg.limits.min_password_length
    ));
    let account_registration = format!(
        "draft/account-registration={}",
        registration_values.join(",")
    );

    let caps: Vec<String> = CAPS
        .iter()
        .copied()
        .filter(|c| *c != "capability-negotiation")
        .filter(|c| *c != "sts" || tls_port.is_some())
        .filter(|c| *c != "draft/webpush" || cfg.webpush.is_some())
        .map(|c| match c {
            "sasl" if sasl_external => "sasl=PLAIN,SCRAM-SHA-256,EXTERNAL".to_string(),
            "sasl" => "sasl=PLAIN,SCRAM-SHA-256".to_string(),
            "draft/multiline" => "draft/multiline=max-bytes=4096,max-lines=20".to_string(),
            "draft/metadata-2" => {
                "draft/metadata-2=max-subs=50,max-keys=50,max-value-bytes=4096".to_string()
            }
            "draft/account-registration" => account_registration.to_string(),
            // STS: plaintext clients get port (upgrade), TLS clients get duration (persistence)
            "sts" if client_is_tls => "sts=duration=2592000".to_string(),
            "sts" => format!("sts=port={}", tls_port.unwrap_or(6697)),
            _ => c.to_string(),
        })
        // "If a client has not indicated support for CAP LS 302 features, the
        // server MUST NOT send these new features to the client" — a 3.1 client
        // gets bare names, without the values 3.2 introduced.
        .map(|c| {
            if version_302 {
                c
            } else {
                c.split('=').next().unwrap_or(&c).to_string()
            }
        })
        .collect();

    if version_302 {
        let mut result = Vec::new();
        let chunk_size = 10;
        for chunk in caps.chunks(chunk_size) {
            result.push(chunk.join(" "));
        }
        result
    } else {
        vec![caps.join(" ")]
    }
}

/// Filter requested caps to only those we support. A requested cap may include a
/// value (e.g. draft/multiline=max-lines=10). Returns (acked, naked); acked names
/// are the canonical ones, so a legacy request is enabled under its current name.
pub fn filter_requested(
    requested: &[String],
    enabled_in_config: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut ack = Vec::new();
    let mut nak = Vec::new();

    for cap in requested {
        let cap = cap.trim();
        if cap.is_empty() {
            continue;
        }
        let base = cap.split('=').next().unwrap_or(cap);
        // A name we no longer advertise is still honoured: ACK it, mapped to the
        // capability it became, so an older client is not left worse off.
        let resolved = match LEGACY_CAP_ALIASES.iter().find(|(old, _)| *old == base) {
            Some((old, replacement)) => replacement.unwrap_or(old),
            None => base,
        };
        let known =
            CAPS.contains(&resolved) || LEGACY_CAP_ALIASES.iter().any(|(old, _)| *old == base);
        if known && (enabled_in_config.is_empty() || enabled_in_config.contains(resolved)) {
            ack.push(resolved.to_string());
        } else {
            nak.push(cap.to_string());
        }
    }

    (ack, nak)
}
