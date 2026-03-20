use std::collections::HashSet;

/// All IRCv3 capabilities we support
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
    "utf8only",
    "sasl",
    "cap-notify",
    "draft/extended-isupport",
    "whox",
    "bot",
    "message-redaction",
    "account-extban",
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
    "typing",
    "reply",
    "draft/channel-context",
    "draft/client-batch",
    "sts",
];

/// Capabilities that depend on message-tags
pub const TAGS_DEPENDENT: &[&str] = &["server-time", "batch", "account-tag"];

/// Build CAP LS reply value (space-separated list).
/// `tls_port` is required to advertise `sts`; omit it when TLS is not configured.
pub fn build_cap_list(version_302: bool, tls_port: Option<u16>) -> Vec<String> {
    let caps: Vec<String> = CAPS
        .iter()
        .copied()
        .filter(|c| *c != "capability-negotiation")
        .filter(|c| *c != "sts" || tls_port.is_some())
        .map(|c| match c {
            "sasl" => "sasl=PLAIN,SCRAM-SHA-256".to_string(),
            "draft/multiline" => "draft/multiline=max-bytes=4096,max-lines=20".to_string(),
            "draft/metadata-2" => "draft/metadata-2=max-subs=50,max-keys=50".to_string(),
            "sts" => format!("sts=port={},duration=2592000", tls_port.unwrap_or(6697)),
            _ => c.to_string(),
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

/// Filter requested caps to only those we support. Requested cap may include =value (e.g. draft/multiline=max-lines=10).
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
        if CAPS.contains(&base)
            && (enabled_in_config.is_empty() || enabled_in_config.contains(base))
        {
            ack.push(base.to_string());
        } else {
            nak.push(cap.to_string());
        }
    }

    (ack, nak)
}
