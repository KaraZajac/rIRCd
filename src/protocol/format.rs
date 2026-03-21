use super::message::Message;
use chrono::Utc;
use std::collections::{HashMap, HashSet};

/// Format an IRC message for sending (with CRLF).
pub fn format_message(msg: &Message) -> String {
    let mut out = String::new();

    if !msg.tags.is_empty() {
        out.push('@');
        let tag_str = format_tags(&msg.tags);
        out.push_str(&tag_str);
        out.push(' ');
    }

    if let Some(ref prefix) = msg.prefix {
        out.push(':');
        out.push_str(prefix);
        out.push(' ');
    }

    out.push_str(&msg.command);

    for (i, param) in msg.params.iter().enumerate() {
        out.push(' ');
        if i == msg.params.len() - 1 && (param.contains(' ') || param.starts_with(':')) {
            out.push(':');
        }
        out.push_str(param);
    }

    out.push_str("\r\n");
    out
}

fn format_tags(tags: &HashMap<String, Option<String>>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in tags {
        let part = match v {
            Some(val) => format!("{}={}", k, escape_tag_value(val)),
            None => k.clone(),
        };
        parts.push(part);
    }
    parts.join(";")
}

fn escape_tag_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            ';' => result.push_str("\\:"),
            ' ' => result.push_str("\\s"),
            '\r' => result.push_str("\\r"),
            '\n' => result.push_str("\\n"),
            c if c as u32 != 0 && c != '\r' && c != '\n' => result.push(c),
            _ => {}
        }
    }
    result
}

/// Add server-time tag (ISO 8601) to tags
pub fn add_server_time(tags: &mut HashMap<String, Option<String>>) {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string();
    tags.insert("time".to_string(), Some(now));
}

/// Add IRCv3 tags for a recipient: server-time, msgid, account; then client-only tags (+prefix).
/// Server tags are added first per spec; client_only_tags (e.g. +typing, +react) are relayed as-is.
/// If client_tag_deny is set, listed tags (or "*" for all) are not added.
pub fn add_tags_for_recipient(
    mut msg: Message,
    recipient_caps: &HashSet<String>,
    sender_account: Option<&str>,
    msgid: Option<&str>,
    client_only_tags: Option<&HashMap<String, Option<String>>>,
    client_tag_deny: Option<&[String]>,
) -> Message {
    if !recipient_caps.is_empty() {
        if recipient_caps.contains("server-time") {
            add_server_time(&mut msg.tags);
        }
        if let Some(id) = msgid {
            if recipient_caps.contains("message-tags") {
                msg.tags.insert("msgid".to_string(), Some(id.to_string()));
            }
        }
        if recipient_caps.contains("account-tag") {
            if let Some(acc) = sender_account {
                msg.tags
                    .insert("account".to_string(), Some(acc.to_string()));
            } else {
                msg.tags.insert("account".to_string(), None); // * means not logged in
            }
        }
    }
    let deny_all = client_tag_deny
        .map(|d| d.contains(&"*".to_string()))
        .unwrap_or(false);
    // Client-only tags (+ prefix) require the message-tags capability per IRCv3 spec
    if recipient_caps.contains("message-tags") {
        if let Some(tags) = client_only_tags {
            for (k, v) in tags {
                if k.starts_with('+') {
                    if deny_all {
                        continue;
                    }
                    if let Some(deny) = client_tag_deny {
                        if deny
                            .iter()
                            .any(|d| d == k || d.as_str() == k.trim_start_matches('+'))
                        {
                            continue;
                        }
                    }
                    msg.tags.insert(k.clone(), v.clone());
                }
            }
        }
    }
    msg
}

/// Generate a short unique message id (for message-ids cap)
pub fn generate_msgid() -> String {
    uuid::Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .chars()
        .take(12)
        .collect()
}

/// Add batch tag to a message (for batch cap). Reference must match BATCH +ref / BATCH -ref.
pub fn add_batch_tag(mut msg: Message, batch_ref: &str) -> Message {
    msg.tags
        .insert("batch".to_string(), Some(batch_ref.to_string()));
    msg
}

/// Create a numeric reply message
#[allow(dead_code)]
pub fn numeric(server: &str, numeric: u16, nick: &str, text: &str) -> Message {
    let mut msg = Message::new(
        numeric.to_string(),
        vec![nick.to_string(), text.to_string()],
    );
    msg.prefix = Some(server.to_string());
    msg
}

/// Create a numeric reply with extra params
#[allow(dead_code)]
pub fn numeric_params(server: &str, numeric: u16, params: Vec<String>) -> Message {
    let mut msg = Message::new(numeric.to_string(), params);
    msg.prefix = Some(server.to_string());
    msg
}
