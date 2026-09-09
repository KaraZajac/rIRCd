use super::message::Message;
use chrono::Utc;
use std::collections::{HashMap, HashSet};

/// Truncate `s` to at most `max_bytes`, never splitting a character.
///
/// IRC length limits are counted in bytes, but slicing a `str` at a byte index
/// that lands inside a multi-byte character panics — and every one of these
/// limits is applied to text a client chose.
pub fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Format an IRC message for sending (with CRLF).
/// Serialise a message so the line stays inside `max_line` bytes, excluding the
/// CRLF, by shortening its final parameter.
///
/// A message the server relays grows: it gains a `:nick!user@host ` prefix it
/// did not have when the sender wrote it. Without this, that growth pushes the
/// line past the protocol limit and the peer is the one that has to deal with
/// it — by truncating at a byte that may be mid-character, or by dropping the
/// line entirely.
pub fn format_message_within(msg: &Message, max_line: usize) -> String {
    let line = format_message(msg);
    // The limit is on the message body. Tags are counted separately (and have
    // their own, larger limit), so a message with tags must not be cut short
    // because of them.
    let tag_len = if msg.tags.is_empty() {
        0
    } else {
        line.find(' ').map(|i| i + 1).unwrap_or(0)
    };
    let body_len = line.len().saturating_sub(2 + tag_len); // without tags or CRLF
    if body_len <= max_line || msg.params.is_empty() {
        return line;
    }
    let excess = body_len - max_line;
    let last = msg.params.len() - 1;
    let mut shortened = msg.clone();
    let keep = shortened.params[last].len().saturating_sub(excess);
    shortened.params[last] = truncate_bytes(&shortened.params[last], keep).to_string();
    format_message(&shortened)
}

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
        // The last parameter needs the ':' when it holds spaces, starts with a
        // ':' of its own, or is empty — without it an empty one is not a
        // parameter at all, it is a trailing space the peer discards.
        //
        // For the commands whose final parameter is free-form text it is always
        // written as trailing, whether or not this particular text happens to
        // need it: that is how the sender wrote it, and how the length of the
        // line is reckoned.
        const TEXT_COMMANDS: &[&str] = &["PRIVMSG", "NOTICE"];
        if i == msg.params.len() - 1
            && (param.contains(' ')
                || param.starts_with(':')
                || param.is_empty()
                || (msg.params.len() > 1 && TEXT_COMMANDS.contains(&msg.command.as_str())))
        {
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
/// The IRCv3 server-time format: exactly three decimal places and a literal
/// 'Z'. `to_rfc3339` is a different rendering of the same instant
/// (nanoseconds, numeric offset) that clients do not accept here, and that
/// sorts differently when timestamps are compared as strings.
pub fn server_time_now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string()
}

/// Normalise a stored timestamp to the server-time format, leaving it alone if
/// it cannot be parsed.
pub fn to_server_time(ts: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => dt
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:%M:%S.%3fZ")
            .to_string(),
        Err(_) => ts.to_string(),
    }
}

/// Stamp the message with the time it is being sent, unless it already carries
/// one. Replayed history arrives with the time it was originally sent, and that
/// is the whole point of it — overwriting it with the time of the CHATHISTORY
/// request makes every message look like it was sent just now.
pub fn add_server_time(tags: &mut HashMap<String, Option<String>>) {
    tags.entry("time".to_string())
        .or_insert_with(|| Some(Utc::now().format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string()));
}

/// Add IRCv3 tags for a recipient: server-time, msgid, account, bot; then client-only tags (+prefix).
/// Server tags are added first per spec; client_only_tags (e.g. +typing, +react) are relayed as-is.
/// If client_tag_deny is set, listed tags (or "*" for all) are not added.
/// Attributes of the message's sender that become tags on the recipient's copy.
#[derive(Debug, Clone, Default)]
pub struct SenderTags {
    /// Sender has umode +B (bot).
    pub is_bot: bool,
    /// Operator name when the sender is an IRC operator (draft/oper-tag).
    pub oper: Option<String>,
}

impl SenderTags {
    pub fn new(is_bot: bool, oper: Option<String>) -> Self {
        Self { is_bot, oper }
    }
}

pub fn add_tags_for_recipient(
    mut msg: Message,
    recipient_caps: &HashSet<String>,
    sender_account: Option<&str>,
    msgid: Option<&str>,
    client_only_tags: Option<&HashMap<String, Option<String>>>,
    client_tag_deny: Option<&[String]>,
    sender: &SenderTags,
) -> Message {
    // A message may arrive here already carrying tags — a time it was sent at,
    // tags a client attached. A recipient only sees the ones it negotiated, so
    // anything it did not ask for is taken off its copy rather than left on.
    if !recipient_caps.contains("server-time") {
        msg.tags.remove("time");
    }
    if !recipient_caps.contains("message-tags") {
        msg.tags.remove("msgid");
        msg.tags.retain(|k, _| !k.starts_with('+'));
    }
    if !recipient_caps.is_empty() {
        if recipient_caps.contains("server-time") {
            add_server_time(&mut msg.tags);
        }
        if let Some(id) = msgid {
            if recipient_caps.contains("message-tags") {
                msg.tags.insert("msgid".to_string(), Some(id.to_string()));
            }
        }
        // account-tag: MUST NOT be sent if the user is not identified
        if recipient_caps.contains("account-tag") {
            if let Some(acc) = sender_account {
                msg.tags
                    .insert("account".to_string(), Some(acc.to_string()));
            }
        }
        // bot tag: SHOULD be added to messages from bots, only to clients with message-tags
        if sender.is_bot && recipient_caps.contains("message-tags") {
            msg.tags.insert("bot".to_string(), None);
        }
        // draft/oper-tag: mark messages from an IRC operator for clients that asked.
        if recipient_caps.contains("draft/oper-tag") && recipient_caps.contains("message-tags") {
            if let Some(ref oper_name) = sender.oper {
                msg.tags
                    .insert("draft/oper".to_string(), Some(oper_name.clone()));
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
