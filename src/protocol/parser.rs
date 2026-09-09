use super::message::Message;
use std::collections::HashMap;

/// The protocol's own limit on a message body. An operator may raise it — some
/// servers do, and clients that send long SASL responses or passwords need it —
/// so it is the default rather than a hard ceiling.
pub const DEFAULT_MAX_MESSAGE_BODY: usize = 512;
const MAX_TAG_DATA: usize = 4094;
const MAX_TOTAL_TAGGED: usize = 8191;

/// Parse an IRC message from a line (without CRLF).
/// Returns error if line exceeds limits or is malformed.
pub fn parse_message(line: &str) -> Result<Message, ParseError> {
    parse_message_with_limit(line, DEFAULT_MAX_MESSAGE_BODY)
}

pub fn parse_message_with_limit(line: &str, max_body: usize) -> Result<Message, ParseError> {
    let line = line
        .trim_end_matches("\r\n")
        .trim_end_matches('\n')
        .trim_end_matches('\r');

    if line.len() > MAX_TOTAL_TAGGED {
        return Err(ParseError::InputTooLong);
    }

    let mut remaining = line;

    // Parse optional tags
    let mut tags = HashMap::new();
    if remaining.starts_with('@') {
        let (tag_str, rest) = match remaining.find(' ') {
            Some(pos) => (&remaining[1..pos], remaining[pos + 1..].trim_start()),
            None => return Err(ParseError::Malformed),
        };
        if tag_str.len() > MAX_TAG_DATA {
            return Err(ParseError::InputTooLong);
        }
        for part in tag_str.split(';') {
            if let Some((k, v)) = part.split_once('=') {
                let value = if v.is_empty() {
                    None
                } else {
                    Some(unescape_tag_value(v))
                };
                tags.insert(k.to_string(), value);
            } else {
                tags.insert(part.to_string(), None);
            }
        }
        remaining = rest;
    }

    // Parse optional prefix
    let mut prefix = None;
    if let Some(after_colon) = remaining.strip_prefix(':') {
        let (p, rest) = match after_colon.split_once(' ') {
            Some((p, rest)) => (p, rest.trim_start()),
            None => return Err(ParseError::Malformed),
        };
        prefix = Some(p.to_string());
        remaining = rest;
    }

    if remaining.is_empty() {
        return Err(ParseError::Malformed);
    }

    // Parse command and params
    let parts: Vec<&str> = remaining.splitn(2, ' ').collect();
    let command = parts[0].to_uppercase();
    let params = if parts.len() > 1 {
        parse_params(parts[1])?
    } else {
        Vec::new()
    };

    // Check body length (from prefix or command onwards)
    let body_start = if tags.is_empty() {
        0
    } else {
        line.find(' ').map(|p| p + 1).unwrap_or(0)
    };
    let body = &line[body_start.min(line.len())..];
    if body.len() > max_body {
        return Err(ParseError::InputTooLong);
    }

    Ok(Message {
        tags,
        prefix,
        command,
        params,
    })
}

fn parse_params(s: &str) -> Result<Vec<String>, ParseError> {
    let mut params = Vec::new();
    let mut rest = s;

    loop {
        // One or more spaces separate parameters (RFC 1459 §2.3.1), so runs of
        // them are one separator, not empty parameters between them. Clients do
        // send them: an omitted optional argument, as in `WHOIS  nick`, leaves
        // two spaces behind.
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            break;
        }
        if let Some(stripped) = rest.strip_prefix(':') {
            params.push(stripped.to_string());
            break;
        }
        match rest.find(' ') {
            Some(pos) => {
                params.push(rest[..pos].to_string());
                rest = rest[pos + 1..].trim_start();
            }
            None => {
                params.push(rest.to_string());
                break;
            }
        }
    }

    Ok(params)
}

fn unescape_tag_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => result.push('\\'),
                Some(';') => result.push(';'),
                Some('s') => result.push(' '),
                Some('r') => result.push('\r'),
                Some('n') => result.push('\n'),
                Some(':') => result.push(';'), // spec: \: = semicolon
                Some(other) => result.push(other),
                None => {}
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[derive(Debug, Clone)]
pub enum ParseError {
    Malformed,
    InputTooLong,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Malformed => write!(f, "Malformed message"),
            ParseError::InputTooLong => write!(f, "Input line was too long"),
        }
    }
}

impl std::error::Error for ParseError {}
