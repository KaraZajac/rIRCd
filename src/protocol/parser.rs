use super::message::Message;
use std::collections::HashMap;

const MAX_MESSAGE_BODY: usize = 512;
const MAX_TAG_DATA: usize = 4094;
const MAX_TOTAL_TAGGED: usize = 8191;

/// Parse an IRC message from a line (without CRLF).
/// Returns error if line exceeds limits or is malformed.
pub fn parse_message(line: &str) -> Result<Message, ParseError> {
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
    if remaining.starts_with(':') {
        let (p, rest) = match remaining[1..].find(' ') {
            Some(pos) => (&remaining[1..pos], remaining[pos + 1..].trim_start()),
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
    if body.len() > MAX_MESSAGE_BODY {
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
        if rest.is_empty() {
            break;
        }
        if rest.starts_with(':') {
            params.push(rest[1..].to_string());
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
