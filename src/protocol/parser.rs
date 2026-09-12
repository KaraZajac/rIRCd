use super::message::Message;
use std::collections::HashMap;

/// The protocol's own limit on a message body. An operator may raise it — some
/// servers do, and clients that send long SASL responses or passwords need it —
/// so it is the default rather than a hard ceiling.
pub const DEFAULT_MAX_MESSAGE_BODY: usize = 512;
const MAX_TAG_DATA: usize = 4094;
/// The longest a whole line may be, tags included, for a caller using the
/// protocol's own body limit. Tags are counted separately from the body and
/// have far more room, so this is the bound on what one line can cost to read.
///
/// A caller that allows a larger body — a server link, whose burst lines name
/// every member of a channel — gets a total large enough to hold it. Without
/// that, the larger body limit was unreachable: the line was turned away here
/// before anything looked at the body, and a channel with enough members in it
/// simply failed to cross a link, saying nothing about why.
pub const MAX_TOTAL_TAGGED: usize = 8191;

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

    let total_allowed = MAX_TOTAL_TAGGED.max(max_body.saturating_add(MAX_TAG_DATA));
    if line.len() > total_allowed {
        return Err(ParseError::InputTooLong);
    }

    // A carriage return or a line feed left inside the line is not content: it
    // is a second message somebody is trying to smuggle through the first. A
    // bare CR survives reading up to the newline, and a WebSocket frame is
    // delimited by the frame and not by either character at all — so the only
    // place that can refuse it for every transport at once is here. NUL goes
    // with them: it ends the line for anything reading it as a C string, and no
    // specification has ever allowed one in a message.
    if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(ParseError::ForbiddenCharacter);
    }

    // Leading spaces are separator, never content: a line may not begin with a
    // parameter, and trimming here means the prefix and command are found
    // wherever they actually start.
    let mut remaining = line.trim_start_matches(' ');

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

    // A run of spaces where the command should be is separator, not a command;
    // a line without one is not a message.
    remaining = remaining.trim_start_matches(' ');
    if remaining.is_empty() {
        return Err(ParseError::Malformed);
    }

    // Parse command and params
    let parts: Vec<&str> = remaining.splitn(2, ' ').collect();
    if !is_command_token(parts[0]) {
        return Err(ParseError::Malformed);
    }
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
                // Only spaces separate parameters. Trimming whitespace here
                // would eat a tab that belongs to the next one, and a tab is
                // an ordinary character in an IRC parameter — the run of
                // spaces is handled at the top of the loop.
                rest = &rest[pos + 1..];
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

/// Whether a token can be a command without changing meaning on the way back
/// out.
///
/// A command the server does not know is answered with 421, so this is not the
/// place to be strict about names — it is the place to refuse the two shapes
/// that would be read as something other than a command when the message is
/// serialised again. One starting with ':' becomes a prefix to whoever reads
/// the line, which would let a client choose the apparent source of a message;
/// one starting with '@' becomes a tag block.
fn is_command_token(s: &str) -> bool {
    !s.is_empty() && !s.starts_with(':') && !s.starts_with('@')
}

#[derive(Debug, Clone)]
pub enum ParseError {
    Malformed,
    InputTooLong,
    /// A CR, LF or NUL inside the line, where only the end of it may have a
    /// terminator and none of the three may appear at all.
    ForbiddenCharacter,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Malformed => write!(f, "Malformed message"),
            ParseError::InputTooLong => write!(f, "Input line was too long"),
            ParseError::ForbiddenCharacter => {
                write!(f, "Message contained a carriage return, line feed or NUL")
            }
        }
    }
}

impl std::error::Error for ParseError {}
