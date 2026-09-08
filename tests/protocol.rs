//! Wire-format tests for the protocol layer.

use rircd::protocol::{format_message, parse_message, Message};

/// `format_message` adds the trailing `:` itself, so callers must pass the bare
/// text as the last parameter — a param written as `" :text"` would be sent as
/// `: :text` and reach the client with a stray colon and leading space.
#[test]
fn trailing_param_gets_exactly_one_colon() {
    let msg = Message::new(
        "REGISTER",
        vec![
            "SUCCESS".into(),
            "alice".into(),
            "Account successfully registered".into(),
        ],
    )
    .with_prefix("irc.example.com");

    assert_eq!(
        format_message(&msg),
        ":irc.example.com REGISTER SUCCESS alice :Account successfully registered\r\n"
    );
}

#[test]
fn standard_reply_fail_format() {
    let msg = Message::new(
        "FAIL",
        vec![
            "VERIFY".into(),
            "INVALID_CODE".into(),
            "alice".into(),
            "Invalid or expired code".into(),
        ],
    )
    .with_prefix("irc.example.com");

    assert_eq!(
        format_message(&msg),
        ":irc.example.com FAIL VERIFY INVALID_CODE alice :Invalid or expired code\r\n"
    );
}

/// A single-word last param needs no colon, and one that already starts with ':'
/// is escaped so it survives the round trip.
#[test]
fn last_param_colon_rules() {
    let no_spaces = Message::new("PING", vec!["token123".into()]);
    assert_eq!(format_message(&no_spaces), "PING token123\r\n");

    let leading_colon = Message::new("PRIVMSG", vec!["#chan".into(), ":-)".into()]);
    assert_eq!(format_message(&leading_colon), "PRIVMSG #chan ::-)\r\n");
}

#[test]
fn round_trip_through_parser() {
    let line = ":irc.example.com 900 alice alice!u@host alice :You are now logged in as alice";
    let parsed = parse_message(line).expect("parses");

    assert_eq!(parsed.command, "900");
    assert_eq!(parsed.prefix.as_deref(), Some("irc.example.com"));
    assert_eq!(parsed.trailing(), Some("You are now logged in as alice"));
    assert_eq!(format_message(&parsed), format!("{}\r\n", line));
}

/// Regression: the prefix used to be cut one character short, because the space
/// was located in `line[1..]` but indexed as an absolute offset into `line`.
#[test]
fn prefix_keeps_its_last_character() {
    let msg = parse_message(":nick!user@host PRIVMSG #chan :hi").expect("parses");

    assert_eq!(msg.prefix.as_deref(), Some("nick!user@host"));
    assert_eq!(msg.command, "PRIVMSG");
    assert_eq!(msg.params, vec!["#chan", "hi"]);
}

#[test]
fn parses_tags_and_unescapes_values() {
    let msg = parse_message("@time=2026-09-07T12:00:00.000Z;+draft/edit=abc PRIVMSG #chan :hi")
        .expect("parses");

    assert_eq!(
        msg.tags.get("time").and_then(|v| v.clone()).as_deref(),
        Some("2026-09-07T12:00:00.000Z")
    );
    assert_eq!(
        msg.tags
            .get("+draft/edit")
            .and_then(|v| v.clone())
            .as_deref(),
        Some("abc")
    );
    assert_eq!(msg.trailing(), Some("hi"));
}
