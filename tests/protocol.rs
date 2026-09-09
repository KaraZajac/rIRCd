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

/// Length limits are counted in bytes, but the text is whatever a client sent.
/// Slicing at a raw byte index panicked when it landed inside a character —
/// `TOPIC #chan :🎉…` over the limit took the whole server down.
#[test]
fn truncation_never_splits_a_character() {
    use rircd::protocol::truncate_bytes;

    let party = "🎉".repeat(120); // 480 bytes, boundaries only every 4
    let cut = truncate_bytes(&party, 307);
    assert!(cut.len() <= 307);
    assert_eq!(cut.len() % 4, 0, "cut on a character boundary");
    assert!(party.starts_with(cut));

    // Three-byte characters: no boundary at 40 either.
    let cjk = "字".repeat(50);
    assert_eq!(truncate_bytes(&cjk, 40).len(), 39);

    // Untouched when it already fits, and safe at the edges.
    assert_eq!(truncate_bytes("short", 307), "short");
    assert_eq!(truncate_bytes("🎉", 2), "");
    assert_eq!(truncate_bytes("", 10), "");
}

/// A run of spaces is one separator. `WHOIS  nick` — the server argument left
/// out — used to parse as an empty first parameter, so the nick landed in
/// params[1] and WHOIS answered 431 "No nickname given".
#[test]
fn runs_of_spaces_are_one_separator() {
    let msg = parse_message("WHOIS  coolNick").expect("parses");
    assert_eq!(msg.command, "WHOIS");
    assert_eq!(msg.params, vec!["coolNick"]);

    let spaced = parse_message("MODE   #chan    +o    alice").expect("parses");
    assert_eq!(spaced.params, vec!["#chan", "+o", "alice"]);

    // The trailing parameter still keeps the spaces inside it.
    let trailing = parse_message("PRIVMSG #chan  :  hello  world").expect("parses");
    assert_eq!(trailing.params, vec!["#chan", "  hello  world"]);
}

/// An empty last parameter is still a parameter. Without the ':' it is sent as
/// a trailing space, which the peer discards — `PONG server ""` arrived as
/// `PONG server`.
#[test]
fn empty_last_param_keeps_its_colon() {
    let pong = Message::new("PONG", vec!["irc.example.com".into(), String::new()]);
    assert_eq!(format_message(&pong), "PONG irc.example.com :\r\n");

    let parsed = parse_message("PONG irc.example.com :").expect("parses");
    assert_eq!(parsed.params, vec!["irc.example.com", ""]);
}
