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

/// A relayed message grows by its `:nick!user@host ` prefix. If that pushes the
/// line past the limit the server must shorten it, rather than leaving the peer
/// to cut it at a byte that may be mid-character.
#[test]
fn outgoing_lines_are_kept_within_the_limit() {
    use rircd::protocol::format_message_within;

    let long = "x".repeat(500);
    let msg = Message::new("PRIVMSG", vec!["#chan".into(), long])
        .with_prefix("someone!user@host.example.com");

    let line = format_message_within(&msg, 510);
    assert_eq!(line.len(), 512, "510 bytes of content plus CRLF");
    assert!(line.ends_with("\r\n"));

    // A message that already fits is untouched.
    let short = Message::new("PRIVMSG", vec!["#chan".into(), "hi".into()]).with_prefix("a!b@c");
    assert_eq!(format_message_within(&short, 510), format_message(&short));
}

/// A command the server does not know still has to reach the handler that
/// answers 421 — but one that would be read back as a prefix or a tag block
/// must not, because that would let a client choose the apparent source of a
/// message it sent.
#[test]
fn a_command_may_be_unknown_but_not_unreadable() {
    use rircd::protocol::parse_message;

    // Unknown, oddly spelled, but still a command: these get 421, not silence.
    for line in [
        "PRIVMSG #chan :hi",
        "001 nick :Welcome",
        ":server 366 nick #chan :End",
        "NONEXISTENT_COMMAND",
        "draft/x #chan",
        "12 nick",
    ] {
        assert!(parse_message(line).is_ok(), "{line:?} was refused");
    }

    for line in [
        "@tag=1 ", // tags do not make a command out of nothing
        " ",       // a line of separator is not a message
        "   ",
        ":prefix   ",
        ":prefix", // a prefix with nothing after it is not a message either
    ] {
        assert!(
            parse_message(line).is_err(),
            "{line:?} was accepted as a message"
        );
    }
}

/// The limit is a promise: LINELEN says what the longest line will be, and a
/// client is entitled to hold the server to it even when the prefix and
/// command alone are longer than that.
#[test]
fn a_line_never_exceeds_the_limit_it_was_given() {
    use rircd::protocol::format_message_within;

    let msg = Message::new("PRIVMSG", vec!["#chan".into(), "x".repeat(200)])
        .with_prefix("averylongnickname!averylongusername@a.very.long.hostname.example.com");

    for limit in [16usize, 32, 64, 100, 512] {
        let line = format_message_within(&msg, limit);
        let body = line.trim_end_matches("\r\n");
        assert!(
            body.len() <= limit,
            "{} bytes for a {limit}-byte limit: {line:?}",
            body.len()
        );
    }
}

/// One message is one line. A carriage return or a line feed left inside a
/// message would end it early, and everything after would reach the reader
/// looking exactly like something the server had said — a forged PRIVMSG from
/// anyone, a numeric that never happened.
///
/// A bare CR survives reading up to the newline, and a WebSocket frame is
/// delimited by the frame rather than by either character, so the refusal has
/// to be in the parser, where every transport passes.
#[test]
fn a_message_may_not_smuggle_a_second_one() {
    use rircd::protocol::parse_message;

    for hostile in [
        "PRIVMSG #chan :hi\r:evil!e@e PRIVMSG #chan :forged",
        "PRIVMSG #chan :hi\n:evil!e@e PRIVMSG #chan :forged",
        "PRIVMSG #chan :hi\r\n:evil!e@e PRIVMSG #chan :forged",
        "NICK a\rb",
        "@tag=x\ry PRIVMSG #chan :hi",
        "\rPING x",
        "PING to\0ken",
    ] {
        assert!(
            parse_message(hostile).is_err(),
            "accepted a line with an embedded terminator: {hostile:?}"
        );
    }

    // The terminator the line legitimately ends with is still fine.
    assert!(parse_message("PING token\r\n").is_ok());
    assert!(parse_message("PING token\n").is_ok());
    assert!(parse_message("PING token\r").is_ok());
}

/// The same promise from the other side. Nothing a client sends can carry a
/// terminator any more, but a topic out of the database, a line of MOTD from a
/// configuration file, or a name a linked server chose has never been through
/// the parser — and one message still has to be one line.
#[test]
fn nothing_written_out_can_end_the_line_early() {
    let hostile = "innocent\r\n:evil!e@e PRIVMSG #chan :forged";
    let cases = [
        Message::new("PRIVMSG", vec!["#chan".into(), hostile.into()]),
        Message::new("332", vec!["nick".into(), "#chan".into(), hostile.into()]),
        Message::new("PRIVMSG", vec!["#chan".into(), "hi".into()])
            .with_prefix("evil\r\n:server 001 you :welcome"),
        Message::new("NOTICE", vec!["nick".into(), "a\0b".into()]),
    ];
    for msg in cases {
        let line = format_message(&msg);
        assert_eq!(
            line.matches("\r\n").count(),
            1,
            "more than one line came out of one message: {line:?}"
        );
        assert!(line.ends_with("\r\n"), "{line:?}");
        let body = line.trim_end_matches("\r\n");
        assert!(
            !body.contains('\r') && !body.contains('\n') && !body.contains('\0'),
            "a terminator survived into the body: {body:?}"
        );
    }
}
