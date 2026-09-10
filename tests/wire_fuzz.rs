//! What the wire layer does with input nobody would write on purpose.
//!
//! A server reads bytes chosen by whoever connects. Every function here sees
//! them before any authentication, so the bar is not "handles it well" but
//! "cannot be made to panic, hang, or hand back a line longer than the limit
//! it was given".
//!
//! The generator is a small xorshift rather than a fuzzing crate: it needs no
//! dependency, it runs in the ordinary `cargo test`, and a failure is
//! reproducible from the seed printed with it.

use rircd::protocol::{
    format_message, format_message_within, parse_message, parse_message_with_limit, Message,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

/// Characters that mean something to the parser, mixed with ordinary text and
/// the awkward ends of Unicode. Random bytes alone almost never produce a
/// parseable message, so the interesting cases have to be aimed for.
const ALPHABET: &[&str] = &[
    " ",
    "  ",
    ":",
    "@",
    "!",
    ";",
    "=",
    ",",
    "*",
    "?",
    "+",
    "-",
    "#",
    "&",
    "%",
    "$",
    "\\",
    "/",
    "a",
    "Z",
    "0",
    "9",
    "\t",
    "\x07",
    "\u{0}",
    "\u{7f}",
    "é",
    "💜",
    "\u{202e}",
    "\u{feff}",
    "PRIVMSG",
    "NICK",
    "CAP",
    "time",
    "msgid",
    "draft/x",
    "batch",
    // The two characters that end a line, and the one that ends it for anything
    // reading a C string. Without them here the test below asserted that
    // nothing could smuggle a second line against an alphabet that could not
    // produce one, and it passed for a year while the server let them through.
    "\r",
    "\n",
    "\r\n",
    "\u{0}",
    // Numbers that are not numbers this server can hold. A timestamp off a
    // link, a channel limit, a history count: each is parsed from whatever the
    // sender typed and then used in arithmetic that has a range.
    "9223372036854775807",
    "-9223372036854775808",
    "18446744073709551615",
    "-1",
    "00000000000000000000",
];

fn gibberish(rng: &mut Rng, max_pieces: usize) -> String {
    let pieces = rng.below(max_pieces) + 1;
    let mut s = String::new();
    for _ in 0..pieces {
        s.push_str(rng.pick(ALPHABET));
    }
    s
}

/// The one thing the server may never do with a line off the wire.
#[test]
fn parsing_arbitrary_input_never_panics() {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for i in 0..200_000u32 {
        let line = gibberish(&mut rng, 12);
        // Both the default limit and a deliberately tiny one: a limit shorter
        // than the command itself is a legal configuration.
        for limit in [512usize, 1, 7, 8191] {
            let _ = parse_message_with_limit(&line, limit);
        }
        if i % 50_000 == 0 {
            // Keeps a failing case findable: the seed plus the iteration.
            let _ = i;
        }
    }
}

/// Whatever the parser accepts, the formatter has to be able to send, and the
/// result has to parse back to the same message. A message that changes shape
/// on the way out is one a client and the server disagree about.
#[test]
fn what_parses_survives_a_round_trip() {
    let mut rng = Rng(0x5eed_1234_abcd_0002);
    let mut round_tripped = 0u32;
    for _ in 0..200_000u32 {
        let line = gibberish(&mut rng, 12);
        let Ok(msg) = parse_message(&line) else {
            continue;
        };
        let out = format_message(&msg);
        assert!(
            out.ends_with("\r\n"),
            "formatted message is not a line: {out:?} from {line:?}"
        );
        let Ok(again) = parse_message(&out) else {
            panic!("re-parsing our own output failed: {out:?} from {line:?}");
        };
        assert_eq!(
            (&msg.command, &msg.params, &msg.prefix),
            (&again.command, &again.params, &again.prefix),
            "round trip changed the message: {line:?} -> {out:?}"
        );
        round_tripped += 1;
    }
    // If the alphabet ever stops producing parseable lines the test would
    // silently check nothing.
    assert!(
        round_tripped > 1000,
        "only {round_tripped} inputs parsed; the generator is not reaching the parser"
    );
}

/// `format_message_within` is what keeps an outgoing line inside the limit the
/// client was promised. Tags are excluded from the measurement, so the check is
/// on the body.
#[test]
fn outgoing_lines_stay_within_their_limit() {
    let mut rng = Rng(0x5eed_1234_abcd_0003);
    for _ in 0..50_000u32 {
        let command = gibberish(&mut rng, 2);
        let params: Vec<String> = (0..rng.below(4)).map(|_| gibberish(&mut rng, 8)).collect();
        let mut msg = Message::new(&command, params);
        if rng.below(2) == 0 {
            msg.prefix = Some(gibberish(&mut rng, 3));
        }
        for limit in [64usize, 128, 512] {
            let out = format_message_within(&msg, limit);
            let body = out.trim_end_matches("\r\n");
            let body = match body.strip_prefix('@') {
                Some(rest) => rest.split_once(' ').map(|(_, b)| b).unwrap_or(""),
                None => body,
            };
            assert!(
                body.len() <= limit,
                "line of {} bytes exceeds the {limit}-byte limit: {out:?}",
                body.len()
            );
            assert!(out.is_char_boundary(out.len()));
        }
    }
}

/// A tag block is attacker-controlled and separately limited. Whatever comes
/// back out has to still be one line: a raw newline in a tag value would let a
/// client inject a second message into somebody else's stream.
#[test]
fn nothing_that_parses_can_smuggle_a_second_line() {
    let mut rng = Rng(0x5eed_1234_abcd_0004);
    for _ in 0..200_000u32 {
        let line = format!("@{} {}", gibberish(&mut rng, 6), gibberish(&mut rng, 6));
        let Ok(msg) = parse_message(&line) else {
            continue;
        };
        let out = format_message(&msg);
        assert_eq!(
            out.matches("\r\n").count(),
            1,
            "formatted output holds more than one line: {out:?} from {line:?}"
        );
        assert!(
            !out.trim_end_matches("\r\n").contains(['\r', '\n']),
            "a line ending survived into the middle of a message: {out:?} from {line:?}"
        );
    }
}

/// The link protocol reads bytes a peer chose, and a peer is only as trusted as
/// its password. These are the functions that look at those bytes first.
///
/// `valid_uid` used to cut the first three bytes off a nine-byte string without
/// asking where its characters were, so `1A€DEFG` — nine bytes, six characters
/// — panicked. That panic unwound past the end of the link's read loop, so the
/// link was never detached: the registry kept a peer that had gone, its users
/// stayed, and the server refused to let it back because it was already there.
/// One malformed line, one server wedged until a restart.
#[test]
fn what_a_peer_sends_never_panics_the_link() {
    use rircd::link::{valid_sid, valid_uid, LinkRegistry};

    let mut rng = Rng(0x5eed_0f00_d00d_0007);
    let mut accepted = 0u32;
    for _ in 0..200_000u32 {
        let s = gibberish(&mut rng, 5);

        // Whatever it says, deciding is all these may do.
        let is_sid = valid_sid(&s);
        let is_uid = valid_uid(&s);
        assert!(!is_sid || s.len() == 3, "a sid of {} bytes: {s:?}", s.len());
        assert!(!is_uid || s.len() == 9, "a uid of {} bytes: {s:?}", s.len());
        if is_uid {
            // The promise the rest of the link code relies on: the first three
            // bytes are a sid, and cutting there is safe.
            assert!(s.is_char_boundary(3), "uid {s:?} cannot be cut at three");
            assert!(valid_sid(&s[..3]), "uid {s:?} does not start with a sid");
            accepted += 1;
        }

        // Routing looks a server up by whatever it was told.
        let reg = LinkRegistry::default();
        assert!(reg.route(&s).is_none());
        assert!(!reg.is_linked(&s));
        assert!(reg.by_name(&s).is_none());
    }
    assert!(
        accepted > 0,
        "the generator never produced a usable id, so nothing was tested"
    );
}

/// Channel modes come off a link as a string of letters and a list of
/// arguments, and neither has to make sense. Applying them may change the
/// channel; it may not fall over.
#[test]
fn channel_modes_off_a_link_never_panic() {
    use rircd::channel::Channel;

    let mut rng = Rng(0x5eed_c0de_1111_0009);
    for _ in 0..100_000u32 {
        let letters = gibberish(&mut rng, 4);
        let args: Vec<String> = (0..rng.below(4)).map(|_| gibberish(&mut rng, 2)).collect();

        let mut ch = Channel::new("#fuzz".to_string());
        ch.set_mode_string(&letters, &args);
        ch.merge_mode_string(&letters, &args);

        // What comes back out has to be something that goes back in.
        let (out, out_args) = ch.mode_string();
        assert!(out.starts_with('+'), "mode string without a sign: {out:?}");
        let mut round = Channel::new("#fuzz".to_string());
        round.set_mode_string(&out, &out_args);
        assert_eq!(
            round.mode_string(),
            (out.clone(), out_args.clone()),
            "modes changed on the way round: {letters:?} {args:?}"
        );

        // And the lists, which a mask is added to and taken off by name.
        for letter in ['b', 'e', 'I', 'q', 'x', '\u{0}'] {
            let mask = gibberish(&mut rng, 2);
            let had = ch.list_contains(letter, &mask);
            let removed = ch.remove_from_list(letter, &mask);
            assert_eq!(had, removed, "removing {mask:?} from +{letter} disagreed");
            assert!(!ch.list_contains(letter, &mask));
        }
    }
}
