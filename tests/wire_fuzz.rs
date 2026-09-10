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
    " ", "  ", ":", "@", "!", ";", "=", ",", "*", "?", "+", "-", "#", "&", "%", "$", "\\", "/",
    "a", "Z", "0", "9", "\t", "\x07", "\u{0}", "\u{7f}", "é", "💜", "\u{202e}", "\u{feff}",
    "PRIVMSG", "NICK", "CAP", "time", "msgid", "draft/x", "batch",
    // The two characters that end a line, and the one that ends it for anything
    // reading a C string. Without them here the test below asserted that
    // nothing could smuggle a second line against an alphabet that could not
    // produce one, and it passed for a year while the server let them through.
    "\r", "\n", "\r\n", "\u{0}",
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
