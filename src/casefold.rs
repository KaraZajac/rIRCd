//! How this server decides that two names are the same name.
//!
//! IRC has never agreed on it. `ascii` folds A–Z and nothing else, and is what
//! a network started today should use. `rfc1459` also folds `[]\~` onto
//! `{}|^`, because the terminals of 1993 treated them as the same letters, and
//! a network that has been running since then cannot change its mind without
//! renaming its channels.
//!
//! The choice is server-wide and is made once, at startup, so it lives here
//! rather than being carried into every comparison. Two servers on one network
//! must agree on it; a link between servers that disagree would put the same
//! channel in two places.

use std::sync::atomic::{AtomicBool, Ordering};

static RFC1459: AtomicBool = AtomicBool::new(false);

/// Set from the configuration at startup. Unknown names fall back to `ascii`,
/// which is the one a network should be using unless it has a reason.
pub fn configure(name: &str) -> &'static str {
    let rfc = name.eq_ignore_ascii_case("rfc1459");
    RFC1459.store(rfc, Ordering::Relaxed);
    current()
}

/// The name to advertise in `CASEMAPPING`.
pub fn current() -> &'static str {
    if RFC1459.load(Ordering::Relaxed) {
        "rfc1459"
    } else {
        "ascii"
    }
}

fn rfc1459() -> bool {
    RFC1459.load(Ordering::Relaxed)
}

/// An identifier folded down: a nick, a channel, an account, a mask.
///
/// Used wherever two names are compared, and never for anything that is not a
/// name — a mode letter or a command is not an identifier and does not fold.
pub fn lower(s: &str) -> String {
    fold_lower(s, rfc1459())
}

/// The fold itself, with the choice passed in rather than read. Everything that
/// decides whether two names are equal goes through here.
///
/// Only ASCII folds, whichever mapping is in use. `CASEMAPPING=ascii` promises
/// a client that "the characters a to z are the lower-case equivalents of the
/// characters A to Z" and of nothing else; `rfc1459` adds four more ASCII
/// characters to that and no others. Folding the rest of Unicode as well would
/// be this server quietly disagreeing with every client that implements the
/// mapping it was told about — `CAFÉ` and `café` would be one person here and
/// two people to them, and a ban on one would appear not to match the other.
fn fold_lower(s: &str, rfc1459: bool) -> String {
    let base = s.to_ascii_lowercase();
    if !rfc1459 {
        return base;
    }
    base.chars().map(lower_char).collect()
}

/// The same fold, written the other way up. Both exist because the tables that
/// use them were written before the fold was a function, and a name folded up
/// and a name folded down are the same comparison.
pub fn upper(s: &str) -> String {
    fold_upper(s, rfc1459())
}

fn fold_upper(s: &str, rfc1459: bool) -> String {
    let base = s.to_ascii_uppercase();
    if !rfc1459 {
        return base;
    }
    base.chars().map(upper_char).collect()
}

fn lower_char(c: char) -> char {
    match c {
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        '~' => '^',
        c => c,
    }
}

fn upper_char(c: char) -> char {
    match c {
        '{' => '[',
        '}' => ']',
        '|' => '\\',
        '^' => '~',
        c => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ascii` folds A–Z and nothing else: a channel named with brackets is not
    /// the same channel as one named with braces.
    #[test]
    fn ascii_folds_letters_and_leaves_punctuation_alone() {
        assert_eq!(fold_lower("#Foo", false), "#foo");
        assert_eq!(fold_lower("#F]|oo{", false), "#f]|oo{");
        assert_eq!(fold_upper("#f}\\oo[", false), "#F}\\OO[");
        assert_ne!(fold_lower("#F]|oo{", false), fold_lower("#f}\\oo[", false));
    }

    /// On an rfc1459 network `#F]|oo{` and `#f}\oo[` are one channel, and a
    /// server that got that wrong would hand somebody an empty room with the
    /// name of a full one.
    #[test]
    fn rfc1459_folds_the_bracket_pairs_too() {
        assert_eq!(fold_lower("#F]|oo{", true), fold_lower("#f}\\oo[", true));
        assert_eq!(fold_upper("#F]|oo{", true), fold_upper("#f}\\oo[", true));
        assert_eq!(fold_lower("nick~", true), fold_lower("NICK^", true));
        // Still not the same as a name that merely looks close.
        assert_ne!(fold_lower("#Foo", true), fold_lower("#fooa", true));
    }

    /// Folding up and folding down have to agree about which names are equal,
    /// because both are used, in different tables, for the same question.
    #[test]
    fn the_two_directions_agree() {
        for rfc in [false, true] {
            for (a, b) in [
                ("Foo", "foo"),
                ("#F]|oo{", "#f}\\oo["),
                ("nick~", "NICK^"),
                ("a", "b"),
                ("#Foo", "#fooa"),
            ] {
                assert_eq!(
                    fold_lower(a, rfc) == fold_lower(b, rfc),
                    fold_upper(a, rfc) == fold_upper(b, rfc),
                    "rfc1459={rfc}: {a} vs {b}"
                );
            }
        }
    }

    /// `CASEMAPPING` is a promise to the client about which characters fold,
    /// and both mappings promise ASCII only. A server that folded the rest of
    /// Unicode as well would be telling a client that `CAFÉ` and `café` are two
    /// names while treating them as one — so a member list would be one short,
    /// and a ban the server applied would look to the client like a ban that
    /// did not match.
    #[test]
    fn only_ascii_folds_whichever_mapping_is_in_use() {
        for rfc in [false, true] {
            assert_eq!(fold_lower("CAFE", rfc), "cafe", "ASCII still folds");
            assert_ne!(
                fold_lower("CAFÉ", rfc),
                fold_lower("café", rfc),
                "rfc1459={rfc}: É is not a letter either mapping folds"
            );
            assert_ne!(
                fold_upper("Straße", rfc),
                fold_upper("STRASSE", rfc),
                "rfc1459={rfc}: nor is ß, which Unicode uppercases to two letters"
            );
            // And the fold must not change the length of a name, or an
            // identifier could outgrow the limit it was checked against.
            for name in ["café", "ΣΣΣ", "Straße", "ǅ"] {
                assert_eq!(fold_lower(name, rfc).len(), name.len(), "{name}");
                assert_eq!(fold_upper(name, rfc).len(), name.len(), "{name}");
            }
        }
    }

    /// The default has to be the one a new network wants, whatever is in the
    /// configuration file — including nothing, or a name nobody recognises.
    #[test]
    fn an_unknown_name_falls_back_to_ascii() {
        assert_eq!(configure("rfc1459"), "rfc1459");
        assert_eq!(configure("RFC1459"), "rfc1459");
        assert_eq!(configure("ascii"), "ascii");
        assert_eq!(configure("strict-rfc1459"), "ascii");
        assert_eq!(configure(""), "ascii");
    }
}
