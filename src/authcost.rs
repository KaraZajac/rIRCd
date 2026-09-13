//! What failing to log in costs, and how fast that is forgiven.
//!
//! Checking a password is deliberately expensive — that is the whole point of
//! the hash — so every attempt is a piece of this server's work that the
//! client chose to spend. Getting it right is not the problem: a gateway with a
//! thousand people behind it logs a thousand people in and costs one check
//! each. Getting it wrong over and over is the problem, and nothing in the
//! protocol stops a client doing that as fast as it can type.
//!
//! So only failures are counted, and they are counted against the address that
//! caused them. An address that has spent its allowance is not refused — the
//! person behind it may be a neighbour of whoever is guessing, and telling them
//! their own password is wrong would be a lie. It is made to wait instead. The
//! wait costs the server nothing, because nothing waits with it: the check
//! itself does not run on the loop that serves everybody else.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Failed checks an address may have outstanding before it starts waiting.
///
/// Somebody who mistypes a password tries again, and a client that offers a
/// stale token retries once it has a fresh one. Nobody gets it wrong eight
/// times in ten seconds and means it.
const FAILURE_BURST: f64 = 8.0;

/// Failures forgiven per second: one every ten seconds.
///
/// Slow enough that guessing is not worth attempting, fast enough that a
/// person who really did forget their password is not kept waiting all evening.
const FORGIVEN_PER_SEC: f64 = 0.1;

/// How much longer each failure past the allowance makes the next one wait.
const WAIT_PER_EXCESS: Duration = Duration::from_millis(1500);

/// The longest an attempt is ever made to wait.
///
/// Long enough that guessing is pointless — one try every few seconds, from
/// that address, no matter how many connections it opens — and short enough
/// that a real client is still waiting for the answer when it arrives.
const MAX_WAIT: Duration = Duration::from_secs(6);

/// Addresses remembered at once.
///
/// The key is whoever connected, so without a ceiling this is one more table a
/// client can put things in. Entries that have been fully forgiven are dropped
/// before a new one is added, so the ceiling is only reached when that many
/// addresses are actively failing.
const MAX_TRACKED: usize = 8192;

#[derive(Debug)]
struct Spent {
    amount: f64,
    at: Instant,
}

/// How much each address has spent failing to log in.
#[derive(Debug, Default)]
pub struct AuthCost {
    by_address: HashMap<String, Spent>,
}

impl AuthCost {
    /// Charge one check to `address` and say how long it should wait first.
    ///
    /// Zero for an address that has not been failing. An address that has is
    /// made to wait, which is what bounds how much of this server's work it can
    /// spend — never refused, because the credentials it is offering this time
    /// may well be right.
    pub fn spend(&mut self, address: &str) -> Duration {
        let address = &crate::client::limit_key_for(address);
        let now = Instant::now();
        if let Some(spent) = self.by_address.get_mut(address) {
            spent.forgive(now);
            spent.amount += 1.0;
            return wait_for(spent.amount);
        }
        self.forget_settled(now);
        if self.by_address.len() < MAX_TRACKED {
            self.by_address.insert(
                address.to_string(),
                Spent {
                    amount: 1.0,
                    at: now,
                },
            );
        }
        // More addresses are failing at once than this table can hold. Waiting
        // is not what keeps the server up — running the check somewhere other
        // than the loop everybody shares is — so an untracked address goes
        // ahead rather than being punished for arriving late.
        Duration::ZERO
    }

    /// Give the allowance back: the credentials were right, so that check was
    /// one somebody wanted.
    pub fn refund(&mut self, address: &str) {
        let address = &crate::client::limit_key_for(address);
        let now = Instant::now();
        if let Some(spent) = self.by_address.get_mut(address) {
            spent.forgive(now);
            spent.amount = (spent.amount - 1.0).max(0.0);
            if spent.amount <= 0.0 {
                self.by_address.remove(address);
            }
        }
    }

    /// Drop the addresses that have nothing left outstanding.
    fn forget_settled(&mut self, now: Instant) {
        self.by_address.retain(|_, spent| {
            spent.forgive(now);
            spent.amount > 0.0
        });
    }

    /// How many addresses are being remembered. For tests.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.by_address.len()
    }
}

fn wait_for(amount: f64) -> Duration {
    let excess = amount - FAILURE_BURST;
    if excess <= 0.0 {
        return Duration::ZERO;
    }
    WAIT_PER_EXCESS.mul_f64(excess).min(MAX_WAIT)
}

impl Spent {
    fn forgive(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.at).as_secs_f64();
        self.amount = (self.amount - elapsed * FORGIVEN_PER_SEC).max(0.0);
        self.at = now;
    }
}

/// Something that may happen to one key only so often.
///
/// Registering and resetting both send mail to an address the client chose,
/// and asking is free. Whatever else limits the asker, the address itself
/// needs a say: one message per gap, however many people ask for it and from
/// wherever they ask. Keys that are past their gap are dropped as they are
/// met, so the table holds only what is still cooling.
#[derive(Debug, Default)]
pub struct Cooldown {
    last: HashMap<String, Instant>,
}

impl Cooldown {
    /// Whether `key` could go ahead now. Records nothing: the answer is asked
    /// for before the work that might still fail for another reason, and a
    /// slot spent on a registration refused for its password would keep the
    /// person's real attempt out.
    pub fn would_allow(&self, key: &str, gap: Duration) -> bool {
        let now = Instant::now();
        match self.last.get(&key.to_lowercase()) {
            Some(when) => now.duration_since(*when) >= gap,
            None => self.last.len() < MAX_TRACKED,
        }
    }

    /// Record that `key` went ahead: the message is going out.
    pub fn record(&mut self, key: &str, gap: Duration) {
        let now = Instant::now();
        self.last.retain(|_, when| now.duration_since(*when) < gap);
        if self.last.len() >= MAX_TRACKED {
            // More keys cooling than this will remember. Refusing later is the
            // safe side: the cost of a wrongly refused mail is a retry, the
            // cost of a wrongly sent one is somebody's inbox.
            return;
        }
        self.last.insert(key.to_lowercase(), now);
    }

    /// Whether `key` may go ahead now, recording it if so.
    pub fn allow(&mut self, key: &str, gap: Duration) -> bool {
        if !self.would_allow(key, gap) {
            return false;
        }
        self.record(key, gap);
        true
    }
}

/// So many of something per key per window, and then no more until the
/// window has moved on.
///
/// The failed-login budget forgives slowly and never refuses, which is right
/// for a person who may well be about to get it right. Registering is not
/// that: thirty in ten minutes from one address is what an office behind one
/// NAT does on its first day, and a hundred is a script.
#[derive(Debug, Default)]
pub struct RateWindow {
    seen: HashMap<String, std::collections::VecDeque<Instant>>,
}

impl RateWindow {
    /// Whether `key` may have another now, and records it if so. `max` of 0
    /// means no limit.
    pub fn allow(&mut self, key: &str, max: usize, window: Duration) -> bool {
        if max == 0 {
            return true;
        }
        let now = Instant::now();
        let key = crate::client::limit_key_for(key);
        if !self.seen.contains_key(&key) {
            self.seen.retain(|_, when| {
                while when.front().is_some_and(|t| now.duration_since(*t) > window) {
                    when.pop_front();
                }
                !when.is_empty()
            });
            if self.seen.len() >= MAX_TRACKED {
                return false;
            }
        }
        let when = self.seen.entry(key).or_default();
        while when.front().is_some_and(|t| now.duration_since(*t) > window) {
            when.pop_front();
        }
        if when.len() >= max {
            return false;
        }
        when.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_holds_so_many_and_no_more() {
        let mut rate = RateWindow::default();
        for i in 0..3 {
            assert!(rate.allow("198.51.100.7", 3, Duration::from_secs(600)), "{i}");
        }
        assert!(!rate.allow("198.51.100.7", 3, Duration::from_secs(600)));
        assert!(rate.allow("203.0.113.9", 3, Duration::from_secs(600)), "somebody else");
        assert!(rate.allow("198.51.100.7", 0, Duration::from_secs(600)), "zero is no limit");
        // The same /64 is the same key.
        assert!(rate.allow("2001:db8::1", 1, Duration::from_secs(600)));
        assert!(!rate.allow("2001:db8::2", 1, Duration::from_secs(600)));
    }

    #[test]
    fn a_key_goes_once_per_gap() {
        let mut cool = Cooldown::default();
        assert!(cool.allow("Alice@Example.org", Duration::from_secs(60)));
        assert!(!cool.allow("alice@example.org", Duration::from_secs(60)), "case is one key");
        assert!(cool.allow("bob@example.org", Duration::from_secs(60)));
        if let Some(when) = cool.last.get_mut("alice@example.org") {
            *when -= Duration::from_secs(61);
        }
        assert!(cool.allow("alice@example.org", Duration::from_secs(60)), "the gap has passed");
    }

    #[test]
    fn a_burst_of_failures_costs_nothing_and_then_it_costs_time() {
        let mut cost = AuthCost::default();
        for i in 0..FAILURE_BURST as usize {
            assert_eq!(
                cost.spend("198.51.100.7"),
                Duration::ZERO,
                "check {i} should not have to wait"
            );
        }
        assert!(
            cost.spend("198.51.100.7") > Duration::ZERO,
            "the one past the allowance waits"
        );
    }

    #[test]
    fn no_one_is_ever_refused_outright() {
        let mut cost = AuthCost::default();
        let mut longest = Duration::ZERO;
        for _ in 0..1000 {
            longest = longest.max(cost.spend("198.51.100.7"));
        }
        assert!(longest <= MAX_WAIT, "the wait is capped at {MAX_WAIT:?}");
    }

    #[test]
    fn one_address_spending_does_not_delay_another() {
        let mut cost = AuthCost::default();
        for _ in 0..FAILURE_BURST as usize + 20 {
            cost.spend("198.51.100.7");
        }
        assert_eq!(cost.spend("203.0.113.9"), Duration::ZERO);
    }

    #[test]
    fn getting_it_right_costs_nothing() {
        let mut cost = AuthCost::default();
        for _ in 0..1000 {
            assert_eq!(cost.spend("198.51.100.7"), Duration::ZERO);
            cost.refund("198.51.100.7");
        }
        assert_eq!(cost.tracked(), 0, "nothing outstanding, nothing remembered");
    }

    #[test]
    fn time_forgives() {
        let mut cost = AuthCost::default();
        for _ in 0..FAILURE_BURST as usize + 1 {
            cost.spend("198.51.100.7");
        }
        assert!(cost.spend("198.51.100.7") > Duration::ZERO);
        // A minute ago is six failures forgiven.
        let entry = cost.by_address.get_mut("198.51.100.7").unwrap();
        entry.at -= Duration::from_secs(60);
        assert_eq!(cost.spend("198.51.100.7"), Duration::ZERO);
    }

    #[test]
    fn settled_addresses_are_not_remembered_for_ever() {
        let mut cost = AuthCost::default();
        for i in 0..MAX_TRACKED + 64 {
            let address = format!("198.51.100.{i}");
            cost.spend(&address);
            // Long enough ago that this address has nothing left outstanding.
            let entry = cost.by_address.get_mut(&address).unwrap();
            entry.at -= Duration::from_secs(3600);
        }
        assert!(
            cost.tracked() <= 1,
            "addresses that settled are dropped, not piled up: {} left",
            cost.tracked()
        );
    }

    #[test]
    fn addresses_that_keep_failing_do_not_grow_past_the_ceiling() {
        let mut cost = AuthCost::default();
        for i in 0..MAX_TRACKED * 2 {
            cost.spend(&format!("198.51.100.{i}"));
        }
        assert!(cost.tracked() <= MAX_TRACKED, "{} tracked", cost.tracked());
    }
}
