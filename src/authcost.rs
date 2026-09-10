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

#[cfg(test)]
mod tests {
    use super::*;

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
