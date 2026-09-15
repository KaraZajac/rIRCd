//! Bans that lift themselves.
//!
//! `+b ~t:<duration>:<mask>` on a channel, and the same on `+q`: the duration
//! is minutes, or a number with a unit — `30s`, `10m`, `2h`, `1d`. When it is
//! up the server takes the mask off the list itself, and everybody hears it
//! the way they would hear an operator do it.
//!
//! A timed shun is here too, for a different reason. Every other server ban
//! is judged when it is matched, so an expired one simply stops matching; a
//! shun is remembered on the connection it covers, so when one runs out
//! somebody has to go and forget it.
//!
//! Every server on the network runs this over its own copy of the lists, so
//! a ban set on one server lifts everywhere at about the same moment; the
//! second `-b` to arrive for a mask already gone is nothing to act on.

use crate::channel::ChannelStore;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// How often the lists are looked over.
const EVERY: std::time::Duration = std::time::Duration::from_secs(10);
/// The longest a timed ban may be asked for: a year. Past that, set a plain one.
const MAX_SECS: i64 = 366 * 86_400;

/// The seconds a `~t:` prefix asks for, and the mask under it, from a mask
/// like `~t:30m:nick!*@*`. None for anything that is not a timed mask; an
/// error for one that is but cannot be read.
pub fn parse_timed(mask: &str) -> Option<Result<(i64, &str), &'static str>> {
    let rest = mask.strip_prefix("~t:")?;
    let Some((duration, inner)) = rest.split_once(':') else {
        return Some(Err("a timed mask is ~t:<duration>:<mask>"));
    };
    if inner.is_empty() {
        return Some(Err("a timed mask is ~t:<duration>:<mask>"));
    }
    let (number, unit) = match duration.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => duration.split_at(i),
        None => (duration, "m"),
    };
    let Ok(n) = number.parse::<i64>() else {
        return Some(Err("the duration is a number of minutes, or a number with s, m, h or d"));
    };
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3_600),
        "d" => n.saturating_mul(86_400),
        _ => return Some(Err("the duration is a number of minutes, or a number with s, m, h or d")),
    };
    if secs <= 0 || secs > MAX_SECS {
        return Some(Err("a timed ban lasts between one second and a year"));
    }
    Some(Ok((secs, inner)))
}

/// The mask a timed mask is really about; a mask that is not timed is its own.
pub fn peel_timed(mask: &str) -> &str {
    match parse_timed(mask) {
        Some(Ok((_, inner))) => inner,
        _ => mask,
    }
}

pub fn start(
    cfg: Arc<RwLock<Config>>,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(EVERY).await;
            sweep(&cfg, &state, &channels, &senders).await;
        }
    });
}

/// Lift every timed ban whose time is up. Returns what was lifted, as
/// (channel, letter, mask).
pub async fn sweep(
    cfg: &Arc<RwLock<Config>>,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Senders,
) -> Vec<(String, char, String)> {
    let now = chrono::Utc::now().timestamp();

    // A shun that has run out stops covering anybody.
    let stale = {
        let state_r = state.read().await;
        state_r
            .server_bans
            .iter()
            .any(|b| b.kind == crate::persist::BanKind::Shun && b.is_expired(now))
    };
    if stale {
        let gone: Vec<String> = {
            let mut state_w = state.write().await;
            let (expired, kept): (Vec<_>, Vec<_>) = state_w
                .server_bans
                .drain(..)
                .partition(|b| b.kind == crate::persist::BanKind::Shun && b.is_expired(now));
            state_w.server_bans = kept;
            expired.into_iter().map(|b| b.mask).collect()
        };
        crate::commands::server_cmds::apply_shuns(state).await;
        for mask in gone {
            tracing::info!(%mask, "Shun expired");
            if let Some(ref pool) = cfg.read().await.db {
                crate::persist::delete_server_ban(pool, &mask).await;
            }
        }
    }
    // Look first, under read locks, and only then touch what is due.
    let due: Vec<(String, char, String)> = {
        let store = channels.read().await;
        let mut due = Vec::new();
        for (key, ch) in store.channels.iter() {
            let ch = ch.read().await;
            for (letter, list) in [('b', &ch.bans), ('q', &ch.quiet_list)] {
                for mask in list {
                    let Some(Ok((secs, _))) = parse_timed(mask) else {
                        continue;
                    };
                    let set_at = ch
                        .list_meta
                        .get(&format!("{letter}{mask}"))
                        .map(|(_, at)| *at)
                        .unwrap_or(ch.created_at);
                    if set_at.saturating_add(secs) <= now {
                        due.push((key.clone(), letter, mask.clone()));
                    }
                }
            }
        }
        due
    };
    if due.is_empty() {
        return due;
    }
    let (server_name, pool, our_sid) = {
        let guard = cfg.read().await;
        (
            guard.server.name.clone(),
            guard.db.clone(),
            state.read().await.sid.clone(),
        )
    };
    let mut lifted = Vec::new();
    for (key, letter, mask) in due {
        let members: Vec<String> = {
            let store = channels.read().await;
            let Some(ch) = store.channels.get(&key) else {
                continue;
            };
            let mut ch = ch.write().await;
            if !ch.remove_from_list(letter, &mask) {
                continue;
            }
            ch.list_meta.remove(&format!("{letter}{mask}"));
            ch.members.keys().cloned().collect()
        };
        tracing::info!(channel = %key, %letter, %mask, "Timed ban lifted");
        let word = Message::new(
            "MODE",
            vec![key.clone(), format!("-{letter}"), mask.clone()],
        )
        .with_prefix(&server_name);
        {
            let registry = senders.read().await;
            for member in &members {
                registry.deliver(member, &word);
            }
        }
        if let Some(ref pool) = pool {
            crate::persist::set_channel_list_entry(pool, &key, letter, &mask, false, "", 0).await;
        }
        let guard = cfg.read().await;
        crate::link::announce_channel_mode(&guard, &our_sid, &key, &format!("-{letter}"), &[mask.clone()])
            .await;
        lifted.push((key, letter, mask));
    }
    lifted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timed_mask_says_how_long_and_of_what() {
        assert_eq!(parse_timed("~t:30:nick!*@*"), Some(Ok((1800, "nick!*@*"))));
        assert_eq!(parse_timed("~t:45s:nick!*@*"), Some(Ok((45, "nick!*@*"))));
        assert_eq!(parse_timed("~t:2h:*!*@host"), Some(Ok((7200, "*!*@host"))));
        assert_eq!(parse_timed("~t:1d:~a:alice"), Some(Ok((86_400, "~a:alice"))));
        assert_eq!(parse_timed("nick!*@*"), None);
        assert!(matches!(parse_timed("~t:nick!*@*"), Some(Err(_))));
        assert!(matches!(parse_timed("~t:0:nick!*@*"), Some(Err(_))));
        assert!(matches!(parse_timed("~t:5y:nick!*@*"), Some(Err(_))));
        assert!(matches!(parse_timed("~t:10:"), Some(Err(_))));
        assert_eq!(peel_timed("~t:10:~m:*!*@spam"), "~m:*!*@spam");
        assert_eq!(peel_timed("plain!*@*"), "plain!*@*");
    }
}
