//! Who may reach you directly: `+g` and `ACCEPT`, and `SILENCE`.
//!
//! A channel has operators to keep it usable. An inbox has only its owner,
//! and the two tools every other server gives them are these. `+g` is a door
//! that is shut by default and opened by name — `ACCEPT alice` — and somebody
//! knocking is told so, once, and you are told they knocked, once. `SILENCE`
//! is a list of people who do not exist to you: nothing of theirs arrives and
//! nothing tells them so, which is the whole point of it.
//!
//! Both are decided on the server the recipient is on, at the moment of
//! delivery, so they hold for a sender on another server exactly as for one
//! here. Neither is written down: they are about this session's peace.

use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Names one person may accept. A list, not a set of everybody they know.
pub const MAX_ACCEPT: usize = 64;
/// Masks one person may silence. Advertised as `SILENCE=`.
pub const MAX_SILENCE: usize = 32;
/// How often the owner of a `+g` inbox is told about the same knocker.
const KNOCK_REMINDER: Duration = Duration::from_secs(60);

/// Why a direct message is not being delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The recipient is `+R` and the sender has no account.
    Unregistered,
    /// The recipient is `+g` and has not accepted the sender.
    Callerid,
    /// The sender matches the recipient's silence list.
    Silenced,
}

/// Whether `target_id` will take a direct message from this sender, and if
/// not, why. Silence is checked first: a silenced sender is told nothing,
/// not even that the recipient is `+g`.
pub async fn refuses_direct(
    state: &ServerState,
    target_id: &str,
    sender_id: &str,
    sender_nick: &str,
    sender_account: Option<&str>,
    sender_source: &str,
    sender_is_oper: bool,
) -> Option<Refusal> {
    let target = state.clients.get(target_id)?;
    let t = target.read().await;
    if t.silence.iter().any(|m| silenced_by(m, sender_source, sender_account)) {
        return Some(Refusal::Silenced);
    }
    if t.registered_only && sender_account.is_none() {
        return Some(Refusal::Unregistered);
    }
    if t.callerid && !sender_is_oper && sender_id != target_id {
        let nick = sender_nick.to_lowercase();
        let accepted = t.accept.iter().any(|a| {
            a == &nick || sender_account.is_some_and(|acct| a == &acct.to_lowercase())
        });
        if !accepted {
            return Some(Refusal::Callerid);
        }
    }
    None
}

/// Whether one silence mask covers this sender: `~a:account` against the
/// account, anything else as a glob against `nick!user@host`.
fn silenced_by(mask: &str, source: &str, account: Option<&str>) -> bool {
    match mask.strip_prefix("~a:") {
        Some(want) => account.is_some_and(|a| a.eq_ignore_ascii_case(want)),
        None => crate::user::glob_match(mask, source),
    }
}

/// Tell a `+g` recipient that somebody they have not accepted is trying, at
/// most once a minute per somebody. Returns whether they were told.
pub async fn remind_of_knock(state: &ServerState, target_id: &str, sender_id: &str) -> bool {
    let Some(target) = state.clients.get(target_id) else {
        return false;
    };
    let mut t = target.write().await;
    let now = Instant::now();
    t.knocks.retain(|_, when| now.duration_since(*when) < KNOCK_REMINDER);
    if t.knocks.contains_key(sender_id) {
        return false;
    }
    if t.knocks.len() >= MAX_ACCEPT {
        return false;
    }
    t.knocks.insert(sender_id.to_string(), now);
    true
}

/// The three numerics a `+g` refusal is made of: 716 and 717 to the sender,
/// 718 to the recipient. Sent by whoever found the refusal, so a sender on
/// another server gets nothing — their message was simply not delivered —
/// and the recipient is still told.
pub async fn explain_callerid(
    state: &ServerState,
    senders: &Senders,
    server_name: &str,
    sender_id: Option<&str>,
    sender_nick: &str,
    sender_source: &str,
    target_id: &str,
    target_nick: &str,
) {
    let registry = senders.read().await;
    if let Some(sender_id) = sender_id {
        registry.deliver(
            sender_id,
            &Message::new(
                "716",
                vec![
                    sender_nick.to_string(),
                    target_nick.to_string(),
                    "is in +g mode (server-side ignore)".into(),
                ],
            )
            .with_prefix(server_name),
        );
    }
    drop(registry);
    if remind_of_knock(state, target_id, sender_source).await {
        let registry = senders.read().await;
        if let Some(sender_id) = sender_id {
            registry.deliver(
                sender_id,
                &Message::new(
                    "717",
                    vec![
                        sender_nick.to_string(),
                        target_nick.to_string(),
                        "has been informed that you messaged them".into(),
                    ],
                )
                .with_prefix(server_name),
            );
        }
        registry.deliver(
            target_id,
            &Message::new(
                "718",
                vec![
                    target_nick.to_string(),
                    sender_nick.to_string(),
                    sender_source.to_string(),
                    "is messaging you, and you have umode +g".into(),
                ],
            )
            .with_prefix(server_name),
        );
    }
}

/// `ACCEPT <nick>[,<nick>...]`, `ACCEPT -<nick>`, `ACCEPT *`.
///
/// A name on the list may reach a `+g` inbox. It is matched against the
/// sender's nick and, if they have one, their account — so a friend who is
/// logged in keeps getting through after changing what they are called, and a
/// stranger who takes a friend's old nick while the friend is logged in
/// elsewhere gets through too, which is what naming a nick has always meant.
pub async fn handle_accept(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let state_r = state.read().await;
    let Some(client) = state_r.clients.get(client_id).cloned() else {
        return Ok(());
    };
    drop(state_r);
    let nick = client.read().await.nick_or_id().to_string();
    let arg = msg.params.first().cloned().unwrap_or_else(|| "*".to_string());

    if arg == "*" {
        let list = client.read().await.accept.clone();
        for entry in &list {
            reply_to_client(
                &senders,
                client_id,
                Message::new("281", vec![nick.clone(), entry.clone()]).with_prefix(s),
                label,
            )
            .await;
        }
        reply_to_client(
            &senders,
            client_id,
            Message::new("282", vec![nick.clone(), "End of /ACCEPT list".into()]).with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    for item in arg.split(',').filter(|i| !i.is_empty()) {
        let (remove, name) = match item.strip_prefix('-') {
            Some(n) => (true, n),
            None => (false, item),
        };
        let name = name.to_lowercase();
        let mut g = client.write().await;
        if remove {
            let before = g.accept.len();
            g.accept.retain(|a| a != &name);
            if g.accept.len() == before {
                drop(g);
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "458",
                        vec![nick.clone(), name.clone(), "is not on your accept list".into()],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }
            continue;
        }
        if g.accept.iter().any(|a| a == &name) {
            drop(g);
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "457",
                    vec![nick.clone(), name.clone(), "is already on your accept list".into()],
                )
                .with_prefix(s),
                label,
            )
            .await;
            continue;
        }
        if g.accept.len() >= MAX_ACCEPT {
            drop(g);
            reply_to_client(
                &senders,
                client_id,
                Message::new("456", vec![nick.clone(), "Accept list is full".into()]).with_prefix(s),
                label,
            )
            .await;
            break;
        }
        g.accept.push(name);
    }
    Ok(())
}

/// `SILENCE`, `SILENCE +<mask>`, `SILENCE -<mask>`.
///
/// A mask here is somebody who does not exist to you. Nothing of theirs
/// arrives — no message, no notice, no invitation — and nothing tells them
/// so. `nick`, `nick!user@host` and `~a:account` are all masks.
pub async fn handle_silence(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let state_r = state.read().await;
    let Some(client) = state_r.clients.get(client_id).cloned() else {
        return Ok(());
    };
    drop(state_r);
    let nick = client.read().await.nick_or_id().to_string();

    let Some(arg) = msg.params.first().cloned().filter(|a| !a.is_empty()) else {
        let list = client.read().await.silence.clone();
        for mask in &list {
            reply_to_client(
                &senders,
                client_id,
                Message::new("271", vec![nick.clone(), mask.clone()]).with_prefix(s),
                label,
            )
            .await;
        }
        reply_to_client(
            &senders,
            client_id,
            Message::new("272", vec![nick.clone(), "End of /SILENCE list".into()]).with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    };

    let (remove, raw) = match arg.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, arg.strip_prefix('+').unwrap_or(&arg)),
    };
    // `~a:account` and a full nick!user@host stand as given; a bare user@host
    // or a bare nick is filled out the way a ban mask is.
    let mask = if raw.starts_with("~a:") || raw.contains('!') {
        raw.to_lowercase()
    } else if raw.contains('@') {
        format!("*!{}", raw.to_lowercase())
    } else {
        format!("{}!*@*", raw.to_lowercase())
    };
    let mut g = client.write().await;
    if remove {
        g.silence.retain(|m| m != &mask);
    } else if !g.silence.iter().any(|m| m == &mask) {
        if g.silence.len() >= MAX_SILENCE {
            drop(g);
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "511",
                    vec![nick.clone(), mask.clone(), "Your silence list is full".into()],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
        g.silence.push(mask.clone());
    }
    drop(g);
    // Acknowledged the way a MODE is: the change echoed back.
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "SILENCE",
            vec![format!("{}{}", if remove { "-" } else { "+" }, mask)],
        )
        .with_prefix(&nick),
        label,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silence_mask_is_a_glob_or_an_account() {
        assert!(silenced_by("troll!*@*", "troll!x@host", None));
        assert!(!silenced_by("troll!*@*", "friend!x@host", None));
        assert!(silenced_by("~a:troll", "anything!x@host", Some("Troll")));
        assert!(!silenced_by("~a:troll", "anything!x@host", None));
    }
}
