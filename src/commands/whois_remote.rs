//! Asking another server the one thing about its users only it knows.
//!
//! A `WHOIS` is answered from what this server was told about a user: their
//! nick, their name, their account, the server they are on. How long they have
//! been quiet is not in any of that. It is known to the server they are typing
//! at, changes every time they say anything, and is not worth telling the
//! network about — so it is asked for, once, when somebody wants it.
//!
//! That makes this the first thing on a link that is a question rather than an
//! announcement, and the shape is the one anything else of the kind will want:
//!
//! - the asking server issues a token nobody else chose and remembers what the
//!   answer is for;
//! - the question goes to the one server that can answer it, not to everybody;
//! - the answer carries the token back, and is only accepted for the user who
//!   asked;
//! - the waiting is bounded, and gives up on its own, because a peer that
//!   never answers must not be able to leave anything behind.

use super::reply::{end_labeled_batch, reply_in_batch, reply_to_client};
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{Senders, ServerState, WhoisWait};
use std::sync::Arc;
use tokio::sync::RwLock;

/// How long the server that owns the user has to answer.
///
/// Long enough for a link across the world and back, short enough that a
/// `WHOIS` never looks like it went unanswered. Whichever comes first — the
/// answer or this — finishes the reply, and the other finds nothing to do.
const ANSWER_WITHIN: std::time::Duration = std::time::Duration::from_secs(3);

/// Ask the server a user is on how long they have been quiet.
///
/// Returns whether the question went out. `false` means there was no way to
/// ask — no link runtime, no route, or too many questions already outstanding
/// — and the caller finishes the reply itself, without an idle line, which is
/// what it did before there was anywhere to ask.
#[allow(clippy::too_many_arguments)]
pub async fn ask(
    client_id: &str,
    asker_uid: &str,
    asker_nick: &str,
    target_nick: &str,
    target_uid: &str,
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    cfg: &Config,
    label: Option<&str>,
    batch_ref: Option<String>,
) -> bool {
    if cfg.links_runtime.is_none() {
        return false;
    }
    let token = {
        let mut state_w = state.write().await;
        state_w.pending_whois.issue(WhoisWait {
            asker: client_id.to_string(),
            asker_uid: asker_uid.to_string(),
            asker_nick: asker_nick.to_string(),
            target_nick: target_nick.to_string(),
            label: label.map(str::to_string),
            batch_ref: batch_ref.clone(),
        })
    };
    let Some(token) = token else {
        tracing::warn!(
            client_id,
            target = %target_nick,
            "WHOIS: too many answers already outstanding, not asking"
        );
        return false;
    };

    let asked = crate::link::route_to_user(
        cfg,
        asker_uid,
        target_uid,
        // params[0] is replaced with the target on the way out.
        &Message::new("WHOISREQ", vec![String::new(), token.clone()]),
    )
    .await;
    if !asked {
        // Nowhere to send it, so nothing will ever answer: take the question
        // back rather than leaving it for the timeout.
        state.write().await.pending_whois.take(&token);
        return false;
    }

    // Nothing waits on the answer. If it does not come, this does what the
    // answer would have done, minus the line it would have carried.
    let (state, senders, cfg) = (state.clone(), senders.clone(), cfg.server.name.clone());
    let waiting_token = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(ANSWER_WITHIN).await;
        let Some(wait) = state.write().await.pending_whois.take(&waiting_token) else {
            return;
        };
        tracing::info!(
            token = %waiting_token,
            target = %wait.target_nick,
            "WHOIS: the server holding this user did not answer in time"
        );
        finish(&senders, &cfg, wait, None).await;
    });
    true
}

/// Answer a question about one of this server's own users.
///
/// The asking server has already said everything it knows; this adds the one
/// thing it could not know. A question about somebody who is not here, or not
/// ours, is dropped: there is nothing truthful to say and an invented answer
/// would be indistinguishable from a real one.
pub async fn answer(
    state: &Arc<RwLock<ServerState>>,
    cfg: &Config,
    asker_uid: &str,
    target_uid: &str,
    token: &str,
) {
    let found = {
        let state_r = state.read().await;
        match state_r.clients.get(target_uid) {
            Some(client) => {
                let guard = client.read().await;
                guard
                    .server
                    .is_none()
                    .then(|| (guard.last_active, guard.signon_at))
            }
            None => None,
        }
    };
    let Some((last_active, signon_at)) = found else {
        return;
    };
    let idle = chrono::Utc::now()
        .timestamp()
        .saturating_sub(last_active)
        .max(0);
    crate::link::route_to_user(
        cfg,
        target_uid,
        asker_uid,
        &Message::new(
            "WHOISREP",
            vec![
                String::new(),
                token.to_string(),
                idle.to_string(),
                signon_at.to_string(),
            ],
        ),
    )
    .await;
}

/// Take an answer and finish the reply it belongs to.
///
/// The token has to be one this server issued and the answer has to be for the
/// user who asked; anything else is a peer answering a question nobody put to
/// it, and is dropped rather than shown to a client.
pub async fn accept(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    server_name: &str,
    asker_uid: &str,
    token: &str,
    idle: i64,
    signon: i64,
) {
    let wait = {
        let mut state_w = state.write().await;
        match state_w.pending_whois.take(token) {
            Some(wait) if wait.asker_uid == asker_uid => Some(wait),
            Some(wait) => {
                // Put it back: the right answer may still be coming, and the
                // timeout will clear it if not.
                tracing::warn!(
                    token = %token,
                    expected = %wait.asker_uid,
                    got = %asker_uid,
                    "WHOIS: an answer for somebody else's question"
                );
                state_w.pending_whois.put_back(token.to_string(), wait);
                None
            }
            None => None,
        }
    };
    let Some(wait) = wait else {
        return;
    };
    finish(senders, server_name, wait, Some((idle.max(0), signon))).await;
}

/// Send what is left of a `WHOIS` reply: the idle line when there is one, then
/// the line that ends the list, then the batch if the request was labelled.
async fn finish(senders: &Senders, server_name: &str, wait: WhoisWait, idle: Option<(i64, i64)>) {
    let send = |msg: Message| {
        let (senders, asker, batch_ref, label) = (
            senders.clone(),
            wait.asker.clone(),
            wait.batch_ref.clone(),
            wait.label.clone(),
        );
        async move {
            match batch_ref {
                Some(ref br) => reply_in_batch(&senders, &asker, msg, br).await,
                None => reply_to_client(&senders, &asker, msg, label.as_deref()).await,
            }
        }
    };

    if let Some((idle_secs, signon_at)) = idle {
        send(
            Message::new(
                "317",
                vec![
                    wait.asker_nick.clone(),
                    wait.target_nick.clone(),
                    idle_secs.to_string(),
                    signon_at.to_string(),
                    "seconds idle, signon time".into(),
                ],
            )
            .with_prefix(server_name),
        )
        .await;
    }
    send(
        Message::new(
            "318",
            vec![
                wait.asker_nick.clone(),
                wait.target_nick.clone(),
                "End of /WHOIS list".into(),
            ],
        )
        .with_prefix(server_name),
    )
    .await;
    if let Some(ref br) = wait.batch_ref {
        end_labeled_batch(senders, &wait.asker, br, server_name).await;
    }
}
