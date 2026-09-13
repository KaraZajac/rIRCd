//! Looking after an account without a NickServ to do it.
//!
//! Registering an account is the easy half. The hard half is everything that
//! goes wrong afterwards: a password that leaked, a password that was
//! forgotten, a person who wants to leave. A services package handles those
//! with `SET PASSWORD`, `RESETPASS` and `DROP`; this server has no services
//! package, so it handles them here, and it has to be at least as careful,
//! because on this server the account *is* the nick and the channels.
//!
//! Every one of these proves something before it acts, and every proof is
//! charged against the same failed-login budget the other credential checks
//! use. A password check is a password check whatever command it arrives in.

use crate::commands::reply_to_client;
use crate::config::Config;
use crate::persist::{self, ResetOutcome, ResetStart};
use crate::protocol::Message;
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Who is asking: nick, account, address and user id — from the registered
/// client, or from the pending connection for a command allowed before that.
async fn asker(
    state: &Arc<RwLock<ServerState>>,
    client_id: &str,
) -> Option<(String, Option<String>, String, String)> {
    let state_r = state.read().await;
    if let Some(c) = state_r.clients.get(client_id) {
        let g = c.read().await;
        return Some((
            g.nick_or_id().to_string(),
            g.account.clone(),
            g.host.clone(),
            state_r.user_id(client_id),
        ));
    }
    state_r.pending.get(client_id).map(|p| {
        (
            p.nick.clone().unwrap_or_else(|| "*".to_string()),
            p.account.clone(),
            p.host.clone(),
            client_id.to_string(),
        )
    })
}

fn fail(cfg: &Config, command: &str, code: &str, target: &str, text: &str) -> Message {
    Message::new(
        "FAIL",
        vec![command.into(), code.into(), target.into(), text.into()],
    )
    .with_prefix(&cfg.server.name)
}

fn note(cfg: &Config, command: &str, code: &str, target: &str, text: &str) -> Message {
    Message::new(
        "NOTE",
        vec![command.into(), code.into(), target.into(), text.into()],
    )
    .with_prefix(&cfg.server.name)
}

/// Close every connection logged in to `account`, except the user `keep`.
///
/// Returns how many users were closed. A password that has just changed hands
/// is a password whoever had it before no longer has, and the way to make that
/// true of a live session is to end the session. The one that did the changing
/// is kept when there is one: with `multiclient` its other devices are the same
/// user and stay too, which is the difference between "your other logins" and
/// "your other windows".
async fn close_every_login(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    cfg: &Config,
    account: &str,
    keep: Option<&str>,
    reason: &str,
) -> usize {
    let doomed: Vec<String> = {
        let state_r = state.read().await;
        let mut ids = Vec::new();
        for (id, client) in state_r.users() {
            if keep.is_some_and(|k| k == id) {
                continue;
            }
            let g = client.read().await;
            if g
                .account
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(account))
            {
                ids.push(id.clone());
            }
        }
        ids
    };
    let farewell = Message::new("ERROR", vec![format!("Closing link: {reason}")])
        .with_prefix(&cfg.server.name);
    let mut registry = senders.write().await;
    for id in &doomed {
        registry.close_user(id, farewell.clone());
    }
    doomed.len()
}

/// `PASSWD <current> <new>` — change the password of the account you are
/// logged in to.
///
/// The current password is asked for even though the client is logged in. A
/// logged-in session is not proof of knowing the password: it may be a device
/// left unlocked, a session resumed by certificate, or the very session whose
/// owner just noticed something wrong. Other logins to the account are closed,
/// because a changed password is meant to lock somebody out and a live session
/// is the somebody.
#[allow(clippy::too_many_arguments)]
pub async fn handle_passwd(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((_nick, account, host, user_id)) = asker(&state, client_id).await else {
        return Ok(());
    };
    let Some(account) = account else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "PASSWD", "NOT_LOGGED_IN", "*", "Log in to an account first"),
            label,
        )
        .await;
        return Ok(());
    };
    let (Some(current), Some(new)) = (msg.params.first(), msg.params.get(1)) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "PASSWD", "NEED_PARAMS", &account, "PASSWD <current> <new>"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "PASSWD", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    };

    // Charged first, the way OPER is: an address that keeps getting it wrong is
    // told no without anything being checked, and the check itself is the
    // expensive part.
    let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
    if over_budget || !persist::verify_user(pool, &account, current).await {
        tracing::warn!(client_id, %account, over_budget, "PASSWD: current password refused");
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "PASSWD", "INCORRECT_PASSWORD", &account, "Current password is wrong"),
            label,
        )
        .await;
        return Ok(());
    }
    // Not refunded on success, unlike a login. A login that succeeds is one
    // somebody wanted and costs the server one check; a password change that
    // succeeds costs it two, in order, on the loop everybody shares — and an
    // account holder who could do that for free could do it in a loop. Eight
    // in ten seconds is nobody changing their password.

    match persist::set_password(pool, &account, new, cfg.limits.min_password_length).await {
        Ok(()) => {}
        Err(persist::RegisterError::WeakPassword) => {
            reply_to_client(
                &senders,
                client_id,
                fail(
                    cfg,
                    "PASSWD",
                    "WEAK_PASSWORD",
                    &account,
                    &format!(
                        "Password must be at least {} characters",
                        cfg.limits.min_password_length
                    ),
                ),
                label,
            )
            .await;
            return Ok(());
        }
        Err(e) => {
            tracing::error!(client_id, %account, "PASSWD: could not store the new password: {e:?}");
            cfg.db_health.note(false);
            reply_to_client(
                &senders,
                client_id,
                fail(cfg, "PASSWD", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
                label,
            )
            .await;
            return Ok(());
        }
    }

    let closed = close_every_login(
        &state,
        &senders,
        cfg,
        &account,
        Some(&user_id),
        "password changed from another session",
    )
    .await;
    tracing::info!(client_id, %account, other_logins_closed = closed, "PASSWD: password changed");
    reply_to_client(
        &senders,
        client_id,
        note(
            cfg,
            "PASSWD",
            "CHANGED",
            &account,
            &format!(
                "Password changed; {closed} other login{} closed",
                if closed == 1 { "" } else { "s" }
            ),
        ),
        label,
    )
    .await;
    Ok(())
}

/// `RESETPASS <account>` sends a code to the account's address;
/// `RESETPASS <account> <code> <new password>` uses it.
///
/// The first form answers the same way whatever happened — sent, no such
/// account, no address, asked too recently — because a command that said
/// otherwise would be a way of finding out which names are accounts. What it
/// does differ on is cost: it is charged to the asker's address like a failed
/// login, and an account is sent at most one code per code lifetime, so nobody
/// can turn it into a way of filling somebody's inbox.
///
/// Using a code closes every login to the account. Whoever is resetting the
/// password cannot log in, so any session that exists belongs to somebody else.
#[allow(clippy::too_many_arguments)]
pub async fn handle_resetpass(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((_nick, _account, host, _user_id)) = asker(&state, client_id).await else {
        return Ok(());
    };
    let Some(account) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            fail(
                cfg,
                "RESETPASS",
                "NEED_PARAMS",
                "*",
                "RESETPASS <account> — or RESETPASS <account> <code> <new password>",
            ),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "RESETPASS", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    };

    match (msg.params.get(1), msg.params.get(2)) {
        // ── Ask for a code ───────────────────────────────────────────────────
        (None, _) => {
            let Some(email_cfg) = cfg.email.clone() else {
                reply_to_client(
                    &senders,
                    client_id,
                    fail(
                        cfg,
                        "RESETPASS",
                        "UNAVAILABLE",
                        &account,
                        "This server cannot send mail, so it cannot reset passwords",
                    ),
                    label,
                )
                .await;
                return Ok(());
            };
            // Somebody asking for reset after reset is not resetting anything.
            // They are made to wait like a failed login, and while they are
            // over budget nothing is sent — but they are told the same thing.
            let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
            if !over_budget {
                let code = crate::mail::generate_code();
                let now = chrono::Utc::now().timestamp();
                match persist::begin_password_reset(pool, &account, &code, now).await {
                    ResetStart::Started { email } => {
                        let (network, pool_bg, account_bg, client_bg) = (
                            cfg.network.name.clone(),
                            pool.clone(),
                            account.clone(),
                            client_id.to_string(),
                        );
                        tokio::spawn(async move {
                            match crate::mail::send_password_reset(
                                &email_cfg,
                                &network,
                                &email,
                                &account_bg,
                                &code,
                            )
                            .await
                            {
                                Ok(()) => tracing::info!(
                                    client_id = %client_bg,
                                    account = %account_bg,
                                    "RESETPASS: code sent"
                                ),
                                Err(e) => {
                                    // A code that never arrived must not sit there
                                    // stopping the next request for a quarter hour.
                                    tracing::error!(
                                        client_id = %client_bg,
                                        account = %account_bg,
                                        "RESETPASS: could not send the code: {e}"
                                    );
                                    let _ = sqlx::query(
                                        "UPDATE users SET reset_code = NULL, reset_expires = NULL \
                                         WHERE nick_lower = ?",
                                    )
                                    .bind(account_bg.to_lowercase())
                                    .execute(&pool_bg)
                                    .await;
                                }
                            }
                        });
                    }
                    ResetStart::NoSuchAccount => {
                        tracing::info!(client_id, %account, "RESETPASS: no such account, saying nothing");
                    }
                    ResetStart::NoEmail => {
                        tracing::info!(client_id, %account, "RESETPASS: account has no address, saying nothing");
                    }
                    ResetStart::TooSoon => {
                        tracing::info!(client_id, %account, "RESETPASS: a code is already out, not sending another");
                    }
                    ResetStart::Io(e) => {
                        tracing::error!(client_id, %account, "RESETPASS: {e}");
                        cfg.db_health.note(false);
                        reply_to_client(
                            &senders,
                            client_id,
                            fail(cfg, "RESETPASS", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
                            label,
                        )
                        .await;
                        return Ok(());
                    }
                }
            } else {
                tracing::warn!(client_id, %account, %host, "RESETPASS: over budget, not sending");
            }
            reply_to_client(
                &senders,
                client_id,
                note(
                    cfg,
                    "RESETPASS",
                    "SENT",
                    &account,
                    "If that account exists and has an address, a code has been sent to it",
                ),
                label,
            )
            .await;
        }
        // ── Use one ─────────────────────────────────────────────────────────
        (Some(code), Some(new_password)) => {
            // A wrong code is a guess, and guessing is what the budget is for.
            let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
            let outcome = if over_budget {
                ResetOutcome::InvalidCode
            } else {
                persist::finish_password_reset(
                    pool,
                    &account,
                    code,
                    new_password,
                    cfg.limits.min_password_length,
                )
                .await
            };
            match outcome {
                ResetOutcome::Changed => {
                    // Charged like PASSWD, for the same reason: this is a hash
                    // and a database write on the shared loop, and a reset is
                    // something a person does once.
                    let closed = close_every_login(
                        &state,
                        &senders,
                        cfg,
                        &account,
                        None,
                        "password reset",
                    )
                    .await;
                    tracing::info!(client_id, %account, logins_closed = closed, "RESETPASS: password reset");
                    reply_to_client(
                        &senders,
                        client_id,
                        note(
                            cfg,
                            "RESETPASS",
                            "CHANGED",
                            &account,
                            "Password changed; log in with it now",
                        ),
                        label,
                    )
                    .await;
                }
                ResetOutcome::InvalidCode => {
                    tracing::warn!(client_id, %account, over_budget, "RESETPASS: code refused");
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(cfg, "RESETPASS", "INVALID_CODE", &account, "Wrong or expired code"),
                        label,
                    )
                    .await;
                }
                ResetOutcome::WeakPassword => {
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(
                            cfg,
                            "RESETPASS",
                            "WEAK_PASSWORD",
                            &account,
                            &format!(
                                "Password must be at least {} characters",
                                cfg.limits.min_password_length
                            ),
                        ),
                        label,
                    )
                    .await;
                }
                ResetOutcome::Io(e) => {
                    tracing::error!(client_id, %account, "RESETPASS: {e}");
                    cfg.db_health.note(false);
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(cfg, "RESETPASS", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
                        label,
                    )
                    .await;
                }
            }
        }
        (Some(_), None) => {
            reply_to_client(
                &senders,
                client_id,
                fail(
                    cfg,
                    "RESETPASS",
                    "NEED_PARAMS",
                    &account,
                    "RESETPASS <account> <code> <new password>",
                ),
                label,
            )
            .await;
        }
    }
    Ok(())
}

/// `DROPACCOUNT <password>` — remove the account you are logged in to, and
/// everything that named it.
///
/// The channels it founded are left with no founder rather than with a founder
/// who no longer exists: their operators keep their standing, and a network
/// operator can give them a new owner. Everything else the account owned goes
/// with it — its profile, its read markers, its push endpoints, its place on
/// operator lists — because a name that is free to register again must not
/// come with a previous life attached.
#[allow(clippy::too_many_arguments)]
pub async fn handle_dropaccount(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, account, host, _user_id)) = asker(&state, client_id).await else {
        return Ok(());
    };
    let Some(account) = account else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "DROPACCOUNT", "NOT_LOGGED_IN", "*", "Log in to the account first"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(password) = msg.params.first() else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "DROPACCOUNT", "NEED_PARAMS", &account, "DROPACCOUNT <password>"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "DROPACCOUNT", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    };

    let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
    if over_budget || !persist::verify_user(pool, &account, password).await {
        tracing::warn!(client_id, %account, over_budget, "DROPACCOUNT: password refused");
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "DROPACCOUNT", "INCORRECT_PASSWORD", &account, "Password is wrong"),
            label,
        )
        .await;
        return Ok(());
    }
    // Charged even when right, like PASSWD. Nobody drops an account twice.

    let erased = match persist::erase_account(pool, &account).await {
        Ok(erased) => erased,
        Err(e) => {
            tracing::error!(client_id, %account, "DROPACCOUNT: could not erase the account: {e}");
            cfg.db_health.note(false);
            reply_to_client(
                &senders,
                client_id,
                fail(cfg, "DROPACCOUNT", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
                label,
            )
            .await;
            return Ok(());
        }
    };

    // What the database no longer says, memory must stop saying too, and the
    // rest of the network has to hear. Founder first, then standing.
    let mut orphaned: Vec<(String, i64, Vec<String>)> = Vec::new();
    let mut standing_lost: Vec<(String, i64, char)> = Vec::new();
    {
        let store = channels.read().await;
        for (key, entry) in store.channels.iter() {
            let mut ch = entry.write().await;
            if ch.is_founder(Some(&account)) {
                ch.founder.clear();
                orphaned.push((
                    key.clone(),
                    ch.created_at,
                    ch.members.keys().cloned().collect(),
                ));
            }
            let before = ch.persisted_operators.len();
            ch.persisted_operators
                .retain(|o| !o.eq_ignore_ascii_case(&account));
            if ch.persisted_operators.len() != before {
                standing_lost.push((key.clone(), ch.created_at, 'o'));
            }
            let before = ch.persisted_voice.len();
            ch.persisted_voice
                .retain(|v| !v.eq_ignore_ascii_case(&account));
            if ch.persisted_voice.len() != before {
                standing_lost.push((key.clone(), ch.created_at, 'v'));
            }
        }
    }
    {
        let mut state_w = state.write().await;
        state_w
            .metadata
            .remove(&crate::commands::metadata::account_key(&account));
        state_w.read_markers.remove(&account);
        state_w.read_markers.remove(&account.to_lowercase());
        let lower = account.to_lowercase();
        state_w.channel_accounts.retain(|_, set| {
            set.remove(&lower);
            !set.is_empty()
        });
    }
    let gone = format!("-{account}");
    for (key, created_at, _) in &orphaned {
        crate::link::announce_channel_access(cfg, key, *created_at, 'f', std::slice::from_ref(&gone))
            .await;
    }
    for (key, created_at, letter) in &standing_lost {
        crate::link::announce_channel_access(cfg, key, *created_at, *letter, std::slice::from_ref(&gone))
            .await;
    }
    // The people in a channel that just lost its founder are told so. A room
    // that quietly became nobody's is a room somebody will quietly take.
    for (key, _, members) in &orphaned {
        let word = Message::new(
            "NOTICE",
            vec![
                key.clone(),
                format!("{key} no longer has a founder: the account {account} was dropped"),
            ],
        )
        .with_prefix(&cfg.server.name);
        let registry = senders.read().await;
        for member in members {
            registry.deliver(member, &word);
        }
    }

    tracing::info!(
        client_id,
        %nick,
        %account,
        channels_orphaned = ?erased.channels_founded,
        "DROPACCOUNT: account erased"
    );
    reply_to_client(
        &senders,
        client_id,
        note(
            cfg,
            "DROPACCOUNT",
            "DROPPED",
            &account,
            &format!(
                "Account dropped; {} channel{} left without a founder. Goodbye.",
                erased.channels_founded.len(),
                if erased.channels_founded.len() == 1 { "" } else { "s" }
            ),
        ),
        label,
    )
    .await;
    // Every login to it, this one included: there is no account to be logged
    // in to any more. The reply above is already on its way out ahead of this.
    close_every_login(&state, &senders, cfg, &account, None, "account dropped").await;
    Ok(())
}
