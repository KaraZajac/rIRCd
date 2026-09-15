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

/// What an address that has spent its allowance is told.
///
/// Not that its credentials are wrong: they may well be right, and saying so
/// when nothing was checked is a lie the person on the other end has no way
/// to see through — they would go and change a password that was fine. The
/// budget exists to stop the checks being run, so what it owes them is the
/// truth about why. See `crate::authcost`.
fn slow_down(cfg: &Config, command: &str, target: &str) -> Message {
    fail(
        cfg,
        command,
        "RATE_LIMITED",
        target,
        "Too many credential checks from your address just now; try again in a moment",
    )
}

fn note(cfg: &Config, command: &str, code: &str, target: &str, text: &str) -> Message {
    Message::new(
        "NOTE",
        vec![command.into(), code.into(), target.into(), text.into()],
    )
    .with_prefix(&cfg.server.name)
}

/// What the database no longer says, memory must stop saying too, and the
/// rest of the network has to hear. Founder first, then standing; then the
/// people in a channel that just lost its founder are told so, because a room
/// that quietly became nobody's is a room somebody will quietly take. `why`
/// finishes the sentence "the account X …". Returns the channels orphaned.
pub async fn forget_account(
    account: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<crate::channel::ChannelStore>>,
    senders: &Senders,
    cfg: &Config,
    why: &str,
) -> Vec<String> {
    let mut orphaned: Vec<(String, i64, Vec<String>)> = Vec::new();
    let mut standing_lost: Vec<(String, i64, char)> = Vec::new();
    {
        let store = channels.read().await;
        for (key, entry) in store.channels.iter() {
            let mut ch = entry.write().await;
            if ch.is_founder(Some(account)) {
                ch.founder.clear();
                orphaned.push((
                    key.clone(),
                    ch.created_at,
                    ch.members.keys().cloned().collect(),
                ));
            }
            let before = ch.persisted_operators.len();
            ch.persisted_operators
                .retain(|o| !o.eq_ignore_ascii_case(account));
            if ch.persisted_operators.len() != before {
                standing_lost.push((key.clone(), ch.created_at, 'o'));
            }
            let before = ch.persisted_voice.len();
            ch.persisted_voice
                .retain(|v| !v.eq_ignore_ascii_case(account));
            if ch.persisted_voice.len() != before {
                standing_lost.push((key.clone(), ch.created_at, 'v'));
            }
        }
    }
    {
        let mut state_w = state.write().await;
        state_w
            .metadata
            .remove(&crate::commands::metadata::account_key(account));
        state_w.read_markers.remove(account);
        state_w.read_markers.remove(&account.to_lowercase());
        let lower = account.to_lowercase();
        state_w.grouped_nicks.retain(|_, owner| *owner != lower);
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
                format!("{key} no longer has a founder: the account {account} {why}"),
            ],
        )
        .with_prefix(&cfg.server.name);
        let registry = senders.read().await;
        for member in members {
            registry.deliver(member, &word);
        }
    }
    orphaned.into_iter().map(|(key, _, _)| key).collect()
}

/// Close every connection logged in to `account`, except the user `keep`.
///
/// Returns how many users were closed. A password that has just changed hands
/// is a password whoever had it before no longer has, and the way to make that
/// true of a live session is to end the session. The one that did the changing
/// is kept when there is one: with `multiclient` its other devices are the same
/// user and stay too, which is the difference between "your other logins" and
/// "your other windows".
pub async fn close_every_login(
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
    if over_budget {
        tracing::warn!(client_id, %account, "PASSWD: over budget, not checking");
        reply_to_client(&senders, client_id, slow_down(cfg, "PASSWD", &account), label).await;
        return Ok(());
    }
    if persist::verify_user(pool, &account, current).await {
        // Given back, the way a login that works is: the allowance is for
        // guessing, and somebody who knew their password was not guessing.
        // Charging it too meant a handful of ordinary changes could spend a
        // budget meant for an attacker, and the person would be the one made
        // to wait for it.
        state.write().await.auth_cost.refund(&host);
    } else {
        tracing::warn!(client_id, %account, "PASSWD: current password refused");
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "PASSWD", "INCORRECT_PASSWORD", &account, "Current password is wrong"),
            label,
        )
        .await;
        return Ok(());
    }

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
                        // The address has its own say, shared with REGISTER:
                        // one message per gap however it is asked for. A code
                        // stored for a message that is not going out is
                        // cleared, or it would hold the next request off.
                        let gap = std::time::Duration::from_secs(email_cfg.mail_gap_secs);
                        if !state.read().await.mail_cooldown.would_allow(&email, gap) {
                            tracing::info!(client_id, %account, "RESETPASS: that address was mailed lately, not sending");
                            let _ = sqlx::query(
                                "UPDATE users SET reset_code = NULL, reset_expires = NULL \
                                 WHERE nick_lower = ?",
                            )
                            .bind(account.to_lowercase())
                            .execute(pool)
                            .await;
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
                            return Ok(());
                        }
                        state.write().await.mail_cooldown.record(&email, gap);
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
            // An address that has spent its allowance is told that, rather
            // than that its code was wrong: the code may be the right one.
            let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
            if over_budget {
                tracing::warn!(client_id, %account, "RESETPASS: over budget, not checking");
                reply_to_client(&senders, client_id, slow_down(cfg, "RESETPASS", &account), label)
                    .await;
                return Ok(());
            }
            let outcome = persist::finish_password_reset(
                pool,
                &account,
                code,
                new_password,
                cfg.limits.min_password_length,
            )
            .await;
            if !matches!(outcome, ResetOutcome::InvalidCode) {
                // The code was the one that was mailed, so this was not a
                // guess. Given back, as a login that works is.
                state.write().await.auth_cost.refund(&host);
            }
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
    if over_budget {
        tracing::warn!(client_id, %account, "DROPACCOUNT: over budget, not checking");
        reply_to_client(&senders, client_id, slow_down(cfg, "DROPACCOUNT", &account), label).await;
        return Ok(());
    }
    if persist::verify_user(pool, &account, password).await {
        state.write().await.auth_cost.refund(&host);
    } else {
        tracing::warn!(client_id, %account, "DROPACCOUNT: password refused");
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "DROPACCOUNT", "INCORRECT_PASSWORD", &account, "Password is wrong"),
            label,
        )
        .await;
        return Ok(());
    }

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

    forget_account(&account, &state, &channels, &senders, cfg, "was dropped").await;

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

/// How many nicks an account may hold besides its own name.
pub const MAX_GROUPED_NICKS: usize = 5;

/// `GROUP` — reserve the nick you are using for your account; `GROUP -<nick>`
/// gives one back; `GROUP *` lists them.
///
/// What a services package calls grouping. An account's own name is
/// reserved for it already; this reserves the others somebody goes by —
/// the work nick, the phone nick — so nobody else can sit on them, and so
/// that being logged in is enough to use any of them. You have to be using
/// a nick to group it: reserving names you have never been seen under is
/// squatting, and the server does not help with that.
pub async fn handle_group(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, account, _host, _user_id)) = asker(&state, client_id).await else {
        return Ok(());
    };
    let Some(account) = account else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "GROUP", "NOT_LOGGED_IN", "*", "Log in to an account first"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "GROUP", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    };
    let arg = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if arg == "*" {
        let mut names = vec![account.clone()];
        names.extend(persist::grouped_nicks_of(pool, &account).await);
        reply_to_client(
            &senders,
            client_id,
            note(cfg, "GROUP", "NICKS", &account, &names.join(" ")),
            label,
        )
        .await;
        return Ok(());
    }
    if let Some(gone) = arg.strip_prefix('-') {
        if gone.is_empty() || gone.eq_ignore_ascii_case(&account) {
            reply_to_client(
                &senders,
                client_id,
                fail(cfg, "GROUP", "INVALID_TARGET", gone, "An account's own name is not grouped; DROPACCOUNT is how that goes"),
                label,
            )
            .await;
            return Ok(());
        }
        if !persist::ungroup_nick(pool, gone, &account).await {
            reply_to_client(
                &senders,
                client_id,
                fail(cfg, "GROUP", "NOT_YOURS", gone, "That nick is not grouped to your account"),
                label,
            )
            .await;
            return Ok(());
        }
        state.write().await.grouped_nicks.remove(&crate::casefold::lower(gone));
        tracing::info!(client_id, %account, nick = %gone, "GROUP: nick released");
        reply_to_client(
            &senders,
            client_id,
            note(cfg, "GROUP", "RELEASED", gone, &format!("{gone} is no longer reserved for {account}")),
            label,
        )
        .await;
        return Ok(());
    }
    if !arg.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "GROUP", "INVALID_PARAMS", arg, "GROUP reserves the nick you are using; GROUP -<nick> releases one; GROUP * lists them"),
            label,
        )
        .await;
        return Ok(());
    }
    if nick.eq_ignore_ascii_case(&account) {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "GROUP", "ALREADY_YOURS", &nick, "An account's own name is reserved for it already"),
            label,
        )
        .await;
        return Ok(());
    }
    let lower = account.to_lowercase();
    let (held_by_me, held_by_other, mine) = {
        let state_r = state.read().await;
        let owner = state_r.grouped_owner(&nick).map(str::to_string);
        (
            owner.as_deref() == Some(lower.as_str()),
            owner.is_some_and(|o| o != lower),
            state_r.grouped_nicks.values().filter(|o| **o == lower).count(),
        )
    };
    if held_by_me {
        reply_to_client(
            &senders,
            client_id,
            note(cfg, "GROUP", "GROUPED", &nick, &format!("{nick} is already reserved for {account}")),
            label,
        )
        .await;
        return Ok(());
    }
    if held_by_other || persist::nick_is_registered(pool, &cfg.db_health, &nick).await {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "GROUP", "NICK_RESERVED", &nick, "That nick is somebody else's"),
            label,
        )
        .await;
        return Ok(());
    }
    if mine >= MAX_GROUPED_NICKS {
        reply_to_client(
            &senders,
            client_id,
            fail(
                cfg,
                "GROUP",
                "TOO_MANY",
                &nick,
                &format!("An account may hold {MAX_GROUPED_NICKS} nicks besides its own; GROUP -<nick> to let one go"),
            ),
            label,
        )
        .await;
        return Ok(());
    }
    if let Err(e) = persist::group_nick(pool, &nick, &account).await {
        tracing::warn!(client_id, %account, %nick, "GROUP: could not store: {e}");
        cfg.db_health.note(false);
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "GROUP", "TEMPORARILY_UNAVAILABLE", &nick, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    }
    state
        .write()
        .await
        .grouped_nicks
        .insert(crate::casefold::lower(&nick), lower);
    tracing::info!(client_id, %account, %nick, "GROUP: nick reserved");
    reply_to_client(
        &senders,
        client_id,
        note(cfg, "GROUP", "GROUPED", &nick, &format!("{nick} is now reserved for {account}")),
        label,
    )
    .await;
    Ok(())
}

/// `SETEMAIL <current password> <new address>` to ask, `SETEMAIL <code>` to
/// confirm.
///
/// The address on an account is what a forgotten password goes to, so moving
/// it is the one change that can quietly take an account away from the person
/// who owns it. Two things have to be true: the password, which says it is
/// them, and a code read at the new address, which says they can receive
/// there. Until the code comes back the account keeps the address it had, so
/// a borrowed session cannot point it somewhere else and wait.
pub async fn handle_setemail(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((_nick, account, host, _user_id)) = asker(&state, client_id).await else {
        return Ok(());
    };
    let Some(account) = account else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "SETEMAIL", "NOT_LOGGED_IN", "*", "Log in to an account first"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "SETEMAIL", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(email_cfg) = cfg.email.clone() else {
        reply_to_client(
            &senders,
            client_id,
            fail(
                cfg,
                "SETEMAIL",
                "NO_EMAIL",
                &account,
                "This server does not send mail, so an address cannot be proved",
            ),
            label,
        )
        .await;
        return Ok(());
    };

    match (msg.params.first(), msg.params.get(1)) {
        // ── Confirm one ──────────────────────────────────────────────────────
        (Some(code), None) => {
            let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
            if over_budget {
                tracing::warn!(client_id, %account, "SETEMAIL: over budget, not checking");
                reply_to_client(&senders, client_id, slow_down(cfg, "SETEMAIL", &account), label)
                    .await;
                return Ok(());
            }
            match persist::finish_email_change(pool, &account, code).await {
                persist::EmailChangeOutcome::Changed(now_at) => {
                    state.write().await.auth_cost.refund(&host);
                    tracing::info!(client_id, %account, "SETEMAIL: address changed");
                    reply_to_client(
                        &senders,
                        client_id,
                        note(
                            cfg,
                            "SETEMAIL",
                            "CHANGED",
                            &account,
                            &format!("{account} is now at {now_at}"),
                        ),
                        label,
                    )
                    .await;
                }
                persist::EmailChangeOutcome::InvalidCode => {
                    tracing::warn!(client_id, %account, "SETEMAIL: code refused");
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(
                            cfg,
                            "SETEMAIL",
                            "INVALID_CODE",
                            &account,
                            "Wrong or expired code, or no change was asked for",
                        ),
                        label,
                    )
                    .await;
                }
                persist::EmailChangeOutcome::Io(e) => {
                    tracing::error!(client_id, %account, "SETEMAIL: {e}");
                    cfg.db_health.note(false);
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(cfg, "SETEMAIL", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
                        label,
                    )
                    .await;
                }
            }
        }
        // ── Ask to move ──────────────────────────────────────────────────────
        (Some(password), Some(wanted)) => {
            if !crate::mail::is_valid_email(wanted) {
                reply_to_client(
                    &senders,
                    client_id,
                    fail(cfg, "SETEMAIL", "INVALID_EMAIL", wanted, "That is not an address this server can write to"),
                    label,
                )
                .await;
                return Ok(());
            }
            let over_budget = !state.write().await.auth_cost.spend(&host).is_zero();
            if over_budget {
                reply_to_client(&senders, client_id, slow_down(cfg, "SETEMAIL", &account), label)
                    .await;
                return Ok(());
            }
            if !persist::verify_user(pool, &account, password).await {
                tracing::warn!(client_id, %account, "SETEMAIL: password refused");
                reply_to_client(
                    &senders,
                    client_id,
                    fail(cfg, "SETEMAIL", "INCORRECT_PASSWORD", &account, "Password is wrong"),
                    label,
                )
                .await;
                return Ok(());
            }
            state.write().await.auth_cost.refund(&host);
            let code = crate::mail::generate_code();
            let now = chrono::Utc::now().timestamp();
            match persist::begin_email_change(pool, &account, wanted, &code, now).await {
                persist::EmailChangeStart::TooSoon => {
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(
                            cfg,
                            "SETEMAIL",
                            "RATE_LIMITED",
                            &account,
                            "A code is already out for this account; use it or wait for it to expire",
                        ),
                        label,
                    )
                    .await;
                }
                persist::EmailChangeStart::NoSuchAccount => {
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(cfg, "SETEMAIL", "NOT_LOGGED_IN", &account, "That account is gone"),
                        label,
                    )
                    .await;
                }
                persist::EmailChangeStart::Io(e) => {
                    tracing::error!(client_id, %account, "SETEMAIL: {e}");
                    cfg.db_health.note(false);
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(cfg, "SETEMAIL", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
                        label,
                    )
                    .await;
                }
                persist::EmailChangeStart::Started => {
                    // The address has its own say, shared with REGISTER and
                    // RESETPASS: one message per gap, however it is asked for.
                    let gap = std::time::Duration::from_secs(email_cfg.mail_gap_secs);
                    let wanted = wanted.to_string();
                    if !state.read().await.mail_cooldown.would_allow(&wanted, gap) {
                        tracing::info!(client_id, %account, "SETEMAIL: that address was mailed lately, not sending");
                        persist::cancel_email_change(pool, &account).await;
                        reply_to_client(
                            &senders,
                            client_id,
                            fail(
                                cfg,
                                "SETEMAIL",
                                "RATE_LIMITED",
                                &wanted,
                                "That address was written to lately; try again in a while",
                            ),
                            label,
                        )
                        .await;
                        return Ok(());
                    }
                    state.write().await.mail_cooldown.record(&wanted, gap);
                    let (network, account_bg, client_bg) = (
                        cfg.network.name.clone(),
                        account.clone(),
                        client_id.to_string(),
                    );
                    let to = wanted.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::mail::send_email_change(
                            &email_cfg, &network, &to, &account_bg, &code,
                        )
                        .await
                        {
                            tracing::warn!(client_id = %client_bg, account = %account_bg, "SETEMAIL: could not send: {e}");
                        }
                    });
                    reply_to_client(
                        &senders,
                        client_id,
                        note(
                            cfg,
                            "SETEMAIL",
                            "SENT",
                            &wanted,
                            &format!("A code is on its way to {wanted}; {account} keeps the address it has until you send it back"),
                        ),
                        label,
                    )
                    .await;
                }
            }
        }
        _ => {
            reply_to_client(
                &senders,
                client_id,
                fail(
                    cfg,
                    "SETEMAIL",
                    "NEED_PARAMS",
                    &account,
                    "SETEMAIL <current password> <new address>, then SETEMAIL <code>",
                ),
                label,
            )
            .await;
        }
    }
    Ok(())
}

/// `ACCOUNTINFO [<account>]` — what this server is holding about an account.
///
/// Yours without asking; somebody else's needs the `ban` privilege, which is
/// the one an operator has when they are working out who is doing what.
pub async fn handle_accountinfo(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((_nick, own_account, _host, _user_id)) = asker(&state, client_id).await else {
        return Ok(());
    };
    let asked_about = msg.params.first().cloned();
    let may_look_elsewhere = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => c.read().await.may(crate::config::OperPrivilege::Ban),
            None => false,
        }
    };
    let account = match asked_about {
        Some(other)
            if !own_account
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(&other)) =>
        {
            if !may_look_elsewhere {
                reply_to_client(
                    &senders,
                    client_id,
                    fail(
                        cfg,
                        "ACCOUNTINFO",
                        "NOT_YOURS",
                        &other,
                        "Only an operator can look at somebody else's account",
                    ),
                    label,
                )
                .await;
                return Ok(());
            }
            other
        }
        Some(mine) => mine,
        None => match own_account {
            Some(a) => a,
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    fail(cfg, "ACCOUNTINFO", "NOT_LOGGED_IN", "*", "Log in to an account first"),
                    label,
                )
                .await;
                return Ok(());
            }
        },
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "ACCOUNTINFO", "TEMPORARILY_UNAVAILABLE", &account, "Try again later"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(summary) = persist::account_summary(pool, &account).await else {
        reply_to_client(
            &senders,
            client_id,
            fail(cfg, "ACCOUNTINFO", "NO_SUCH_ACCOUNT", &account, "No account by that name"),
            label,
        )
        .await;
        return Ok(());
    };
    let when = |at: i64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "an unknown time".into())
    };
    let mut lines: Vec<(&str, String)> = vec![(
        "ACCOUNT",
        format!(
            "{} — registered {}, last seen {}",
            summary.nick,
            when(summary.created_at),
            match summary.last_seen {
                Some(at) => when(at),
                None => "never".to_string(),
            }
        ),
    )];
    lines.push((
        "EMAIL",
        match (summary.email.is_empty(), summary.pending_email.as_deref()) {
            (true, None) => "no address on this account".to_string(),
            (true, Some(waiting)) => format!("none yet; a code is out for {waiting}"),
            (false, None) => format!(
                "{}{}",
                summary.email,
                if summary.verified { "" } else { " (never proved)" }
            ),
            (false, Some(waiting)) => format!(
                "{} — a move to {waiting} is waiting for its code",
                summary.email
            ),
        },
    ));
    if let Some(ref fp) = summary.certfp {
        lines.push(("CERTFP", fp.clone()));
    }
    let mut nicks = vec![summary.nick.clone()];
    nicks.extend(persist::grouped_nicks_of(pool, &account).await);
    lines.push(("NICKS", nicks.join(" ")));
    let founded = persist::channels_founded_by(pool, &account).await;
    lines.push((
        "CHANNELS",
        if founded.is_empty() {
            "none".to_string()
        } else {
            founded.join(" ")
        },
    ));
    if summary.noexpire {
        lines.push(("EXPIRY", "kept whatever the expiry clock says".to_string()));
    }
    for (kind, text) in lines {
        reply_to_client(
            &senders,
            client_id,
            note(cfg, "ACCOUNTINFO", kind, &account, &text),
            label,
        )
        .await;
    }
    Ok(())
}
