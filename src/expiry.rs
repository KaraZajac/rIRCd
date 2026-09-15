//! Nick and channel expiry, without the services package that usually does it.
//!
//! A registration is a promise the server keeps on somebody's behalf: a nick
//! nobody else may use, a channel that stays theirs when it empties. Kept for
//! somebody who has not been back in a year, it is a name and a room taken
//! from everybody who has. `[expiry]` says how long is long enough; nothing
//! here runs unless it does.
//!
//! "Unseen" is measured the way a person would measure it. A login is use,
//! and so is somebody who holds a channel standing in it — including the ones
//! who connected months ago and never left. The sweep looks at who is here
//! before it looks at the clock.

use crate::channel::ChannelStore;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// How often the sweep runs. The clock it reads counts in days.
const EVERY: std::time::Duration = std::time::Duration::from_secs(3600);
/// A little quiet after startup before the first sweep, so links have
/// bursted and people have reconnected before anybody is judged absent.
const FIRST_AFTER: std::time::Duration = std::time::Duration::from_secs(120);
const DAY: i64 = 86_400;

/// What one sweep let go of.
#[derive(Debug, Default)]
pub struct Swept {
    pub accounts: Vec<String>,
    pub channels: Vec<String>,
    pub files: usize,
}

/// Sweep on a timer for as long as the server runs.
pub fn start(
    cfg: Arc<RwLock<Config>>,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
) {
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_AFTER).await;
        loop {
            sweep(&cfg, &state, &channels, &senders).await;
            tokio::time::sleep(EVERY).await;
        }
    });
}

/// One pass over everything the policy covers. Nothing happens without a
/// policy, a database, or while the database is known to be down.
pub async fn sweep(
    cfg: &Arc<RwLock<Config>>,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Senders,
) -> Swept {
    let mut swept = Swept::default();
    // The configuration is read once and let go of: a read lock held across
    // a sweep would stand between a REHASH and every command behind it.
    let (policy, pool, server_name, uploads) = {
        let guard = cfg.read().await;
        let Some(policy) = guard.expiry.clone() else {
            return swept;
        };
        (
            policy,
            guard.db.clone().filter(|_| !guard.db_health.is_down()),
            guard.server.name.clone(),
            guard
                .filehost
                .as_ref()
                .map(|f| std::path::PathBuf::from(&f.upload_dir)),
        )
    };
    let now = chrono::Utc::now().timestamp();

    // Shared files first, because they are the one thing here that is not in
    // the database — a database that is down is no reason to let the disk
    // keep filling.
    if policy.uploads_days > 0 {
        if let Some(ref dir) = uploads {
            let cutoff = now.saturating_sub(i64::from(policy.uploads_days) * DAY);
            swept.files = crate::filehost::sweep_uploads(dir, cutoff).await;
        }
    }

    let Some(pool) = pool else {
        report(state, senders, &server_name, &swept).await;
        return swept;
    };

    if policy.accounts_days > 0 {
        let cutoff = now.saturating_sub(i64::from(policy.accounts_days) * DAY);
        for account in crate::persist::accounts_unseen_since(&pool, cutoff).await {
            if logged_in_now(state, &account).await {
                crate::persist::touch_account_seen(&pool, &account).await;
                continue;
            }
            match crate::persist::erase_account(&pool, &account).await {
                Ok(erased) => {
                    let why = format!(
                        "expired after {} days without a login",
                        policy.accounts_days
                    );
                    let guard = cfg.read().await;
                    crate::commands::account::forget_account(
                        &account, state, channels, senders, &guard, &why,
                    )
                    .await;
                    // A login that landed between the look and the erase is a
                    // login to nothing. Usually nobody.
                    crate::commands::account::close_every_login(
                        state,
                        senders,
                        &guard,
                        &account,
                        None,
                        "account expired",
                    )
                    .await;
                    drop(guard);
                    tracing::warn!(
                        %account,
                        days = policy.accounts_days,
                        channels_orphaned = ?erased.channels_founded,
                        "Account expired"
                    );
                    swept.accounts.push(account);
                }
                Err(e) => {
                    tracing::warn!(%account, "Could not expire the account: {e}");
                    cfg.read().await.db_health.note(false);
                }
            }
        }
    }

    if policy.channels_days > 0 {
        let cutoff = now.saturating_sub(i64::from(policy.channels_days) * DAY);
        for name in crate::persist::channels_unused_since(&pool, cutoff).await {
            match holder_present(&name, state, channels).await {
                Presence::Held => {
                    crate::persist::touch_channel_used(&pool, &name).await;
                }
                presence => {
                    if let Err(e) = crate::persist::unregister_channel(&pool, &name).await {
                        tracing::warn!(channel = %name, "Could not expire the registration: {e}");
                        cfg.read().await.db_health.note(false);
                        continue;
                    }
                    if presence == Presence::Unheld {
                        let guard = cfg.read().await;
                        let_go(&name, channels, senders, &guard, policy.channels_days).await;
                    }
                    tracing::warn!(channel = %name, days = policy.channels_days, "Channel registration expired");
                    swept.channels.push(name);
                }
            }
        }
    }

    report(state, senders, &server_name, &swept).await;
    swept
}

/// Tell the operators what a sweep let go of, when it let go of anything.
async fn report(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    server_name: &str,
    swept: &Swept,
) {
    if swept.accounts.is_empty() && swept.channels.is_empty() && swept.files == 0 {
        return;
    }
    crate::commands::registration::notify_opers(
        state,
        senders,
        server_name,
        's',
        &format!(
            "Expiry: {} account(s) erased, {} channel registration(s) given up, {} shared file(s) let go",
            swept.accounts.len(),
            swept.channels.len(),
            swept.files
        ),
    )
    .await;
}

/// Whether anybody connected right now is logged in to the account.
async fn logged_in_now(state: &Arc<RwLock<ServerState>>, account: &str) -> bool {
    let state_r = state.read().await;
    for client in state_r.clients.values() {
        if client
            .read()
            .await
            .account
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(account))
        {
            return true;
        }
    }
    false
}

#[derive(Debug, PartialEq, Eq)]
enum Presence {
    /// Somebody who holds the channel is in it.
    Held,
    /// The channel is here and nobody in it holds it.
    Unheld,
    /// The channel is in the database and not in memory: empty, and nobody's
    /// to stand in.
    NotInMemory,
}

/// Whether somebody who holds the channel — its founder or somebody on its
/// operator list — is standing in it right now.
async fn holder_present(
    name: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
) -> Presence {
    let (founder, ops, members) = {
        let store = channels.read().await;
        let Some(ch) = store.channels.get(name) else {
            return Presence::NotInMemory;
        };
        let ch = ch.read().await;
        (
            ch.founder.clone(),
            ch.persisted_operators.clone(),
            ch.members.keys().cloned().collect::<Vec<_>>(),
        )
    };
    let holds = |a: &str| {
        (!founder.is_empty() && a.eq_ignore_ascii_case(&founder))
            || ops.iter().any(|o| o.eq_ignore_ascii_case(a))
    };
    let state_r = state.read().await;
    for uid in members {
        // A member this server cannot put a name to is not one to expire
        // around. Erring towards keeping a registration costs a day.
        let Some(client) = state_r.clients.get(&uid) else {
            return Presence::Held;
        };
        if client.read().await.account.as_deref().is_some_and(|a| holds(a)) {
            return Presence::Held;
        }
    }
    Presence::Unheld
}

/// The registration is gone from the database; now from memory, from the
/// rest of the network, and — if anybody is in the room — from their idea of
/// whose it is. An empty channel that is nobody's is forgotten, exactly as
/// PART would forget it.
async fn let_go(
    name: &str,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Senders,
    cfg: &Config,
    days: u32,
) {
    let (created_at, founder, ops, voices, members) = {
        let store = channels.read().await;
        let Some(ch) = store.channels.get(name) else {
            return;
        };
        let mut ch = ch.write().await;
        (
            ch.created_at,
            std::mem::take(&mut ch.founder),
            std::mem::take(&mut ch.persisted_operators),
            std::mem::take(&mut ch.persisted_voice),
            ch.members.keys().cloned().collect::<Vec<_>>(),
        )
    };
    if members.is_empty() {
        channels.write().await.channels.remove(name);
    }
    if !founder.is_empty() {
        crate::link::announce_channel_access(cfg, name, created_at, 'f', &[format!("-{founder}")])
            .await;
    }
    let withdrawn: Vec<String> = ops.iter().map(|o| format!("-{o}")).collect();
    crate::link::announce_channel_access(cfg, name, created_at, 'o', &withdrawn).await;
    let withdrawn: Vec<String> = voices.iter().map(|v| format!("-{v}")).collect();
    crate::link::announce_channel_access(cfg, name, created_at, 'v', &withdrawn).await;
    if !members.is_empty() {
        let word = Message::new(
            "NOTICE",
            vec![
                name.to_string(),
                format!("{name} is no longer registered: nobody holding it has been in for {days} days"),
            ],
        )
        .with_prefix(&cfg.server.name);
        let registry = senders.read().await;
        for member in &members {
            registry.deliver(member, &word);
        }
    }
}
