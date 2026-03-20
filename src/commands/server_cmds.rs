//! Standard IRC server information commands: LUSERS, VERSION, TIME, INFO, LINKS, STATS, WHOWAS, HELP, KNOCK.

use crate::channel::{canonical_channel_key, ChannelStore};
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::ServerState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;

async fn send_to_client(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    msg: Message,
) {
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(msg).await;
    }
}

// ─── LUSERS ───────────────────────────────────────────────────────────────────

/// LUSERS — server user/channel statistics.
/// Replies: 251 RPL_LUSERCLIENT, 252 RPL_LUSEROP, 254 RPL_LUSERCHANNELS, 255 RPL_LUSERME, 265–266 RPL_LOCALUSERS/RPL_GLOBALUSERS
pub async fn handle_lusers(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let state = state.read().await;

    let nick = match state.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let total_users = state.clients.len();
    let mut ops = 0usize;
    let mut invisible_users = 0usize;
    for c in state.clients.values() {
        let g = c.read().await;
        if g.oper { ops += 1; }
        if g.invisible { invisible_users += 1; }
    }
    let visible_users = total_users.saturating_sub(invisible_users);
    let channels_count = channels.read().await.channels.len();

    // 251 RPL_LUSERCLIENT
    reply_to_client(
        &senders, client_id,
        Message::new("251", vec![
            nick.clone(),
            format!("There are {} users and {} invisible on 1 servers", visible_users, invisible_users),
        ]).with_prefix(s),
        label,
    ).await;

    if ops > 0 {
        // 252 RPL_LUSEROP
        reply_to_client(
            &senders, client_id,
            Message::new("252", vec![nick.clone(), ops.to_string(), "IRC Operators online".into()])
                .with_prefix(s),
            label,
        ).await;
    }

    // 254 RPL_LUSERCHANNELS
    reply_to_client(
        &senders, client_id,
        Message::new("254", vec![nick.clone(), channels_count.to_string(), "channels formed".into()])
            .with_prefix(s),
        label,
    ).await;

    // 255 RPL_LUSERME
    reply_to_client(
        &senders, client_id,
        Message::new("255", vec![
            nick.clone(),
            format!("I have {} clients and 1 servers", total_users),
        ]).with_prefix(s),
        label,
    ).await;

    // 265 RPL_LOCALUSERS
    reply_to_client(
        &senders, client_id,
        Message::new("265", vec![
            nick.clone(),
            total_users.to_string(),
            total_users.to_string(),
            format!("Current local users {}, max {}", total_users, total_users),
        ]).with_prefix(s),
        label,
    ).await;

    // 266 RPL_GLOBALUSERS
    reply_to_client(
        &senders, client_id,
        Message::new("266", vec![
            nick.clone(),
            total_users.to_string(),
            total_users.to_string(),
            format!("Current global users {}, max {}", total_users, total_users),
        ]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── VERSION ──────────────────────────────────────────────────────────────────

/// VERSION — report the server version string.
/// Reply: 351 RPL_VERSION
pub async fn handle_version(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    reply_to_client(
        &senders, client_id,
        Message::new("351", vec![
            nick,
            format!("rIRCd-{}", env!("CARGO_PKG_VERSION")),
            s.to_string(),
            "IRCv3 compliant IRC server written in Rust".into(),
        ]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── TIME ─────────────────────────────────────────────────────────────────────

/// TIME — report the server's current local time.
/// Reply: 391 RPL_TIME
pub async fn handle_time(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let time_str = chrono::Utc::now().format("%A %B %e %Y -- %T %z").to_string();

    reply_to_client(
        &senders, client_id,
        Message::new("391", vec![nick, s.to_string(), time_str]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── INFO ─────────────────────────────────────────────────────────────────────

/// INFO — server information block.
/// Reply: 371 RPL_INFO * n, then 374 RPL_ENDOFINFO
pub async fn handle_info(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let started = state.read().await.started_at;
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let uptime_secs = chrono::Utc::now().timestamp() - started;
    let days = uptime_secs / 86400;
    let hours = (uptime_secs % 86400) / 3600;
    let mins = (uptime_secs % 3600) / 60;

    let lines = [
        format!("rIRCd v{}", env!("CARGO_PKG_VERSION")),
        String::from("An IRCv3-compliant IRC server written in Rust."),
        String::from("https://github.com/KaraZajac/rIRCd"),
        String::new(),
        format!("Server: {}", s),
        format!("Network: {}", cfg.network.name),
        format!("Uptime: {}d {}h {}m", days, hours, mins),
    ];

    for line in &lines {
        reply_to_client(
            &senders, client_id,
            Message::new("371", vec![nick.clone(), line.clone()]).with_prefix(s),
            label,
        ).await;
    }

    reply_to_client(
        &senders, client_id,
        Message::new("374", vec![nick, "End of /INFO".into()]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── LINKS ────────────────────────────────────────────────────────────────────

/// LINKS — server link list. We are a single-server network, so just list ourselves.
/// Reply: 364 RPL_LINKS, 365 RPL_ENDOFLINKS
pub async fn handle_links(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    reply_to_client(
        &senders, client_id,
        Message::new("364", vec![
            nick.clone(), s.to_string(), s.to_string(),
            format!("0 rIRCd v{}", env!("CARGO_PKG_VERSION")),
        ]).with_prefix(s),
        label,
    ).await;

    reply_to_client(
        &senders, client_id,
        Message::new("365", vec![nick, "*".into(), "End of /LINKS".into()]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── STATS ────────────────────────────────────────────────────────────────────

/// STATS — server statistics. Implements 'u' (uptime) and 'o' (opers); stubs others.
pub async fn handle_stats(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let query = msg.params.first().map(|s| s.as_str()).unwrap_or("u");

    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    match query {
        "u" => {
            let started = state.read().await.started_at;
            let up = chrono::Utc::now().timestamp() - started;
            let days = up / 86400;
            let hours = (up % 86400) / 3600;
            let mins = (up % 3600) / 60;
            let secs = up % 60;
            reply_to_client(
                &senders, client_id,
                Message::new("242", vec![
                    nick.clone(),
                    format!("Server Up {} days, {}:{:02}:{:02}", days, hours, mins, secs),
                ]).with_prefix(s),
                label,
            ).await;
        }
        "o" => {
            for oper in &cfg.opers {
                let mask = oper.hostmask.as_deref().unwrap_or("*").to_string();
                reply_to_client(
                    &senders, client_id,
                    Message::new("243", vec![
                        nick.clone(), "O".into(),
                        mask, "*".into(), oper.name.clone(), "0".into(),
                    ]).with_prefix(s),
                    label,
                ).await;
            }
        }
        _ => {}
    }

    reply_to_client(
        &senders, client_id,
        Message::new("219", vec![nick, query.to_string(), "End of /STATS".into()]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── WHOWAS ───────────────────────────────────────────────────────────────────

/// WHOWAS — show historical nick information.
/// Replies: 314 RPL_WHOWASUSER, 312 RPL_WHOISSERVER, 369 RPL_ENDOFWHOWAS
pub async fn handle_whowas(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let target_nick = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let count: usize = msg.params.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
        .min(20);

    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    if target_nick.is_empty() {
        reply_to_client(
            &senders, client_id,
            Message::new("431", vec![nick.clone(), "No nickname given".into()]).with_prefix(s),
            label,
        ).await;
        reply_to_client(
            &senders, client_id,
            Message::new("369", vec![nick, target_nick.to_string(), "End of WHOWAS".into()]).with_prefix(s),
            label,
        ).await;
        return Ok(());
    }

    let entries: Vec<_> = {
        let state = state.read().await;
        state.whowas
            .get(&target_nick.to_lowercase())
            .map(|list| list.iter().rev().take(count).cloned().collect())
            .unwrap_or_default()
    };

    if entries.is_empty() {
        reply_to_client(
            &senders, client_id,
            Message::new("406", vec![nick.clone(), target_nick.to_string(), "There was no such nickname".into()])
                .with_prefix(s),
            label,
        ).await;
    } else {
        for e in &entries {
            // 314 RPL_WHOWASUSER
            reply_to_client(
                &senders, client_id,
                Message::new("314", vec![
                    nick.clone(), e.nick.clone(), e.user.clone(), e.host.clone(),
                    "*".into(), e.realname.clone(),
                ]).with_prefix(s),
                label,
            ).await;
            // 312 RPL_WHOISSERVER
            let ts = chrono::DateTime::from_timestamp(e.timestamp, 0)
                .map(|dt| dt.format("%a %b %e %Y").to_string())
                .unwrap_or_else(|| e.timestamp.to_string());
            reply_to_client(
                &senders, client_id,
                Message::new("312", vec![nick.clone(), e.nick.clone(), e.server.clone(), ts]).with_prefix(s),
                label,
            ).await;
        }
    }

    reply_to_client(
        &senders, client_id,
        Message::new("369", vec![nick, target_nick.to_string(), "End of WHOWAS".into()]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── HELP ─────────────────────────────────────────────────────────────────────

/// HELP / HELPOP — return a brief command reference.
/// Replies: 704 RPL_HELPSTART, 705 RPL_HELPTXT, 706 RPL_ENDOFHELP
pub async fn handle_help(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let topic = msg.params.first().map(|s| s.to_uppercase());
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let (subject, lines): (&str, &[&str]) = match topic.as_deref() {
        Some("JOIN")  => ("JOIN",  &["JOIN <channel>[,<channel>...] [key]", "  Join one or more channels."]),
        Some("PART")  => ("PART",  &["PART <channel>[,...] [reason]", "  Leave channels."]),
        Some("PRIVMSG") => ("PRIVMSG", &["PRIVMSG <target> :<message>", "  Send a message to a user or channel."]),
        Some("NICK")  => ("NICK",  &["NICK <new_nick>", "  Change your nickname."]),
        Some("QUIT")  => ("QUIT",  &["QUIT [reason]", "  Disconnect from the server."]),
        Some("WHO")   => ("WHO",   &["WHO <mask>", "  Show users matching mask."]),
        Some("WHOIS") => ("WHOIS", &["WHOIS <nick>", "  Show information about a user."]),
        Some("WHOWAS") => ("WHOWAS", &["WHOWAS <nick> [count]", "  Show historical nick information."]),
        Some("MODE")  => ("MODE",  &[
            "MODE <channel> [+/-modes] [args]",
            "  Channel modes: i (invite-only), t (topic protect), s (secret), p (private),",
            "  n (no external), m (moderated), k (key), b (ban), o (op), v (voice),",
            "  R (registered-only), c (no colors), C (no CTCP), q (quiet mask).",
            "MODE <nick> [+/-modes]",
            "  User modes: B (bot).",
        ]),
        Some("KICK")  => ("KICK",  &["KICK <channel> <nick> [reason]", "  Remove a user from a channel."]),
        Some("TOPIC") => ("TOPIC", &["TOPIC <channel> [:<new topic>]", "  Get or set channel topic."]),
        Some("INVITE") => ("INVITE", &["INVITE <nick> <channel>", "  Invite a user to a channel."]),
        Some("KNOCK") => ("KNOCK", &["KNOCK <channel> [message]", "  Request an invite to an invite-only channel."]),
        Some("AWAY")  => ("AWAY",  &["AWAY [:<message>]", "  Set or clear away status."]),
        Some("LIST")  => ("LIST",  &["LIST [pattern]", "  List channels on the server."]),
        Some("NAMES") => ("NAMES", &["NAMES [<channel>]", "  List users in a channel."]),
        Some("OPER")  => ("OPER",  &["OPER <name> <password>", "  Gain IRC operator privileges."]),
        Some("REGISTER") => ("REGISTER", &[
            "REGISTER <account|*> {<email>|*} <password>",
            "  Register your nick as an account. Account must be * or match your current nick.",
        ]),
        Some("MONITOR") => ("MONITOR", &[
            "MONITOR + <nicks>  — add nicks to watch list",
            "MONITOR - <nicks>  — remove nicks",
            "MONITOR C          — clear watch list",
            "MONITOR L          — list watch list",
            "MONITOR S          — show status of watched nicks",
        ]),
        Some("CHATHISTORY") => ("CHATHISTORY", &[
            "CHATHISTORY LATEST <channel> * <count>",
            "CHATHISTORY BEFORE <channel> msgid=<id>|timestamp=<ts> <count>",
            "CHATHISTORY AFTER  <channel> msgid=<id>|timestamp=<ts> <count>",
            "  Retrieve message history for a channel.",
        ]),
        _ => ("*", &[
            "Available commands (HELP <command> for details):",
            "  JOIN PART PRIVMSG NOTICE NICK QUIT WHO WHOIS WHOWAS MODE",
            "  KICK TOPIC INVITE KNOCK AWAY LIST NAMES OPER REGISTER",
            "  MONITOR CHATHISTORY VERSION TIME INFO LINKS STATS LUSERS",
        ]),
    };

    send_to_client(&senders, client_id,
        Message::new("704", vec![nick.clone(), subject.to_string(), format!("Help for {}", subject)]).with_prefix(s),
    ).await;

    for line in lines {
        send_to_client(&senders, client_id,
            Message::new("705", vec![nick.clone(), subject.to_string(), line.to_string()]).with_prefix(s),
        ).await;
    }

    send_to_client(&senders, client_id,
        Message::new("706", vec![nick, subject.to_string(), "End of /HELP".into()]).with_prefix(s),
    ).await;

    Ok(())
}

// ─── KNOCK ────────────────────────────────────────────────────────────────────

/// KNOCK <channel> [message] — request an invite to an invite-only channel.
/// Notifies all ops in the channel with a NOTICE. Sends 710 RPL_KNOCK to ops and 711 to sender.
pub async fn handle_knock(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let ch_name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let knock_msg = msg.trailing().unwrap_or("knock knock").to_string();

    let state = state.read().await;
    let (nick, source, account) = match state.clients.get(client_id) {
        Some(c) => {
            let g = c.read().await;
            (g.nick_or_id().to_string(), g.source().unwrap_or_else(|| g.nick_or_id().to_string()), g.account.clone())
        }
        None => return Ok(()),
    };

    if ch_name.is_empty() {
        reply_to_client(
            &senders, client_id,
            Message::new("461", vec![nick, "KNOCK".into(), "Not enough parameters".into()]).with_prefix(s),
            label,
        ).await;
        return Ok(());
    }

    let ch_key = crate::channel::canonical_channel_key(ch_name);
    let ch_store = channels.read().await;
    let ch = match ch_store.channels.get(&ch_key) {
        Some(c) => c.read().await,
        None => {
            reply_to_client(
                &senders, client_id,
                Message::new("403", vec![nick, ch_name.to_string(), "No such channel".into()]).with_prefix(s),
                label,
            ).await;
            return Ok(());
        }
    };

    if !ch.modes.invite_only {
        // 480: ERR_CANNOTKNOCK — channel is not invite-only
        reply_to_client(
            &senders, client_id,
            Message::new("480", vec![nick.clone(), ch_name.to_string(), "Channel is not invite-only".into()]).with_prefix(s),
            label,
        ).await;
        return Ok(());
    }

    if ch.is_member(client_id) {
        reply_to_client(
            &senders, client_id,
            Message::new("481", vec![nick.clone(), ch_name.to_string(), "You are already in that channel".into()]).with_prefix(s),
            label,
        ).await;
        return Ok(());
    }

    // Check banned
    if ch.is_banned(account.as_deref(), &source) {
        reply_to_client(
            &senders, client_id,
            Message::new("474", vec![nick.clone(), ch_name.to_string(), "You are banned from that channel".into()]).with_prefix(s),
            label,
        ).await;
        return Ok(());
    }

    // Notify ops (710 RPL_KNOCK)
    let op_ids: Vec<String> = ch.members.iter()
        .filter(|(_, m)| m.modes.op)
        .map(|(id, _)| id.clone())
        .collect();
    drop(ch);
    drop(ch_store);

    let knock_notice = Message::new("710", vec![
        ch_name.to_string(),
        ch_name.to_string(),
        format!("{}!{}@{}", nick, source.split('!').nth(1).unwrap_or("*").split('@').next().unwrap_or("*"),
                source.split('@').nth(1).unwrap_or("*")),
        format!("has knocked: {}", knock_msg),
    ]).with_prefix(s);

    for op_id in &op_ids {
        send_to_client(&senders, op_id, knock_notice.clone()).await;
    }

    // Tell sender their knock was delivered (711 RPL_KNOCKDLVR)
    reply_to_client(
        &senders, client_id,
        Message::new("711", vec![nick, ch_name.to_string(), "Your KNOCK has been delivered".into()]).with_prefix(s),
        label,
    ).await;

    Ok(())
}

// ─── KILL ─────────────────────────────────────────────────────────────────────

/// KILL <nick> <reason> — forcibly disconnect a user (oper only).
pub async fn handle_kill(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;

    let (is_oper, killer_nick, killer_source) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (g.oper, g.nick_or_id().to_string(), g.source().unwrap_or_else(|| g.nick_or_id().to_string()))
            }
            None => return Ok(()),
        }
    };

    if !is_oper {
        reply_to_client(&senders, client_id,
            Message::new("481", vec![killer_nick, "Permission Denied- You're not an IRC operator".into()])
                .with_prefix(s), label).await;
        return Ok(());
    }

    let target_nick = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let reason = msg.trailing().or_else(|| msg.params.get(1).map(|s| s.as_str())).unwrap_or("No reason").to_string();

    if target_nick.is_empty() {
        reply_to_client(&senders, client_id,
            Message::new("461", vec![killer_nick, "KILL".into(), "Not enough parameters".into()])
                .with_prefix(s), label).await;
        return Ok(());
    }

    let target_id = {
        let state_r = state.read().await;
        state_r.nick_to_id.get(&target_nick.to_uppercase()).cloned()
    };

    let tid = match target_id {
        Some(id) => id,
        None => {
            reply_to_client(&senders, client_id,
                Message::new("401", vec![killer_nick, target_nick.into(), "No such nick/channel".into()])
                    .with_prefix(s), label).await;
            return Ok(());
        }
    };

    let (target_source, target_channels, target_nick_upper) = {
        let state_r = state.read().await;
        match state_r.clients.get(&tid) {
            Some(c) => {
                let g = c.read().await;
                let source = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
                let chans: Vec<String> = g.channels.keys().cloned().collect();
                let nick_upper = g.nick.as_deref().unwrap_or("").to_uppercase();
                (source, chans, nick_upper)
            }
            None => return Ok(()),
        }
    };

    // Send ERROR to target
    let error_msg = Message::new("ERROR", vec![format!("Killed ({} ({}))", killer_source, reason)]);
    send_to_client(&senders, &tid, error_msg).await;

    // Remove from senders (causes write task to close the connection)
    senders.write().await.remove(&tid);

    // Broadcast QUIT to channel members
    let quit_msg = Message::new("QUIT", vec![format!("Killed by {} ({})", killer_nick, reason)])
        .with_prefix(&target_source);
    for ch_name in &target_channels {
        let ch_key = canonical_channel_key(ch_name);
        let mut ch_store = channels.write().await;
        let mut should_remove = false;
        if let Some(ch_rw) = ch_store.channels.get_mut(&ch_key) {
            let mut ch = ch_rw.write().await;
            let member_ids: Vec<String> = ch.members.keys().filter(|id| id.as_str() != tid).cloned().collect();
            ch.members.remove(&tid);
            should_remove = ch.members.is_empty();
            drop(ch);
            for mid in &member_ids {
                send_to_client(&senders, mid, quit_msg.clone()).await;
            }
        }
        if should_remove {
            ch_store.channels.remove(&ch_key);
        }
    }

    // Remove from server state
    {
        let mut state_w = state.write().await;
        state_w.record_whowas_for_kill(&tid, s);
        state_w.clients.remove(&tid);
        state_w.nick_to_id.remove(&target_nick_upper);
    }

    // Notify the killer
    reply_to_client(&senders, client_id,
        Message::new("NOTICE", vec![killer_nick, format!("Killed {}: {}", target_nick, reason)])
            .with_prefix(s), label).await;

    Ok(())
}

// ─── WALLOPS ──────────────────────────────────────────────────────────────────

/// WALLOPS <text> — broadcast to all users with +w (oper only).
pub async fn handle_wallops(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;

    let (is_oper, source, nick) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                let src = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
                let n = g.nick_or_id().to_string();
                (g.oper, src, n)
            }
            None => return Ok(()),
        }
    };

    if !is_oper {
        reply_to_client(&senders, client_id,
            Message::new("481", vec![nick, "Permission Denied- You're not an IRC operator".into()])
                .with_prefix(s), label).await;
        return Ok(());
    }

    let text = msg.trailing().unwrap_or("").to_string();
    if text.is_empty() {
        return Ok(());
    }

    let wallops_msg = Message::new("WALLOPS", vec![format!(":{}", text)]).with_prefix(&source);

    // Collect all clients with +w
    let wallops_ids: Vec<String> = {
        let state_r = state.read().await;
        let mut ids = Vec::new();
        for (id, c) in &state_r.clients {
            if c.read().await.wallops {
                ids.push(id.clone());
            }
        }
        ids
    };

    for tid in &wallops_ids {
        send_to_client(&senders, tid, wallops_msg.clone()).await;
    }

    Ok(())
}

// ─── REHASH ───────────────────────────────────────────────────────────────────

/// REHASH — reload the config file without restarting (oper only).
/// Replies: 382 RPL_REHASHING
pub async fn handle_rehash(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: Arc<RwLock<Config>>,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let server_name = cfg.read().await.server.name.clone();

    let (is_oper, nick) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (g.oper, g.nick_or_id().to_string())
            }
            None => return Ok(()),
        }
    };

    if !is_oper {
        reply_to_client(
            &senders,
            client_id,
            Message::new("481", vec![nick, "Permission Denied- You're not an IRC operator".into()])
                .with_prefix(&server_name),
            label,
        )
        .await;
        return Ok(());
    }

    let config_path = state.read().await.config_path.clone();
    let config_path = match config_path {
        Some(p) => p,
        None => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec!["REHASH".into(), "INTERNAL_ERROR".into(), "*".into(), "No config path available".into()])
                    .with_prefix(&server_name),
                label,
            )
            .await;
            return Ok(());
        }
    };

    let new_cfg = match crate::config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec!["REHASH".into(), "INTERNAL_ERROR".into(), "*".into(), format!("Failed to load config: {}", e)])
                    .with_prefix(&server_name),
                label,
            )
            .await;
            return Ok(());
        }
    };

    // Preserve the live database pool — REHASH does not reconnect
    let existing_db = cfg.read().await.db.clone();
    let mut new_cfg = new_cfg;
    new_cfg.db = existing_db;

    let config_file = config_path.to_string_lossy().to_string();
    *cfg.write().await = new_cfg;

    info!("Config reloaded by {}", nick);
    reply_to_client(
        &senders,
        client_id,
        Message::new("382", vec![nick, config_file, "Rehashing".into()])
            .with_prefix(&server_name),
        label,
    )
    .await;

    Ok(())
}
