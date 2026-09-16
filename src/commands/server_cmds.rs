//! Standard IRC server information commands: LUSERS, VERSION, TIME, INFO, LINKS, STATS, WHOWAS, HELP, KNOCK.

use crate::channel::{canonical_channel_key, ChannelStore};
use crate::commands::{end_labeled_batch, reply_in_batch, reply_to_client, start_labeled_batch};
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Deliver to a user: every connection they have open, not just one.
///
/// Channel members and message targets are users, and a user may be reading on
/// more than one connection at a time.
async fn send_to_client(senders: &Senders, user_id: &str, msg: Message) {
    senders.read().await.deliver(user_id, &msg);
}

// ─── LUSERS ───────────────────────────────────────────────────────────────────

/// LUSERS — server user/channel statistics.
/// Replies: 251 RPL_LUSERCLIENT, 252 RPL_LUSEROP, 254 RPL_LUSERCHANNELS, 255 RPL_LUSERME, 265–266 RPL_LOCALUSERS/RPL_GLOBALUSERS
pub async fn handle_lusers(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let state = state.read().await;

    let nick = match state.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let total_users = state.user_count();
    let peak_users = state.max_clients.max(total_users);
    let mut ops = 0usize;
    let mut invisible_users = 0usize;
    // Local and global are different numbers once there is a network: the
    // client tables hold everyone, and only some of them are here.
    let mut local_users = 0usize;
    for (_, c) in state.users() {
        let g = c.read().await;
        if g.oper {
            ops += 1;
        }
        if g.invisible {
            invisible_users += 1;
        }
        if g.server.is_none() {
            local_users += 1;
        }
    }
    let visible_users = total_users.saturating_sub(invisible_users);
    let servers = match cfg.links_runtime {
        Some(ref links) => links.read().await.count() + 1,
        None => 1,
    };
    let peak_local = state.max_clients.max(local_users);
    let channels_count = channels.read().await.channels.len();

    // labeled-response: LUSERS produces multiple messages, wrap in batch
    let batch_ref = if let Some(l) = label {
        Some(start_labeled_batch(&senders, client_id, l, s).await)
    } else {
        None
    };
    macro_rules! send_reply {
        ($msg:expr) => {
            if let Some(ref br) = batch_ref {
                reply_in_batch(&senders, client_id, $msg, br).await;
            } else {
                reply_to_client(&senders, client_id, $msg, None).await;
            }
        };
    }

    // 251 RPL_LUSERCLIENT
    send_reply!(Message::new(
        "251",
        vec![
            nick.clone(),
            format!(
                "There are {} users and {} invisible on {} servers",
                visible_users, invisible_users, servers
            ),
        ],
    )
    .with_prefix(s));

    // 252 RPL_LUSEROP. Sent even when the answer is none: leaving it out is the
    // older habit, and it makes "no operators are online" indistinguishable
    // from "this server does not say".
    send_reply!(Message::new(
        "252",
        vec![nick.clone(), ops.to_string(), "IRC Operators online".into()],
    )
    .with_prefix(s));

    // 254 RPL_LUSERCHANNELS
    send_reply!(Message::new(
        "254",
        vec![
            nick.clone(),
            channels_count.to_string(),
            "channels formed".into(),
        ],
    )
    .with_prefix(s));

    // 255 RPL_LUSERME
    send_reply!(Message::new(
        "255",
        vec![
            nick.clone(),
            format!("I have {} clients and {} servers", local_users, servers),
        ],
    )
    .with_prefix(s));

    // 265 RPL_LOCALUSERS
    send_reply!(Message::new(
        "265",
        vec![
            nick.clone(),
            local_users.to_string(),
            peak_local.to_string(),
            format!("Current local users {}, max {}", local_users, peak_local),
        ],
    )
    .with_prefix(s));

    // 266 RPL_GLOBALUSERS
    send_reply!(Message::new(
        "266",
        vec![
            nick.clone(),
            total_users.to_string(),
            peak_users.to_string(),
            format!("Current global users {}, max {}", total_users, peak_users),
        ],
    )
    .with_prefix(s));

    if let Some(ref br) = batch_ref {
        end_labeled_batch(&senders, client_id, br, s).await;
    }

    Ok(())
}

// ─── VERSION ──────────────────────────────────────────────────────────────────

/// VERSION — report the server version string.
/// Reply: 351 RPL_VERSION
pub async fn handle_version(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "351",
            vec![
                nick,
                format!("rIRCd-{}", env!("CARGO_PKG_VERSION")),
                s.to_string(),
                "IRCv3 compliant IRC server written in Rust".into(),
            ],
        )
        .with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── TIME ─────────────────────────────────────────────────────────────────────

/// TIME — report the server's current local time.
/// Reply: 391 RPL_TIME
pub async fn handle_time(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let time_str = chrono::Utc::now()
        .format("%A %B %e %Y -- %T %z")
        .to_string();

    reply_to_client(
        &senders,
        client_id,
        Message::new("391", vec![nick, s.to_string(), time_str]).with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── INFO ─────────────────────────────────────────────────────────────────────

/// INFO — server information block.
/// Reply: 371 RPL_INFO * n, then 374 RPL_ENDOFINFO
pub async fn handle_info(
    client_id: &str,
    target: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let started = state.read().await.started_at;
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    // `INFO <server>` asks a particular server. Answering for one that is not
    // on the network with this server's own information would be a quiet lie.
    if !target.is_empty() && !target.eq_ignore_ascii_case(s) {
        let known = match cfg.links_runtime {
            Some(ref links) => links.read().await.by_name(target).is_some(),
            None => false,
        };
        if !known {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "402",
                    vec![nick, target.to_string(), "No such server".into()],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
    }

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
            &senders,
            client_id,
            Message::new("371", vec![nick.clone(), line.clone()]).with_prefix(s),
            label,
        )
        .await;
    }

    reply_to_client(
        &senders,
        client_id,
        Message::new("374", vec![nick, "End of /INFO".into()]).with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── LINKS ────────────────────────────────────────────────────────────────────

/// LINKS — server link list. We are a single-server network, so just list ourselves.
/// Reply: 364 RPL_LINKS, 365 RPL_ENDOFLINKS
pub async fn handle_links(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    // This server first, then everything it is linked to. A one-server network
    // is the same answer it always was.
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "364",
            vec![
                nick.clone(),
                s.to_string(),
                s.to_string(),
                format!("0 {}", cfg.server.description),
            ],
        )
        .with_prefix(s),
        label,
    )
    .await;

    if let Some(ref links) = cfg.links_runtime {
        let mut remotes: Vec<(String, u32, String)> = links
            .read()
            .await
            .all()
            .map(|r| (r.name.clone(), r.hops, r.description.clone()))
            .collect();
        remotes.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, hops, description) in remotes {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "364",
                    vec![
                        nick.clone(),
                        name.clone(),
                        s.to_string(),
                        format!("{} {}", hops, description),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
    }

    reply_to_client(
        &senders,
        client_id,
        Message::new("365", vec![nick, "*".into(), "End of /LINKS".into()]).with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── STATS ────────────────────────────────────────────────────────────────────

/// STATS — server statistics. Implements 'u' (uptime) and 'o' (opers); stubs others.
/// Rows for `STATS k`: the server bans in force.
async fn stats_bans(
    state: &Arc<RwLock<ServerState>>,
    nick: &str,
    server: &str,
    kind: crate::persist::BanKind,
) -> Vec<Message> {
    let now = chrono::Utc::now().timestamp();
    state
        .read()
        .await
        .server_bans
        .iter()
        .filter(|b| !b.is_expired(now) && b.kind == kind)
        .map(|b| {
            let remaining = match b.expires_at {
                Some(e) => format!("{}s", (e - now).max(0)),
                None => "permanent".to_string(),
            };
            // 216 RPL_STATSKLINE, and the same row shape for a D-line
            Message::new(
                "216",
                vec![
                    nick.to_string(),
                    b.kind.letter().into(),
                    b.mask.clone(),
                    remaining,
                    b.set_by.clone(),
                    b.reason.clone(),
                ],
            )
            .with_prefix(server)
        })
        .collect()
}

/// Rows for `STATS m`: how often each command has been used.
async fn stats_commands(
    state: &Arc<RwLock<ServerState>>,
    nick: &str,
    server: &str,
) -> Vec<Message> {
    let state_r = state.read().await;
    let mut counts: Vec<(&String, &u64)> = state_r.command_counts.iter().collect();
    counts.sort_by(|a, b| b.1.cmp(a.1));
    counts
        .into_iter()
        .map(|(command, count)| {
            // 212 RPL_STATSCOMMANDS
            Message::new(
                "212",
                vec![
                    nick.to_string(),
                    command.clone(),
                    count.to_string(),
                    "0".into(),
                ],
            )
            .with_prefix(server)
        })
        .collect()
}

pub async fn handle_stats(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let query = msg.params.first().map(|s| s.as_str()).unwrap_or("u");

    let (nick, is_oper) = match state.read().await.clients.get(client_id) {
        Some(c) => {
            let g = c.read().await;
            (g.nick_or_id().to_string(), g.oper)
        }
        None => return Ok(()),
    };

    // Who the operators are, and who is banned, are for operators. OPER
    // refuses a name it has no block for without checking anything, which is
    // what makes guessing operator passwords pointless — and only as long as
    // the names are not handed out on request. The ban list, likewise, tells
    // whoever is banned exactly what to change.
    if matches!(query, "o" | "k" | "K") && !is_oper {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    match query {
        "u" => {
            let started = state.read().await.started_at;
            let up = chrono::Utc::now().timestamp() - started;
            let days = up / 86400;
            let hours = (up % 86400) / 3600;
            let mins = (up % 3600) / 60;
            let secs = up % 60;
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "242",
                    vec![
                        nick.clone(),
                        format!("Server Up {} days, {}:{:02}:{:02}", days, hours, mins, secs),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
        "o" => {
            for oper in &cfg.opers {
                let mask = oper.hostmask.as_deref().unwrap_or("*").to_string();
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "243",
                        vec![
                            nick.clone(),
                            "O".into(),
                            mask,
                            "*".into(),
                            oper.name.clone(),
                            "0".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }
        }
        "k" | "K" => {
            for m in stats_bans(&state, &nick, &cfg.server.name, crate::persist::BanKind::Kline).await {
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        "d" | "D" => {
            for m in stats_bans(&state, &nick, &cfg.server.name, crate::persist::BanKind::Dline).await {
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        "s" | "S" => {
            for m in stats_bans(&state, &nick, &cfg.server.name, crate::persist::BanKind::Shun).await {
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        // Who the rest of it does not apply to. Worth being able to read back:
        // an exemption nobody remembers is how a ban quietly stops working.
        "e" | "E" => {
            for m in stats_bans(&state, &nick, &cfg.server.name, crate::persist::BanKind::Exempt).await {
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        // The kinds of client this server tells apart. No hosts of anybody's
        // in it, but it describes the shape of the server, so it keeps the
        // company the rest of STATS keeps.
        "y" | "Y" => {
            if !is_oper {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "481",
                        vec![nick.clone(), "Permission Denied- You're not an IRC operator".into()],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            } else {
                for m in stats_classes(cfg, &state, &senders, &nick, s).await {
                    reply_to_client(&senders, client_id, m, label).await;
                }
            }
        }
        // What this server is carrying, and what it has been doing. Both name
        // hosts and count traffic, so both are the operators' to see.
        "l" | "L" | "t" | "T" => {
            if !is_oper {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "481",
                        vec![nick.clone(), "Permission Denied- You're not an IRC operator".into()],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            } else if query.eq_ignore_ascii_case("l") {
                for m in stats_links(&state, &senders, &nick, s).await {
                    reply_to_client(&senders, client_id, m, label).await;
                }
            } else {
                for m in stats_totals(&state, &senders, &nick, s).await {
                    reply_to_client(&senders, client_id, m, label).await;
                }
            }
        }
        "m" | "M" => {
            for m in stats_commands(&state, &nick, &cfg.server.name).await {
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        _ => {}
    }

    reply_to_client(
        &senders,
        client_id,
        Message::new("219", vec![nick, query.to_string(), "End of /STATS".into()]).with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── WHOWAS ───────────────────────────────────────────────────────────────────

/// WHOWAS — show historical nick information.
/// Replies: 314 RPL_WHOWASUSER, 312 RPL_WHOISSERVER, 369 RPL_ENDOFWHOWAS
pub async fn handle_whowas(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let target_nick = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let count: usize = match msg.params.get(1).and_then(|s| s.parse::<i64>().ok()) {
        Some(n) if n > 0 => (n as usize).min(20),
        // "If a non-positive number is passed as being <count>, then a full
        // search is done" — RFC 1459 §4.5.3.
        Some(_) => 20,
        None => 5,
    };

    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    if target_nick.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("431", vec![nick.clone(), "No nickname given".into()]).with_prefix(s),
            label,
        )
        .await;
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "369",
                vec![nick, target_nick.to_string(), "End of WHOWAS".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let mut entries: Vec<_> = {
        let state = state.read().await;
        state
            .whowas
            .get(&target_nick.to_lowercase())
            .map(|list| list.iter().rev().take(count).cloned().collect())
            .unwrap_or_default()
    };
    // Fall back to database if no in-memory entries
    if entries.is_empty() {
        if let Some(ref pool) = cfg.db {
            entries = crate::persist::load_whowas(pool, target_nick, count as i64).await;
        }
    }

    if entries.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "406",
                vec![
                    nick.clone(),
                    target_nick.to_string(),
                    "There was no such nickname".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
    } else {
        for e in &entries {
            // 314 RPL_WHOWASUSER
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "314",
                    vec![
                        nick.clone(),
                        e.nick.clone(),
                        e.user.clone(),
                        e.host.clone(),
                        "*".into(),
                        e.realname.clone(),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
            // 312 RPL_WHOISSERVER
            let ts = chrono::DateTime::from_timestamp(e.timestamp, 0)
                .map(|dt| dt.format("%a %b %e %Y").to_string())
                .unwrap_or_else(|| e.timestamp.to_string());
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "312",
                    vec![nick.clone(), e.nick.clone(), e.server.clone(), ts],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
    }

    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "369",
            vec![nick, target_nick.to_string(), "End of WHOWAS".into()],
        )
        .with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── HELP ─────────────────────────────────────────────────────────────────────

/// HELP / HELPOP — return a brief command reference.
/// Replies: 704 RPL_HELPSTART, 705 RPL_HELPTXT, 706 RPL_ENDOFHELP
pub async fn handle_help(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
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
        Some("JOIN") => (
            "JOIN",
            &[
                "JOIN <channel>[,<channel>...] [key]",
                "  Join one or more channels.",
            ],
        ),
        Some("PART") => (
            "PART",
            &["PART <channel>[,...] [reason]", "  Leave channels."],
        ),
        Some("PRIVMSG") => (
            "PRIVMSG",
            &[
                "PRIVMSG <target> :<message>",
                "  Send a message to a user or channel.",
            ],
        ),
        Some("NICK") => ("NICK", &["NICK <new_nick>", "  Change your nickname."]),
        Some("QUIT") => ("QUIT", &["QUIT [reason]", "  Disconnect from the server."]),
        Some("WHO") => ("WHO", &["WHO <mask>", "  Show users matching mask."]),
        Some("WHOIS") => (
            "WHOIS",
            &["WHOIS <nick>", "  Show information about a user."],
        ),
        Some("WHOWAS") => (
            "WHOWAS",
            &[
                "WHOWAS <nick> [count]",
                "  Show historical nick information.",
            ],
        ),
        Some("MODE") => (
            "MODE",
            &[
                "MODE <channel> [+/-modes] [args]",
                "  Channel modes: i (invite-only), t (topic protect), s (secret), p (private),",
                "  n (no external), m (moderated), k (key), l (limit), b (ban), o (op),",
                "  v (voice), R (registered-only), M (registered speak), Z (TLS only),",
                "  c (no colors), C (no CTCP), q (quiet mask), j (join throttle, <joins>:<seconds>),",
                "  f (flood limit, <lines>:<seconds>: one line over it and the server kicks),",
                "  N (no nick changes), T (no notices), z (op-moderated: what the muted say",
                "  goes to the ops), O (operators only), L #overflow (where a full channel",
                "  sends people). A ban or quiet may be timed: +b ~t:30m:nick!*@* lifts itself",
                "  after 30 minutes (s, m, h, d; a bare number is minutes).",
                "MODE <nick> [+/-modes]",
                "  User modes: B (bot).",
            ],
        ),
        Some("KICK") => (
            "KICK",
            &[
                "KICK <channel> <nick> [reason]",
                "  Remove a user from a channel.",
            ],
        ),
        Some("TOPIC") => (
            "TOPIC",
            &[
                "TOPIC <channel> [:<new topic>]",
                "  Get or set channel topic.",
            ],
        ),
        Some("INVITE") => (
            "INVITE",
            &["INVITE <nick> <channel>", "  Invite a user to a channel."],
        ),
        Some("KNOCK") => (
            "KNOCK",
            &[
                "KNOCK <channel> [message]",
                "  Request an invite to an invite-only channel.",
            ],
        ),
        Some("AWAY") => (
            "AWAY",
            &["AWAY [:<message>]", "  Set or clear away status."],
        ),
        Some("LIST") => (
            "LIST",
            &["LIST [pattern]", "  List channels on the server."],
        ),
        Some("NAMES") => (
            "NAMES",
            &["NAMES [<channel>]", "  List users in a channel."],
        ),
        Some("OPER") => (
            "OPER",
            &["OPER <name> <password>", "  Gain IRC operator privileges."],
        ),
        Some("REGISTER") => (
            "REGISTER",
            &[
                "REGISTER <account|*> {<email>|*} <password>",
                "  Register your nick as an account. Account must be * or match your current nick.",
            ],
        ),
        Some("MONITOR") => (
            "MONITOR",
            &[
                "MONITOR + <nicks>  — add nicks to watch list",
                "MONITOR - <nicks>  — remove nicks",
                "MONITOR C          — clear watch list",
                "MONITOR L          — list watch list",
                "MONITOR S          — show status of watched nicks",
            ],
        ),
        Some("VERIFY") => (
            "VERIFY",
            &[
                "VERIFY <account|*> <code>",
                "  Confirm the code emailed to you when you registered.",
            ],
        ),
        Some("PASSWD") => (
            "PASSWD",
            &[
                "PASSWD <current> <new>",
                "  Change the password of the account you are logged in to.",
                "  Your other logins are closed; this one stays.",
            ],
        ),
        Some("RESETPASS") => (
            "RESETPASS",
            &[
                "RESETPASS <account>",
                "  Have a reset code sent to the account's address.",
                "RESETPASS <account> <code> <new password>",
                "  Use the code. Every login to the account is closed.",
            ],
        ),
        Some("DROPACCOUNT") => (
            "DROPACCOUNT",
            &[
                "DROPACCOUNT <password>",
                "  Remove your account and everything that named it. Channels",
                "  you founded are left without a founder; their operators stay.",
            ],
        ),
        Some("CHANOWN") => (
            "CHANOWN",
            &[
                "CHANOWN <#channel>",
                "  Who the channel belongs to.",
                "CHANOWN <#channel> <account>",
                "  Hand it on. The founder may; so may an operator, out loud.",
            ],
        ),
        Some("CHANACCESS") => (
            "CHANACCESS",
            &[
                "CHANACCESS <#channel>",
                "  The founder, and everyone whose operator or voice status",
                "  is remembered between visits.",
            ],
        ),
        Some("CHANDROP") => (
            "CHANDROP",
            &[
                "CHANDROP <#channel>",
                "  Give a channel up. Its operators keep their standing; it",
                "  just stops being anybody's to own.",
            ],
        ),
        Some("ACCEPT") => (
            "ACCEPT",
            &[
                "ACCEPT <nick>[,<nick>...]   — let them through your +g",
                "ACCEPT -<nick>              — stop letting them",
                "ACCEPT *                    — list",
                "  With user mode +g, only people on this list may message you.",
            ],
        ),
        Some("SILENCE") => (
            "SILENCE",
            &[
                "SILENCE +<mask>   — somebody who does not exist to you",
                "SILENCE -<mask>   — lift it",
                "SILENCE           — list",
                "  nick, nick!user@host and ~a:account are all masks. Nothing of",
                "  theirs arrives, and nothing tells them so.",
            ],
        ),
        Some("CONNECT") => (
            "CONNECT",
            &[
                "CONNECT <server>",
                "  Dial a configured [[links]] block now. Operators with the",
                "  links privilege.",
            ],
        ),
        Some("SQUIT") => (
            "SQUIT",
            &[
                "SQUIT <server> [:<reason>]",
                "  Drop the link to a directly attached server. It is told why.",
            ],
        ),
        Some("SANICK") => (
            "SANICK",
            &[
                "SANICK <nick> <newnick>",
                "  Change somebody else's nick. Operators with the kill privilege.",
                "  They are told who did it; the network sees an ordinary nick change.",
            ],
        ),
        Some("KLINE") => (
            "KLINE",
            &[
                "KLINE [<seconds>] <nick!user@host> :<reason>",
                "  Refuse connections matching a mask; the host may be a network",
                "  (user@203.0.113.0/24). Existing matches are closed. UNKLINE lifts it.",
            ],
        ),
        Some("DLINE") => (
            "DLINE",
            &[
                "DLINE [<seconds>] <address|network> :<reason>",
                "  Turn an address away the moment it connects, before anything is",
                "  spent on it. CIDR for a network; nothing wider than a /8 or /16.",
                "  UNDLINE lifts it; STATS d lists them.",
            ],
        ),
        Some("SAJOIN") => (
            "SAJOIN",
            &[
                "SAJOIN <nick> <#channel>",
                "  Put somebody in a channel. The server invites them, so +b, +i, +k,",
                "  +l and +j open; +O, +Z and +R still hold. Operators with channels.",
            ],
        ),
        Some("SAPART") => (
            "SAPART",
            &[
                "SAPART <nick> <#channel> [:<reason>]",
                "  Take somebody out of a channel. An ordinary PART, with your reason.",
            ],
        ),
        Some("SAMODE") => (
            "SAMODE",
            &[
                "SAMODE <#channel> <modes> [<args>]",
                "  Set channel modes without holding ops there. Operators with channels.",
            ],
        ),
        Some("TESTMASK") => (
            "TESTMASK",
            &[
                "TESTMASK <mask>",
                "  How many people a K-line on this mask would hit, here and elsewhere,",
                "  before anybody sets it.",
            ],
        ),
        Some("MAP") => (
            "MAP",
            &[
                "MAP",
                "  The network as a tree, with how many people are on each server.",
            ],
        ),
        Some("TRACE") => (
            "TRACE",
            &[
                "TRACE [<nick>]",
                "  The connections this server is holding and the servers it is linked",
                "  to; one person when named. The class is how they arrived: plain,",
                "  tls or websocket. Operators only.",
            ],
        ),
        Some("STATS") => (
            "STATS",
            &[
                "STATS <letter>",
                "  u uptime, m command counts, o operator blocks, k K-lines, d D-lines,",
                "  s shuns, e exemptions, y connection classes, l what each connection",
                "  has carried, t what this server has been doing. Everything but u and",
                "  m is for operators.",
            ],
        ),
        Some("ELINE") | Some("UNELINE") => (
            "ELINE",
            &[
                "ELINE [<duration>] <mask> :<reason>",
                "  Say who the bans do not apply to. A blocklist eventually lists",
                "  somebody who belongs here — a shared address, a VPN, an exit node —",
                "  and this is how one address is vouched for without having to stop",
                "  believing the list for everybody. It covers the D-lines and the",
                "  blocklist at the door, and the K-lines and shuns after. It is not a",
                "  promise about behaviour: KILL still works. UNELINE stops vouching,",
                "  and STATS e reads them back.",
            ],
        ),
        Some("RESV") => (
            "RESV",
            &[
                "RESV [<seconds>] <pattern> :<reason>",
                "  A name this network keeps for itself. A pattern beginning with #",
                "  is about channels and anything else about nicks, so #help* never",
                "  stops anybody being called helpdesk. Whoever asks for one is told",
                "  why. Operators are not held to it, and a channel that already has",
                "  people in it keeps them. UNRESV gives the name back.",
            ],
        ),
        Some("SHUN") => (
            "SHUN",
            &[
                "SHUN [<seconds>] <nick!user@host> :<reason>",
                "  Leave somebody connected and let nothing they say reach anybody.",
                "  They may listen, answer a PING, and leave; everything else they",
                "  type quietly does nothing, and they are not told. UNSHUN lifts it,",
                "  STATS s lists them. Operators with the ban privilege.",
            ],
        ),
        Some("SPAMFILTER") => (
            "SPAMFILTER",
            &[
                "SPAMFILTER ADD <targets> <action> [<seconds>] :<pattern>",
                "SPAMFILTER DEL <id|pattern>   LIST   TEST :<text>",
                "  targets: p private messages, c channel messages, n nicks,",
                "  t topics, q quit reasons, r real names, or * for all of them.",
                "  action: warn, block, kill, kline, dline. <seconds> is how long",
                "  a ban lasts, 0 for no end.",
                "  A pattern between slashes is a regular expression; anything else",
                "  is a glob, so say *phrase* to match it anywhere in a line.",
                "  Operators are never filtered. The sender is not told which",
                "  pattern caught them; the operators are.",
            ],
        ),
        Some("SETEMAIL") => (
            "SETEMAIL",
            &[
                "SETEMAIL <current password> <new address>",
                "SETEMAIL <code>",
                "  Move your account to another address. A code goes to the new one;",
                "  until you send it back the account keeps the address it has, so",
                "  a borrowed session cannot point it somewhere else and wait.",
            ],
        ),
        Some("ACCOUNTINFO") => (
            "ACCOUNTINFO",
            &[
                "ACCOUNTINFO [<account>]",
                "  What this server is holding about an account: when it was",
                "  registered and last seen, its address, its nicks, the channels it",
                "  founded. Yours without asking; somebody else's needs the ban",
                "  privilege. ACCINFO is the same command.",
            ],
        ),
        Some("GROUP") => (
            "GROUP",
            &[
                "GROUP            reserve the nick you are using for your account",
                "GROUP -<nick>    give one back        GROUP *    list them",
                "  Up to five besides the account's own name. Being logged in is",
                "  enough to use any of them; nobody else can take them.",
            ],
        ),
        Some("NOEXPIRE") => (
            "NOEXPIRE",
            &[
                "NOEXPIRE <account|#channel> [ON|OFF]",
                "  Keep a name or a room out of [expiry]'s reach, or put it back.",
                "  Operators with channels. Without ON or OFF, shows which it is.",
            ],
        ),
        Some("MLOCK") => (
            "MLOCK",
            &[
                "MLOCK <#channel> [<+modes-modes>|OFF]",
                "  Lock modes so the operators the founder appointed cannot undo them:",
                "  MLOCK #chan +nt-k keeps n and t on and k off. Founder only; a server",
                "  operator may override. Without modes, shows the lock.",
            ],
        ),
        Some("SNOMASK") => (
            "SNOMASK",
            &[
                "MODE <you> +s [+|-]<letters>   MODE <you> -s",
                "  Which server notices an operator hears. Letters:",
                "  a accounts  b bans  c connections  f floods  k kills",
                "  l links  n nick changes  o operators  s server",
                "  A new operator starts with all but c and n.",
            ],
        ),
        Some("GHOST") => (
            "GHOST",
            &[
                "GHOST <nick>",
                "  Close a stale session of your own account that is holding",
                "  the nick, wherever on the network it is.",
            ],
        ),
        Some("WEBPUSH") => (
            "WEBPUSH",
            &[
                "WEBPUSH REGISTER <endpoint> p256dh=<key>;auth=<secret>",
                "WEBPUSH UNREGISTER <endpoint>",
                "  Manage Web Push endpoints for notifications. Requires being logged in.",
            ],
        ),
        Some("CHATHISTORY") => (
            "CHATHISTORY",
            &[
                "CHATHISTORY LATEST <channel> * <count>",
                "CHATHISTORY BEFORE <channel> msgid=<id>|timestamp=<ts> <count>",
                "CHATHISTORY AFTER  <channel> msgid=<id>|timestamp=<ts> <count>",
                "  Retrieve message history for a channel.",
            ],
        ),
        _ => (
            "*",
            &[
                "Available commands (HELP <command> for details):",
                "  JOIN PART PRIVMSG NOTICE NICK QUIT WHO WHOIS WHOWAS MODE",
                "  KICK TOPIC INVITE KNOCK AWAY LIST NAMES OPER REGISTER",
                "  VERIFY PASSWD RESETPASS DROPACCOUNT GHOST",
                "  CHANOWN CHANACCESS CHANDROP ACCEPT SILENCE",
                "  WEBPUSH MONITOR CHATHISTORY VERSION TIME INFO LINKS CONNECT SQUIT SANICK",
                "  KLINE DLINE SNOMASK MLOCK SAJOIN SAPART SAMODE TESTMASK MAP GROUP NOEXPIRE",
                "  SPAMFILTER SHUN TRACE SETEMAIL ACCOUNTINFO RESV",
                "  STATS LUSERS",
            ],
        ),
    };

    send_to_client(
        &senders,
        client_id,
        Message::new(
            "704",
            vec![
                nick.clone(),
                subject.to_string(),
                format!("Help for {}", subject),
            ],
        )
        .with_prefix(s),
    )
    .await;

    for line in lines {
        send_to_client(
            &senders,
            client_id,
            Message::new(
                "705",
                vec![nick.clone(), subject.to_string(), line.to_string()],
            )
            .with_prefix(s),
        )
        .await;
    }

    send_to_client(
        &senders,
        client_id,
        Message::new(
            "706",
            vec![nick, subject.to_string(), "End of /HELP".into()],
        )
        .with_prefix(s),
    )
    .await;

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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let ch_name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let knock_msg = msg
        .params
        .get(1)
        .cloned()
        .unwrap_or_else(|| "knock knock".to_string());

    let state = state.read().await;
    let (nick, source, account, realname, in_channels, is_oper) = match state.clients.get(client_id) {
        Some(c) => {
            let g = c.read().await;
            (
                g.nick_or_id().to_string(),
                g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                g.account.clone(),
                g.realname.clone().unwrap_or_default(),
                g.channels.keys().cloned().collect::<Vec<String>>(),
                g.oper,
            )
        }
        None => return Ok(()),
    };
    let certfp = state.certfps.get(client_id).cloned();

    if ch_name.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec![nick, "KNOCK".into(), "Not enough parameters".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let ch_key = crate::channel::canonical_channel_key(ch_name);
    let ch_store = channels.read().await;
    let ch = match ch_store.channels.get(&ch_key) {
        Some(c) => c.read().await,
        None => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "403",
                    vec![nick, ch_name.to_string(), "No such channel".into()],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
    };

    if !ch.modes.invite_only {
        // 480: ERR_CANNOTKNOCK — channel is not invite-only
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "480",
                vec![
                    nick.clone(),
                    ch_name.to_string(),
                    "Channel is not invite-only".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    if ch.is_member(&state.user_id(client_id)) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![
                    nick.clone(),
                    ch_name.to_string(),
                    "You are already in that channel".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    // Check banned
    if ch.is_banned(
        &crate::channel::Subject::from_source(&source)
            .with_account(account.as_deref())
            .with_realname(&realname)
            .in_channels(&in_channels)
            .with_certfp(certfp.as_deref())
            .oper(is_oper),
    ) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "474",
                vec![
                    nick.clone(),
                    ch_name.to_string(),
                    "You are banned from that channel".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    // Notify ops (710 RPL_KNOCK)
    let op_ids: Vec<String> = ch
        .members
        .iter()
        .filter(|(_, m)| m.modes.is_op())
        .map(|(id, _)| id.clone())
        .collect();
    drop(ch);
    drop(ch_store);

    let knock_notice = Message::new(
        "710",
        vec![
            ch_name.to_string(),
            ch_name.to_string(),
            format!(
                "{}!{}@{}",
                nick,
                source
                    .split('!')
                    .nth(1)
                    .unwrap_or("*")
                    .split('@')
                    .next()
                    .unwrap_or("*"),
                source.split('@').nth(1).unwrap_or("*")
            ),
            format!("has knocked: {}", knock_msg),
        ],
    )
    .with_prefix(s);

    for op_id in &op_ids {
        send_to_client(&senders, op_id, knock_notice.clone()).await;
    }

    // Tell sender their knock was delivered (711 RPL_KNOCKDLVR)
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "711",
            vec![
                nick,
                ch_name.to_string(),
                "Your KNOCK has been delivered".into(),
            ],
        )
        .with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── KILL ─────────────────────────────────────────────────────────────────────

/// KILL <nick> <reason> — forcibly disconnect a user (oper only).
pub async fn handle_kill(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;

    let (is_oper, killer_nick, killer_source) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.may(crate::config::OperPrivilege::Kill),
                    g.nick_or_id().to_string(),
                    g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                )
            }
            None => return Ok(()),
        }
    };

    if !is_oper {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![
                    killer_nick,
                    "Permission Denied- You're not an IRC operator".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let target_nick = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let reason = msg
        .trailing()
        .or_else(|| msg.params.get(1).map(|s| s.as_str()))
        .unwrap_or("No reason")
        .to_string();

    if target_nick.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec![killer_nick, "KILL".into(), "Not enough parameters".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let target_id = {
        let state_r = state.read().await;
        state_r
            .nick_to_id
            .get(&crate::casefold::upper(target_nick))
            .cloned()
    };

    let tid = match target_id {
        Some(id) => id,
        None => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "401",
                    vec![
                        killer_nick,
                        target_nick.into(),
                        "No such nick/channel".into(),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
    };

    // A user on another server is killed by the server that holds them: this one
    // asks, and hears about the result as a QUIT like everybody else.
    {
        let state_r = state.read().await;
        let remote = match state_r.clients.get(&tid) {
            Some(c) => c.read().await.server.is_some(),
            None => false,
        };
        let killer_id = state_r.user_id(client_id);
        drop(state_r);
        if remote {
            let ask = Message::new("KILL", vec![tid.clone(), reason.clone()]);
            if crate::link::route_to_user(cfg, &killer_id, &tid, &ask).await {
                tracing::warn!(client_id, killer = %killer_nick, target = %target_nick, "KILL sent across the link");
            }
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "NOTICE",
                    vec![killer_nick, format!("Killed {}: {}", target_nick, reason)],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
    }

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

    // Send ERROR to the target and close its connection.
    let error_msg = Message::new(
        "ERROR",
        vec![format!("Killed ({} ({}))", killer_source, reason)],
    );
    senders.write().await.close_user(&tid, error_msg);

    // Broadcast QUIT to channel members
    let quit_msg = Message::new(
        "QUIT",
        vec![format!("Killed by {} ({})", killer_nick, reason)],
    )
    .with_prefix(&target_source);
    for ch_name in &target_channels {
        let ch_key = canonical_channel_key(ch_name);
        let mut ch_store = channels.write().await;
        let mut should_remove = false;
        if let Some(ch_rw) = ch_store.channels.get_mut(&ch_key) {
            let mut ch = ch_rw.write().await;
            let member_ids: Vec<String> = ch
                .members
                .keys()
                .filter(|id| id.as_str() != tid)
                .cloned()
                .collect();
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
        // Every connection the user held goes, not just the entry under its own
        // id: a killed user with a second session open would otherwise stay
        // reachable through it.
        state_w.remove_client(&tid).await;
        state_w.nick_to_id.remove(&target_nick_upper);
    }
    crate::link::announce_quit(
        cfg,
        &tid,
        &format!("Killed by {} ({})", killer_nick, reason),
    )
    .await;
    tracing::warn!(client_id, killer = %killer_nick, target = %target_nick, reason = %reason, "KILL");

    // Notify the killer
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![killer_nick, format!("Killed {}: {}", target_nick, reason)],
        )
        .with_prefix(s),
        label,
    )
    .await;

    Ok(())
}

// ─── WALLOPS ──────────────────────────────────────────────────────────────────

/// WALLOPS <text> — broadcast to all users with +w (oper only).
pub async fn handle_wallops(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
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
                (g.may(crate::config::OperPrivilege::Wallops), src, n)
            }
            None => return Ok(()),
        }
    };

    if !is_oper {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let text = msg.trailing().unwrap_or("").to_string();
    if text.is_empty() {
        return Ok(());
    }

    let wallops_msg = Message::new("WALLOPS", vec![text]).with_prefix(&source);

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

    tracing::info!(client_id, recipients = wallops_ids.len(), "WALLOPS");
    for tid in &wallops_ids {
        send_to_client(&senders, tid, wallops_msg.clone()).await;
    }

    Ok(())
}

// ─── REHASH ───────────────────────────────────────────────────────────────────

/// Read the configuration again and put it in place, without dropping anybody.
///
/// Shared by `REHASH` and by `SIGHUP`, because they are the same operation
/// asked for in two ways: an operator on the network, and whoever renewed the
/// certificate. The unit file in `distrib/` sends the signal on
/// `systemctl reload`.
///
/// What survives the swap is everything a connection is holding: the database
/// pool, the history writer, the servers already linked, the Web Push key, and
/// the TLS acceptor itself — which is behind a lock precisely so a renewed
/// certificate can be dropped into it while clients keep talking.
///
/// Returns the path that was read, so the caller can say which file it was.
pub async fn reload_config(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    cfg: &Arc<RwLock<Config>>,
    config_path: &std::path::Path,
) -> anyhow::Result<String> {
    let server_name = cfg.read().await.server.name.clone();
    let new_cfg = crate::config::load(config_path)?;

    // Snapshot old cap list before replacing config
    let old_caps_raw = crate::capability::build_cap_list(&*cfg.read().await, false, false);
    let old_caps: std::collections::HashSet<String> =
        old_caps_raw[0].split(' ').map(|s| s.to_string()).collect();

    // Preserve the live database pool and history writer — REHASH does not
    // reconnect. Nor does it re-link: the servers already attached stay
    // attached, so the registry they are in has to survive the new config, or
    // every link would still be up with nothing able to reach it.
    let (existing_db, existing_history, existing_tls, existing_links) = {
        let c = cfg.read().await;
        (
            c.db.clone(),
            c.history.clone(),
            c.tls_acceptor.clone(),
            c.links_runtime.clone(),
        )
    };
    let mut new_cfg = new_cfg;
    new_cfg.db = existing_db;
    new_cfg.history = existing_history;
    new_cfg.tls_acceptor = existing_tls.clone();
    new_cfg.links_runtime = existing_links;

    // Reload the certificate: renewals happen on a schedule, and restarting to
    // pick one up would drop every connection.
    if let Some(ref shared) = existing_tls {
        if new_cfg.tls_enabled() {
            match crate::server::build_tls_acceptor(&new_cfg) {
                Ok(acceptor) => {
                    *shared.write().await = acceptor;
                    tracing::info!("Certificate reloaded");
                }
                Err(e) => {
                    tracing::error!("Keeping the certificate that is running: {}", e);
                }
            }
        }
    }

    // Keep the VAPID key and HTTP client. Rotating them would invalidate every
    // push subscription registered under the old key.
    if let Some(ref webpush_cfg) = new_cfg.webpush {
        let existing_runtime = cfg.read().await.webpush_runtime.clone();
        new_cfg.webpush_runtime = match existing_runtime {
            Some(runtime) => Some(runtime),
            None => match crate::webpush::WebpushRuntime::new(webpush_cfg) {
                Ok(runtime) => Some(std::sync::Arc::new(runtime)),
                Err(e) => {
                    tracing::error!("Could not set up Web Push: {}", e);
                    None
                }
            },
        };
    }

    *cfg.write().await = new_cfg;

    // Compute new cap list and diff
    let new_caps_raw = crate::capability::build_cap_list(&*cfg.read().await, false, false);
    let new_caps: std::collections::HashSet<String> =
        new_caps_raw[0].split(' ').map(|s| s.to_string()).collect();

    // Extract just cap names (strip =value) for comparison
    let old_names: std::collections::HashSet<String> = old_caps
        .iter()
        .map(|s| s.split('=').next().unwrap_or(s).to_string())
        .collect();
    let new_names: std::collections::HashSet<String> = new_caps
        .iter()
        .map(|s| s.split('=').next().unwrap_or(s).to_string())
        .collect();

    // Caps added or whose values changed
    let mut cap_new: Vec<String> = Vec::new();
    let mut cap_del: Vec<String> = Vec::new();

    for name in new_names.difference(&old_names) {
        // Newly added cap — include with value from new_caps
        if let Some(full) = new_caps
            .iter()
            .find(|s| s.split('=').next().unwrap_or(s) == name)
        {
            cap_new.push(full.clone());
        }
    }
    for name in old_names.difference(&new_names) {
        cap_del.push(name.clone());
    }
    // Check for value changes on caps present in both
    for name in old_names.intersection(&new_names) {
        let old_full = old_caps
            .iter()
            .find(|s| s.split('=').next().unwrap_or(s) == name);
        let new_full = new_caps
            .iter()
            .find(|s| s.split('=').next().unwrap_or(s) == name);
        if old_full != new_full {
            if let Some(full) = new_full {
                cap_new.push(full.clone());
            }
        }
    }

    // Send CAP NEW / CAP DEL to clients with cap-notify
    if !cap_new.is_empty() || !cap_del.is_empty() {
        let state_r = state.read().await;
        // Once per user: the client table also answers to the id of every
        // connection that reaches one, and CAP NEW twice is CAP NEW wrong.
        let client_ids: Vec<String> = state_r.users().map(|(id, _)| id.clone()).collect();
        // `cap-notify` is negotiated by a connection, so the answer is per
        // connection too: a client that never asked is not told.
        let registry = senders.read().await;
        for cid in &client_ids {
            if !cap_new.is_empty() {
                let cap_line = cap_new.join(" ");
                registry.deliver_requiring(
                    cid,
                    "cap-notify",
                    &Message::new("CAP", vec!["*".into(), "NEW".into(), cap_line])
                        .with_prefix(&server_name),
                );
            }
            if !cap_del.is_empty() {
                let cap_line = cap_del.join(" ");
                registry.deliver_requiring(
                    cid,
                    "cap-notify",
                    &Message::new("CAP", vec!["*".into(), "DEL".into(), cap_line])
                        .with_prefix(&server_name),
                );
            }
        }
    }

    Ok(config_path.to_string_lossy().to_string())
}

/// REHASH — reload the config file without restarting (oper only).
/// Replies: 382 RPL_REHASHING
pub async fn handle_rehash(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: Arc<RwLock<Config>>,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let server_name = cfg.read().await.server.name.clone();

    let (is_oper, nick) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.may(crate::config::OperPrivilege::Rehash),
                    g.nick_or_id().to_string(),
                )
            }
            None => return Ok(()),
        }
    };

    if !is_oper {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
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
                Message::new(
                    "FAIL",
                    vec![
                        "REHASH".into(),
                        "INTERNAL_ERROR".into(),
                        "*".into(),
                        "No config path available".into(),
                    ],
                )
                .with_prefix(&server_name),
                label,
            )
            .await;
            return Ok(());
        }
    };

    let config_file = match reload_config(&state, &senders, &cfg, &config_path).await {
        Ok(file) => file,
        Err(e) => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REHASH".into(),
                        "INTERNAL_ERROR".into(),
                        "*".into(),
                        format!("Failed to load config: {}", e),
                    ],
                )
                .with_prefix(&server_name),
                label,
            )
            .await;
            return Ok(());
        }
    };

    info!("Config reloaded by {}", nick);
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &server_name,
        's',
        &format!("{nick} rehashed the configuration"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new("382", vec![nick, config_file, "Rehashing".into()]).with_prefix(&server_name),
        label,
    )
    .await;

    // A changed expiry policy should be seen to work, not waited an hour for.
    tokio::spawn(async move {
        crate::expiry::sweep(&cfg, &state, &channels, &senders).await;
    });

    Ok(())
}

// ─── ADMIN ────────────────────────────────────────────────────────────────────

/// `ADMIN [<target>]` — who is responsible for this server.
/// Replies: 256 RPL_ADMINME, 257/258 RPL_ADMINLOC1/2, 259 RPL_ADMINEMAIL.
pub async fn handle_admin(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = cfg.server.name.as_str();
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let name = cfg
        .server
        .admin_name
        .clone()
        .unwrap_or_else(|| format!("Administrator of {}", cfg.network.name));
    let location = cfg
        .server
        .admin_location
        .clone()
        .unwrap_or_else(|| cfg.server.name.clone());
    let email = cfg
        .server
        .admin_email
        .clone()
        .unwrap_or_else(|| "not configured".to_string());

    for (numeric, text) in [
        ("256", format!("Administrative info about {}", s)),
        ("257", name),
        ("258", location),
        ("259", email),
    ] {
        reply_to_client(
            &senders,
            client_id,
            Message::new(numeric, vec![nick.clone(), text]).with_prefix(s),
            label,
        )
        .await;
    }
    Ok(())
}

/// `DIE` — shut the server down. Operators only.
pub async fn handle_die(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    const PRIVILEGE: crate::config::OperPrivilege = crate::config::OperPrivilege::Die;
    let (nick, allowed) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (g.nick_or_id().to_string(), g.may(PRIVILEGE))
            }
            None => return Ok(()),
        }
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    tracing::warn!(oper = %nick, "DIE: shutting down on operator request");
    let notice = Message::new(
        "NOTICE",
        vec![
            "*".into(),
            format!("Server shutting down (requested by {})", nick),
        ],
    )
    .with_prefix(&cfg.server.name);
    for sink in senders.read().await.all_sinks() {
        sink.send(notice.clone());
    }

    // Take the same path as a signal, so the shutdown is the ordinary one.
    #[cfg(unix)]
    {
        let _ = nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM);
    }
    Ok(())
}

// ─── Server bans ──────────────────────────────────────────────────────────────

/// Normalise a ban mask to `nick!user@host`, the form connections are matched in.
fn normalize_ban_mask(mask: &str) -> String {
    if mask.contains('!') {
        mask.to_string()
    } else if mask.contains('@') {
        format!("*!{}", mask)
    } else {
        format!("*!*@{}", mask)
    }
}

/// Whether a ban mask says who it is for.
///
/// One made only of wildcards is for everybody — the operator setting it
/// included, and everybody who tries to connect after the next restart, when
/// it is read back from the database with nobody left inside to lift it. Four
/// literal characters is the line other servers draw, and the same one is
/// drawn here, for a mask typed by an operator and for one sent by a peer.
pub fn mask_too_broad(normalized: &str) -> bool {
    // `*!*@10.0.0.0/8` has plenty of literal characters and covers sixteen
    // million addresses; a network is judged by its size, not its spelling.
    if let Some((_, host)) = normalized.rsplit_once('@') {
        if host.contains('/') {
            return crate::persist::network_too_broad(host);
        }
    }
    normalized
        .chars()
        .filter(|c| !matches!(c, '*' | '?' | '!' | '@' | '.'))
        .count()
        < 4
}

/// Whether a ban of either kind says who it is for. A D-line has to be an
/// address or a network at all, and not one wider than an operator's call.
pub fn ban_too_broad(mask: &str, kind: crate::persist::BanKind) -> bool {
    match kind {
        // A shun names somebody the way a K-line does, so it is held to the
        // same rule: a mask made of wildcards would silence the network.
        // An exemption is held to the same rule, and for a sharper reason:
        // a mask of wildcards would not silence the network, it would vouch
        // for it — every ban and every blocklist answer undone at once.
        crate::persist::BanKind::Kline
        | crate::persist::BanKind::Shun
        | crate::persist::BanKind::Exempt => mask_too_broad(mask),
        crate::persist::BanKind::Dline => {
            let parses = crate::persist::address_in(mask, "0.0.0.0").is_some()
                || crate::persist::address_in(mask, "::").is_some();
            !parses || crate::persist::network_too_broad(mask)
        }
    }
}

/// Whether a ban of this kind, with this mask, would cover a connection.
fn ban_covers(mask: &str, kind: crate::persist::BanKind, source: &str, ip: &str) -> bool {
    crate::persist::ServerBan {
        mask: mask.to_string(),
        reason: String::new(),
        set_by: String::new(),
        set_at: 0,
        expires_at: None,
        kind,
    }
    .matches(source, ip)
}

/// Put a ban into effect here: remember it, and close every connection it
/// covers. Returns who was closed. The same whether an operator on this server
/// set it or one on another did.
pub async fn enforce_ban(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    server_name: &str,
    ban: &crate::persist::ServerBan,
) -> Vec<(String, String)> {
    let mut hits: Vec<(String, String)> = Vec::new();
    {
        let mut state_w = state.write().await;
        state_w
            .server_bans
            .retain(|b| !(b.kind == ban.kind && b.mask == ban.mask));
        state_w.server_bans.push(ban.clone());
        state_w.publish_door_bans();
        if ban.kind.is_exemption() {
            // Nobody is closed and nobody is silenced: this says who is *not*
            // to be kept out. It takes effect on whoever knocks next, and on
            // the shuns, which may now be covering somebody vouched for.
            drop(state_w);
            apply_shuns(state).await;
            return hits;
        }
        for (id, client) in state_w.users() {
            let g = client.read().await;
            // Only this server's own users are closed. Somebody on another
            // server is that server's to close, and it hears the same ban.
            if g.server.is_some() {
                continue;
            }
            let source = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
            // A ban placed now is judged the same way a ban already standing
            // is judged when somebody arrives: an exemption comes first.
            // Otherwise being vouched for would only protect whoever was not
            // already connected when the ban was typed.
            if ban.matches(&source, &g.host) && state_w.exemption_for(&source, &g.host).is_none() {
                hits.push((id.clone(), g.nick_or_id().to_string()));
            }
        }
    }
    if !ban.kind.closes_the_connection() {
        // Nobody is closed and nobody is told. Their connection carries the
        // answer from here on, so the dispatch loop does not match masks on
        // every line they send.
        apply_shuns(state).await;
        for (_, hit_nick) in &hits {
            tracing::info!(nick = %hit_nick, mask = %ban.mask, "Shunning user");
        }
        return hits;
    }
    for (id, hit_nick) in &hits {
        senders.write().await.close_user(
            id,
            Message::new(
                "ERROR",
                vec![format!("Closing link: banned ({})", ban.reason)],
            )
            .with_prefix(server_name),
        );
        tracing::info!(nick = %hit_nick, mask = %ban.mask, "Disconnecting banned user");
    }
    hits
}

/// Work out again who the shuns in force cover.
///
/// Read once per message from the dispatch loop, so it is worked out here —
/// when a shun is set, lifted or expires — rather than by matching every
/// mask against every line. Only this server's own users: somebody on
/// another server is shunned there, by the same shun, which crossed the link.
pub async fn apply_shuns(state: &Arc<RwLock<ServerState>>) {
    let (shuns, people) = {
        let state_r = state.read().await;
        let shuns = state_r.shuns_in_force();
        let mut people = Vec::new();
        for (id, client) in state_r.users() {
            let g = client.read().await;
            if g.server.is_some() {
                continue;
            }
            let source = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
            // Somebody vouched for is not silenced either: a shun is a ban,
            // and an exemption is about all of them.
            if state_r.exemption_for(&source, &g.host).is_some() {
                continue;
            }
            people.push((id.clone(), source, g.host.clone()));
        }
        (shuns, people)
    };
    let covered: std::collections::HashSet<String> = people
        .into_iter()
        .filter(|(_, source, host)| shuns.iter().any(|b| b.matches(source, host)))
        .map(|(id, _, _)| id)
        .collect();
    state.write().await.shunned = covered;
}

/// `KLINE [<duration>] <mask> :<reason>` — refuse connections matching a mask.
///
/// Duration is in seconds; omit it, or pass 0, for a ban with no end. Existing
/// connections that match are closed.
pub async fn handle_kline(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, own_source, own_ip)) = may_ban(&state, &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let Some((duration, mask, reason)) = ban_arguments(&msg, "KLINE", &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };

    // A mask has to say who it is for. One made only of wildcards is for
    // everybody — the operator setting it included, and everybody who tries
    // to connect after the next restart, when it is read back from the
    // database with nobody left inside to lift it. Four literal characters
    // is the line other servers draw, and the same one is drawn here.
    let normalized = normalize_ban_mask(&mask);
    if ban_too_broad(&normalized, crate::persist::BanKind::Kline) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "KLINE".into(),
                    "MASK_TOO_BROAD".into(),
                    normalized.clone(),
                    "A ban mask needs at least four characters that are not wildcards, and a network no wider than a /8".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if ban_covers(&normalized, crate::persist::BanKind::Kline, &own_source, &own_ip) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "KLINE".into(),
                    "MATCHES_YOURSELF".into(),
                    normalized.clone(),
                    "That mask matches your own connection".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let ban = new_ban(normalized, reason, &nick, duration, crate::persist::BanKind::Kline);
    place_ban(client_id, &nick, ban, &state, &senders, cfg, label).await;
    Ok(())
}

/// Who is asking to ban, if they may: their nick, their `nick!user@host`,
/// and their real address — the last two so a ban that would hit the person
/// setting it can be refused.
async fn may_ban(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    client_id: &str,
    cfg: &Config,
    label: Option<&str>,
) -> Option<(String, String, String)> {
    let (nick, allowed, own_source, own_ip) = {
        let state_r = state.read().await;
        let c = state_r.clients.get(client_id)?;
        let g = c.read().await;
        (
            g.nick_or_id().to_string(),
            g.may(crate::config::OperPrivilege::Ban),
            g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
            g.host.clone(),
        )
    };
    if !allowed {
        reply_to_client(
            senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return None;
    }
    Some((nick, own_source, own_ip))
}

/// `[<duration>] <mask> :<reason>`, the shape KLINE and DLINE share. Duration
/// is in seconds; omitted, or 0, for a ban with no end.
async fn ban_arguments(
    msg: &Message,
    command: &str,
    senders: &Senders,
    client_id: &str,
    cfg: &Config,
    label: Option<&str>,
) -> Option<(i64, String, String)> {
    let params: Vec<&str> = msg.params.iter().map(|p| p.as_str()).collect();
    let (duration, mask) = match params.first().and_then(|p| p.parse::<i64>().ok()) {
        Some(secs) => (secs, params.get(1).copied().unwrap_or("")),
        None => (0, params.first().copied().unwrap_or("")),
    };
    let reason = msg
        .trailing()
        .filter(|t| *t != mask)
        .unwrap_or("No reason given")
        .to_string();
    if mask.is_empty() {
        reply_to_client(
            senders,
            client_id,
            Message::new("461", vec![command.into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return None;
    }
    Some((duration, mask.to_string(), reason))
}

/// What to call a ban of this kind when telling somebody about it.
fn ban_noun(kind: crate::persist::BanKind) -> &'static str {
    match kind {
        crate::persist::BanKind::Kline => "K-line",
        crate::persist::BanKind::Dline => "D-line",
        crate::persist::BanKind::Shun => "shun",
        crate::persist::BanKind::Exempt => "exemption",
    }
}

fn new_ban(
    mask: String,
    reason: String,
    set_by: &str,
    duration: i64,
    kind: crate::persist::BanKind,
) -> crate::persist::ServerBan {
    crate::persist::ServerBan {
        mask,
        reason,
        set_by: set_by.to_string(),
        set_at: chrono::Utc::now().timestamp(),
        expires_at: if duration > 0 {
            // The duration is whatever number was typed. Added to the clock it
            // can leave the range a timestamp has, which in a release build
            // wraps round to the past and quietly makes the ban expired.
            Some(chrono::Utc::now().timestamp().saturating_add(duration))
        } else {
            None
        },
        kind,
    }
}

/// Put a new ban into the world: the database, the network, this server's
/// own connections, the operators' notices, and the reply to whoever set it.
async fn place_ban(
    client_id: &str,
    nick: &str,
    ban: crate::persist::ServerBan,
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    cfg: &Config,
    label: Option<&str>,
) {
    if let Some(ref pool) = cfg.db {
        if let Err(e) = crate::persist::save_server_ban(pool, &ban).await {
            tracing::error!(client_id, error = %e, kind = ban.kind.letter(), "Could not store the ban");
        }
    }
    tracing::warn!(
        oper = %nick, kind = ban.kind.letter(), mask = %ban.mask, expires = ?ban.expires_at, "Server ban added"
    );

    // A ban is a fact about the network, not about the server it was typed
    // at: somebody shut out here and welcome one server over is not shut out.
    crate::link::announce_kline(cfg, &ban).await;
    let hits = enforce_ban(state, senders, &cfg.server.name, &ban).await;
    crate::commands::registration::notify_opers(
        state,
        senders,
        &cfg.server.name,
        'b',
        &format!(
            "{} added a {} on {}{} ({})",
            nick,
            ban_noun(ban.kind),
            ban.mask,
            match ban.expires_at {
                Some(at) => format!(" until {}", clock_time(at)),
                None => String::new(),
            },
            ban.reason,
        ),
    )
    .await;

    reply_to_client(
        senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![
                nick.to_string(),
                if ban.kind.is_exemption() {
                    format!(
                        "{} on {} added: the bans and the blocklist no longer apply there",
                        ban_noun(ban.kind),
                        ban.mask,
                    )
                } else {
                    format!(
                        "{} on {} added ({} connection(s) {})",
                        ban_noun(ban.kind),
                        ban.mask,
                        hits.len(),
                        if ban.kind.closes_the_connection() { "closed" } else { "silenced" }
                    )
                },
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
}

/// `DLINE [<duration>] <address|network> :<reason>` — turn an address away
/// the moment it connects.
///
/// A K-line is judged once a connection has a nick and a user, which is
/// after the handshake, the DNS blocklist, and a slot in the connection
/// tables have all been spent on it. A D-line is judged before any of that,
/// on nothing but the address, which is the right thing for an address that
/// is only ever going to be turned away. A network is written as CIDR:
/// `203.0.113.0/24`, `2001:db8::/32`. Nothing wider than a /8 or a /16.
pub async fn handle_dline(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, _own_source, own_ip)) = may_ban(&state, &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let Some((duration, mask, reason)) = ban_arguments(&msg, "DLINE", &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let mask = mask.to_lowercase();
    if ban_too_broad(&mask, crate::persist::BanKind::Dline) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "DLINE".into(),
                    "MASK_TOO_BROAD".into(),
                    mask.clone(),
                    "A D-line is an address or a network in CIDR form, no wider than a /8 (IPv4) or a /16 (IPv6)".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if ban_covers(&mask, crate::persist::BanKind::Dline, "", &own_ip) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "DLINE".into(),
                    "MATCHES_YOURSELF".into(),
                    mask.clone(),
                    "That address covers your own connection".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let ban = new_ban(mask, reason, &nick, duration, crate::persist::BanKind::Dline);
    place_ban(client_id, &nick, ban, &state, &senders, cfg, label).await;
    Ok(())
}

/// `UNDLINE <address|network>` — lift a D-line.
pub async fn handle_undline(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, _, _)) = may_ban(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let mask = msg
        .params
        .first()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if mask.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "UNDLINE".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let removed = match cfg.db {
        Some(ref pool) => crate::persist::delete_server_ban(pool, &mask, crate::persist::BanKind::Dline).await,
        None => false,
    };
    let known = {
        let mut state_w = state.write().await;
        let before = state_w.server_bans.len();
        state_w
            .server_bans
            .retain(|b| !(b.kind == crate::persist::BanKind::Dline && b.mask == mask));
        state_w.publish_door_bans();
        state_w.server_bans.len() != before
    };
    tracing::warn!(oper = %nick, %mask, removed, "D-line removed");
    crate::link::announce_unkline(cfg, &mask, crate::persist::BanKind::Dline).await;
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'b',
        &format!("{nick} removed the D-line on {mask}"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![
                nick,
                if known || removed {
                    format!("D-line on {mask} removed")
                } else {
                    format!("No D-line on {mask}")
                },
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// `UNKLINE <mask>` — remove a ban.
pub async fn handle_unkline(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    const PRIVILEGE: crate::config::OperPrivilege = crate::config::OperPrivilege::Ban;
    let (nick, allowed) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (g.nick_or_id().to_string(), g.may(PRIVILEGE))
            }
            None => return Ok(()),
        }
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let mask = normalize_ban_mask(msg.params.first().map(|s| s.as_str()).unwrap_or(""));
    let removed = match cfg.db {
        Some(ref pool) => crate::persist::delete_server_ban(pool, &mask, crate::persist::BanKind::Kline).await,
        None => false,
    };
    {
        let mut state_w = state.write().await;
        state_w
            .server_bans
            .retain(|b| !(b.kind == crate::persist::BanKind::Kline && b.mask == mask));
        state_w.publish_door_bans();
    }
    tracing::warn!(oper = %nick, %mask, removed, "Server ban removed");
    crate::link::announce_unkline(cfg, &mask, crate::persist::BanKind::Kline).await;
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'b',
        &format!("{nick} removed the server ban on {mask}"),
    )
    .await;

    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![
                nick,
                if removed {
                    format!("Ban on {} removed", mask)
                } else {
                    format!("No ban on {}", mask)
                },
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// A moment, as a person reads one.
fn clock_time(at: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| at.to_string())
}

/// What an operator gets back from CONNECT or SQUIT when it cannot be done.
fn link_fail(cfg: &Config, command: &str, code: &str, target: &str, text: &str) -> Message {
    Message::new(
        "FAIL",
        vec![command.into(), code.into(), target.into(), text.into()],
    )
    .with_prefix(&cfg.server.name)
}

/// Whether this client may change the shape of the network, and its nick.
async fn may_shape_links(
    state: &Arc<RwLock<ServerState>>,
    client_id: &str,
) -> Option<(String, bool)> {
    let state_r = state.read().await;
    let client = state_r.clients.get(client_id)?;
    let g = client.read().await;
    Some((
        g.nick_or_id().to_string(),
        g.may(crate::config::OperPrivilege::Links),
    ))
}

/// `SQUIT <server> [:<reason>]` — drop a link to a directly attached server.
///
/// The peer is sent a SQUIT of its own first, so it knows this was a decision
/// and not a failure, and then everything a failure would have done follows:
/// the users behind it are gone from here, and if this side has autoconnect
/// for it, it will be dialled again in a while. A server behind a peer is that
/// peer's to drop.
pub async fn handle_squit(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, allowed)) = may_shape_links(&state, client_id).await else {
        return Ok(());
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let Some(target) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "SQUIT".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let reason = msg
        .params
        .get(1)
        .cloned()
        .unwrap_or_else(|| format!("Link closed by {nick}"));
    let Some(ref links) = cfg.links_runtime else {
        reply_to_client(
            &senders,
            client_id,
            link_fail(cfg, "SQUIT", "NO_LINKS", &target, "This server has no links"),
            label,
        )
        .await;
        return Ok(());
    };
    let closed = links.read().await.close_peer(&target, &reason);
    match closed {
        Some(name) => {
            tracing::warn!(oper = %nick, server = %name, %reason, "SQUIT");
            crate::commands::registration::notify_opers(
                &state,
                &senders,
                &cfg.server.name,
                'l',
                &format!("{nick} closed the link to {name} ({reason})"),
            )
            .await;
            reply_to_client(
                &senders,
                client_id,
                Message::new("NOTICE", vec![nick, format!("Closing link to {name}: {reason}")])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        None => {
            reply_to_client(
                &senders,
                client_id,
                link_fail(
                    cfg,
                    "SQUIT",
                    "NO_SUCH_LINK",
                    &target,
                    "Not a directly attached server",
                ),
                label,
            )
            .await;
        }
    }
    Ok(())
}

/// `CONNECT <server>` — dial a configured `[[links]]` block now.
///
/// The block has to exist and have a host to dial; a block without one is the
/// side that waits to be connected to. A server already linked is not dialled
/// again, because one link per server is a rule the link code keeps too.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connect(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg_shared: Arc<RwLock<Config>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, allowed)) = may_shape_links(&state, client_id).await else {
        return Ok(());
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let Some(target) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "CONNECT".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(ref links) = cfg.links_runtime else {
        reply_to_client(
            &senders,
            client_id,
            link_fail(cfg, "CONNECT", "NO_LINKS", &target, "This server has no links configured"),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(link) = cfg
        .links
        .iter()
        .find(|l| l.name.eq_ignore_ascii_case(&target) || l.sid.eq_ignore_ascii_case(&target))
        .cloned()
    else {
        reply_to_client(
            &senders,
            client_id,
            link_fail(cfg, "CONNECT", "NO_SUCH_LINK", &target, "No [[links]] block by that name"),
            label,
        )
        .await;
        return Ok(());
    };
    if links.read().await.is_linked(&link.sid) {
        reply_to_client(
            &senders,
            client_id,
            link_fail(cfg, "CONNECT", "ALREADY_LINKED", &link.name, "Already linked"),
            label,
        )
        .await;
        return Ok(());
    }
    let Some(ref host) = link.host else {
        reply_to_client(
            &senders,
            client_id,
            link_fail(
                cfg,
                "CONNECT",
                "NO_HOST",
                &link.name,
                "That link has no host to dial; this side waits to be connected to",
            ),
            label,
        )
        .await;
        return Ok(());
    };
    let where_to = format!("{}:{}", host, link.port);
    tracing::warn!(oper = %nick, server = %link.name, target = %where_to, "CONNECT");
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'l',
        &format!("{nick} is connecting to {} ({where_to})", link.name),
    )
    .await;
    let ctx = crate::link::LinkContext {
        cfg: cfg_shared,
        state,
        channels,
        senders: senders.clone(),
        links: links.clone(),
    };
    crate::link::connect_once(link.clone(), ctx);
    reply_to_client(
        &senders,
        client_id,
        Message::new("NOTICE", vec![nick, format!("Connecting to {} ({where_to})", link.name)])
            .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// `SANICK <nick> <newnick>` — an operator changes somebody else's nick.
///
/// The milder cousin of KILL: somebody sitting on a name they should not
/// have is moved off it rather than off the network. The change happens the
/// way any nick change happens, so every channel, watcher and server hears
/// it the same way, and the person is told who did it. Somebody on another
/// server is that server's to rename, so the request goes there.
pub async fn handle_sanick(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let (oper_nick, allowed, oper_id) = {
        let state_r = state.read().await;
        let Some(client) = state_r.clients.get(client_id) else {
            return Ok(());
        };
        let g = client.read().await;
        (
            g.nick_or_id().to_string(),
            g.may(crate::config::OperPrivilege::Kill),
            state_r.user_id(client_id),
        )
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "481",
                vec![oper_nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }
    let (Some(target_nick), Some(new_nick)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
    else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![oper_nick, "SANICK".into(), "Not enough parameters".into()])
                .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    };
    if !crate::commands::registration::is_valid_nick(&new_nick) {
        reply_to_client(
            &senders,
            client_id,
            Message::new("432", vec![oper_nick, new_nick, "Erroneous nickname".into()]).with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }
    let (target_id, target_account, remote, current) = {
        let state_r = state.read().await;
        let Some(tid) = state_r
            .nick_to_id
            .get(&crate::casefold::upper(&target_nick))
            .cloned()
        else {
            drop(state_r);
            reply_to_client(
                &senders,
                client_id,
                Message::new("401", vec![oper_nick, target_nick, "No such nick".into()]).with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        };
        let (account, remote, current) = match state_r.clients.get(&tid) {
            Some(c) => {
                let g = c.read().await;
                (g.account.clone(), g.server.is_some(), g.nick.clone())
            }
            None => (None, false, None),
        };
        if state_r
            .nick_to_id
            .get(&crate::casefold::upper(&new_nick))
            .is_some_and(|holder| *holder != tid)
        {
            drop(state_r);
            reply_to_client(
                &senders,
                client_id,
                Message::new("433", vec![oper_nick, new_nick, "Nickname is already in use".into()])
                    .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
        (tid, account, remote, current)
    };
    if current.as_deref() == Some(new_nick.as_str()) {
        return Ok(());
    }
    // A registered nick belongs to its account, and an operator moving
    // somebody onto one they do not own would be handing it over.
    let (holds, grouped_to_other) = {
        let state_r = state.read().await;
        (
            state_r.account_holds_nick(target_account.as_deref(), &new_nick),
            state_r.grouped_owner(&new_nick).is_some(),
        )
    };
    if cfg.server.nick_protection && !holds {
        let registered = grouped_to_other
            || match cfg.db {
                Some(ref pool) => {
                    crate::persist::nick_is_registered(pool, &cfg.db_health, &new_nick).await
                }
                None => false,
            };
        if registered {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "433",
                    vec![oper_nick, new_nick, "Nickname is registered to another account".into()],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
    }
    tracing::warn!(client_id, oper = %oper_nick, target = %target_nick, %new_nick, remote, "SANICK");
    if remote {
        let ask = Message::new("SANICK", vec![target_id.clone(), new_nick.clone()]);
        crate::link::route_to_user(cfg, &oper_id, &target_id, &ask).await;
    } else {
        let changed = crate::commands::registration::apply_nick_change(
            &target_id,
            &new_nick,
            state.clone(),
            channels,
            senders.clone(),
            cfg,
            None,
            Some(&oper_nick),
        )
        .await?;
        if !changed {
            return Ok(());
        }
    }
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        s,
        'k',
        &format!("{oper_nick} changed {target_nick}'s nick to {new_nick}"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![oper_nick, format!("Changed {target_nick}'s nick to {new_nick}")],
        )
        .with_prefix(s),
        label,
    )
    .await;
    Ok(())
}

/// Who is asking for one of the SA* commands, if they may: their nick and
/// user id. The `channels` privilege covers them, as it covers CHANOWN.
async fn may_force(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    client_id: &str,
    cfg: &Config,
    label: Option<&str>,
) -> Option<(String, String)> {
    let (nick, allowed, uid) = {
        let state_r = state.read().await;
        let c = state_r.clients.get(client_id)?;
        let g = c.read().await;
        (
            g.nick_or_id().to_string(),
            g.may(crate::config::OperPrivilege::Channels),
            state_r.user_id(client_id),
        )
    };
    if !allowed {
        reply_to_client(
            senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return None;
    }
    Some((nick, uid))
}

/// The user id behind a nick, whether it is on this server, and one of its
/// connections here (the one a reply would go to).
async fn find_target(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    nick: &str,
) -> Option<(String, bool, String)> {
    let state_r = state.read().await;
    let uid = state_r.nick_to_id.get(&crate::casefold::upper(nick))?.clone();
    let remote = match state_r.clients.get(&uid) {
        Some(c) => c.read().await.server.is_some(),
        None => return None,
    };
    let session = senders
        .read()
        .await
        .sessions_of(&uid)
        .into_iter()
        .next()
        .unwrap_or_else(|| uid.clone());
    Some((uid, remote, session))
}

/// Put somebody in a channel on an operator's say-so. The server invites
/// them first, so the doors an invitation opens — `+b`, `+i`, `+k`, `+l`,
/// `+j` — open; the ones it does not (`+O`, `+Z`, `+R`) still hold, and the
/// operator is told, because a forced join that broke a channel's promise
/// would be the server lying on the operator's behalf.
pub async fn force_join(
    target_uid: &str,
    session: &str,
    channel: &str,
    by: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<crate::channel::ChannelStore>>,
    senders: &Senders,
    cfg: &Config,
) -> anyhow::Result<()> {
    let key = crate::channel::canonical_channel_key(channel);
    {
        let store = channels.read().await;
        if let Some(ch) = store.channels.get(&key) {
            ch.write().await.invite_list.insert(target_uid.to_string());
        }
    }
    let nick = match state.read().await.clients.get(target_uid) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => target_uid.to_string(),
    };
    senders.read().await.deliver(
        target_uid,
        &Message::new(
            "NOTICE",
            vec![nick, format!("You have been joined to {channel} by operator {by}")],
        )
        .with_prefix(&cfg.server.name),
    );
    crate::commands::channel_cmds::handle_join(
        session,
        Message::new("JOIN", vec![channel.to_string()]),
        state.clone(),
        channels.clone(),
        senders.clone(),
        cfg,
        None,
    )
    .await
}

/// Take somebody out of a channel on an operator's say-so. An ordinary PART
/// in every way that shows, with the reason the operator gave.
pub async fn force_part(
    target_uid: &str,
    session: &str,
    channel: &str,
    by: &str,
    reason: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<crate::channel::ChannelStore>>,
    senders: &Senders,
    cfg: &Config,
) -> anyhow::Result<()> {
    let nick = match state.read().await.clients.get(target_uid) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => target_uid.to_string(),
    };
    senders.read().await.deliver(
        target_uid,
        &Message::new(
            "NOTICE",
            vec![nick, format!("You have been removed from {channel} by operator {by} ({reason})")],
        )
        .with_prefix(&cfg.server.name),
    );
    crate::commands::channel_cmds::handle_part(
        session,
        Message::new("PART", vec![channel.to_string(), reason.to_string()]),
        state.clone(),
        channels.clone(),
        senders.clone(),
        cfg,
        None,
    )
    .await
}

/// `SAJOIN <nick> <#channel>` — put somebody in a channel.
pub async fn handle_sajoin(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((oper_nick, oper_id)) = may_force(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let (Some(target_nick), Some(channel)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
    else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![oper_nick, "SAJOIN".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    if !channel.starts_with('#') || channel.len() > 64 || channel.contains([' ', ',']) {
        reply_to_client(
            &senders,
            client_id,
            Message::new("403", vec![oper_nick, channel, "No such channel".into()]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let Some((target_uid, remote, session)) = find_target(&state, &senders, &target_nick).await else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("401", vec![oper_nick, target_nick, "No such nick".into()]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    tracing::warn!(client_id, oper = %oper_nick, target = %target_nick, %channel, remote, "SAJOIN");
    if remote {
        let ask = Message::new("SAJOIN", vec![target_uid.clone(), channel.clone()]);
        crate::link::route_to_user(cfg, &oper_id, &target_uid, &ask).await;
    } else {
        force_join(&target_uid, &session, &channel, &oper_nick, &state, &channels, &senders, cfg).await?;
    }
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'k',
        &format!("{oper_nick} joined {target_nick} to {channel}"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new("NOTICE", vec![oper_nick, format!("Joined {target_nick} to {channel}")])
            .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// `SAPART <nick> <#channel> [:<reason>]` — take somebody out of a channel.
pub async fn handle_sapart(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((oper_nick, oper_id)) = may_force(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let (Some(target_nick), Some(channel)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
    else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![oper_nick, "SAPART".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let reason = msg
        .params
        .get(2)
        .cloned()
        .unwrap_or_else(|| format!("Removed by {oper_nick}"));
    let Some((target_uid, remote, session)) = find_target(&state, &senders, &target_nick).await else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("401", vec![oper_nick, target_nick, "No such nick".into()]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let key = crate::channel::canonical_channel_key(&channel);
    let there = {
        let store = channels.read().await;
        match store.channels.get(&key) {
            Some(ch) => ch.read().await.members.contains_key(&target_uid),
            None => false,
        }
    };
    if !there {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "441",
                vec![oper_nick, target_nick, channel, "They aren't on that channel".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    tracing::warn!(client_id, oper = %oper_nick, target = %target_nick, %channel, %reason, remote, "SAPART");
    if remote {
        let ask = Message::new("SAPART", vec![target_uid.clone(), channel.clone(), reason.clone()]);
        crate::link::route_to_user(cfg, &oper_id, &target_uid, &ask).await;
    } else {
        force_part(&target_uid, &session, &channel, &oper_nick, &reason, &state, &channels, &senders, cfg)
            .await?;
    }
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'k',
        &format!("{oper_nick} removed {target_nick} from {channel} ({reason})"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new("NOTICE", vec![oper_nick, format!("Removed {target_nick} from {channel}")])
            .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// `SAMODE <#channel> <modes> [<args>]` — set channel modes without holding
/// ops there. Shown as the operator's own MODE, because it is; the
/// operators are told it was done this way.
pub async fn handle_samode(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((oper_nick, _)) = may_force(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let (Some(channel), Some(_)) = (msg.params.first().cloned(), msg.params.get(1)) else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![oper_nick, "SAMODE".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    if !channel.starts_with('#') {
        reply_to_client(
            &senders,
            client_id,
            Message::new("403", vec![oper_nick, channel, "No such channel".into()]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let change = msg.params[1..].join(" ");
    tracing::warn!(client_id, oper = %oper_nick, %channel, %change, "SAMODE");
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'k',
        &format!("{oper_nick} used SAMODE on {channel}: {change}"),
    )
    .await;
    let mut as_mode = msg.clone();
    as_mode.command = "MODE".to_string();
    crate::commands::channel_cmds::handle_mode_as(
        client_id, as_mode, state, channels, senders, cfg, label, true,
    )
    .await
}

/// `TESTMASK <mask>` — how many people a ban on this mask would hit, here
/// and on the rest of the network, before anybody sets it.
pub async fn handle_testmask(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let (nick, is_oper) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (g.nick_or_id().to_string(), g.oper)
            }
            None => return Ok(()),
        }
    };
    if !is_oper {
        reply_to_client(
            &senders,
            client_id,
            Message::new("481", vec![nick, "Permission Denied- You're not an IRC operator".into()])
                .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }
    let Some(mask) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "TESTMASK".into(), "Not enough parameters".into()]).with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    };
    let normalized = normalize_ban_mask(&mask);
    let (local, remote) = {
        let state_r = state.read().await;
        let mut local = 0usize;
        let mut remote = 0usize;
        for (_, client) in state_r.users() {
            let g = client.read().await;
            let source = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
            if ban_covers(&normalized, crate::persist::BanKind::Kline, &source, &g.host) {
                if g.server.is_some() {
                    remote += 1;
                } else {
                    local += 1;
                }
            }
        }
        (local, remote)
    };
    // 724 RPL_TESTMASK
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "724",
            vec![
                nick,
                normalized,
                local.to_string(),
                remote.to_string(),
                "Number of matches (local, remote)".into(),
            ],
        )
        .with_prefix(s),
        label,
    )
    .await;
    Ok(())
}

/// `MAP` — the network as a tree, with how many people are on each server.
pub async fn handle_map(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };
    // People per server, counted once.
    let mut on: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut local = 0usize;
    {
        let state_r = state.read().await;
        for (_, client) in state_r.users() {
            match client.read().await.server.clone() {
                Some(server) => *on.entry(server).or_insert(0) += 1,
                None => local += 1,
            }
        }
    }
    let mut rows = vec![format!("{} [{} users]", s, local)];
    if let Some(ref links) = cfg.links_runtime {
        let links = links.read().await;
        let mut servers: Vec<_> = links.all().cloned().collect();
        servers.sort_by(|a, b| a.hops.cmp(&b.hops).then(a.name.cmp(&b.name)));
        for server in servers {
            let users = on.get(&server.name).or_else(|| on.get(&server.sid)).copied().unwrap_or(0);
            rows.push(format!(
                "{}`-{} [{} users]",
                "  ".repeat(server.hops.saturating_sub(1) as usize),
                server.name,
                users
            ));
        }
    }
    for row in rows {
        // 015 RPL_MAP
        reply_to_client(&senders, client_id, Message::new("015", vec![nick.clone(), row]).with_prefix(s), label).await;
    }
    // 017 RPL_MAPEND
    reply_to_client(&senders, client_id, Message::new("017", vec![nick, "End of /MAP".into()]).with_prefix(s), label).await;
    Ok(())
}

/// `NOEXPIRE <account|#channel> [ON|OFF]` — keep a name or a room out of
/// `[expiry]`'s reach, or put it back; without ON or OFF, say which it is.
/// An operator's decision, kept with the row it is about.
pub async fn handle_noexpire(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let (nick, allowed) = {
        let state_r = state.read().await;
        let Some(c) = state_r.clients.get(client_id) else {
            return Ok(());
        };
        let g = c.read().await;
        (g.nick_or_id().to_string(), g.may(crate::config::OperPrivilege::Channels))
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new("481", vec![nick, "Permission Denied- You're not an IRC operator".into()])
                .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }
    let Some(target) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "NOEXPIRE".into(), "Not enough parameters".into()]).with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    };
    let Some(pool) = cfg.db.as_ref().filter(|_| !cfg.db_health.is_down()) else {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec!["NOEXPIRE".into(), "TEMPORARILY_UNAVAILABLE".into(), target, "Try again later".into()],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    };
    let (kind, name) = if target.starts_with('#') {
        ('c', crate::channel::canonical_channel_key(&target))
    } else {
        ('a', target.clone())
    };
    let wanted = match msg.params.get(1).map(|p| p.to_ascii_uppercase()) {
        None => None,
        Some(p) if p == "ON" => Some(true),
        Some(p) if p == "OFF" => Some(false),
        Some(_) => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec!["NOEXPIRE".into(), "INVALID_PARAMS".into(), target, "NOEXPIRE <target> [ON|OFF]".into()],
                )
                .with_prefix(s),
                label,
            )
            .await;
            return Ok(());
        }
    };
    let known = match wanted {
        Some(on) => crate::persist::set_noexpire(pool, kind, &name, on).await,
        None => crate::persist::noexpire(pool, kind, &name).await.is_some(),
    };
    if !known {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "NOEXPIRE".into(),
                    "NO_SUCH_TARGET".into(),
                    target,
                    if kind == 'c' { "No such registered channel" } else { "No such account" }.into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }
    let on = match wanted {
        Some(on) => on,
        None => crate::persist::noexpire(pool, kind, &name).await.unwrap_or(false),
    };
    if wanted.is_some() {
        tracing::warn!(client_id, oper = %nick, %target, on, "NOEXPIRE");
        crate::commands::registration::notify_opers(
            &state,
            &senders,
            s,
            's',
            &format!("{nick} set NOEXPIRE {} on {target}", if on { "ON" } else { "OFF" }),
        )
        .await;
    }
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTE",
            vec![
                "NOEXPIRE".into(),
                "STATUS".into(),
                target.clone(),
                if on {
                    format!("{target} is kept whatever the expiry clock says")
                } else {
                    format!("{target} expires like everything else")
                },
            ],
        )
        .with_prefix(s),
        label,
    )
    .await;
    Ok(())
}

/// `SPAMFILTER ADD|DEL|LIST|TEST` — patterns an operator would rather never
/// see again.
///
/// ```text
/// SPAMFILTER ADD <targets> <action> [<seconds>] :<pattern>
/// SPAMFILTER DEL <id|pattern>
/// SPAMFILTER LIST
/// SPAMFILTER TEST :<text>
/// ```
///
/// `targets` is letters from `pcntqr`, or `*`; `action` is warn, block,
/// kill, kline or dline; `seconds` is how long a ban lasts. A pattern
/// between slashes is a regular expression, anything else a glob.
pub async fn handle_spamfilter(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    use crate::spamfilter::{self, SpamFilter};
    let s = &cfg.server.name;
    let (nick, allowed) = {
        let state_r = state.read().await;
        let Some(c) = state_r.clients.get(client_id) else {
            return Ok(());
        };
        let g = c.read().await;
        (g.nick_or_id().to_string(), g.may(crate::config::OperPrivilege::Ban))
    };
    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new("481", vec![nick, "Permission Denied- You're not an IRC operator".into()])
                .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }
    let refuse = |code: &str, target: &str, text: &str| {
        Message::new(
            "FAIL",
            vec!["SPAMFILTER".into(), code.into(), target.into(), text.into()],
        )
        .with_prefix(s)
    };
    let sub = msg
        .params
        .first()
        .map(|p| p.to_ascii_uppercase())
        .unwrap_or_default();
    match sub.as_str() {
        "LIST" => {
            let filters = state.read().await.spam_filters.clone();
            for f in &filters {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "NOTE",
                        vec![
                            "SPAMFILTER".into(),
                            "FILTER".into(),
                            f.id(),
                            format!(
                                "{} {} {} by {} — {} hit(s) — {}",
                                f.targets,
                                f.action.name(),
                                if f.duration > 0 { format!("{}s", f.duration) } else { "-".into() },
                                f.set_by,
                                f.hits,
                                f.pattern
                            ),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "NOTE",
                    vec![
                        "SPAMFILTER".into(),
                        "END".into(),
                        "*".into(),
                        format!("{} filter(s) of {}", filters.len(), spamfilter::MAX_FILTERS),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
        "TEST" => {
            let text = msg.params.get(1).cloned().unwrap_or_default();
            if text.is_empty() {
                reply_to_client(&senders, client_id, refuse("NEED_PARAMS", "*", "SPAMFILTER TEST :<text>"), label).await;
                return Ok(());
            }
            let hits: Vec<String> = state
                .read()
                .await
                .spam_filters
                .iter()
                .filter(|f| f.matches(&text))
                .map(|f| format!("[{}] {} ({})", f.id(), f.pattern, f.action.name()))
                .collect();
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "NOTE",
                    vec![
                        "SPAMFILTER".into(),
                        "TESTED".into(),
                        "*".into(),
                        if hits.is_empty() {
                            "Nothing matches that".to_string()
                        } else {
                            format!("Matched by {}", hits.join(", "))
                        },
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
        "DEL" => {
            let Some(which) = msg.params.get(1).cloned() else {
                reply_to_client(&senders, client_id, refuse("NEED_PARAMS", "*", "SPAMFILTER DEL <id|pattern>"), label).await;
                return Ok(());
            };
            let gone = spamfilter::remove(&mut *state.write().await, &which);
            let Some(pattern) = gone else {
                reply_to_client(&senders, client_id, refuse("NO_SUCH_FILTER", &which, "No filter by that id or pattern"), label).await;
                return Ok(());
            };
            if let Some(ref pool) = cfg.db {
                crate::persist::delete_spamfilter(pool, &pattern).await;
            }
            crate::link::announce_unspamfilter(cfg, &pattern).await;
            tracing::warn!(client_id, oper = %nick, %pattern, "Spam filter removed");
            crate::commands::registration::notify_opers(
                &state,
                &senders,
                s,
                'f',
                &format!("{nick} removed the spam filter {pattern}"),
            )
            .await;
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "NOTE",
                    vec!["SPAMFILTER".into(), "REMOVED".into(), pattern.clone(), format!("{pattern} is no longer filtered")],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
        "ADD" => {
            let (Some(targets), Some(action)) = (msg.params.get(1).cloned(), msg.params.get(2).cloned())
            else {
                reply_to_client(&senders, client_id, refuse("NEED_PARAMS", "*", "SPAMFILTER ADD <targets> <action> [<seconds>] :<pattern>"), label).await;
                return Ok(());
            };
            // The seconds are optional, so the pattern is whichever of the
            // last two is not a number.
            let (duration, pattern) = match msg.params.get(3).and_then(|d| d.parse::<i64>().ok()) {
                Some(secs) => (secs, msg.params.get(4).cloned().unwrap_or_default()),
                None => (0, msg.params.get(3).cloned().unwrap_or_default()),
            };
            let targets = match spamfilter::normalise_targets(&targets) {
                Ok(t) => t,
                Err(e) => {
                    reply_to_client(&senders, client_id, refuse("INVALID_TARGETS", &targets, &e), label).await;
                    return Ok(());
                }
            };
            let Some(parsed_action) = spamfilter::Action::parse(&action) else {
                reply_to_client(&senders, client_id, refuse("INVALID_ACTION", &action, "warn, block, kill, kline or dline"), label).await;
                return Ok(());
            };
            let mut filter = match SpamFilter::compile(&pattern) {
                Ok(f) => f,
                Err(e) => {
                    reply_to_client(&senders, client_id, refuse("INVALID_PATTERN", &pattern, &e), label).await;
                    return Ok(());
                }
            };
            // A filter is judged against the operator's own nick and real
            // name before it is kept: one that would catch the person adding
            // it is one they would rather find out about now.
            let (own_nick, own_real) = {
                let state_r = state.read().await;
                match state_r.clients.get(client_id) {
                    Some(c) => {
                        let g = c.read().await;
                        (g.nick_or_id().to_string(), g.realname.clone().unwrap_or_default())
                    }
                    None => (nick.clone(), String::new()),
                }
            };
            if (targets.contains('n') && filter.matches(&own_nick))
                || (targets.contains('r') && filter.matches(&own_real))
            {
                reply_to_client(&senders, client_id, refuse("MATCHES_YOURSELF", &pattern, "That pattern matches your own nick or real name"), label).await;
                return Ok(());
            }
            filter.targets = targets.clone();
            filter.action = parsed_action;
            filter.duration = duration.clamp(0, 366 * 86_400);
            filter.set_by = nick.clone();
            filter.set_at = chrono::Utc::now().timestamp();
            let id = filter.id();
            let stored = filter.clone();
            if !crate::spamfilter::install(&mut *state.write().await, filter) {
                reply_to_client(
                    &senders,
                    client_id,
                    refuse("TOO_MANY", &pattern, &format!("This server holds {} filters already", spamfilter::MAX_FILTERS)),
                    label,
                )
                .await;
                return Ok(());
            }
            if let Some(ref pool) = cfg.db {
                if let Err(e) = crate::persist::save_spamfilter(
                    pool,
                    &stored.pattern,
                    &stored.targets,
                    stored.action.name(),
                    stored.duration,
                    &stored.set_by,
                    stored.set_at,
                )
                .await
                {
                    tracing::error!(client_id, pattern = %stored.pattern, "Could not store the spam filter: {e}");
                }
            }
            crate::link::announce_spamfilter(cfg, &stored).await;
            tracing::warn!(client_id, oper = %nick, pattern = %stored.pattern, %targets, action = %action, "Spam filter added");
            crate::commands::registration::notify_opers(
                &state,
                &senders,
                s,
                'f',
                &format!("{nick} added spam filter [{id}] {} ({targets}, {})", stored.pattern, stored.action.name()),
            )
            .await;
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "NOTE",
                    vec![
                        "SPAMFILTER".into(),
                        "ADDED".into(),
                        id.clone(),
                        format!("[{id}] {} is filtered in {targets} ({})", stored.pattern, stored.action.name()),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
        _ => {
            reply_to_client(
                &senders,
                client_id,
                refuse("INVALID_PARAMS", "*", "SPAMFILTER ADD|DEL|LIST|TEST"),
                label,
            )
            .await;
        }
    }
    Ok(())
}

/// `SHUN [<duration>] <mask> :<reason>` — somebody who should stop, rather
/// than go.
///
/// A K-line closes the connection, which tells whoever was behind it to come
/// back from another address. A shun leaves them connected and lets nothing
/// they say reach anybody: they may listen, keep the connection alive, and
/// leave, and everything else they type quietly does nothing. They are not
/// told, because a shun that announced itself would just be a slower kill.
pub async fn handle_shun(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    const KIND: crate::persist::BanKind = crate::persist::BanKind::Shun;
    let Some((nick, own_source, own_ip)) = may_ban(&state, &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let Some((duration, mask, reason)) =
        ban_arguments(&msg, "SHUN", &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let normalized = normalize_ban_mask(&mask);
    if ban_too_broad(&normalized, KIND) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "SHUN".into(),
                    "MASK_TOO_BROAD".into(),
                    normalized,
                    "A shun needs a mask that names somebody: at least four characters that are not wildcards".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if ban_covers(&normalized, KIND, &own_source, &own_ip) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "SHUN".into(),
                    "MATCHES_YOURSELF".into(),
                    normalized,
                    "That mask matches your own connection".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let ban = new_ban(normalized, reason, &nick, duration, KIND);
    place_ban(client_id, &nick, ban, &state, &senders, cfg, label).await;
    Ok(())
}

/// `UNSHUN <mask>` — let somebody speak again.
pub async fn handle_unshun(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, _, _)) = may_ban(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let Some(given) = msg.params.first() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "UNSHUN".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let mask = normalize_ban_mask(given);
    let removed = match cfg.db {
        Some(ref pool) => crate::persist::delete_server_ban(pool, &mask, crate::persist::BanKind::Shun).await,
        None => false,
    };
    let known = {
        let mut state_w = state.write().await;
        let before = state_w.server_bans.len();
        state_w
            .server_bans
            .retain(|b| !(b.kind == crate::persist::BanKind::Shun && b.mask == mask));
        state_w.server_bans.len() != before
    };
    // Whoever it covered is covered by it no longer — unless another shun
    // still names them, which is why this is worked out again rather than
    // simply cleared.
    apply_shuns(&state).await;
    tracing::warn!(oper = %nick, %mask, removed, "Shun removed");
    crate::link::announce_unkline(cfg, &mask, crate::persist::BanKind::Shun).await;
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'b',
        &format!("{nick} removed the shun on {mask}"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![
                nick,
                if known || removed {
                    format!("Shun on {mask} removed")
                } else {
                    format!("No shun on {mask}")
                },
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// `ELINE [<duration>] <mask> :<reason>` — say who the bans do not apply to.
///
/// ```text
/// ELINE *!*@10.0.0.0/8 :the office
/// ELINE 30d *!*@vpn.example :a shared address people we know come through
/// ```
///
/// Every blocklist eventually lists somebody who belongs here: a shared
/// address, a VPN, an exit node. Without a way to say so, the only answers
/// are to stop believing the list for everybody or to stop asking it — both
/// of which give up more than the one address was worth. An exemption is how
/// one address is vouched for while the rest of it stands.
///
/// It covers all of them: a D-line and the blocklist at the door, a K-line
/// once there is a nick to judge, and a shun. An exemption is not a promise
/// about behaviour, so an operator can still close a connection by hand with
/// KILL — what it says is that no *standing rule* turns this address away.
pub async fn handle_eline(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    const KIND: crate::persist::BanKind = crate::persist::BanKind::Exempt;
    let Some((nick, _, _)) = may_ban(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let Some((duration, mask, reason)) =
        ban_arguments(&msg, "ELINE", &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let normalized = normalize_ban_mask(&mask);
    if ban_too_broad(&normalized, KIND) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "ELINE".into(),
                    "MASK_TOO_BROAD".into(),
                    normalized,
                    "An exemption needs a mask that names somebody: at least four characters that are not wildcards".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    // No check against the operator's own address here, unlike the bans. That
    // check is there to stop somebody shutting themselves out by accident, and
    // an exemption cannot: vouching for the address you are sitting at is a
    // reasonable thing to do and the usual first one.
    let ban = new_ban(normalized, reason, &nick, duration, KIND);
    place_ban(client_id, &nick, ban, &state, &senders, cfg, label).await;
    Ok(())
}

/// `UNELINE <mask>` — stop vouching for an address.
pub async fn handle_uneline(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, _, _)) = may_ban(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let Some(given) = msg.params.first() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec![nick, "UNELINE".into(), "Not enough parameters".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let mask = normalize_ban_mask(given);
    let removed = match cfg.db {
        Some(ref pool) => crate::persist::delete_server_ban(pool, &mask, crate::persist::BanKind::Exempt).await,
        None => false,
    };
    let known = {
        let mut state_w = state.write().await;
        let before = state_w.server_bans.len();
        state_w
            .server_bans
            .retain(|b| !(b.kind.is_exemption() && b.mask == mask));
        let gone = state_w.server_bans.len() != before;
        // The door is told at once: until it is, it would keep waving through
        // an address nothing vouches for any more.
        state_w.publish_door_bans();
        gone
    };
    // Whoever this was covering may be under a shun that was never applied to
    // them while it stood.
    apply_shuns(&state).await;
    tracing::warn!(oper = %nick, %mask, removed, "Exemption removed");
    crate::link::announce_unkline(cfg, &mask, crate::persist::BanKind::Exempt).await;
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'b',
        &format!("{nick} removed the exemption on {mask}"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![
                nick,
                if known || removed {
                    format!("Exemption on {mask} removed")
                } else {
                    format!("No exemption on {mask}")
                },
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// Whether this client may look at other people's connections. `STATS l`,
/// `STATS t` and `TRACE` all name hosts and count traffic, which is nobody
/// else's business.
async fn may_look(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    client_id: &str,
    cfg: &Config,
    label: Option<&str>,
) -> Option<String> {
    let (nick, is_oper) = {
        let state_r = state.read().await;
        let c = state_r.clients.get(client_id)?;
        let g = c.read().await;
        (g.nick_or_id().to_string(), g.oper)
    };
    if !is_oper {
        reply_to_client(
            senders,
            client_id,
            Message::new(
                "481",
                vec![nick, "Permission Denied- You're not an IRC operator".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return None;
    }
    Some(nick)
}

/// One row per connection this server is holding, for `STATS l`.
///
/// `RPL_STATSLINKINFO` is the oldest answer to "what is this server actually
/// carrying": how much is queued for somebody, how much has crossed, and how
/// long they have been here. A client that has stopped reading shows up in
/// the send queue before it shows up anywhere else.
async fn stats_links(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    nick: &str,
    server: &str,
) -> Vec<Message> {
    let now = chrono::Utc::now().timestamp();
    let mut rows = Vec::new();
    let state_r = state.read().await;
    let registry = senders.read().await;
    for (id, client) in state_r.users() {
        let g = client.read().await;
        // Somebody on another server has no connection here to describe.
        if g.server.is_some() {
            continue;
        }
        let who = format!(
            "{}[{}@{}]",
            g.nick_or_id(),
            g.display_user(),
            g.display_host()
        );
        for session in registry.sessions_of(id) {
            let Some(sink) = registry.get(&session) else {
                continue;
            };
            let stats = sink.stats();
            let (sent_msgs, sent_bytes, got_msgs, got_bytes) = stats.counts();
            rows.push(
                Message::new(
                    "211",
                    vec![
                        nick.to_string(),
                        who.clone(),
                        sink.sendq().to_string(),
                        sent_msgs.to_string(),
                        sent_bytes.to_string(),
                        got_msgs.to_string(),
                        got_bytes.to_string(),
                        format!("{}", now.saturating_sub(stats.since)),
                    ],
                )
                .with_prefix(server),
            );
        }
    }
    rows
}

/// What this server has been doing, for `STATS t`.
async fn stats_totals(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    nick: &str,
    server: &str,
) -> Vec<Message> {
    let (users, peak, uptime, commands) = {
        let state_r = state.read().await;
        (
            state_r.user_count(),
            state_r.max_clients,
            chrono::Utc::now()
                .timestamp()
                .saturating_sub(state_r.started_at),
            state_r.command_counts.values().sum::<u64>(),
        )
    };
    // Summed over the connections open now: a server that kept a running
    // total would have to be told when each one ended, and a number that is
    // only true if nothing was missed is worse than one that says what it is.
    let (sent_msgs, sent_bytes, got_msgs, got_bytes) = {
        let registry = senders.read().await;
        registry.all_stats().into_iter().fold(
            (0u64, 0u64, 0u64, 0u64),
            |(a, b, c, d), stats| {
                let (sm, sb, gm, gb) = stats.counts();
                (a + sm, b + sb, c + gm, d + gb)
            },
        )
    };
    [
        format!("Up {uptime} seconds"),
        format!("{users} user(s) now, {peak} at once at the most"),
        format!("{commands} command(s) handled"),
        format!(
            "On the connections open now: {sent_msgs} message(s) and {sent_bytes} byte(s) out, \
             {got_msgs} and {got_bytes} in"
        ),
    ]
    .into_iter()
    .map(|line| Message::new("249", vec![nick.to_string(), line]).with_prefix(server))
    .collect()
}

/// `TRACE [<nick>]` — the connections this server is holding, and the
/// servers it is linked to.
///
/// The class is how the connection arrived, because that is the only class
/// this server has: `plain`, `tls` or `websocket`.
pub async fn handle_trace(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let Some(nick) = may_look(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let wanted = msg.params.first().cloned();
    let mut rows: Vec<Message> = Vec::new();
    {
        let state_r = state.read().await;
        let registry = senders.read().await;
        for (id, client) in state_r.users() {
            let g = client.read().await;
            if g.server.is_some() {
                continue;
            }
            let their_nick = g.nick_or_id().to_string();
            if let Some(ref only) = wanted {
                if !their_nick.eq_ignore_ascii_case(only) {
                    continue;
                }
            }
            let class = registry
                .sessions_of(id)
                .into_iter()
                .find_map(|session| registry.get(&session).map(|sink| sink.stats().class.clone()))
                .unwrap_or_else(|| std::sync::Arc::from("plain"));
            let source = format!("{}[{}@{}]", their_nick, g.display_user(), g.display_host());
            rows.push(
                Message::new(
                    if g.oper { "204" } else { "205" },
                    vec![
                        nick.clone(),
                        if g.oper { "Oper".into() } else { "User".into() },
                        class.to_string(),
                        source,
                    ],
                )
                .with_prefix(s),
            );
        }
    }
    // The servers, when nobody asked about one person in particular.
    if wanted.is_none() {
        if let Some(ref links) = cfg.links_runtime {
            for server in links.read().await.all() {
                rows.push(
                    Message::new(
                        "206",
                        vec![
                            nick.clone(),
                            "Serv".into(),
                            if server.behind.is_none() { "link".into() } else { "behind".into() },
                            server.name.clone(),
                            format!("{} hop(s)", server.hops),
                        ],
                    )
                    .with_prefix(s),
                );
            }
        }
    }
    for row in rows {
        reply_to_client(&senders, client_id, row, label).await;
    }
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "262",
            vec![
                nick,
                s.clone(),
                concat!("rIRCd-", env!("CARGO_PKG_VERSION")).into(),
                "End of TRACE".into(),
            ],
        )
        .with_prefix(s),
        label,
    )
    .await;
    Ok(())
}

/// The kinds of client this server tells apart, for `STATS y`.
///
/// Counted from the connections themselves rather than from the accept
/// path's own tally: what is actually here is a better answer than what was
/// once let in, and it shows where the unclassed connections ended up too.
async fn stats_classes(
    cfg: &Config,
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    nick: &str,
    server: &str,
) -> Vec<Message> {
    let mut here: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for stats in senders.read().await.all_stats() {
        *here.entry(stats.class.to_string()).or_insert(0) += 1;
    }
    let classes = state.read().await.classes.clone();
    let mut rows = Vec::new();
    let mut row = |name: &str, ping: String, max: String, sendq: String, note: String| {
        // 218 RPL_STATSYLINE
        rows.push(
            Message::new(
                "218",
                vec![
                    nick.to_string(),
                    "Y".into(),
                    name.to_string(),
                    ping,
                    max,
                    sendq,
                    note,
                ],
            )
            .with_prefix(server),
        );
    };
    for class in &classes {
        let n = here.remove(&class.name).unwrap_or(0);
        row(
            &class.name,
            class
                .ping_secs
                .map(|s| s.to_string())
                .unwrap_or_else(|| cfg.server.ping_timeout_secs.to_string()),
            class
                .max_clients
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".into()),
            class
                .sendq
                .map(|q| q.to_string())
                .unwrap_or_else(|| crate::client::SEND_QUEUE.to_string()),
            format!(
                "{n} here; {}",
                if class.hosts.is_empty() {
                    "everybody else".to_string()
                } else {
                    class.hosts.join(" ")
                }
            ),
        );
    }
    // Whatever is left is in no class at all, and is named by how it arrived.
    let mut loose: Vec<(String, usize)> = here.into_iter().collect();
    loose.sort();
    for (name, n) in loose {
        row(
            &name,
            cfg.server.ping_timeout_secs.to_string(),
            "-".into(),
            crate::client::SEND_QUEUE.to_string(),
            format!("{n} here; in no class"),
        );
    }
    rows
}

/// Whether a reservation pattern says anything. One made of wildcards keeps
/// the whole network out of its own channels.
pub fn reservation_says_nothing(pattern: &str) -> bool {
    reservation_too_broad(pattern)
}

fn reservation_too_broad(pattern: &str) -> bool {
    pattern
        .chars()
        .filter(|c| !matches!(c, '*' | '?' | '#' | '&'))
        .count()
        < 2
}

/// `RESV [<seconds>] <pattern> :<reason>` — a name this network keeps.
///
/// A pattern beginning with `#` is about channels and anything else about
/// nicks, so `#help*` never stops anybody being called `helpdesk`. Whoever
/// asks for a reserved name is told why, which is the difference between
/// this and a spam filter: a filter is quiet on purpose, and a reservation
/// is a rule people are meant to be able to read.
///
/// Operators are not held to it — reserving the staff channel and then
/// being unable to enter it would be a strange way to run a network — and a
/// channel that already has people in it keeps them; the reservation stops
/// anybody else coming in.
pub async fn handle_resv(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, own_source, _own_ip)) = may_ban(&state, &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    let Some((duration, pattern, reason)) =
        ban_arguments(&msg, "RESV", &senders, client_id, cfg, label).await
    else {
        return Ok(());
    };
    if reservation_too_broad(&pattern) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "RESV".into(),
                    "MASK_TOO_BROAD".into(),
                    pattern,
                    "A reservation needs at least two characters that are not wildcards".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    // Reserving your own name is how an operator locks themselves out of
    // their own nick at the next reconnection.
    let own_nick = own_source.split('!').next().unwrap_or(&nick).to_string();
    if !pattern.starts_with('#')
        && !pattern.starts_with('&')
        && crate::user::glob_match(&pattern.to_lowercase(), &own_nick.to_lowercase())
    {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "RESV".into(),
                    "MATCHES_YOURSELF".into(),
                    pattern,
                    "That pattern covers the nick you are using".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp();
    let reservation = crate::persist::Reservation {
        pattern: pattern.clone(),
        reason,
        set_by: nick.clone(),
        set_at: now,
        expires_at: (duration > 0).then(|| now.saturating_add(duration)),
    };
    install_reservation(&state, reservation.clone()).await;
    if let Some(ref pool) = cfg.db {
        if let Err(e) = crate::persist::save_reservation(pool, &reservation).await {
            tracing::error!(client_id, %pattern, "RESV: could not store: {e}");
        }
    }
    crate::link::announce_resv(cfg, &reservation).await;
    tracing::warn!(oper = %nick, %pattern, "Reservation added");
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'b',
        &format!(
            "{nick} reserved {pattern} ({}){}",
            reservation.reason,
            match reservation.expires_at {
                Some(at) => format!(" until {}", clock_time(at)),
                None => String::new(),
            }
        ),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTE",
            vec![
                "RESV".into(),
                "RESERVED".into(),
                pattern.clone(),
                format!(
                    "{pattern} is reserved for this network{}",
                    if reservation.is_channel() {
                        "; anybody already in such a channel stays"
                    } else {
                        ""
                    }
                ),
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// Put a reservation into this server's list, replacing one on the same
/// pattern.
pub async fn install_reservation(
    state: &Arc<RwLock<ServerState>>,
    reservation: crate::persist::Reservation,
) {
    let mut state_w = state.write().await;
    state_w
        .reservations
        .retain(|r| r.pattern != reservation.pattern);
    state_w.reservations.push(reservation);
}

/// `UNRESV <pattern>` — give a name back.
pub async fn handle_unresv(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let Some((nick, _, _)) = may_ban(&state, &senders, client_id, cfg, label).await else {
        return Ok(());
    };
    let Some(pattern) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec![nick, "UNRESV".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
    let removed = match cfg.db {
        Some(ref pool) => crate::persist::delete_reservation(pool, &pattern).await,
        None => false,
    };
    let known = {
        let mut state_w = state.write().await;
        let before = state_w.reservations.len();
        state_w.reservations.retain(|r| r.pattern != pattern);
        state_w.reservations.len() != before
    };
    crate::link::announce_unresv(cfg, &pattern).await;
    tracing::warn!(oper = %nick, %pattern, removed, "Reservation removed");
    crate::commands::registration::notify_opers(
        &state,
        &senders,
        &cfg.server.name,
        'b',
        &format!("{nick} gave {pattern} back"),
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTE",
            vec![
                "UNRESV".into(),
                if known || removed { "RELEASED" } else { "NO_SUCH_RESV" }.into(),
                pattern.clone(),
                if known || removed {
                    format!("{pattern} is anybody's again")
                } else {
                    format!("{pattern} was not reserved")
                },
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}
