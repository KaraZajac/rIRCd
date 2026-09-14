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
                "  KLINE DLINE SNOMASK MLOCK",
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
    let (nick, source, account) = match state.clients.get(client_id) {
        Some(c) => {
            let g = c.read().await;
            (
                g.nick_or_id().to_string(),
                g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                g.account.clone(),
            )
        }
        None => return Ok(()),
    };

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
    if ch.is_banned(account.as_deref(), &source) {
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
        .filter(|(_, m)| m.modes.op)
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
        crate::persist::BanKind::Kline => mask_too_broad(mask),
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
        state_w.server_bans.retain(|b| b.mask != ban.mask);
        state_w.server_bans.push(ban.clone());
        state_w.publish_dlines();
        for (id, client) in state_w.users() {
            let g = client.read().await;
            // Only this server's own users are closed. Somebody on another
            // server is that server's to close, and it hears the same ban.
            if g.server.is_some() {
                continue;
            }
            let source = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
            if ban.matches(&source, &g.host) {
                hits.push((id.clone(), g.nick_or_id().to_string()));
            }
        }
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
            "{} added a {}-line on {}{} ({})",
            nick,
            ban.kind.letter(),
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
                format!(
                    "{}-line on {} added ({} connection(s) closed)",
                    ban.kind.letter(),
                    ban.mask,
                    hits.len()
                ),
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
        Some(ref pool) => crate::persist::delete_server_ban(pool, &mask).await,
        None => false,
    };
    let known = {
        let mut state_w = state.write().await;
        let before = state_w.server_bans.len();
        state_w
            .server_bans
            .retain(|b| !(b.kind == crate::persist::BanKind::Dline && b.mask == mask));
        state_w.publish_dlines();
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
        Some(ref pool) => crate::persist::delete_server_ban(pool, &mask).await,
        None => false,
    };
    {
        let mut state_w = state.write().await;
        state_w.server_bans.retain(|b| b.mask != mask);
        state_w.publish_dlines();
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
    if cfg.server.nick_protection
        && !target_account
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&new_nick))
    {
        let registered = match cfg.db {
            Some(ref pool) => crate::persist::nick_is_registered(pool, &cfg.db_health, &new_nick).await,
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
