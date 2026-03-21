use crate::capability::{build_cap_list, filter_requested};
use crate::channel::ChannelStore;
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::persist::{self, RegisterError};
use crate::protocol::Message;
use crate::user::{Client, ScramServerState, ServerState};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256_reg(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256_reg(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Send a message to a client. Returns true if the client was in senders and the send was attempted.
async fn send_to_client(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    msg: Message,
) -> bool {
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(msg).await;
        true
    } else {
        false
    }
}

/// ISUPPORT (005) token list; used at registration and for extended-isupport.
fn isupport_tokens(cfg: &Config) -> String {
    let base = "CHANTYPES=# CHANLIMIT=#:50 CHANNELLEN=64 NICKLEN=32 NAMELEN=128 TOPICLEN=307 KICKLEN=307 MODES=4 CASEMAPPING=ascii CHANMODES=beIq,k,l,imnstpRcC USERMODES=,,,BiorRw MAXLIST=beIq:100 PREFIX=(ohv)@%+ STATUSMSG=@+ EXCEPTS INVEX UTF8ONLY WHOX BOT=B ACCOUNTEXTBAN=~a MONITOR=100 CHATHISTORY=200 MSGREFTYPES=msgid,timestamp TARGMAX=PRIVMSG:1,NOTICE:1,KICK:1 METADATA=50";
    let deny = cfg
        .server
        .client_tag_deny
        .as_ref()
        .map(|v| format!(" CLIENTTAGDENY={}", v.join(",")))
        .unwrap_or_default();
    let icon = cfg
        .network
        .icon
        .as_ref()
        .map(|url| format!(" ICON={}", url))
        .unwrap_or_default();
    let filehost = cfg
        .filehost
        .as_ref()
        .map(|fh| format!(" draft/FILEHOST={}", fh.public_url))
        .unwrap_or_default();
    format!("{}{}{}{}", base, deny, icon, filehost)
}

pub async fn complete_registration(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let pending = {
        let mut state = state.write().await;
        state.pending.remove(client_id)
    };

    let mut pending = match pending {
        Some(p) if p.nick.is_some() && p.user.is_some() => p,
        _ => return Ok(()),
    };

    let nick = pending.nick.unwrap();
    let user = pending.user.unwrap();
    let realname = pending.realname.unwrap_or_else(|| nick.clone());

    let mut state_guard = state.write().await;

    if state_guard.nick_to_id.contains_key(&nick.to_uppercase()) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "433",
                vec![
                    "*".into(),
                    nick.clone(),
                    "Nickname is already in use".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let mut client = Client::new(client_id.to_string(), pending.host);
    client.nick = Some(nick.clone());
    client.user = Some(user);
    client.realname = Some(realname);
    client.registered = true;
    client.capabilities = pending.capabilities.clone();
    client.account = pending.account.clone();
    client.away_message = pending.away_message.take();

    // Auto-cloak: if cloak_key is set, derive a stable vhost from the real IP via HMAC-SHA256
    if let Some(ref cloak_key) = cfg.server.cloak_key {
        let hash = hmac_sha256_reg(cloak_key.as_bytes(), client.host.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        client.vhost = Some(format!("{}.IP", &hex[..8]));
    }

    let client = state_guard.add_client(client).await;

    drop(state_guard);

    let server = &cfg.server.name;
    let nick_str = &client.read().await.nick.clone().unwrap();

    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "001",
            vec![
                nick_str.clone(),
                format!("Welcome to the Internet Relay Network {}", nick_str),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "002",
            vec![
                nick_str.clone(),
                format!("Your host is {}, running rIRCd", server),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "003",
            vec![nick_str.clone(), "This server was created for IRCv3".into()],
        )
        .with_prefix(server),
        label,
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "004",
            vec![
                nick_str.clone(),
                server.clone(),
                "rIRCd-0.1".into(),
                "BiorRw".into(),
                "beIqklimntspRcC".into(),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;

    let isupport = isupport_tokens(cfg);
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "005",
            vec![
                nick_str.clone(),
                isupport.clone(),
                "are supported by this server".to_string(),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;

    send_motd(nick_str, server, &senders, cfg, label, client_id).await;

    // monitor: notify clients monitoring this nick that they came online (730)
    let source = client
        .read()
        .await
        .source()
        .unwrap_or_else(|| nick_str.clone());
    let watchers: Vec<String> = state
        .read()
        .await
        .monitor_watchers
        .by_nick
        .get(&nick_str.to_lowercase())
        .map(|s: &std::collections::HashSet<String>| s.iter().cloned().collect())
        .unwrap_or_default();
    if !watchers.is_empty() {
        tracing::info!(
            nick = %nick_str,
            watcher_count = watchers.len(),
            "Monitor: notifying watchers that nick came online (730)"
        );
    }
    for w in &watchers {
        if *w == client_id {
            continue;
        }
        let client_arc = state.read().await.clients.get(w).cloned();
        let nick = match client_arc {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => "*".to_string(),
        };
        let m = Message::new("730", vec![nick, format!(":{}", source)]).with_prefix(server);
        if !send_to_client(&senders, w, m).await {
            tracing::warn!(watcher_id = %w, nick = %nick_str, "Monitor: watcher not in senders, 730 not delivered");
        }
    }

    Ok(())
}

pub async fn handle_isupport(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let nick = {
        let state = state.read().await;
        if let Some(c) = state.clients.get(client_id) {
            c.read().await.nick_or_id().to_string()
        } else if let Some(p) = state.pending.get(client_id) {
            p.nick.as_deref().unwrap_or("*").to_string()
        } else {
            "*".to_string()
        }
    };
    let isupport = isupport_tokens(cfg);
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "005",
            vec![nick, isupport, "are supported by this server".to_string()],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// WEBIRC password gateway hostname ip [options] — accept real IP/host from gateway before CAP.
/// Only applies if client is not yet registered and cfg.webirc.password matches.
pub async fn handle_webirc(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    let state_guard = state.read().await;
    if state_guard.clients.contains_key(client_id) {
        return Ok(());
    }
    let expected = cfg.webirc.as_ref().map(|w| w.password.as_str());
    let password = msg.params.first().map(|s| s.as_str());
    let ip = msg.params.get(3).map(|s| s.as_str()).unwrap_or("");
    drop(state_guard);
    if expected != password || ip.is_empty() {
        let tx = senders.read().await.get(client_id).cloned();
        if let Some(tx) = tx {
            let _ = tx
                .send(
                    Message::new("ERROR", vec![":Invalid WebIRC password".into()])
                        .with_prefix(&cfg.server.name),
                )
                .await;
        }
        return Ok(());
    }
    let mut state_w = state.write().await;
    let pending = state_w.get_or_create_pending(client_id, host);
    pending.host = ip.to_string();
    Ok(())
}

pub async fn handle_cap(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let subcmd = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let version_302 = msg.params.get(1).map(|s| s.as_str()) == Some("302");

    let mut state_guard = state.write().await;
    let conn = state_guard.get_or_create_pending(client_id, host);

    match subcmd {
        "LS" => {
            conn.cap_negotiating = true;
            let tls_port: Option<u16> = if cfg.tls_enabled() {
                cfg.server
                    .listen_tls
                    .first()
                    .and_then(|addr| addr.rsplit(':').next())
                    .and_then(|p| p.parse().ok())
            } else {
                None
            };
            // CAP LS 302 multi-line format per IRCv3 spec:
            //   continuation lines: CAP * LS * :cap1 cap2 ...
            //   final line:         CAP * LS :cap1 cap2 ...
            // Without 302 (or single-line): CAP * LS :cap1 cap2 ...
            let caps = build_cap_list(version_302, tls_port);
            let total = caps.len();
            for (i, cap_line) in caps.iter().enumerate() {
                let is_last = i == total - 1;
                let params = if !is_last {
                    // Continuation: the asterisk is a separate third parameter.
                    vec!["*".into(), "LS".into(), "*".into(), cap_line.clone()]
                } else {
                    vec!["*".into(), "LS".into(), cap_line.clone()]
                };
                let mut reply = Message::new("CAP", params);
                reply.prefix = Some(cfg.server.name.clone());
                reply_to_client(&senders, client_id, reply, label).await;
            }
        }
        "LIST" => {
            let cap_line = conn
                .capabilities
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            let mut reply = Message::new("CAP", vec!["*".into(), "LIST".into(), cap_line]);
            reply.prefix = Some(cfg.server.name.clone());
            reply_to_client(&senders, client_id, reply, label).await;
        }
        "REQ" => {
            let requested: Vec<String> = msg
                .trailing()
                .unwrap_or("")
                .split_whitespace()
                .map(String::from)
                .collect();
            let (ack, nak) = filter_requested(&requested, &std::collections::HashSet::new());
            if nak.is_empty() {
                for c in &ack {
                    conn.capabilities.insert(c.clone());
                }
                let mut reply = Message::new("CAP", vec!["*".into(), "ACK".into(), ack.join(" ")]);
                reply.prefix = Some(cfg.server.name.clone());
                reply_to_client(&senders, client_id, reply, label).await;
                // cap-notify: no action needed here; CAP NEW/DEL would be sent if
                // the server's capability list changed at runtime (it doesn't).
            } else {
                let mut reply = Message::new("CAP", vec!["*".into(), "NAK".into(), nak.join(" ")]);
                reply.prefix = Some(cfg.server.name.clone());
                reply_to_client(&senders, client_id, reply, label).await;
            }
        }
        "END" => {
            conn.cap_ended = true;
        }
        _ => {}
    }

    let should_complete = conn.ready_to_register();
    drop(state_guard);

    if should_complete {
        complete_registration(client_id, state, senders, cfg, label).await?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_nick(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let mut state_guard = state.write().await;
    let nick = msg.params.first().cloned();
    let nick = match nick {
        Some(n) if !n.is_empty() && is_valid_nick(&n) => n,
        _ => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("431", vec!["*".into(), "No nickname given".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };

    if let Some(client) = state_guard.clients.get(client_id) {
        let client_guard = client.write().await;
        if client_guard.registered {
            if state_guard
                .nick_to_id
                .get(&nick.to_uppercase())
                .map(|id| id != client_id)
                == Some(true)
            {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "433",
                        vec![
                            client_guard.nick_or_id().to_string(),
                            nick.clone(),
                            "Nickname is already in use".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            let old_nick = client_guard.nick.clone();
            let old_source = client_guard
                .source()
                .unwrap_or_else(|| client_guard.nick_or_id().to_string());
            // Record old nick in WHOWAS before changing it.
            // Build the entry while we hold client_guard, then drop it before mutating state_guard.
            let whowas_entry = old_nick.as_ref().map(|n| crate::user::WhowasEntry {
                nick: n.clone(),
                user: client_guard.user.as_deref().unwrap_or("*").to_string(),
                host: client_guard.host.clone(),
                realname: client_guard.realname.as_deref().unwrap_or("").to_string(),
                server: cfg.server.name.clone(),
                timestamp: chrono::Utc::now().timestamp(),
            });
            drop(client_guard);
            if let Some(entry) = whowas_entry {
                state_guard.push_whowas(entry);
            }
            if let Some(ref o) = old_nick {
                state_guard.nick_to_id.remove(&o.to_uppercase());
            }
            if let Some(client) = state_guard.clients.get(client_id) {
                client.write().await.nick = Some(nick.clone());
            }
            state_guard
                .nick_to_id
                .insert(nick.to_uppercase(), client_id.to_string());
            // monitor: 731 to watchers of old nick, 730 to watchers of new nick
            let watchers_old: Vec<String> = state_guard
                .monitor_watchers
                .by_nick
                .get(
                    &old_nick
                        .as_ref()
                        .map(|n| n.to_lowercase())
                        .unwrap_or_default(),
                )
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            let watchers_new: Vec<String> = state_guard
                .monitor_watchers
                .by_nick
                .get(&nick.to_lowercase())
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            drop(state_guard);
            let server = &cfg.server.name;
            let client_arc = state.read().await.clients.get(client_id).cloned();
            let new_source = match client_arc {
                Some(c) => c.read().await.source().unwrap_or_else(|| nick.clone()),
                None => nick.clone(),
            };
            for w in &watchers_old {
                if *w == client_id {
                    continue;
                }
                let client_arc = state.read().await.clients.get(w).cloned();
                let recv_nick = match client_arc {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => "*".to_string(),
                };
                let m = Message::new(
                    "731",
                    vec![recv_nick, format!(":{}", old_nick.as_deref().unwrap_or(""))],
                )
                .with_prefix(server);
                send_to_client(&senders, w, m).await;
            }
            for w in &watchers_new {
                if *w == client_id {
                    continue;
                }
                let client_arc = state.read().await.clients.get(w).cloned();
                let recv_nick = match client_arc {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => "*".to_string(),
                };
                let m = Message::new("730", vec![recv_nick, format!(":{}", new_source)])
                    .with_prefix(server);
                send_to_client(&senders, w, m).await;
            }

            // Broadcast NICK change to channel members (and self)
            let nick_msg = Message::new("NICK", vec![nick.clone()]).with_prefix(&old_source);
            send_to_client(&senders, client_id, nick_msg.clone()).await;
            let channel_names: Vec<String> = match state.read().await.clients.get(client_id) {
                Some(c) => c.read().await.channels.keys().cloned().collect(),
                None => Vec::new(),
            };
            let mut notified = std::collections::HashSet::new();
            notified.insert(client_id.to_string());
            for ch_name in &channel_names {
                let ch_store = channels.read().await;
                let member_ids: Vec<String> = match ch_store.channels.get(ch_name.as_str()) {
                    Some(ch) => ch.read().await.members.keys().cloned().collect(),
                    None => Vec::new(),
                };
                drop(ch_store);
                for mid in member_ids {
                    if notified.insert(mid.clone()) {
                        send_to_client(&senders, &mid, nick_msg.clone()).await;
                    }
                }

                // Record NICK event for draft/event-playback (one per channel)
                if let Some(ref pool) = cfg.db {
                    let _ = persist::append_channel_history(
                        pool,
                        ch_name,
                        &old_source,
                        &nick,
                        None,
                        "NICK",
                    )
                    .await;
                }
            }

            return Ok(());
        }
    }

    let nick_taken = state_guard.nick_to_id.contains_key(&nick.to_uppercase());
    if nick_taken {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "433",
                vec![
                    "*".into(),
                    nick.clone(),
                    "Nickname is already in use".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let conn = state_guard.get_or_create_pending(client_id, host);
    conn.nick = Some(nick);

    let should_complete = conn.ready_to_register();
    drop(state_guard);

    if should_complete {
        complete_registration(client_id, state, senders, cfg, label).await?;
    }

    Ok(())
}

fn is_valid_nick(n: &str) -> bool {
    if n.is_empty() || n.len() > 32 {
        return false;
    }
    let bad_start = [
        '#', '&', '@', '%', '+', ':', '$', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    if bad_start.contains(&n.chars().next().unwrap_or(' ')) {
        return false;
    }
    for c in n.chars() {
        if matches!(c, ' ' | ',' | '*' | '?' | '!' | '@' | '.' | '\0') {
            return false;
        }
    }
    true
}

pub async fn handle_user(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let mut state_guard = state.write().await;

    if state_guard.clients.contains_key(client_id) {
        reply_to_client(
            &senders,
            client_id,
            Message::new("462", vec!["*".into(), "You may not reregister".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let user = msg.params.first().cloned().unwrap_or_else(|| "user".into());
    let realname = msg.trailing().unwrap_or("").to_string();

    let conn = state_guard.get_or_create_pending(client_id, host);
    conn.user = Some(user);
    conn.realname = Some(realname);

    let should_complete = conn.ready_to_register();
    drop(state_guard);

    if should_complete {
        complete_registration(client_id, state, senders, cfg, label).await?;
    }

    Ok(())
}

pub async fn handle_pass(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    let pass = msg
        .params
        .first()
        .cloned()
        .or_else(|| msg.trailing().map(String::from));
    if let Some(p) = pass {
        let mut state = state.write().await;
        let conn = state.get_or_create_pending(client_id, "unknown");
        conn.pass = Some(p.to_string());
    }
    Ok(())
}

/// Send MOTD lines (375 / 372... / 376) to a client.
async fn send_motd(
    nick: &str,
    server: &str,
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
    client_id: &str,
) {
    reply_to_client(
        senders,
        client_id,
        Message::new(
            "375",
            vec![
                nick.to_string(),
                format!("- {} Message of the day -", server),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;
    for line in cfg.server.motd.lines() {
        let line = line.trim();
        if !line.is_empty() {
            reply_to_client(
                senders,
                client_id,
                Message::new("372", vec![nick.to_string(), format!("- {}", line)])
                    .with_prefix(server),
                label,
            )
            .await;
        }
    }
    reply_to_client(
        senders,
        client_id,
        Message::new(
            "376",
            vec![nick.to_string(), "End of /MOTD command.".into()],
        )
        .with_prefix(server),
        label,
    )
    .await;
}

pub async fn handle_motd(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state_r = state.read().await;
    let client = match state_r.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();
    drop(state_r);
    send_motd(&nick, &cfg.server.name, &senders, cfg, label, client_id).await;
    Ok(())
}

pub async fn handle_ping(
    client_id: &str,
    msg: Message,
    _state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let token = msg
        .params
        .first()
        .map(|s| s.as_str())
        .unwrap_or(&cfg.server.name);
    reply_to_client(
        &senders,
        client_id,
        Message::new("PONG", vec![cfg.server.name.clone(), token.to_string()])
            .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

pub async fn handle_pong(
    _client_id: &str,
    _msg: Message,
    _state: Arc<RwLock<ServerState>>,
    _senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    _cfg: &Config,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    Ok(())
}

pub async fn handle_quit(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    let reason = msg.trailing().unwrap_or("Client quit").to_string();

    let (source, channel_names, had_account, quit_nick, monitor_list) = {
        let mut state_guard = state.write().await;
        let client = state_guard.clients.get(client_id).cloned();
        if let Some(client) = client {
            let c = client.read().await;
            let source = c.source().unwrap_or_else(|| c.nick_or_id().to_string());
            let chans: Vec<String> = c.channels.keys().cloned().collect();
            let had_account = c.account.is_some();
            let nick = c.nick.clone().unwrap_or_else(|| client_id.to_string());
            let list = c.monitor_list.clone();
            // Record WHOWAS before the client is removed
            state_guard.record_whowas(&c, &cfg.server.name);
            (source, chans, had_account, nick, list)
        } else {
            state_guard.pending.remove(client_id);
            return Ok(());
        }
    };

    let quit_msg = Message::new("QUIT", vec![reason.clone()]).with_prefix(&source);

    for ch_name in &channel_names {
        let mut ch_store = channels.write().await;
        let mut should_remove = false;
        if let Some(ch_rw) = ch_store.channels.get_mut(ch_name) {
            let mut ch = ch_rw.write().await;
            for (member_id, _) in ch.members.clone().iter() {
                if member_id != client_id {
                    if let Some(tx) = senders.read().await.get(member_id) {
                        let _ = tx.send(quit_msg.clone()).await;
                    }
                }
            }
            ch.members.remove(client_id);
            should_remove = ch.members.is_empty();
        }
        if should_remove {
            ch_store.channels.remove(ch_name);
        }
        drop(ch_store);

        // Record QUIT event for draft/event-playback (one per channel)
        if let Some(ref pool) = cfg.db {
            let _ = persist::append_channel_history(pool, ch_name, &source, &reason, None, "QUIT")
                .await;
        }
    }

    // account-notify: on logout send ACCOUNT * to channel peers that have the cap
    if had_account {
        let account_star = Message::new("ACCOUNT", vec!["*".into()]).with_prefix(&source);
        for ch_name in &channel_names {
            let ch_store = channels.read().await;
            let ch_guard = match ch_store.channels.get(ch_name) {
                Some(ch) => ch,
                None => continue,
            };
            let member_ids: Vec<String> = ch_guard.read().await.members.keys().cloned().collect();
            let _ = ch_guard;
            drop(ch_store);
            let state = state.read().await;
            for mid in &member_ids {
                let caps = match state.clients.get(mid) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                if caps.contains("account-notify") {
                    send_to_client(&senders, mid, account_star.clone()).await;
                }
            }
        }
    }

    // monitor: notify clients monitoring this nick that they went offline (731), then clean watchers
    let watchers_731: Vec<String> = state
        .read()
        .await
        .monitor_watchers
        .by_nick
        .get(&quit_nick.to_lowercase())
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    if !watchers_731.is_empty() {
        tracing::info!(
            nick = %quit_nick,
            watcher_count = watchers_731.len(),
            "Monitor: notifying watchers that nick went offline (731)"
        );
    }
    let server = &cfg.server.name;
    for w in &watchers_731 {
        let client_arc = state.read().await.clients.get(w).cloned();
        let nick = match client_arc {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => "*".to_string(),
        };
        let m = Message::new("731", vec![nick, format!(":{}", quit_nick)]).with_prefix(server);
        if !send_to_client(&senders, w, m).await {
            tracing::warn!(watcher_id = %w, nick = %quit_nick, "Monitor: watcher not in senders, 731 not delivered");
        }
    }
    {
        let mut state_w = state.write().await;
        state_w
            .monitor_watchers
            .remove_client(client_id, &monitor_list);
        state_w.remove_client(client_id).await;
    }
    senders.write().await.remove(client_id);

    Ok(())
}

/// Safe preview for debug logs: hex for short strings, else length + first 16 bytes hex. Never log raw credentials.
fn sasl_preview(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = s.as_bytes();
    let to_hex = |b: &[u8]| {
        b.iter()
            .flat_map(|&x| {
                [
                    HEX[(x >> 4) as usize] as char,
                    HEX[(x & 15) as usize] as char,
                ]
            })
            .collect::<String>()
    };
    if bytes.len() <= 64 {
        format!("len={} hex={}", bytes.len(), to_hex(bytes))
    } else {
        format!(
            "len={} hex_prefix={}",
            bytes.len(),
            to_hex(&bytes[..16.min(bytes.len())])
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_authenticate(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let mechanism = msg.params.first().map(|s| s.as_str()).unwrap_or("");

    // ── Check stored mechanism for routing ────────────────────────────────────
    let stored_mechanism = {
        let sg = state.read().await;
        sg.pending
            .get(client_id)
            .and_then(|c| c.sasl_mechanism.clone())
    };

    // Already-authenticated guard
    {
        let sg = state.read().await;
        if let Some(conn) = sg.pending.get(client_id) {
            if conn.account.is_some() {
                let nick = conn.nick.clone().unwrap_or_else(|| "*".to_string());
                drop(sg);
                tracing::info!(client_id, "SASL: already authenticated, sending 907");
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "907",
                        vec![nick, "You have already authenticated using SASL".into()],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            if conn.sasl_failed {
                return Ok(());
            }
        }
    }

    // Route SCRAM-SHA-256: initial selection or continuation
    if mechanism == "SCRAM-SHA-256" || stored_mechanism.as_deref() == Some("SCRAM-SHA-256") {
        if mechanism == "SCRAM-SHA-256" {
            // Store mechanism and send AUTHENTICATE +
            {
                let mut sg = state.write().await;
                if let Some(conn) = sg.pending.get_mut(client_id) {
                    conn.sasl_mechanism = Some("SCRAM-SHA-256".to_string());
                }
            }
            // Client may have sent data inline
            let inline = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
            if inline.is_empty() || inline == "SCRAM-SHA-256" {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("AUTHENTICATE", vec!["+".into()]).with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            return handle_authenticate_scram_step(
                client_id, host, inline, state, channels, senders, cfg, label,
            )
            .await;
        } else {
            // Continuation
            return handle_authenticate_scram_step(
                client_id, host, mechanism, state, channels, senders, cfg, label,
            )
            .await;
        }
    }

    // Unknown mechanism (not PLAIN, not SCRAM, not a continuation of either)
    if mechanism != "PLAIN"
        && mechanism != "+"
        && !mechanism.is_empty()
        && stored_mechanism.is_none()
    {
        let nick = state
            .read()
            .await
            .pending
            .get(client_id)
            .and_then(|c| c.nick.clone())
            .unwrap_or_else(|| "*".to_string());
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "908",
                vec![
                    nick,
                    "PLAIN,SCRAM-SHA-256".into(),
                    "are available SASL mechanisms".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Token: first message is "AUTHENTICATE PLAIN" [optional first chunk]; continuation is "AUTHENTICATE <chunk>".
    // When client sends only "AUTHENTICATE PLAIN", params = ["PLAIN"] and trailing() returns the last param "PLAIN" —
    // we must not treat the mechanism name as a credential chunk.
    let token = if mechanism == "PLAIN" {
        let raw = msg
            .params
            .get(1)
            .map(|s| s.as_str())
            .or_else(|| msg.trailing())
            .unwrap_or("");
        if raw == "PLAIN" {
            ""
        } else {
            raw
        }
    } else {
        msg.params
            .first()
            .map(|s| s.as_str())
            .or_else(|| msg.trailing())
            .unwrap_or("")
    };

    let token_from = if mechanism == "PLAIN" {
        if msg.params.get(1).is_some() {
            "params[1]"
        } else if msg.trailing().is_some() {
            "trailing"
        } else {
            "empty"
        }
    } else if !msg.params.is_empty() {
        "params[0]"
    } else if msg.trailing().is_some() {
        "trailing"
    } else {
        "empty"
    };

    // RFC 4616: authzid + authcid + passwd ≤ 255+255+255 octets decoded → base64 ≤ 1024 bytes. Use 1200 to allow real-world clients that send slightly over (e.g. padding).
    const MAX_SASL_PLAIN_BUF: usize = 1200;

    tracing::info!(
        client_id = %client_id,
        token_len = token.len(),
        token_is_plus = token == "+",
        token_from = %token_from,
        params_count = msg.params.len(),
        "SASL AUTHENTICATE: received (mechanism={})",
        mechanism
    );
    tracing::debug!(
        client_id = %client_id,
        token_preview = %sasl_preview(token),
        "SASL PLAIN token detail"
    );

    // SASL PLAIN chunking (IRCv3): response is base64, split into ≤400-byte chunks. We stop and decode when:
    // - client sends AUTHENTICATE + (explicit end; used after a 400-byte chunk), or
    // - client sends a chunk with length < 400 (last chunk). We then decode the accumulated buffer and send 903 or 904.
    let (to_decode, is_end, explicit_end) = {
        let mut state_guard = state.write().await;
        let conn = state_guard.get_or_create_pending(client_id, host);
        // Store mechanism atomically with pending creation. This handles the case where the
        // pending connection was removed by complete_registration() and just recreated above.
        if mechanism == "PLAIN" {
            conn.sasl_mechanism = Some("PLAIN".to_string());
        }
        // is_end = true when we have the full response: token is "+" or token.len() < 400.
        let explicit_end = token == "+";
        let chunk_lt_400 = token.len() < 400;
        let is_end = explicit_end || (token != "+" && chunk_lt_400);
        if token == "+" {
            tracing::info!(
                client_id = %client_id,
                buffer_len = conn.sasl_plain_buffer.len(),
                chunk_count = conn.sasl_chunk_count,
                "SASL AUTHENTICATE: explicit end (+) received, will decode"
            );
            (conn.sasl_plain_buffer.clone(), true, true)
        } else if token.is_empty() {
            // Client sent "AUTHENTICATE PLAIN" with no initial response — do not append; we will send AUTHENTICATE + to request credentials.
            tracing::info!(
                client_id = %client_id,
                "SASL AUTHENTICATE: no data (initial PLAIN), will send AUTHENTICATE +"
            );
            (conn.sasl_plain_buffer.clone(), false, false)
        } else {
            let new_len = conn.sasl_plain_buffer.len() + token.len();
            if new_len > MAX_SASL_PLAIN_BUF {
                let nick = conn.nick.clone().unwrap_or_else(|| "*".to_string());
                let buf_len_before = conn.sasl_plain_buffer.len();
                let chunks = conn.sasl_chunk_count;
                conn.sasl_plain_buffer.clear();
                conn.sasl_chunk_count = 0;
                conn.sasl_failed = true;
                drop(state_guard);
                tracing::warn!(
                    client_id = %client_id,
                    chunk_count = chunks,
                    buffer_len = buf_len_before,
                    token_len = token.len(),
                    new_len,
                    max = MAX_SASL_PLAIN_BUF,
                    "SASL AUTHENTICATE: buffer exceeded max length, sending 904"
                );
                sasl_fail(
                    state,
                    &senders,
                    client_id,
                    cfg,
                    label,
                    &nick,
                    "SASL authentication failed",
                )
                .await;
                return Ok(());
            }
            conn.sasl_plain_buffer.push_str(token);
            conn.sasl_chunk_count = conn.sasl_chunk_count.saturating_add(1);
            tracing::info!(
                client_id = %client_id,
                chunk_num = conn.sasl_chunk_count,
                chunk_len = token.len(),
                buffer_total = conn.sasl_plain_buffer.len(),
                is_end,
                is_end_reason = if is_end { "last chunk (<400 bytes)" } else { "more chunks" },
                "SASL AUTHENTICATE: chunk appended"
            );
            (conn.sasl_plain_buffer.clone(), is_end, explicit_end)
        }
    };

    if to_decode.is_empty() {
        if is_end {
            if let Some(conn) = state.write().await.pending.get_mut(client_id) {
                conn.sasl_failed = true;
            }
            tracing::info!(client_id = %client_id, "SASL AUTHENTICATE: empty response, sending 904");
            reply_to_client(
                &senders,
                client_id,
                Message::new("904", vec!["*".into(), "SASL authentication failed".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        } else {
            tracing::info!(client_id = %client_id, "SASL AUTHENTICATE: empty token, sending AUTHENTICATE + (request credentials)");
            reply_to_client(
                &senders,
                client_id,
                Message::new("AUTHENTICATE", vec!["+".into()]).with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        return Ok(());
    }

    // We only decode when we have the complete payload: client sent AUTHENTICATE + or a chunk < 400 (last chunk).
    // If we got a full 400-byte chunk, just request more and do not pad/decode.
    if !is_end {
        tracing::info!(
            client_id = %client_id,
            buffer_len = to_decode.len(),
            "SASL AUTHENTICATE: sending AUTHENTICATE + (request next chunk)"
        );
        reply_to_client(
            &senders,
            client_id,
            Message::new("AUTHENTICATE", vec!["+".into()]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let chunk_count = state
        .read()
        .await
        .pending
        .get(client_id)
        .map(|c| c.sasl_chunk_count)
        .unwrap_or(0);
    tracing::info!(
        client_id = %client_id,
        buffer_len = to_decode.len(),
        chunk_count,
        explicit_end,
        buffer_preview = %sasl_preview(&to_decode),
        "SASL AUTHENTICATE: complete payload received, decoding"
    );

    // Pad base64 to a multiple of 4 only when we have the final payload (so decode can succeed).
    let to_decode_padded = if to_decode.len() % 4 != 0 {
        let pad = 4 - (to_decode.len() % 4);
        format!("{}{}", to_decode, "=".repeat(pad))
    } else {
        to_decode.clone()
    };

    // We only reach decode when is_end is true, so we have the full response. If decode fails, fail auth;
    // we must not "request more" or we keep the buffer and the client will send another chunk and we exceed the cap.
    let decoded = match base64_decode(&to_decode_padded) {
        Ok(d) => d,
        Err(e) => {
            let nick = state
                .read()
                .await
                .pending
                .get(client_id)
                .and_then(|c| c.nick.clone())
                .unwrap_or_else(|| "*".to_string());
            if let Some(conn) = state.write().await.pending.get_mut(client_id) {
                conn.sasl_plain_buffer.clear();
                conn.sasl_chunk_count = 0;
                conn.sasl_failed = true;
            }
            tracing::warn!(
                client_id = %client_id,
                buf_len = to_decode.len(),
                buffer_preview = %sasl_preview(&to_decode),
                decode_error = %e,
                "SASL AUTHENTICATE: base64 decode failed (malformed payload)"
            );
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL authentication failed",
            )
            .await;
            return Ok(());
        }
    };

    if let Some(conn) = state.write().await.pending.get_mut(client_id) {
        conn.sasl_plain_buffer.clear();
        conn.sasl_chunk_count = 0;
    }

    tracing::info!(
        client_id = %client_id,
        decoded_len = decoded.len(),
        "SASL AUTHENTICATE: base64 decoded OK"
    );

    // RFC 4616: message = [authzid] UTF8NUL authcid UTF8NUL passwd → exactly 3 parts
    let parts: Vec<&str> = decoded.splitn(3, '\0').collect();
    let nick: String = state
        .read()
        .await
        .pending
        .get(client_id)
        .and_then(|c| c.nick.clone())
        .unwrap_or_else(|| "*".to_string());

    if parts.len() != 3 {
        tracing::info!(client_id = %client_id, parts_len = parts.len(), "SASL AUTHENTICATE: malformed PLAIN (expected 3 NUL-separated parts), sending 904");
        sasl_fail(
            state,
            &senders,
            client_id,
            cfg,
            label,
            &nick,
            "SASL authentication failed",
        )
        .await;
        return Ok(());
    }

    let authzid = parts[0];
    let authcid = parts[1];
    let passwd = parts[2];

    // RFC 4616: "if preparation fails or results in an empty string, verification SHALL fail"
    if authcid.is_empty() || passwd.is_empty() {
        tracing::info!(client_id = %client_id, "SASL AUTHENTICATE: empty authcid or passwd, sending 904");
        sasl_fail(
            state,
            &senders,
            client_id,
            cfg,
            label,
            &nick,
            "SASL authentication failed",
        )
        .await;
        return Ok(());
    }

    // RFC 4616: "MUST be capable of accepting authzid, authcid, and passwd ... up to and including 255 octets"
    const MAX_PLAIN_FIELD: usize = 255;
    if authzid.len() > MAX_PLAIN_FIELD
        || authcid.len() > MAX_PLAIN_FIELD
        || passwd.len() > MAX_PLAIN_FIELD
    {
        tracing::info!(
            client_id = %client_id,
            authzid_len = authzid.len(),
            authcid_len = authcid.len(),
            "SASL AUTHENTICATE: field exceeds 255 octets, sending 904"
        );
        sasl_fail(
            state,
            &senders,
            client_id,
            cfg,
            label,
            &nick,
            "SASL authentication failed",
        )
        .await;
        return Ok(());
    }

    // RFC 4616: "verify that the authentication credentials permit the client to act as the (presented or derived) authorization identity"
    // For IRC we only allow acting as self; if authzid is set and differs from authcid, reject.
    if !authzid.is_empty() && authzid != authcid {
        tracing::info!(client_id = %client_id, "SASL AUTHENTICATE: not authorized to requested authzid, sending 904");
        sasl_fail(
            state,
            &senders,
            client_id,
            cfg,
            label,
            &nick,
            "Not authorized to requested authorization identity",
        )
        .await;
        return Ok(());
    }

    let verified = match cfg.db.as_ref() {
        Some(pool) => persist::verify_user(pool, authcid, passwd).await,
        None => false,
    };
    if !verified {
        tracing::info!(client_id = %client_id, authcid = %authcid, "SASL AUTHENTICATE: invalid credentials, sending 904");
        sasl_fail(
            state,
            &senders,
            client_id,
            cfg,
            label,
            &nick,
            "SASL authentication failed",
        )
        .await;
        return Ok(());
    }

    // Authorization identity: presented authzid or derived from authcid (RFC 4616)
    let account = if authzid.is_empty() { authcid } else { authzid };

    // Set account immediately so any concurrent AUTHENTICATE (e.g. client sending same line 2–3x) is ignored.
    {
        let mut state = state.write().await;
        if let Some(client) = state.clients.get_mut(client_id) {
            client.write().await.account = Some(account.to_string());
        } else if let Some(conn) = state.pending.get_mut(client_id) {
            conn.account = Some(account.to_string());
        }
    }

    tracing::info!(client_id = %client_id, account = %account, "SASL PLAIN authentication successful");
    let (channel_list, source, user_ident_host) = {
        let mut state = state.write().await;
        if let Some(client) = state.clients.get_mut(client_id) {
            let ch_list = client
                .read()
                .await
                .channels
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            let src = client
                .read()
                .await
                .source()
                .unwrap_or_else(|| client_id.to_string());
            let uih = src.clone();
            (ch_list, src, uih)
        } else if let Some(conn) = state.pending.get(client_id) {
            let uih = conn
                .user
                .as_ref()
                .map(|u| format!("{}!{}@{}", nick, u, conn.host))
                .unwrap_or_else(|| client_id.to_string());
            (Vec::new(), client_id.to_string(), uih)
        } else {
            (Vec::new(), client_id.to_string(), client_id.to_string())
        }
    };

    // IRCv3: on success send 900 (RPL_LOGGEDIN) then 903 (RPL_SASLSUCCESS)
    let server_name = &cfg.server.name;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "900",
            vec![
                nick.to_string(),
                user_ident_host,
                account.to_string(),
                "You are now logged in as ".to_string() + account,
            ],
        )
        .with_prefix(server_name),
        label,
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "903",
            vec![nick.to_string(), "SASL authentication successful".into()],
        )
        .with_prefix(server_name),
        label,
    )
    .await;
    tracing::info!(client_id = %client_id, nick = %nick, account = %account, "SASL AUTHENTICATE: success, sent 900 and 903");

    // account-notify: tell channel peers that have the cap (prefix = user whose account changed)
    for ch_name in &channel_list {
        let ch_store = channels.read().await;
        let ch_guard = match ch_store.channels.get(ch_name) {
            Some(ch) => ch,
            None => continue,
        };
        let member_ids: Vec<String> = ch_guard.read().await.members.keys().cloned().collect();
        let _ = ch_guard;
        drop(ch_store);
        let state = state.read().await;
        for mid in &member_ids {
            if *mid == client_id {
                continue;
            }
            let caps = match state.clients.get(mid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            if caps.contains("account-notify") {
                send_to_client(
                    &senders,
                    mid,
                    Message::new("ACCOUNT", vec![account.to_string()]).with_prefix(&source),
                )
                .await;
            }
        }
    }
    Ok(())
}

async fn sasl_fail(
    state: Arc<RwLock<ServerState>>,
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    cfg: &Config,
    label: Option<&str>,
    nick: &str,
    reason: &str,
) {
    if let Some(conn) = state.write().await.pending.get_mut(client_id) {
        conn.sasl_failed = true;
    }
    tracing::warn!(client_id = %client_id, nick = %nick, "SASL PLAIN authentication failed: {}", reason);
    let msg = Message::new("904", vec![nick.to_string(), reason.to_string()])
        .with_prefix(&cfg.server.name);
    reply_to_client(senders, client_id, msg, label).await;
    tracing::info!(client_id = %client_id, nick = %nick, "SASL AUTHENTICATE: failure, sent 904");
}

/// Decode base64 to UTF-8 string. Fails on invalid UTF-8 per RFC 4616 (PLAIN uses UTF-8).
fn base64_decode(s: &str) -> anyhow::Result<String> {
    let decoded = B64.decode(s)?;
    String::from_utf8(decoded)
        .map_err(|e| anyhow::anyhow!("SASL PLAIN message must be valid UTF-8: {}", e))
}

// ─── SASL SCRAM-SHA-256 ───────────────────────────────────────────────────────

/// Handle one AUTHENTICATE step for SCRAM-SHA-256.
/// Step 1: receive client-first, send server-first.
/// Step 2: receive client-final, verify proof, send server-final + 903/904.
#[allow(clippy::too_many_arguments)]
async fn handle_authenticate_scram_step(
    client_id: &str,
    host: &str,
    token: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let nick = {
        let sg = state.read().await;
        sg.pending
            .get(client_id)
            .and_then(|c| c.nick.clone())
            .unwrap_or_else(|| "*".to_string())
    };

    // Decode the base64 payload
    let payload = match B64.decode(token) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(_) => {
                sasl_fail(
                    state,
                    &senders,
                    client_id,
                    cfg,
                    label,
                    &nick,
                    "SASL SCRAM: invalid UTF-8",
                )
                .await;
                return Ok(());
            }
        },
        Err(_) => {
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL SCRAM: invalid base64",
            )
            .await;
            return Ok(());
        }
    };

    // Determine which step we're on by checking sasl_scram
    let has_scram_state = state
        .read()
        .await
        .pending
        .get(client_id)
        .map(|c| c.sasl_scram.is_some())
        .unwrap_or(false);

    if !has_scram_state {
        // ── Step 1: process client-first-message ─────────────────────────────
        // Format: n,,n=username,r=clientnonce
        // GS2 header is "n,," for no channel binding
        let bare = if let Some(b) = payload.strip_prefix("n,,") {
            b
        } else {
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL SCRAM: invalid GS2 header",
            )
            .await;
            return Ok(());
        };

        let mut username = String::new();
        let mut client_nonce = String::new();
        for part in bare.split(',') {
            if let Some(v) = part.strip_prefix("n=") {
                username = v.to_string();
            }
            if let Some(v) = part.strip_prefix("r=") {
                client_nonce = v.to_string();
            }
        }
        if username.is_empty() || client_nonce.is_empty() {
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL SCRAM: missing n= or r= in client-first",
            )
            .await;
            return Ok(());
        }

        // Look up SCRAM credentials
        let pool = match cfg.db.as_ref() {
            Some(p) => p,
            None => {
                sasl_fail(
                    state,
                    &senders,
                    client_id,
                    cfg,
                    label,
                    &nick,
                    "SASL SCRAM: database unavailable",
                )
                .await;
                return Ok(());
            }
        };
        let creds = match persist::get_scram_credentials(pool, &username).await {
            Some(c) => c,
            None => {
                // Account not found or not SCRAM-enrolled — still fail with generic message
                tracing::info!(client_id, account = %username, "SASL SCRAM: account not found or not SCRAM-enrolled");
                sasl_fail(
                    state,
                    &senders,
                    client_id,
                    cfg,
                    label,
                    &nick,
                    "SASL authentication failed",
                )
                .await;
                return Ok(());
            }
        };

        // Generate server nonce and build server-first-message
        let server_nonce: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();
        let full_nonce = format!("{}{}", client_nonce, server_nonce);
        let server_first = format!(
            "r={},s={},i={}",
            full_nonce, creds.salt_b64, creds.iterations
        );

        // Store SCRAM state
        {
            let mut sg = state.write().await;
            let conn = sg.get_or_create_pending(client_id, host);
            conn.sasl_scram = Some(ScramServerState {
                username: username.clone(),
                full_nonce: full_nonce.clone(),
                client_first_bare: bare.to_string(),
                server_first: server_first.clone(),
                stored_key: creds.stored_key,
                server_key: creds.server_key,
            });
        }

        // Send server-first
        let encoded = B64.encode(server_first.as_bytes());
        reply_to_client(
            &senders,
            client_id,
            Message::new("AUTHENTICATE", vec![encoded]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
    } else {
        // ── Step 2: process client-final-message ─────────────────────────────
        // Format: c=biws,r=fullnonce,p=base64(ClientProof)
        let scram = {
            let mut sg = state.write().await;
            sg.pending
                .get_mut(client_id)
                .and_then(|c| c.sasl_scram.take())
        };
        let scram = match scram {
            Some(s) => s,
            None => {
                sasl_fail(
                    state,
                    &senders,
                    client_id,
                    cfg,
                    label,
                    &nick,
                    "SASL SCRAM: internal state error",
                )
                .await;
                return Ok(());
            }
        };

        let mut cbind = String::new();
        let mut recv_nonce = String::new();
        let mut client_proof_b64 = String::new();
        // We need client-final-without-proof for auth message
        let proof_prefix = ",p=";
        let client_final_without_proof = payload
            .find(proof_prefix)
            .map(|i| &payload[..i])
            .unwrap_or(&payload);
        for part in payload.split(',') {
            if let Some(v) = part.strip_prefix("c=") {
                cbind = v.to_string();
            } else if let Some(v) = part.strip_prefix("r=") {
                recv_nonce = v.to_string();
            } else if let Some(v) = part.strip_prefix("p=") {
                client_proof_b64 = v.to_string();
            }
        }

        // Validate nonce
        if recv_nonce != scram.full_nonce {
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL authentication failed",
            )
            .await;
            return Ok(());
        }
        // Validate channel binding header (no channel binding = "biws" = base64("n,,"))
        if cbind != "biws" {
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL authentication failed",
            )
            .await;
            return Ok(());
        }

        let client_proof = match B64.decode(&client_proof_b64) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                sasl_fail(
                    state,
                    &senders,
                    client_id,
                    cfg,
                    label,
                    &nick,
                    "SASL SCRAM: invalid client proof",
                )
                .await;
                return Ok(());
            }
        };

        // auth_message = client_first_bare + "," + server_first + "," + client_final_without_proof
        let auth_message = format!(
            "{},{},{}",
            scram.client_first_bare, scram.server_first, client_final_without_proof
        );

        // Verify: ClientSignature = HMAC(StoredKey, AuthMessage)
        //         RecoveredClientKey = ClientProof XOR ClientSignature
        //         SHA256(RecoveredClientKey) must equal StoredKey
        let client_signature = hmac_sha256_reg(&scram.stored_key, auth_message.as_bytes());
        let recovered_client_key = xor32(&client_proof, &client_signature);
        let recovered_stored_key = sha256_reg(&recovered_client_key);

        if recovered_stored_key != scram.stored_key {
            sasl_fail(
                state,
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL authentication failed",
            )
            .await;
            return Ok(());
        }

        // Compute and send server-final: v=base64(ServerSignature)
        let server_sig = hmac_sha256_reg(&scram.server_key, auth_message.as_bytes());
        let server_final = format!("v={}", B64.encode(server_sig));
        reply_to_client(
            &senders,
            client_id,
            Message::new("AUTHENTICATE", vec![B64.encode(server_final.as_bytes())])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;

        let account = scram.username.clone();

        // Set account
        {
            let mut sg = state.write().await;
            if let Some(conn) = sg.pending.get_mut(client_id) {
                conn.account = Some(account.clone());
            }
        }

        tracing::info!(client_id, account = %account, "SASL SCRAM-SHA-256 authentication successful");

        // 900 RPL_LOGGEDIN + 903 RPL_SASLSUCCESS
        let (channel_list, source, user_ident_host) = {
            let sg = state.write().await;
            if let Some(conn) = sg.pending.get(client_id) {
                let uih = format!(
                    "{}!{}@{}",
                    nick,
                    conn.nick.as_deref().unwrap_or("*"),
                    conn.host
                );
                (Vec::<String>::new(), uih.clone(), uih)
            } else {
                (Vec::new(), nick.clone(), nick.clone())
            }
        };

        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "900",
                vec![
                    nick.to_string(),
                    user_ident_host,
                    account.clone(),
                    format!("You are now logged in as {}", account),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "903",
                vec![nick.to_string(), "SASL authentication successful".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;

        // account-notify
        let account_msg = Message::new("ACCOUNT", vec![account.clone()]).with_prefix(&source);
        for ch_name in &channel_list {
            let ch_store = channels.read().await;
            if let Some(ch) = ch_store.channels.get(ch_name) {
                let member_ids: Vec<String> = ch.read().await.members.keys().cloned().collect();
                drop(ch_store);
                let sg = state.read().await;
                for mid in &member_ids {
                    if *mid == client_id {
                        continue;
                    }
                    if let Some(c) = sg.clients.get(mid) {
                        if c.read().await.has_cap("account-notify") {
                            send_to_client(&senders, mid, account_msg.clone()).await;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn handle_oper(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let password = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    if name.is_empty() || password.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec!["OPER".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    for oper in &cfg.opers {
        if oper.name == name && bcrypt::verify(password, &oper.password_hash).unwrap_or(false) {
            let found = if let Some(c) = state.read().await.clients.get(client_id) {
                c.write().await.oper = true;
                true
            } else {
                false
            };
            if found {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "381",
                        vec!["*".into(), "You are now an IRC operator".into()],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            } else {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("451", vec!["*".into(), "You have not registered".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            return Ok(());
        }
    }
    reply_to_client(
        &senders,
        client_id,
        Message::new("464", vec!["*".into(), "Password incorrect".into()])
            .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// REGISTER <account> {<email>|*} <password> — draft/account-registration. Account must be * (current nick).
pub async fn handle_register(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let pool = match cfg.db.as_ref() {
        Some(p) => p,
        None => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "TEMPORARILY_UNAVAILABLE".into(),
                        "*".into(),
                        " :Registration unavailable".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };
    let (_nick, account) = {
        let state_guard = state.read().await;
        let client = match state_guard.clients.get(client_id) {
            Some(c) => c.clone(),
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "REGISTER".into(),
                            "COMPLETE_CONNECTION_REQUIRED".into(),
                            " :Complete connection registration first".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        };
        let g = client.read().await;
        let nick = g.nick.as_deref().unwrap_or("").to_string();
        if nick.is_empty() {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "NEED_NICK".into(),
                        "*".into(),
                        " :Send NICK first".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        if g.account.is_some() {
            let acc = g.account.as_deref().unwrap_or("*");
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "ALREADY_AUTHENTICATED".into(),
                        acc.into(),
                        " :Already logged in".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        let account_param = msg.params.first().map(|s| s.as_str()).unwrap_or("*");
        // Accept "*" (use current nick) or the nick itself; anything else is rejected.
        let account = if account_param == "*" || account_param.eq_ignore_ascii_case(&nick) {
            nick.clone()
        } else {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "ACCOUNT_NAME_MUST_BE_NICK".into(),
                        account_param.into(),
                        " :Account name must match your current nick".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        };
        (nick, account)
    };
    let email = msg
        .params
        .get(1)
        .and_then(|s| if s == "*" { None } else { Some(s.as_str()) });
    let password = msg
        .trailing()
        .or_else(|| msg.params.get(2).map(|s| s.as_str()))
        .unwrap_or("");
    if password.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "REGISTER".into(),
                    "UNACCEPTABLE_PASSWORD".into(),
                    account.clone(),
                    " :Password required".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    match persist::register_user(pool, &account, password, email).await {
        Ok(()) => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "REGISTER",
                    vec![
                        "SUCCESS".into(),
                        account.clone(),
                        " :Account successfully registered".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        Err(RegisterError::AccountExists) => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "ACCOUNT_EXISTS".into(),
                        account.clone(),
                        " :Account already exists".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        Err(RegisterError::WeakPassword) => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "WEAK_PASSWORD".into(),
                        account.clone(),
                        " :Password too weak".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        Err(RegisterError::Io(e)) => {
            tracing::error!(client_id, account = %account, error = %e, "REGISTER: database error");
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "TEMPORARILY_UNAVAILABLE".into(),
                        account.clone(),
                        " :Registration temporarily unavailable".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
    }
    Ok(())
}

/// VERIFY <account> <code> — draft/account-registration. We don't require verification; any VERIFY returns INVALID_CODE.
pub async fn handle_verify(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let account = msg.params.first().map(|s| s.as_str()).unwrap_or("*");
    let _code = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let state_guard = state.read().await;
    if let Some(c) = state_guard.clients.get(client_id) {
        let acc_opt = c.read().await.account.clone();
        if let Some(ref acc) = acc_opt {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "VERIFY".into(),
                        "ALREADY_AUTHENTICATED".into(),
                        acc.clone(),
                        " :Already logged in".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    }
    let account_str = account.to_string();
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "FAIL",
            vec![
                "VERIFY".into(),
                "INVALID_CODE".into(),
                account_str,
                " :Verification not required or code invalid".into(),
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

pub async fn handle_away(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let away_msg = msg.trailing().map(String::from);
    let (source, channel_list) = {
        let mut state = state.write().await;
        if !state.clients.contains_key(client_id) {
            if let Some(pending) = state.pending.get_mut(client_id) {
                pending.away_message = away_msg;
            }
            return Ok(());
        }
        let client = state.clients.get(client_id).cloned().unwrap();
        let mut client_guard = client.write().await;
        client_guard.away_message = away_msg.clone();
        let source = client_guard
            .source()
            .unwrap_or_else(|| client_id.to_string());
        let channel_list: Vec<String> = client_guard.channels.keys().cloned().collect();
        (source, channel_list)
    };

    // Send 306 RPL_NOWAWAY or 305 RPL_UNAWAY to the client
    let (reply_code, reply_text) = if away_msg.is_some() {
        ("306", "You have been marked as being away")
    } else {
        ("305", "You are no longer marked as being away")
    };
    reply_to_client(
        &senders,
        client_id,
        Message::new(reply_code, vec!["*".into(), reply_text.into()]).with_prefix(&cfg.server.name),
        label,
    )
    .await;

    // away-notify: tell channel peers that have the cap
    for ch_name in &channel_list {
        let ch_store = channels.read().await;
        let ch_guard = match ch_store.channels.get(ch_name) {
            Some(ch) => ch,
            None => continue,
        };
        let member_ids: Vec<String> = ch_guard.read().await.members.keys().cloned().collect();
        let _ = ch_guard;
        drop(ch_store);

        let state = state.read().await;
        let away_message = Message::new(
            "AWAY",
            away_msg
                .as_ref()
                .map(|s| vec![s.clone()])
                .unwrap_or_default(),
        )
        .with_prefix(&source);
        for mid in &member_ids {
            if *mid == client_id {
                continue;
            }
            let caps = match state.clients.get(mid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            if caps.contains("away-notify") {
                send_to_client(&senders, mid, away_message.clone()).await;
            }
        }
    }

    Ok(())
}

/// Max realname length (must match NAMELEN in RPL_ISUPPORT)
const NAMELEN: usize = 128;

pub async fn handle_setname(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let realname = msg.trailing().unwrap_or("").to_string();
    let has_standard_replies = {
        let state = state.read().await;
        match state.clients.get(client_id) {
            Some(c) => c.read().await.has_cap("standard-replies"),
            None => false,
        }
    };

    if realname.len() > NAMELEN {
        if has_standard_replies {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "SETNAME".into(),
                        "INVALID_REALNAME".into(),
                        "Realname is not valid".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        return Ok(());
    }

    let (source, channel_list) = {
        let mut state = state.write().await;
        let client = match state.clients.get_mut(client_id) {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let source = client
            .read()
            .await
            .source()
            .unwrap_or_else(|| client_id.to_string());
        let channel_list: Vec<String> = client.read().await.channels.keys().cloned().collect();
        drop(client);
        if let Some(c) = state.clients.get_mut(client_id) {
            c.write().await.realname = Some(realname.clone());
        }
        (source, channel_list)
    };

    let setname_msg = Message::new("SETNAME", vec![realname]).with_prefix(&source);

    // Send to self if they have setname
    let state = state.read().await;
    let self_has_setname = match state.clients.get(client_id) {
        Some(c) => c.read().await.has_cap("setname"),
        None => false,
    };
    if self_has_setname {
        reply_to_client(&senders, client_id, setname_msg.clone(), label).await;
    }
    for ch_name in &channel_list {
        let ch_store = channels.read().await;
        let ch_guard = match ch_store.channels.get(ch_name) {
            Some(ch) => ch,
            None => continue,
        };
        let member_ids: Vec<String> = ch_guard.read().await.members.keys().cloned().collect();
        let _ = ch_guard;
        drop(ch_store);
        for mid in &member_ids {
            if *mid == client_id {
                continue;
            }
            let has_setname = match state.clients.get(mid) {
                Some(c) => c.read().await.has_cap("setname"),
                None => false,
            };
            if has_setname {
                send_to_client(&senders, mid, setname_msg.clone()).await;
            }
        }
    }

    Ok(())
}

/// SETHOST newhost — oper only. Sets vhost (display host); notifies channel peers via CHGHOST.
pub async fn handle_sethost(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let new_host = msg
        .trailing()
        .or_else(|| msg.params.first().map(|s| s.as_str()))
        .unwrap_or("")
        .trim()
        .to_string();
    if new_host.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec!["SETHOST".into(), "Not enough parameters".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if new_host.contains(' ') {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec!["SETHOST".into(), "Host cannot contain spaces".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let (old_source, new_user, new_host_owned) = {
        let state_guard = state.read().await;
        let client = match state_guard.clients.get(client_id) {
            Some(c) => c.clone(),
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("451", vec!["*".into(), "You have not registered".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        };
        let mut guard = client.write().await;
        if !guard.oper {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "481",
                    vec![
                        "*".into(),
                        "Permission denied - You're not an IRC operator".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        let old_source = guard.source().unwrap_or_else(|| client_id.to_string());
        let display_user = guard
            .vuser
            .as_deref()
            .unwrap_or_else(|| guard.user.as_deref().unwrap_or(""))
            .to_string();
        guard.vhost = Some(new_host.clone());
        (old_source, display_user, new_host)
    };
    send_chghost_if_changed(
        state,
        channels,
        senders.clone(),
        client_id,
        &old_source,
        &new_user,
        &new_host_owned,
    )
    .await;
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec!["*".into(), format!("Host changed to '{}'", new_host_owned)],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// SETUSER newusername — oper only. Sets vuser (display user); notifies channel peers via CHGHOST.
pub async fn handle_setuser(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let new_user = msg
        .trailing()
        .or_else(|| msg.params.first().map(|s| s.as_str()))
        .unwrap_or("")
        .to_string();
    if new_user.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec!["SETUSER".into(), "Not enough parameters".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let (old_source, new_host) = {
        let state_guard = state.read().await;
        let client = match state_guard.clients.get(client_id) {
            Some(c) => c.clone(),
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("451", vec!["*".into(), "You have not registered".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        };
        let mut guard = client.write().await;
        if !guard.oper {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "481",
                    vec![
                        "*".into(),
                        "Permission denied - You're not an IRC operator".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        let old_source = guard.source().unwrap_or_else(|| client_id.to_string());
        let display_host = guard
            .vhost
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| guard.host.clone());
        guard.vuser = Some(new_user.clone());
        (old_source, display_host)
    };
    send_chghost_if_changed(
        state,
        channels,
        senders,
        client_id,
        &old_source,
        &new_user,
        &new_host,
    )
    .await;
    Ok(())
}

/// Notify channel peers with `chghost` cap when a client's username or host changes.
pub async fn send_chghost_if_changed(
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    old_source: &str,
    new_user: &str,
    new_host: &str,
) {
    let channel_names: Vec<String> = {
        let state = state.read().await;
        match state.clients.get(client_id) {
            Some(c) => c.read().await.channels.keys().cloned().collect(),
            None => return,
        }
    };
    let chghost_msg =
        Message::new("CHGHOST", vec![new_user.into(), new_host.into()]).with_prefix(old_source);
    for ch_name in channel_names {
        let member_ids: Vec<String> = {
            let ch_store = channels.read().await;
            match ch_store.channels.get(&ch_name) {
                Some(ch) => ch.read().await.members.keys().cloned().collect(),
                None => continue,
            }
        };
        let state = state.read().await;
        for mid in member_ids {
            if mid == client_id {
                continue;
            }
            if let Some(c) = state.clients.get(&mid) {
                if c.read().await.capabilities.contains("chghost") {
                    send_to_client(&senders, &mid, chghost_msg.clone()).await;
                }
            }
        }
    }
}
