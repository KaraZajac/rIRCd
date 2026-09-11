use crate::capability::{build_cap_list, filter_requested};
use crate::channel::ChannelStore;
use crate::commands::{reply_to_client, session_caps};
use crate::config::Config;
use crate::persist::{self, RegisterError};
use crate::protocol::Message;
use crate::user::{Client, ScramServerState, Senders, ServerState};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;

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
/// Deliver to a user: every connection they have open, not just one.
/// Returns whether they had any.
async fn send_to_client(senders: &Senders, user_id: &str, msg: Message) -> bool {
    let registry = senders.read().await;
    let sessions = registry.sessions_of(user_id);
    let mut delivered = false;
    for session in sessions {
        if let Some(sink) = registry.get(&session) {
            sink.send(msg.clone());
            delivered = true;
        }
    }
    delivered
}

/// Deliver to a user, skipping the connection that caused the event, and only
/// to the connections that asked for the capability that carries it.
///
/// A capability belongs to a connection. Deciding from the user's set — which
/// is the union of its connections' — would send `ACCOUNT` or `AWAY` to a
/// client that never agreed to read one.
async fn send_to_others_requiring(
    senders: &Senders,
    user_id: &str,
    cap: &str,
    except: Option<&str>,
    msg: &Message,
) {
    senders
        .read()
        .await
        .deliver_requiring_except(user_id, cap, except, msg);
}

/// Deliver to a user's other connections, skipping the one that sent the
/// command. That one is answered directly, with the label it asked under; the
/// rest see the same event without one.
async fn send_to_other_sessions(senders: &Senders, user_id: &str, except: &str, msg: Message) {
    let registry = senders.read().await;
    for session in registry.sessions_of(user_id) {
        if session == except {
            continue;
        }
        if let Some(sink) = registry.get(&session) {
            sink.send(msg.clone());
        }
    }
}

/// Maximum ISUPPORT tokens per 005 line (RFC recommends ≤13).
const ISUPPORT_TOKENS_PER_LINE: usize = 13;

/// ISUPPORT (005) token list; used at registration and for extended-isupport.
/// `client_has_webpush` adds the VAPID token, which draft/webpush says to send
/// only to clients that enabled the capability.
fn isupport_tokens(cfg: &Config, client_has_webpush: bool) -> String {
    let network = format!(" NETWORK={}", cfg.network.name);
    let base = format!("CHANTYPES=# CHANLIMIT=#:50 CHANNELLEN=64 NICKLEN=32 NAMELEN=128 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 HOSTLEN=64 USERLEN=32 KEYLEN=64 LINELEN={linelen} MODES=4 CASEMAPPING={casemapping} CHANMODES=beIq,k,l,imnstpRcC USERMODES=,,,BiorRw MAXLIST=beIq:100 PREFIX=(ohv)@%+ STATUSMSG=@+ SAFELIST ELIST=CMNTU EXCEPTS INVEX KNOCK UTF8ONLY WHOX BOT=B EXTBAN=~,am ACCOUNTEXTBAN=a MONITOR=100 CHATHISTORY=200 MSGREFTYPES=msgid,timestamp TARGMAX=PRIVMSG:{targmax},NOTICE:{targmax},KICK:{targmax},NAMES: METADATA=50{}", network, linelen = cfg.limits.max_line_length, targmax = cfg.limits.max_targets, casemapping = crate::casefold::current());
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
        .map(|fh| {
            format!(
                " FILEHOST={} draft/FILEHOST={}",
                fh.public_url, fh.public_url
            )
        })
        .unwrap_or_default();
    // draft/webpush: public key clients use to verify notifications came from us.
    let vapid = match (client_has_webpush, cfg.webpush_runtime.as_ref()) {
        (true, Some(rt)) => format!(" VAPID={}", rt.key.public_b64()),
        _ => String::new(),
    };
    format!("{}{}{}{}{}", base, deny, icon, filehost, vapid)
}

pub async fn complete_registration(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
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

    // A server password is checked once, here: PASS has to arrive before the
    // NICK/USER pair that completes registration, so this is the first moment
    // it is known whether one was given at all.
    if let Some(ref expected) = cfg.server.password {
        let given = pending.pass.clone().unwrap_or_default();
        // ct_eq is false for differing lengths, so this is the whole check.
        if !bool::from(<[u8] as subtle::ConstantTimeEq>::ct_eq(
            given.as_bytes(),
            expected.as_bytes(),
        )) {
            reply_to_client(
                &senders,
                client_id,
                Message::new("464", vec!["*".into(), "Password incorrect".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            senders.write().await.close_user(
                client_id,
                Message::new("ERROR", vec!["Closing link: Password incorrect".into()])
                    .with_prefix(&cfg.server.name),
            );
            return Ok(());
        }
    }

    let nick = pending.nick.unwrap();
    let user = pending.user.unwrap();
    let realname = pending.realname.unwrap_or_else(|| nick.clone());
    let pending_metadata: Vec<(String, String)> =
        std::mem::take(&mut pending.metadata).into_iter().collect();

    let mut state_guard = state.write().await;

    // Set when this connection joins a user that is already here, rather than
    // becoming one of its own.
    let mut attach_to: Option<String> = None;

    if let Some(holder_id) = state_guard
        .nick_to_id
        .get(&crate::casefold::upper(&nick))
        .cloned()
    {
        // The nick is in use. If it is in use by this same account, this is the
        // same person arriving on another connection, and what happens next is
        // the operator's choice: join the existing user as another session, or
        // take over from the connection that had it.
        let same_account = pending.account.is_some()
            && match state_guard.clients.get(&holder_id) {
                Some(c) => c.read().await.account == pending.account,
                None => false,
            };
        if same_account && cfg.server.multiclient {
            tracing::info!(
                client_id,
                %nick,
                user = %holder_id,
                "Adding a session to an account that is already connected"
            );
            attach_to = Some(holder_id);
        } else if !(same_account && cfg.server.persistent_sessions) {
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
        } else {
            tracing::info!(
                client_id,
                %nick,
                replaced = %holder_id,
                "Resuming a persistent session; disconnecting the earlier one"
            );
            state_guard
                .nick_to_id
                .remove(&crate::casefold::upper(&nick));
            drop(state_guard);
            senders.write().await.close_user(
                &holder_id,
                Message::new(
                    "ERROR",
                    vec!["Closing link: session resumed from another connection".into()],
                )
                .with_prefix(&cfg.server.name),
            );
            state.write().await.remove_client(&holder_id).await;
            // To the rest of the network the earlier session is a user that has
            // gone; the one resuming it arrives with an id of its own.
            crate::link::announce_quit(cfg, &holder_id, "session resumed from another connection")
                .await;
            state_guard = state.write().await;
        }
    }

    // A user's own id, distinct from the connection it arrived on. On a linked
    // network this is what the other servers know it by, and it stays the same
    // as the user opens and closes connections.
    let uid = {
        let sid = if state_guard.sid.is_empty() {
            crate::link::our_sid(cfg)
        } else {
            state_guard.sid.clone()
        };
        crate::link::next_uid(&sid, &state_guard.uid_counter)
    };
    let mut client = Client::new_on(uid.clone(), client_id.to_string(), pending.host);
    client.nick = Some(nick.clone());
    client.user = Some(user);
    client.realname = Some(realname);
    client.registered = true;
    client.capabilities = pending.capabilities.clone();
    client.account = pending.account.clone();
    client.away_message = pending.away_message.take();
    client.is_tls = pending.is_tls;

    // Auto-cloak: if cloak_key is set, derive a stable vhost from the real IP via HMAC-SHA256
    if let Some(ref cloak_key) = cfg.server.cloak_key {
        let hash = hmac_sha256_reg(cloak_key.as_bytes(), client.host.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        client.vhost = Some(format!("{}.IP", &hex[..8]));
    }

    // Server bans are checked against the real host, before the connection is
    // admitted and given a nick anyone can see.
    let real_source = format!(
        "{}!{}@{}",
        client.nick.as_deref().unwrap_or("*"),
        client.user.as_deref().unwrap_or("*"),
        client.host
    );
    if let Some(ban) = state_guard.matching_ban(&real_source, &client.host) {
        let reason = ban.reason.clone();
        let mask = ban.mask.clone();
        drop(state_guard);
        tracing::info!(client_id, %mask, "Refusing banned connection");
        reply_to_client(
            &senders,
            client_id,
            Message::new("ERROR", vec![format!("Closing link: banned ({})", reason)])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // The capabilities are this connection's. A user's set is the union of its
    // connections', so a message is built for the superset and trimmed back per
    // connection as it goes out.
    senders
        .write()
        .await
        .set_session_caps(client_id, pending.capabilities.clone());

    let client = match attach_to {
        // Another connection for a user that is already here: it takes no new
        // nick and no new place in any channel, it just starts reading.
        Some(ref user_id) => {
            state_guard.attach_session(user_id, client_id).await;
            let user = state_guard
                .clients
                .get(user_id)
                .cloned()
                .expect("attached to a user that is here");
            drop(state_guard);
            {
                let mut registry = senders.write().await;
                registry.reassign_session(user_id, client_id);
                let union = registry.union_caps(user_id);
                drop(registry);
                user.write().await.capabilities = union;
            }
            user
        }
        None => {
            let client = state_guard.add_client(client, client_id).await;
            drop(state_guard);
            // The connection was its own user until now. File it under the user
            // id instead, so anything addressed to the user reaches it.
            senders.write().await.reassign_session(&uid, client_id);
            // A new person on the network. A second connection for someone who
            // is already here is not — the network has met them already.
            crate::link::announce_user(cfg, &*client.read().await).await;
            client
        }
    };

    let server = &cfg.server.name;
    let nick_str = &client.read().await.nick_or_id().to_string();

    // Read what is being logged before logging it: awaiting inside the macro's
    // arguments leaves a formatting borrow held across the await, which is
    // enough to stop this whole call being sendable to a task of its own.
    let (logged_host, logged_tls) = {
        let guard = client.read().await;
        (guard.display_host().to_string(), guard.is_tls)
    };
    tracing::info!(
        client_id,
        nick = %nick_str,
        host = %logged_host,
        tls = logged_tls,
        "Client registered"
    );

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
                concat!("rIRCd-", env!("CARGO_PKG_VERSION")).into(),
                "BioRrw".into(),
                "bceIklmnopqRstvC".into(),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;

    let isupport = isupport_tokens(
        cfg,
        session_caps(&senders, client_id)
            .await
            .contains("draft/webpush"),
    );
    let tokens: Vec<&str> = isupport.split(' ').collect();
    for chunk in tokens.chunks(ISUPPORT_TOKENS_PER_LINE) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "005",
                vec![
                    nick_str.clone(),
                    chunk.join(" "),
                    "are supported by this server".to_string(),
                ],
            )
            .with_prefix(server),
            label,
        )
        .await;
    }

    send_motd(nick_str, server, &senders, cfg, label, client_id).await;

    // draft/metadata before-connect: keys set during registration now belong to
    // a user with a nick, so they move into its store and come back as part of
    // the burst.
    if !pending_metadata.is_empty() {
        // Filed under the account if the client logged in during registration,
        // and under the nick if it did not. By this point SASL has finished
        // either way, so this is the first moment the answer is known.
        let account = client.read().await.account.clone();
        let key = match account {
            Some(ref account) => crate::commands::metadata::account_key(account),
            None => crate::commands::metadata::nick_key(nick_str),
        };
        {
            let mut state_w = state.write().await;
            let entry = state_w.metadata.entry(key.clone()).or_default();
            for (k, v) in &pending_metadata {
                entry.insert(k.clone(), v.clone());
            }
        }
        // Only an account is a lasting identity to file keys under; a bare
        // nick belongs to whoever holds it next.
        if let (Some(pool), true) = (
            cfg.db.as_ref(),
            crate::commands::metadata::is_lasting(&key),
        ) {
            for (k, v) in &pending_metadata {
                crate::persist::save_metadata(pool, &key, k, v).await;
            }
        }
        let caps = session_caps(&senders, client_id).await;
        crate::commands::metadata::send_channel_metadata_on_join(
            &senders,
            client_id,
            nick_str,
            nick_str,
            server,
            caps.contains("batch"),
            pending_metadata.clone(),
        )
        .await;
    }

    // draft/auto-join: send AUTOJOIN with configured channel list
    {
        let caps = session_caps(&senders, client_id).await;
        if caps.contains("draft/auto-join") {
            if let Some(ref auto_join) = cfg.server.auto_join {
                let channels: Vec<&str> = auto_join
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !channels.is_empty() {
                    // Split across multiple messages if needed to stay under 512 bytes
                    // Prefix: ":<server> AUTOJOIN " — reserve space for that + \r\n
                    let prefix_len = server.len() + 12; // ": AUTOJOIN \r\n"
                    let max_payload = 510 - prefix_len;
                    let mut current = String::new();
                    for ch in &channels {
                        let needed = if current.is_empty() {
                            ch.len()
                        } else {
                            ch.len() + 1 // comma
                        };
                        if !current.is_empty() && current.len() + needed > max_payload {
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new("AUTOJOIN", vec![current.clone()]).with_prefix(server),
                                label,
                            )
                            .await;
                            current.clear();
                        }
                        if !current.is_empty() {
                            current.push(',');
                        }
                        current.push_str(ch);
                    }
                    if !current.is_empty() {
                        reply_to_client(
                            &senders,
                            client_id,
                            Message::new("AUTOJOIN", vec![current]).with_prefix(server),
                            label,
                        )
                        .await;
                    }
                    tracing::info!(
                        nick = %nick_str,
                        channels = %auto_join,
                        "Sent AUTOJOIN list to client"
                    );
                }
            }
        }
    }

    // monitor: notify clients monitoring this nick that they came online (730)
    let source = client
        .read()
        .await
        .source()
        .unwrap_or_else(|| nick_str.clone());
    let mut watchers: Vec<String> = state
        .read()
        .await
        .monitor_watchers
        .by_nick
        .get(&crate::casefold::lower(nick_str))
        .map(|s: &std::collections::HashSet<String>| s.iter().cloned().collect())
        .unwrap_or_default();
    // extended-monitor: mask watchers (nick!user@host globs) also want to know.
    {
        let state_r = state.read().await;
        for w in state_r
            .monitor_watchers
            .pattern_watchers_for(&crate::casefold::lower(&source))
        {
            if !watchers.contains(&w) {
                watchers.push(w);
            }
        }
    }
    // An extra connection for someone already here is not an arrival: nobody
    // watching this nick saw it go offline, so there is nothing to announce.
    let watchers: Vec<String> = if attach_to.is_some() {
        Vec::new()
    } else {
        watchers
    };
    if !watchers.is_empty() {
        tracing::info!(
            nick = %nick_str,
            watcher_count = watchers.len(),
            "Monitor: notifying watchers that nick came online (730)"
        );
    }
    let self_id = state.read().await.user_id(client_id);
    for w in &watchers {
        if *w == self_id {
            continue;
        }
        let client_arc = state.read().await.clients.get(w).cloned();
        let nick = match client_arc {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => "*".to_string(),
        };
        let m = Message::new("730", vec![nick, source.clone()]).with_prefix(server);
        if !send_to_client(&senders, w, m).await {
            tracing::warn!(watcher_id = %w, nick = %nick_str, "Monitor: watcher not in senders, 730 not delivered");
        }
    }

    match attach_to {
        // The user is already in its channels; this connection has to be told
        // where it has arrived, and only this connection.
        Some(_) => {
            send_channel_state_to_session(client_id, &client, &state, &channels, &senders, cfg)
                .await
        }
        None => rejoin_account_channels(client_id, &state, &channels, &senders, cfg).await,
    }

    Ok(())
}

/// Tell one connection which channels its user is in, as if it had just joined
/// them: the JOIN it would have seen, the topic, and who is there.
async fn send_channel_state_to_session(
    session_id: &str,
    client: &Arc<RwLock<Client>>,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Senders,
    cfg: &Config,
) {
    let (source, nick, joined, account) = {
        let g = client.read().await;
        (
            g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
            g.nick_or_id().to_string(),
            g.channels.keys().cloned().collect::<Vec<_>>(),
            g.account.clone(),
        )
    };
    // The burst goes to this connection, so it is shaped by what this
    // connection negotiated rather than by the account's union.
    let caps = session_caps(senders, session_id).await;

    for ch_key in joined {
        let join_msg = if caps.contains("extended-join") {
            Message::new(
                "JOIN",
                vec![
                    ch_key.clone(),
                    account.clone().unwrap_or_else(|| "*".to_string()),
                    client.read().await.realname.clone().unwrap_or_default(),
                ],
            )
            .with_prefix(&source)
        } else {
            Message::new("JOIN", vec![ch_key.clone()]).with_prefix(&source)
        };
        reply_to_client(senders, session_id, join_msg, None).await;

        let ch_store = channels.read().await;
        let Some(ch_ref) = ch_store.channels.get(&ch_key) else {
            continue;
        };
        let (topic, topic_setter, topic_time) = {
            let ch = ch_ref.read().await;
            (ch.topic.clone(), ch.topic_setter.clone(), ch.topic_time)
        };
        if let Some(topic) = topic {
            reply_to_client(
                senders,
                session_id,
                Message::new("332", vec![nick.clone(), ch_key.clone(), topic])
                    .with_prefix(&cfg.server.name),
                None,
            )
            .await;
            reply_to_client(
                senders,
                session_id,
                Message::new(
                    "333",
                    vec![
                        nick.clone(),
                        ch_key.clone(),
                        topic_setter.unwrap_or_else(|| "*".to_string()),
                        topic_time.unwrap_or(0).to_string(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                None,
            )
            .await;
        }

        let state_r = state.read().await;
        // draft/read-marker: where this session should consider itself caught
        // up to, the same as it would learn on joining.
        if caps.contains("draft/read-marker") {
            let key = account.clone().unwrap_or_else(|| session_id.to_string());
            let ts = state_r
                .read_markers
                .get(&key)
                .and_then(|m| m.get(&ch_key).cloned())
                .unwrap_or_else(|| "*".to_string());
            let ts_param = if ts == "*" {
                "*".to_string()
            } else {
                format!("timestamp={}", ts)
            };
            reply_to_client(
                senders,
                session_id,
                Message::new("MARKREAD", vec![ch_key.clone(), ts_param])
                    .with_prefix(&cfg.server.name),
                None,
            )
            .await;
        }
        crate::commands::channel_cmds::send_names_for_channel(
            ch_ref,
            &ch_key,
            &nick,
            &state_r,
            senders,
            session_id,
            &cfg.server.name,
            &caps,
            None,
            None,
        )
        .await;
    }
}

/// Put a returning client back into the channels its account was in.
///
/// A client that reconnects has left nothing behind on the server, so without
/// this it comes back to an empty session and has to remember its own channels.
/// Off unless the operator turned it on.
pub async fn rejoin_account_channels(
    client_id: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Senders,
    cfg: &Config,
) {
    if !cfg.server.persistent_sessions {
        return;
    }
    let Some(pool) = cfg.db.as_ref() else {
        return;
    };
    let account = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.account.clone(),
        None => None,
    };
    let Some(account) = account else {
        return;
    };

    for channel in persist::channels_for_account(pool, &account).await {
        let already_in = match state.read().await.clients.get(client_id) {
            Some(c) => c.read().await.channels.contains_key(&channel),
            None => true,
        };
        if already_in {
            continue;
        }
        let join = Message::new("JOIN", vec![channel.clone()]);
        if let Err(e) = crate::commands::channel_cmds::handle_join(
            client_id,
            join,
            state.clone(),
            channels.clone(),
            senders.clone(),
            cfg,
            None,
        )
        .await
        {
            tracing::warn!(client_id, %channel, error = %e, "Could not rejoin channel on login");
        }
    }
}

pub async fn handle_isupport(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let (nick, has_webpush) = {
        let state = state.read().await;
        if let Some(c) = state.clients.get(client_id) {
            let g = c.read().await;
            (
                g.nick_or_id().to_string(),
                senders
                    .read()
                    .await
                    .caps_of(client_id)
                    .contains("draft/webpush"),
            )
        } else if let Some(p) = state.pending.get(client_id) {
            (
                p.nick.as_deref().unwrap_or("*").to_string(),
                p.capabilities.contains("draft/webpush"),
            )
        } else {
            ("*".to_string(), false)
        }
    };
    let isupport = isupport_tokens(cfg, has_webpush);
    let tokens: Vec<&str> = isupport.split(' ').collect();
    for chunk in tokens.chunks(ISUPPORT_TOKENS_PER_LINE) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "005",
                vec![
                    nick.clone(),
                    chunk.join(" "),
                    "are supported by this server".to_string(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
    }
    Ok(())
}

/// WEBIRC password gateway hostname ip [options] — accept real IP/host from gateway before CAP.
/// Only applies if client is not yet registered and cfg.webirc.password matches.
pub async fn handle_webirc(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
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
    // Constant-time comparison for WEBIRC password to prevent timing attacks
    let password_ok = match (expected, password) {
        (Some(e), Some(p)) => {
            use subtle::ConstantTimeEq;
            e.len() == p.len() && e.as_bytes().ct_eq(p.as_bytes()).into()
        }
        (None, None) => true,
        _ => false,
    };
    if !password_ok || ip.is_empty() {
        tracing::warn!(client_id, ip = %ip, "WEBIRC authentication failed");
        let tx = senders.read().await.get(client_id).cloned();
        if let Some(tx) = tx {
            tx.send(
                Message::new("ERROR", vec!["Invalid WebIRC password".into()])
                    .with_prefix(&cfg.server.name),
            );
        }
        return Ok(());
    }
    tracing::info!(client_id, real_ip = %ip, "WEBIRC accepted, real IP set");
    let mut state_w = state.write().await;
    let pending = state_w.get_or_create_pending(client_id, host);
    pending.host = ip.to_string();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_cap(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let subcmd = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let version_302 = msg.params.get(1).map(|s| s.as_str()) == Some("302");

    // Determine if client is already registered; use nick for responses, "*" during registration
    let (is_registered, cap_nick) = {
        let state_r = state.read().await;
        let reg = state_r.clients.contains_key(client_id);
        let nick = if reg {
            match state_r.clients.get(client_id) {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            }
        } else {
            "*".to_string()
        };
        (reg, nick)
    };
    let mut state_guard = state.write().await;
    let mut sasl_aborted: Option<String> = None;

    match subcmd {
        "LS" => {
            if !is_registered {
                let conn = state_guard.get_or_create_pending(client_id, host);
                conn.cap_negotiating = true;
                // CAP 302 implicitly enables cap-notify
                if version_302 {
                    conn.capabilities.insert("cap-notify".to_string());
                }
            } else if version_302 {
                if let Some(c) = state_guard.clients.get(client_id).cloned() {
                    let user_id = state_guard.user_id(client_id);
                    let union = {
                        let mut registry = senders.write().await;
                        let mut session_caps = registry.caps_of(client_id);
                        session_caps.insert("cap-notify".to_string());
                        registry.set_session_caps(client_id, session_caps);
                        registry.union_caps(&user_id)
                    };
                    c.write().await.capabilities = union;
                }
            }
            let client_is_tls = if is_registered {
                match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.is_tls,
                    None => false,
                }
            } else {
                state_guard
                    .pending
                    .get(client_id)
                    .map(|p| p.is_tls)
                    .unwrap_or(false)
            };
            let caps = build_cap_list(cfg, version_302, client_is_tls);
            let total = caps.len();
            for (i, cap_line) in caps.iter().enumerate() {
                let is_last = i == total - 1;
                let params = if !is_last {
                    vec![cap_nick.clone(), "LS".into(), "*".into(), cap_line.clone()]
                } else {
                    vec![cap_nick.clone(), "LS".into(), cap_line.clone()]
                };
                let mut reply = Message::new("CAP", params);
                reply.prefix = Some(cfg.server.name.clone());
                reply_to_client(&senders, client_id, reply, label).await;
            }
        }
        "LIST" => {
            let cap_line = if is_registered {
                // `CAP LIST` answers for this connection. Listing the account's
                // union would tell a client it had negotiated things it never
                // asked for, and it would then act on them.
                match Some(senders.read().await.caps_of(client_id)) {
                    Some(cg) => cg.iter().cloned().collect::<Vec<_>>().join(" "),
                    None => String::new(),
                }
            } else {
                let conn = state_guard.get_or_create_pending(client_id, host);
                conn.capabilities
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let mut reply = Message::new("CAP", vec![cap_nick.clone(), "LIST".into(), cap_line]);
            reply.prefix = Some(cfg.server.name.clone());
            reply_to_client(&senders, client_id, reply, label).await;
        }
        "REQ" => {
            let raw: Vec<String> = msg
                .trailing()
                .unwrap_or("")
                .split_whitespace()
                .map(String::from)
                .collect();

            // Separate caps to enable vs disable (prefixed with `-`)
            let mut to_enable: Vec<String> = Vec::new();
            let mut to_disable: Vec<String> = Vec::new();
            for cap in &raw {
                if let Some(stripped) = cap.strip_prefix('-') {
                    to_disable.push(stripped.to_string());
                } else {
                    to_enable.push(cap.clone());
                }
            }

            let (ack_enable, nak) = filter_requested(&to_enable, &std::collections::HashSet::new());
            // Gather current client caps to check cap-notify protection
            let client_caps: std::collections::HashSet<String> = if is_registered {
                senders.read().await.caps_of(client_id)
            } else {
                state_guard
                    .pending
                    .get(client_id)
                    .map(|p| p.capabilities.clone())
                    .unwrap_or_default()
            };

            let mut nak_disable = Vec::new();
            for cap in &to_disable {
                let base = cap.split('=').next().unwrap_or(cap);
                // 302 clients implicitly enable cap-notify; MUST NOT be allowed to disable it.
                // Also NAK unknown capabilities.
                let is_protected_cap_notify =
                    base == "cap-notify" && client_caps.contains("cap-notify");
                if is_protected_cap_notify || !crate::capability::CAPS.contains(&base) {
                    nak_disable.push(format!("-{}", cap));
                }
            }

            if nak.is_empty() && nak_disable.is_empty() {
                if is_registered {
                    // Capabilities belong to this connection. The user's set is
                    // the union of its connections', so that a message is built
                    // for everything any of them asked for.
                    if let Some(c) = state_guard.clients.get(client_id).cloned() {
                        let user_id = state_guard.user_id(client_id);
                        let union = {
                            let mut registry = senders.write().await;
                            let mut session_caps = registry.caps_of(client_id);
                            for cap in &ack_enable {
                                session_caps.insert(cap.clone());
                            }
                            for cap in &to_disable {
                                let base = cap.split('=').next().unwrap_or(cap);
                                session_caps.remove(base);
                            }
                            registry.set_session_caps(client_id, session_caps);
                            registry.union_caps(&user_id)
                        };
                        c.write().await.capabilities = union;
                    }
                } else {
                    let conn = state_guard.get_or_create_pending(client_id, host);
                    for c in &ack_enable {
                        conn.capabilities.insert(c.clone());
                    }
                    for c in &to_disable {
                        let base = c.split('=').next().unwrap_or(c);
                        conn.capabilities.remove(base);
                    }
                }
                let ack_str: Vec<String> = ack_enable
                    .iter()
                    .cloned()
                    .chain(to_disable.iter().map(|c| format!("-{}", c)))
                    .collect();
                let mut reply = Message::new(
                    "CAP",
                    vec![cap_nick.clone(), "ACK".into(), ack_str.join(" ")],
                );
                reply.prefix = Some(cfg.server.name.clone());
                reply_to_client(&senders, client_id, reply, label).await;
            } else {
                // The request is rejected as a whole, so the NAK echoes everything
                // that was asked for — a client matches the reply against what it
                // sent, not against the subset the server happened to dislike.
                let mut reply =
                    Message::new("CAP", vec![cap_nick.clone(), "NAK".into(), raw.join(" ")]);
                reply.prefix = Some(cfg.server.name.clone());
                reply_to_client(&senders, client_id, reply, label).await;
            }
        }
        "END" => {
            if !is_registered {
                let conn = state_guard.get_or_create_pending(client_id, host);
                conn.cap_ended = true;
                // Ending negotiation with an exchange still in flight abandons
                // it: say so and let registration finish, rather than holding
                // the connection open for a response that is not coming.
                //
                // A check that is running is a response that *is* coming, and
                // an attempt that already failed was answered with 904 — the
                // client is not waiting on either, so neither is abandoned.
                if conn.sasl_mechanism.is_some()
                    && conn.account.is_none()
                    && !conn.sasl_failed
                    && !conn.sasl_checking()
                {
                    let nick = conn.nick.clone().unwrap_or_else(|| "*".to_string());
                    conn.sasl_mechanism = None;
                    conn.sasl_plain_buffer.clear();
                    conn.sasl_chunk_count = 0;
                    conn.sasl_scram = None;
                    sasl_aborted = Some(nick);
                }
            }
        }
        _ => {
            // 410 ERR_INVALIDCAPCMD
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "410",
                    vec![
                        cap_nick,
                        subcmd.to_string(),
                        "Invalid CAP subcommand".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
    }

    let should_complete = if !is_registered {
        state_guard
            .pending
            .get(client_id)
            .is_some_and(|p| p.ready_to_register())
    } else {
        false
    };
    drop(state_guard);

    if let Some(nick) = sasl_aborted {
        reply_to_client(
            &senders,
            client_id,
            Message::new("906", vec![nick, "SASL authentication aborted".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
    }

    if should_complete {
        complete_registration(client_id, state, channels, senders, cfg, label).await?;
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let mut state_guard = state.write().await;
    let nick = msg.params.first().cloned();
    let nick = match nick {
        Some(n) if !n.is_empty() && is_valid_nick(&n) => n,
        // A nick that was given but cannot be used is a different error from
        // giving none at all, and the client needs to see which one it sent.
        Some(n) if !n.is_empty() => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("432", vec!["*".into(), n, "Erroneous nickname".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
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

    // A registered nick belongs to its account: refuse it to anyone else, unless
    // the operator has turned that off.
    if cfg.server.nick_protection {
        // Who is asking, and are they already logged in to this account?
        let (current_nick, current_account) = match state_guard.clients.get(client_id) {
            Some(client) => {
                let g = client.read().await;
                (g.nick_or_id().to_string(), g.account.clone())
            }
            None => match state_guard.pending.get(client_id) {
                Some(p) => (
                    p.nick.clone().unwrap_or_else(|| "*".to_string()),
                    p.account.clone(),
                ),
                None => ("*".to_string(), None),
            },
        };
        let owns_it = current_account
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&nick));

        if !owns_it {
            let registered = match cfg.db {
                Some(ref pool) => {
                    crate::persist::nick_is_registered(pool, &cfg.db_health, &nick).await
                }
                None => false,
            };
            if registered {
                drop(state_guard);
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "433",
                        vec![
                            current_nick,
                            nick.clone(),
                            "Nickname is registered to another account".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        }
    }

    // Changing to the nick you already have, spelling and all, changes nothing:
    // no echo, and nothing for anyone else to hear about.
    if let Some(client) = state_guard.clients.get(client_id) {
        if client.read().await.nick.as_deref() == Some(nick.as_str()) {
            return Ok(());
        }
    }

    if let Some(client) = state_guard.clients.get(client_id) {
        let client_guard = client.write().await;
        if client_guard.registered {
            // Held by someone else, meaning some *other* user — another of
            // this user's own connections is not a collision.
            let self_user = state_guard.user_id(client_id);
            if state_guard
                .nick_to_id
                .get(&nick.to_uppercase())
                .map(|id| *id != self_user)
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
                user: client_guard.display_user().to_string(),
                host: client_guard.display_host().to_string(),
                realname: client_guard.realname.as_deref().unwrap_or("").to_string(),
                server: cfg.server.name.clone(),
                timestamp: chrono::Utc::now().timestamp(),
            });
            drop(client_guard);
            if let Some(entry) = whowas_entry {
                // Persist to DB
                if let Some(ref pool) = cfg.db {
                    persist::save_whowas(
                        pool,
                        &entry.nick,
                        &entry.user,
                        &entry.host,
                        &entry.realname,
                        &entry.server,
                    )
                    .await;
                }
                state_guard.push_whowas(entry);
            }
            if let Some(ref o) = old_nick {
                tracing::info!(client_id, old_nick = %o, new_nick = %nick, "Nick change");
                state_guard.nick_to_id.remove(&crate::casefold::upper(o));
                // Somebody logged in has their profile filed under their
                // account, so changing what they are called moves nothing:
                // it was never filed under the name. Somebody with no account
                // has keys filed under the nick they are leaving, and those
                // describe the person rather than the seat, so they come along
                // — left behind, the next holder of the old name wears them.
                let account = match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.account.clone(),
                    None => None,
                };
                if account.is_none() {
                    let (from, to) = (
                        crate::commands::metadata::nick_key(o),
                        crate::commands::metadata::nick_key(&nick),
                    );
                    if from != to {
                        if let Some(keys) = state_guard.metadata.remove(&from) {
                            state_guard.metadata.insert(to, keys);
                        }
                    }
                }
            }
            // One nick change happened at one time, and every server has to
            // agree on when: it is what settles a collision.
            let nick_ts = chrono::Utc::now().timestamp();
            if let Some(client) = state_guard.clients.get(client_id) {
                let mut g = client.write().await;
                g.nick = Some(nick.clone());
                g.nick_ts = nick_ts;
            }
            // The nick belongs to the user, so it must point at the user and
            // not at whichever of its connections changed it — otherwise a
            // message addressed to the nick reaches only that one.
            let user_id = state_guard.user_id(client_id);
            state_guard
                .nick_to_id
                .insert(crate::casefold::upper(&nick), user_id.clone());
            // monitor: 731 to watchers of old nick, 730 to watchers of new nick.
            // A change of case is the same nick, so nobody went offline or came
            // online and there is nothing to report.
            let case_change_only = old_nick
                .as_deref()
                .is_some_and(|old| old.eq_ignore_ascii_case(&nick));
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
                .get(&crate::casefold::lower(&nick))
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            drop(state_guard);
            // Nothing to move on disk: what is written down is filed under an
            // account, and an account does not change when a nick does.
            // The rest of the network is told once the local tables are
            // settled, and never while a lock over them is held.
            crate::link::announce_nick(cfg, &user_id, &nick, nick_ts).await;
            let server = &cfg.server.name;
            let client_arc = state.read().await.clients.get(client_id).cloned();
            let new_source = match client_arc {
                Some(c) => c.read().await.source().unwrap_or_else(|| nick.clone()),
                None => nick.clone(),
            };
            for w in &watchers_old {
                if *w == user_id || case_change_only {
                    continue;
                }
                let client_arc = state.read().await.clients.get(w).cloned();
                let recv_nick = match client_arc {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => "*".to_string(),
                };
                let m = Message::new(
                    "731",
                    vec![recv_nick, old_nick.as_deref().unwrap_or("").to_string()],
                )
                .with_prefix(server);
                send_to_client(&senders, w, m).await;
            }
            for w in &watchers_new {
                if *w == user_id || case_change_only {
                    continue;
                }
                let client_arc = state.read().await.clients.get(w).cloned();
                let recv_nick = match client_arc {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => "*".to_string(),
                };
                let m =
                    Message::new("730", vec![recv_nick, new_source.clone()]).with_prefix(server);
                send_to_client(&senders, w, m).await;
            }

            // Broadcast NICK change to channel members (and self). One event
            // happened at one time: stamping each copy separately gives two
            // people in the same channel two different times for it, and
            // history a third.
            let happened_at = crate::protocol::server_time_now();
            let mut nick_msg = Message::new("NICK", vec![nick.clone()]).with_prefix(&old_source);
            nick_msg
                .tags
                .insert("time".to_string(), Some(happened_at.clone()));
            // The sender's own copy is the answer to their NICK, so it carries
            // the label; the copies other members see do not.
            reply_to_client(&senders, client_id, nick_msg.clone(), label).await;
            // The user's other connections are watching the same nick change.
            let self_id = state.read().await.user_id(client_id);
            send_to_other_sessions(&senders, &self_id, client_id, nick_msg.clone()).await;
            let channel_names: Vec<String> = match state.read().await.clients.get(client_id) {
                Some(c) => c.read().await.channels.keys().cloned().collect(),
                None => Vec::new(),
            };
            let mut notified = std::collections::HashSet::new();
            notified.insert(self_id);
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
                cfg.record_history_at(ch_name, &old_source, &nick, None, "NICK", &happened_at);
            }

            return Ok(());
        }
    }

    // With persistent sessions, a client already authenticated to the account
    // that holds this nick is that account returning, so the nick is not taken
    // as far as it is concerned; complete_registration hands it over.
    let resuming_own_session = cfg.server.persistent_sessions && {
        let pending_account = state_guard
            .pending
            .get(client_id)
            .and_then(|c| c.account.clone());
        match (
            pending_account,
            state_guard
                .nick_to_id
                .get(&crate::casefold::upper(&nick))
                .cloned(),
        ) {
            (Some(account), Some(holder)) => match state_guard.clients.get(&holder) {
                Some(c) => c.read().await.account.as_deref() == Some(account.as_str()),
                None => false,
            },
            _ => false,
        }
    };
    let nick_taken = state_guard
        .nick_to_id
        .contains_key(&crate::casefold::upper(&nick))
        && !resuming_own_session;
    if nick_taken {
        // Remember what was asked for: REGISTER needs to tell someone trying to
        // claim a nick in use that the account is taken, not that they gave no
        // nick at all.
        // The pending entry may not exist yet if NICK is the first thing sent.
        if !state_guard.clients.contains_key(client_id) {
            let conn = state_guard.get_or_create_pending(client_id, host);
            conn.nick_in_use = Some(nick.clone());
        }
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
        complete_registration(client_id, state, channels, senders, cfg, label).await?;
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

#[allow(clippy::too_many_arguments)]
pub async fn handle_user(
    client_id: &str,
    host: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
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
    // USER takes four parameters, the last being the real name. Fewer than that,
    // or an empty real name, is not a usable registration.
    let realname = msg.params.get(3).cloned().unwrap_or_default();
    if msg.params.len() < 4 || realname.is_empty() {
        drop(state_guard);
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec!["*".into(), "USER".into(), "Not enough parameters".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let conn = state_guard.get_or_create_pending(client_id, host);
    conn.user = Some(user);
    conn.realname = Some(realname);

    let should_complete = conn.ready_to_register();
    drop(state_guard);

    if should_complete {
        complete_registration(client_id, state, channels, senders, cfg, label).await?;
    }

    Ok(())
}

pub async fn handle_pass(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _senders: Senders,
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
    senders: &Senders,
    cfg: &Config,
    label: Option<&str>,
    client_id: &str,
) {
    // 422 ERR_NOMOTD if MOTD is empty
    let motd_content: Vec<&str> = cfg
        .server
        .motd
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if motd_content.is_empty() {
        reply_to_client(
            senders,
            client_id,
            Message::new("422", vec![nick.to_string(), "MOTD File is missing".into()])
                .with_prefix(server),
            label,
        )
        .await;
        return;
    }

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
    for line in &motd_content {
        reply_to_client(
            senders,
            client_id,
            Message::new("372", vec![nick.to_string(), format!("- {}", line)]).with_prefix(server),
            label,
        )
        .await;
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
    senders: Senders,
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
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    // PING carries the token to echo back. Without one there is nothing to
    // answer with, so it is an error rather than a PONG naming ourselves.
    let Some(token) = msg.params.first().map(|s| s.as_str()) else {
        let nick = {
            let state_r = state.read().await;
            match state_r.clients.get(client_id) {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            }
        };
        reply_to_client(
            &senders,
            client_id,
            Message::new("409", vec![nick, "No origin specified".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };
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
    _senders: Senders,
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let reason = msg.trailing().unwrap_or("Client quit").to_string();

    let user_id = state.read().await.user_id(client_id);

    // One connection of several going away is not the user leaving: the others
    // are still reading, still in every channel. Only the last one out closes
    // the door.
    let others_remain = state.write().await.detach_session(client_id).await;
    if others_remain {
        tracing::info!(
            client_id,
            user = %user_id,
            "Session closed; the account is still connected elsewhere"
        );
        if let Some(sink) = senders.write().await.remove(client_id) {
            sink.close(
                Message::new("ERROR", vec![format!("Closing link: {}", reason)])
                    .with_prefix(&cfg.server.name),
            );
        }
        state.write().await.forget_session(client_id);
        return Ok(());
    }
    let (source, channel_names, had_account, quit_nick, monitor_list) = {
        let mut state_guard = state.write().await;
        let client = state_guard.clients.get(&user_id).cloned();
        if let Some(client) = client {
            let c = client.read().await;
            let source = c.source().unwrap_or_else(|| c.nick_or_id().to_string());
            let chans: Vec<String> = c.channels.keys().cloned().collect();
            let had_account = c.account.is_some();
            let nick = c.nick.clone().unwrap_or_else(|| user_id.to_string());
            let list = c.monitor_list.clone();
            // Record WHOWAS before the client is removed (use display_host to respect cloaking)
            if let Some(ref pool) = cfg.db {
                if let Some(ref n) = c.nick {
                    persist::save_whowas(
                        pool,
                        n,
                        c.display_user(),
                        c.display_host(),
                        c.realname.as_deref().unwrap_or(""),
                        &cfg.server.name,
                    )
                    .await;
                }
            }
            state_guard.record_whowas(&c, &cfg.server.name);
            (source, chans, had_account, nick, list)
        } else {
            state_guard.forget_session(client_id);
            drop(state_guard);
            // A connection that quits before registering ends the same way:
            // forgetting it is not enough, the socket has to be closed.
            if let Some(sink) = senders.write().await.remove(client_id) {
                sink.close(
                    Message::new("ERROR", vec![format!("Closing link: {}", reason)])
                        .with_prefix(&cfg.server.name),
                );
            }
            return Ok(());
        }
    };

    tracing::info!(client_id, nick = %quit_nick, reason = %reason, channels = channel_names.len(), "Client quit");

    let happened_at = crate::protocol::server_time_now();
    let mut quit_msg = Message::new("QUIT", vec![reason.clone()]).with_prefix(&source);
    quit_msg
        .tags
        .insert("time".to_string(), Some(happened_at.clone()));

    for ch_name in &channel_names {
        let mut ch_store = channels.write().await;
        let mut should_remove = false;
        if let Some(ch_rw) = ch_store.channels.get_mut(ch_name) {
            let mut ch = ch_rw.write().await;
            for (member_id, _) in ch.members.clone().iter() {
                if *member_id != user_id {
                    senders.read().await.deliver(member_id, &quit_msg);
                }
            }
            ch.members.remove(&user_id);
            should_remove = ch.members.is_empty() && !ch.is_registered();
        }
        if should_remove {
            ch_store.channels.remove(ch_name);
        }
        drop(ch_store);

        // Record QUIT event for draft/event-playback (one per channel)
        cfg.record_history_at(ch_name, &source, &reason, None, "QUIT", &happened_at);
    }

    // 901 RPL_LOGGEDOUT: notify the client they are no longer logged in
    if had_account {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "901",
                vec![
                    quit_nick.clone(),
                    source.clone(),
                    "You are now logged out".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
    }

    // account-notify: on logout send ACCOUNT * to channel peers that have the cap
    if had_account {
        let account_star = Message::new("ACCOUNT", vec!["*".into()]).with_prefix(&source);
        crate::link::announce_account(cfg, &state.read().await.user_id(client_id), None).await;
        for ch_name in &channel_names {
            let ch_store = channels.read().await;
            let ch_guard = match ch_store.channels.get(ch_name) {
                Some(ch) => ch,
                None => continue,
            };
            let member_ids: Vec<String> = ch_guard.read().await.members.keys().cloned().collect();
            let _ = ch_guard;
            drop(ch_store);
            for mid in &member_ids {
                send_to_others_requiring(&senders, mid, "account-notify", None, &account_star)
                    .await;
            }
        }
    }

    // monitor: notify clients monitoring this nick that they went offline (731), then clean watchers
    let mut watchers_731: Vec<String> = state
        .read()
        .await
        .monitor_watchers
        .by_nick
        .get(&crate::casefold::lower(&quit_nick))
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();
    // extended-monitor: mask watchers get the offline notification too.
    {
        let state_r = state.read().await;
        for w in state_r
            .monitor_watchers
            .pattern_watchers_for(&crate::casefold::lower(&source))
        {
            if !watchers_731.contains(&w) && w != user_id {
                watchers_731.push(w);
            }
        }
    }
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
        let m = Message::new("731", vec![nick, quit_nick.clone()]).with_prefix(server);
        if !send_to_client(&senders, w, m).await {
            tracing::warn!(watcher_id = %w, nick = %quit_nick, "Monitor: watcher not in senders, 731 not delivered");
        }
    }
    {
        let mut state_w = state.write().await;
        state_w
            .monitor_watchers
            .remove_client(&user_id, &monitor_list);
        state_w
            .monitor_watchers
            .remove_client_patterns(&user_id, &monitor_list);
        state_w.forget_session(client_id);
        state_w.remove_client(&user_id).await;
    }
    // The last connection is gone, so the person is gone from the network, not
    // just from this server.
    crate::link::announce_quit(cfg, &user_id, &reason).await;

    // QUIT ends the connection: send ERROR and close it. Dropping the sink is
    // not enough — the connection task holds a sender of its own, so without
    // the kill signal the socket stays open until it times out.
    senders.write().await.close_user(
        &user_id,
        Message::new("ERROR", vec![format!("Closing link: {}", reason)])
            .with_prefix(&cfg.server.name),
    );
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let mechanism = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    // Naming a mechanism starts an attempt; "+" and base64 payloads continue one.
    let is_mechanism_selection = matches!(mechanism, "PLAIN" | "SCRAM-SHA-256" | "EXTERNAL");

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
            // A failed attempt does not end SASL: "the client MAY retry from the
            // AUTHENTICATE <mechanism> command" (sasl-3.1). Naming a mechanism
            // starts a fresh attempt; anything else after a failure is ignored,
            // so a half-sent response cannot be resumed into a success.
            if conn.sasl_failed && !is_mechanism_selection {
                return Ok(());
            }
        }
    }

    // Naming a mechanism starts a fresh attempt, so nothing the last one left
    // behind belongs to it: a part-received response, the middle of a SCRAM
    // exchange, the fact that it failed. Left in place, the second half of the
    // old attempt answers the first half of the new one — a client retrying
    // SCRAM after a wrong password had its opening message read as a reply to
    // a question it was never asked.
    if is_mechanism_selection {
        let mut sg = state.write().await;
        let conn = sg.get_or_create_pending(client_id, host);
        conn.sasl_failed = false;
        conn.sasl_scram = None;
        conn.sasl_plain_buffer.clear();
        conn.sasl_chunk_count = 0;
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

    // AUTHENTICATE * — abort in-progress SASL (IRCv3: 906 ERR_SASLABORTED)
    if mechanism == "*" {
        let nick = state
            .read()
            .await
            .pending
            .get(client_id)
            .and_then(|c| c.nick.clone())
            .unwrap_or_else(|| "*".to_string());
        {
            let mut sg = state.write().await;
            if let Some(conn) = sg.pending.get_mut(client_id) {
                conn.sasl_mechanism = None;
                conn.sasl_plain_buffer.clear();
                conn.sasl_chunk_count = 0;
                conn.sasl_scram = None;
            }
        }
        tracing::info!(client_id, "SASL: authentication aborted by client");
        reply_to_client(
            &senders,
            client_id,
            Message::new("906", vec![nick, "SASL authentication aborted".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Route SASL EXTERNAL: TLS client certificate authentication
    if mechanism == "EXTERNAL" || stored_mechanism.as_deref() == Some("EXTERNAL") {
        if mechanism == "EXTERNAL" {
            {
                let mut sg = state.write().await;
                if let Some(conn) = sg.pending.get_mut(client_id) {
                    conn.sasl_mechanism = Some("EXTERNAL".to_string());
                }
            }
            // If client sent data inline (authzid), use it; otherwise request with AUTHENTICATE +
            let inline = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
            if inline.is_empty() || inline == "EXTERNAL" {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("AUTHENTICATE", vec!["+".into()]).with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        }
        // Client sent the authzid payload (or "+")
        // Look up certfp for this client
        let certfp = {
            let sg = state.read().await;
            sg.certfps.get(client_id).cloned()
        };
        let certfp = match certfp {
            Some(fp) => fp,
            None => {
                let nick = state
                    .read()
                    .await
                    .pending
                    .get(client_id)
                    .and_then(|c| c.nick.clone())
                    .unwrap_or_else(|| "*".to_string());
                tracing::info!(client_id, "SASL EXTERNAL: no TLS client certificate");
                sasl_fail(
                    state.clone(),
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
        // Look up account by certfp in the database
        let account = if let Some(ref pool) = cfg.db {
            crate::persist::lookup_account_by_certfp(pool, &certfp).await
        } else {
            None
        };
        let account = match account {
            Some(a) => a,
            None => {
                let nick = state
                    .read()
                    .await
                    .pending
                    .get(client_id)
                    .and_then(|c| c.nick.clone())
                    .unwrap_or_else(|| "*".to_string());
                tracing::info!(client_id, certfp = %certfp, "SASL EXTERNAL: no account for certfp");
                sasl_fail(
                    state.clone(),
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
        // Authentication successful
        {
            let mut sg = state.write().await;
            if let Some(conn) = sg.pending.get_mut(client_id) {
                conn.account = Some(account.clone());
                conn.sasl_mechanism = None;
            }
        }
        tracing::info!(client_id, account = %account, "SASL EXTERNAL authentication successful");
        let nick = state
            .read()
            .await
            .pending
            .get(client_id)
            .and_then(|c| c.nick.clone())
            .unwrap_or_else(|| "*".to_string());
        let source = format!(
            "{}!{}@{}",
            &nick,
            state
                .read()
                .await
                .pending
                .get(client_id)
                .and_then(|c| c.user.as_deref())
                .unwrap_or("*"),
            host
        );
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "900",
                vec![
                    nick.clone(),
                    source,
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
            Message::new("903", vec![nick, "SASL authentication successful".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        // Try to complete registration if ready
        {
            let ready = state
                .read()
                .await
                .pending
                .get(client_id)
                .is_some_and(|p| p.ready_to_register());
            if ready {
                complete_registration(client_id, state, channels.clone(), senders, cfg, label)
                    .await?;
            }
        }
        return Ok(());
    }

    // Unknown mechanism (not PLAIN, not SCRAM, not EXTERNAL, not a continuation)
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
        let mechs = if cfg.tls.client_certs && cfg.tls_enabled() {
            "PLAIN,SCRAM-SHA-256,EXTERNAL"
        } else {
            "PLAIN,SCRAM-SHA-256"
        };
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "908",
                vec![
                    nick.clone(),
                    mechs.into(),
                    "are available SASL mechanisms".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        // 908 lists what is on offer; the attempt itself still has to fail, or
        // the client is left waiting for an answer that never comes.
        reply_to_client(
            &senders,
            client_id,
            Message::new("904", vec![nick, "SASL authentication failed".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // SASL messages are sent in chunks of at most 400 bytes; a longer one is a
    // client error the spec answers with 905, not a generic line-length reply.
    if let Some(chunk) = msg.params.first() {
        if chunk.len() > 400 {
            let nick = {
                let state_r = state.read().await;
                match state_r.clients.get(client_id) {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => state_r
                        .pending
                        .get(client_id)
                        .and_then(|p| p.nick.clone())
                        .unwrap_or_else(|| "*".to_string()),
                }
            };
            reply_to_client(
                &senders,
                client_id,
                Message::new("905", vec![nick, "SASL message too long".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
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

    // Bounds the whole base64 response, so a client cannot make the server hold
    // an unbounded buffer by never terminating its AUTHENTICATE sequence.
    // Generous enough for the long passphrases people actually use.
    const MAX_SASL_PLAIN_BUF: usize = 4096;

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
            conn.sasl_failed = false;
            conn.sasl_plain_buffer.clear();
            conn.sasl_chunk_count = 0;
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
                    "SASL AUTHENTICATE: buffer exceeded max length, sending 905"
                );
                // 905 is for one AUTHENTICATE line over 400 bytes. A response
                // that never ends is a failed exchange, not a long line.
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("904", vec![nick, "SASL authentication failed".into()])
                        .with_prefix(&cfg.server.name),
                    label,
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

    // Decode only once the whole payload is in: the client sent AUTHENTICATE +
    // or a chunk shorter than 400 bytes. A full 400-byte chunk means more is
    // coming — and the client sends the rest without waiting, so answering it
    // would put an unexpected AUTHENTICATE + where the client expects the
    // result of the exchange.
    if !is_end {
        tracing::debug!(
            client_id = %client_id,
            buffer_len = to_decode.len(),
            "SASL AUTHENTICATE: full chunk, waiting for the rest"
        );
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
    // A client authenticating after registration has no pending entry, and its
    // nick is what the numerics and the ACCOUNT notification are addressed to.
    let nick: String = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => state_r
                .pending
                .get(client_id)
                .and_then(|c| c.nick.clone())
                .unwrap_or_else(|| "*".to_string()),
        }
    };

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

    // RFC 4616's 255 octets is what a server MUST be capable of accepting, not a
    // maximum it may impose: a longer password is still a valid one. The whole
    // response is bounded by MAX_SASL_PLAIN_BUF above, which is the limit that
    // actually protects the server.

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

    // Checking a password is deliberately slow — a fifth of a second of CPU —
    // and every command in this server is handled by one loop. Waiting here for
    // the answer is waiting on behalf of every other client: one connection
    // offering credentials as fast as it can type would decide when anybody
    // else got served, and the backlog outlives the connection that sent it.
    //
    // So the check goes to a task of its own and this loop moves on. The client
    // hears nothing until the answer arrives, which is what it was waiting for
    // anyway, and `ready_to_register` already holds its registration open while
    // SASL is in flight.
    let wait_first = {
        let mut state_w = state.write().await;
        // One credential at a time. SASL is a conversation, and a client that
        // sends the next answer before hearing the last one is not having it —
        // without this, a connection could start a check per line and leave
        // this server holding all of them at once.
        if state_w
            .pending
            .get(client_id)
            .is_some_and(|conn| conn.sasl_checking())
        {
            tracing::info!(
                client_id = %client_id,
                "SASL AUTHENTICATE: a check for this connection is already running, ignoring"
            );
            return Ok(());
        }
        let wait = state_w.auth_cost.spend(host);
        if let Some(conn) = state_w.pending.get_mut(client_id) {
            // Long enough for the wait and the check, and no longer: if the
            // answer never comes the connection still gets to finish
            // registering rather than hanging on it.
            conn.sasl_check_until =
                Some(std::time::Instant::now() + wait + std::time::Duration::from_secs(15));
        }
        wait
    };
    if !wait_first.is_zero() {
        tracing::warn!(
            client_id = %client_id,
            host = %host,
            wait_ms = wait_first.as_millis() as u64,
            "SASL AUTHENTICATE: this address has been failing, making it wait"
        );
    }
    let owned = (
        client_id.to_string(),
        host.to_string(),
        nick.clone(),
        authzid.to_string(),
        authcid.to_string(),
        passwd.to_string(),
        cfg.clone(),
        label.map(str::to_string),
    );
    let (task_state, task_channels, task_senders) =
        (state.clone(), channels.clone(), senders.clone());
    tokio::spawn(async move {
        if !wait_first.is_zero() {
            tokio::time::sleep(wait_first).await;
        }
        let (
            owned_client_id,
            owned_host,
            nick,
            owned_authzid,
            owned_authcid,
            owned_passwd,
            owned_cfg,
            owned_label,
        ) = owned;
        let client_id: &str = &owned_client_id;
        let host: &str = &owned_host;
        let authzid: &str = &owned_authzid;
        let authcid: &str = &owned_authcid;
        let passwd: &str = &owned_passwd;
        let cfg: &Config = &owned_cfg;
        let label: Option<&str> = owned_label.as_deref();
        let (state, channels, senders) = (task_state, task_channels, task_senders);
        let verified = match cfg.db.as_ref() {
            Some(pool) => persist::verify_user(pool, authcid, passwd).await,
            None => false,
        };
        {
            let mut state_w = state.write().await;
            if verified {
                state_w.auth_cost.refund(host);
            }
            // The answer is here, so the attempt is no longer in flight.
            if let Some(conn) = state_w.pending.get_mut(client_id) {
                conn.sasl_check_until = None;
            }
        }
        if !verified {
            tracing::info!(client_id = %client_id, authcid = %authcid, "SASL AUTHENTICATE: invalid credentials, sending 904");
            sasl_fail(
                state.clone(),
                &senders,
                client_id,
                cfg,
                label,
                &nick,
                "SASL authentication failed",
            )
            .await;
            return finish_registration_if_ready(client_id, state, channels, senders, cfg, label)
                .await;
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

        // Auto-associate TLS certfp with the account for SASL EXTERNAL
        if let Some(ref pool) = cfg.db {
            let certfp = state.read().await.certfps.get(client_id).cloned();
            if let Some(fp) = certfp {
                tracing::info!(client_id = %client_id, account = %account, "Auto-associating certfp with account");
                crate::persist::set_certfp(pool, account, &fp).await;
            }
        }

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
                    // USER has not arrived yet, but 900's second parameter is a
                    // mask; the internal connection id is not one and means
                    // nothing to a client.
                    .unwrap_or_else(|| format!("{}!*@{}", nick, conn.host));
                (Vec::new(), client_id.to_string(), uih)
            } else {
                (Vec::new(), client_id.to_string(), format!("{}!*@*", nick))
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
        let account_msg = Message::new("ACCOUNT", vec![account.to_string()]).with_prefix(&source);
        crate::link::announce_account(cfg, &state.read().await.user_id(client_id), Some(account))
            .await;
        let mut already_notified = std::collections::HashSet::new();
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
                let skip = state.is_self(mid, client_id).then_some(client_id);
                send_to_others_requiring(&senders, mid, "account-notify", skip, &account_msg).await;
                already_notified.insert(mid.clone());
            }
        }
        // extended-monitor: notify monitor watchers with account-notify + extended-monitor
        {
            let state_r = state.read().await;
            notify_extended_monitor_watchers(
                &state_r,
                &senders,
                &nick,
                &source,
                account_msg,
                "account-notify",
                &already_notified,
                client_id,
            )
            .await;
        }
        finish_registration_if_ready(client_id, state, channels, senders, cfg, label).await
    });
    Ok(())
}

/// Finish registering a connection whose last piece has arrived.
///
/// A SASL answer can now come back after the client has said everything else it
/// meant to say, so whoever produces that answer is the last one able to notice
/// that the connection is ready.
async fn finish_registration_if_ready(
    client_id: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let ready = state
        .read()
        .await
        .pending
        .get(client_id)
        .is_some_and(|p| p.ready_to_register());
    if ready {
        complete_registration(client_id, state, channels, senders, cfg, label).await?;
    }
    Ok(())
}

async fn sasl_fail(
    state: Arc<RwLock<ServerState>>,
    senders: &Senders,
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
    senders: Senders,
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

        // Auto-associate TLS certfp with the account for SASL EXTERNAL
        if let Some(ref pool) = cfg.db {
            let certfp = state.read().await.certfps.get(client_id).cloned();
            if let Some(fp) = certfp {
                tracing::info!(client_id, account = %account, "Auto-associating certfp with account");
                crate::persist::set_certfp(pool, &account, &fp).await;
            }
        }

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
        crate::link::announce_account(cfg, &state.read().await.user_id(client_id), Some(&account))
            .await;
        for ch_name in &channel_list {
            let ch_store = channels.read().await;
            if let Some(ch) = ch_store.channels.get(ch_name) {
                let member_ids: Vec<String> = ch.read().await.members.keys().cloned().collect();
                drop(ch_store);
                let sg = state.read().await;
                for mid in &member_ids {
                    let skip = sg.is_self(mid, client_id).then_some(client_id);
                    send_to_others_requiring(&senders, mid, "account-notify", skip, &account_msg)
                        .await;
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let password = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let oper_nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => "*".to_string(),
    };
    if name.is_empty() || password.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec![
                    oper_nick.clone(),
                    "OPER".into(),
                    "Not enough parameters".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    // An operator's password is checked the same expensive way anyone's is, and
    // it is checked on the one loop that serves every client. Flood control
    // holds a single connection to a guess a second, which four connections
    // between them is enough to spend the whole server; so an address that
    // keeps getting it wrong is told no without anything being checked.
    //
    // Unlike SASL this cannot be made to wait instead: an answer that arrives
    // after the replies to whatever the client said next is an answer in the
    // wrong place. A name with no operator block costs nothing and is refused
    // straight away, which is also what stops this being a lever for anyone who
    // does not know one.
    let matched = match cfg.opers.iter().find(|o| o.name == name) {
        Some(oper) => oper,
        None => {
            tracing::warn!(client_id, oper_name = %name, "OPER login failed: no such operator");
            reply_to_client(
                &senders,
                client_id,
                Message::new("464", vec![oper_nick, "Password incorrect".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };
    let oper_host = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.host.clone(),
        None => client_id.to_string(),
    };
    let over_budget = !state.write().await.auth_cost.spend(&oper_host).is_zero();
    if over_budget {
        tracing::warn!(
            client_id,
            oper_name = %name,
            host = %oper_host,
            "OPER: too many failed attempts from this address, not checking"
        );
    }
    if over_budget || !crate::persist::bcrypt_verify(password, &matched.password_hash).await {
        tracing::warn!(client_id, oper_name = %name, "OPER login failed: bad password");
        reply_to_client(
            &senders,
            client_id,
            Message::new("464", vec![oper_nick, "Password incorrect".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    state.write().await.auth_cost.refund(&oper_host);
    let (oper_name, oper_privileges) = (matched.name.clone(), matched.privileges.clone());
    let found = if let Some(c) = state.read().await.clients.get(client_id) {
        let mut g = c.write().await;
        g.oper = true;
        g.oper_name = Some(oper_name.clone());
        g.oper_privileges = oper_privileges;
        true
    } else {
        false
    };
    if !found {
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
    tracing::warn!(client_id, oper_name = %name, "OPER login successful");
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "381",
            vec![oper_nick.clone(), "You are now an IRC operator".into()],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    // Becoming an operator is a user mode change, and clients track their modes
    // from MODE rather than from the numeric.
    reply_to_client(
        &senders,
        client_id,
        Message::new("MODE", vec![oper_nick, "+o".into()]).with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// Log a connection into `account` and apply every side effect a successful
/// authentication implies: set the account (on the registered client, or on the
/// pending connection for clients still negotiating), associate the TLS client
/// certificate fingerprint with the account, send 900 RPL_LOGGEDIN, and announce
/// the change to channel peers with account-notify and to extended-monitor watchers.
///
/// Callers send their own mechanism-specific success reply afterwards (SASL 903,
/// REGISTER SUCCESS, VERIFY SUCCESS).
pub async fn login_client(
    client_id: &str,
    account: &str,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) {
    // Set the account first so a concurrent authentication attempt is a no-op.
    {
        let mut state_w = state.write().await;
        if let Some(client) = state_w.clients.get(client_id) {
            client.write().await.account = Some(account.to_string());
        } else if let Some(conn) = state_w.pending.get_mut(client_id) {
            conn.account = Some(account.to_string());
        }
    }

    // Auto-associate the TLS client certificate fingerprint so SASL EXTERNAL works next time.
    if let Some(ref pool) = cfg.db {
        let certfp = state.read().await.certfps.get(client_id).cloned();
        if let Some(fp) = certfp {
            tracing::info!(client_id, account = %account, "Auto-associating certfp with account");
            crate::persist::set_certfp(pool, account, &fp).await;
        }
    }

    let (nick, source, channel_list) = {
        let state_r = state.read().await;
        if let Some(client) = state_r.clients.get(client_id) {
            let g = client.read().await;
            (
                g.nick_or_id().to_string(),
                g.source().unwrap_or_else(|| client_id.to_string()),
                g.channels.keys().cloned().collect::<Vec<_>>(),
            )
        } else if let Some(conn) = state_r.pending.get(client_id) {
            let nick = conn.nick.clone().unwrap_or_else(|| "*".to_string());
            let source = conn
                .user
                .as_ref()
                .map(|u| format!("{}!{}@{}", nick, u, conn.host))
                .unwrap_or_else(|| nick.clone());
            (nick, source, Vec::new())
        } else {
            ("*".to_string(), client_id.to_string(), Vec::new())
        }
    };

    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "900",
            vec![
                nick.clone(),
                source.clone(),
                account.to_string(),
                format!("You are now logged in as {}", account),
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;

    // account-notify: tell channel peers that have the cap (prefix = user whose account changed)
    let account_msg = Message::new("ACCOUNT", vec![account.to_string()]).with_prefix(&source);
    crate::link::announce_account(cfg, &state.read().await.user_id(client_id), Some(account)).await;
    let mut already_notified = std::collections::HashSet::new();
    for ch_name in &channel_list {
        let member_ids: Vec<String> = {
            let ch_store = channels.read().await;
            match ch_store.channels.get(ch_name) {
                Some(ch) => ch.read().await.members.keys().cloned().collect(),
                None => continue,
            }
        };
        let state_r = state.read().await;
        for mid in &member_ids {
            let skip = state_r.is_self(mid, client_id).then_some(client_id);
            send_to_others_requiring(&senders, mid, "account-notify", skip, &account_msg).await;
            already_notified.insert(mid.clone());
        }
    }

    // extended-monitor: notify watchers that have account-notify + extended-monitor
    let state_r = state.read().await;
    notify_extended_monitor_watchers(
        &state_r,
        &senders,
        &nick,
        &source,
        account_msg,
        "account-notify",
        &already_notified,
        client_id,
    )
    .await;
}

/// REGISTER <account> {<email>|*} <password> — draft/account-registration. Account must be * (current nick).
pub async fn handle_register(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
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
                        "Registration unavailable".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };
    // before-connect: registering mid-handshake is optional, and the capability
    // only advertises it when it is allowed. Refuse it otherwise rather than
    // letting it through unannounced.
    if !cfg.server.register_before_connect && !state.read().await.clients.contains_key(client_id) {
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
                "FAIL",
                vec![
                    "REGISTER".into(),
                    "COMPLETE_CONNECTION_REQUIRED".into(),
                    nick,
                    "Finish connecting before registering an account".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let account = {
        // before-connect: a client may register before it finishes connecting, so
        // read the nick and account from the pending connection in that case.
        let (nick, current_account) = {
            let state_r = state.read().await;
            if let Some(c) = state_r.clients.get(client_id) {
                let g = c.read().await;
                (g.nick.clone().unwrap_or_default(), g.account.clone())
            } else if let Some(conn) = state_r.pending.get(client_id) {
                (conn.nick.clone().unwrap_or_default(), conn.account.clone())
            } else {
                (String::new(), None)
            }
        };
        if nick.is_empty() {
            // The nick they asked for belongs to someone: the account name they
            // would register is taken too.
            let wanted = {
                let state_r = state.read().await;
                state_r
                    .pending
                    .get(client_id)
                    .and_then(|c| c.nick_in_use.clone())
            };
            if let Some(wanted) = wanted {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "REGISTER".into(),
                            "ACCOUNT_EXISTS".into(),
                            wanted,
                            "That nickname is already in use".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "NEED_NICK".into(),
                        "*".into(),
                        "Send NICK first".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        if let Some(acc) = current_account {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REGISTER".into(),
                        "ALREADY_AUTHENTICATED".into(),
                        acc,
                        "Already logged in".into(),
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
        if account_param == "*" || account_param.eq_ignore_ascii_case(&nick) {
            nick
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
                        "Account name must match your current nick".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
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
                    "Password required".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // With [email] configured, registrations are held until VERIFY confirms the
    // address, so an address we can actually mail is required (cap: email-required).
    let verification = match cfg.email {
        Some(ref email_cfg) => {
            let addr = email.unwrap_or("");
            if !crate::mail::is_valid_email(addr) {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "REGISTER".into(),
                            "INVALID_EMAIL".into(),
                            account.clone(),
                            "A valid email address is required to register".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            Some(persist::PendingVerification {
                code: crate::mail::generate_code(),
                expires_at: chrono::Utc::now().timestamp() + email_cfg.code_expiry_secs,
            })
        }
        None => None,
    };

    if cfg.db_health.is_down() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "REGISTER".into(),
                    "TEMPORARILY_UNAVAILABLE".into(),
                    account.clone(),
                    "Registration is temporarily unavailable".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let outcome = persist::register_user(
        pool,
        &account,
        password,
        email,
        verification.as_ref(),
        cfg.limits.min_password_length,
    )
    .await;
    cfg.db_health
        .note(!matches!(outcome, Err(RegisterError::Io(_))));
    match outcome {
        Ok(()) => {
            let Some(pending) = verification else {
                // No verification configured: the spec requires the client to be
                // authenticated as if it had used SASL.
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "REGISTER",
                        vec![
                            "SUCCESS".into(),
                            account.clone(),
                            "Account successfully registered".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                login_client(
                    client_id,
                    &account,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    cfg,
                    label,
                )
                .await;
                tracing::info!(client_id, account = %account, "Account registered and logged in");

                // before-connect: a client that registered mid-handshake can now proceed.
                let ready = state
                    .read()
                    .await
                    .pending
                    .get(client_id)
                    .is_some_and(|p| p.ready_to_register());
                if ready {
                    complete_registration(client_id, state, channels.clone(), senders, cfg, label)
                        .await?;
                }
                return Ok(());
            };

            let email_addr = email.unwrap_or("").to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "REGISTER",
                    vec![
                        "VERIFICATION_REQUIRED".into(),
                        account.clone(),
                        format!("A verification code has been sent to {}", email_addr),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;

            // Mail delivery can block for as long as the SMTP timeout, and every
            // command on this server is handled by one task, so send in the
            // background and tell the client afterwards if it failed.
            let email_cfg = cfg.email.clone().expect("checked above");
            let network = cfg.network.name.clone();
            let server_name = cfg.server.name.clone();
            let pool = pool.clone();
            let senders_bg = senders.clone();
            let client_id_bg = client_id.to_string();
            let account_bg = account.clone();
            tokio::spawn(async move {
                match crate::mail::send_verification(
                    &email_cfg,
                    &network,
                    &email_addr,
                    &account_bg,
                    &pending.code,
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(
                            client_id = %client_id_bg,
                            account = %account_bg,
                            "Verification code sent"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            client_id = %client_id_bg,
                            account = %account_bg,
                            error = %e,
                            "Failed to send verification code; rolling back registration"
                        );
                        persist::delete_account(&pool, &account_bg).await;
                        send_to_client(
                            &senders_bg,
                            &client_id_bg,
                            Message::new(
                                "FAIL",
                                vec![
                                    "REGISTER".into(),
                                    "TEMPORARILY_UNAVAILABLE".into(),
                                    account_bg.clone(),
                                    "Could not send the verification email; please try again"
                                        .into(),
                                ],
                            )
                            .with_prefix(&server_name),
                        )
                        .await;
                    }
                }
            });
            tracing::info!(
                client_id,
                account = %account,
                "Account registered, awaiting email verification"
            );
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
                        "Account already exists".into(),
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
                        "Password too weak".into(),
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
                        "Registration temporarily unavailable".into(),
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

/// `GHOST <nick>` — disconnect a stale session holding a nick you own.
///
/// With registered nicks reserved, the only thing that can be sitting on your
/// nick is one of your own connections that has not timed out yet; this is how
/// you take it back without waiting.
pub async fn handle_ghost(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let (nick, account) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (g.nick_or_id().to_string(), g.account.clone())
            }
            None => return Ok(()),
        }
    };

    let target = msg.params.first().cloned().unwrap_or_default();
    if target.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec!["GHOST".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let Some(account) = account else {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "GHOST".into(),
                    "ACCOUNT_REQUIRED".into(),
                    target,
                    "Log in to the account that owns the nick first".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };

    // Only the account that owns the nick may reclaim it.
    if !target.eq_ignore_ascii_case(&account) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "GHOST".into(),
                    "NOT_YOUR_NICK".into(),
                    target,
                    "That nick belongs to another account".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let ghost_id = state
        .read()
        .await
        .nick_to_id
        .get(&target.to_uppercase())
        .cloned();
    // GHOST disconnects the user holding a nick, and a user is not allowed to
    // ghost itself — which is a comparison of users, not of connections.
    let self_id = state.read().await.user_id(client_id);
    let Some(ghost_id) = ghost_id.filter(|id| **id != self_id) else {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "GHOST".into(),
                    "NO_SUCH_SESSION".into(),
                    target,
                    "Nobody else is using that nick".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };

    // The connections are on the server the session is on, so a session
    // somewhere else has to be closed by the server it is on. Everything that
    // decides whether it may be closed has been checked here and is checked
    // again there, from what that server knows rather than from what this one
    // says.
    let elsewhere = {
        let state_r = state.read().await;
        match state_r.clients.get(&ghost_id) {
            Some(c) => c.read().await.server.is_some(),
            None => false,
        }
    };
    if elsewhere {
        let asked = crate::link::route_to_user(
            cfg,
            &self_id,
            &ghost_id,
            &Message::new("GHOST", vec![String::new()]),
        )
        .await;
        tracing::info!(client_id, %account, ghost = %ghost_id, asked,
                       "GHOST: asking the server holding the session to close it");
        let text = if asked {
            format!("Asked the server holding {} to close that session", target)
        } else {
            format!("There is no way to reach the server holding {}", target)
        };
        reply_to_client(
            &senders,
            client_id,
            Message::new("NOTICE", vec![nick, text]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    tracing::info!(client_id, %account, ghost = %ghost_id, "GHOST: closing stale session");
    senders.write().await.close_user(
        &ghost_id,
        Message::new("ERROR", vec![format!("Closing link: replaced by {}", nick)])
            .with_prefix(&cfg.server.name),
    );
    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTICE",
            vec![nick, format!("Session using {} has been closed", target)],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}

/// Close a session on this server because the account that owns its nick asked,
/// from another server.
///
/// Every condition the asking server checked is checked again here, from what
/// this server knows: that the asker has an account, that the account owns the
/// nick being reclaimed, and that they are not asking to close themselves. A
/// link is trusted to speak for its own users, not to have got the rules right.
pub async fn ghost_for_remote(
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    server_name: &str,
    asker_uid: &str,
    target_uid: &str,
) {
    let asker_account = {
        let state_r = state.read().await;
        match state_r.clients.get(asker_uid) {
            Some(c) => c.read().await.account.clone(),
            None => None,
        }
    };
    let Some(account) = asker_account else {
        tracing::warn!(asker = %asker_uid, "GHOST from a user with no account, refused");
        return;
    };
    if asker_uid == target_uid {
        return;
    }
    let (target_nick, target_is_ours) = {
        let state_r = state.read().await;
        match state_r.clients.get(target_uid) {
            Some(c) => {
                let g = c.read().await;
                (g.nick.clone(), g.server.is_none())
            }
            None => (None, false),
        }
    };
    let Some(target_nick) = target_nick else {
        return;
    };
    if !target_is_ours {
        // Not ours to close. The server that holds it was the one asked.
        return;
    }
    if !target_nick.eq_ignore_ascii_case(&account) {
        tracing::warn!(
            asker = %asker_uid,
            %account,
            target = %target_nick,
            "GHOST for a nick the asking account does not own, refused"
        );
        return;
    }
    tracing::info!(asker = %asker_uid, %account, target = %target_uid,
                   "GHOST: closing a session for another server");
    senders.write().await.close_user(
        target_uid,
        Message::new(
            "ERROR",
            vec![format!("Closing link: replaced by {}", account)],
        )
        .with_prefix(server_name),
    );
}

/// VERIFY {<account>|*} <code> — draft/account-registration. Confirms an account
/// registered while `[email]` verification is enabled, then logs the client in.
pub async fn handle_verify(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    // Current account and nick, from the registered client or the pending connection.
    let (current_account, nick) = {
        let state_r = state.read().await;
        if let Some(c) = state_r.clients.get(client_id) {
            let g = c.read().await;
            (g.account.clone(), g.nick.clone())
        } else if let Some(conn) = state_r.pending.get(client_id) {
            (conn.account.clone(), conn.nick.clone())
        } else {
            (None, None)
        }
    };

    if let Some(acc) = current_account {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "VERIFY".into(),
                    "ALREADY_AUTHENTICATED".into(),
                    acc,
                    "Already logged in".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let account_param = msg.params.first().map(|s| s.as_str()).unwrap_or("*");
    let code = msg
        .params
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("")
        .to_string();

    // "*" means the account named by the current nick.
    let account = if account_param == "*" {
        match nick {
            Some(n) => n,
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "VERIFY".into(),
                            "INVALID_CODE".into(),
                            "*".into(),
                            "Send NICK first".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        }
    } else {
        account_param.to_string()
    };

    let fail = |code_name: &str, text: &str| {
        Message::new(
            "FAIL",
            vec![
                "VERIFY".into(),
                code_name.into(),
                account.clone(),
                text.into(),
            ],
        )
        .with_prefix(&cfg.server.name)
    };

    let pool = match cfg.db.as_ref() {
        Some(p) => p,
        None => {
            reply_to_client(
                &senders,
                client_id,
                fail("TEMPORARILY_UNAVAILABLE", "Verification unavailable"),
                label,
            )
            .await;
            return Ok(());
        }
    };

    if code.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            fail("INVALID_CODE", "Verification code required"),
            label,
        )
        .await;
        return Ok(());
    }

    if cfg.db_health.is_down() {
        reply_to_client(
            &senders,
            client_id,
            fail(
                "TEMPORARILY_UNAVAILABLE",
                "Verification temporarily unavailable",
            ),
            label,
        )
        .await;
        return Ok(());
    }
    let outcome = persist::verify_account(pool, &account, &code).await;
    cfg.db_health
        .note(!matches!(outcome, persist::VerifyOutcome::Io(_)));
    match outcome {
        persist::VerifyOutcome::Verified => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "VERIFY",
                    vec!["SUCCESS".into(), account.clone(), "Account verified".into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            login_client(
                client_id,
                &account,
                state.clone(),
                channels.clone(),
                senders.clone(),
                cfg,
                label,
            )
            .await;
            tracing::info!(client_id, account = %account, "Account verified and logged in");

            // A client that verified during connection registration can now proceed.
            let ready = state
                .read()
                .await
                .pending
                .get(client_id)
                .is_some_and(|p| p.ready_to_register());
            if ready {
                complete_registration(client_id, state, channels.clone(), senders, cfg, label)
                    .await?;
            }
        }
        persist::VerifyOutcome::InvalidCode => {
            tracing::info!(client_id, account = %account, "VERIFY: invalid or expired code");
            reply_to_client(
                &senders,
                client_id,
                fail("INVALID_CODE", "Invalid or expired verification code"),
                label,
            )
            .await;
        }
        persist::VerifyOutcome::AlreadyVerified => {
            reply_to_client(
                &senders,
                client_id,
                fail("INVALID_CODE", "Verification not required or code invalid"),
                label,
            )
            .await;
        }
        persist::VerifyOutcome::Io(e) => {
            tracing::error!(client_id, account = %account, error = %e, "VERIFY: database error");
            reply_to_client(
                &senders,
                client_id,
                fail(
                    "TEMPORARILY_UNAVAILABLE",
                    "Verification temporarily unavailable",
                ),
                label,
            )
            .await;
        }
    }
    Ok(())
}

pub async fn handle_away(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<crate::channel::ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    // AWAYLEN=307 (matches ISUPPORT)
    // "If this command is sent with no parameters, or with the empty string as
    // the parameter, the user is no longer away" — Modern §away-message.
    let away_msg = msg
        .trailing()
        .map(|s| crate::protocol::truncate_bytes(s, 307))
        .filter(|s| !s.is_empty())
        .map(String::from);
    let (source, nick, channel_list) = {
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
        let nick = client_guard.nick_or_id().to_string();
        let channel_list: Vec<String> = client_guard.channels.keys().cloned().collect();
        (source, nick, channel_list)
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
        Message::new(reply_code, vec![nick.clone(), reply_text.into()])
            .with_prefix(&cfg.server.name),
        label,
    )
    .await;

    // away-notify: tell channel peers that have the cap
    let away_message = Message::new(
        "AWAY",
        away_msg
            .as_ref()
            .map(|s| vec![s.clone()])
            .unwrap_or_default(),
    )
    .with_prefix(&source);
    // Whether someone is away is part of who they are, so the whole network is
    // told: a 301 on another server has to be right too.
    {
        let user_id = state.read().await.user_id(client_id);
        crate::link::announce_away(cfg, &user_id, away_msg.as_deref()).await;
    }
    let mut already_notified = std::collections::HashSet::new();
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
            let skip = state.is_self(mid, client_id).then_some(client_id);
            send_to_others_requiring(&senders, mid, "away-notify", skip, &away_message).await;
            already_notified.insert(mid.clone());
        }
    }

    // extended-monitor: notify monitor watchers with away-notify + extended-monitor
    {
        let state_r = state.read().await;
        notify_extended_monitor_watchers(
            &state_r,
            &senders,
            &nick,
            &source,
            away_message,
            "away-notify",
            &already_notified,
            client_id,
        )
        .await;
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let realname = msg.trailing().unwrap_or("").to_string();
    let has_standard_replies = session_caps(&senders, client_id)
        .await
        .contains("standard-replies");

    // An empty realname is as invalid as an over-long one: SETNAME with no
    // parameter must be rejected, not applied.
    if realname.is_empty() || realname.len() > NAMELEN {
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
        } else {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "461",
                    vec!["SETNAME".into(), "Realname is not valid".into()],
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
        tracing::info!(client_id, realname = %realname, "SETNAME");
        if let Some(c) = state.clients.get_mut(client_id) {
            c.write().await.realname = Some(realname.clone());
        }
        (source, channel_list)
    };

    let setname_msg = Message::new("SETNAME", vec![realname.clone()]).with_prefix(&source);
    crate::link::announce_setname(cfg, &state.read().await.user_id(client_id), &realname).await;

    // Send to self if this connection asked for setname
    let self_has_setname = session_caps(&senders, client_id).await.contains("setname");
    let state = state.read().await;
    if self_has_setname {
        reply_to_client(&senders, client_id, setname_msg.clone(), label).await;
    }
    let mut already_notified = std::collections::HashSet::new();
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
            let skip = state.is_self(mid, client_id).then_some(client_id);
            send_to_others_requiring(&senders, mid, "setname", skip, &setname_msg).await;
            already_notified.insert(mid.clone());
        }
    }

    // extended-monitor: notify monitor watchers with setname + extended-monitor
    let nick = match state.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => client_id.to_string(),
    };
    notify_extended_monitor_watchers(
        &state,
        &senders,
        &nick,
        &source,
        setname_msg,
        "setname",
        &already_notified,
        client_id,
    )
    .await;

    Ok(())
}

/// SETHOST newhost — oper only. Sets vhost (display host); notifies channel peers via CHGHOST.
pub async fn handle_sethost(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
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
        if !guard.may(crate::config::OperPrivilege::SetHost) {
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
        tracing::info!(client_id, new_host = %new_host, "SETHOST");
        (old_source, display_user, new_host)
    };
    send_chghost_if_changed(
        state,
        channels,
        senders.clone(),
        cfg,
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
    senders: Senders,
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
        if !guard.may(crate::config::OperPrivilege::SetHost) {
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
        cfg,
        client_id,
        &old_source,
        &new_user,
        &new_host,
    )
    .await;
    Ok(())
}

/// Notify channel peers with `chghost` cap when a client's username or host changes.
/// For clients without the cap, send fallback QUIT/JOIN/MODE messages.
pub async fn send_chghost_if_changed(
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    client_id: &str,
    old_source: &str,
    new_user: &str,
    new_host: &str,
) {
    let (channel_names, nick, new_source) = {
        let state = state.read().await;
        match state.clients.get(client_id) {
            Some(c) => {
                let cg = c.read().await;
                let channels: Vec<String> = cg.channels.keys().cloned().collect();
                let nick = cg.nick.clone().unwrap_or_default();
                let new_src = format!("{}!{}@{}", nick, new_user, new_host);
                (channels, nick, new_src)
            }
            None => return,
        }
    };
    let chghost_msg =
        Message::new("CHGHOST", vec![new_user.into(), new_host.into()]).with_prefix(old_source);
    crate::link::announce_chghost(
        cfg,
        &state.read().await.user_id(client_id),
        new_user,
        new_host,
    )
    .await;
    let quit_msg = Message::new("QUIT", vec!["Changing host".into()]).with_prefix(old_source);
    let mut already_notified = std::collections::HashSet::new();
    let user_id = state.read().await.user_id(client_id);
    for ch_name in channel_names {
        let (member_ids, member_modes) = {
            let ch_store = channels.read().await;
            match ch_store.channels.get(&ch_name) {
                Some(ch) => {
                    let ch = ch.read().await;
                    let ids: Vec<String> = ch.members.keys().cloned().collect();
                    let modes = ch.members.get(&user_id).map(|m| m.modes.clone());
                    (ids, modes)
                }
                None => continue,
            }
        };
        for mid in member_ids {
            let skip = (mid == user_id).then_some(client_id);
            // `chghost` is negotiated by a connection. The ones that asked for
            // it are told in a word; the ones that did not are shown the user
            // leaving and coming back, which is the only way they can see it.
            send_to_others_requiring(&senders, &mid, "chghost", skip, &chghost_msg).await;
            let plain: Vec<String> = senders
                .read()
                .await
                .sessions_with_cap(&mid, "chghost", false)
                .into_iter()
                .filter(|s| Some(s.as_str()) != skip)
                .collect();
            for mid in &plain {
                {
                    send_to_client(&senders, mid, quit_msg.clone()).await;
                    let join_msg =
                        Message::new("JOIN", vec![ch_name.clone()]).with_prefix(&new_source);
                    send_to_client(&senders, mid, join_msg).await;
                    if let Some(ref modes) = member_modes {
                        let mut mode_chars = String::new();
                        let mut mode_args = Vec::new();
                        if modes.op {
                            mode_chars.push('o');
                            mode_args.push(nick.clone());
                        }
                        if modes.halfop {
                            mode_chars.push('h');
                            mode_args.push(nick.clone());
                        }
                        if modes.voice {
                            mode_chars.push('v');
                            mode_args.push(nick.clone());
                        }
                        if !mode_chars.is_empty() {
                            let mut params = vec![ch_name.clone(), format!("+{}", mode_chars)];
                            params.extend(mode_args);
                            let mode_msg = Message::new("MODE", params).with_prefix(&new_source);
                            send_to_client(&senders, mid, mode_msg).await;
                        }
                    }
                }
            }
            already_notified.insert(mid.clone());
        }
    }

    // extended-monitor: notify monitor watchers with chghost + extended-monitor
    {
        let state_r = state.read().await;
        notify_extended_monitor_watchers(
            &state_r,
            &senders,
            &nick,
            old_source,
            chghost_msg,
            "chghost",
            &already_notified,
            client_id,
        )
        .await;
    }
}

/// Send a notification to extended-monitor watchers of a nick.
/// `required_cap` is the capability the watcher needs (e.g. "away-notify", "account-notify").
/// `already_notified` are client IDs already notified via channel membership (to avoid duplicates).
async fn notify_extended_monitor_watchers(
    state: &ServerState,
    senders: &Senders,
    nick: &str,
    source: &str,
    msg: Message,
    required_cap: &str,
    already_notified: &std::collections::HashSet<String>,
    client_id: &str,
) {
    let nick_lower = crate::casefold::lower(nick);
    let source_lower = crate::casefold::lower(source);

    // Collect watchers from both exact nick and pattern matches
    let mut watcher_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(watchers) = state.monitor_watchers.watchers(&nick_lower) {
        watcher_ids.extend(watchers.iter().cloned());
    }
    for wid in state.monitor_watchers.pattern_watchers_for(&source_lower) {
        watcher_ids.insert(wid);
    }

    for wid in &watcher_ids {
        // Skip the user themselves and anyone already notified via channel
        if state.is_self(wid, client_id) || already_notified.contains(wid) {
            continue;
        }
        // Both capabilities on the same connection: a watcher whose other
        // client asked for one of them has not asked for this.
        let registry = senders.read().await;
        for session in registry.sessions_with_cap(wid, "extended-monitor", true) {
            if registry.caps_of(&session).contains(required_cap) {
                if let Some(sink) = registry.get(&session) {
                    sink.send(msg.clone());
                }
            }
        }
    }
}
