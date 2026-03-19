use crate::channel::{canonical_channel_key, Channel, ChannelMembership, ChannelMemberModeSet, ChannelStore};
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::{add_batch_tag, generate_msgid, Message};
use crate::user::ServerState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

async fn send_to_client(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    msg: Message,
) {
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(msg).await;
    }
}

pub async fn handle_join(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
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

    let ch_names = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if ch_names.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec!["JOIN".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let client_data = client.read().await;
    let source = client_data.source().unwrap_or_else(|| client_data.nick_or_id().to_string());
    let nick = client_data.nick_or_id().to_string();

    let client_caps = client_data.capabilities.clone();
    let account = client_data.account.clone();
    drop(client_data);

    for ch_name in ch_names.split(',') {
        let ch_name = ch_name.trim();
        if ch_name.is_empty() || !ch_name.starts_with('#'){
            continue;
        }

        // Check per-channel so joining multiple channels in one command can't bypass the limit
        let current_channel_count = match state.clients.get(client_id) {
            Some(c) => c.read().await.channels.len(),
            None => return Ok(()),
        };
        if current_channel_count >= cfg.limits.max_channels_per_client {
            let nick = match state.clients.get(client_id) {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => return Ok(()),
            };
            reply_to_client(
                &senders,
                client_id,
                Message::new("405", vec![nick, ch_name.to_string(), "You have joined too many channels".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            continue;
        }

        let ch_key = canonical_channel_key(ch_name);

        let mut ch_store = channels.write().await;
        let ch = ch_store
            .channels
            .entry(ch_key.clone())
            .or_insert_with(|| RwLock::new(Channel::new(ch_key.clone())));

        let mut ch = ch.write().await;
        if ch.is_member(client_id) {
            continue;
        }

        if ch.is_banned(account.as_deref(), &source) {
            reply_to_client(
                &senders,
                client_id,
                Message::new("474", vec![nick.clone(), ch_name.to_string(), "Cannot join channel (+b)".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            continue;
        }

        if ch.modes.invite_only && !ch.invite_list.contains(&client_id.to_string()) {
            reply_to_client(
                &senders,
                client_id,
                Message::new("473", vec![nick.clone(), ch_name.to_string(), "Cannot join channel (+i)".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            continue;
        }

        if let Some(ref key) = ch.key {
            if msg.params.get(1).as_ref().map(|s| s.as_str()) != Some(key.as_str()) {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("475", vec![nick.clone(), ch_name.to_string(), "Cannot join channel (+k)".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                continue;
            }
        }

        let is_first = ch.members.is_empty();
        let (persisted_op, persisted_voice) = ch.persisted_modes_for(&nick, account.as_deref());
        let mut modes = ChannelMemberModeSet::default();
        modes.op = is_first || persisted_op;
        modes.voice = persisted_voice;
        ch.members.insert(
            client_id.to_string(),
            ChannelMembership {
                client_id: client_id.to_string(),
                modes: modes.clone(),
            },
        );

        if let Some(client) = state.clients.get(client_id) {
            let mut c = client.write().await;
            c.channels.insert(ch_key.clone(), ChannelMembership { client_id: client_id.to_string(), modes });
        }

        let joining_account = match state.clients.get(client_id) {
            Some(c) => c.read().await.account.clone().unwrap_or_else(|| "*".to_string()),
            None => "*".to_string(),
        };
        let joining_realname = match state.clients.get(client_id) {
            Some(c) => c.read().await.realname.clone().unwrap_or_else(|| "*".to_string()),
            None => "*".to_string(),
        };
        let member_ids: Vec<String> = ch.members.keys().cloned().collect();
        let topic = ch.topic.clone();
        drop(ch);
        for mid in &member_ids {
            let caps = match state.clients.get(mid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            let join_msg = if caps.contains("extended-join") {
                Message::new("JOIN", vec![ch_key.clone(), joining_account.clone(), joining_realname.clone()]).with_prefix(&source)
            } else {
                Message::new("JOIN", vec![ch_key.clone()]).with_prefix(&source)
            };
            if let Some(tx) = senders.read().await.get(mid) {
                let _ = tx.send(join_msg).await;
            }
        }

        if let Some(ref topic_str) = topic {
            reply_to_client(
                &senders,
                client_id,
                Message::new("332", vec![nick.clone(), ch_key.clone(), topic_str.clone()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }

        // no-implicit-names: send NAMES to joining user unless they have the cap
        if !client_caps.contains("no-implicit-names") {
            if let Some(ch_ref) = ch_store.channels.get(&ch_key) {
                send_names_for_channel(ch_ref, &ch_key, &nick, &state, &senders, client_id, &cfg.server.name, &client_caps, label).await;
            }
        }
        // draft/read-marker: send MARKREAD for channel (before ENDOFNAMES per spec; we send after NAMES)
        if client_caps.contains("draft/read-marker") {
            let key = account.clone().unwrap_or_else(|| client_id.to_string());
            let ts = state
                .read_markers
                .get(&key)
                .and_then(|m| m.get(&ch_key).cloned())
                .unwrap_or_else(|| "*".to_string());
            let ts_param = if ts == "*" {
                "*".to_string()
            } else {
                format!("timestamp={}", ts)
            };
            let m = Message::new("MARKREAD", vec![ch_key.clone(), ts_param]).with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, m).await;
        }
    }

    Ok(())
}

pub async fn handle_part(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let source = client.read().await.source().unwrap_or_else(|| client_id.to_string());
    let ch_names = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let reason = msg.trailing().unwrap_or("Leaving").to_string();

    for ch_name in ch_names.split(',') {
        let ch_name = ch_name.trim();
        if ch_name.is_empty() || !ch_name.starts_with('#') && !ch_name.starts_with('&') {
            continue;
        }
        let ch_key = canonical_channel_key(ch_name);

        let part_msg = Message::new("PART", vec![ch_name.to_string(), reason.clone()]).with_prefix(&source);

        let mut ch_store = channels.write().await;
        let mut should_remove = false;
        if let Some(ch_rw) = ch_store.channels.get_mut(&ch_key) {
            let mut ch = ch_rw.write().await;
            if !ch.is_member(client_id) {
                // Not in channel — send 442 ERR_NOTONCHANNEL and skip
                let nick = client.read().await.nick_or_id().to_string();
                drop(ch);
                drop(ch_store);
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("442", vec![nick, ch_name.to_string(), "You're not on that channel".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                continue;
            }
            for (mid, _) in &ch.members.clone() {
                if let Some(tx) = senders.read().await.get(mid) {
                    let _ = tx.send(part_msg.clone()).await;
                }
            }
            ch.members.remove(client_id);
            should_remove = ch.members.is_empty();
        }
        if should_remove {
            ch_store.channels.remove(&ch_key);
        }

        if let Some(client) = state.clients.get(client_id) {
            let mut c = client.write().await;
            c.channels.remove(&ch_key);
        }
    }

    Ok(())
}

pub async fn handle_names(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();
    let client_caps = match state.clients.get(client_id) {
        Some(c) => c.read().await.capabilities.clone(),
        None => Default::default(),
    };

    let ch_names: Vec<&str> = msg.params.first().map(|s| s.split(',').collect()).unwrap_or_default();
    let ch_store = channels.read().await;

    if ch_names.is_empty() {
        for (ch_name, ch) in &ch_store.channels {
            send_names_for_channel(&ch, ch_name, &nick, &state, &senders, client_id, &cfg.server.name, &client_caps, label).await;
        }
        return Ok(());
    }

    for ch_name in ch_names {
        let ch_key = canonical_channel_key(ch_name);
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            send_names_for_channel(ch, &ch_key, &nick, &state, &senders, client_id, &cfg.server.name, &client_caps, label).await;
        }
    }

    Ok(())
}

async fn send_names_for_channel(
    ch: &RwLock<Channel>,
    ch_name: &str,
    nick: &str,
    state: &ServerState,
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    server: &str,
    client_caps: &std::collections::HashSet<String>,
    label: Option<&str>,
) {
    let ch = ch.read().await;
    let mut names: Vec<String> = Vec::new();
    let use_userhost = client_caps.contains("userhost-in-names");
    let use_multi_prefix = client_caps.contains("multi-prefix");
    for (mid, memb) in &ch.members {
        if let Some(c) = state.clients.get(mid) {
            let c = c.read().await;
            let prefix_str = if use_multi_prefix {
                memb.modes.prefixes_ordered()
            } else {
                memb.modes.prefix().to_string()
            };
            let entry = if use_userhost {
                format!("{}{}", prefix_str, c.source().unwrap_or_else(|| c.nick_or_id().to_string()))
            } else {
                format!("{}{}", prefix_str, c.nick_or_id())
            };
            names.push(entry);
        }
    }
    let names_str = names.join(" ");
    let use_batch = client_caps.contains("batch") && client_caps.contains("message-tags");

    if use_batch {
        let batch_ref = generate_msgid();
        let batch_start = Message::new("BATCH", vec![format!("+{}", batch_ref), "names".into(), ch_name.into()]).with_prefix(server);
        let batch_end = Message::new("BATCH", vec![format!("-{}", batch_ref)]).with_prefix(server);
        let msg = add_batch_tag(
            Message::new("353", vec![nick.into(), "=".into(), ch_name.into(), names_str]).with_prefix(server),
            &batch_ref,
        );
        let end_msg = add_batch_tag(
            Message::new("366", vec![nick.into(), ch_name.into(), "End of /NAMES list".into()]).with_prefix(server),
            &batch_ref,
        );
        reply_to_client(senders, client_id, batch_start, label).await;
        reply_to_client(senders, client_id, msg, label).await;
        reply_to_client(senders, client_id, end_msg, label).await;
        reply_to_client(senders, client_id, batch_end, label).await;
    } else {
        let msg = Message::new("353", vec![nick.into(), "=".into(), ch_name.into(), names_str]).with_prefix(server);
        reply_to_client(senders, client_id, msg, label).await;
        let end_msg = Message::new("366", vec![nick.into(), ch_name.into(), "End of /NAMES list".into()]).with_prefix(server);
        reply_to_client(senders, client_id, end_msg, label).await;
    }
}

pub async fn handle_list(
    client_id: &str,
    _msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();

    let ch_store = channels.read().await;
    for (ch_name, ch) in &ch_store.channels {
        let ch = ch.read().await;
        let topic = ch.topic.as_deref().unwrap_or("");
        let count = ch.member_count();
        let msg = Message::new("322", vec![nick.clone(), ch_name.clone(), count.to_string(), topic.to_string()])
            .with_prefix(&cfg.server.name);
        reply_to_client(&senders, client_id, msg, label).await;
    }

    let end_msg = Message::new("323", vec![nick, "End of /LIST".into()]).with_prefix(&cfg.server.name);
    reply_to_client(&senders, client_id, end_msg, label).await;

    Ok(())
}

pub async fn handle_mode(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if target.is_empty() {
        return Ok(());
    }

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(target);
        let ch_store = channels.write().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let mut ch = ch.write().await;
            let member = ch.members.get(client_id);
            let is_op = member.map(|m| m.modes.op).unwrap_or(false);

            if msg.params.len() == 1 {
                let mut modes = String::new();
                if ch.modes.secret { modes.push('s'); }
                if ch.modes.private { modes.push('p'); }
                if ch.modes.invite_only { modes.push('i'); }
                if ch.modes.topic_protect { modes.push('t'); }
                if ch.modes.no_external { modes.push('n'); }
                if !ch.bans.is_empty() { modes.push('b'); }
                let mode_str = if modes.is_empty() { "" } else { &modes };
                let msg = Message::new("324", vec![nick.clone(), target.into(), format!("+{}", mode_str), "".to_string()])
                    .with_prefix(&cfg.server.name);
                reply_to_client(&senders, client_id, msg, label).await;
                return Ok(());
            }

            let mode_str = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
            if !is_op {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("482", vec![nick.clone(), target.into(), "You're not channel operator".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            let mut plus = true;
            // param_idx starts at 2: params[0]=target, params[1]=mode_str, params[2+]=mode args
            let mut param_idx: usize = 2;
            for c in mode_str.chars() {
                match c {
                    '+' => plus = true,
                    '-' => plus = false,
                    'i' => ch.modes.invite_only = plus,
                    't' => ch.modes.topic_protect = plus,
                    's' => ch.modes.secret = plus,
                    'p' => ch.modes.private = plus,
                    'n' => ch.modes.no_external = plus,
                    'k' => {
                        if plus {
                            ch.key = msg.params.get(param_idx).cloned();
                        } else {
                            ch.key = None;
                        }
                        param_idx += 1;
                    }
                    'o' => {
                        if let Some(target_nick) = msg.params.get(param_idx) {
                            if let Some(target_id) = state.nick_to_id.get(&target_nick.to_uppercase()) {
                                if let Some(memb) = ch.members.get_mut(target_id) {
                                    memb.modes.op = plus;
                                }
                            }
                            param_idx += 1;
                        }
                    }
                    'b' => {
                        if let Some(mask) = msg.params.get(param_idx) {
                            if plus {
                                if !ch.bans.contains(mask) {
                                    ch.bans.push(mask.clone());
                                }
                            } else {
                                ch.bans.retain(|b| b != mask);
                            }
                            param_idx += 1;
                        }
                    }
                    _ => {}
                }
            }

            let mode_msg = Message::new("MODE", msg.params.clone()).with_prefix(nick.as_str());
            for (mid, _) in &ch.members.clone() {
                if let Some(tx) = senders.read().await.get(mid) {
                    let _ = tx.send(mode_msg.clone()).await;
                }
            }
        }
    } else if target.eq_ignore_ascii_case(&nick) {
        // User mode: MODE <own_nick> +B / -B (bot)
        let mode_str = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
        let mut plus = true;
        for c in mode_str.chars() {
            match c {
                '+' => plus = true,
                '-' => plus = false,
                'B' => {
                    if let Some(client_ref) = state.clients.get(client_id) {
                        client_ref.write().await.bot = plus;
                    }
                    let mode_msg = Message::new("MODE", vec![nick.clone(), format!("{}{}", if plus { "+" } else { "-" }, "B")])
                        .with_prefix(&nick);
                    reply_to_client(&senders, client_id, mode_msg, label).await;
                }
                _ => {}
            }
        }
    }

    Ok(())
}

pub async fn handle_topic(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let ch_name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let new_topic = msg.trailing().map(|s| s.to_string());

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();
    let source = client.read().await.source().unwrap_or_else(|| nick.clone());

    let ch_key = canonical_channel_key(ch_name);
    let mut ch_store = channels.write().await;
    if let Some(ch) = ch_store.channels.get_mut(&ch_key) {
        let mut ch = ch.write().await;
        let is_op = ch.members.get(client_id).map(|m| m.modes.op).unwrap_or(false);

        if new_topic.is_none() {
            if let Some(ref topic) = ch.topic {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("332", vec![nick.clone(), ch_name.into(), topic.clone()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            } else {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("331", vec![nick.clone(), ch_name.into(), "No topic is set".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            return Ok(());
        }

        if ch.modes.topic_protect && !is_op {
            reply_to_client(
                &senders,
                client_id,
                Message::new("482", vec![nick.clone(), ch_name.into(), "You're not channel operator".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        ch.topic = new_topic.clone();
        ch.topic_setter = Some(source.clone());
        ch.topic_time = Some(chrono::Utc::now().timestamp());

        let topic_msg = Message::new(
            "TOPIC",
            vec![ch_name.into(), new_topic.unwrap_or_default()],
        )
        .with_prefix(&source);
        for (mid, _) in &ch.members.clone() {
            if let Some(tx) = senders.read().await.get(mid) {
                let _ = tx.send(topic_msg.clone()).await;
            }
        }
    } else {
        reply_to_client(
            &senders,
            client_id,
            Message::new("403", vec![nick.clone(), ch_name.into(), "No such channel".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
    }

    Ok(())
}

pub async fn handle_kick(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let ch_name = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    let target_nick = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let reason = msg.trailing().unwrap_or("Kicked").to_string();

    if ch_name.is_empty() || target_nick.is_empty() {
        return Ok(());
    }

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let source = client.read().await.source().unwrap_or_else(|| client_id.to_string());

    let target_id = state.nick_to_id.get(&target_nick.to_uppercase()).cloned();

    let ch_key = canonical_channel_key(ch_name);
    let mut ch_store = channels.write().await;
    if let Some(ch) = ch_store.channels.get_mut(&ch_key) {
        let mut ch = ch.write().await;
        let is_op = ch.members.get(client_id).map(|m| m.modes.op).unwrap_or(false);
        if !is_op {
            let nick = client.read().await.nick_or_id().to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new("482", vec![nick, ch_name.into(), "You're not channel operator".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        let mut should_remove_channel = false;
        if let Some(tid) = target_id {
            if ch.members.remove(&tid).is_some() {
                if let Some(target_client) = state.clients.get(&tid) {
                    target_client.write().await.channels.remove(&ch_key);
                }
                let kick_msg = Message::new("KICK", vec![ch_name.into(), target_nick.into(), reason])
                    .with_prefix(&source);
                for (mid, _) in &ch.members.clone() {
                    if let Some(tx) = senders.read().await.get(mid) {
                        let _ = tx.send(kick_msg.clone()).await;
                    }
                }
                if let Some(tx) = senders.read().await.get(&tid) {
                    let _ = tx.send(kick_msg).await;
                }
                should_remove_channel = ch.members.is_empty();
            }
        }
        drop(ch);
        if should_remove_channel {
            ch_store.channels.remove(&ch_key);
        }
    }

    Ok(())
}

pub async fn handle_invite(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target_nick = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    let ch_name = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");

    if target_nick.is_empty() || ch_name.is_empty() {
        return Ok(());
    }

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let source = client.read().await.source().unwrap_or_else(|| client_id.to_string());

    let ch_key = canonical_channel_key(ch_name);
    let mut ch_store = channels.write().await;
    if let Some(ch) = ch_store.channels.get_mut(&ch_key) {
        let mut ch = ch.write().await;
        let is_op = ch.members.get(client_id).map(|m| m.modes.op).unwrap_or(false);
        if !is_op {
            let nick = client.read().await.nick_or_id().to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new("482", vec![nick, ch_name.into(), "You're not channel operator".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        if let Some(target_id) = state.nick_to_id.get(&target_nick.to_uppercase()) {
            ch.invite_list.insert(target_id.clone());
            let invite_msg = Message::new("INVITE", vec![target_nick.into(), ch_name.into()])
                .with_prefix(&source);
            if let Some(tx) = senders.read().await.get(target_id) {
                let _ = tx.send(invite_msg.clone()).await;
            }
            reply_to_client(
                &senders,
                client_id,
                Message::new("341", vec![source.clone(), target_nick.into(), ch_name.into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            // invite-notify: notify other channel members that have the cap (release locks first)
            let notify_member_ids: Vec<String> = ch.members.keys().cloned().collect();
            drop(ch);
            drop(ch_store);
            for mid in &notify_member_ids {
                if *mid == client_id || *mid == *target_id {
                    continue;
                }
                let caps = match state.clients.get(mid) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                if caps.contains("invite-notify") {
                    send_to_client(&senders, mid, invite_msg.clone()).await;
                }
            }
            return Ok(());
        }
    }

    Ok(())
}

/// RENAME old_channel new_channel [reason] — draft/channel-rename. Requester must be in channel and op.
pub async fn handle_rename(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let old_name = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    let new_name = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let reason = msg.trailing().unwrap_or("").to_string();

    if old_name.is_empty() || new_name.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec!["RENAME".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if !old_name.starts_with('#') && !old_name.starts_with('&') {
        return Ok(());
    }
    if !new_name.starts_with('#') && !new_name.starts_with('&') {
        return Ok(());
    }
    // Same prefix type (spec: MAY prevent changing prefix type)
    let old_prefix = old_name.chars().next().unwrap_or(' ');
    let new_prefix = new_name.chars().next().unwrap_or(' ');
    if old_prefix != new_prefix {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["RENAME".into(), "CANNOT_RENAME".into(), old_name.into(), new_name.into(), "You cannot change a channel prefix type".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let state_r = state.read().await;
    let client_arc = state_r.clients.get(client_id).cloned();
    drop(state_r);
    let source = match client_arc.as_ref() {
        Some(c) => c.read().await.source().unwrap_or_else(|| client_id.to_string()),
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
    let nick = match &client_arc {
        Some(c) => Some(c.read().await.nick_or_id().to_string()),
        None => None,
    };

    let old_key = canonical_channel_key(old_name);
    let new_key = canonical_channel_key(new_name);
    let mut ch_store = channels.write().await;
    let ch_ref = match ch_store.channels.get(&old_key) {
        Some(ch) => ch,
        None => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("403", vec![nick.clone().unwrap_or_else(|| "*".into()), old_name.into(), "No such channel".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };
    let (is_member, is_op, member_ids, topic, topic_setter, topic_time) = {
        let ch = ch_ref.read().await;
        let is_member = ch.members.contains_key(client_id);
        let is_op = ch.members.get(client_id).map(|m| m.modes.op).unwrap_or(false);
        let member_ids: Vec<String> = ch.members.keys().cloned().collect();
        (
            is_member,
            is_op,
            member_ids,
            ch.topic.clone(),
            ch.topic_setter.clone(),
            ch.topic_time,
        )
    };

    if !is_member {
        reply_to_client(
            &senders,
            client_id,
            Message::new("442", vec![nick.unwrap_or_else(|| "*".into()), old_name.into(), "You're not on that channel".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if !is_op {
        reply_to_client(
            &senders,
            client_id,
            Message::new("482", vec![nick.unwrap_or_else(|| "*".into()), old_name.into(), "You must be a channel operator".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if ch_store.channels.contains_key(&new_key) && old_key != new_key {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["RENAME".into(), "CHANNEL_NAME_IN_USE".into(), old_name.into(), new_name.into(), "Channel already exists".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let case_only = old_key == new_key;
    let channel = ch_store.channels.remove(&old_key).expect("channel existed");
    let mut ch = channel.write().await;
    ch.name = new_key.clone();
    drop(ch);
    ch_store.channels.insert(new_key.clone(), channel);

    for mid in &member_ids {
        let state_r = state.read().await;
        if let Some(c) = state_r.clients.get(mid) {
            let mut guard = c.write().await;
            if let Some(membership) = guard.channels.remove(&old_key) {
                guard.channels.insert(new_key.clone(), membership);
            }
            drop(guard);
        }
        drop(state_r);
    }

    let rename_msg = Message::new("RENAME", vec![old_name.into(), new_name.into(), format!(":{}", reason)]).with_prefix(&source);
    let mut use_rename_per_client: Vec<(String, bool)> = Vec::new();
    for mid in &member_ids {
        let client_arc = state.read().await.clients.get(mid).cloned();
        let use_rename = match &client_arc {
            Some(c) => c.read().await.has_cap("draft/channel-rename"),
            None => false,
        };
        use_rename_per_client.push((mid.clone(), use_rename || case_only));
    }

    drop(ch_store);

    for (mid, use_rename) in &use_rename_per_client {
        if *use_rename {
            send_to_client(&senders, mid, rename_msg.clone()).await;
        } else {
            send_to_client(&senders, mid, Message::new("PART", vec![old_name.into(), format!(":{}", reason)]).with_prefix(&source)).await;
            send_to_client(&senders, mid, Message::new("JOIN", vec![new_name.into()]).with_prefix(&source)).await;
            let client_arc = state.read().await.clients.get(mid).cloned();
            let recv_nick = match client_arc {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            };
            if let Some(ref t) = topic {
                send_to_client(&senders, mid, Message::new("332", vec![recv_nick.clone(), new_name.into(), t.clone()]).with_prefix(&cfg.server.name)).await;
            }
            if let (Some(ref ts), Some(tt)) = (&topic_setter, topic_time) {
                send_to_client(&senders, mid, Message::new("333", vec![recv_nick.clone(), new_name.into(), ts.clone(), tt.to_string()]).with_prefix(&cfg.server.name)).await;
            }
            let ch_store = channels.read().await;
            if let Some(ch_ref) = ch_store.channels.get(&new_key) {
                let client_arc = state.read().await.clients.get(mid).cloned();
                let caps = match client_arc {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => std::collections::HashSet::new(),
                };
                let state_r = state.read().await;
                send_names_for_channel(ch_ref, &new_key, &recv_nick, &*state_r, &senders, mid, &cfg.server.name, &caps, label).await;
            }
        }
    }

    Ok(())
}
