use crate::channel::ChannelStore;
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::ServerState;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Parse WHOX type string "%<fields>[,<token>]". Returns (requested_fields, token).
fn parse_whox_type(s: &str) -> (Vec<char>, Option<String>) {
    let s = s.trim_start_matches('%');
    let (fields_str, token) = match s.find(',') {
        Some(i) => (&s[..i], Some(s[i + 1..].to_string())),
        None => (s, None),
    };
    let requested: Vec<char> = fields_str.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let token = token.filter(|t| t.chars().all(|c| c.is_ascii_digit()) && t.len() <= 3);
    (requested, token)
}

/// Build 354 RPL_WHOSPCRPL params for WHOX: nick then requested field values in spec order (t,c,u,i,h,s,n,f,d,l,a,o,r).
fn build_354_params(
    nick: &str,
    requested: &[char],
    token: Option<&str>,
    channel: &str,
    user: &str,
    ip: &str,
    host: &str,
    server: &str,
    nick_target: &str,
    flags: &str,
    hopcount: &str,
    idle: &str,
    account: Option<&str>,
    oplevel: &str,
    realname: &str,
) -> Vec<String> {
    let order = ['t', 'c', 'u', 'i', 'h', 's', 'n', 'f', 'd', 'l', 'a', 'o', 'r'];
    let mut params = vec![nick.to_string()];
    for &f in &order {
        if !requested.contains(&f) {
            continue;
        }
        let val = match f {
            't' => token.unwrap_or("").to_string(),
            'c' => channel.to_string(),
            'u' => user.to_string(),
            'i' => ip.to_string(),
            'h' => host.to_string(),
            's' => server.to_string(),
            'n' => nick_target.to_string(),
            'f' => flags.to_string(),
            'd' => hopcount.to_string(),
            'l' => idle.to_string(),
            'a' => account.unwrap_or("0").to_string(),
            'o' => oplevel.to_string(),
            'r' => realname.to_string(),
            _ => continue,
        };
        if f == 'r' {
            params.push(format!(":{}", val));
        } else {
            params.push(val);
        }
    }
    params
}

pub async fn handle_who(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let whox_type = msg.params.get(1).map(|s| s.as_str());
    let use_whox = whox_type.map(|s| s.starts_with('%')).unwrap_or(false);

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
    let use_multi_prefix = client_caps.contains("multi-prefix");
    let (whox_requested, whox_token) = if use_whox && client_caps.contains("whox") {
        whox_type.map(|s| parse_whox_type(s)).unwrap_or((vec![], None))
    } else {
        (vec![], None)
    };
    let use_whox = use_whox && client_caps.contains("whox") && !whox_requested.is_empty();

    if target.starts_with('#') || target.starts_with('&') {
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(target) {
            let ch = ch.read().await;
            for (mid, memb) in &ch.members {
                if let Some(c) = state.clients.get(mid) {
                    let c = c.read().await;
                    let prefix_str = if use_multi_prefix {
                        memb.modes.prefixes_ordered()
                    } else {
                        memb.modes.prefix().to_string()
                    };
                    let hopcount = "0";
                    let realname = c.realname.as_deref().unwrap_or("");
                    let flags = if c.away_message.is_some() { "G" } else { "H" };
                    let oplevel = if memb.modes.op { "@" } else { "" };

                    if use_whox {
                        let params = build_354_params(
                            &nick,
                            &whox_requested,
                            whox_token.as_deref(),
                            target,
                            c.display_user(),
                            &c.host,
                            c.display_host(),
                            &cfg.server.name,
                            c.nick_or_id(),
                            flags,
                            hopcount,
                            "0",
                            c.account.as_deref(),
                            oplevel,
                            realname,
                        );
                        let msg = Message::new("354", params).with_prefix(&cfg.server.name);
                        reply_to_client(&senders, client_id, msg, label).await;
                    } else {
                        // RPL_WHOREPLY: channel user host server nick flags :hopcount realname
                        let oper_flag = if c.oper { "*" } else { "" };
                        let flags_field = format!("{}{}{}", flags, oper_flag, prefix_str);
                        let msg = Message::new("352", vec![
                            nick.clone(),
                            target.to_string(),
                            c.display_user().to_string(),
                            c.display_host().to_string(),
                            cfg.server.name.clone(),
                            c.nick_or_id().to_string(),
                            flags_field,
                            format!(":{} {}", hopcount, realname),
                        ]).with_prefix(&cfg.server.name);
                        reply_to_client(&senders, client_id, msg, label).await;
                    }
                }
            }
        }
    } else {
        // Determine which clients share a channel with the requester (for invisible filtering)
        let requester_channels: std::collections::HashSet<String> = match state.clients.get(client_id) {
            Some(c) => c.read().await.channels.keys().cloned().collect(),
            None => Default::default(),
        };
        let has_wildcards = target.contains('*') || target.contains('?');
        let target_upper = target.to_uppercase();

        // Collect matching client IDs
        let matching_ids: Vec<String> = if !has_wildcards && target != "*" {
            // Exact nick lookup
            state.nick_to_id.get(&target_upper).cloned().into_iter().collect()
        } else {
            // Glob or wildcard: iterate all clients
            let target_lower = target.to_lowercase();
            state.clients.keys()
                .filter(|id| {
                    if let Some(c) = state.clients.get(*id) {
                        if let Ok(g) = c.try_read() {
                            let match_str = format!(
                                "{}!{}@{}",
                                g.nick_or_id().to_lowercase(),
                                g.display_user().to_lowercase(),
                                g.display_host().to_lowercase()
                            );
                            return crate::user::glob_match(&target_lower, &match_str)
                                || crate::user::glob_match(&target_lower, g.nick_or_id());
                        }
                    }
                    false
                })
                .cloned()
                .collect()
        };

        for target_id in &matching_ids {
            if let Some(c) = state.clients.get(target_id) {
                let c = c.read().await;
                // +i invisible: skip unless requester shares a channel or is the same user
                if c.invisible && target_id != client_id {
                    let shares_channel = c.channels.keys().any(|ch| requester_channels.contains(ch));
                    if !shares_channel {
                        continue;
                    }
                }
                let hopcount = "0";
                let realname = c.realname.as_deref().unwrap_or("");
                let flags = if c.away_message.is_some() { "G" } else { "H" };
                let channel = c.channels.keys().next().map(|s| s.as_str()).unwrap_or("*");

                if use_whox {
                    let params = build_354_params(
                        &nick,
                        &whox_requested,
                        whox_token.as_deref(),
                        channel,
                        c.display_user(),
                        &c.host,
                        c.display_host(),
                        &cfg.server.name,
                        c.nick_or_id(),
                        flags,
                        hopcount,
                        "0",
                        c.account.as_deref(),
                        "",
                        realname,
                    );
                    let msg = Message::new("354", params).with_prefix(&cfg.server.name);
                    reply_to_client(&senders, client_id, msg, label).await;
                } else {
                    let oper_flag = if c.oper { "*" } else { "" };
                    let flags_field = format!("{}{}", flags, oper_flag);
                    let msg = Message::new("352", vec![
                        nick.clone(),
                        "*".to_string(),
                        c.display_user().to_string(),
                        c.display_host().to_string(),
                        cfg.server.name.clone(),
                        c.nick_or_id().to_string(),
                        flags_field,
                        format!(":{} {}", hopcount, realname),
                    ]).with_prefix(&cfg.server.name);
                    reply_to_client(&senders, client_id, msg, label).await;
                }
            }
        }
    }

    let end_msg = Message::new("315", vec![nick, target.into(), "End of /WHO list".into()])
        .with_prefix(&cfg.server.name);
    reply_to_client(&senders, client_id, end_msg, label).await;

    Ok(())
}

pub async fn handle_whois(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    _channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target_nick = msg.params.first().map(|s| s.as_str()).unwrap_or("");

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();

    if target_nick.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("431", vec!["No nickname given".into()]).with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let target_id = state.nick_to_id.get(&target_nick.to_uppercase()).cloned();
    if let Some(tid) = target_id {
        if let Some(c) = state.clients.get(&tid) {
            let c = c.read().await;
            let ch_list: Vec<String> = c.channels.keys().cloned().collect();
            let ch_str = ch_list.join(" ");

            reply_to_client(
                &senders,
                client_id,
                Message::new("311", vec![
                    nick.clone(),
                    target_nick.into(),
                    c.display_user().into(),
                    c.display_host().into(),
                    "*".into(),
                    c.realname.as_deref().unwrap_or("").into(),
                ])
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;

            if !ch_list.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("319", vec![nick.clone(), target_nick.into(), ch_str])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            // 312 RPL_WHOISSERVER
            reply_to_client(
                &senders,
                client_id,
                Message::new("312", vec![nick.clone(), target_nick.into(), cfg.server.name.clone(), "rIRCd server".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            // 317 RPL_WHOISIDLE: seconds idle, signon time
            {
                let idle_secs = chrono::Utc::now().timestamp().saturating_sub(c.last_active);
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("317", vec![nick.clone(), target_nick.into(), idle_secs.to_string(), c.signon_at.to_string(), "seconds idle, signon time".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            // 301 RPL_AWAY if target is away
            if let Some(ref away_msg) = c.away_message {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("301", vec![nick.clone(), target_nick.into(), away_msg.clone()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            if c.bot {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("335", vec![nick.clone(), target_nick.into(), "is a bot".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            if c.oper {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("313", vec![nick.clone(), target_nick.into(), "is an IRC operator".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            // 379 RPL_WHOISMODES — user modes
            {
                let mut modes = String::from("+");
                if c.invisible { modes.push('i'); }
                if c.oper { modes.push('o'); }
                if c.account.is_some() { modes.push('r'); }
                if c.wallops { modes.push('w'); }
                if c.bot { modes.push('B'); }
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("379", vec![nick.clone(), target_nick.into(), format!("is using modes {}", modes)])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
        }
    }

    let end_msg = Message::new("318", vec![nick, target_nick.into(), "End of /WHOIS list".into()])
        .with_prefix(&cfg.server.name);
    reply_to_client(&senders, client_id, end_msg, label).await;

    Ok(())
}

const MONITOR_LIMIT: usize = 100;

/// MONITOR +nicks / -nicks / C / L / S per IRCv3 monitor spec. Sends 730 RPL_MONONLINE, 731 RPL_MONOFFLINE, 732 RPL_MONLIST, 733 RPL_ENDOFMONLIST, 734 ERR_MONLISTFULL.
pub async fn handle_monitor(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let param0 = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    let targets_preview = msg.params.get(1).cloned().or_else(|| msg.trailing().map(String::from)).unwrap_or_default();
    tracing::info!(
        client_id = %client_id,
        op = %param0,
        targets = %targets_preview,
        "MONITOR command received"
    );

    let state_guard = state.read().await;
    let client = match state_guard.clients.get(client_id) {
        Some(c) => c.clone(),
        None => {
            tracing::info!(client_id = %client_id, "MONITOR: client not in state.clients (not registered?), ignoring");
            return Ok(());
        }
    };
    let nick = client.read().await.nick_or_id().to_string();
    let has_cap = client.read().await.has_cap("monitor");
    if !has_cap {
        tracing::info!(client_id = %client_id, nick = %nick, "MONITOR: client does not have 'monitor' capability, ignoring (client must CAP REQ :monitor)");
        return Ok(());
    }
    let targets_str = msg.params.get(1).cloned().or_else(|| msg.trailing().map(String::from));
    let targets: Vec<String> = targets_str
        .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
        .unwrap_or_default();

    drop(state_guard);

    let server = &cfg.server.name;

    match param0 {
        "+" => {
            let has_extended_monitor = client.read().await.has_cap("extended-monitor");
            let mut state_w = state.write().await;
            let client_arc = match state_w.clients.get(client_id) {
                Some(c) => c.clone(),
                None => return Ok(()),
            };
            let mut current_list = client_arc.read().await.monitor_list.clone();
            let mut added_nicks: Vec<String> = Vec::new();
            let mut added_patterns: Vec<String> = Vec::new();
            let mut failed = Vec::new();
            for t in &targets {
                let n = t.to_lowercase();
                if current_list.contains(&n) {
                    continue;
                }
                if current_list.len() >= MONITOR_LIMIT {
                    failed.push(t.clone());
                    continue;
                }
                current_list.insert(n.clone());
                // extended-monitor: targets with '!' or '@' are glob patterns
                if has_extended_monitor && (n.contains('!') || n.contains('@')) {
                    added_patterns.push(n);
                } else {
                    added_nicks.push(n);
                }
            }
            {
                let mut guard = client_arc.write().await;
                guard.monitor_list = current_list;
            }
            for n in &added_nicks {
                state_w.monitor_watchers.add(n.clone(), client_id.to_string());
            }
            for p in &added_patterns {
                state_w.monitor_watchers.add_pattern(p.clone(), client_id.to_string());
            }
            if !failed.is_empty() {
                let fail_msg = Message::new("734", vec![nick.clone(), MONITOR_LIMIT.to_string(), failed.join(","), "Monitor list is full.".to_string()])
                    .with_prefix(server);
                reply_to_client(&senders, client_id, fail_msg, label).await;
            }
            drop(state_w);

            let state_r = state.read().await;
            let mut online_list = Vec::new();
            let mut offline_list = Vec::new();

            // Nick-based online/offline check
            for n in &added_nicks {
                if let Some(id) = state_r.nick_to_id.get(&n.to_uppercase()) {
                    if let Some(c) = state_r.clients.get(id) {
                        let src = c.read().await.source().unwrap_or_else(|| n.clone());
                        online_list.push(src);
                    } else {
                        offline_list.push(n.clone());
                    }
                } else {
                    offline_list.push(n.clone());
                }
            }
            // Pattern-based online check (extended-monitor)
            for pat in &added_patterns {
                let mut matched = false;
                for c in state_r.clients.values() {
                    let g = c.read().await;
                    if let Some(src) = g.source() {
                        if crate::user::glob_match(pat, &src.to_lowercase()) {
                            online_list.push(src);
                            matched = true;
                        }
                    }
                }
                if !matched {
                    offline_list.push(pat.clone());
                }
            }

            if !online_list.is_empty() {
                let m = Message::new("730", vec![nick.clone(), format!(":{}", online_list.join(","))]).with_prefix(server);
                reply_to_client(&senders, client_id, m, label).await;
            }
            if !offline_list.is_empty() {
                let m = Message::new("731", vec![nick.clone(), format!(":{}", offline_list.join(","))]).with_prefix(server);
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        "-" => {
            let mut state_w = state.write().await;
            let client_arc = state_w.clients.get(client_id).cloned();
            if let Some(c) = client_arc {
                let mut guard = c.write().await;
                for t in &targets {
                    let n = t.to_lowercase();
                    if guard.monitor_list.remove(&n) {
                        if n.contains('!') || n.contains('@') {
                            state_w.monitor_watchers.remove_pattern(&n, client_id);
                        } else {
                            state_w.monitor_watchers.remove(&n, client_id);
                        }
                    }
                }
            }
        }
        "C" => {
            let mut state_w = state.write().await;
            let client_arc = state_w.clients.get(client_id).cloned();
            if let Some(c) = client_arc {
                let list = c.write().await.monitor_list.drain().collect::<Vec<_>>();
                for n in &list {
                    if n.contains('!') || n.contains('@') {
                        state_w.monitor_watchers.remove_pattern(n, client_id);
                    } else {
                        state_w.monitor_watchers.remove(n, client_id);
                    }
                }
            }
        }
        "L" => {
            let list: Vec<String> = {
                let state_r = state.read().await;
                match state_r.clients.get(client_id) {
                    Some(c) => {
                        let guard = c.read().await;
                        guard.monitor_list.iter().cloned().collect()
                    }
                    None => Vec::new(),
                }
            };
            for chunk in list.chunks(20) {
                let m = Message::new("732", vec![nick.clone(), format!(":{}", chunk.join(","))]).with_prefix(server);
                reply_to_client(&senders, client_id, m, label).await;
            }
            let m = Message::new("733", vec![nick.clone(), "End of MONITOR list".into()]).with_prefix(server);
            reply_to_client(&senders, client_id, m, label).await;
        }
        "S" => {
            let list: Vec<String> = {
                let state_r = state.read().await;
                match state_r.clients.get(client_id) {
                    Some(c) => {
                        let guard = c.read().await;
                        guard.monitor_list.iter().cloned().collect()
                    }
                    None => Vec::new(),
                }
            };
            let mut online = Vec::new();
            let mut offline = Vec::new();
            for n in &list {
                if n.contains('!') || n.contains('@') {
                    // Pattern-based check
                    let state_r = state.read().await;
                    let mut matched = false;
                    for c in state_r.clients.values() {
                        let g = c.read().await;
                        if let Some(src) = g.source() {
                            if crate::user::glob_match(n, &src.to_lowercase()) {
                                online.push(src);
                                matched = true;
                            }
                        }
                    }
                    if !matched {
                        offline.push(n.clone());
                    }
                } else {
                    // Nick-based check
                    let state_r = state.read().await;
                    let id_opt = state_r.nick_to_id.get(&n.to_uppercase()).cloned();
                    let client_arc = id_opt.and_then(|id| state_r.clients.get(&id).cloned());
                    drop(state_r);
                    match client_arc {
                        Some(c) => {
                            let src = c.read().await.source().unwrap_or_else(|| n.clone());
                            online.push(src);
                        }
                        None => offline.push(n.clone()),
                    }
                }
            }
            if !online.is_empty() {
                let m = Message::new("730", vec![nick.clone(), format!(":{}", online.join(","))]).with_prefix(server);
                reply_to_client(&senders, client_id, m, label).await;
            }
            if !offline.is_empty() {
                let m = Message::new("731", vec![nick.clone(), format!(":{}", offline.join(","))]).with_prefix(server);
                reply_to_client(&senders, client_id, m, label).await;
            }
        }
        _ => {}
    }

    Ok(())
}

/// ISON nick1 [nick2 ...] — check which nicks are currently online (303 RPL_ISON).
pub async fn handle_ison(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state_r = state.read().await;
    let nick = match state_r.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    // Nicks may be space-separated across multiple params or in trailing
    let all: Vec<String> = msg.params.iter()
        .flat_map(|p| p.split_whitespace().map(String::from))
        .collect();

    let mut online: Vec<String> = Vec::new();
    for n in &all {
        if state_r.nick_to_id.contains_key(&n.to_uppercase()) {
            online.push(n.clone());
        }
    }

    let m = Message::new("303", vec![nick, format!(":{}", online.join(" "))]).with_prefix(&cfg.server.name);
    reply_to_client(&senders, client_id, m, label).await;
    Ok(())
}

/// USERHOST nick1 [nick2 ...] — return host info for up to 5 nicks (302 RPL_USERHOST).
pub async fn handle_userhost(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state_r = state.read().await;
    let nick = match state_r.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => return Ok(()),
    };

    let mut results: Vec<String> = Vec::new();
    for target_nick in msg.params.iter().take(5) {
        if let Some(tid) = state_r.nick_to_id.get(&target_nick.to_uppercase()) {
            if let Some(c) = state_r.clients.get(tid) {
                let g = c.read().await;
                let oper_star = if g.oper { "*" } else { "" };
                let away_sign = if g.away_message.is_some() { "-" } else { "+" };
                results.push(format!("{}{}={}{}@{}",
                    g.nick_or_id(), oper_star, away_sign, g.display_user(), g.display_host()));
            }
        }
    }

    let m = Message::new("302", vec![nick, format!(":{}", results.join(" "))]).with_prefix(&cfg.server.name);
    reply_to_client(&senders, client_id, m, label).await;
    Ok(())
}
