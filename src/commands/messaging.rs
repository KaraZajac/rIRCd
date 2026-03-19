use crate::channel::{canonical_channel_key, ChannelStore};
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::persist;
use crate::protocol::{add_tags_for_recipient, generate_msgid, Message};
use crate::user::{PendingClientBatch, PendingMultilineBatch, ServerState};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

async fn send_to_client(
    senders: &Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    msg: Message,
) {
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(msg).await;
    }
}

/// Strip mIRC/IRC color and formatting codes from a message.
/// Removes: \x03[n][,m] (colors), \x02 (bold), \x1d (italic), \x1f (underline),
///          \x1e (strikethrough), \x0f (reset), \x16 (reverse)
fn strip_colors(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\x03' => {
                i += 1;
                // Optional foreground number (1-2 digits)
                if i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                    if i < chars.len() && chars[i].is_ascii_digit() { i += 1; }
                    // Optional ,background
                    if i < chars.len() && chars[i] == ',' {
                        i += 1;
                        if i < chars.len() && chars[i].is_ascii_digit() {
                            i += 1;
                            if i < chars.len() && chars[i].is_ascii_digit() { i += 1; }
                        }
                    }
                }
            }
            '\x02' | '\x0f' | '\x16' | '\x1d' | '\x1e' | '\x1f' => { i += 1; }
            c => { out.push(c); i += 1; }
        }
    }
    out
}

/// Returns true if the text is a CTCP message (starts and ends with \x01).
fn is_ctcp(text: &str) -> bool {
    text.starts_with('\x01')
}

/// Send message to a recipient, adding server-time/msgid/account tags and client-only (+prefix) tags.
async fn send_to_client_with_caps(
    senders: &Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    to_id: &str,
    msg: Message,
    recipient_caps: &std::collections::HashSet<String>,
    sender_account: Option<&str>,
    msgid: Option<&str>,
    client_only_tags: Option<&std::collections::HashMap<String, Option<String>>>,
    client_tag_deny: Option<&[String]>,
) {
    let tagged = add_tags_for_recipient(msg, recipient_caps, sender_account, msgid, client_only_tags, client_tag_deny);
    send_to_client(senders, to_id, tagged).await;
}

pub async fn handle_privmsg(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let text = msg.trailing().unwrap_or("").to_string();

    if target.is_empty() || text.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("411", vec!["No recipient given (PRIVMSG)".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

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
    let sender_data = client.read().await;
    let source = sender_data.source().unwrap_or_else(|| client_id.to_string());
    let sender_account = sender_data.account.clone();
    let echo_message = sender_data.has_cap("echo-message");
    drop(sender_data);
    drop(state_guard);

    // Update last_active for idle tracking (WHOIS 317)
    client.write().await.last_active = chrono::Utc::now().timestamp();

    // draft/message-edit: if the client sends +draft/edit=<original-msgid>, verify ownership
    // before accepting the message. Only the original sender may edit their own message.
    if let Some(Some(edit_msgid)) = msg.tags.get("+draft/edit") {
        let edit_msgid = edit_msgid.clone();
        let is_owner = {
            let state_r = state.read().await;
            state_r.msgid_store.get(&edit_msgid)
                .map(|(_, sid)| sid == client_id)
                .unwrap_or(false)
        };
        if !is_owner {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec![
                    "EDIT".into(),
                    "CANNOT_EDIT".into(),
                    target.to_string(),
                    edit_msgid.clone(),
                    "Message not found or you are not the original sender".into(),
                ])
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    }

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        state_w.record_msgid(msgid.clone(), target.to_string(), client_id.to_string());
    }
    let state_guard = state.read().await;

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;
            if !ch.is_member(client_id) {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("404", vec![target.into(), "Cannot send to channel".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            // +C: block CTCPs (ACTION \x01ACTION...\x01 is also blocked)
            if ch.modes.no_ctcp && is_ctcp(&text) {
                reply_to_client(&senders, client_id,
                    Message::new("404", vec![target.into(), "CTCPs are not allowed in this channel (+C)".into()])
                        .with_prefix(&cfg.server.name), label).await;
                return Ok(());
            }

            // +q: sender is quieted
            if ch.is_quieted(sender_account.as_deref(), &source) {
                reply_to_client(&senders, client_id,
                    Message::new("404", vec![target.into(), "You are quieted in this channel (+q)".into()])
                        .with_prefix(&cfg.server.name), label).await;
                return Ok(());
            }

            // +R: registered users only for speaking
            if ch.modes.registered_only && sender_account.is_none() {
                reply_to_client(&senders, client_id,
                    Message::new("404", vec![target.into(), "You must be registered to speak here (+R)".into()])
                        .with_prefix(&cfg.server.name), label).await;
                return Ok(());
            }

            // +c: strip colors from message text
            let text = if ch.modes.no_colors { strip_colors(&text) } else { text.clone() };
            drop(ch);
            drop(ch_store);

            // Rebuild ch reference and relay
            let ch_store = channels.read().await;
            let ch = match ch_store.channels.get(&ch_key) {
                Some(c) => c.read().await,
                None => return Ok(()),
            };

            let base_msg = Message::new("PRIVMSG", vec![target.into(), text.clone()]).with_prefix(&source);
            for (mid, _) in &ch.members {
                if *mid == client_id {
                    if echo_message {
                        let caps = match state_guard.clients.get(mid) {
                            Some(c) => c.read().await.capabilities.clone(),
                            None => Default::default(),
                        };
                        let tagged = add_tags_for_recipient(base_msg.clone(), &caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref());
                        reply_to_client(&senders, client_id, tagged, label).await;
                    }
                    continue;
                }
                let recipient_caps = match state_guard.clients.get(mid) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                send_to_client_with_caps(&senders, mid, base_msg.clone(), &recipient_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref()).await;
            }
            if let Some(ref pool) = cfg.db {
                let _ = persist::append_channel_history(pool, &ch_key, &source, &text, Some(&msgid)).await;
            }
        } else {
            reply_to_client(
                &senders,
                client_id,
                Message::new("403", vec![target.into(), "No such channel".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
    } else {
        let target_id = state_guard.nick_to_id.get(&target.to_uppercase()).cloned();
        if let Some(tid) = target_id {
            let privmsg = Message::new("PRIVMSG", vec![target.into(), text.clone()]).with_prefix(&source);
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            send_to_client_with_caps(&senders, &tid, privmsg.clone(), &target_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref()).await;
            // 301 RPL_AWAY if target is away
            let target_away = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.away_message.clone(),
                None => None,
            };
            if let Some(away_msg) = target_away {
                let sender_nick = source.split('!').next().unwrap_or("*").to_string();
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("301", vec![sender_nick, target.to_string(), away_msg])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            if echo_message {
                let sender_caps = match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                let tagged = add_tags_for_recipient(privmsg, &sender_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref());
                reply_to_client(&senders, client_id, tagged, label).await;
            }
        } else {
            reply_to_client(
                &senders,
                client_id,
                Message::new("401", vec![target.into(), "No such nick/channel".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
    }

    Ok(())
}

pub async fn handle_notice(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let text = msg.trailing().unwrap_or("").to_string();

    if target.is_empty() || text.is_empty() {
        return Ok(());
    }

    let state_guard = state.read().await;
    let client = match state_guard.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let sender_data = client.read().await;
    let source = sender_data.source().unwrap_or_else(|| client_id.to_string());
    let sender_account = sender_data.account.clone();
    let echo_message = sender_data.has_cap("echo-message");
    drop(sender_data);
    drop(state_guard);

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        state_w.record_msgid(msgid.clone(), target.to_string(), client_id.to_string());
    }
    let state_guard = state.read().await;

    let base_msg = Message::new("NOTICE", vec![target.into(), text.clone()]).with_prefix(&source);

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;
            if ch.is_member(client_id) {
                for (mid, _) in &ch.members {
                    if *mid == client_id {
                        if echo_message {
                            let caps = match state_guard.clients.get(mid) {
                                Some(c) => c.read().await.capabilities.clone(),
                                None => Default::default(),
                            };
                            let tagged = add_tags_for_recipient(base_msg.clone(), &caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref());
                            reply_to_client(&senders, client_id, tagged, label).await;
                        }
                        continue;
                    }
                    let recipient_caps = match state_guard.clients.get(mid) {
                        Some(c) => c.read().await.capabilities.clone(),
                        None => Default::default(),
                    };
                    send_to_client_with_caps(&senders, mid, base_msg.clone(), &recipient_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref()).await;
                }
            }
            if let Some(ref pool) = cfg.db {
                let _ = persist::append_channel_history(pool, &ch_key, &source, &text, Some(&msgid)).await;
            }
        }
    } else {
        let target_id = state_guard.nick_to_id.get(&target.to_uppercase()).cloned();
        if let Some(tid) = target_id {
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            send_to_client_with_caps(&senders, &tid, base_msg.clone(), &target_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref()).await;
            if echo_message {
                let sender_caps = match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                let tagged = add_tags_for_recipient(base_msg, &sender_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref());
                reply_to_client(&senders, client_id, tagged, label).await;
            }
        }
    }

    Ok(())
}

const MULTILINE_MAX_BYTES: usize = 4096;
const MULTILINE_MAX_LINES: usize = 20;

/// Deliver a completed draft/multiline batch: validate, then send as batch to capable clients or as separate lines to others.
pub async fn deliver_multiline_batch(
    client_id: &str,
    batch: PendingMultilineBatch,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    if batch.lines.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["BATCH".into(), "MULTILINE_INVALID".into(), "*".into(), " :Invalid multiline batch with blank lines only".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if batch.lines.len() > MULTILINE_MAX_LINES {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["BATCH".into(), "MULTILINE_MAX_LINES".into(), MULTILINE_MAX_LINES.to_string(), " :Multiline batch max-lines exceeded".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let mut total_bytes = 0usize;
    for (i, (concat, text)) in batch.lines.iter().enumerate() {
        total_bytes += text.len();
        if i > 0 && !concat {
            total_bytes += 1; // \n
        }
    }
    if total_bytes > MULTILINE_MAX_BYTES {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["BATCH".into(), "MULTILINE_MAX_BYTES".into(), MULTILINE_MAX_BYTES.to_string(), " :Multiline batch max-bytes exceeded".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let (source, sender_account, echo_message) = {
        let state_guard = state.read().await;
        let client = match state_guard.clients.get(client_id) {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let g = client.read().await;
        let source = g.source().unwrap_or_else(|| client_id.to_string());
        let account = g.account.clone();
        let echo = g.has_cap("echo-message");
        (source, account, echo)
    };

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        state_w.record_msgid(msgid.clone(), batch.target.clone(), client_id.to_string());
    }

    let state_guard = state.read().await;
    let recipient_ids: Vec<String> = if batch.target.starts_with('#') || batch.target.starts_with('&') {
        let ch_key = canonical_channel_key(&batch.target);
        let ch_store = channels.read().await;
        match ch_store.channels.get(&ch_key) {
            Some(ch) => {
                let ch = ch.read().await;
                if !ch.is_member(client_id) {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("404", vec![batch.target.clone(), "Cannot send to channel".into()])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                    return Ok(());
                }
                ch.members.keys().cloned().collect()
            }
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("403", vec![batch.target.clone(), "No such channel".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        }
    } else {
        match state_guard.nick_to_id.get(&batch.target.to_uppercase()) {
            Some(tid) => vec![tid.clone()],
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("401", vec![batch.target.clone(), "No such nick/channel".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        }
    };

    let batch_start = Message::new(
        "BATCH",
        vec![format!("+{}", batch.ref_tag), "draft/multiline".into(), batch.target.clone()],
    )
    .with_prefix(&cfg.server.name);

    drop(state_guard);

    for mid in &recipient_ids {
        let caps = {
            let state_r = state.read().await;
            let client_arc = state_r.clients.get(mid).cloned();
            drop(state_r);
            match client_arc {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            }
        };
        let has_multiline = caps.contains("draft/multiline");

        if has_multiline {
            send_to_client(&senders, mid, batch_start.clone()).await;
            for (concat, text) in &batch.lines {
                let mut line_msg = Message::new(batch.command.clone(), vec![batch.target.clone(), format!(":{}", text)]).with_prefix(&source);
                line_msg.tags.insert("batch".to_string(), Some(batch.ref_tag.clone()));
                if *concat {
                    line_msg.tags.insert("draft/multiline-concat".to_string(), None);
                }
                let tagged = add_tags_for_recipient(line_msg, &caps, sender_account.as_deref(), Some(&msgid), None, cfg.server.client_tag_deny.as_deref());
                send_to_client(&senders, mid, tagged).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", batch.ref_tag)]).with_prefix(&cfg.server.name);
            send_to_client(&senders, mid, batch_end).await;
        } else {
            for (_, text) in &batch.lines {
                let line_msg = Message::new(batch.command.clone(), vec![batch.target.clone(), format!(":{}", text)]).with_prefix(&source);
                let tagged = add_tags_for_recipient(line_msg, &caps, sender_account.as_deref(), Some(&msgid), None, cfg.server.client_tag_deny.as_deref());
                send_to_client(&senders, mid, tagged).await;
            }
        }
    }

    if echo_message {
        let sender_caps = {
            let state_r = state.read().await;
            let client_arc = state_r.clients.get(client_id).cloned();
            drop(state_r);
            match client_arc {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            }
        };
        let has_multiline = sender_caps.contains("draft/multiline");
        if has_multiline {
            let echo_batch_start = Message::new(
                "BATCH",
                vec![format!("+{}", batch.ref_tag), "draft/multiline".into(), batch.target.clone()],
            )
            .with_prefix(&cfg.server.name);
            reply_to_client(&senders, client_id, echo_batch_start, label).await;
            for (concat, text) in &batch.lines {
                let mut line_msg = Message::new(batch.command.clone(), vec![batch.target.clone(), format!(":{}", text)]).with_prefix(&source);
                line_msg.tags.insert("batch".to_string(), Some(batch.ref_tag.clone()));
                if *concat {
                    line_msg.tags.insert("draft/multiline-concat".to_string(), None);
                }
                let tagged = add_tags_for_recipient(line_msg, &sender_caps, sender_account.as_deref(), Some(&msgid), None, cfg.server.client_tag_deny.as_deref());
                reply_to_client(&senders, client_id, tagged, label).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", batch.ref_tag)]).with_prefix(&cfg.server.name);
            reply_to_client(&senders, client_id, batch_end, label).await;
        } else {
            for (_, text) in &batch.lines {
                let line_msg = Message::new(batch.command.clone(), vec![batch.target.clone(), format!(":{}", text)]).with_prefix(&source);
                let tagged = add_tags_for_recipient(line_msg, &sender_caps, sender_account.as_deref(), Some(&msgid), None, cfg.server.client_tag_deny.as_deref());
                reply_to_client(&senders, client_id, tagged, label).await;
            }
        }
    }

    if let Some(ref pool) = cfg.db {
        if batch.target.starts_with('#') || batch.target.starts_with('&') {
            for (_, text) in &batch.lines {
                let _ = persist::append_channel_history(pool, &batch.target, &source, text, Some(&msgid)).await;
            }
        }
    }

    Ok(())
}

/// TAGMSG: like PRIVMSG but no text; only delivered to clients with message-tags cap.
pub async fn handle_tagmsg(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if target.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("411", vec!["No recipient given (TAGMSG)".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let state_guard = state.read().await;
    let client = match state_guard.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let sender_data = client.read().await;
    let source = sender_data.source().unwrap_or_else(|| client_id.to_string());
    let sender_account = sender_data.account.clone();
    let echo_message = sender_data.has_cap("echo-message");
    drop(sender_data);
    drop(state_guard);

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        state_w.record_msgid(msgid.clone(), target.to_string(), client_id.to_string());
    }
    let state_guard = state.read().await;

    let base_msg = Message::new("TAGMSG", vec![target.into()]).with_prefix(&source);

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;
            if ch.is_member(client_id) {
                for (mid, _) in &ch.members {
                    let caps = match state_guard.clients.get(mid) {
                        Some(c) => c.read().await.capabilities.clone(),
                        None => Default::default(),
                    };
                    if !caps.contains("message-tags") {
                        continue;
                    }
                    if *mid == client_id {
                        if !echo_message {
                            continue;
                        }
                        let tagged = add_tags_for_recipient(base_msg.clone(), &caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref());
                        reply_to_client(&senders, client_id, tagged, label).await;
                        continue;
                    }
                    send_to_client_with_caps(&senders, mid, base_msg.clone(), &caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref()).await;
                }
            }
        }
    } else {
        let target_id = state_guard.nick_to_id.get(&target.to_uppercase()).cloned();
        if let Some(tid) = target_id {
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            if target_caps.contains("message-tags") {
                send_to_client_with_caps(&senders, &tid, base_msg.clone(), &target_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref()).await;
            }
            if echo_message {
                let sender_caps = match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                if sender_caps.contains("message-tags") {
                    let tagged = add_tags_for_recipient(base_msg, &sender_caps, sender_account.as_deref(), Some(&msgid), Some(&msg.tags), cfg.server.client_tag_deny.as_deref());
                    reply_to_client(&senders, client_id, tagged, label).await;
                }
            }
        }
    }

    Ok(())
}

pub async fn handle_redact(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    // Per IRCv3 message-redaction spec: REDACT <target> <msgid> [:<reason>]
    let target_param = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    let msgid = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    // Reason is the trailing param (index 2) if provided.
    let reason = if msg.params.len() > 2 {
        msg.params.get(2).map(|s| s.as_str()).unwrap_or("message redacted")
    } else {
        "message redacted"
    };

    if target_param.is_empty() || msgid.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["REDACT".into(), "NEED_MORE_PARAMS".into(), "Target and message ID required".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Look up the original message to get target and original sender.
    // Use the server-recorded target (not the one the client provided, to prevent spoofing).
    let entry = {
        let state_r = state.read().await;
        state_r.msgid_store.get(msgid).map(|(t, s)| (t.to_string(), s.to_string()))
    };

    let (target, sender_id) = match entry {
        Some(e) => e,
        None => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec!["REDACT".into(), "UNKNOWN_MSGID".into(), "No such message".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };

    let allowed = if client_id == sender_id {
        true
    } else if target.starts_with('#') || target.starts_with('&') {
        // Channel ops may redact others' messages
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        match ch_store.channels.get(&ch_key) {
            Some(ch) => ch.read().await.members.get(client_id).map(|m| m.modes.op).unwrap_or(false),
            None => false,
        }
    } else {
        // DM: only the message target may redact (i.e. the recipient of a DM can remove it from their view)
        let state_r = state.read().await;
        state_r.nick_to_id.get(&target.to_uppercase()).map_or(false, |tid| *tid == client_id)
    };

    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["REDACT".into(), "REDACT_FORBIDDEN".into(), "You may not redact this message".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Remove from the store now that we've authorised the redaction.
    {
        let mut state_w = state.write().await;
        state_w.msgid_store.take(msgid);
    }

    // Get sender's nick!user@host for the relay prefix.
    let source = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => c.read().await.source().unwrap_or_else(|| client_id.to_string()),
            None => client_id.to_string(),
        }
    };

    // Per spec: :<nick!user@host> REDACT <target> <msgid> :<reason>
    let redact_relay = Message::new("REDACT", vec![target.clone(), msgid.to_string(), reason.to_string()])
        .with_prefix(&source);

    // Deliver only to clients that have negotiated the message-redaction capability.
    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let member_ids: Vec<String> = ch.read().await.members.keys().cloned().collect();
            drop(ch_store);
            let state_r = state.read().await;
            for mid in &member_ids {
                let has_cap = match state_r.clients.get(mid) {
                    Some(c) => c.read().await.capabilities.contains("message-redaction"),
                    None => false,
                };
                if has_cap {
                    send_to_client(&senders, mid, redact_relay.clone()).await;
                }
            }
        }
    } else {
        // DM: send to original sender and recipient if they have the cap.
        let state_r = state.read().await;
        let tid_opt = state_r.nick_to_id.get(&target.to_uppercase()).cloned();
        let sender_has_cap = state_r.clients.get(client_id)
            .map(|c| c.try_read().map(|g| g.capabilities.contains("message-redaction")).unwrap_or(false))
            .unwrap_or(false);
        let recipient_has_cap = tid_opt.as_deref().and_then(|tid| state_r.clients.get(tid))
            .map(|c| c.try_read().map(|g| g.capabilities.contains("message-redaction")).unwrap_or(false))
            .unwrap_or(false);
        drop(state_r);

        if sender_has_cap {
            send_to_client(&senders, client_id, redact_relay.clone()).await;
        }
        if let Some(ref tid) = tid_opt {
            if tid != client_id && recipient_has_cap {
                send_to_client(&senders, tid, redact_relay.clone()).await;
            }
        }
    }

    Ok(())
}

const CHATHISTORY_LIMIT: usize = 200;

/// CHATHISTORY: legacy "CHATHISTORY #channel [count]" or spec "CHATHISTORY LATEST #channel * limit".
/// When client has batch+message-tags, wraps reply in BATCH chathistory.
pub async fn handle_chathistory(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let pool = match cfg.db.as_ref() {
        Some(p) => p,
        None => return Ok(()),
    };
    let params = &msg.params;
    let (target, limit) = if params.get(0).map(|s| s.as_str()) == Some("LATEST")
        || params.get(0).map(|s| s.as_str()) == Some("BEFORE")
        || params.get(0).map(|s| s.as_str()) == Some("AFTER")
    {
        let subcommand = params.get(0).map(|s| s.as_str()).unwrap_or("");
        let target = params.get(1).map(|s| s.as_str()).unwrap_or("");
        let _cursor = params.get(2).map(|s| s.as_str()).unwrap_or("*");
        let limit_param = params.get(3).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
        if target.is_empty() {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec!["CHATHISTORY".into(), "INVALID_PARAMS".into(), subcommand.into(), "Insufficient parameters".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        (target, limit_param.min(CHATHISTORY_LIMIT))
    } else {
        let target = params.get(0).map(|s| s.as_str()).unwrap_or("");
        let limit_param = params.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
        (target, limit_param.min(CHATHISTORY_LIMIT))
    };

    if target.is_empty() || (!target.starts_with('#') && !target.starts_with('&')) {
        reply_to_client(
            &senders,
            client_id,
            Message::new("461", vec!["CHATHISTORY".into(), "Channel name required".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let is_member = {
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        match ch_store.channels.get(&ch_key) {
            Some(ch) => ch.read().await.members.contains_key(client_id),
            None => false,
        }
    };
    if !is_member {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["CHATHISTORY".into(), "INVALID_TARGET".into(), "CHATHISTORY".into(), target.into(), "You're not on that channel".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let entries = persist::read_channel_history(pool, target, limit).await;
    let caps = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => c.read().await.capabilities.clone(),
            None => std::collections::HashSet::new(),
        }
    };
    let use_batch = caps.contains("batch") && caps.contains("message-tags");
    let batch_ref = if use_batch {
        Some(crate::protocol::generate_msgid())
    } else {
        None
    };

    if use_batch {
        if let Some(ref ref_id) = batch_ref {
            let batch_start = Message::new("BATCH", vec![format!("+{}", ref_id), "chathistory".into(), target.into()]).with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_start).await;
        }
    }
    for e in entries {
        let mut m = Message::new("PRIVMSG", vec![target.into(), e.text.clone()]);
        m.prefix = Some(e.source.clone());
        m.tags.insert("time".to_string(), Some(e.ts.clone()));
        if let Some(ref id) = e.msgid {
            m.tags.insert("msgid".to_string(), Some(id.clone()));
        }
        if let Some(ref ref_id) = batch_ref {
            m.tags.insert("batch".to_string(), Some(ref_id.clone()));
        }
        let tagged = add_tags_for_recipient(m, &caps, None, e.msgid.as_deref(), None, cfg.server.client_tag_deny.as_deref());
        send_to_client(&senders, client_id, tagged).await;
    }
    if use_batch {
        if let Some(ref ref_id) = batch_ref {
            let batch_end = Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_end).await;
        }
    }

    Ok(())
}

/// MARKREAD target [timestamp] — draft/read-marker. Set or get last read timestamp per target.
pub async fn handle_markread(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    if target.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["MARKREAD".into(), "NEED_MORE_PARAMS".into(), "Missing parameters".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let client_arc = state.read().await.clients.get(client_id).cloned();
    let key = match client_arc {
        Some(c) => c.read().await.account.clone().unwrap_or_else(|| client_id.to_string()),
        None => client_id.to_string(),
    };
    let timestamp_param = msg.params.get(1).map(|s| s.as_str());

    if let Some(ts) = timestamp_param {
        if ts == "*" {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec!["MARKREAD".into(), "INVALID_PARAMS".into(), "timestamp must not be * for set".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        let ts = if ts.starts_with("timestamp=") {
            ts.trim_start_matches("timestamp=").to_string()
        } else {
            ts.to_string()
        };
        let mut state_w = state.write().await;
        let entry = state_w.read_markers.entry(key.clone()).or_default();
        let current = entry.get(target).cloned();
        if current.as_ref().map(|c| c.as_str()) < Some(ts.as_str()) {
            entry.insert(target.to_string(), ts.clone());
        }
        let reply_ts = entry.get(target).cloned().unwrap_or_else(|| ts);
        drop(state_w);
        let m = Message::new("MARKREAD", vec![target.into(), format!("timestamp={}", reply_ts)]).with_prefix(&cfg.server.name);
        reply_to_client(&senders, client_id, m, label).await;
    } else {
        let state_r = state.read().await;
        let ts = state_r
            .read_markers
            .get(&key)
            .and_then(|m| m.get(target))
            .cloned();
        drop(state_r);
        let ts_param = ts.map(|t| format!("timestamp={}", t)).unwrap_or_else(|| "*".to_string());
        let m = Message::new("MARKREAD", vec![target.into(), ts_param]).with_prefix(&cfg.server.name);
        reply_to_client(&senders, client_id, m, label).await;
    }
    Ok(())
}

/// Deliver a draft/client-batch to the target channel or user.
/// Clients with the `batch` cap receive the batch wrapped in BATCH open/close with a server-assigned ref.
/// Clients without the `batch` cap receive each message individually.
pub async fn deliver_client_batch(
    client_id: &str,
    batch: PendingClientBatch,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    if batch.messages.is_empty() {
        return Ok(());
    }

    let (source, sender_account) = {
        let state_r = state.read().await;
        let client = match state_r.clients.get(client_id) {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let g = client.read().await;
        let source = g.source().unwrap_or_else(|| client_id.to_string());
        let account = g.account.clone();
        (source, account)
    };

    let state_r = state.read().await;
    let recipient_ids: Vec<String> = if batch.target.starts_with('#') || batch.target.starts_with('&') {
        let ch_key = canonical_channel_key(&batch.target);
        let ch_store = channels.read().await;
        match ch_store.channels.get(&ch_key) {
            Some(ch) => {
                let ch = ch.read().await;
                if !ch.is_member(client_id) {
                    return Ok(());
                }
                ch.members.keys().cloned().collect()
            }
            None => return Ok(()),
        }
    } else {
        match state_r.nick_to_id.get(&batch.target.to_uppercase()) {
            Some(tid) => vec![tid.clone()],
            None => return Ok(()),
        }
    };
    drop(state_r);

    // Generate a server-side batch ref for each recipient (they can't share the client's ref tag)
    let server_ref = generate_msgid();

    for mid in &recipient_ids {
        let caps = {
            let state_r = state.read().await;
            match state_r.clients.get(mid).cloned() {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            }
        };
        let has_batch = caps.contains("batch") && caps.contains("draft/client-batch");

        if has_batch {
            let batch_start = Message::new(
                "BATCH",
                vec![format!("+{}", server_ref), batch.batch_type.clone(), batch.target.clone()],
            )
            .with_prefix(&source);
            send_to_client(&senders, mid, batch_start).await;
            for mut inner in batch.messages.clone() {
                // Rewrite source prefix and strip the original batch tag
                inner.prefix = Some(source.clone());
                inner.tags.insert("batch".to_string(), Some(server_ref.clone()));
                let tagged = add_tags_for_recipient(inner, &caps, sender_account.as_deref(), None, None, cfg.server.client_tag_deny.as_deref());
                send_to_client(&senders, mid, tagged).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", server_ref)]).with_prefix(&source);
            send_to_client(&senders, mid, batch_end).await;
        } else {
            for mut inner in batch.messages.clone() {
                inner.prefix = Some(source.clone());
                inner.tags.remove("batch");
                let tagged = add_tags_for_recipient(inner, &caps, sender_account.as_deref(), None, None, cfg.server.client_tag_deny.as_deref());
                send_to_client(&senders, mid, tagged).await;
            }
        }
    }

    Ok(())
}
