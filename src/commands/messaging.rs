use crate::channel::{canonical_channel_key, ChannelStore};
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::persist;
use crate::protocol::{add_tags_for_recipient, generate_msgid, Message};
use crate::user::{PendingClientBatch, PendingMultilineBatch, ServerState};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::debug;

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
                    if i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    // Optional ,background
                    if i < chars.len() && chars[i] == ',' {
                        i += 1;
                        if i < chars.len() && chars[i].is_ascii_digit() {
                            i += 1;
                            if i < chars.len() && chars[i].is_ascii_digit() {
                                i += 1;
                            }
                        }
                    }
                }
            }
            '\x02' | '\x0f' | '\x16' | '\x1d' | '\x1e' | '\x1f' => {
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Returns true if the text is a CTCP message (starts and ends with \x01).
fn is_ctcp(text: &str) -> bool {
    text.starts_with('\x01')
}

/// Send message to a recipient, adding server-time/msgid/account tags and client-only (+prefix) tags.
#[allow(clippy::too_many_arguments)]
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
    let tagged = add_tags_for_recipient(
        msg,
        recipient_caps,
        sender_account,
        msgid,
        client_only_tags,
        client_tag_deny,
    );
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
    let source = sender_data
        .source()
        .unwrap_or_else(|| client_id.to_string());
    let sender_nick = sender_data.nick_or_id().to_string();
    let sender_account = sender_data.account.clone();
    let echo_message = sender_data.has_cap("echo-message");
    drop(sender_data);
    drop(state_guard);

    // Update last_active for idle tracking (WHOIS 317)
    client.write().await.last_active = chrono::Utc::now().timestamp();

    // draft/message-edit: if the client sends +draft/edit=<original-msgid>, verify ownership
    // before accepting the message. Only the original sender may edit their own message.
    // Falls back to DB lookup when the in-memory msgid store doesn't have the entry
    // (after server restart or LRU eviction).
    let pending_edit_msgid: Option<String> = msg
        .tags
        .get("+draft/edit")
        .and_then(|v| v.as_ref())
        .cloned();
    if let Some(ref edit_msgid) = pending_edit_msgid {
        // Resolve original sender nick: try in-memory store first, then DB.
        // We compare nicks (not client_ids) because the user may have reconnected
        // on a different connection since sending the original message.
        let in_mem = {
            let state_r = state.read().await;
            state_r
                .msgid_store
                .get(edit_msgid.as_str())
                .map(|(_, sid)| sid.to_string())
        };

        let original_nick: Option<String> = if let Some(ref stored_sender_id) = in_mem {
            // Found in memory — resolve the stored sender's nick
            let c_arc = state.read().await.clients.get(stored_sender_id).cloned();
            if let Some(c) = c_arc {
                c.read().await.nick.clone()
            } else {
                // Stored client_id no longer connected; fall back to DB
                None
            }
        } else {
            None
        };

        // If we couldn't resolve from memory, try DB
        let original_nick = match original_nick {
            Some(n) => Some(n),
            None => match cfg.db {
                Some(ref pool) => persist::lookup_channel_history_by_msgid(pool, edit_msgid)
                    .await
                    .and_then(|(_, db_source)| db_source.split('!').next().map(|s| s.to_string())),
                None => None,
            },
        };

        let is_owner = original_nick
            .as_deref()
            .map(|orig| orig.eq_ignore_ascii_case(&sender_nick))
            .unwrap_or(false);

        if !is_owner {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "EDIT".into(),
                        "CANNOT_EDIT".into(),
                        target.to_string(),
                        edit_msgid.clone(),
                        "Message not found or you are not the original sender".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    }

    // STATUSMSG: @#channel (ops+halfops) or +#channel (voiced+ops+halfops)
    let (statusmsg_prefix, target) = if (target.starts_with('@') || target.starts_with('+'))
        && target.len() > 1
        && (target[1..].starts_with('#') || target[1..].starts_with('&'))
    {
        (Some(target.chars().next().unwrap()), &target[1..])
    } else {
        (None, target)
    };

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        state_w.record_msgid(msgid.clone(), target.to_string(), client_id.to_string());
    }
    // If this is an edit, update the channel history entry in the DB.
    if let Some(ref orig_msgid) = pending_edit_msgid {
        if let Some(ref pool) = cfg.db {
            let rows =
                persist::update_channel_history_message(pool, orig_msgid, &text, &msgid).await;
            tracing::info!(
                client_id,
                orig_msgid,
                new_msgid = %msgid,
                rows_affected = rows,
                "EDIT DB update"
            );
        }
    }
    let state_guard = state.read().await;

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(target);
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
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            target.into(),
                            "CTCPs are not allowed in this channel (+C)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            // +q: sender is quieted
            if ch.is_quieted(sender_account.as_deref(), &source) {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![target.into(), "You are quieted in this channel (+q)".into()],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            // +R: registered users only for speaking
            if ch.modes.registered_only && sender_account.is_none() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            target.into(),
                            "You must be registered to speak here (+R)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            // +c: strip colors from message text
            let text = if ch.modes.no_colors {
                strip_colors(&text)
            } else {
                text.clone()
            };
            drop(ch);
            drop(ch_store);

            // Rebuild ch reference and relay
            let ch_store = channels.read().await;
            let ch = match ch_store.channels.get(&ch_key) {
                Some(c) => c.read().await,
                None => return Ok(()),
            };

            // For STATUSMSG, the target shown to recipients includes the status prefix
            let display_target = if let Some(pfx) = statusmsg_prefix {
                format!("{}{}", pfx, target)
            } else {
                target.to_string()
            };
            let base_msg =
                Message::new("PRIVMSG", vec![display_target, text.clone()]).with_prefix(&source);
            for (mid, memb) in &ch.members {
                // STATUSMSG filter: @ → ops/halfops only; + → voiced/halfop/op only
                if let Some(pfx) = statusmsg_prefix {
                    let passes = match pfx {
                        '@' => memb.modes.op || memb.modes.halfop,
                        '+' => memb.modes.voice || memb.modes.halfop || memb.modes.op,
                        _ => true,
                    };
                    if !passes {
                        continue;
                    }
                }
                if *mid == client_id {
                    if echo_message {
                        let caps = match state_guard.clients.get(mid) {
                            Some(c) => c.read().await.capabilities.clone(),
                            None => Default::default(),
                        };
                        let tagged = add_tags_for_recipient(
                            base_msg.clone(),
                            &caps,
                            sender_account.as_deref(),
                            Some(&msgid),
                            Some(&msg.tags),
                            cfg.server.client_tag_deny.as_deref(),
                        );
                        reply_to_client(&senders, client_id, tagged, label).await;
                    }
                    continue;
                }
                let recipient_caps = match state_guard.clients.get(mid) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                send_to_client_with_caps(
                    &senders,
                    mid,
                    base_msg.clone(),
                    &recipient_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                )
                .await;
            }
            // Only append new history if this is NOT an edit (edits already updated in-place)
            if pending_edit_msgid.is_none() {
                if let Some(ref pool) = cfg.db {
                    let _ = persist::append_channel_history(
                        pool,
                        &ch_key,
                        &source,
                        &text,
                        Some(&msgid),
                        "PRIVMSG",
                    )
                    .await;
                }
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
            let privmsg =
                Message::new("PRIVMSG", vec![target.into(), text.clone()]).with_prefix(&source);
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            send_to_client_with_caps(
                &senders,
                &tid,
                privmsg.clone(),
                &target_caps,
                sender_account.as_deref(),
                Some(&msgid),
                Some(&msg.tags),
                cfg.server.client_tag_deny.as_deref(),
            )
            .await;
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
                let tagged = add_tags_for_recipient(
                    privmsg,
                    &sender_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                );
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
    let raw_target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let text = msg.trailing().unwrap_or("").to_string();

    if raw_target.is_empty() || text.is_empty() {
        return Ok(());
    }

    let state_guard = state.read().await;
    let client = match state_guard.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let sender_data = client.read().await;
    let source = sender_data
        .source()
        .unwrap_or_else(|| client_id.to_string());
    let sender_account = sender_data.account.clone();
    let echo_message = sender_data.has_cap("echo-message");
    drop(sender_data);
    drop(state_guard);

    // STATUSMSG: @#channel (ops+halfops) or +#channel (voiced+ops+halfops)
    let (statusmsg_prefix, target) = if (raw_target.starts_with('@') || raw_target.starts_with('+'))
        && raw_target.len() > 1
        && (raw_target[1..].starts_with('#') || raw_target[1..].starts_with('&'))
    {
        (Some(raw_target.chars().next().unwrap()), &raw_target[1..])
    } else {
        (None, raw_target)
    };

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        state_w.record_msgid(msgid.clone(), target.to_string(), client_id.to_string());
    }
    let state_guard = state.read().await;

    let display_target = if let Some(pfx) = statusmsg_prefix {
        format!("{}{}", pfx, target)
    } else {
        target.to_string()
    };
    let base_msg = Message::new("NOTICE", vec![display_target, text.clone()]).with_prefix(&source);

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;
            if !ch.is_member(client_id) {
                return Ok(());
            }
            // +m: only voiced/op may send
            if ch.modes.moderated
                && !ch
                    .members
                    .get(client_id)
                    .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                    .unwrap_or(false)
            {
                return Ok(()); // NOTICE silently drops per RFC
            }
            // +R: registered-only channel
            if ch.modes.registered_only && sender_account.is_none() {
                return Ok(());
            }
            // +q: sender is quieted
            if ch.is_quieted(sender_account.as_deref(), &source) {
                return Ok(());
            }
            for (mid, memb) in &ch.members {
                // STATUSMSG filter
                if let Some(pfx) = statusmsg_prefix {
                    let passes = match pfx {
                        '@' => memb.modes.op || memb.modes.halfop,
                        '+' => memb.modes.voice || memb.modes.halfop || memb.modes.op,
                        _ => true,
                    };
                    if !passes {
                        continue;
                    }
                }
                if *mid == client_id {
                    if echo_message {
                        let caps = match state_guard.clients.get(mid) {
                            Some(c) => c.read().await.capabilities.clone(),
                            None => Default::default(),
                        };
                        let tagged = add_tags_for_recipient(
                            base_msg.clone(),
                            &caps,
                            sender_account.as_deref(),
                            Some(&msgid),
                            Some(&msg.tags),
                            cfg.server.client_tag_deny.as_deref(),
                        );
                        reply_to_client(&senders, client_id, tagged, label).await;
                    }
                    continue;
                }
                let recipient_caps = match state_guard.clients.get(mid) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                send_to_client_with_caps(
                    &senders,
                    mid,
                    base_msg.clone(),
                    &recipient_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                )
                .await;
            }
            if statusmsg_prefix.is_none() {
                if let Some(ref pool) = cfg.db {
                    let _ = persist::append_channel_history(
                        pool,
                        &ch_key,
                        &source,
                        &text,
                        Some(&msgid),
                        "NOTICE",
                    )
                    .await;
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
            send_to_client_with_caps(
                &senders,
                &tid,
                base_msg.clone(),
                &target_caps,
                sender_account.as_deref(),
                Some(&msgid),
                Some(&msg.tags),
                cfg.server.client_tag_deny.as_deref(),
            )
            .await;
            if echo_message {
                let sender_caps = match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                let tagged = add_tags_for_recipient(
                    base_msg,
                    &sender_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                );
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
            Message::new(
                "FAIL",
                vec![
                    "BATCH".into(),
                    "MULTILINE_INVALID".into(),
                    "*".into(),
                    " :Invalid multiline batch with blank lines only".into(),
                ],
            )
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
            Message::new(
                "FAIL",
                vec![
                    "BATCH".into(),
                    "MULTILINE_MAX_LINES".into(),
                    MULTILINE_MAX_LINES.to_string(),
                    " :Multiline batch max-lines exceeded".into(),
                ],
            )
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
            Message::new(
                "FAIL",
                vec![
                    "BATCH".into(),
                    "MULTILINE_MAX_BYTES".into(),
                    MULTILINE_MAX_BYTES.to_string(),
                    " :Multiline batch max-bytes exceeded".into(),
                ],
            )
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
    let recipient_ids: Vec<String> =
        if batch.target.starts_with('#') || batch.target.starts_with('&') {
            let ch_key = canonical_channel_key(&batch.target);
            let ch_store = channels.read().await;
            match ch_store.channels.get(&ch_key) {
                Some(ch) => {
                    let ch = ch.read().await;
                    if !ch.is_member(client_id) {
                        reply_to_client(
                            &senders,
                            client_id,
                            Message::new(
                                "404",
                                vec![batch.target.clone(), "Cannot send to channel".into()],
                            )
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
                        Message::new(
                            "401",
                            vec![batch.target.clone(), "No such nick/channel".into()],
                        )
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
        vec![
            format!("+{}", batch.ref_tag),
            "draft/multiline".into(),
            batch.target.clone(),
        ],
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
                let mut line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), format!(":{}", text)],
                )
                .with_prefix(&source);
                line_msg
                    .tags
                    .insert("batch".to_string(), Some(batch.ref_tag.clone()));
                if *concat {
                    line_msg
                        .tags
                        .insert("draft/multiline-concat".to_string(), None);
                }
                let tagged = add_tags_for_recipient(
                    line_msg,
                    &caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    None,
                    cfg.server.client_tag_deny.as_deref(),
                );
                send_to_client(&senders, mid, tagged).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", batch.ref_tag)])
                .with_prefix(&cfg.server.name);
            send_to_client(&senders, mid, batch_end).await;
        } else {
            for (_, text) in &batch.lines {
                let line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), format!(":{}", text)],
                )
                .with_prefix(&source);
                let tagged = add_tags_for_recipient(
                    line_msg,
                    &caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    None,
                    cfg.server.client_tag_deny.as_deref(),
                );
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
                vec![
                    format!("+{}", batch.ref_tag),
                    "draft/multiline".into(),
                    batch.target.clone(),
                ],
            )
            .with_prefix(&cfg.server.name);
            reply_to_client(&senders, client_id, echo_batch_start, label).await;
            for (concat, text) in &batch.lines {
                let mut line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), format!(":{}", text)],
                )
                .with_prefix(&source);
                line_msg
                    .tags
                    .insert("batch".to_string(), Some(batch.ref_tag.clone()));
                if *concat {
                    line_msg
                        .tags
                        .insert("draft/multiline-concat".to_string(), None);
                }
                let tagged = add_tags_for_recipient(
                    line_msg,
                    &sender_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    None,
                    cfg.server.client_tag_deny.as_deref(),
                );
                reply_to_client(&senders, client_id, tagged, label).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", batch.ref_tag)])
                .with_prefix(&cfg.server.name);
            reply_to_client(&senders, client_id, batch_end, label).await;
        } else {
            for (_, text) in &batch.lines {
                let line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), format!(":{}", text)],
                )
                .with_prefix(&source);
                let tagged = add_tags_for_recipient(
                    line_msg,
                    &sender_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    None,
                    cfg.server.client_tag_deny.as_deref(),
                );
                reply_to_client(&senders, client_id, tagged, label).await;
            }
        }
    }

    if let Some(ref pool) = cfg.db {
        if batch.target.starts_with('#') || batch.target.starts_with('&') {
            let cmd = if batch.command == "NOTICE" {
                "NOTICE"
            } else {
                "PRIVMSG"
            };
            for (_, text) in &batch.lines {
                let _ = persist::append_channel_history(
                    pool,
                    &batch.target,
                    &source,
                    text,
                    Some(&msgid),
                    cmd,
                )
                .await;
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
    let source = sender_data
        .source()
        .unwrap_or_else(|| client_id.to_string());
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
        let ch_key = canonical_channel_key(target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;
            if ch.is_member(client_id) {
                for mid in ch.members.keys() {
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
                        let tagged = add_tags_for_recipient(
                            base_msg.clone(),
                            &caps,
                            sender_account.as_deref(),
                            Some(&msgid),
                            Some(&msg.tags),
                            cfg.server.client_tag_deny.as_deref(),
                        );
                        reply_to_client(&senders, client_id, tagged, label).await;
                        continue;
                    }
                    send_to_client_with_caps(
                        &senders,
                        mid,
                        base_msg.clone(),
                        &caps,
                        sender_account.as_deref(),
                        Some(&msgid),
                        Some(&msg.tags),
                        cfg.server.client_tag_deny.as_deref(),
                    )
                    .await;
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
                send_to_client_with_caps(
                    &senders,
                    &tid,
                    base_msg.clone(),
                    &target_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                )
                .await;
            }
            if echo_message {
                let sender_caps = match state_guard.clients.get(client_id) {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => Default::default(),
                };
                if sender_caps.contains("message-tags") {
                    let tagged = add_tags_for_recipient(
                        base_msg,
                        &sender_caps,
                        sender_account.as_deref(),
                        Some(&msgid),
                        Some(&msg.tags),
                        cfg.server.client_tag_deny.as_deref(),
                    );
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
    let target_param = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let msgid = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let reason = msg.trailing().unwrap_or("message redacted").to_string();

    tracing::info!(client_id, target_param, msgid, "REDACT received");

    if target_param.is_empty() || msgid.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "REDACT".into(),
                    "NEED_MORE_PARAMS".into(),
                    "Target and message ID required".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Resolve the original message's target and sender nick.
    // Try the in-memory msgid store first (messages sent this session), then fall back to the DB
    // (handles messages sent before a restart — the key fix for cross-restart redaction).
    let in_mem = {
        let state_r = state.read().await;
        state_r
            .msgid_store
            .get(msgid)
            .map(|(t, s)| (t.to_string(), s.to_string()))
    };

    // (target_channel_or_nick, sender_nick_for_auth)
    let (target, sender_nick): (String, Option<String>) = if let Some((t, sender_id)) = in_mem {
        debug!(
            "REDACT: msgid={} found in memory store (target={} sender_id={})",
            msgid, t, sender_id
        );
        let nick = {
            let c_arc = state.read().await.clients.get(&sender_id).cloned();
            if let Some(c) = c_arc {
                c.read().await.nick.clone()
            } else {
                None
            }
        };
        (t, nick)
    } else {
        debug!("REDACT: msgid={} not in memory, querying DB", msgid);
        let db_result = match cfg.db {
            Some(ref pool) => persist::lookup_channel_history_by_msgid(pool, msgid).await,
            None => None,
        };
        match db_result {
            Some((channel, source)) => {
                // source is "nick!user@host"; extract just the nick for auth
                let nick = source.split('!').next().map(|s| s.to_string());
                debug!(
                    "REDACT: msgid={} found in DB (channel={} source={} nick={:?})",
                    msgid, channel, source, nick
                );
                (channel, nick)
            }
            None => {
                debug!("REDACT: msgid={} not found in memory or DB", msgid);
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "REDACT".into(),
                            "UNKNOWN_MSGID".into(),
                            "No such message".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        }
    };

    // Get the current client's nick and oper status for the authorization check
    let (current_nick, is_oper, source) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.nick_or_id().to_string(),
                    g.oper,
                    g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                )
            }
            None => return Ok(()),
        }
    };

    // Authorization: own message (by nick), channel op, or IRC oper
    let is_own = sender_nick
        .as_deref()
        .map(|sn| sn.eq_ignore_ascii_case(&current_nick))
        .unwrap_or(false);

    let is_op = if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(&target);
        let ch_store = channels.read().await;
        match ch_store.channels.get(&ch_key) {
            Some(ch) => ch
                .read()
                .await
                .members
                .get(client_id)
                .map(|m| m.modes.op)
                .unwrap_or(false),
            None => false,
        }
    } else {
        false
    };

    let allowed = is_own || is_op || is_oper;
    tracing::info!(
        client_id, allowed, is_own, is_op, is_oper,
        current_nick = %current_nick, sender_nick = ?sender_nick,
        "REDACT auth check"
    );

    if !allowed {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "REDACT".into(),
                    "REDACT_FORBIDDEN".into(),
                    "You may not redact this message".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Remove from in-memory store
    {
        let mut state_w = state.write().await;
        state_w.msgid_store.take(msgid);
    }

    // Delete from DB
    if let Some(ref pool) = cfg.db {
        let deleted = persist::delete_channel_history_by_msgid(pool, msgid).await;
        tracing::info!(
            client_id,
            msgid,
            rows_affected = deleted,
            "REDACT DB delete"
        );
    }

    // Per spec: :<nick!user@host> REDACT <target> <msgid> :<reason>
    let redact_relay = Message::new("REDACT", vec![target.clone(), msgid.to_string(), reason])
        .with_prefix(&source);

    // Deliver only to clients that have negotiated the message-redaction capability
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
        // DM: send to the redacting client and the other party if they have the cap
        let state_r = state.read().await;
        let tid_opt = state_r.nick_to_id.get(&target.to_uppercase()).cloned();
        let sender_has_cap = state_r
            .clients
            .get(client_id)
            .and_then(|c| c.try_read().ok())
            .map(|g| g.capabilities.contains("message-redaction"))
            .unwrap_or(false);
        let recipient_has_cap = tid_opt
            .as_deref()
            .and_then(|tid| state_r.clients.get(tid))
            .and_then(|c| c.try_read().ok())
            .map(|g| g.capabilities.contains("message-redaction"))
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
    let subcommand = params.first().map(|s| s.to_uppercase()).unwrap_or_default();

    // TARGETS is a special subcommand that returns a list of conversations, not messages.
    if subcommand == "TARGETS" {
        let from_ts = params.get(1).map(|s| s.as_str()).unwrap_or("");
        let to_ts = params.get(2).map(|s| s.as_str()).unwrap_or("");
        let limit = params
            .get(3)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50)
            .min(CHATHISTORY_LIMIT);
        // Strip "timestamp=" prefix if present.
        let from_ts = from_ts.strip_prefix("timestamp=").unwrap_or(from_ts);
        let to_ts = to_ts.strip_prefix("timestamp=").unwrap_or(to_ts);
        if from_ts.is_empty() || to_ts.is_empty() {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "CHATHISTORY".into(),
                        "INVALID_PARAMS".into(),
                        "TARGETS".into(),
                        "Insufficient parameters".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        let targets = persist::list_history_targets(pool, from_ts, to_ts, limit).await;
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
        if let Some(ref ref_id) = batch_ref {
            let batch_start = Message::new(
                "BATCH",
                vec![
                    format!("+{}", ref_id),
                    "chathistory".into(),
                    "targets".into(),
                ],
            )
            .with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_start).await;
        }
        for (chan, latest_ts) in &targets {
            let mut m = Message::new(
                "CHATHISTORY",
                vec![
                    "TARGETS".into(),
                    chan.clone(),
                    format!("timestamp={}", latest_ts),
                ],
            );
            m.prefix = Some(cfg.server.name.clone());
            if let Some(ref ref_id) = batch_ref {
                m.tags.insert("batch".to_string(), Some(ref_id.clone()));
            }
            send_to_client(&senders, client_id, m).await;
        }
        if let Some(ref ref_id) = batch_ref {
            let batch_end =
                Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_end).await;
        }
        return Ok(());
    }

    // Parse target, cursor, and limit for LATEST/BEFORE/AFTER/AROUND/BETWEEN and legacy forms.
    // BETWEEN has two cursors: CHATHISTORY BETWEEN <target> <start> <end> <limit>
    let (target, cursor, cursor2, limit) = if matches!(
        subcommand.as_str(),
        "LATEST" | "BEFORE" | "AFTER" | "AROUND" | "BETWEEN"
    ) {
        let target = params.get(1).map(|s| s.as_str()).unwrap_or("");
        let cursor = params.get(2).map(|s| s.as_str()).unwrap_or("*");
        let (cursor2, limit_param) = if subcommand == "BETWEEN" {
            let c2 = params.get(3).map(|s| s.as_str()).unwrap_or("*");
            let lim = params
                .get(4)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50);
            (Some(c2), lim)
        } else {
            let lim = params
                .get(3)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50);
            (None, lim)
        };
        if target.is_empty() {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "CHATHISTORY".into(),
                        "INVALID_PARAMS".into(),
                        subcommand.as_str().into(),
                        "Insufficient parameters".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        (target, cursor, cursor2, limit_param.min(CHATHISTORY_LIMIT))
    } else {
        // Legacy: CHATHISTORY #channel [count]
        let target = params.first().map(|s| s.as_str()).unwrap_or("");
        let limit_param = params
            .get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);
        (target, "*", None, limit_param.min(CHATHISTORY_LIMIT))
    };

    if target.is_empty() || (!target.starts_with('#') && !target.starts_with('&')) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec!["CHATHISTORY".into(), "Channel name required".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let is_member = {
        let ch_key = canonical_channel_key(target);
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
            Message::new(
                "FAIL",
                vec![
                    "CHATHISTORY".into(),
                    "INVALID_TARGET".into(),
                    "CHATHISTORY".into(),
                    target.into(),
                    "You're not on that channel".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let caps = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => c.read().await.capabilities.clone(),
            None => std::collections::HashSet::new(),
        }
    };
    let include_events = caps.contains("draft/event-playback");

    let entries = match (subcommand.as_str(), cursor) {
        ("AROUND", c) if c != "*" => {
            persist::read_channel_history_around(pool, target, c, limit, include_events).await
        }
        ("BEFORE", c) if c != "*" => {
            persist::read_channel_history_before(pool, target, c, limit, include_events).await
        }
        ("AFTER", c) if c != "*" => {
            persist::read_channel_history_after(pool, target, c, limit, include_events).await
        }
        ("BETWEEN", c) if c != "*" => {
            let end = cursor2.unwrap_or("*");
            if end == "*" {
                persist::read_channel_history(pool, target, limit, include_events).await
            } else {
                persist::read_channel_history_between(pool, target, c, end, limit, include_events)
                    .await
            }
        }
        _ => persist::read_channel_history(pool, target, limit, include_events).await,
    };
    let use_batch = caps.contains("batch") && caps.contains("message-tags");
    let batch_ref = if use_batch {
        Some(crate::protocol::generate_msgid())
    } else {
        None
    };

    if use_batch {
        if let Some(ref ref_id) = batch_ref {
            let batch_start = Message::new(
                "BATCH",
                vec![format!("+{}", ref_id), "chathistory".into(), target.into()],
            )
            .with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_start).await;
        }
    }

    // Capture the time range spanned by the fetched entries so we can query redacted messages.
    let oldest_ts = entries.first().map(|e| e.ts.clone()).unwrap_or_default();
    let newest_ts = entries.last().map(|e| e.ts.clone()).unwrap_or_default();

    for e in &entries {
        // Build the correct IRC message based on the stored command type
        let mut m = match e.command.as_str() {
            "JOIN" => Message::new("JOIN", vec![target.into()]),
            "PART" => {
                let mut params = vec![target.into()];
                if !e.text.is_empty() {
                    params.push(e.text.clone());
                }
                Message::new("PART", params)
            }
            "QUIT" => Message::new("QUIT", vec![e.text.clone()]),
            "TOPIC" => Message::new("TOPIC", vec![target.into(), e.text.clone()]),
            "NICK" => Message::new("NICK", vec![e.text.clone()]),
            "NOTICE" => Message::new("NOTICE", vec![target.into(), e.text.clone()]),
            _ => Message::new("PRIVMSG", vec![target.into(), e.text.clone()]),
        };
        m.prefix = Some(e.source.clone());
        m.tags.insert("time".to_string(), Some(e.ts.clone()));
        if let Some(ref id) = e.msgid {
            m.tags.insert("msgid".to_string(), Some(id.clone()));
        }
        if let Some(ref ref_id) = batch_ref {
            m.tags.insert("batch".to_string(), Some(ref_id.clone()));
        }
        // If this message was edited, include the +draft/edit tag pointing to the original msgid
        if let Some(ref orig_id) = e.original_msgid {
            if caps.contains("draft/message-edit") {
                m.tags
                    .insert("+draft/edit".to_string(), Some(orig_id.clone()));
            }
        }
        let tagged = add_tags_for_recipient(
            m,
            &caps,
            None,
            e.msgid.as_deref(),
            None,
            cfg.server.client_tag_deny.as_deref(),
        );
        send_to_client(&senders, client_id, tagged).await;
    }

    // If the client supports message-redaction, include REDACT events for any messages
    // that were soft-deleted within the returned time range, so the client can update
    // its local buffer on reconnect.
    if !entries.is_empty() && caps.contains("message-redaction") {
        let redacted = persist::read_redacted_in_range(pool, target, &oldest_ts, &newest_ts).await;
        for (msgid, source) in redacted {
            let mut redact_msg = Message::new(
                "REDACT",
                vec![target.to_string(), msgid.clone(), "Message redacted".into()],
            )
            .with_prefix(&source);
            if let Some(ref ref_id) = batch_ref {
                redact_msg
                    .tags
                    .insert("batch".to_string(), Some(ref_id.clone()));
            }
            send_to_client(&senders, client_id, redact_msg).await;
        }
    }

    if use_batch {
        if let Some(ref ref_id) = batch_ref {
            let batch_end =
                Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(&cfg.server.name);
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
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if target.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "MARKREAD".into(),
                    "NEED_MORE_PARAMS".into(),
                    "Missing parameters".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    let client_arc = state.read().await.clients.get(client_id).cloned();
    let key = match client_arc {
        Some(c) => c
            .read()
            .await
            .account
            .clone()
            .unwrap_or_else(|| client_id.to_string()),
        None => client_id.to_string(),
    };
    let timestamp_param = msg.params.get(1).map(|s| s.as_str());

    if let Some(ts) = timestamp_param {
        if ts == "*" {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "MARKREAD".into(),
                        "INVALID_PARAMS".into(),
                        "timestamp must not be * for set".into(),
                    ],
                )
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
        let updated_ts = {
            let mut state_w = state.write().await;
            let entry = state_w.read_markers.entry(key.clone()).or_default();
            let current = entry.get(target).cloned();
            if current.as_deref() < Some(ts.as_str()) {
                entry.insert(target.to_string(), ts.clone());
            }
            entry.get(target).cloned().unwrap_or(ts)
        };
        // Persist to database
        if let Some(ref pool) = cfg.db {
            persist::save_read_marker(pool, &key, target, &updated_ts).await;
        }
        let m = Message::new(
            "MARKREAD",
            vec![target.into(), format!("timestamp={}", updated_ts)],
        )
        .with_prefix(&cfg.server.name);
        reply_to_client(&senders, client_id, m, label).await;
    } else {
        let state_r = state.read().await;
        let ts = state_r
            .read_markers
            .get(&key)
            .and_then(|m| m.get(target))
            .cloned();
        drop(state_r);
        let ts_param = ts
            .map(|t| format!("timestamp={}", t))
            .unwrap_or_else(|| "*".to_string());
        let m =
            Message::new("MARKREAD", vec![target.into(), ts_param]).with_prefix(&cfg.server.name);
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
    let recipient_ids: Vec<String> =
        if batch.target.starts_with('#') || batch.target.starts_with('&') {
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
                vec![
                    format!("+{}", server_ref),
                    batch.batch_type.clone(),
                    batch.target.clone(),
                ],
            )
            .with_prefix(&source);
            send_to_client(&senders, mid, batch_start).await;
            for mut inner in batch.messages.clone() {
                // Rewrite source prefix and strip the original batch tag
                inner.prefix = Some(source.clone());
                inner
                    .tags
                    .insert("batch".to_string(), Some(server_ref.clone()));
                let tagged = add_tags_for_recipient(
                    inner,
                    &caps,
                    sender_account.as_deref(),
                    None,
                    None,
                    cfg.server.client_tag_deny.as_deref(),
                );
                send_to_client(&senders, mid, tagged).await;
            }
            let batch_end =
                Message::new("BATCH", vec![format!("-{}", server_ref)]).with_prefix(&source);
            send_to_client(&senders, mid, batch_end).await;
        } else {
            for mut inner in batch.messages.clone() {
                inner.prefix = Some(source.clone());
                inner.tags.remove("batch");
                let tagged = add_tags_for_recipient(
                    inner,
                    &caps,
                    sender_account.as_deref(),
                    None,
                    None,
                    cfg.server.client_tag_deny.as_deref(),
                );
                send_to_client(&senders, mid, tagged).await;
            }
        }
    }

    Ok(())
}
