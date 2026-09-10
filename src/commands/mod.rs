mod channel_cmds;
mod messaging;
pub(crate) mod metadata;
mod query_cmds;
mod registration;
mod reply;
mod server_cmds;
mod webpush_cmds;

pub use reply::{
    end_labeled_batch, reply_in_batch, reply_to_client, reply_to_sender, send_labeled_ack,
    start_labeled_batch,
};

use crate::channel::ChannelStore;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{PendingClientBatch, PendingMultilineBatch, Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// KICK names two lists: channels and users. RFC 2812 pairs them when both
/// have the same length, and otherwise applies the single channel to every
/// user, or every channel to the single user.
fn split_kicks(msg: &Message, max: usize) -> Vec<Message> {
    let (Some(channels), Some(users)) = (msg.params.first(), msg.params.get(1)) else {
        return vec![msg.clone()];
    };
    if !channels.contains(',') && !users.contains(',') {
        return vec![msg.clone()];
    }
    let channels: Vec<&str> = channels.split(',').filter(|c| !c.is_empty()).collect();
    let users: Vec<&str> = users.split(',').filter(|u| !u.is_empty()).collect();
    if channels.is_empty() || users.is_empty() {
        return vec![msg.clone()];
    }
    let pairs: Vec<(&str, &str)> = if channels.len() == users.len() {
        channels
            .iter()
            .copied()
            .zip(users.iter().copied())
            .collect()
    } else if channels.len() == 1 {
        users.iter().map(|u| (channels[0], *u)).collect()
    } else if users.len() == 1 {
        channels.iter().map(|c| (*c, users[0])).collect()
    } else {
        // Mismatched lists that are not one-to-many either way: RFC 2812 has
        // no reading for this, so it is left alone and answered as written.
        return vec![msg.clone()];
    };

    pairs
        .into_iter()
        .take(max)
        .map(|(ch, user)| {
            let mut copy = msg.clone();
            copy.params[0] = ch.to_string();
            copy.params[1] = user.to_string();
            copy
        })
        .collect()
}

/// One message per target, for the commands whose first parameter is a
/// comma-separated target list. A single target — the overwhelming majority of
/// traffic — comes back as the one message it already was.
fn split_targets(msg: &Message, max: usize) -> Vec<Message> {
    let Some(targets) = msg.params.first() else {
        return vec![msg.clone()];
    };
    if !targets.contains(',') {
        return vec![msg.clone()];
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for target in targets.split(',') {
        if target.is_empty() || !seen.insert(target.to_uppercase()) {
            continue;
        }
        if out.len() >= max {
            break;
        }
        let mut copy = msg.clone();
        copy.params[0] = target.to_string();
        out.push(copy);
    }
    if out.is_empty() {
        out.push(msg.clone());
    }
    out
}

/// Messages one client-initiated batch may carry before the server gives up on it.
const CLIENT_BATCH_MAX_MESSAGES: usize = 100;

pub async fn handle_message(
    client_id: String,
    host: String,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: Arc<RwLock<Config>>,
) -> anyhow::Result<()> {
    // labeled-response: label values MUST NOT exceed 64 bytes
    let label = msg
        .tags
        .get("label")
        .and_then(|v| v.as_ref())
        .filter(|l| l.len() <= 64)
        .cloned();

    // REHASH needs write access to cfg — handle before acquiring the read lock
    if msg.command == "REHASH" {
        return server_cmds::handle_rehash(&client_id, state, senders, cfg, label.as_deref()).await;
    }

    let cfg_guard = cfg.read().await;
    let cfg = &*cfg_guard;

    // draft/multiline: BATCH + ref draft/multiline target
    if msg.command == "BATCH" {
        let first = msg.params.first().map(|s| s.as_str()).unwrap_or("");
        if let Some(stripped) = first.strip_prefix('+') {
            let ref_tag = stripped.to_string();
            let batch_type = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
            if batch_type == "draft/multiline" {
                let target = msg.params.get(2).map(|s| s.to_string()).unwrap_or_default();
                let mut state_w = state.write().await;
                state_w.pending_multiline.insert(
                    client_id.clone(),
                    PendingMultilineBatch {
                        ref_tag: ref_tag.clone(),
                        target,
                        command: String::new(),
                        lines: Vec::new(),
                        label: label.clone(),
                        tags: msg.tags.clone(),
                    },
                );
                return Ok(());
            } else if !batch_type.is_empty() {
                // draft/client-batch: any other batch type is collected and delivered
                let target = msg.params.get(2).map(|s| s.to_string()).unwrap_or_default();
                let mut state_w = state.write().await;
                state_w.pending_client_batches.insert(
                    client_id.clone(),
                    PendingClientBatch {
                        ref_tag,
                        batch_type: batch_type.to_string(),
                        target,
                        messages: Vec::new(),
                    },
                );
                return Ok(());
            }
        } else if let Some(stripped) = first.strip_prefix('-') {
            let ref_tag = stripped.to_string();
            let batch = {
                let mut state_w = state.write().await;
                state_w.pending_multiline.remove(&client_id)
            };
            if let Some(batch) = batch {
                if batch.ref_tag != ref_tag {
                    return Ok(());
                }
                return messaging::deliver_multiline_batch(
                    &client_id,
                    batch,
                    state,
                    channels,
                    senders,
                    cfg,
                    label.as_deref(),
                )
                .await;
            }
            let client_batch = {
                let mut state_w = state.write().await;
                state_w.pending_client_batches.remove(&client_id)
            };
            if let Some(batch) = client_batch {
                if batch.ref_tag == ref_tag {
                    return messaging::deliver_client_batch(
                        &client_id,
                        batch,
                        state,
                        channels,
                        senders,
                        cfg,
                        label.as_deref(),
                    )
                    .await;
                }
            }
        }
    }

    // draft/multiline: PRIVMSG/NOTICE with batch=ref appends to pending batch
    if msg.command == "PRIVMSG" || msg.command == "NOTICE" {
        let batch_ref = msg.tags.get("batch").and_then(|v| v.as_ref()).cloned();
        if let Some(ref ref_val) = batch_ref {
            let mut state_w = state.write().await;
            if let Some(pending) = state_w.pending_multiline.get_mut(&client_id) {
                if pending.ref_tag == *ref_val {
                    let line_target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                    if line_target != pending.target {
                        let (batch_target, line_target_owned) =
                            (pending.target.clone(), line_target.to_string());
                        crate::commands::reply_to_client(
                            &senders,
                            &client_id,
                            Message::new(
                                "FAIL",
                                vec![
                                    "BATCH".into(),
                                    "MULTILINE_INVALID_TARGET".into(),
                                    batch_target,
                                    line_target_owned,
                                    "Invalid multiline target".into(),
                                ],
                            )
                            .with_prefix(&cfg.server.name),
                            label.as_deref(),
                        )
                        .await;
                        let _ = state.write().await.pending_multiline.remove(&client_id);
                        return Ok(());
                    }
                    if pending.command.is_empty() {
                        pending.command = msg.command.clone();
                    } else if pending.command != msg.command {
                        drop(state_w);
                        crate::commands::reply_to_client(
                            &senders,
                            &client_id,
                            Message::new(
                                "FAIL",
                                vec![
                                    "BATCH".into(),
                                    "MULTILINE_INVALID".into(),
                                    "*".into(),
                                    "Invalid multiline batch".into(),
                                ],
                            )
                            .with_prefix(&cfg.server.name),
                            label.as_deref(),
                        )
                        .await;
                        let _ = state.write().await.pending_multiline.remove(&client_id);
                        return Ok(());
                    }
                    let concat = msg.tags.contains_key("draft/multiline-concat");
                    let text = msg.trailing().unwrap_or("").to_string();
                    if concat && text.is_empty() {
                        drop(state_w);
                        crate::commands::reply_to_client(
                            &senders,
                            &client_id,
                            Message::new(
                                "FAIL",
                                vec![
                                    "BATCH".into(),
                                    "MULTILINE_INVALID".into(),
                                    "Invalid multiline batch with concatenated blank line".into(),
                                ],
                            )
                            .with_prefix(&cfg.server.name),
                            label.as_deref(),
                        )
                        .await;
                        let _ = state.write().await.pending_multiline.remove(&client_id);
                        return Ok(());
                    }
                    // Enforce the advertised limits while collecting, not only at
                    // delivery: an unclosed batch would otherwise grow forever.
                    let over_lines = pending.lines.len() >= messaging::MULTILINE_MAX_LINES;
                    let over_bytes = pending.lines.iter().map(|(_, l)| l.len()).sum::<usize>()
                        + text.len()
                        > messaging::MULTILINE_MAX_BYTES;
                    if over_lines || over_bytes {
                        let (code, limit) = if over_lines {
                            ("MULTILINE_MAX_LINES", messaging::MULTILINE_MAX_LINES)
                        } else {
                            ("MULTILINE_MAX_BYTES", messaging::MULTILINE_MAX_BYTES)
                        };
                        drop(state_w);
                        crate::commands::reply_to_client(
                            &senders,
                            &client_id,
                            Message::new(
                                "FAIL",
                                vec![
                                    "BATCH".into(),
                                    code.into(),
                                    limit.to_string(),
                                    "Multiline batch is too large".into(),
                                ],
                            )
                            .with_prefix(&cfg.server.name),
                            label.as_deref(),
                        )
                        .await;
                        let _ = state.write().await.pending_multiline.remove(&client_id);
                        return Ok(());
                    }
                    pending.lines.push((concat, text));
                    return Ok(());
                }
            }
        }
    }

    // draft/client-batch: PRIVMSG/NOTICE/TAGMSG with batch=ref appends to pending client batch
    if msg.command == "PRIVMSG" || msg.command == "NOTICE" || msg.command == "TAGMSG" {
        let batch_ref = msg.tags.get("batch").and_then(|v| v.as_ref()).cloned();
        if let Some(ref ref_val) = batch_ref {
            let appended = {
                let mut state_w = state.write().await;
                if let Some(pending) = state_w.pending_client_batches.get_mut(&client_id) {
                    if pending.ref_tag == *ref_val {
                        // Bounded for the same reason as multiline batches.
                        if pending.messages.len() >= CLIENT_BATCH_MAX_MESSAGES {
                            state_w.pending_client_batches.remove(&client_id);
                            drop(state_w);
                            crate::commands::reply_to_client(
                                &senders,
                                &client_id,
                                Message::new(
                                    "FAIL",
                                    vec![
                                        "BATCH".into(),
                                        "MAX_MESSAGES".into(),
                                        CLIENT_BATCH_MAX_MESSAGES.to_string(),
                                        "Too many messages in one batch".into(),
                                    ],
                                )
                                .with_prefix(&cfg.server.name),
                                label.as_deref(),
                            )
                            .await;
                            return Ok(());
                        }
                        pending.messages.push(msg.clone());
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if appended {
                return Ok(());
            }
        }
    }

    state
        .write()
        .await
        .command_counts
        .entry(msg.command.clone())
        .and_modify(|n| *n += 1)
        .or_insert(1);

    tracing::trace!(
        client = %client_id,
        command = %msg.command,
        params = %msg.params.iter().take(2).cloned().collect::<Vec<_>>().join(" "),
        "Command"
    );

    match msg.command.as_str() {
        "WEBIRC" => {
            registration::handle_webirc(
                &client_id,
                &host,
                msg,
                state,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "CAP" => {
            registration::handle_cap(
                &client_id,
                &host,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "NICK" => {
            registration::handle_nick(
                &client_id,
                &host,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "USER" => {
            registration::handle_user(
                &client_id,
                &host,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "PASS" => {
            registration::handle_pass(&client_id, msg, state, senders, label.as_deref()).await
        }
        "PING" => {
            registration::handle_ping(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "PONG" => {
            let result = registration::handle_pong(
                &client_id,
                msg,
                state,
                senders.clone(),
                cfg,
                label.as_deref(),
            )
            .await;
            // labeled-response: PONG produces no reply, so send ACK if labeled
            if let Some(ref l) = label {
                reply::send_labeled_ack(&senders, &client_id, l, &cfg.server.name).await;
            }
            result
        }
        "QUIT" => {
            registration::handle_quit(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "JOIN" => {
            channel_cmds::handle_join(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "PART" => {
            channel_cmds::handle_part(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "NAMES" => {
            channel_cmds::handle_names(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "LIST" => {
            channel_cmds::handle_list(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "PRIVMSG" => {
            let parts = split_targets(&msg, cfg.limits.max_targets);
            // Naming several targets is still one command, so its answer is one
            // labeled response: a batch around the lot rather than a label on
            // each piece.
            let parent_batch = match (parts.len() > 1, label.as_deref()) {
                (true, Some(l)) => {
                    Some(start_labeled_batch(&senders, &client_id, l, &cfg.server.name).await)
                }
                _ => None,
            };
            let mut result = Ok(());
            for one in parts {
                result = messaging::handle_privmsg(
                    &client_id,
                    one,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    cfg,
                    label.as_deref(),
                    parent_batch.as_deref(),
                )
                .await;
                if result.is_err() {
                    break;
                }
            }
            if let Some(ref br) = parent_batch {
                end_labeled_batch(&senders, &client_id, br, &cfg.server.name).await;
            }
            result
        }
        "NOTICE" => {
            let parts = split_targets(&msg, cfg.limits.max_targets);
            // Naming several targets is still one command, so its answer is one
            // labeled response: a batch around the lot rather than a label on
            // each piece.
            let parent_batch = match (parts.len() > 1, label.as_deref()) {
                (true, Some(l)) => {
                    Some(start_labeled_batch(&senders, &client_id, l, &cfg.server.name).await)
                }
                _ => None,
            };
            let mut result = Ok(());
            for one in parts {
                result = messaging::handle_notice(
                    &client_id,
                    one,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    cfg,
                    label.as_deref(),
                    parent_batch.as_deref(),
                )
                .await;
                if result.is_err() {
                    break;
                }
            }
            if let Some(ref br) = parent_batch {
                end_labeled_batch(&senders, &client_id, br, &cfg.server.name).await;
            }
            result
        }
        "TAGMSG" => {
            let parts = split_targets(&msg, cfg.limits.max_targets);
            // Naming several targets is still one command, so its answer is one
            // labeled response: a batch around the lot rather than a label on
            // each piece.
            let parent_batch = match (parts.len() > 1, label.as_deref()) {
                (true, Some(l)) => {
                    Some(start_labeled_batch(&senders, &client_id, l, &cfg.server.name).await)
                }
                _ => None,
            };
            let mut result = Ok(());
            for one in parts {
                result = messaging::handle_tagmsg(
                    &client_id,
                    one,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    cfg,
                    label.as_deref(),
                    parent_batch.as_deref(),
                )
                .await;
                if result.is_err() {
                    break;
                }
            }
            if let Some(ref br) = parent_batch {
                end_labeled_batch(&senders, &client_id, br, &cfg.server.name).await;
            }
            result
        }
        "MODE" => {
            channel_cmds::handle_mode(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "TOPIC" => {
            channel_cmds::handle_topic(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "KICK" => {
            let mut result = Ok(());
            for one in split_kicks(&msg, cfg.limits.max_targets) {
                result = channel_cmds::handle_kick(
                    &client_id,
                    one,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    cfg,
                    label.as_deref(),
                )
                .await;
                if result.is_err() {
                    break;
                }
            }
            result
        }
        "INVITE" => {
            channel_cmds::handle_invite(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "WHO" => {
            query_cmds::handle_who(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "WHOIS" => {
            query_cmds::handle_whois(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "AWAY" => {
            registration::handle_away(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "AUTHENTICATE" => {
            registration::handle_authenticate(
                &client_id,
                &host,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "OPER" => {
            registration::handle_oper(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "REGISTER" => {
            registration::handle_register(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "VERIFY" => {
            registration::handle_verify(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "SETHOST" => {
            registration::handle_sethost(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "SETUSER" => {
            registration::handle_setuser(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "SETNAME" => {
            registration::handle_setname(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "ISUPPORT" => {
            registration::handle_isupport(&client_id, state, senders, cfg, label.as_deref()).await
        }
        "MOTD" => {
            registration::handle_motd(&client_id, state, senders, cfg, label.as_deref()).await
        }
        "REDACT" => {
            messaging::handle_redact(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "CHATHISTORY" => {
            messaging::handle_chathistory(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "MONITOR" => {
            query_cmds::handle_monitor(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "RENAME" => {
            channel_cmds::handle_rename(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "MARKREAD" => {
            messaging::handle_markread(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "METADATA" => {
            metadata::handle_metadata(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "LUSERS" => {
            server_cmds::handle_lusers(
                &client_id,
                state,
                channels.clone(),
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "VERSION" => {
            server_cmds::handle_version(&client_id, state, senders, cfg, label.as_deref()).await
        }
        "TIME" => server_cmds::handle_time(&client_id, state, senders, cfg, label.as_deref()).await,
        "INFO" => server_cmds::handle_info(&client_id, state, senders, cfg, label.as_deref()).await,
        "LINKS" => {
            server_cmds::handle_links(&client_id, state, senders, cfg, label.as_deref()).await
        }
        "STATS" => {
            server_cmds::handle_stats(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "WHOWAS" => {
            server_cmds::handle_whowas(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        // HELPOP is what several networks call HELP; the same answer serves.
        "HELP" | "HELPOP" => {
            server_cmds::handle_help(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "KNOCK" => {
            server_cmds::handle_knock(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "KILL" => {
            server_cmds::handle_kill(
                &client_id,
                msg,
                state,
                channels,
                senders,
                cfg,
                label.as_deref(),
            )
            .await
        }
        "WALLOPS" => {
            server_cmds::handle_wallops(&client_id, msg, state, senders, cfg, label.as_deref())
                .await
        }
        "WEBPUSH" => {
            webpush_cmds::handle_webpush(&client_id, msg, state, senders, cfg, label.as_deref())
                .await
        }
        "GHOST" => {
            registration::handle_ghost(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "ADMIN" => {
            server_cmds::handle_admin(&client_id, state, senders, cfg, label.as_deref()).await
        }
        "DIE" => server_cmds::handle_die(&client_id, state, senders, cfg, label.as_deref()).await,
        "KLINE" => {
            server_cmds::handle_kline(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "UNKLINE" => {
            server_cmds::handle_unkline(&client_id, msg, state, senders, cfg, label.as_deref())
                .await
        }
        "ISON" => {
            query_cmds::handle_ison(&client_id, msg, state, senders, cfg, label.as_deref()).await
        }
        "USERHOST" => {
            query_cmds::handle_userhost(&client_id, msg, state, senders, cfg, label.as_deref())
                .await
        }
        _ => {
            let target = {
                let state = state.read().await;
                state.clients.get(&client_id).cloned()
            };
            let target = match target {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            };
            tracing::debug!(client = %client_id, command = %msg.command, "Unknown command");
            reply_to_client(
                &senders,
                &client_id,
                Message::new("421", vec![target, msg.command, "Unknown command".into()])
                    .with_prefix(&cfg.server.name),
                label.as_deref(),
            )
            .await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    fn msg(command: &str, params: &[&str]) -> Message {
        Message::new(command, params.iter().map(|p| p.to_string()).collect())
    }

    fn targets_of(m: &Message, max: usize) -> Vec<String> {
        split_targets(m, max)
            .into_iter()
            .map(|m| m.params[0].clone())
            .collect()
    }

    #[test]
    fn one_target_passes_through_untouched() {
        let m = msg("PRIVMSG", &["#chan", "hi"]);
        let out = split_targets(&m, 4);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].params, m.params);
    }

    #[test]
    fn a_target_list_becomes_one_message_each() {
        let m = msg("PRIVMSG", &["alice,bob,#chan", "hi"]);
        assert_eq!(targets_of(&m, 4), ["alice", "bob", "#chan"]);
        // The text travels with every copy.
        assert!(split_targets(&m, 4).iter().all(|m| m.params[1] == "hi"));
    }

    #[test]
    fn a_target_named_twice_is_delivered_once() {
        let m = msg("PRIVMSG", &["alice,Alice,alice", "hi"]);
        assert_eq!(targets_of(&m, 4), ["alice"]);
    }

    #[test]
    fn the_target_limit_is_a_limit() {
        let m = msg("PRIVMSG", &["a,b,c,d,e,f", "hi"]);
        assert_eq!(targets_of(&m, 3), ["a", "b", "c"]);
    }

    #[test]
    fn empty_entries_in_the_list_are_skipped() {
        let m = msg("PRIVMSG", &["a,,b,", "hi"]);
        assert_eq!(targets_of(&m, 4), ["a", "b"]);
    }

    /// A list of nothing but commas is left alone rather than turned into no
    /// message at all: the handler answers it, as it would any bad target.
    #[test]
    fn a_list_of_nothing_is_left_for_the_handler() {
        let m = msg("PRIVMSG", &[",,,", "hi"]);
        assert_eq!(targets_of(&m, 4), [",,,"]);
    }

    fn kick_pairs(m: &Message, max: usize) -> Vec<(String, String)> {
        split_kicks(m, max)
            .into_iter()
            .map(|m| (m.params[0].clone(), m.params[1].clone()))
            .collect()
    }

    #[test]
    fn one_channel_kicks_every_named_user() {
        let m = msg("KICK", &["#chan", "bar,baz", "bye"]);
        assert_eq!(
            kick_pairs(&m, 4),
            [
                ("#chan".to_string(), "bar".to_string()),
                ("#chan".to_string(), "baz".to_string())
            ]
        );
    }

    #[test]
    fn equal_length_lists_are_paired_in_order() {
        let m = msg("KICK", &["#a,#b", "bar,baz", "bye"]);
        assert_eq!(
            kick_pairs(&m, 4),
            [
                ("#a".to_string(), "bar".to_string()),
                ("#b".to_string(), "baz".to_string())
            ]
        );
    }

    #[test]
    fn one_user_is_kicked_from_every_named_channel() {
        let m = msg("KICK", &["#a,#b", "bar", "bye"]);
        assert_eq!(
            kick_pairs(&m, 4),
            [
                ("#a".to_string(), "bar".to_string()),
                ("#b".to_string(), "bar".to_string())
            ]
        );
    }

    /// Two lists of different lengths, neither of them one: RFC 2812 has no
    /// reading for that, so it goes through as written and is refused.
    #[test]
    fn mismatched_lists_are_not_guessed_at() {
        let m = msg("KICK", &["#a,#b", "x,y,z", "bye"]);
        assert_eq!(
            kick_pairs(&m, 4),
            [("#a,#b".to_string(), "x,y,z".to_string())]
        );
    }
}
