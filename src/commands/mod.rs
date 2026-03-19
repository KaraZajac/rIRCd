mod channel_cmds;
mod metadata;
mod messaging;
mod query_cmds;
mod registration;
mod reply;
mod server_cmds;

pub use reply::reply_to_client;

use crate::channel::ChannelStore;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::{PendingClientBatch, PendingMultilineBatch, ServerState};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub async fn handle_message(
    client_id: String,
    host: String,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
) -> anyhow::Result<()> {
    let label = msg.tags.get("label").and_then(|v| v.as_ref()).cloned();

    // draft/multiline: BATCH + ref draft/multiline target
    if msg.command == "BATCH" {
        let first = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
        if first.starts_with('+') {
            let ref_tag = first[1..].to_string();
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
        } else if first.starts_with('-') {
            let ref_tag = first[1..].to_string();
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
                    let line_target = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
                    if line_target != pending.target {
                        let (batch_target, line_target_owned) = (pending.target.clone(), line_target.to_string());
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
                                    " :Invalid multiline target".into(),
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
                            Message::new("FAIL", vec!["BATCH".into(), "MULTILINE_INVALID".into(), "*".into(), " :Invalid multiline batch".into()])
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
                            Message::new("FAIL", vec!["BATCH".into(), "MULTILINE_INVALID".into(), "*".into(), " :Invalid multiline batch with concatenated blank line".into()])
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

    match msg.command.as_str() {
        "WEBIRC" => registration::handle_webirc(&client_id, &host, msg, state, senders, cfg, label.as_deref()).await,
        "CAP" => registration::handle_cap(&client_id, &host, msg, state, senders, cfg, label.as_deref()).await,
        "NICK" => registration::handle_nick(&client_id, &host, msg, state, channels, senders, cfg, label.as_deref()).await,
        "USER" => registration::handle_user(&client_id, &host, msg, state, senders, cfg, label.as_deref()).await,
        "PASS" => registration::handle_pass(&client_id, msg, state, senders, label.as_deref()).await,
        "PING" => registration::handle_ping(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "PONG" => registration::handle_pong(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "QUIT" => registration::handle_quit(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "JOIN" => channel_cmds::handle_join(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "PART" => channel_cmds::handle_part(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "NAMES" => channel_cmds::handle_names(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "LIST" => channel_cmds::handle_list(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "PRIVMSG" => messaging::handle_privmsg(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "NOTICE" => messaging::handle_notice(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "TAGMSG" => messaging::handle_tagmsg(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "MODE" => channel_cmds::handle_mode(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "TOPIC" => channel_cmds::handle_topic(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "KICK" => channel_cmds::handle_kick(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "INVITE" => channel_cmds::handle_invite(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "WHO" => query_cmds::handle_who(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "WHOIS" => query_cmds::handle_whois(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "AWAY" => registration::handle_away(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "AUTHENTICATE" => registration::handle_authenticate(&client_id, &host, msg, state, channels, senders, cfg, label.as_deref()).await,
        "OPER" => registration::handle_oper(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "REGISTER" => registration::handle_register(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "VERIFY" => registration::handle_verify(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "SETHOST" => registration::handle_sethost(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "SETUSER" => registration::handle_setuser(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "SETNAME" => registration::handle_setname(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "ISUPPORT" => registration::handle_isupport(&client_id, state, senders, cfg, label.as_deref()).await,
        "MOTD" => registration::handle_motd(&client_id, state, senders, cfg, label.as_deref()).await,
        "REDACT" => messaging::handle_redact(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "CHATHISTORY" => messaging::handle_chathistory(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "MONITOR" => query_cmds::handle_monitor(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "RENAME" => channel_cmds::handle_rename(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "MARKREAD" => messaging::handle_markread(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "METADATA" => metadata::handle_metadata(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "LUSERS" => server_cmds::handle_lusers(&client_id, state, channels.clone(), senders, cfg, label.as_deref()).await,
        "VERSION" => server_cmds::handle_version(&client_id, state, senders, cfg, label.as_deref()).await,
        "TIME" => server_cmds::handle_time(&client_id, state, senders, cfg, label.as_deref()).await,
        "INFO" => server_cmds::handle_info(&client_id, state, senders, cfg, label.as_deref()).await,
        "LINKS" => server_cmds::handle_links(&client_id, state, senders, cfg, label.as_deref()).await,
        "STATS" => server_cmds::handle_stats(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "WHOWAS" => server_cmds::handle_whowas(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "HELP" => server_cmds::handle_help(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "KNOCK" => server_cmds::handle_knock(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "KILL" => server_cmds::handle_kill(&client_id, msg, state, channels, senders, cfg, label.as_deref()).await,
        "WALLOPS" => server_cmds::handle_wallops(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "ISON" => query_cmds::handle_ison(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        "USERHOST" => query_cmds::handle_userhost(&client_id, msg, state, senders, cfg, label.as_deref()).await,
        _ => {
            let target = {
                let state = state.read().await;
                state.clients
                    .get(&client_id)
                    .cloned()
            };
            let target = match target {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            };
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
