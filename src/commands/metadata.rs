//! draft/metadata-2: METADATA command (GET, LIST, SET, CLEAR). In-memory key-value store per target.

use crate::channel::ChannelStore;
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::ServerState;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

fn meta_key_valid(key: &str) -> bool {
    !key.is_empty()
        && key.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '/' || c == '-')
}

fn normalize_target(target: &str, self_nick: &str) -> String {
    if target == "*" {
        self_nick.to_string()
    } else {
        target.to_string()
    }
}

fn is_channel(t: &str) -> bool {
    t.starts_with('#') || t.starts_with('&')
}

pub async fn handle_metadata(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target_param = msg.params.get(0).map(|s| s.as_str()).unwrap_or("");
    let subcommand = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    if target_param.is_empty() || subcommand.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new("FAIL", vec!["METADATA".into(), "SUBCOMMAND_INVALID".into(), "*".into(), " :invalid subcommand".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let (self_nick, is_oper) = {
        let state_guard = state.read().await;
        let client = match state_guard.clients.get(client_id) {
            Some(c) => c.clone(),
            None => {
                reply_to_client(&senders, client_id, Message::new("451", vec!["*".into(), "You have not registered".into()]).with_prefix(&cfg.server.name), label).await;
                return Ok(());
            }
        };
        let g = client.read().await;
        (g.nick_or_id().to_string(), g.oper)
    };

    let target = normalize_target(target_param, &self_nick);

    match subcommand.to_uppercase().as_str() {
        "GET" => {
            let keys: Vec<String> = msg.params.iter().skip(2).map(|s| s.to_string()).collect();
            if keys.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("FAIL", vec!["METADATA".into(), "KEY_INVALID".into(), "*".into(), " :invalid key".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            let state_guard = state.read().await;
            let meta = state_guard.metadata.get(&target);
            for key in keys {
                if !meta_key_valid(&key) {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("FAIL", vec!["METADATA".into(), "KEY_INVALID".into(), key.clone(), " :invalid key".into()])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                    continue;
                }
                let value = meta.and_then(|m| m.get(&key)).cloned();
                if let Some(v) = value {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("761", vec![self_nick.clone(), target.clone(), key, "*".into(), format!(":{}", v)])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                } else {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("766", vec![self_nick.clone(), target.clone(), key.clone(), ":key not set".into()])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                }
            }
        }
        "LIST" => {
            let state_guard = state.read().await;
            let meta = state_guard.metadata.get(&target);
            if let Some(m) = meta {
                for (k, v) in m {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("761", vec![self_nick.clone(), target.clone(), k.clone(), "*".into(), format!(":{}", v)])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                }
            }
        }
        "SET" => {
            let key = msg.params.get(2).map(|s| s.as_str()).unwrap_or("");
            let value = msg.trailing().map(|s| s.to_string());
            if key.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("FAIL", vec!["METADATA".into(), "KEY_INVALID".into(), "*".into(), " :invalid key".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            if !meta_key_valid(key) {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("FAIL", vec!["METADATA".into(), "KEY_INVALID".into(), key.to_string(), " :invalid key".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            // Permission: self can set own; channel op can set channel
            let can_set = if target == self_nick {
                true
            } else if is_channel(&target) {
                let ch_store = channels.read().await;
                if let Some(ch) = ch_store.channels.get(&target) {
                    let ch_guard = ch.read().await;
                    ch_guard.members.get(client_id).map(|m| m.modes.op).unwrap_or(false)
                } else {
                    false
                }
            } else {
                is_oper
            };
            if !can_set {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("FAIL", vec!["METADATA".into(), "KEY_NO_PERMISSION".into(), target.clone(), key.to_string(), format!(":You do not have permission to set '{}' on '{}'", key, target)])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            if let Some(ref v) = value {
                if v.len() > 2048 {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new("FAIL", vec!["METADATA".into(), "VALUE_INVALID".into(), " :value is too long or not UTF8".into()])
                            .with_prefix(&cfg.server.name),
                        label,
                    )
                    .await;
                    return Ok(());
                }
            }
            let new_value = {
                let mut state_guard = state.write().await;
                let entry = state_guard.metadata.entry(target.clone()).or_default();
                if let Some(ref val) = value {
                    entry.insert(key.to_string(), val.clone());
                } else {
                    entry.remove(key);
                }
                value.clone()
            };
            // Persist to database
            if let Some(ref pool) = cfg.db {
                if let Some(ref v) = new_value {
                    crate::persist::save_metadata(pool, &target, key, v).await;
                } else {
                    crate::persist::delete_metadata(pool, &target, key).await;
                }
            }
            if let Some(v) = new_value {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("761", vec![self_nick.clone(), target.clone(), key.to_string(), "*".into(), format!(":{}", v)])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            } else {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("766", vec![self_nick.clone(), target.clone(), key.to_string(), ":key not set".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
        }
        "CLEAR" => {
            let can_set = if target == self_nick {
                true
            } else if is_channel(&target) {
                let ch_store = channels.read().await;
                if let Some(ch) = ch_store.channels.get(&target) {
                    let ch_guard = ch.read().await;
                    ch_guard.members.get(client_id).map(|m| m.modes.op).unwrap_or(false)
                } else {
                    false
                }
            } else {
                is_oper
            };
            if !can_set {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("FAIL", vec!["METADATA".into(), "KEY_NO_PERMISSION".into(), "*".into(), format!(":You do not have permission to clear metadata on '{}'", target)])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            let cleared: Vec<(String, String)> = {
                let mut state_guard = state.write().await;
                let entry = state_guard.metadata.entry(target.clone()).or_default();
                let kvs: Vec<_> = entry.drain().collect();
                kvs
            };
            // Persist to database
            if let Some(ref pool) = cfg.db {
                crate::persist::clear_metadata(pool, &target).await;
            }
            for (k, v) in cleared {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("761", vec![self_nick.clone(), target.clone(), k, "*".into(), format!(":{}", v)])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
        }
        _ => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("FAIL", vec!["METADATA".into(), "SUBCOMMAND_INVALID".into(), "*".into(), " :invalid subcommand".into()])
                    .with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
    }
    Ok(())
}
