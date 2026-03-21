//! draft/metadata-2: METADATA command (GET, LIST, SET, CLEAR, SUB, UNSUB, SUBS, SYNC).

use crate::channel::ChannelStore;
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::{generate_msgid, Message};
use crate::user::ServerState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Max metadata keys allowed per target
const MAX_METADATA_KEYS: usize = 50;
/// Max keys a client may subscribe to
const MAX_SUBS: usize = 50;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn meta_key_valid(key: &str) -> bool {
    !key.is_empty()
        && key.chars().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == '_'
                || c == '.'
                || c == '/'
                || c == '-'
        })
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

async fn target_exists(
    target: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
) -> bool {
    if is_channel(target) {
        channels.read().await.channels.contains_key(target)
    } else {
        state
            .read()
            .await
            .nick_to_id
            .contains_key(&target.to_lowercase())
    }
}

/// Send a metadata batch (GET / LIST / SYNC) to one client.
/// Uses `metadata` batch wrapping when the client has `batch` cap.
/// Always ends with 762 RPL_METADATAEND.
#[allow(clippy::too_many_arguments)]
async fn send_metadata_batch(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    nick: &str,
    target: &str,
    entries: &[(String, String)],
    server_name: &str,
    has_batch: bool,
    label: Option<&str>,
) {
    let batch_ref: Option<String> = if has_batch {
        Some(generate_msgid())
    } else {
        None
    };

    if let Some(ref ref_id) = batch_ref {
        reply_to_client(
            senders,
            client_id,
            Message::new(
                "BATCH",
                vec![
                    format!("+{}", ref_id),
                    "metadata".into(),
                    target.to_string(),
                ],
            )
            .with_prefix(server_name),
            label,
        )
        .await;
    }

    for (key, value) in entries {
        let mut m = Message::new(
            "761",
            vec![
                nick.to_string(),
                target.to_string(),
                key.clone(),
                "*".to_string(),
                format!(":{}", value),
            ],
        )
        .with_prefix(server_name);
        if let Some(ref ref_id) = batch_ref {
            m.tags.insert("batch".to_string(), Some(ref_id.clone()));
        }
        reply_to_client(senders, client_id, m, label).await;
    }

    let mut end_msg = Message::new("762", vec![nick.to_string(), "End of METADATA".to_string()])
        .with_prefix(server_name);
    if let Some(ref ref_id) = batch_ref {
        end_msg
            .tags
            .insert("batch".to_string(), Some(ref_id.clone()));
    }
    reply_to_client(senders, client_id, end_msg, label).await;

    if let Some(ref ref_id) = batch_ref {
        reply_to_client(
            senders,
            client_id,
            Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(server_name),
            label,
        )
        .await;
    }
}

/// Broadcast a METADATA change event to all eligible subscribers.
/// `value = None` means the key was deleted.
/// The setter (setter_id) does not receive their own notification.
#[allow(clippy::too_many_arguments)]
async fn broadcast_metadata_event(
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    setter_source: &str,
    setter_id: &str,
    target: &str,
    key: &str,
    value: Option<&str>,
) {
    let mut params = vec![target.to_string(), key.to_string(), "*".to_string()];
    if let Some(v) = value {
        params.push(format!(":{}", v));
    }
    let event = Message::new("METADATA", params).with_prefix(setter_source);

    // Step 1: collect candidate client IDs who can observe the target
    let candidate_ids: Vec<String> = if is_channel(target) {
        let ch_store = channels.read().await;
        match ch_store.channels.get(target) {
            Some(ch) => ch.read().await.members.keys().cloned().collect(),
            None => return,
        }
    } else {
        // User target: clients sharing a channel with them, plus the user themselves
        let state_r = state.read().await;
        let target_lower = target.to_lowercase();
        let target_id = match state_r.nick_to_id.get(&target_lower).cloned() {
            Some(id) => id,
            None => return,
        };
        let target_chans: Vec<String> = match state_r.clients.get(&target_id) {
            Some(c) => c.read().await.channels.keys().cloned().collect(),
            None => return,
        };
        drop(state_r);

        let ch_store = channels.read().await;
        let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        ids.insert(target_id);
        for ch_key in &target_chans {
            if let Some(ch) = ch_store.channels.get(ch_key) {
                for id in ch.read().await.members.keys() {
                    ids.insert(id.clone());
                }
            }
        }
        ids.into_iter().collect()
    };

    // Step 2: filter by: not the setter + has draft/metadata-2 cap + subscribed to this key
    let state_r = state.read().await;
    let mut notify_ids = Vec::new();
    for id in &candidate_ids {
        if id == setter_id {
            continue;
        }
        if let Some(client) = state_r.clients.get(id) {
            let g = client.read().await;
            if g.capabilities.contains("draft/metadata-2") && g.metadata_subscriptions.contains(key)
            {
                notify_ids.push(id.clone());
            }
        }
    }
    drop(state_r);

    for id in notify_ids {
        if let Some(tx) = senders.read().await.get(&id) {
            let _ = tx.send(event.clone()).await;
        }
    }
}

/// Called by the JOIN handler to push current channel metadata to a newly joined client.
/// Pre-collected entries avoid re-acquiring the ServerState lock inside a read guard.
pub async fn send_channel_metadata_on_join(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    channel: &str,
    nick: &str,
    server_name: &str,
    has_batch: bool,
    entries: Vec<(String, String)>,
) {
    if entries.is_empty() {
        return;
    }
    send_metadata_batch(
        senders,
        client_id,
        nick,
        channel,
        &entries,
        server_name,
        has_batch,
        None,
    )
    .await;
}

// ─── Main handler ─────────────────────────────────────────────────────────────

pub async fn handle_metadata(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let target_param = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let subcommand = msg
        .params
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("")
        .to_uppercase();

    if target_param.is_empty() || subcommand.is_empty() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "METADATA".into(),
                    "SUBCOMMAND_INVALID".into(),
                    "*".into(),
                    " :invalid subcommand".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let (self_nick, is_oper, setter_source, has_batch) = {
        let state_r = state.read().await;
        let client = match state_r.clients.get(client_id) {
            Some(c) => c.clone(),
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("451", vec!["*".into(), "You have not registered".into()])
                        .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }
        };
        let g = client.read().await;
        let src = g.source().unwrap_or_else(|| g.nick_or_id().to_string());
        let has_batch = g.capabilities.contains("batch");
        (g.nick_or_id().to_string(), g.oper, src, has_batch)
    };

    let target = normalize_target(target_param, &self_nick);

    match subcommand.as_str() {
        // ── GET ───────────────────────────────────────────────────────────────
        "GET" => {
            let keys: Vec<String> = msg.params.iter().skip(2).map(|s| s.to_string()).collect();
            if keys.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_INVALID".into(),
                            "*".into(),
                            " :invalid key".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            if !target_exists(&target, &state, &channels).await {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "INVALID_TARGET".into(),
                            target.clone(),
                            " :No such target".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            let state_r = state.read().await;
            let meta = state_r.metadata.get(&target);
            let mut entries = Vec::new();
            let mut missing = Vec::new();

            for key in &keys {
                if !meta_key_valid(key) {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new(
                            "FAIL",
                            vec![
                                "METADATA".into(),
                                "KEY_INVALID".into(),
                                key.clone(),
                                " :invalid key".into(),
                            ],
                        )
                        .with_prefix(s),
                        label,
                    )
                    .await;
                    continue;
                }
                match meta.and_then(|m| m.get(key)) {
                    Some(v) => entries.push((key.clone(), v.clone())),
                    None => missing.push(key.clone()),
                }
            }

            let has_batch_cap = has_batch;
            drop(state_r);

            let batch_ref: Option<String> = if has_batch_cap {
                Some(generate_msgid())
            } else {
                None
            };
            if let Some(ref ref_id) = batch_ref {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "BATCH",
                        vec![format!("+{}", ref_id), "metadata".into(), target.clone()],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }

            for (key, value) in &entries {
                let mut m = Message::new(
                    "761",
                    vec![
                        self_nick.clone(),
                        target.clone(),
                        key.clone(),
                        "*".into(),
                        format!(":{}", value),
                    ],
                )
                .with_prefix(s);
                if let Some(ref ref_id) = batch_ref {
                    m.tags.insert("batch".to_string(), Some(ref_id.clone()));
                }
                reply_to_client(&senders, client_id, m, label).await;
            }
            for key in &missing {
                let mut m = Message::new(
                    "766",
                    vec![
                        self_nick.clone(),
                        target.clone(),
                        key.clone(),
                        " :key not set".into(),
                    ],
                )
                .with_prefix(s);
                if let Some(ref ref_id) = batch_ref {
                    m.tags.insert("batch".to_string(), Some(ref_id.clone()));
                }
                reply_to_client(&senders, client_id, m, label).await;
            }

            let mut end = Message::new(
                "762",
                vec![self_nick.clone(), "End of METADATA".to_string()],
            )
            .with_prefix(s);
            if let Some(ref ref_id) = batch_ref {
                end.tags.insert("batch".to_string(), Some(ref_id.clone()));
            }
            reply_to_client(&senders, client_id, end, label).await;

            if let Some(ref ref_id) = batch_ref {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(s),
                    label,
                )
                .await;
            }
        }

        // ── LIST ──────────────────────────────────────────────────────────────
        "LIST" => {
            if !target_exists(&target, &state, &channels).await {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "INVALID_TARGET".into(),
                            target.clone(),
                            " :No such target".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            let entries: Vec<(String, String)> = {
                let state_r = state.read().await;
                state_r
                    .metadata
                    .get(&target)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default()
            };

            send_metadata_batch(
                &senders, client_id, &self_nick, &target, &entries, s, has_batch, label,
            )
            .await;
        }

        // ── SET ───────────────────────────────────────────────────────────────
        "SET" => {
            let key = msg.params.get(2).map(|s| s.as_str()).unwrap_or("");
            let value = msg.trailing().map(|s| s.to_string());

            if key.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_INVALID".into(),
                            "*".into(),
                            " :invalid key".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }
            if !meta_key_valid(key) {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_INVALID".into(),
                            key.to_string(),
                            " :invalid key".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            // Permission check
            let can_set = if target == self_nick {
                true
            } else if is_channel(&target) {
                let ch_store = channels.read().await;
                if let Some(ch) = ch_store.channels.get(&target) {
                    ch.read()
                        .await
                        .members
                        .get(client_id)
                        .map(|m| m.modes.op)
                        .unwrap_or(false)
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
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_NO_PERMISSION".into(),
                            target.clone(),
                            key.to_string(),
                            format!(
                                ":You do not have permission to set '{}' on '{}'",
                                key, target
                            ),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            // Value length
            if let Some(ref v) = value {
                if v.len() > 2048 {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new(
                            "FAIL",
                            vec![
                                "METADATA".into(),
                                "VALUE_INVALID".into(),
                                " :value too long".into(),
                            ],
                        )
                        .with_prefix(s),
                        label,
                    )
                    .await;
                    return Ok(());
                }
            }

            // Key count limit (only when setting, not deleting)
            if value.is_some() {
                let state_r = state.read().await;
                let current_count = state_r.metadata.get(&target).map(|m| m.len()).unwrap_or(0);
                let already_set = state_r
                    .metadata
                    .get(&target)
                    .and_then(|m| m.get(key))
                    .is_some();
                drop(state_r);
                if !already_set && current_count >= MAX_METADATA_KEYS {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new(
                            "FAIL",
                            vec![
                                "METADATA".into(),
                                "LIMIT_REACHED".into(),
                                target.clone(),
                                format!(":Metadata key limit ({}) reached", MAX_METADATA_KEYS),
                            ],
                        )
                        .with_prefix(s),
                        label,
                    )
                    .await;
                    return Ok(());
                }
            }

            // Apply change
            let new_value = {
                let mut state_w = state.write().await;
                let entry = state_w.metadata.entry(target.clone()).or_default();
                if let Some(ref val) = value {
                    entry.insert(key.to_string(), val.clone());
                } else {
                    entry.remove(key);
                }
                value.clone()
            };

            // Persist
            if let Some(ref pool) = cfg.db {
                if let Some(ref v) = new_value {
                    crate::persist::save_metadata(pool, &target, key, v).await;
                } else {
                    crate::persist::delete_metadata(pool, &target, key).await;
                }
            }

            // Reply to setter
            if let Some(ref v) = new_value {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "761",
                        vec![
                            self_nick.clone(),
                            target.clone(),
                            key.to_string(),
                            "*".into(),
                            format!(":{}", v),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            } else {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "766",
                        vec![
                            self_nick.clone(),
                            target.clone(),
                            key.to_string(),
                            " :key not set".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }

            // Broadcast METADATA event to subscribers
            broadcast_metadata_event(
                &state,
                &channels,
                &senders,
                &setter_source,
                client_id,
                &target,
                key,
                new_value.as_deref(),
            )
            .await;
        }

        // ── CLEAR ─────────────────────────────────────────────────────────────
        "CLEAR" => {
            let can_set = if target == self_nick {
                true
            } else if is_channel(&target) {
                let ch_store = channels.read().await;
                if let Some(ch) = ch_store.channels.get(&target) {
                    ch.read()
                        .await
                        .members
                        .get(client_id)
                        .map(|m| m.modes.op)
                        .unwrap_or(false)
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
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_NO_PERMISSION".into(),
                            "*".into(),
                            format!(
                                ":You do not have permission to clear metadata on '{}'",
                                target
                            ),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            let cleared: Vec<(String, String)> = {
                let mut state_w = state.write().await;
                let entry = state_w.metadata.entry(target.clone()).or_default();
                entry.drain().collect()
            };

            if let Some(ref pool) = cfg.db {
                crate::persist::clear_metadata(pool, &target).await;
            }

            // Broadcast deletion events for each cleared key
            for (key, _) in &cleared {
                broadcast_metadata_event(
                    &state,
                    &channels,
                    &senders,
                    &setter_source,
                    client_id,
                    &target,
                    key,
                    None,
                )
                .await;
            }

            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "762",
                    vec![self_nick.clone(), "End of METADATA".to_string()],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }

        // ── SUB ───────────────────────────────────────────────────────────────
        "SUB" => {
            let keys: Vec<String> = msg.params.iter().skip(2).map(|s| s.to_string()).collect();
            if keys.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_INVALID".into(),
                            "*".into(),
                            " :no keys specified".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            for key in &keys {
                if !meta_key_valid(key) {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new(
                            "FAIL",
                            vec![
                                "METADATA".into(),
                                "KEY_INVALID".into(),
                                key.clone(),
                                " :invalid key".into(),
                            ],
                        )
                        .with_prefix(s),
                        label,
                    )
                    .await;
                    continue;
                }

                // Check limit and insert atomically under a single write lock
                let result: Result<(), ()> = {
                    let state_r = state.read().await;
                    if let Some(client) = state_r.clients.get(client_id) {
                        let mut g = client.write().await;
                        let already = g.metadata_subscriptions.contains(key);
                        if !already && g.metadata_subscriptions.len() >= MAX_SUBS {
                            Err(())
                        } else {
                            g.metadata_subscriptions.insert(key.clone());
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                };

                match result {
                    Err(()) => {
                        reply_to_client(
                            &senders,
                            client_id,
                            Message::new(
                                "FAIL",
                                vec![
                                    "METADATA".into(),
                                    "TOO_MANY_SUBS".into(),
                                    key.clone(),
                                    format!(":Subscription limit ({}) reached", MAX_SUBS),
                                ],
                            )
                            .with_prefix(s),
                            label,
                        )
                        .await;
                    }
                    Ok(()) => {
                        reply_to_client(
                            &senders,
                            client_id,
                            Message::new(
                                "770",
                                vec![self_nick.clone(), key.clone(), "Subscribed".to_string()],
                            )
                            .with_prefix(s),
                            label,
                        )
                        .await;
                    }
                }
            }
        }

        // ── UNSUB ─────────────────────────────────────────────────────────────
        "UNSUB" => {
            let keys: Vec<String> = msg.params.iter().skip(2).map(|s| s.to_string()).collect();
            if keys.is_empty() {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_INVALID".into(),
                            "*".into(),
                            " :no keys specified".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            for key in &keys {
                {
                    let state_r = state.read().await;
                    if let Some(client) = state_r.clients.get(client_id) {
                        client.write().await.metadata_subscriptions.remove(key);
                    }
                }
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "771",
                        vec![self_nick.clone(), key.clone(), "Unsubscribed".to_string()],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }
        }

        // ── SUBS ──────────────────────────────────────────────────────────────
        "SUBS" => {
            let subs: Vec<String> = {
                let state_r = state.read().await;
                match state_r.clients.get(client_id) {
                    Some(c) => c
                        .read()
                        .await
                        .metadata_subscriptions
                        .iter()
                        .cloned()
                        .collect(),
                    None => vec![],
                }
            };

            let batch_ref: Option<String> = if has_batch {
                Some(generate_msgid())
            } else {
                None
            };
            if let Some(ref ref_id) = batch_ref {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "BATCH",
                        vec![format!("+{}", ref_id), "metadata-subs".into()],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
            }

            for key in &subs {
                let mut m =
                    Message::new("772", vec![self_nick.clone(), key.clone()]).with_prefix(s);
                if let Some(ref ref_id) = batch_ref {
                    m.tags.insert("batch".to_string(), Some(ref_id.clone()));
                }
                reply_to_client(&senders, client_id, m, label).await;
            }

            let mut end = Message::new(
                "762",
                vec![self_nick.clone(), "End of METADATA".to_string()],
            )
            .with_prefix(s);
            if let Some(ref ref_id) = batch_ref {
                end.tags.insert("batch".to_string(), Some(ref_id.clone()));
            }
            reply_to_client(&senders, client_id, end, label).await;

            if let Some(ref ref_id) = batch_ref {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(s),
                    label,
                )
                .await;
            }
        }

        // ── SYNC ──────────────────────────────────────────────────────────────
        "SYNC" => {
            if !target_exists(&target, &state, &channels).await {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "INVALID_TARGET".into(),
                            target.clone(),
                            " :No such target".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            // Return all metadata for target (client can filter by their subscriptions locally)
            let entries: Vec<(String, String)> = {
                let state_r = state.read().await;
                state_r
                    .metadata
                    .get(&target)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default()
            };

            send_metadata_batch(
                &senders, client_id, &self_nick, &target, &entries, s, has_batch, label,
            )
            .await;
        }

        _ => {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "METADATA".into(),
                        "SUBCOMMAND_INVALID".into(),
                        "*".into(),
                        " :invalid subcommand".into(),
                    ],
                )
                .with_prefix(s),
                label,
            )
            .await;
        }
    }

    Ok(())
}
