//! draft/metadata-2: METADATA command (GET, LIST, SET, CLEAR, SUB, UNSUB, SUBS, SYNC).

use crate::channel::{canonical_channel_key, ChannelStore};
use crate::commands::reply_to_client;
use crate::config::Config;
use crate::protocol::{generate_msgid, Message};
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Max metadata keys allowed per target
const MAX_METADATA_KEYS: usize = 50;
/// A value has to come back out in RPL_KEYVALUE, which shares one 512-byte
/// line with the nick, the target and the key. Storing more than fits would
/// mean handing back something the client never sent.
const MAX_METADATA_VALUE_BYTES: usize = 400;
/// Max keys a client may subscribe to
const MAX_SUBS: usize = 50;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// The metadata specification has been through two capability names for the
/// same thing. Either one means the client wants metadata.
pub(crate) fn wants_metadata(caps: &std::collections::HashSet<String>) -> bool {
    caps.contains("draft/metadata-2") || caps.contains("draft/metadata-3")
}

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

/// Storage key for a target. IRC compares nicks and channel names
/// case-insensitively, so metadata set on "Alice" must be found by a client
/// asking about "alice". Replies still echo the spelling the client used.
pub(crate) fn metadata_key(target: &str) -> String {
    if is_channel(target) {
        canonical_channel_key(target)
    } else {
        crate::casefold::upper(target)
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
        channels
            .read()
            .await
            .channels
            .contains_key(&canonical_channel_key(target))
    } else {
        // nick_to_id is keyed by the uppercased nick.
        state
            .read()
            .await
            .nick_to_id
            .contains_key(&target.to_uppercase())
    }
}

/// Whether this client may read a target's metadata. A channel that hides its
/// membership hides what has been set on it too, or an invite-only channel
/// leaks through METADATA what it will not say through NAMES.
async fn may_read_metadata(
    target: &str,
    client_id: &str,
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
) -> bool {
    if !is_channel(target) {
        return true;
    }
    let user_id = state.read().await.user_id(client_id);
    let ch_store = channels.read().await;
    let Some(ch) = ch_store.channels.get(&canonical_channel_key(target)) else {
        return true;
    };
    let ch = ch.read().await;
    if !(ch.modes.invite_only || ch.modes.secret) {
        return true;
    }
    ch.is_member(&user_id)
}

/// Wrap a set of already-built replies in a `metadata` batch. Clients without
/// the batch capability get RPL_METADATAEND as the terminator instead.
#[allow(clippy::too_many_arguments)]
async fn send_in_metadata_batch(
    senders: &Senders,
    client_id: &str,
    nick: &str,
    target: &str,
    messages: Vec<Message>,
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

    for mut m in messages {
        if let Some(ref ref_id) = batch_ref {
            m.tags.insert("batch".to_string(), Some(ref_id.clone()));
        }
        reply_to_client(senders, client_id, m, label).await;
    }

    match batch_ref {
        Some(ref_id) => {
            reply_to_client(
                senders,
                client_id,
                Message::new("BATCH", vec![format!("-{}", ref_id)]).with_prefix(server_name),
                label,
            )
            .await
        }
        None => {
            reply_to_client(
                senders,
                client_id,
                Message::new("762", vec![nick.to_string(), "End of METADATA".to_string()])
                    .with_prefix(server_name),
                label,
            )
            .await
        }
    }
}

async fn send_metadata_batch(
    senders: &Senders,
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
                value.to_string(),
            ],
        )
        .with_prefix(server_name);
        if let Some(ref ref_id) = batch_ref {
            m.tags.insert("batch".to_string(), Some(ref_id.clone()));
        }
        reply_to_client(senders, client_id, m, label).await;
    }

    // The batch is its own terminator, so RPL_METADATAEND is only sent to a
    // client that is not getting one.
    if batch_ref.is_none() {
        let end_msg = Message::new("762", vec![nick.to_string(), "End of METADATA".to_string()])
            .with_prefix(server_name);
        reply_to_client(senders, client_id, end_msg, label).await;
    }

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
pub(crate) async fn broadcast_metadata_event(
    state: &Arc<RwLock<ServerState>>,
    channels: &Arc<RwLock<ChannelStore>>,
    senders: &Senders,
    setter_source: &str,
    setter_id: &str,
    server_name: &str,
    target: &str,
    key: &str,
    value: Option<&str>,
) {
    let mut params = vec![target.to_string(), key.to_string(), "*".to_string()];
    if let Some(v) = value {
        params.push(v.to_string());
    }
    let event = Message::new("METADATA", params).with_prefix(setter_source);

    // Step 1: collect candidate client IDs who can observe the target
    let candidate_ids: Vec<String> = if is_channel(target) {
        let ch_store = channels.read().await;
        match ch_store.channels.get(&canonical_channel_key(target)) {
            Some(ch) => ch.read().await.members.keys().cloned().collect(),
            None => return,
        }
    } else {
        // User target: clients sharing a channel with them, plus the user themselves
        let state_r = state.read().await;
        let target_id = match state_r.nick_to_id.get(&crate::casefold::upper(target)).cloned() {
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

    // Step 2: not the setter, wants metadata, and subscribed to this key.
    // The two versions of the specification notify differently, so each
    // recipient is told in the shape it negotiated.
    let state_r = state.read().await;
    let mut notify: Vec<(String, String, bool)> = Vec::new();
    for id in &candidate_ids {
        if id == setter_id {
            continue;
        }
        if let Some(client) = state_r.clients.get(id) {
            let g = client.read().await;
            if wants_metadata(&g.capabilities) && g.metadata_subscriptions.contains(key) {
                notify.push((
                    id.clone(),
                    g.nick_or_id().to_string(),
                    g.capabilities.contains("draft/metadata-3"),
                ));
            }
        }
    }
    drop(state_r);

    for (id, nick, as_numeric) in notify {
        let msg = if as_numeric {
            match value {
                Some(v) => Message::new(
                    "761",
                    vec![
                        nick,
                        target.to_string(),
                        key.to_string(),
                        "*".to_string(),
                        v.to_string(),
                    ],
                )
                .with_prefix(server_name),
                None => Message::new(
                    "766",
                    vec![
                        nick,
                        target.to_string(),
                        key.to_string(),
                        "key not set".to_string(),
                    ],
                )
                .with_prefix(server_name),
            }
        } else {
            event.clone()
        };
        senders.read().await.deliver(&id, &msg);
    }
}

/// Called by the JOIN handler to push current channel metadata to a newly joined client.
/// Pre-collected entries avoid re-acquiring the ServerState lock inside a read guard.
pub async fn send_channel_metadata_on_join(
    senders: &Senders,
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
    senders: Senders,
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

    tracing::debug!(client_id, target = %target_param, subcommand = %subcommand, "METADATA");

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
                    "invalid subcommand".into(),
                ],
            )
            .with_prefix(s),
            label,
        )
        .await;
        return Ok(());
    }

    let registered = state.read().await.clients.contains_key(client_id);
    if !registered {
        return handle_metadata_before_connect(
            client_id,
            &msg,
            target_param,
            &subcommand,
            state,
            senders,
            cfg,
            label,
        )
        .await;
    }

    let (self_nick, is_oper, setter_source, has_batch, self_account) = {
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
        (
            g.nick_or_id().to_string(),
            g.oper,
            src,
            has_batch,
            g.account.clone(),
        )
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
                            "invalid key".into(),
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
                            "No such target".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            if !may_read_metadata(&target, client_id, &state, &channels).await {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_NO_PERMISSION".into(),
                            target.clone(),
                            "*".into(),
                            format!("You are not in '{}'", target),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            let state_r = state.read().await;
            let meta = state_r.metadata.get(&metadata_key(&target));
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
                                "invalid key".into(),
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
                        value.to_string(),
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
                        "key not set".into(),
                    ],
                )
                .with_prefix(s);
                if let Some(ref ref_id) = batch_ref {
                    m.tags.insert("batch".to_string(), Some(ref_id.clone()));
                }
                reply_to_client(&senders, client_id, m, label).await;
            }

            if batch_ref.is_none() {
                let end = Message::new(
                    "762",
                    vec![self_nick.clone(), "End of METADATA".to_string()],
                )
                .with_prefix(s);
                reply_to_client(&senders, client_id, end, label).await;
            }

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
                            "No such target".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            if !may_read_metadata(&target, client_id, &state, &channels).await {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_NO_PERMISSION".into(),
                            target.clone(),
                            "*".into(),
                            format!("You are not in '{}'", target),
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
                    .get(&metadata_key(&target))
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
            // `METADATA <target> SET <key>` with nothing after it unsets the
            // key, so the value has to be read by position: the last parameter
            // of a three-parameter SET is the key, not an empty value.
            let value = msg.params.get(3).map(|s| s.to_string());

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
                            "invalid key".into(),
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
                            "invalid key".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            if let Some(ref v) = value {
                if v.len() > MAX_METADATA_VALUE_BYTES {
                    reply_to_client(
                        &senders,
                        client_id,
                        Message::new(
                            "FAIL",
                            vec![
                                "METADATA".into(),
                                "INVALID_VALUE".into(),
                                key.to_string(),
                                format!("Value is longer than {} bytes", MAX_METADATA_VALUE_BYTES),
                            ],
                        )
                        .with_prefix(s),
                        label,
                    )
                    .await;
                    return Ok(());
                }
            }

            // Permission check
            let can_set = if target == self_nick {
                true
            } else if is_channel(&target) {
                let uid = state.read().await.user_id(client_id);
                let ch_store = channels.read().await;
                if let Some(ch) = ch_store.channels.get(&target) {
                    ch.read()
                        .await
                        .members
                        .get(&uid)
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
                                "You do not have permission to set '{}' on '{}'",
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
                                "value too long".into(),
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
                let current_count = state_r
                    .metadata
                    .get(&metadata_key(&target))
                    .map(|m| m.len())
                    .unwrap_or(0);
                let already_set = state_r
                    .metadata
                    .get(&metadata_key(&target))
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
                                format!("Metadata key limit ({}) reached", MAX_METADATA_KEYS),
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
                let entry = state_w.metadata.entry(metadata_key(&target)).or_default();
                if let Some(ref val) = value {
                    entry.insert(key.to_string(), val.clone());
                } else {
                    entry.remove(key);
                }
                value.clone()
            };

            // Persist. A nick with no account behind it is not a lasting
            // identity: keeping its keys would hand them to whoever takes the
            // name next, and would grow the table for as long as names came
            // and went. Channels and accounts do persist.
            let lasting = is_channel(&target) || self_account.is_some();
            if let Some(ref pool) = cfg.db {
                if lasting {
                    if let Some(ref v) = new_value {
                        crate::persist::save_metadata(pool, &metadata_key(&target), key, v).await;
                    } else {
                        crate::persist::delete_metadata(pool, &metadata_key(&target), key).await;
                    }
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
                            v.to_string(),
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
                            "key not set".into(),
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
                s,
                &target,
                key,
                new_value.as_deref(),
            )
            .await;
            crate::link::announce_metadata(
                cfg,
                &state.read().await.user_id(client_id),
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
                let uid = state.read().await.user_id(client_id);
                let ch_store = channels.read().await;
                if let Some(ch) = ch_store.channels.get(&target) {
                    ch.read()
                        .await
                        .members
                        .get(&uid)
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
                            "*".into(),
                            format!(
                                "You do not have permission to clear metadata on '{}'",
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
                let entry = state_w.metadata.entry(metadata_key(&target)).or_default();
                entry.drain().collect()
            };

            if let Some(ref pool) = cfg.db {
                crate::persist::clear_metadata(pool, &metadata_key(&target)).await;
            }

            // Broadcast deletion events for each cleared key
            let setter_uid = state.read().await.user_id(client_id);
            for (key, _) in &cleared {
                broadcast_metadata_event(
                    &state,
                    &channels,
                    &senders,
                    &setter_source,
                    client_id,
                    s,
                    &target,
                    key,
                    None,
                )
                .await;
                crate::link::announce_metadata(cfg, &setter_uid, &target, key, None).await;
            }

            // One RPL_KEYNOTSET per key that was cleared, so the client knows
            // exactly what went.
            let cleared_msgs: Vec<Message> = cleared
                .iter()
                .map(|(key, _)| {
                    Message::new(
                        "766",
                        vec![
                            self_nick.clone(),
                            target.clone(),
                            key.clone(),
                            "key not set".to_string(),
                        ],
                    )
                    .with_prefix(s)
                })
                .collect();
            send_in_metadata_batch(
                &senders,
                client_id,
                &self_nick,
                &target,
                cleared_msgs,
                s,
                has_batch,
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
                            "no keys specified".into(),
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
                                "invalid key".into(),
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
                                    format!("Subscription limit ({}) reached", MAX_SUBS),
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
                            Message::new("770", vec![self_nick.clone(), key.clone()])
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
                            "no keys specified".into(),
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
                    Message::new("771", vec![self_nick.clone(), key.clone()]).with_prefix(s),
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
                            "No such target".into(),
                        ],
                    )
                    .with_prefix(s),
                    label,
                )
                .await;
                return Ok(());
            }

            if !may_read_metadata(&target, client_id, &state, &channels).await {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "FAIL",
                        vec![
                            "METADATA".into(),
                            "KEY_NO_PERMISSION".into(),
                            target.clone(),
                            "*".into(),
                            format!("You are not in '{}'", target),
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
                    .get(&metadata_key(&target))
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
                        "invalid subcommand".into(),
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

/// METADATA during registration. Only the connection's own keys are reachable
/// — there is no nick yet to name anyone else by, and nothing else on the
/// server is this connection's business until it has registered. What is set
/// here is handed to the user at the end of registration.
#[allow(clippy::too_many_arguments)]
async fn handle_metadata_before_connect(
    client_id: &str,
    msg: &Message,
    target_param: &str,
    subcommand: &str,
    state: Arc<RwLock<ServerState>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let s = &cfg.server.name;
    let fail = |code: &str, ctx: String, text: &str| {
        Message::new(
            "FAIL",
            vec!["METADATA".into(), code.into(), ctx, text.into()],
        )
        .with_prefix(s)
    };

    if target_param != "*" {
        reply_to_client(
            &senders,
            client_id,
            fail(
                "INVALID_TARGET",
                target_param.to_string(),
                "Only your own metadata can be set before registering",
            ),
            label,
        )
        .await;
        return Ok(());
    }

    let has_batch = {
        let state_r = state.read().await;
        state_r
            .pending
            .get(client_id)
            .map(|p| p.capabilities.contains("batch"))
            .unwrap_or(false)
    };

    match subcommand {
        "SET" => {
            let key = msg.params.get(2).map(|s| s.as_str()).unwrap_or("");
            let value = msg.params.get(3).map(|s| s.to_string());
            if key.is_empty() || !meta_key_valid(key) {
                reply_to_client(
                    &senders,
                    client_id,
                    fail(
                        "KEY_INVALID",
                        if key.is_empty() {
                            "*".into()
                        } else {
                            key.into()
                        },
                        "invalid key",
                    ),
                    label,
                )
                .await;
                return Ok(());
            }
            if let Some(ref v) = value {
                if v.len() > MAX_METADATA_VALUE_BYTES {
                    reply_to_client(
                        &senders,
                        client_id,
                        fail(
                            "INVALID_VALUE",
                            key.to_string(),
                            &format!("Value is longer than {} bytes", MAX_METADATA_VALUE_BYTES),
                        ),
                        label,
                    )
                    .await;
                    return Ok(());
                }
            }

            let mut state_w = state.write().await;
            let Some(pending) = state_w.pending.get_mut(client_id) else {
                return Ok(());
            };
            let reply = match value {
                Some(v) => {
                    if pending.metadata.len() >= MAX_METADATA_KEYS
                        && !pending.metadata.contains_key(key)
                    {
                        drop(state_w);
                        reply_to_client(
                            &senders,
                            client_id,
                            fail(
                                "LIMIT_REACHED",
                                key.to_string(),
                                &format!("Metadata key limit ({}) reached", MAX_METADATA_KEYS),
                            ),
                            label,
                        )
                        .await;
                        return Ok(());
                    }
                    pending.metadata.insert(key.to_string(), v.clone());
                    Message::new(
                        "761",
                        vec!["*".into(), "*".into(), key.into(), "*".into(), v],
                    )
                }
                None => {
                    pending.metadata.remove(key);
                    Message::new(
                        "766",
                        vec!["*".into(), "*".into(), key.into(), "key not set".into()],
                    )
                }
            };
            drop(state_w);
            reply_to_client(&senders, client_id, reply.with_prefix(s), label).await;
        }
        "GET" | "LIST" => {
            let stored: Vec<(String, String)> = {
                let state_r = state.read().await;
                state_r
                    .pending
                    .get(client_id)
                    .map(|p| {
                        p.metadata
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let wanted: Vec<String> = if subcommand == "GET" {
                msg.params.iter().skip(2).map(|k| k.to_string()).collect()
            } else {
                stored.iter().map(|(k, _)| k.clone()).collect()
            };
            let messages: Vec<Message> = wanted
                .iter()
                .map(|key| {
                    match stored.iter().find(|(k, _)| k == key) {
                        Some((_, v)) => Message::new(
                            "761",
                            vec!["*".into(), "*".into(), key.clone(), "*".into(), v.clone()],
                        ),
                        None => Message::new(
                            "766",
                            vec!["*".into(), "*".into(), key.clone(), "key not set".into()],
                        ),
                    }
                    .with_prefix(s)
                })
                .collect();
            send_in_metadata_batch(&senders, client_id, "*", "*", messages, s, has_batch, label)
                .await;
        }
        _ => {
            reply_to_client(
                &senders,
                client_id,
                Message::new("451", vec!["*".into(), "You have not registered".into()])
                    .with_prefix(s),
                label,
            )
            .await;
        }
    }
    Ok(())
}
