use crate::channel::{
    canonical_channel_key, Channel, ChannelMemberModeSet, ChannelMembership, ChannelStore,
};
use crate::commands::{
    end_labeled_batch, reply_in_batch, reply_to_client, session_caps, start_labeled_batch,
};
use crate::config::Config;
use crate::protocol::{add_batch_tag, generate_msgid, Message};
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

/// Constant-time byte comparison for secrets (channel keys, passwords).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Deliver to a user: every connection they have open, not just one.
///
/// Channel members and message targets are users, and a user may be reading on
/// more than one connection at a time.
async fn send_to_client(senders: &Senders, user_id: &str, msg: Message) {
    senders.read().await.deliver(user_id, &msg);
}

/// JOIN answers with several messages — the JOIN itself, the topic, the names —
/// so a labeled JOIN needs them wrapped in a labeled-response batch rather than
/// each carrying the label on its own.
pub async fn handle_join(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let wants_batch = match label {
        Some(_) => session_caps(&senders, client_id).await.contains("batch"),
        None => false,
    };
    let batch_ref = match (label, wants_batch) {
        (Some(l), true) => {
            Some(start_labeled_batch(&senders, client_id, l, &cfg.server.name).await)
        }
        _ => None,
    };

    let result = handle_join_inner(
        client_id,
        msg,
        state,
        channels,
        senders.clone(),
        cfg,
        label,
        batch_ref.as_deref(),
    )
    .await;

    if let Some(ref br) = batch_ref {
        end_labeled_batch(&senders, client_id, br, &cfg.server.name).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_join_inner(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
    batch_ref: Option<&str>,
) -> anyhow::Result<()> {
    // Every message the joining client gets belongs to its JOIN, so each is
    // tagged into the batch when there is one.
    macro_rules! reply_self {
        ($msg:expr) => {
            match batch_ref {
                Some(br) => reply_in_batch(&senders, client_id, $msg, br).await,
                None => reply_to_client(&senders, client_id, $msg, label).await,
            }
        };
    }
    let state_arc = state.clone();
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => {
            reply_self!(
                Message::new("451", vec!["*".into(), "You have not registered".into()])
                    .with_prefix(&cfg.server.name)
            );
            return Ok(());
        }
    };

    let ch_names = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if ch_names.is_empty() {
        reply_self!(
            Message::new("461", vec!["JOIN".into(), "Not enough parameters".into()])
                .with_prefix(&cfg.server.name)
        );
        return Ok(());
    }

    let client_data = client.read().await;
    let source = client_data
        .source()
        .unwrap_or_else(|| client_data.nick_or_id().to_string());
    let nick = client_data.nick_or_id().to_string();
    // Channel membership is the user's, not this one connection's.
    let user_id = client_data.id.clone();

    let account = client_data.account.clone();
    let is_oper = client_data.oper;
    drop(client_data);
    // What this connection negotiated, not what the person behind it did on
    // some other client: a reply belongs to the one that asked.
    let client_caps = session_caps(&senders, client_id).await;

    // Collected while the state read guard is held, applied once it is released.
    let mut remembered_memberships: Vec<(String, String)> = Vec::new();
    // The channels this JOIN founded, each with the account that founded it and
    // the moment the channel was made. One JOIN can name several channels, and
    // founding one of them says nothing about the others.
    let mut new_founders: Vec<(String, String, i64)> = Vec::new();

    // JOIN 0: part all channels the client is currently in
    if ch_names.trim() == "0" {
        let client_arc = match state.clients.get(client_id) {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let joined_channels: Vec<String> =
            client_arc.read().await.channels.keys().cloned().collect();
        // Channel membership belongs to the user, not to one of its connections.
        let user_id = client_arc.read().await.id.clone();
        drop(state); // release ServerState read guard
        for ch_key in &joined_channels {
            let part_msg =
                Message::new("PART", vec![ch_key.clone(), "Leaving all channels".into()])
                    .with_prefix(&source);
            let member_ids: Vec<String> = {
                let ch_store = channels.write().await;
                if let Some(ch_lock) = ch_store.channels.get(ch_key) {
                    let mut ch = ch_lock.write().await;
                    let ids: Vec<String> = ch.members.keys().cloned().collect();
                    ch.members.remove(&user_id);
                    ch.invite_list.remove(&user_id);
                    ids
                } else {
                    vec![]
                }
            };
            for mid in &member_ids {
                senders.read().await.deliver(mid, &part_msg);
            }
        }
        client_arc.write().await.channels.clear();
        return Ok(());
    }

    // Parse comma-separated keys (JOIN #a,#b key1,key2)
    let keys_str = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let keys: Vec<&str> = if keys_str.is_empty() {
        Vec::new()
    } else {
        keys_str.split(',').collect()
    };

    for (ch_idx, ch_name) in ch_names.split(',').enumerate() {
        let ch_name = ch_name.trim();
        if ch_name.is_empty()
            || !ch_name.starts_with('#')
            || ch_name.len() > 64
            || ch_name.contains(' ')
            || ch_name.contains(',')
            || ch_name.contains('\x07')
            || ch_name.contains('\x00')
        {
            reply_self!(Message::new(
                "403",
                vec![nick.clone(), ch_name.to_string(), "No such channel".into()],
            )
            .with_prefix(&cfg.server.name));
            continue;
        }
        let provided_key = keys.get(ch_idx).copied().unwrap_or("");

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
            reply_self!(Message::new(
                "405",
                vec![
                    nick,
                    ch_name.to_string(),
                    "You have joined too many channels".into(),
                ],
            )
            .with_prefix(&cfg.server.name));
            continue;
        }

        let ch_key = canonical_channel_key(ch_name);

        let mut ch_store = channels.write().await;
        // Bringing a channel into being is a different act from walking into
        // one, and a network may want to say who can do it. Joining a channel
        // that already exists is never gated here — that is what the channel's
        // own modes are for.
        if !ch_store.channels.contains_key(&ch_key) {
            let refusal = match cfg.server.channel_creation {
                crate::config::ChannelCreation::Anyone => None,
                crate::config::ChannelCreation::Accounts if account.is_none() => Some((
                    "477",
                    "You must be logged in to an account to create a channel",
                )),
                crate::config::ChannelCreation::Opers if !is_oper => Some((
                    "481",
                    "Only a network operator can create a channel here",
                )),
                _ => None,
            };
            if let Some((numeric, text)) = refusal {
                drop(ch_store);
                reply_self!(Message::new(
                    numeric,
                    vec![nick.clone(), ch_name.to_string(), text.into()],
                )
                .with_prefix(&cfg.server.name));
                continue;
            }
        }
        let ch = ch_store
            .channels
            .entry(ch_key.clone())
            .or_insert_with(|| RwLock::new(Channel::new(ch_name.to_string())));

        let mut ch = ch.write().await;
        if ch.is_member(&user_id) {
            // Another connection of this user is already in the channel, so the
            // channel does not change and nobody else hears anything. This
            // connection has never been told what is in here, though, so it
            // gets the burst a fresh join would get — otherwise a second client
            // on the same account shows an empty window for a channel it is in.
            let catch_up = senders.read().await.sessions_of(&user_id).len() > 1;
            let topic = ch.topic.clone();
            let topic_setter = ch.topic_setter.clone();
            let topic_time = ch.topic_time;
            drop(ch);
            if !catch_up {
                continue;
            }
            let realname = match state.clients.get(client_id) {
                Some(c) => c
                    .read()
                    .await
                    .realname
                    .clone()
                    .unwrap_or_else(|| "*".to_string()),
                None => "*".to_string(),
            };
            let join_msg = if client_caps.contains("extended-join") {
                Message::new(
                    "JOIN",
                    vec![
                        ch_key.clone(),
                        account.clone().unwrap_or_else(|| "*".to_string()),
                        realname,
                    ],
                )
                .with_prefix(&source)
            } else {
                Message::new("JOIN", vec![ch_key.clone()]).with_prefix(&source)
            };
            reply_self!(join_msg);
            if let Some(ref topic_str) = topic {
                reply_self!(Message::new(
                    "332",
                    vec![nick.clone(), ch_key.clone(), topic_str.clone()],
                )
                .with_prefix(&cfg.server.name));
                reply_self!(Message::new(
                    "333",
                    vec![
                        nick.clone(),
                        ch_key.clone(),
                        topic_setter.as_deref().unwrap_or("*").to_string(),
                        topic_time.unwrap_or(0).to_string(),
                    ],
                )
                .with_prefix(&cfg.server.name));
            }
            if !client_caps.contains("no-implicit-names") {
                if let Some(ch_ref) = ch_store.channels.get(&ch_key) {
                    send_names_for_channel(
                        ch_ref,
                        &ch_key,
                        &nick,
                        &state,
                        &senders,
                        client_id,
                        &cfg.server.name,
                        &client_caps,
                        label,
                        batch_ref,
                    )
                    .await;
                }
            }
            continue;
        }

        // Somebody who holds the channel cannot be shut out of it. A registered
        // channel keeps its modes now when the last person leaves, so +b, +i,
        // +k and +l on an empty room would otherwise be a door that locks from
        // the inside — the founder sets one, goes to bed, and never gets back
        // in. Only an account counts here: a nick on the operator list is not
        // proof of who is typing it.
        let holds_the_channel = account.as_deref().is_some_and(|a| {
            a.eq_ignore_ascii_case(&ch.founder)
                || ch
                    .persisted_operators
                    .iter()
                    .any(|o| o.eq_ignore_ascii_case(a))
        });

        // An invitation is permission to come in. Refusing the person you just
        // invited is not a safer channel, it is a broken invitation.
        //
        // This is only safe because INVITE needs the op: if any member could
        // invite, a ban would be one message away from being lifted by anyone
        // it did not apply to.
        if ch.is_banned(account.as_deref(), &source)
            && !ch.is_ban_exempt(account.as_deref(), &source)
            && !ch.invite_list.contains(&user_id)
            && !holds_the_channel
        {
            reply_self!(Message::new(
                "474",
                vec![
                    nick.clone(),
                    ch_name.to_string(),
                    "Cannot join channel (+b)".into(),
                ],
            )
            .with_prefix(&cfg.server.name));
            continue;
        }

        if ch.modes.registered_only && account.is_none() {
            reply_self!(Message::new(
                "477",
                vec![
                    nick.clone(),
                    ch_name.to_string(),
                    "Cannot join channel (+R) - you must be registered".into(),
                ],
            )
            .with_prefix(&cfg.server.name));
            continue;
        }

        if ch.modes.invite_only
            && !ch.invite_list.contains(&user_id)
            && !ch.is_invite_exempt(account.as_deref(), &source)
            && !holds_the_channel
        {
            reply_self!(Message::new(
                "473",
                vec![
                    nick.clone(),
                    ch_name.to_string(),
                    "Cannot join channel (+i)".into(),
                ],
            )
            .with_prefix(&cfg.server.name));
            continue;
        }

        if let Some(ref key) = ch.key {
            // Constant-time comparison to prevent timing attacks on channel keys
            if !ct_eq(provided_key.as_bytes(), key.as_bytes())
                && !ch.invite_list.contains(&user_id)
                && !holds_the_channel
            {
                reply_self!(Message::new(
                    "475",
                    vec![
                        nick.clone(),
                        ch_name.to_string(),
                        "Cannot join channel (+k)".into(),
                    ],
                )
                .with_prefix(&cfg.server.name));
                continue;
            }
        }

        // An invitation is permission to come in, so it outlasts a full
        // channel: refusing someone you just invited defeats the invite.
        if let Some(limit) = ch.modes.user_limit {
            if ch.member_count() >= limit as usize
                && !ch.invite_list.contains(&user_id)
                && !holds_the_channel
            {
                reply_self!(Message::new(
                    "471",
                    vec![
                        nick.clone(),
                        ch_name.to_string(),
                        "Cannot join channel (+l)".into(),
                    ],
                )
                .with_prefix(&cfg.server.name));
                continue;
            }
        }

        let is_first = ch.members.is_empty();
        let (persisted_op, persisted_voice) = ch.persisted_modes_for(account.as_deref());
        // Whoever creates a channel while logged in becomes its founder, and is
        // opped whenever they return.
        if is_first && ch.founder.is_empty() {
            if let Some(ref acct) = account {
                ch.founder = acct.clone();
                new_founders.push((ch_key.clone(), acct.clone(), ch.created_at));
                if !ch.persisted_operators.iter().any(|o| o == acct) {
                    ch.persisted_operators.push(acct.clone());
                }
            }
        }
        let persisted_op = persisted_op
            || account
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(&ch.founder));
        // Being first through the door makes somebody an operator only when
        // there is nobody the channel already belongs to. A channel that keeps
        // its founder, its access list and its modes when the last person
        // leaves would otherwise hand `@` to whoever came back first — which is
        // every restart, and every quiet hour, and is exactly the takeover that
        // keeping the channel was meant to stop.
        let modes = ChannelMemberModeSet {
            op: persisted_op || (is_first && !ch.is_registered()),
            voice: persisted_voice,
            ..Default::default()
        };
        // Membership belongs to the user: a second connection on the same
        // account is the same person in the channel, listed once.
        ch.members.insert(
            user_id.clone(),
            ChannelMembership {
                client_id: user_id.clone(),
                modes: modes.clone(),
            },
        );
        // An invitation is spent by walking through the door it opened. Left
        // standing, it would be a permanent exemption from a ban that whoever
        // set the ban never granted.
        ch.invite_list.remove(&user_id);
        tracing::debug!(client_id, nick = %nick, channel = %ch_key, op = is_first, "JOIN");

        if let Some(client) = state.clients.get(client_id) {
            let mut c = client.write().await;
            c.channels.insert(
                ch_key.clone(),
                ChannelMembership {
                    client_id: user_id.clone(),
                    modes,
                },
            );
        }

        let joining_account = match state.clients.get(client_id) {
            Some(c) => c
                .read()
                .await
                .account
                .clone()
                .unwrap_or_else(|| "*".to_string()),
            None => "*".to_string(),
        };
        let joining_realname = match state.clients.get(client_id) {
            Some(c) => c
                .read()
                .await
                .realname
                .clone()
                .unwrap_or_else(|| "*".to_string()),
            None => "*".to_string(),
        };
        let member_ids: Vec<String> = ch.members.keys().cloned().collect();
        let topic = ch.topic.clone();
        let topic_setter = ch.topic_setter.clone();
        let topic_time = ch.topic_time;
        // What the rest of the network is told. A channel that has just come
        // into being is announced whole — its age, its modes and the person who
        // made it — because its age is what settles whose channel it is when
        // another server already has one of that name. A join to a channel that
        // was already here says only who joined.
        let channel_ts = ch.created_at;
        let channel_modes = ch.mode_string();
        let announce_whole = ch.members.len() == 1;
        let member_token = format!(
            "{}{}",
            ch.members
                .get(&user_id)
                .map(|m| m.modes.prefixes_ordered())
                .unwrap_or_default(),
            user_id
        );
        drop(ch);
        // One event happened at one time. Stamping each copy as it is built
        // gives two people in the same channel two different times for the
        // same join, and history a third.
        let happened_at = crate::protocol::server_time_now();
        // `extended-join` changes what a JOIN looks like, and it is negotiated
        // by a connection rather than by the person behind it: each client is
        // shown the form it asked for, even when two of them are the same user.
        let mut long_join = Message::new(
            "JOIN",
            vec![
                ch_key.clone(),
                joining_account.clone(),
                joining_realname.clone(),
            ],
        )
        .with_prefix(&source);
        let mut short_join = Message::new("JOIN", vec![ch_key.clone()]).with_prefix(&source);
        for m in [&mut long_join, &mut short_join] {
            m.tags.insert("time".to_string(), Some(happened_at.clone()));
        }
        for mid in &member_ids {
            let registry = senders.read().await;
            // The joining client's own copy is part of the answer to its JOIN,
            // so it goes inside the labeled batch; everyone else's does not —
            // including the user's own other connections, which are watching
            // someone join a channel rather than answering for it.
            if *mid == user_id {
                let own = if registry.caps_of(client_id).contains("extended-join") {
                    long_join.clone()
                } else {
                    short_join.clone()
                };
                drop(registry);
                reply_self!(own);
                senders.read().await.deliver_by_cap_except(
                    mid,
                    "extended-join",
                    Some(client_id),
                    Some(&long_join),
                    Some(&short_join),
                );
            } else {
                registry.deliver_by_cap(mid, "extended-join", Some(&long_join), Some(&short_join));
            }
        }

        // away-notify: if the joining user is away, send AWAY to channel members with the cap
        let joining_away = match state.clients.get(client_id) {
            Some(c) => c.read().await.away_message.clone(),
            None => None,
        };
        if let Some(ref away_msg) = joining_away {
            let away_notify = Message::new("AWAY", vec![away_msg.clone()]).with_prefix(&source);
            let registry = senders.read().await;
            for mid in &member_ids {
                if *mid == user_id {
                    continue;
                }
                registry.deliver_requiring(mid, "away-notify", &away_notify);
            }
        }

        if announce_whole {
            crate::link::announce_channel(cfg, channel_ts, &ch_key, channel_modes, &member_token)
                .await;
        } else {
            crate::link::announce_join(cfg, &user_id, channel_ts, &ch_key).await;
        }

        // Record JOIN event for draft/event-playback
        cfg.record_history_at(&ch_key, &source, "", None, "JOIN", &happened_at);

        // Remember the membership for this account, so a mention can still reach
        // them by push once they disconnect.
        if let Some(ref account) = account {
            remembered_memberships.push((ch_key.clone(), account.clone()));
        }

        if let Some(ref topic_str) = topic {
            reply_self!(
                Message::new("332", vec![nick.clone(), ch_key.clone(), topic_str.clone()])
                    .with_prefix(&cfg.server.name)
            );
            // 333 RPL_TOPICWHOTIME
            let setter = topic_setter.as_deref().unwrap_or("*");
            let time_str = topic_time.unwrap_or(0).to_string();
            reply_self!(Message::new(
                "333",
                vec![nick.clone(), ch_key.clone(), setter.to_string(), time_str],
            )
            .with_prefix(&cfg.server.name));
        }
        // draft/read-marker: the marker has to reach the client before
        // RPL_ENDOFNAMES, so it is sent ahead of the NAMES burst.
        if client_caps.contains("draft/read-marker") {
            let key = account.clone().unwrap_or_else(|| user_id.clone());
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
            let m = Message::new("MARKREAD", vec![ch_key.clone(), ts_param])
                .with_prefix(&cfg.server.name);
            reply_self!(m);
        }

        // no-implicit-names: send NAMES to joining user unless they have the cap
        if !client_caps.contains("no-implicit-names") {
            if let Some(ch_ref) = ch_store.channels.get(&ch_key) {
                send_names_for_channel(
                    ch_ref,
                    &ch_key,
                    &nick,
                    &state,
                    &senders,
                    client_id,
                    &cfg.server.name,
                    &client_caps,
                    label,
                    batch_ref,
                )
                .await;
            }
        }
        // RPL_CHANNELMODEIS (324) and RPL_CREATIONTIME (329) answer `MODE
        // #channel`. Sending them on JOIN too puts unasked-for numerics between
        // the JOINs of a multi-channel join, which clients read positionally.
        // draft/metadata-2: push existing channel metadata to the joining client
        if crate::commands::metadata::wants_metadata(&client_caps) {
            let ch_meta: Vec<(String, String)> = state
                .metadata
                .get(&ch_key)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            crate::commands::metadata::send_channel_metadata_on_join(
                &senders,
                client_id,
                &ch_key,
                &nick,
                &cfg.server.name,
                client_caps.contains("batch"),
                ch_meta,
            )
            .await;

            // Joining brings the other members into view, so the keys this
            // client subscribed to are sent for the people it can now see.
            let subs: std::collections::HashSet<String> = match state.clients.get(client_id) {
                Some(c) => c.read().await.metadata_subscriptions.clone(),
                None => Default::default(),
            };
            for mid in member_ids
                .iter()
                .filter(|m| **m != user_id)
                .take_while(|_| !subs.is_empty())
            {
                let member_nick = match state.clients.get(mid) {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => continue,
                };
                let member_key =
                    crate::commands::metadata::metadata_key_in(&member_nick, &state).await;
                let entries: Vec<(String, String)> = state
                    .metadata
                    .get(&member_key)
                    .map(|m| {
                        m.iter()
                            .filter(|(k, _)| subs.contains(*k))
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                for (key, value) in entries {
                    reply_self!(Message::new(
                        "761",
                        vec![nick.clone(), member_nick.clone(), key, "*".into(), value,],
                    )
                    .with_prefix(&cfg.server.name));
                }
            }
        }
    }

    drop(state);
    if !remembered_memberships.is_empty() {
        {
            let mut state_w = state_arc.write().await;
            for (ch_key, account) in &remembered_memberships {
                state_w
                    .channel_accounts
                    .entry(ch_key.clone())
                    .or_default()
                    .insert(account.to_lowercase());
            }
        }
        if let Some(ref pool) = cfg.db {
            for (ch_key, account) in &remembered_memberships {
                crate::persist::record_account_channel(pool, account, ch_key).await;
            }
        }
    }
    for (ch_key, founder, created_at) in &new_founders {
        if let Some(ref pool) = cfg.db {
            crate::persist::set_channel_founder(pool, ch_key, founder).await;
            crate::persist::set_channel_access(pool, ch_key, founder, true, true).await;
        }
        // A founder the rest of the network does not know about is a founder
        // only here, and the next server somebody joins from would hand the
        // channel to whoever arrived first there.
        crate::link::announce_channel_access(cfg, ch_key, *created_at, 'f', std::slice::from_ref(founder))
            .await;
        crate::link::announce_channel_access(cfg, ch_key, *created_at, 'o', std::slice::from_ref(founder))
            .await;
    }

    Ok(())
}

pub async fn handle_part(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state_arc = state.clone();
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let source = client
        .read()
        .await
        .source()
        .unwrap_or_else(|| client_id.to_string());
    let user_id = client.read().await.id.clone();
    let ch_names = msg.params.first().map(|s| s.as_str()).unwrap_or("");

    let parting_account = match state.clients.get(client_id) {
        Some(c) => c.read().await.account.clone(),
        None => None,
    };
    // Collected while the state read guard is held, applied once it is released.
    let mut forgotten_memberships: Vec<(String, String)> = Vec::new();
    // params[1], not trailing(): `PART #chan` has no reason, and trailing()
    // would hand back the channel name as one.
    let reason = msg
        .params
        .get(1)
        .cloned()
        .unwrap_or_else(|| "Leaving".to_string());

    for ch_name in ch_names.split(',') {
        let ch_name = ch_name.trim();
        if ch_name.is_empty() || !ch_name.starts_with('#') && !ch_name.starts_with('&') {
            continue;
        }
        let ch_key = canonical_channel_key(ch_name);

        let happened_at = crate::protocol::server_time_now();
        let mut part_msg =
            Message::new("PART", vec![ch_name.to_string(), reason.clone()]).with_prefix(&source);
        part_msg
            .tags
            .insert("time".to_string(), Some(happened_at.clone()));

        let mut ch_store = channels.write().await;
        let mut should_remove = false;
        if !ch_store.channels.contains_key(&ch_key) {
            let nick = client.read().await.nick_or_id().to_string();
            drop(ch_store);
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "403",
                    vec![nick, ch_name.to_string(), "No such channel".into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            continue;
        }
        if let Some(ch_rw) = ch_store.channels.get_mut(&ch_key) {
            let mut ch = ch_rw.write().await;
            if !ch.is_member(&state.user_id(client_id)) {
                // Not in channel — send 442 ERR_NOTONCHANNEL and skip
                let nick = client.read().await.nick_or_id().to_string();
                drop(ch);
                drop(ch_store);
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "442",
                        vec![
                            nick,
                            ch_name.to_string(),
                            "You're not on that channel".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                continue;
            }
            for mid in ch.members.clone().keys() {
                senders.read().await.deliver(mid, &part_msg);
            }
            ch.members.remove(&user_id);
            should_remove = ch.members.is_empty() && !ch.is_registered();
        }
        if should_remove {
            tracing::debug!(channel = %ch_key, "Channel empty and unclaimed, forgetting it");
            ch_store.channels.remove(&ch_key);
        }
        drop(ch_store);
        crate::link::announce_part(cfg, &user_id, &ch_key, Some(&reason)).await;
        tracing::debug!(client_id, channel = %ch_name, reason = %reason, "PART");

        // Record PART event for draft/event-playback
        cfg.record_history_at(&ch_key, &source, &reason, None, "PART", &happened_at);

        // Leaving a channel means no more notifications from it.
        if let Some(ref account) = parting_account {
            forgotten_memberships.push((ch_key.clone(), account.clone()));
        }

        if let Some(client) = state.clients.get(client_id) {
            let mut c = client.write().await;
            c.channels.remove(&ch_key);
        }
    }

    drop(state);
    if !forgotten_memberships.is_empty() {
        {
            let mut state_w = state_arc.write().await;
            for (ch_key, account) in &forgotten_memberships {
                if let Some(set) = state_w.channel_accounts.get_mut(ch_key) {
                    set.remove(&account.to_lowercase());
                    // An empty set is a channel nobody is remembered in. Left
                    // behind, every channel that ever existed keeps a row here.
                    if set.is_empty() {
                        state_w.channel_accounts.remove(ch_key);
                    }
                }
            }
        }
        if let Some(ref pool) = cfg.db {
            for (ch_key, account) in &forgotten_memberships {
                crate::persist::forget_account_channel(pool, account, Some(ch_key)).await;
            }
        }
    }

    Ok(())
}

pub async fn handle_names(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();
    let client_caps = session_caps(&senders, client_id).await;

    let ch_names: Vec<&str> = msg
        .params
        .first()
        .map(|s| s.split(',').collect())
        .unwrap_or_default();
    let ch_store = channels.read().await;

    if ch_names.is_empty() {
        for (ch_name, ch) in &ch_store.channels {
            send_names_for_channel(
                ch,
                ch_name,
                &nick,
                &state,
                &senders,
                client_id,
                &cfg.server.name,
                &client_caps,
                label,
                None,
            )
            .await;
        }
        return Ok(());
    }

    // `NAMES #a,#b` is one command with one answer: a list per channel, then a
    // single RPL_ENDOFNAMES naming what was asked for. Ending each channel
    // separately would look like several answers to a client that sent one.
    let asked_for = msg.params.first().cloned().unwrap_or_default();
    let single = ch_names.len() == 1;

    for ch_name in ch_names {
        let ch_key = canonical_channel_key(ch_name);
        match ch_store.channels.get(&ch_key) {
            Some(ch) if single => {
                send_names_for_channel(
                    ch,
                    &ch_key,
                    &nick,
                    &state,
                    &senders,
                    client_id,
                    &cfg.server.name,
                    &client_caps,
                    label,
                    None,
                )
                .await;
            }
            Some(ch) => {
                send_name_reply_for_channel(
                    ch,
                    &ch_key,
                    &nick,
                    &state,
                    &senders,
                    client_id,
                    &cfg.server.name,
                    &client_caps,
                    label,
                )
                .await;
            }
            // "If the channel name is invalid or the channel does not exist,
            // one RPL_ENDOFNAMES containing the given channel name should be
            // returned" — Modern §names-message. There is no error reply.
            None if single => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "366",
                        vec![
                            nick.clone(),
                            ch_name.to_string(),
                            "End of /NAMES list".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            None => {}
        }
    }

    if !single {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "366",
                vec![nick.clone(), asked_for, "End of /NAMES list".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
    }

    Ok(())
}

/// One channel's RPL_NAMREPLY, without the RPL_ENDOFNAMES that closes a list.
/// Used when several channels are answered under one ending.
#[allow(clippy::too_many_arguments)]
async fn send_name_reply_for_channel(
    ch: &RwLock<Channel>,
    ch_name: &str,
    nick: &str,
    state: &ServerState,
    senders: &Senders,
    client_id: &str,
    server: &str,
    client_caps: &std::collections::HashSet<String>,
    label: Option<&str>,
) {
    let ch = ch.read().await;
    let use_userhost = client_caps.contains("userhost-in-names");
    let use_multi_prefix = client_caps.contains("multi-prefix");
    let mut names = Vec::new();
    for (mid, memb) in &ch.members {
        if let Some(c) = state.clients.get(mid) {
            let c = c.read().await;
            let prefix_str = if use_multi_prefix {
                memb.modes.prefixes_ordered()
            } else {
                memb.modes.prefix().to_string()
            };
            let who = if use_userhost {
                c.source().unwrap_or_else(|| c.nick_or_id().to_string())
            } else {
                c.nick_or_id().to_string()
            };
            names.push(format!("{}{}", prefix_str, who));
        }
    }
    let chan_prefix = if ch.modes.secret { "@" } else { "=" };
    reply_to_client(
        senders,
        client_id,
        Message::new(
            "353",
            vec![
                nick.into(),
                chan_prefix.into(),
                ch_name.into(),
                names.join(" "),
            ],
        )
        .with_prefix(server),
        label,
    )
    .await;
}

pub(crate) async fn send_names_for_channel(
    ch: &RwLock<Channel>,
    ch_name: &str,
    nick: &str,
    state: &ServerState,
    senders: &Senders,
    client_id: &str,
    server: &str,
    client_caps: &std::collections::HashSet<String>,
    label: Option<&str>,
    parent_batch: Option<&str>,
) {
    let ch = ch.read().await;
    // Report the channel under its own name rather than the case-folded key.
    let ch_name = if ch.name.is_empty() {
        ch_name
    } else {
        ch.name.as_str()
    };
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
                format!(
                    "{}{}",
                    prefix_str,
                    c.source().unwrap_or_else(|| c.nick_or_id().to_string())
                )
            } else {
                format!("{}{}", prefix_str, c.nick_or_id())
            };
            names.push(entry);
        }
    }
    let names_str = names.join(" ");
    // RPL_NAMREPLY channel type prefix: @ = secret, = = public
    let chan_prefix = if ch.modes.secret { "@" } else { "=" };
    let use_batch = client_caps.contains("batch") && client_caps.contains("message-tags");

    if use_batch {
        let batch_ref = generate_msgid();
        let batch_start = Message::new(
            "BATCH",
            vec![format!("+{}", batch_ref), "names".into(), ch_name.into()],
        )
        .with_prefix(server);
        let batch_end = Message::new("BATCH", vec![format!("-{}", batch_ref)]).with_prefix(server);
        let msg = add_batch_tag(
            Message::new(
                "353",
                vec![
                    nick.into(),
                    chan_prefix.into(),
                    ch_name.into(),
                    names_str.clone(),
                ],
            )
            .with_prefix(server),
            &batch_ref,
        );
        let end_msg = add_batch_tag(
            Message::new(
                "366",
                vec![nick.into(), ch_name.into(), "End of /NAMES list".into()],
            )
            .with_prefix(server),
            &batch_ref,
        );
        // labeled-response: the label goes on the BATCH start, not on the
        // messages inside it. When this batch is itself inside one — a JOIN's
        // labeled response — it is the nesting that ties it to the command, so
        // its opening and closing lines carry the parent's reference instead.
        match parent_batch {
            // Inside another batch — a JOIN's labeled response — these are just
            // more of that answer, so they join it directly. A batch of their
            // own would put them one level down, where a client reading the
            // labeled response does not look for them.
            Some(parent) => {
                let names = Message::new(
                    "353",
                    vec![
                        nick.into(),
                        chan_prefix.into(),
                        ch_name.into(),
                        names_str.clone(),
                    ],
                )
                .with_prefix(server);
                let end = Message::new(
                    "366",
                    vec![nick.into(), ch_name.into(), "End of /NAMES list".into()],
                )
                .with_prefix(server);
                reply_in_batch(senders, client_id, names, parent).await;
                reply_in_batch(senders, client_id, end, parent).await;
            }
            None => {
                reply_to_client(senders, client_id, batch_start, label).await;
                reply_to_client(senders, client_id, msg, None).await;
                reply_to_client(senders, client_id, end_msg, None).await;
                reply_to_client(senders, client_id, batch_end, None).await;
            }
        }
    } else if let Some(parent) = parent_batch {
        // Already inside the caller's labeled response; these belong to it.
        let names = Message::new(
            "353",
            vec![
                nick.into(),
                chan_prefix.into(),
                ch_name.into(),
                names_str.clone(),
            ],
        )
        .with_prefix(server);
        let end = Message::new(
            "366",
            vec![nick.into(), ch_name.into(), "End of /NAMES list".into()],
        )
        .with_prefix(server);
        reply_in_batch(senders, client_id, names, parent).await;
        reply_in_batch(senders, client_id, end, parent).await;
    } else if let Some(label) = label {
        // labeled-response: wrap in labeled-response batch for multi-message reply
        let lr_ref = crate::commands::start_labeled_batch(senders, client_id, label, server).await;
        crate::commands::reply_in_batch(
            senders,
            client_id,
            Message::new(
                "353",
                vec![nick.into(), chan_prefix.into(), ch_name.into(), names_str],
            )
            .with_prefix(server),
            &lr_ref,
        )
        .await;
        crate::commands::reply_in_batch(
            senders,
            client_id,
            Message::new(
                "366",
                vec![nick.into(), ch_name.into(), "End of /NAMES list".into()],
            )
            .with_prefix(server),
            &lr_ref,
        )
        .await;
        crate::commands::end_labeled_batch(senders, client_id, &lr_ref, server).await;
    } else {
        let msg = Message::new(
            "353",
            vec![nick.into(), chan_prefix.into(), ch_name.into(), names_str],
        )
        .with_prefix(server);
        reply_to_client(senders, client_id, msg, None).await;
        let end_msg = Message::new(
            "366",
            vec![nick.into(), ch_name.into(), "End of /NAMES list".into()],
        )
        .with_prefix(server);
        reply_to_client(senders, client_id, end_msg, None).await;
    }
}

pub async fn handle_list(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    // LIST [<filter>], the ELIST=CMNTU forms:
    //   >N / <N   more or fewer than N users
    //   mask      channel names matching the glob
    //   !mask     channel names not matching it
    //   C>N / C<N created more or less than N minutes ago
    //   T>N / T<N topic set more or less than N minutes ago
    let filter = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let min_users: Option<usize> = filter.strip_prefix('>').and_then(|v| v.parse().ok());
    let max_users: Option<usize> = filter.strip_prefix('<').and_then(|v| v.parse().ok());
    let older_than_mins: Option<i64> = filter
        .strip_prefix("C>")
        .or_else(|| filter.strip_prefix("c>"))
        .and_then(|v| v.parse().ok());
    let newer_than_mins: Option<i64> = filter
        .strip_prefix("C<")
        .or_else(|| filter.strip_prefix("c<"))
        .and_then(|v| v.parse().ok());
    let topic_older_than_mins: Option<i64> = filter
        .strip_prefix("T>")
        .or_else(|| filter.strip_prefix("t>"))
        .and_then(|v| v.parse().ok());
    let topic_newer_than_mins: Option<i64> = filter
        .strip_prefix("T<")
        .or_else(|| filter.strip_prefix("t<"))
        .and_then(|v| v.parse().ok());
    let time_filtered = older_than_mins.is_some()
        || newer_than_mins.is_some()
        || topic_older_than_mins.is_some()
        || topic_newer_than_mins.is_some();
    let negated_mask: Option<&str> = if time_filtered {
        None
    } else {
        filter.strip_prefix('!').filter(|m| !m.is_empty())
    };
    let name_mask: Option<&str> = if filter.is_empty()
        || time_filtered
        || negated_mask.is_some()
        || filter.starts_with('>')
        || filter.starts_with('<')
    {
        None
    } else {
        Some(filter)
    };
    let now = chrono::Utc::now().timestamp();

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let nick = client.read().await.nick_or_id().to_string();

    // labeled-response: LIST produces multiple messages, wrap in batch
    let batch_ref = if let Some(l) = label {
        Some(crate::commands::start_labeled_batch(&senders, client_id, l, &cfg.server.name).await)
    } else {
        None
    };

    let ch_store = channels.read().await;
    for (ch_name, ch) in &ch_store.channels {
        let ch = ch.read().await;
        // +s: secret channels are not shown to non-members
        if ch.modes.secret && !ch.is_member(&state.user_id(client_id)) {
            continue;
        }
        let count = ch.member_count();
        // Apply filters
        if let Some(min) = min_users {
            if count <= min {
                continue;
            }
        }
        if let Some(max) = max_users {
            if count >= max {
                continue;
            }
        }
        if let Some(mask) = name_mask {
            let mask_lower = mask.to_lowercase();
            if !crate::user::glob_match(&mask_lower, &ch_name.to_lowercase()) {
                continue;
            }
        }
        if let Some(mask) = negated_mask {
            let mask_lower = mask.to_lowercase();
            if crate::user::glob_match(&mask_lower, &ch_name.to_lowercase()) {
                continue;
            }
        }
        let age_mins = (now - ch.created_at) / 60;
        if let Some(mins) = older_than_mins {
            if age_mins <= mins {
                continue;
            }
        }
        if let Some(mins) = newer_than_mins {
            if age_mins >= mins {
                continue;
            }
        }
        // A channel whose topic was never set has no topic age, so it matches
        // neither "set recently" nor "set a while ago".
        if topic_older_than_mins.is_some() || topic_newer_than_mins.is_some() {
            let Some(set_at) = ch.topic_time else {
                continue;
            };
            let topic_age_mins = (now - set_at) / 60;
            if let Some(mins) = topic_older_than_mins {
                if topic_age_mins <= mins {
                    continue;
                }
            }
            if let Some(mins) = topic_newer_than_mins {
                if topic_age_mins >= mins {
                    continue;
                }
            }
        }
        let topic = ch.topic.as_deref().unwrap_or("");
        let m = Message::new(
            "322",
            vec![
                nick.clone(),
                ch_name.clone(),
                count.to_string(),
                topic.to_string(),
            ],
        )
        .with_prefix(&cfg.server.name);
        if let Some(ref br) = batch_ref {
            crate::commands::reply_in_batch(&senders, client_id, m, br).await;
        } else {
            reply_to_client(&senders, client_id, m, None).await;
        }
    }

    let end_msg =
        Message::new("323", vec![nick, "End of /LIST".into()]).with_prefix(&cfg.server.name);
    if let Some(ref br) = batch_ref {
        crate::commands::reply_in_batch(&senders, client_id, end_msg, br).await;
        crate::commands::end_labeled_batch(&senders, client_id, br, &cfg.server.name).await;
    } else {
        reply_to_client(&senders, client_id, end_msg, None).await;
    }

    Ok(())
}

pub async fn handle_mode(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
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
        let ch_entry = match ch_store.channels.get(&ch_key) {
            Some(ch) => ch,
            None => {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new("403", vec![nick, target.into(), "No such channel".into()])
                        .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
        };
        {
            let mut ch = ch_entry.write().await;
            let member = ch.members.get(&state.user_id(client_id));
            let is_op = member.map(|m| m.modes.op).unwrap_or(false);

            if msg.params.len() == 1 {
                let mut modes = String::new();
                if ch.modes.invite_only {
                    modes.push('i');
                }
                if ch.modes.moderated {
                    modes.push('m');
                }
                if ch.modes.no_external {
                    modes.push('n');
                }
                if ch.modes.secret {
                    modes.push('s');
                }
                if ch.modes.topic_protect {
                    modes.push('t');
                }
                if ch.modes.registered_only {
                    modes.push('R');
                }
                if ch.modes.no_colors {
                    modes.push('c');
                }
                if ch.modes.no_ctcp {
                    modes.push('C');
                }
                if ch.modes.private {
                    modes.push('p');
                }
                if ch.key.is_some() {
                    modes.push('k');
                }
                if ch.modes.user_limit.is_some() {
                    modes.push('l');
                }
                let mut reply_params = vec![nick.clone(), target.into(), format!("+{}", modes)];
                if let Some(ref key) = ch.key {
                    // Only show key value to channel operators
                    if is_op {
                        reply_params.push(key.clone());
                    } else {
                        reply_params.push("*".into());
                    }
                }
                if let Some(limit) = ch.modes.user_limit {
                    reply_params.push(limit.to_string());
                }
                let created_at = ch.created_at;
                let msg = Message::new("324", reply_params).with_prefix(&cfg.server.name);
                reply_to_client(&senders, client_id, msg, label).await;
                // 329 RPL_CREATIONTIME accompanies RPL_CHANNELMODEIS.
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "329",
                        vec![nick.clone(), ch_key.clone(), created_at.to_string()],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            let mode_str = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
            // `MODE #chan +b` with no mask asks what the list holds. Reading a
            // list is not changing one, so it does not need op.
            let list_query_only = msg.params.len() == 2
                && !mode_str.is_empty()
                && mode_str
                    .chars()
                    .all(|c| matches!(c, '+' | '-' | 'b' | 'e' | 'I' | 'q'));
            if !is_op && !list_query_only {
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "482",
                        vec![
                            nick.clone(),
                            target.into(),
                            "You're not channel operator".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }

            let mut plus = true;
            // (who, is_op, granted) — persisted once the channel lock is released.
            let mut access_changes: Vec<(String, bool, bool)> = Vec::new();
            // Mode changes the server refused, so they are left out of the echo.
            let mut rejected_modes: Vec<(char, bool)> = Vec::new();
            // (list, mask, added) — likewise, so bans survive a restart.
            let mut list_changes: Vec<(char, String, bool)> = Vec::new();
            // Who is setting them, for RPL_BANLIST and its kin.
            let setter = nick.clone();
            let set_at = chrono::Utc::now().timestamp();
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
                    'm' => ch.modes.moderated = plus,
                    'R' => ch.modes.registered_only = plus,
                    'c' => ch.modes.no_colors = plus,
                    'C' => ch.modes.no_ctcp = plus,
                    'k' => {
                        if plus {
                            let key = msg.params.get(param_idx).cloned().unwrap_or_default();
                            param_idx += 1;
                            // A key with a space in it cannot be used in a JOIN,
                            // and an empty or over-long one is not a key at all.
                            // Refusing it beats setting one nobody can use.
                            if key.is_empty() || key.contains(' ') || key.len() > 64 {
                                reply_to_client(
                                    &senders,
                                    client_id,
                                    Message::new(
                                        "696",
                                        vec![
                                            nick.clone(),
                                            target.into(),
                                            "k".into(),
                                            "*".into(),
                                            "Invalid channel key".into(),
                                        ],
                                    )
                                    .with_prefix(&cfg.server.name),
                                    label,
                                )
                                .await;
                                rejected_modes.push(('k', plus));
                                continue;
                            }
                            ch.key = Some(key);
                        } else {
                            ch.key = None;
                            param_idx += 1;
                        }
                    }
                    'o' => {
                        let Some(target_nick) = msg.params.get(param_idx).cloned() else {
                            continue;
                        };
                        param_idx += 1;
                        let target_id = state
                            .nick_to_id
                            .get(&crate::casefold::upper(&target_nick))
                            .cloned();
                        // A mode change naming someone who is not here does not
                        // half-apply: it is refused, and no MODE is echoed.
                        let Some(target_id) = target_id else {
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "401",
                                    vec![
                                        nick.clone(),
                                        target_nick.clone(),
                                        "No such nick/channel".into(),
                                    ],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            rejected_modes.push(('o', plus));
                            continue;
                        };
                        if !ch.members.contains_key(&target_id) {
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "441",
                                    vec![
                                        nick.clone(),
                                        target_nick.clone(),
                                        target.into(),
                                        "They aren't on that channel".into(),
                                    ],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            rejected_modes.push(('o', plus));
                            continue;
                        }
                        // Taking the founder's operator status away would be
                        // the same coup as kicking them, done quietly: in a
                        // moderated channel it silences the owner in their own
                        // room. They keep it for as long as the channel is
                        // theirs, and `CHANOWN` is how it stops being theirs.
                        let target_is_founder = match state.clients.get(&target_id) {
                            Some(c) => {
                                let account = c.read().await.account.clone();
                                ch.is_founder(account.as_deref())
                            }
                            None => false,
                        };
                        if !plus && target_is_founder {
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "482",
                                    vec![
                                        nick.clone(),
                                        target.into(),
                                        "The founder keeps operator status in their own channel"
                                            .into(),
                                    ],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            rejected_modes.push(('o', plus));
                            continue;
                        }
                        if let Some(memb) = ch.members.get_mut(&target_id) {
                            memb.modes.op = plus;
                        }
                        // Remember it, so the user keeps the status next time
                        // they join — in memory for this run, and in the
                        // database for the next one.
                        if let Some(c) = state.clients.get(&target_id) {
                            let g = c.read().await;
                            // Only an account is written down. Somebody not
                            // logged in is an operator for as long as they are
                            // here, and that is all: remembering a name would
                            // hand the status to whoever took the name next.
                            let who = match g.account.clone() {
                                Some(account) => account,
                                None => {
                                    drop(g);
                                    continue;
                                }
                            };
                            if plus {
                                // Status that outlives a visit is written down,
                                // and what is written down needs a ceiling.
                                // The operator status itself still applies for
                                // as long as they are here; it is only the
                                // remembering that stops.
                                if !ch.persisted_operators.contains(&who)
                                    && ch.persisted_operators.len()
                                        < crate::channel::MAX_CHANNEL_ACCESS
                                {
                                    ch.persisted_operators.push(who.clone());
                                }
                            } else {
                                ch.persisted_operators.retain(|o| o != &who);
                            }
                            access_changes.push((who, true, plus));
                        }
                    }
                    'b' => {
                        if let Some(mask) = msg.params.get(param_idx) {
                            if plus {
                                if ch.bans.len() >= 100 {
                                    reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "478",
                                            vec![
                                                nick.clone(),
                                                target.into(),
                                                mask.clone(),
                                                "Channel ban list is full".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                } else if !ch.list_contains('b', mask) {
                                    ch.bans.push(mask.clone());
                                    list_changes.push(('b', mask.clone(), true));
                                    ch.list_meta
                                        .insert(format!("b{}", mask), (setter.clone(), set_at));
                                }
                            } else {
                                ch.remove_from_list('b', mask);
                                list_changes.push(('b', mask.clone(), false));
                            }
                            param_idx += 1;
                        } else {
                            // No param: list bans (367 RPL_BANLIST / 368 RPL_ENDOFBANLIST)
                            let bans = ch.bans.clone();
                            let meta_b: std::collections::HashMap<String, (String, i64)> = bans
                                .iter()
                                .map(|m| (m.clone(), ch.list_entry_meta('b', m, &cfg.server.name)))
                                .collect();
                            drop(ch);
                            drop(ch_store);
                            for ban in &bans {
                                reply_to_client(
                                    &senders,
                                    client_id,
                                    Message::new("367", {
                                        let (by, at) =
                                            meta_b.get(ban.as_str()).cloned().unwrap_or_default();
                                        vec![
                                            nick.clone(),
                                            target.into(),
                                            ban.clone(),
                                            by,
                                            at.to_string(),
                                        ]
                                    })
                                    .with_prefix(&cfg.server.name),
                                    label,
                                )
                                .await;
                            }
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "368",
                                    vec![nick, target.into(), "End of channel ban list".into()],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    'q' => {
                        if let Some(mask) = msg.params.get(param_idx) {
                            if plus {
                                if ch.quiet_list.len() >= 100 {
                                    reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "478",
                                            vec![
                                                nick.clone(),
                                                target.into(),
                                                mask.clone(),
                                                "Channel quiet list is full".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                } else if !ch.list_contains('q', mask) {
                                    ch.quiet_list.push(mask.clone());
                                    list_changes.push(('q', mask.clone(), true));
                                    ch.list_meta
                                        .insert(format!("q{}", mask), (setter.clone(), set_at));
                                }
                            } else {
                                ch.remove_from_list('q', mask);
                                list_changes.push(('q', mask.clone(), false));
                            }
                            param_idx += 1;
                        } else {
                            // No param: list quiets (728 RPL_QUIETLIST / 729 RPL_ENDOFQUIETLIST)
                            let quiets = ch.quiet_list.clone();
                            drop(ch);
                            drop(ch_store);
                            for q in &quiets {
                                reply_to_client(
                                    &senders,
                                    client_id,
                                    Message::new(
                                        "728",
                                        vec![
                                            nick.clone(),
                                            target.into(),
                                            "q".into(),
                                            q.clone(),
                                            String::new(),
                                            "0".into(),
                                        ],
                                    )
                                    .with_prefix(&cfg.server.name),
                                    label,
                                )
                                .await;
                            }
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "729",
                                    vec![
                                        nick,
                                        target.into(),
                                        "q".into(),
                                        "End of channel quiet list".into(),
                                    ],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    'v' => {
                        if let Some(target_nick) = msg.params.get(param_idx) {
                            if let Some(target_id) =
                                state.nick_to_id.get(&crate::casefold::upper(target_nick))
                            {
                                if let Some(memb) = ch.members.get_mut(target_id) {
                                    memb.modes.voice = plus;
                                    if let Some(c) = state.clients.get(target_id) {
                                        let g = c.read().await;
                                        let who = g
                                            .account
                                            .clone()
                                            .unwrap_or_else(|| g.nick_or_id().to_string());
                                        if plus {
                                            if !ch.persisted_voice.contains(&who)
                                                && ch.persisted_voice.len()
                                                    < crate::channel::MAX_CHANNEL_ACCESS
                                            {
                                                ch.persisted_voice.push(who.clone());
                                            }
                                        } else {
                                            ch.persisted_voice.retain(|v| v != &who);
                                        }
                                        access_changes.push((who, false, plus));
                                    }
                                } else {
                                    let _ = reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "441",
                                            vec![
                                                nick.clone(),
                                                target_nick.clone(),
                                                target.into(),
                                                "They aren't on that channel".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                }
                            }
                            param_idx += 1;
                        }
                    }
                    'h' => {
                        if let Some(target_nick) = msg.params.get(param_idx) {
                            if let Some(target_id) =
                                state.nick_to_id.get(&crate::casefold::upper(target_nick))
                            {
                                if let Some(memb) = ch.members.get_mut(target_id) {
                                    memb.modes.halfop = plus;
                                } else {
                                    let _ = reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "441",
                                            vec![
                                                nick.clone(),
                                                target_nick.clone(),
                                                target.into(),
                                                "They aren't on that channel".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                }
                            }
                            param_idx += 1;
                        }
                    }
                    'l' => {
                        if plus {
                            let raw = msg.params.get(param_idx).cloned().unwrap_or_default();
                            param_idx += 1;
                            // A limit is a positive number; zero, a negative or
                            // a word is not a smaller limit, it is a mistake.
                            match raw.parse::<u32>() {
                                Ok(n) if n > 0 => ch.modes.user_limit = Some(n),
                                _ => {
                                    reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "696",
                                            vec![
                                                nick.clone(),
                                                target.into(),
                                                "l".into(),
                                                if raw.is_empty() { "*".to_string() } else { raw },
                                                "Invalid channel limit".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                    rejected_modes.push(('l', plus));
                                    continue;
                                }
                            }
                        } else {
                            ch.modes.user_limit = None;
                        }
                    }
                    'e' => {
                        if let Some(mask) = msg.params.get(param_idx) {
                            if plus {
                                if ch.ban_exceptions.len() >= 100 {
                                    reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "478",
                                            vec![
                                                nick.clone(),
                                                target.into(),
                                                mask.clone(),
                                                "Channel exception list is full".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                } else if !ch.list_contains('e', mask) {
                                    ch.ban_exceptions.push(mask.clone());
                                    list_changes.push(('e', mask.clone(), true));
                                    ch.list_meta
                                        .insert(format!("e{}", mask), (setter.clone(), set_at));
                                }
                            } else {
                                ch.remove_from_list('e', mask);
                                list_changes.push(('e', mask.clone(), false));
                            }
                            param_idx += 1;
                        } else {
                            // No param: list ban exceptions (348/349)
                            let exceptions = ch.ban_exceptions.clone();
                            let meta_e: std::collections::HashMap<String, (String, i64)> =
                                exceptions
                                    .iter()
                                    .map(|m| {
                                        (m.clone(), ch.list_entry_meta('e', m, &cfg.server.name))
                                    })
                                    .collect();
                            drop(ch);
                            drop(ch_store);
                            for exc in &exceptions {
                                reply_to_client(
                                    &senders,
                                    client_id,
                                    Message::new("348", {
                                        let (by, at) =
                                            meta_e.get(exc.as_str()).cloned().unwrap_or_default();
                                        vec![
                                            nick.clone(),
                                            target.into(),
                                            exc.clone(),
                                            by,
                                            at.to_string(),
                                        ]
                                    })
                                    .with_prefix(&cfg.server.name),
                                    label,
                                )
                                .await;
                            }
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "349",
                                    vec![
                                        nick,
                                        target.into(),
                                        "End of channel exception list".into(),
                                    ],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    'I' => {
                        if let Some(mask) = msg.params.get(param_idx) {
                            if plus {
                                if ch.invite_exceptions.len() >= 100 {
                                    reply_to_client(
                                        &senders,
                                        client_id,
                                        Message::new(
                                            "478",
                                            vec![
                                                nick.clone(),
                                                target.into(),
                                                mask.clone(),
                                                "Channel invite exception list is full".into(),
                                            ],
                                        )
                                        .with_prefix(&cfg.server.name),
                                        label,
                                    )
                                    .await;
                                } else if !ch.list_contains('I', mask) {
                                    ch.invite_exceptions.push(mask.clone());
                                    list_changes.push(('I', mask.clone(), true));
                                    ch.list_meta
                                        .insert(format!("I{}", mask), (setter.clone(), set_at));
                                }
                            } else {
                                ch.remove_from_list('I', mask);
                                list_changes.push(('I', mask.clone(), false));
                            }
                            param_idx += 1;
                        } else {
                            // No param: list invite exceptions (346/347)
                            let invexes = ch.invite_exceptions.clone();
                            let meta_invex: std::collections::HashMap<String, (String, i64)> =
                                invexes
                                    .iter()
                                    .map(|m| {
                                        (m.clone(), ch.list_entry_meta('I', m, &cfg.server.name))
                                    })
                                    .collect();
                            drop(ch);
                            drop(ch_store);
                            for exc in &invexes {
                                reply_to_client(
                                    &senders,
                                    client_id,
                                    Message::new("346", {
                                        let (by, at) = meta_invex
                                            .get(exc.as_str())
                                            .cloned()
                                            .unwrap_or_default();
                                        vec![
                                            nick.clone(),
                                            target.into(),
                                            exc.clone(),
                                            by,
                                            at.to_string(),
                                        ]
                                    })
                                    .with_prefix(&cfg.server.name),
                                    label,
                                )
                                .await;
                            }
                            reply_to_client(
                                &senders,
                                client_id,
                                Message::new(
                                    "347",
                                    vec![nick, target.into(), "End of channel invite list".into()],
                                )
                                .with_prefix(&cfg.server.name),
                                label,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    _ => {}
                }
            }

            // Collect data needed after dropping ch
            let mode_flags_str = {
                let mut flags = String::new();
                if ch.modes.invite_only {
                    flags.push('i');
                }
                if ch.modes.moderated {
                    flags.push('m');
                }
                if ch.modes.no_external {
                    flags.push('n');
                }
                if ch.modes.secret {
                    flags.push('s');
                }
                if ch.modes.topic_protect {
                    flags.push('t');
                }
                if ch.modes.registered_only {
                    flags.push('R');
                }
                if ch.modes.no_colors {
                    flags.push('c');
                }
                if ch.modes.no_ctcp {
                    flags.push('C');
                }
                flags
            };
            let mode_key_val = ch.key.clone();
            let mode_limit_val = ch.modes.user_limit;
            let channel_created_at = ch.created_at;
            let member_ids_mode: Vec<String> = ch.members.keys().cloned().collect();
            let echo_params = filter_mode_echo(&msg.params, &rejected_modes);
            let mode_msg = echo_params
                .clone()
                .map(|p| Message::new("MODE", p).with_prefix(nick.as_str()));
            let link_mode = echo_params
                .as_ref()
                .and_then(|p| mode_params_for_link(p, &state));
            let mode_setter = state.user_id(client_id);
            tracing::debug!(client_id, channel = %target, modes = %msg.params[1..].join(" "), "MODE change");
            drop(ch);
            drop(ch_store);
            if let Some(ref mode_msg) = mode_msg {
                for mid in &member_ids_mode {
                    senders.read().await.deliver(mid, mode_msg);
                }
            }
            if let Some((letters, args)) = link_mode {
                crate::link::announce_channel_mode(cfg, &mode_setter, &ch_key, &letters, &args)
                    .await;
            }
            // Persist channel modes to database
            if let Some(ref pool) = cfg.db {
                crate::persist::save_channel_modes(
                    pool,
                    &ch_key,
                    &mode_flags_str,
                    mode_key_val.as_deref(),
                    mode_limit_val,
                )
                .await;
                // ... and the operator and voice lists, so status survives a part
                // or a restart the way a services bot would keep it.
                for (who, is_op, granted) in &access_changes {
                    crate::persist::set_channel_access(pool, &ch_key, who, *is_op, *granted).await;
                }
                for (list_type, mask, added) in &list_changes {
                    crate::persist::set_channel_list_entry(
                        pool, &ch_key, *list_type, mask, *added, &setter, set_at,
                    )
                    .await;
                }
            }
            // Status that was granted to last is part of who a channel belongs
            // to, so the rest of the network has to hear about it — otherwise
            // an operator here is an ordinary member one server over.
            for letter in ['o', 'v'] {
                let changed: Vec<String> = access_changes
                    .iter()
                    .filter(|(_, is_op, _)| *is_op == (letter == 'o'))
                    .map(|(who, _, granted)| {
                        if *granted {
                            who.clone()
                        } else {
                            format!("-{who}")
                        }
                    })
                    .collect();
                crate::link::announce_channel_access(
                    cfg,
                    &ch_key,
                    channel_created_at,
                    letter,
                    &changed,
                )
                .await;
            }
        }
    } else if target.eq_ignore_ascii_case(&nick) {
        let mode_str = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");

        if mode_str.is_empty() {
            // MODE query: return current user modes (221 RPL_UMODEIS)
            if let Some(client_ref) = state.clients.get(client_id) {
                let g = client_ref.read().await;
                let mut modes = String::from("+");
                if g.invisible {
                    modes.push('i');
                }
                if g.oper {
                    modes.push('o');
                }
                if g.account.is_some() {
                    modes.push('r');
                }
                if g.wallops {
                    modes.push('w');
                }
                if g.registered_only {
                    modes.push('R');
                }
                if g.bot {
                    modes.push('B');
                }
                let m =
                    Message::new("221", vec![nick.clone(), modes]).with_prefix(&cfg.server.name);
                reply_to_client(&senders, client_id, m, label).await;
            }
            return Ok(());
        }

        let mut plus = true;
        for c in mode_str.chars() {
            match c {
                '+' => plus = true,
                '-' => plus = false,
                'B' => {
                    if let Some(client_ref) = state.clients.get(client_id) {
                        client_ref.write().await.bot = plus;
                    }
                    let m = Message::new(
                        "MODE",
                        vec![nick.clone(), format!("{}B", if plus { "+" } else { "-" })],
                    )
                    .with_prefix(&nick);
                    reply_to_client(&senders, client_id, m, label).await;
                }
                'i' => {
                    if let Some(client_ref) = state.clients.get(client_id) {
                        client_ref.write().await.invisible = plus;
                    }
                    let m = Message::new(
                        "MODE",
                        vec![nick.clone(), format!("{}i", if plus { "+" } else { "-" })],
                    )
                    .with_prefix(&nick);
                    reply_to_client(&senders, client_id, m, label).await;
                }
                'w' => {
                    if let Some(client_ref) = state.clients.get(client_id) {
                        client_ref.write().await.wallops = plus;
                    }
                    let m = Message::new(
                        "MODE",
                        vec![nick.clone(), format!("{}w", if plus { "+" } else { "-" })],
                    )
                    .with_prefix(&nick);
                    reply_to_client(&senders, client_id, m, label).await;
                }
                'R' => {
                    if let Some(client_ref) = state.clients.get(client_id) {
                        client_ref.write().await.registered_only = plus;
                    }
                    let m = Message::new(
                        "MODE",
                        vec![nick.clone(), format!("{}R", if plus { "+" } else { "-" })],
                    )
                    .with_prefix(&nick);
                    reply_to_client(&senders, client_id, m, label).await;
                }
                // Nobody makes themselves an operator with MODE — that is what
                // OPER and a password are for — but anybody may stop being one.
                // An operator who wants to put the power down should not have to
                // reconnect to do it.
                'o' if !plus => {
                    let was_oper = match state.clients.get(client_id) {
                        Some(client_ref) => {
                            let mut g = client_ref.write().await;
                            let was = g.oper;
                            g.oper = false;
                            g.oper_name = None;
                            g.oper_privileges = None;
                            was
                        }
                        None => false,
                    };
                    if was_oper {
                        tracing::info!(client_id, nick = %nick, "Operator status given up");
                        let m = Message::new("MODE", vec![nick.clone(), "-o".to_string()])
                            .with_prefix(&nick);
                        reply_to_client(&senders, client_id, m, label).await;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Rebuild a MODE echo without the changes the server refused.
///
/// A rejected change must not be announced: a client told `+o nobody` succeeded
/// would show ops nobody has. Walks the requested mode string in order,
/// consuming each mode's parameter, and drops the ones in `rejected`.
/// The same mode change, addressed the way the rest of the network needs it.
///
/// `+o` and its like name their target by user id over a link, not by nick: a
/// nick change crossing in the other direction would otherwise be able to hand
/// somebody else the op. Everything else goes as written.
fn mode_params_for_link(params: &[String], state: &ServerState) -> Option<(String, Vec<String>)> {
    const ALWAYS_PARAM: &str = "ovhbeIqk";
    let mode_str = params.get(1)?.clone();
    let mut rest = params[2..].iter();
    let mut plus = true;
    let mut out: Vec<String> = Vec::new();
    for c in mode_str.chars() {
        match c {
            '+' => plus = true,
            '-' => plus = false,
            _ => {
                if !(ALWAYS_PARAM.contains(c) || (c == 'l' && plus)) {
                    continue;
                }
                let Some(p) = rest.next() else { continue };
                if matches!(c, 'o' | 'v' | 'h') {
                    match state.nick_to_id.get(&crate::casefold::upper(p)) {
                        Some(id) => out.push(id.clone()),
                        None => out.push(p.clone()),
                    }
                } else {
                    out.push(p.clone());
                }
            }
        }
    }
    Some((mode_str, out))
}

fn filter_mode_echo(params: &[String], rejected: &[(char, bool)]) -> Option<Vec<String>> {
    // Modes taking a parameter whichever way they are set, and `l` which takes
    // one only when set.
    const ALWAYS_PARAM: &str = "ovhbeIqk";
    let channel = params.first()?;
    let mode_str = params.get(1)?;
    let mut rest = params[2..].iter();

    let mut plus = true;
    let mut kept = String::new();
    let mut kept_params: Vec<String> = Vec::new();
    let mut last_sign: Option<bool> = None;

    for c in mode_str.chars() {
        match c {
            '+' => plus = true,
            '-' => plus = false,
            _ => {
                let takes_param = ALWAYS_PARAM.contains(c) || (c == 'l' && plus);
                let param = if takes_param { rest.next() } else { None };
                if rejected.contains(&(c, plus)) {
                    continue;
                }
                if last_sign != Some(plus) {
                    kept.push(if plus { '+' } else { '-' });
                    last_sign = Some(plus);
                }
                kept.push(c);
                if let Some(p) = param {
                    kept_params.push(p.clone());
                }
            }
        }
    }

    if kept.is_empty() {
        return None;
    }
    let mut out = vec![channel.clone(), kept];
    out.extend(kept_params);
    Some(out)
}

pub async fn handle_topic(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let ch_name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    // Only params[1] sets a topic. `TOPIC #chan` is a query, and reading it via
    // trailing() made it a request to set the topic to the channel's own name.
    let new_topic = msg.params.get(1).cloned();

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
        let is_op = ch
            .members
            .get(&state.user_id(client_id))
            .map(|m| m.modes.op)
            .unwrap_or(false);

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
                    Message::new(
                        "331",
                        vec![nick.clone(), ch_name.into(), "No topic is set".into()],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
            }
            return Ok(());
        }

        // Must be on channel to set topic
        if !ch.is_member(&state.user_id(client_id)) {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "442",
                    vec![
                        nick.clone(),
                        ch_name.into(),
                        "You're not on that channel".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        if ch.modes.topic_protect && !is_op {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "482",
                    vec![
                        nick.clone(),
                        ch_name.into(),
                        "You're not channel operator".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        // Enforce TOPICLEN=307
        let new_topic = new_topic.map(|t| crate::protocol::truncate_bytes(&t, 307).to_string());

        let topic_time_ts = chrono::Utc::now().timestamp();
        ch.topic = new_topic.clone();
        ch.topic_setter = Some(source.clone());
        ch.topic_time = Some(topic_time_ts);

        let topic_text = new_topic.unwrap_or_default();
        tracing::debug!(client_id, channel = %ch_name, topic = %topic_text, "TOPIC set");
        // A topic change is replayable history like any other event, so it needs
        // the same msgid and server-time tags: without them a client cannot tell
        // two topic changes apart, or place them in time.
        let topic_msgid = crate::protocol::generate_msgid();
        let happened_at = crate::protocol::server_time_now();
        let mut topic_msg =
            Message::new("TOPIC", vec![ch_name.into(), topic_text.clone()]).with_prefix(&source);
        topic_msg
            .tags
            .insert("time".to_string(), Some(happened_at.clone()));
        let member_ids_for_topic: Vec<String> = ch.members.keys().cloned().collect();
        drop(ch);
        for mid in &member_ids_for_topic {
            let caps = match state.clients.get(mid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            let tagged = crate::protocol::add_tags_for_recipient(
                topic_msg.clone(),
                &caps,
                None,
                Some(&topic_msgid),
                None,
                cfg.server.client_tag_deny.as_deref(),
                &crate::protocol::SenderTags::default(),
            );
            senders.read().await.deliver(mid, &tagged);
        }

        // Record TOPIC event for draft/event-playback
        cfg.record_history_at(
            &ch_key,
            &source,
            &topic_text,
            Some(&topic_msgid),
            "TOPIC",
            &happened_at,
        );
        let setter = state.user_id(client_id);
        crate::link::announce_topic(cfg, &setter, &ch_key, &topic_text).await;
        if let Some(ref pool) = cfg.db {
            crate::persist::save_channel_topic(pool, &ch_key, &topic_text).await;
        }

        // Setting a topic is announced with the TOPIC message above, which the
        // setter receives along with everyone else. 331/332/333 answer a query
        // — sending 333 here too gives the setter a second message for one
        // action, which clients count as two.
    } else {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "403",
                vec![nick.clone(), ch_name.into(), "No such channel".into()],
            )
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let ch_name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let target_nick = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let kicker_nick = match state.read().await.clients.get(client_id) {
        Some(c) => c.read().await.nick_or_id().to_string(),
        None => client_id.to_string(),
    };
    // KICK's comment is params[2] and KICKLEN caps it at 307. With none given
    // the kicker's own nick is the conventional default.
    let reason = msg
        .params
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or(kicker_nick.as_str())
        .chars()
        .take(307)
        .collect::<String>();

    if ch_name.is_empty() || target_nick.is_empty() {
        return Ok(());
    }

    let state_arc = state.clone();
    let state = state.read().await;
    let mut kicked_account: Option<String> = None;
    // Who left the channel and why, told to the network once the locks are down.
    let mut kicked_across: Option<(String, String)> = None;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let source = client
        .read()
        .await
        .source()
        .unwrap_or_else(|| client_id.to_string());

    let target_id = state
        .nick_to_id
        .get(&crate::casefold::upper(target_nick))
        .cloned();

    let ch_key = canonical_channel_key(ch_name);
    let mut ch_store = channels.write().await;
    if !ch_store.channels.contains_key(&ch_key) {
        let nick = client.read().await.nick_or_id().to_string();
        reply_to_client(
            &senders,
            client_id,
            Message::new("403", vec![nick, ch_name.into(), "No such channel".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    if let Some(ch) = ch_store.channels.get_mut(&ch_key) {
        let mut ch = ch.write().await;
        let is_op = ch
            .members
            .get(&state.user_id(client_id))
            .map(|m| m.modes.op)
            .unwrap_or(false);
        if !is_op {
            let nick = client.read().await.nick_or_id().to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "482",
                    vec![nick, ch_name.into(), "You're not channel operator".into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        let mut should_remove_channel = false;
        if let Some(tid) = target_id {
            if !ch.members.contains_key(&tid) {
                let nick = client.read().await.nick_or_id().to_string();
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "441",
                        vec![
                            nick,
                            target_nick.into(),
                            ch_name.into(),
                            "They aren't on that channel".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            // The founder cannot be thrown out of their own channel. An
            // operator they appointed removing them is the one thing a channel
            // must not allow — it is how a room gets taken from the person
            // whose room it is. Somebody who has to be got rid of is got rid of
            // by taking the channel off them first, which is a decision that
            // leaves a trace, rather than by a KICK that leaves none.
            let target_account = match state.clients.get(&tid) {
                Some(c) => c.read().await.account.clone(),
                None => None,
            };
            if ch.is_founder(target_account.as_deref()) {
                let nick = client.read().await.nick_or_id().to_string();
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "482",
                        vec![
                            nick,
                            ch_name.into(),
                            "You cannot remove the founder from their own channel".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            if ch.members.remove(&tid).is_some() {
                tracing::info!(client_id, channel = %ch_name, target = %target_nick, "KICK");
                if let Some(target_client) = state.clients.get(&tid) {
                    let mut g = target_client.write().await;
                    g.channels.remove(&ch_key);
                    // Being kicked ends the membership, so it must not keep
                    // producing notifications while they are away.
                    kicked_account = g.account.clone();
                }
                let kick_msg = Message::new(
                    "KICK",
                    vec![ch_name.into(), target_nick.into(), reason.clone()],
                )
                .with_prefix(&source);
                for mid in ch.members.clone().keys() {
                    senders.read().await.deliver(mid, &kick_msg);
                }
                senders.read().await.deliver(&tid, &kick_msg);
                should_remove_channel = ch.members.is_empty() && !ch.is_registered();
                kicked_across = Some((tid.clone(), reason.clone()));
            }
        }
        drop(ch);
        if should_remove_channel {
            ch_store.channels.remove(&ch_key);
        }
    }

    drop(state);
    if let Some((tid, reason)) = kicked_across {
        let kicker = state_arc.read().await.user_id(client_id);
        crate::link::announce_kick(cfg, &kicker, &canonical_channel_key(ch_name), &tid, &reason)
            .await;
    }
    if let Some(account) = kicked_account {
        {
            let key = canonical_channel_key(ch_name);
            let mut state_w = state_arc.write().await;
            if let Some(set) = state_w.channel_accounts.get_mut(&key) {
                set.remove(&account.to_lowercase());
                if set.is_empty() {
                    state_w.channel_accounts.remove(&key);
                }
            }
        }
        if let Some(ref pool) = cfg.db {
            crate::persist::forget_account_channel(
                pool,
                &account,
                Some(&canonical_channel_key(ch_name)),
            )
            .await;
        }
    }

    Ok(())
}

/// Invitations one channel may have standing at once before the ones nobody is
/// behind any more are swept up.
const MAX_STANDING_INVITES: usize = 256;

pub async fn handle_invite(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let target_nick = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let ch_name = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");

    // Bare INVITE lists the channels this client has been invited to.
    if target_nick.is_empty() && ch_name.is_empty() {
        let state_r = state.read().await;
        let nick = match state_r.clients.get(client_id) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => "*".to_string(),
        };
        let user_id = state_r.user_id(client_id);
        drop(state_r);

        let invited: Vec<String> = {
            let ch_store = channels.read().await;
            let mut names = Vec::new();
            for ch in ch_store.channels.values() {
                let ch = ch.read().await;
                if ch.invite_list.contains(&user_id) {
                    names.push(ch.name.clone());
                }
            }
            names
        };
        for ch_name in invited {
            reply_to_client(
                &senders,
                client_id,
                Message::new("336", vec![nick.clone(), ch_name]).with_prefix(&cfg.server.name),
                label,
            )
            .await;
        }
        reply_to_client(
            &senders,
            client_id,
            Message::new("337", vec![nick, "End of /INVITE list".into()])
                .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    if target_nick.is_empty() || ch_name.is_empty() {
        // Silence is not an answer: a client waiting on INVITE would wait for
        // ever.
        let nick = match state.read().await.clients.get(client_id) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => "*".to_string(),
        };
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "461",
                vec![nick, "INVITE".into(), "Not enough parameters".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let state = state.read().await;
    let client = match state.clients.get(client_id) {
        Some(c) => c.clone(),
        None => return Ok(()),
    };
    let source = client
        .read()
        .await
        .source()
        .unwrap_or_else(|| client_id.to_string());
    let inviter_nick = client.read().await.nick_or_id().to_string();

    let ch_key = canonical_channel_key(ch_name);
    let mut ch_store = channels.write().await;
    if let Some(ch) = ch_store.channels.get_mut(&ch_key) {
        let mut ch = ch.write().await;
        // Check sender is on the channel
        if !ch.is_member(&state.user_id(client_id)) {
            let nick = client.read().await.nick_or_id().to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "442",
                    vec![nick, ch_name.into(), "You're not on that channel".into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        // Being an operator is only needed to invite past a closed door. "If the
        // channel has the invite-only mode set, the client must have channel
        // operator privileges" — RFC 1459 §4.2.7, RFC 2812 §3.2.7 and the
        // Modern spec all say it of `+i` and of nothing else. On an ordinary
        // channel any member may bring somebody, which is what asking a friend
        // to join is.
        let is_op = ch
            .members
            .get(&state.user_id(client_id))
            .map(|m| m.modes.op)
            .unwrap_or(false);
        if ch.modes.invite_only && !is_op {
            let nick = client.read().await.nick_or_id().to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "482",
                    vec![nick, ch_name.into(), "You're not channel operator".into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }

        if let Some(target_id) = state.nick_to_id.get(&crate::casefold::upper(target_nick)) {
            // 443 ERR_USERONCHANNEL: target is already on the channel
            if ch.is_member(target_id) {
                let nick = client.read().await.nick_or_id().to_string();
                reply_to_client(
                    &senders,
                    client_id,
                    Message::new(
                        "443",
                        vec![
                            nick,
                            target_nick.into(),
                            ch_name.into(),
                            "is already on channel".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                )
                .await;
                return Ok(());
            }
            // An invitation is spent when the guest joins, and forgotten when
            // they do not. Nothing else removes one, so every invitee who never
            // turned up and has since gone stays on the list for as long as the
            // channel does. Dropping the ones nobody is behind any more leaves a
            // list bounded by who is actually connected.
            if ch.invite_list.len() >= MAX_STANDING_INVITES {
                ch.invite_list.retain(|id| state.clients.contains_key(id));
            }
            ch.invite_list.insert(target_id.clone());
            tracing::debug!(client_id, channel = %ch_name, target = %target_nick, "INVITE");
            let invite_msg = Message::new("INVITE", vec![target_nick.into(), ch_name.into()])
                .with_prefix(&source);
            // An INVITE is a message from a user, so it carries the sender's
            // tags — account-tag among them — like any other.
            let inviter_account = state
                .clients
                .get(client_id)
                .map(|c| async { c.read().await.account.clone() });
            let inviter_account = match inviter_account {
                Some(f) => f.await,
                None => None,
            };
            let target_caps = match state.clients.get(target_id) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            let tagged_invite = crate::protocol::add_tags_for_recipient(
                invite_msg.clone(),
                &target_caps,
                inviter_account.as_deref(),
                None,
                None,
                cfg.server.client_tag_deny.as_deref(),
                &crate::protocol::SenderTags::default(),
            );
            senders.read().await.deliver(target_id, &tagged_invite);
            reply_to_client(
                &senders,
                client_id,
                // 341 <client> <nick> <channel>: the first parameter is the
                // requesting client's nick, not their nick!user@host.
                Message::new(
                    "341",
                    vec![inviter_nick.clone(), target_nick.into(), ch_name.into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            // invite-notify: notify other channel members that have the cap (release locks first)
            let notify_member_ids: Vec<String> = ch.members.keys().cloned().collect();
            drop(ch);
            drop(ch_store);
            let registry = senders.read().await;
            for mid in &notify_member_ids {
                if state.is_self(mid, client_id) || *mid == *target_id {
                    continue;
                }
                registry.deliver_requiring(mid, "invite-notify", &invite_msg);
            }
            drop(registry);
            crate::link::announce_invite(
                cfg,
                &state.user_id(client_id),
                target_id,
                &canonical_channel_key(ch_name),
            )
            .await;
            return Ok(());
        } else {
            // 401 ERR_NOSUCHNICK: target nick not found
            let nick = client.read().await.nick_or_id().to_string();
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "401",
                    vec![nick, target_nick.into(), "No such nick/channel".into()],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let old_name = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let new_name = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let reason = msg.params.get(2).cloned().unwrap_or_default();

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
            Message::new(
                "FAIL",
                vec![
                    "RENAME".into(),
                    "CANNOT_RENAME".into(),
                    old_name.into(),
                    new_name.into(),
                    "You cannot change a channel prefix type".into(),
                ],
            )
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
        Some(c) => c
            .read()
            .await
            .source()
            .unwrap_or_else(|| client_id.to_string()),
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
                Message::new(
                    "403",
                    vec![
                        nick.clone().unwrap_or_else(|| "*".into()),
                        old_name.into(),
                        "No such channel".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    };
    let (is_member, is_op, member_ids, topic, topic_setter, topic_time) = {
        let ch = ch_ref.read().await;
        let uid = state.read().await.user_id(client_id);
        let is_member = ch.members.contains_key(&uid);
        let is_op = ch.members.get(&uid).map(|m| m.modes.op).unwrap_or(false);
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
            Message::new(
                "442",
                vec![
                    nick.unwrap_or_else(|| "*".into()),
                    old_name.into(),
                    "You're not on that channel".into(),
                ],
            )
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
            Message::new(
                "482",
                vec![
                    nick.unwrap_or_else(|| "*".into()),
                    old_name.into(),
                    "You must be a channel operator".into(),
                ],
            )
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
            Message::new(
                "FAIL",
                vec![
                    "RENAME".into(),
                    "CHANNEL_NAME_IN_USE".into(),
                    old_name.into(),
                    new_name.into(),
                    "Channel already exists".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let case_only = old_key == new_key;
    tracing::info!(client_id, old = %old_name, new = %new_name, case_only, "RENAME channel");
    // The channel keeps everything it had, so its record has to come with it.
    if !case_only {
        if let Some(ref pool) = cfg.db {
            crate::persist::rename_channel(pool, &old_key, &new_key).await;
        }
    }
    let channel = ch_store.channels.remove(&old_key).expect("channel existed");
    let mut ch = channel.write().await;
    // Store the new name as given; new_key is only the lookup key.
    ch.name = new_name.to_string();
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

    let rename_msg = Message::new(
        "RENAME",
        vec![old_name.into(), new_name.into(), reason.clone()],
    )
    .with_prefix(&source);
    // Per connection, not per person: `draft/channel-rename` is negotiated by a
    // client, and a user's other client may not have asked for it. The one that
    // did gets RENAME; the one that did not gets the part-and-rejoin it can
    // understand.
    let mut use_rename_per_client: Vec<(String, bool)> = Vec::new();
    {
        let registry = senders.read().await;
        for mid in &member_ids {
            for session in registry.sessions_with_cap(mid, "draft/channel-rename", true) {
                use_rename_per_client.push((session, true));
            }
            for session in registry.sessions_with_cap(mid, "draft/channel-rename", false) {
                use_rename_per_client.push((session, case_only));
            }
        }
    }

    drop(ch_store);

    for (mid, use_rename) in &use_rename_per_client {
        if *use_rename {
            send_to_client(&senders, mid, rename_msg.clone()).await;
        } else {
            send_to_client(
                &senders,
                mid,
                Message::new("PART", vec![old_name.into(), reason.clone()]).with_prefix(&source),
            )
            .await;
            send_to_client(
                &senders,
                mid,
                Message::new("JOIN", vec![new_name.into()]).with_prefix(&source),
            )
            .await;
            let client_arc = state.read().await.clients.get(mid).cloned();
            let recv_nick = match client_arc {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            };
            if let Some(ref t) = topic {
                send_to_client(
                    &senders,
                    mid,
                    Message::new("332", vec![recv_nick.clone(), new_name.into(), t.clone()])
                        .with_prefix(&cfg.server.name),
                )
                .await;
            }
            if let (Some(ref ts), Some(tt)) = (&topic_setter, topic_time) {
                send_to_client(
                    &senders,
                    mid,
                    Message::new(
                        "333",
                        vec![
                            recv_nick.clone(),
                            new_name.into(),
                            ts.clone(),
                            tt.to_string(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                )
                .await;
            }
            let ch_store = channels.read().await;
            if let Some(ch_ref) = ch_store.channels.get(&new_key) {
                let client_arc = state.read().await.clients.get(mid).cloned();
                let caps = match client_arc {
                    Some(c) => c.read().await.capabilities.clone(),
                    None => std::collections::HashSet::new(),
                };
                let state_r = state.read().await;
                send_names_for_channel(
                    ch_ref,
                    &new_key,
                    &recv_nick,
                    &state_r,
                    &senders,
                    mid,
                    &cfg.server.name,
                    &caps,
                    label,
                    None,
                )
                .await;
            }
        }
    }

    Ok(())
}

/// `CHANOWN <#channel> [<account>]` — who a channel belongs to, and handing it on.
///
/// Being the founder is the one standing a channel cannot take back: the
/// founder is opped whenever they return, cannot be kicked out of their own
/// room, and cannot be deopped in it. That is deliberate — an operator they
/// appointed turning on them is how a channel gets stolen — but it also means
/// ownership has to have a door, or a channel outlives every reason anyone had
/// for making it. This is the door.
///
/// Two people may open it. The founder, because it is theirs to give: somebody
/// leaves a project and the channel should go where the project went. And a
/// network operator, because a channel whose founder has vanished, or whose
/// founder is the problem, has no other way out. The operator's use of it is
/// said in the channel and logged by name. It is meant to be usable, and it is
/// meant to be seen — an operator who wants a channel can already kick, mode
/// and ban their way through it, so what keeps them honest is not being unable
/// to act but being unable to act quietly.
pub async fn handle_chanown(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let fail = |code: &str, target: &str, text: &str| {
        Message::new(
            "FAIL",
            vec![
                "CHANOWN".into(),
                code.into(),
                target.into(),
                text.into(),
            ],
        )
        .with_prefix(&cfg.server.name)
    };

    let Some(ch_name) = msg.params.first().cloned() else {
        reply_to_client(
            &senders,
            client_id,
            fail("NEED_PARAMS", "*", "Which channel?"),
            label,
        )
        .await;
        return Ok(());
    };
    let new_owner = msg.params.get(1).cloned();
    let ch_key = canonical_channel_key(&ch_name);

    let (nick, account, may_move_channels, oper_name) = {
        let state_r = state.read().await;
        let Some(client) = state_r.clients.get(client_id) else {
            return Ok(());
        };
        let guard = client.read().await;
        (
            guard.nick_or_id().to_string(),
            guard.account.clone(),
            // Acting on somebody else's channel is its own privilege. An
            // operator whose list does not name it is an operator for the
            // things it does name, and this is not one of them.
            guard.may(crate::config::OperPrivilege::Channels),
            guard.oper_name.clone(),
        )
    };

    // The channel has to exist to be owned. An owned one is resident even with
    // nobody in it, which is the whole point of keeping it, so this answers for
    // a channel nobody is standing in.
    let Some(founder) = ({
        let store = channels.read().await;
        match store.channels.get(&ch_key) {
            Some(ch) => {
                let ch = ch.read().await;
                // A channel that hides itself hides itself here too. Answering
                // "only the founder may do that" to somebody who cannot see the
                // channel tells them it exists, which is the one thing +s is
                // for. Whoever owns it, and an operator, can always see it.
                let user_id = state.read().await.user_id(client_id);
                let hidden = ch.modes.secret || ch.modes.invite_only;
                let may_see = !hidden
                    || may_move_channels
                    || ch.is_member(&user_id)
                    || ch.is_founder(account.as_deref());
                may_see.then(|| ch.founder.clone())
            }
            None => None,
        }
    }) else {
        reply_to_client(
            &senders,
            client_id,
            fail("NO_SUCH_CHANNEL", &ch_name, "No such channel"),
            label,
        )
        .await;
        return Ok(());
    };

    // No second parameter is a question rather than an instruction.
    let Some(new_owner) = new_owner else {
        let reply = if founder.is_empty() {
            Message::new(
                "NOTE",
                vec![
                    "CHANOWN".into(),
                    "NO_FOUNDER".into(),
                    ch_name.clone(),
                    "This channel has no founder".into(),
                ],
            )
        } else {
            Message::new(
                "NOTE",
                vec![
                    "CHANOWN".into(),
                    "FOUNDER".into(),
                    ch_name.clone(),
                    founder.clone(),
                    format!("{ch_name} belongs to {founder}"),
                ],
            )
        };
        reply_to_client(
            &senders,
            client_id,
            reply.with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    };

    let owns_it = account
        .as_deref()
        .is_some_and(|a| !founder.is_empty() && a.eq_ignore_ascii_case(&founder));
    if !owns_it && !may_move_channels {
        // A channel with no founder is not up for grabs by whoever asks first.
        // Somebody has to decide who it belongs to, and that is an operator.
        let text = if founder.is_empty() {
            "This channel has no founder; an operator has to give it one"
        } else {
            "Only the founder of a channel can hand it on"
        };
        reply_to_client(
            &senders,
            client_id,
            fail("NOT_FOUNDER", &ch_name, text),
            label,
        )
        .await;
        return Ok(());
    }

    if new_owner.eq_ignore_ascii_case(&founder) {
        reply_to_client(
            &senders,
            client_id,
            fail(
                "ALREADY_FOUNDER",
                &ch_name,
                &format!("{new_owner} already owns {ch_name}"),
            ),
            label,
        )
        .await;
        return Ok(());
    }

    // The new owner has to be an account that exists. Handing a channel to a
    // name nobody can log in as is handing it to nobody, and it would look like
    // it had worked.
    if let Some(ref pool) = cfg.db {
        if !crate::persist::nick_is_registered(pool, &cfg.db_health, &new_owner).await {
            reply_to_client(
                &senders,
                client_id,
                fail(
                    "NO_SUCH_ACCOUNT",
                    &new_owner,
                    "There is no account by that name",
                ),
                label,
            )
            .await;
            return Ok(());
        }
    }

    // Apply it. The outgoing founder keeps operator status: handing a channel
    // on is not the same as being thrown out of it, and somebody who gives a
    // channel away should not have to ask for their own room back.
    let (created_at, reopped) = {
        let store = channels.read().await;
        let Some(entry) = store.channels.get(&ch_key) else {
            return Ok(());
        };
        let mut ch = entry.write().await;
        ch.founder = new_owner.clone();
        for who in [&new_owner, &founder] {
            if !who.is_empty()
                && !ch.persisted_operators.iter().any(|o| o == who)
                && ch.persisted_operators.len() < crate::channel::MAX_CHANNEL_ACCESS
            {
                ch.persisted_operators.push(who.clone());
            }
        }
        // If the new owner is standing in the channel, they hold it now.
        let mut reopped = Vec::new();
        let state_r = state.read().await;
        for member_id in ch.members.keys().cloned().collect::<Vec<_>>() {
            let Some(c) = state_r.clients.get(&member_id) else {
                continue;
            };
            let theirs = c.read().await.account.clone();
            if theirs
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(&new_owner))
            {
                if let Some(memb) = ch.members.get_mut(&member_id) {
                    memb.modes.op = true;
                }
                reopped.push(c.read().await.nick_or_id().to_string());
            }
        }
        (ch.created_at, reopped)
    };

    if let Some(ref pool) = cfg.db {
        crate::persist::record_channel_founder(pool, &ch_key, &new_owner).await;
        crate::persist::set_channel_access(pool, &ch_key, &new_owner, true, true).await;
        if !founder.is_empty() {
            crate::persist::set_channel_access(pool, &ch_key, &founder, true, true).await;
        }
    }

    let mut carried = vec![new_owner.clone()];
    if !founder.is_empty() {
        carried.push(founder.clone());
    }
    crate::link::announce_channel_access(cfg, &ch_key, created_at, 'f', std::slice::from_ref(&new_owner))
        .await;
    crate::link::announce_channel_access(cfg, &ch_key, created_at, 'o', &carried).await;

    // Said out loud, in the channel, whoever did it. A transfer that only the
    // two people involved could see would be a quiet way to take a room.
    let by = match (may_move_channels, oper_name.as_deref()) {
        (true, Some(name)) if !owns_it => format!("network operator {name}"),
        (true, None) if !owns_it => "a network operator".to_string(),
        _ => nick.clone(),
    };
    let announcement = Message::new(
        "NOTICE",
        vec![
            ch_name.clone(),
            format!("{ch_name} now belongs to {new_owner}, handed over by {by}"),
        ],
    )
    .with_prefix(&cfg.server.name);
    let members: Vec<String> = {
        let store = channels.read().await;
        match store.channels.get(&ch_key) {
            Some(ch) => ch.read().await.members.keys().cloned().collect(),
            None => Vec::new(),
        }
    };
    for member_id in &members {
        senders.read().await.deliver(member_id, &announcement);
    }
    for member_nick in &reopped {
        let mode = Message::new(
            "MODE",
            vec![ch_name.clone(), "+o".into(), member_nick.clone()],
        )
        .with_prefix(&cfg.server.name);
        for other in &members {
            senders.read().await.deliver(other, &mode);
        }
    }

    if may_move_channels && !owns_it {
        tracing::warn!(
            client_id,
            channel = %ch_key,
            from = %founder,
            to = %new_owner,
            oper = %oper_name.unwrap_or_else(|| nick.clone()),
            "CHANOWN: an operator moved a channel they do not own"
        );
    } else {
        tracing::info!(client_id, channel = %ch_key, from = %founder, to = %new_owner, "CHANOWN");
    }

    reply_to_client(
        &senders,
        client_id,
        Message::new(
            "NOTE",
            vec![
                "CHANOWN".into(),
                "TRANSFERRED".into(),
                ch_name.clone(),
                new_owner.clone(),
                format!("{ch_name} now belongs to {new_owner}"),
            ],
        )
        .with_prefix(&cfg.server.name),
        label,
    )
    .await;
    Ok(())
}
