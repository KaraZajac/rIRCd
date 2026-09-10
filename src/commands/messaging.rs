use crate::channel::{canonical_channel_key, ChannelStore};
use crate::commands::{reply_to_client, reply_to_sender};
use crate::config::Config;
use crate::persist;
use crate::protocol::{add_tags_for_recipient, generate_msgid, Message, SenderTags};
use crate::user::{PendingClientBatch, PendingMultilineBatch, Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Deliver to a user: every connection they have open, not just one.
///
/// Channel members and message targets are users, and a user may be reading on
/// more than one connection at a time.
async fn send_to_client(senders: &Senders, user_id: &str, msg: Message) {
    senders.read().await.deliver(user_id, &msg);
}

/// One line to a recipient, skipping a connection when it is named.
///
/// The connection that sent a batch sees it back only if it asked to; the
/// user's other connections did not send it and see it like anybody else.
async fn deliver_skipping(senders: &Senders, user_id: &str, skip: Option<&str>, msg: Message) {
    let registry = senders.read().await;
    match skip {
        Some(session) => registry.deliver_except(user_id, session, &msg),
        None => registry.deliver(user_id, &msg),
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
/// A CTCP that +C blocks. ACTION is how clients send "/me", which is ordinary
/// conversation rather than a client query, so it is not blocked.
fn is_blockable_ctcp(text: &str) -> bool {
    let Some(body) = text.strip_prefix('\x01') else {
        return false;
    };
    let verb = body.split([' ', '\x01']).next().unwrap_or("");
    !verb.eq_ignore_ascii_case("ACTION")
}

/// Send message to a recipient, adding server-time/msgid/account tags and client-only (+prefix) tags.
#[allow(clippy::too_many_arguments)]
async fn send_to_client_with_caps(
    senders: &Senders,
    to_id: &str,
    msg: Message,
    recipient_caps: &std::collections::HashSet<String>,
    sender_account: Option<&str>,
    msgid: Option<&str>,
    client_only_tags: Option<&std::collections::HashMap<String, Option<String>>>,
    client_tag_deny: Option<&[String]>,
    sender: &SenderTags,
) {
    let tagged = add_tags_for_recipient(
        msg,
        recipient_caps,
        sender_account,
        msgid,
        client_only_tags,
        client_tag_deny,
        sender,
    );
    send_to_client(senders, to_id, tagged).await;
}

/// Identity used for a direct conversation: the account when the user has one,
/// otherwise the nick.
///
/// Accounts outlive nicks, so keying on the account keeps a conversation
/// together when someone changes nick. An unregistered user has only a nick,
/// and rIRCd account names are nicks, so the two coincide for everyone else.
/// The identity a conversation is keyed by: the account when the user has one,
/// otherwise the bare nick, each marked so the two can never collide.
async fn conversation_key_id(state: &ServerState, nick: &str) -> String {
    if let Some(id) = state.nick_to_id.get(&crate::casefold::upper(nick)) {
        if let Some(client) = state.clients.get(id) {
            let g = client.read().await;
            return match g.account {
                Some(ref a) => crate::persist::account_id(a),
                None => crate::persist::nick_id(g.nick_or_id()),
            };
        }
    }
    crate::persist::nick_id(nick)
}

async fn conversation_identity(state: &ServerState, nick: &str) -> String {
    if let Some(id) = state.nick_to_id.get(&crate::casefold::upper(nick)) {
        if let Some(client) = state.clients.get(id) {
            let g = client.read().await;
            return g
                .account
                .clone()
                .unwrap_or_else(|| g.nick_or_id().to_string());
        }
    }
    nick.to_string()
}

/// Does `text` mention `nick`? Matched case-insensitively on word boundaries, so
/// "kara: hi" and "hi kara!" count but "karaoke" does not.
fn mentions_nick(text: &str, nick: &str) -> bool {
    if nick.is_empty() {
        return false;
    }
    let text_lower = text.to_lowercase();
    let nick_lower = nick.to_lowercase();
    let bytes = text_lower.as_bytes();

    let mut from = 0;
    while let Some(pos) = text_lower[from..].find(&nick_lower) {
        let start = from + pos;
        let end = start + nick_lower.len();
        let before_ok = start == 0 || !is_nick_char(bytes[start - 1] as char);
        let after_ok = end >= bytes.len() || !is_nick_char(bytes[end] as char);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Characters that can appear inside a nick, for mention boundary checks.
fn is_nick_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "[]\\`_^{|}-".contains(c)
}

/// Notify accounts that belong to `channel` but have no connection right now.
///
/// A push is the only way a mention reaches someone who is away, and the message
/// itself is waiting for them in the channel's history when they return.
/// Whether a direct message may be delivered to this person.
///
/// User mode `+R` says only people with an account may write to them, which is
/// the one thing that makes an inbox usable when somebody has decided to fill
/// it. The sender is told, rather than being left to believe it went.
async fn refuses_unregistered(state: &ServerState, target_id: &str, sender_account: Option<&str>) -> bool {
    if sender_account.is_some() {
        return false;
    }
    match state.clients.get(target_id) {
        Some(c) => c.read().await.registered_only,
        None => false,
    }
}

/// A user on another server is reached over the link it came from, not through
/// a connection here. Returns whether the message went that way, so the caller
/// delivers locally only when it did not.
async fn deliver_across_link(
    state: &ServerState,
    cfg: &Config,
    sender_id: &str,
    target_id: &str,
    msg: &Message,
    msgid: &str,
) -> bool {
    let remote = match state.clients.get(target_id) {
        Some(c) => c.read().await.server.is_some(),
        None => false,
    };
    if !remote {
        return false;
    }
    // The message keeps its identity across the link: one msgid and one time,
    // whichever server the recipient turns out to be reading from. What the
    // recipient is shown of that is their own server's decision, made against
    // the capabilities they negotiated with it.
    let mut out = msg.clone();
    out.tags.insert("msgid".to_string(), Some(msgid.to_string()));
    crate::link::route_to_user(cfg, &state.user_id(sender_id), target_id, &out).await
}

async fn push_absent_members(
    state: &ServerState,
    cfg: &Config,
    channel_key: &str,
    base_msg: &Message,
    msgid: &str,
    sender_account: Option<&str>,
    sender_tags: &SenderTags,
    text: &str,
) {
    if cfg.webpush_runtime.is_none() {
        return;
    }
    let Some(accounts) = state.channel_accounts.get(channel_key) else {
        return;
    };

    let caps: std::collections::HashSet<String> = ["message-tags", "server-time", "account-tag"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    for account in accounts {
        // An absent user is known by their account name, which is their nick.
        if !mentions_nick(text, account) {
            continue;
        }
        // Connected users are served by the per-recipient path.
        let connected = match state.nick_to_id.get(&crate::casefold::upper(account)) {
            Some(id) => match state.clients.get(id) {
                Some(c) => c
                    .try_read()
                    .map(|g| g.account.as_deref() == Some(account.as_str()))
                    .unwrap_or(true),
                None => false,
            },
            None => false,
        };
        if connected {
            continue;
        }
        let tagged = add_tags_for_recipient(
            base_msg.clone(),
            &caps,
            sender_account,
            Some(msgid),
            None,
            cfg.server.client_tag_deny.as_deref(),
            sender_tags,
        );
        crate::webpush::notify(cfg, account, &tagged);
    }
}

/// Queue a Web Push notification for a message just delivered to `recipient_id`.
///
/// Notifications are what push exists for, so only messages a user would want to be
/// woken for qualify: direct messages, and channel messages that mention their nick.
/// `channel_text` is `Some` for channel traffic and `None` for direct messages.
#[allow(clippy::too_many_arguments)]
async fn push_notify(
    state: &ServerState,
    cfg: &Config,
    recipient_id: &str,
    base_msg: &Message,
    msgid: &str,
    sender_account: Option<&str>,
    sender: &SenderTags,
    channel_text: Option<&str>,
) {
    if cfg.webpush_runtime.is_none() {
        return;
    }
    let Some(client) = state.clients.get(recipient_id) else {
        return;
    };
    let (account, nick) = {
        let g = client.read().await;
        (g.account.clone(), g.nick.clone().unwrap_or_default())
    };
    let Some(account) = account else {
        return; // Subscriptions are per account; anonymous clients have none.
    };
    if let Some(text) = channel_text {
        if !mentions_nick(text, &nick) {
            return;
        }
    }

    // The payload is one IRC message. msgid must survive; server-time and account
    // are cheap and let a woken client place the message.
    let caps: std::collections::HashSet<String> = ["message-tags", "server-time", "account-tag"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let tagged = add_tags_for_recipient(
        base_msg.clone(),
        &caps,
        sender_account,
        Some(msgid),
        None,
        cfg.server.client_tag_deny.as_deref(),
        sender,
    );
    crate::webpush::notify(cfg, &account, &tagged);
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_privmsg(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
    parent_batch: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    // The text is params[1]: `PRIVMSG #chan` has none, and trailing() would
    // return the target as the message body.
    let text = msg.params.get(1).cloned().unwrap_or_default();

    if target.is_empty() || text.is_empty() {
        let (numeric, why) = if target.is_empty() {
            ("411", "No recipient given (PRIVMSG)")
        } else {
            ("412", "No text to send")
        };
        let nick = match state.read().await.clients.get(client_id) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => "*".to_string(),
        };
        reply_to_sender(
            &senders,
            client_id,
            Message::new(numeric, vec![nick, why.into()]).with_prefix(&cfg.server.name),
            label,
            parent_batch,
        )
        .await;
        return Ok(());
    }

    // TARGMAX enforcement: only 1 target allowed per PRIVMSG
    if target.contains(',') {
        let nick = {
            let sg = state.read().await;
            match sg.clients.get(client_id) {
                Some(c) => c.read().await.nick_or_id().to_string(),
                None => "*".to_string(),
            }
        };
        reply_to_sender(
            &senders,
            client_id,
            Message::new(
                "407",
                vec![nick, target.into(), "Too many recipients".into()],
            )
            .with_prefix(&cfg.server.name),
            label,
            parent_batch,
        )
        .await;
        return Ok(());
    }

    let state_guard = state.read().await;
    let client = match state_guard.clients.get(client_id) {
        Some(c) => c.clone(),
        None => {
            reply_to_sender(
                &senders,
                client_id,
                Message::new("451", vec!["*".into(), "You have not registered".into()])
                    .with_prefix(&cfg.server.name),
                label,
                parent_batch,
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
    let sender_tags = SenderTags::new(sender_data.bot, sender_data.oper_name.clone());
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
            reply_to_sender(
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
                parent_batch,
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
    // The one time this message was sent, used for every copy of it.
    let sent_at = crate::protocol::server_time_now();
    {
        let mut state_w = state.write().await;
        let sender = state_w.user_id(client_id);
        state_w.record_msgid(msgid.clone(), target.to_string(), sender);
    }
    // If this is an edit, update the channel history entry in the DB.
    if let Some(ref orig_msgid) = pending_edit_msgid {
        // The original may still be queued in the history writer.
        cfg.flush_history().await;
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
            // +n: reject non-members when no-external-messages is set
            if !ch.is_member(&state_guard.user_id(client_id)) && ch.modes.no_external {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "Cannot send to channel (+n)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +C: block CTCP queries, but not ACTION
            if ch.modes.no_ctcp && is_blockable_ctcp(&text) {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "CTCPs are not allowed in this channel (+C)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +q, or a mute extban. Voice is permission to speak, so it lifts
            // either one.
            if !ch
                .members
                .get(&state_guard.user_id(client_id))
                .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                .unwrap_or(false)
                && ch.is_muted(sender_account.as_deref(), &source)
            {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "You are quieted in this channel (+q)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +R: registered users only for speaking
            if ch.modes.registered_only && sender_account.is_none() {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "You must be registered to speak here (+R)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +m: only voiced/halfop/op may send to moderated channels
            if ch.modes.moderated
                && !ch
                    .members
                    .get(&state_guard.user_id(client_id))
                    .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                    .unwrap_or(false)
            {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "Cannot send to channel (+m)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
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
            let mut base_msg =
                Message::new("PRIVMSG", vec![display_target, text.clone()]).with_prefix(&source);
            base_msg
                .tags
                .insert("time".to_string(), Some(sent_at.clone()));
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
                if state_guard.is_self(mid, client_id) {
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
                        &sender_tags,
                    );
                    if echo_message {
                        reply_to_sender(&senders, client_id, tagged.clone(), label, parent_batch)
                            .await;
                    }
                    // The sender's other connections did not send anything, so
                    // they see it as any other member of the channel does.
                    senders
                        .read()
                        .await
                        .deliver_except(mid, client_id, &tagged);
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
                    &sender_tags,
                )
                .await;
                push_notify(
                    &state_guard,
                    cfg,
                    mid,
                    &base_msg,
                    &msgid,
                    sender_account.as_deref(),
                    &sender_tags,
                    Some(&text),
                )
                .await;
            }
            // Only append new history if this is NOT an edit (edits already updated in-place)
            if pending_edit_msgid.is_none() {
                cfg.record_history_at(&ch_key, &source, &text, Some(&msgid), "PRIVMSG", &sent_at);
            }
            // The other servers holding members of this channel deliver to
            // their own. It goes out once per link, not once per person.
            let mut across = base_msg.clone();
            across.tags.insert("msgid".to_string(), Some(msgid.clone()));
            crate::link::announce_channel_message(
                cfg,
                &state_guard.user_id(client_id),
                &ch_key,
                &across,
            )
            .await;
            push_absent_members(
                &state_guard,
                cfg,
                &ch_key,
                &base_msg,
                &msgid,
                sender_account.as_deref(),
                &sender_tags,
                &text,
            )
            .await;
        } else {
            reply_to_sender(
                &senders,
                client_id,
                Message::new("403", vec![target.into(), "No such channel".into()])
                    .with_prefix(&cfg.server.name),
                label,
                parent_batch,
            )
            .await;
        }
    } else {
        let target_id = state_guard.nick_to_id.get(&crate::casefold::upper(target)).cloned();
        if let Some(tid) = target_id {
            if refuses_unregistered(&state_guard, &tid, sender_account.as_deref()).await {
                drop(state_guard);
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "477",
                        vec![
                            sender_nick.clone(),
                            target.to_string(),
                            "You must be identified to a registered account to message this user"
                                .into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }
            let mut privmsg =
                Message::new("PRIVMSG", vec![target.into(), text.clone()]).with_prefix(&source);
            privmsg
                .tags
                .insert("time".to_string(), Some(sent_at.clone()));
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            if !deliver_across_link(&state_guard, cfg, client_id, &tid, &privmsg, &msgid).await {
                send_to_client_with_caps(
                    &senders,
                    &tid,
                    privmsg.clone(),
                    &target_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                    &sender_tags,
                )
                .await;
                push_notify(
                    &state_guard,
                    cfg,
                    &tid,
                    &privmsg,
                    &msgid,
                    sender_account.as_deref(),
                    &sender_tags,
                    None,
                )
                .await;
            }

            // Keep direct conversations in history so CHATHISTORY can replay them.
            if pending_edit_msgid.is_none() {
                let me = match sender_account {
                    Some(ref a) => persist::account_id(a),
                    None => persist::nick_id(&sender_nick),
                };
                let peer = conversation_key_id(&state_guard, target).await;
                let key = persist::direct_message_key(&me, &peer);
                cfg.record_history_at(&key, &source, &text, Some(&msgid), "PRIVMSG", &sent_at);
            }
            // 301 RPL_AWAY if target is away
            let target_away = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.away_message.clone(),
                None => None,
            };
            if let Some(away_msg) = target_away {
                let sender_nick = source.split('!').next().unwrap_or("*").to_string();
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new("301", vec![sender_nick, target.to_string(), away_msg])
                        .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
            }
            // The sender's other connections are that same person, writing from
            // somewhere else. A message sent from a phone belongs in the
            // conversation on the desktop, whether or not the phone asked to see
            // its own messages back.
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
                &sender_tags,
            );
            let self_id = state_guard.user_id(client_id);
            senders
                .read()
                .await
                .deliver_except(&self_id, client_id, &tagged);
            if echo_message {
                reply_to_sender(&senders, client_id, tagged, label, parent_batch).await;
            }
        } else {
            reply_to_sender(
                &senders,
                client_id,
                Message::new(
                    "401",
                    vec![
                        sender_nick.clone(),
                        target.into(),
                        "No such nick/channel".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
                parent_batch,
            )
            .await;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_notice(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
    parent_batch: Option<&str>,
) -> anyhow::Result<()> {
    let raw_target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let text = msg.trailing().unwrap_or("").to_string();

    if raw_target.is_empty() || text.is_empty() {
        return Ok(());
    }

    // TARGMAX enforcement: only 1 target allowed per NOTICE
    if raw_target.contains(',') {
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
    let sender_tags = SenderTags::new(sender_data.bot, sender_data.oper_name.clone());
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
    // The one time this message was sent, used for every copy of it.
    let sent_at = crate::protocol::server_time_now();
    {
        let mut state_w = state.write().await;
        let sender = state_w.user_id(client_id);
        state_w.record_msgid(msgid.clone(), target.to_string(), sender);
    }
    let state_guard = state.read().await;

    let display_target = if let Some(pfx) = statusmsg_prefix {
        format!("{}{}", pfx, target)
    } else {
        target.to_string()
    };
    let mut base_msg =
        Message::new("NOTICE", vec![display_target, text.clone()]).with_prefix(&source);
    base_msg
        .tags
        .insert("time".to_string(), Some(sent_at.clone()));

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;
            // +n: reject non-members when no-external-messages is set
            if !ch.is_member(&state_guard.user_id(client_id)) && ch.modes.no_external {
                return Ok(());
            }
            // +m: only voiced/op may send
            if ch.modes.moderated
                && !ch
                    .members
                    .get(&state_guard.user_id(client_id))
                    .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                    .unwrap_or(false)
            {
                return Ok(()); // NOTICE silently drops per RFC
            }
            // +R: registered-only channel
            if ch.modes.registered_only && sender_account.is_none() {
                return Ok(());
            }
            // +q, or a mute extban. Voice is permission to speak, so it lifts
            // either one.
            if !ch
                .members
                .get(&state_guard.user_id(client_id))
                .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                .unwrap_or(false)
                && ch.is_muted(sender_account.as_deref(), &source)
            {
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
                if state_guard.is_self(mid, client_id) {
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
                        &sender_tags,
                    );
                    if echo_message {
                        reply_to_sender(&senders, client_id, tagged.clone(), label, parent_batch)
                            .await;
                    }
                    // The sender's other connections did not send anything, so
                    // they see it as any other member of the channel does.
                    senders
                        .read()
                        .await
                        .deliver_except(mid, client_id, &tagged);
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
                    &sender_tags,
                )
                .await;
                push_notify(
                    &state_guard,
                    cfg,
                    mid,
                    &base_msg,
                    &msgid,
                    sender_account.as_deref(),
                    &sender_tags,
                    Some(&text),
                )
                .await;
            }
            if statusmsg_prefix.is_none() {
                cfg.record_history_at(&ch_key, &source, &text, Some(&msgid), "NOTICE", &sent_at);
            }
            let mut across = base_msg.clone();
            across.tags.insert("msgid".to_string(), Some(msgid.clone()));
            crate::link::announce_channel_message(
                cfg,
                &state_guard.user_id(client_id),
                &ch_key,
                &across,
            )
            .await;
        }
    } else {
        let target_id = state_guard.nick_to_id.get(&crate::casefold::upper(target)).cloned();
        if let Some(tid) = target_id {
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            if !deliver_across_link(&state_guard, cfg, client_id, &tid, &base_msg, &msgid).await {
                send_to_client_with_caps(
                    &senders,
                    &tid,
                    base_msg.clone(),
                    &target_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                    &sender_tags,
                )
                .await;
                push_notify(
                    &state_guard,
                    cfg,
                    &tid,
                    &base_msg,
                    &msgid,
                    sender_account.as_deref(),
                    &sender_tags,
                    None,
                )
                .await;
            }

            {
                let sender_nick = source.split('!').next().unwrap_or(&source);
                let me = match sender_account {
                    Some(ref a) => persist::account_id(a),
                    None => persist::nick_id(sender_nick),
                };
                let peer = conversation_key_id(&state_guard, target).await;
                let key = persist::direct_message_key(&me, &peer);
                cfg.record_history_at(&key, &source, &text, Some(&msgid), "NOTICE", &sent_at);
            }
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
                    &sender_tags,
                );
                reply_to_sender(&senders, client_id, tagged, label, parent_batch).await;
            }
        }
    }

    Ok(())
}

pub(crate) const MULTILINE_MAX_BYTES: usize = 4096;
pub(crate) const MULTILINE_MAX_LINES: usize = 20;

/// Deliver a completed draft/multiline batch: validate, then send as batch to capable clients or as separate lines to others.
/// A multiline batch as a client that cannot receive one should see it: the
/// lines as separate messages, minus the blank ones. A blank line separates
/// paragraphs within the batch and has nothing to say on its own.
fn flatten_multiline(lines: &[(bool, String)]) -> Vec<String> {
    lines
        .iter()
        .map(|(_, text)| text.clone())
        .filter(|l| !l.is_empty())
        .collect()
}

pub async fn deliver_multiline_batch(
    client_id: &str,
    batch: PendingMultilineBatch,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
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
                    "Invalid multiline batch with blank lines only".into(),
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
                    "Multiline batch max-lines exceeded".into(),
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
                    "Multiline batch max-bytes exceeded".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    let (source, sender_account, sender_tags, echo_message) = {
        let state_guard = state.read().await;
        let client = match state_guard.clients.get(client_id) {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let g = client.read().await;
        let source = g.source().unwrap_or_else(|| client_id.to_string());
        let account = g.account.clone();
        let tags = SenderTags::new(g.bot, g.oper_name.clone());
        let echo = g.has_cap("echo-message");
        (source, account, tags, echo)
    };

    let msgid = generate_msgid();
    {
        let mut state_w = state.write().await;
        let sender = state_w.user_id(client_id);
        state_w.record_msgid(msgid.clone(), batch.target.clone(), sender);
    }

    let state_guard = state.read().await;
    let recipient_ids: Vec<String> =
        if batch.target.starts_with('#') || batch.target.starts_with('&') {
            let ch_key = canonical_channel_key(&batch.target);
            let ch_store = channels.read().await;
            match ch_store.channels.get(&ch_key) {
                Some(ch) => {
                    let ch = ch.read().await;
                    if !ch.is_member(&state_guard.user_id(client_id)) {
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
            match state_guard.nick_to_id.get(&crate::casefold::upper(&batch.target)) {
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
    let batch_tags = batch.tags.clone();
    // One message, so one timestamp: every line a client sees, batched or
    // flattened, carries the time the message was sent.
    let batch_time = crate::protocol::server_time_now();

    // Taken before the guard goes: the recipients are users, and the connection
    // that sent this is not one.
    let self_id = state_guard.user_id(client_id);
    drop(state_guard);

    for mid in &recipient_ids {
        // The sender's own connection is answered by the echo-message block
        // below: sending it here too would deliver the whole batch twice, and
        // would reach senders that never asked for an echo. Its owner's other
        // connections did not send anything and see it like anybody else.
        let skip = if *mid == self_id {
            Some(client_id)
        } else {
            None
        };
        if skip.is_some() && senders.read().await.sessions_of(mid).len() < 2 {
            continue;
        }
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
            // draft/multiline: one message split over several lines, so the
            // msgid, time and client-only tags belong to the batch as a whole
            // and are attached to its opening message, not to each line.
            let mut start = batch_start.clone();
            start
                .tags
                .insert("time".to_string(), Some(batch_time.clone()));
            let tagged_start = add_tags_for_recipient(
                start,
                &caps,
                sender_account.as_deref(),
                Some(&msgid),
                Some(&batch_tags),
                cfg.server.client_tag_deny.as_deref(),
                &sender_tags,
            );
            deliver_skipping(&senders, mid, skip, tagged_start).await;
            for (concat, text) in &batch.lines {
                let mut line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), text.clone()],
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
                deliver_skipping(&senders, mid, skip, line_msg).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", batch.ref_tag)])
                .with_prefix(&cfg.server.name);
            deliver_skipping(&senders, mid, skip, batch_end).await;
        } else {
            for (i, text) in flatten_multiline(&batch.lines).iter().enumerate() {
                let mut line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), text.clone()],
                )
                .with_prefix(&source);
                line_msg
                    .tags
                    .insert("time".to_string(), Some(batch_time.clone()));
                // The msgid identifies the message, which was sent once: it goes
                // on the first line only, not on each fragment.
                let line_msgid = if i == 0 { Some(msgid.as_str()) } else { None };
                let tagged = add_tags_for_recipient(
                    line_msg,
                    &caps,
                    sender_account.as_deref(),
                    line_msgid,
                    Some(&batch_tags),
                    cfg.server.client_tag_deny.as_deref(),
                    &sender_tags,
                );
                deliver_skipping(&senders, mid, skip, tagged).await;
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
        // The label came in on the opening BATCH, not the closing one.
        let label = batch.label.as_deref().or(label);
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
            let mut echo_batch_start = echo_batch_start;
            echo_batch_start
                .tags
                .insert("time".to_string(), Some(batch_time.clone()));
            let tagged_start = add_tags_for_recipient(
                echo_batch_start,
                &sender_caps,
                sender_account.as_deref(),
                Some(&msgid),
                Some(&batch_tags),
                cfg.server.client_tag_deny.as_deref(),
                &sender_tags,
            );
            reply_to_client(&senders, client_id, tagged_start, label).await;
            for (concat, text) in &batch.lines {
                let mut line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), text.clone()],
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
                send_to_client(&senders, client_id, line_msg).await;
            }
            let batch_end = Message::new("BATCH", vec![format!("-{}", batch.ref_tag)])
                .with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_end).await;
        } else {
            for (i, text) in flatten_multiline(&batch.lines).iter().enumerate() {
                let mut line_msg = Message::new(
                    batch.command.clone(),
                    vec![batch.target.clone(), text.clone()],
                )
                .with_prefix(&source);
                line_msg
                    .tags
                    .insert("time".to_string(), Some(batch_time.clone()));
                let line_msgid = if i == 0 { Some(msgid.as_str()) } else { None };
                let tagged = add_tags_for_recipient(
                    line_msg,
                    &sender_caps,
                    sender_account.as_deref(),
                    line_msgid,
                    Some(&batch_tags),
                    cfg.server.client_tag_deny.as_deref(),
                    &sender_tags,
                );
                reply_to_client(&senders, client_id, tagged, label).await;
            }
        }
    }

    if batch.target.starts_with('#') || batch.target.starts_with('&') {
        let cmd = if batch.command == "NOTICE" {
            "NOTICE"
        } else {
            "PRIVMSG"
        };
        for (_, text) in &batch.lines {
            cfg.record_history(&batch.target, &source, text, Some(&msgid), cmd);
        }
    }

    Ok(())
}

/// Client-only tags worth keeping: a TAGMSG has no text, so unless it is marked
/// to persist there is nothing about it to replay.
const PERSIST_TAGS: &[&str] = &["+draft/persist", "+persist"];

fn tagmsg_should_persist(tags: &std::collections::HashMap<String, Option<String>>) -> bool {
    PERSIST_TAGS.iter().any(|t| tags.contains_key(*t))
}

/// A TAGMSG carries its meaning in its tags, so history stores them in place of
/// the text, in the same `key=value;key` form they arrive in.
fn serialize_client_tags(tags: &std::collections::HashMap<String, Option<String>>) -> String {
    let mut parts: Vec<String> = tags
        .iter()
        .filter(|(k, _)| k.starts_with('+'))
        .map(|(k, v)| match v {
            Some(v) => format!("{}={}", k, v),
            None => k.clone(),
        })
        .collect();
    parts.sort();
    parts.join(";")
}

fn parse_client_tags(s: &str) -> std::collections::HashMap<String, Option<String>> {
    let mut out = std::collections::HashMap::new();
    for part in s.split(';').filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            Some((k, v)) => out.insert(k.to_string(), Some(v.to_string())),
            None => out.insert(part.to_string(), None),
        };
    }
    out
}

/// TAGMSG: like PRIVMSG but no text; only delivered to clients with message-tags cap.
#[allow(clippy::too_many_arguments)]
pub async fn handle_tagmsg(
    client_id: &str,
    msg: Message,
    state: Arc<RwLock<ServerState>>,
    channels: Arc<RwLock<ChannelStore>>,
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
    parent_batch: Option<&str>,
) -> anyhow::Result<()> {
    let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    if target.is_empty() {
        reply_to_sender(
            &senders,
            client_id,
            Message::new("411", vec!["No recipient given (TAGMSG)".into()])
                .with_prefix(&cfg.server.name),
            label,
            parent_batch,
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
    let sender_nick = sender_data.nick_or_id().to_string();
    let sender_tags = SenderTags::new(sender_data.bot, sender_data.oper_name.clone());
    let echo_message = sender_data.has_cap("echo-message");
    drop(sender_data);
    drop(state_guard);

    let msgid = generate_msgid();
    // The one time this message was sent, used for every copy of it.
    let sent_at = crate::protocol::server_time_now();
    {
        let mut state_w = state.write().await;
        let sender = state_w.user_id(client_id);
        state_w.record_msgid(msgid.clone(), target.to_string(), sender);
    }
    let state_guard = state.read().await;

    let mut base_msg = Message::new("TAGMSG", vec![target.into()]).with_prefix(&source);
    base_msg
        .tags
        .insert("time".to_string(), Some(sent_at.clone()));

    if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(target);
        let ch_store = channels.read().await;
        if let Some(ch) = ch_store.channels.get(&ch_key) {
            let ch = ch.read().await;

            // +n: reject non-members when no-external-messages is set
            if !ch.is_member(&state_guard.user_id(client_id)) && ch.modes.no_external {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "Cannot send to channel (+n)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +q, or a mute extban. Voice is permission to speak, so it lifts
            // either one.
            if !ch
                .members
                .get(&state_guard.user_id(client_id))
                .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                .unwrap_or(false)
                && ch.is_muted(sender_account.as_deref(), &source)
            {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "You are quieted in this channel (+q)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +R: registered users only for speaking
            if ch.modes.registered_only && sender_account.is_none() {
                reply_to_sender(
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
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            // +m: only voiced/halfop/op may send to moderated channels
            if ch.modes.moderated
                && !ch
                    .members
                    .get(&state_guard.user_id(client_id))
                    .map(|m| m.modes.voice || m.modes.halfop || m.modes.op)
                    .unwrap_or(false)
            {
                reply_to_sender(
                    &senders,
                    client_id,
                    Message::new(
                        "404",
                        vec![
                            sender_nick.clone(),
                            target.into(),
                            "Cannot send to channel (+m)".into(),
                        ],
                    )
                    .with_prefix(&cfg.server.name),
                    label,
                    parent_batch,
                )
                .await;
                return Ok(());
            }

            if ch.is_member(&state_guard.user_id(client_id)) || !ch.modes.no_external {
                for mid in ch.members.keys() {
                    let caps = match state_guard.clients.get(mid) {
                        Some(c) => c.read().await.capabilities.clone(),
                        None => Default::default(),
                    };
                    if !caps.contains("message-tags") {
                        continue;
                    }
                    if state_guard.is_self(mid, client_id) {
                        let tagged = add_tags_for_recipient(
                            base_msg.clone(),
                            &caps,
                            sender_account.as_deref(),
                            Some(&msgid),
                            Some(&msg.tags),
                            cfg.server.client_tag_deny.as_deref(),
                            &sender_tags,
                        );
                        if echo_message {
                            reply_to_sender(
                                &senders,
                                client_id,
                                tagged.clone(),
                                label,
                                parent_batch,
                            )
                            .await;
                        }
                        senders
                            .read()
                            .await
                            .deliver_except(mid, client_id, &tagged);
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
                        &sender_tags,
                    )
                    .await;
                }
                if tagmsg_should_persist(&msg.tags) {
                    cfg.record_history(
                        &ch_key,
                        &source,
                        &serialize_client_tags(&msg.tags),
                        Some(&msgid),
                        "TAGMSG",
                    );
                }
                let mut across = base_msg.clone();
                across.tags.insert("msgid".to_string(), Some(msgid.clone()));
                crate::link::announce_channel_message(
                    cfg,
                    &state_guard.user_id(client_id),
                    &ch_key,
                    &across,
                )
                .await;
            }
        }
    } else {
        let target_id = state_guard.nick_to_id.get(&crate::casefold::upper(target)).cloned();
        if let Some(tid) = target_id {
            let target_caps = match state_guard.clients.get(&tid) {
                Some(c) => c.read().await.capabilities.clone(),
                None => Default::default(),
            };
            if !deliver_across_link(&state_guard, cfg, client_id, &tid, &base_msg, &msgid).await
                && target_caps.contains("message-tags")
            {
                send_to_client_with_caps(
                    &senders,
                    &tid,
                    base_msg.clone(),
                    &target_caps,
                    sender_account.as_deref(),
                    Some(&msgid),
                    Some(&msg.tags),
                    cfg.server.client_tag_deny.as_deref(),
                    &sender_tags,
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
                        &sender_tags,
                    );
                    reply_to_sender(&senders, client_id, tagged, label, parent_batch).await;
                }
            }
            if tagmsg_should_persist(&msg.tags) {
                let sender_nick = source.split('!').next().unwrap_or(&source);
                let me = match sender_account {
                    Some(ref a) => persist::account_id(a),
                    None => persist::nick_id(sender_nick),
                };
                let peer = conversation_key_id(&state_guard, target).await;
                let key = persist::direct_message_key(&me, &peer);
                cfg.record_history(
                    &key,
                    &source,
                    &serialize_client_tags(&msg.tags),
                    Some(&msgid),
                    "TAGMSG",
                );
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    // Per IRCv3 message-redaction spec: REDACT <target> <msgid> [:<reason>]
    let target_param = msg.params.first().map(|s| s.as_str()).unwrap_or("");
    let msgid = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
    let reason = msg.params.get(2).cloned();

    tracing::info!(client_id, target_param, msgid, "REDACT received");

    // A channel the client is not in is not a target it can redact in, and
    // saying so is a different answer from "no such message". An operator is
    // the exception: taking a message down is most of what the power is for,
    // and needing to join the channel first would announce the moderation to
    // everyone in it.
    if target_param.starts_with('#') || target_param.starts_with('&') {
        let ch_key = canonical_channel_key(target_param);
        let (user_id, is_oper) = {
            let state_r = state.read().await;
            let uid = state_r.user_id(client_id);
            let oper = match state_r.clients.get(client_id) {
                Some(c) => c.read().await.oper,
                None => false,
            };
            (uid, oper)
        };
        let is_member = {
            let ch_store = channels.read().await;
            match ch_store.channels.get(&ch_key) {
                Some(ch) => ch.read().await.members.contains_key(&user_id),
                None => false,
            }
        };
        if !is_member && !is_oper {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "REDACT".into(),
                        "INVALID_TARGET".into(),
                        target_param.to_string(),
                        "You are not on that channel".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
    }

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
        // The row may still be queued in the history writer.
        cfg.flush_history().await;
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
                            target_param.to_string(),
                            msgid.to_string(),
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

    // The message has to actually be in the target the client named: being an
    // operator of one channel is not authority over a message in another.
    if !target.eq_ignore_ascii_case(target_param) {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "REDACT".into(),
                    "UNKNOWN_MSGID".into(),
                    target_param.to_string(),
                    msgid.to_string(),
                    "No such message".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Authorization: own message (by nick), channel op, or IRC oper
    let is_own = sender_nick
        .as_deref()
        .map(|sn| sn.eq_ignore_ascii_case(&current_nick))
        .unwrap_or(false);

    let is_op = if target.starts_with('#') || target.starts_with('&') {
        let ch_key = canonical_channel_key(&target);
        let uid = state.read().await.user_id(client_id);
        let ch_store = channels.read().await;
        match ch_store.channels.get(&ch_key) {
            Some(ch) => ch
                .read()
                .await
                .members
                .get(&uid)
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
                    target_param.to_string(),
                    msgid.to_string(),
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

    // Delete from DB, once anything still queued has been written.
    cfg.flush_history().await;
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
    let mut relay_params = vec![target.clone(), msgid.to_string()];
    if let Some(ref r) = reason {
        relay_params.push(r.clone());
    }
    let redact_relay = Message::new("REDACT", relay_params).with_prefix(&source);

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
                    Some(c) => c
                        .read()
                        .await
                        .capabilities
                        .contains("draft/message-redaction"),
                    None => false,
                };
                if has_cap {
                    send_to_client(&senders, mid, redact_relay.clone()).await;
                }
            }
            // An operator taking a message down from a channel they are not in
            // is not in that list, and would be left wondering whether the
            // command had done anything.
            let uid = state_r.user_id(client_id);
            let watching = member_ids.contains(&uid);
            let has_cap = state_r
                .clients
                .get(client_id)
                .and_then(|c| c.try_read().ok())
                .map(|g| g.capabilities.contains("draft/message-redaction"))
                .unwrap_or(false);
            if !watching && has_cap {
                drop(state_r);
                send_to_client(&senders, client_id, redact_relay.clone()).await;
            }
        }
    } else {
        // DM: send to the redacting client and the other party if they have the cap
        let state_r = state.read().await;
        let tid_opt = state_r.nick_to_id.get(&crate::casefold::upper(&target)).cloned();
        let sender_has_cap = state_r
            .clients
            .get(client_id)
            .and_then(|c| c.try_read().ok())
            .map(|g| g.capabilities.contains("draft/message-redaction"))
            .unwrap_or(false);
        let recipient_has_cap = tid_opt
            .as_deref()
            .and_then(|tid| state_r.clients.get(tid))
            .and_then(|c| c.try_read().ok())
            .map(|g| g.capabilities.contains("draft/message-redaction"))
            .unwrap_or(false);
        drop(state_r);

        if sender_has_cap {
            send_to_client(&senders, client_id, redact_relay.clone()).await;
        }
        if let Some(ref tid) = tid_opt {
            if !state.read().await.is_self(tid, client_id) && recipient_has_cap {
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
    senders: Senders,
    cfg: &Config,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let pool = match cfg.db.as_ref() {
        Some(p) => p,
        None => return Ok(()),
    };
    if cfg.db_health.is_down() {
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "CHATHISTORY".into(),
                    "MESSAGE_ERROR".into(),
                    msg.params.first().cloned().unwrap_or_else(|| "*".into()),
                    "History is temporarily unavailable".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }
    // History is queued and written in batches, so a client asking right after
    // it spoke would otherwise be told its own last messages do not exist.
    cfg.flush_history().await;
    let params = &msg.params;
    let (requester_nick, requester_identity, requester_user_id) = {
        let state_r = state.read().await;
        match state_r.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                let nick = g.nick_or_id().to_string();
                let identity = match g.account {
                    Some(ref a) => crate::persist::account_id(a),
                    None => crate::persist::nick_id(&nick),
                };
                (nick, identity, g.id.clone())
            }
            None => return Ok(()),
        }
    };
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
        let targets =
            persist::list_history_targets(pool, from_ts, to_ts, limit, &requester_identity).await;
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
                vec![format!("+{}", ref_id), "draft/chathistory-targets".into()],
            )
            .with_prefix(&cfg.server.name);
            send_to_client(&senders, client_id, batch_start).await;
        }
        for (chan, latest_ts) in &targets {
            let mut m = Message::new(
                "CHATHISTORY",
                vec!["TARGETS".into(), chan.clone(), latest_ts.clone()],
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
    } else if subcommand.starts_with('#') || subcommand.starts_with('&') {
        // Legacy: CHATHISTORY #channel [count]
        let target = params.first().map(|s| s.as_str()).unwrap_or("");
        let limit_param = params
            .get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);
        (target, "*", None, limit_param.min(CHATHISTORY_LIMIT))
    } else {
        // Anything else is an unknown subcommand, which the spec answers with a
        // standard reply rather than a numeric about the channel name.
        reply_to_client(
            &senders,
            client_id,
            Message::new(
                "FAIL",
                vec![
                    "CHATHISTORY".into(),
                    "INVALID_PARAMS".into(),
                    subcommand.clone(),
                    "Unknown command".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
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
                    subcommand.clone(),
                    "A target is required".into(),
                ],
            )
            .with_prefix(&cfg.server.name),
            label,
        )
        .await;
        return Ok(());
    }

    // Direct conversations are stored under a key derived from both nicks, so a
    // client can only ever address a conversation it is part of.
    let is_channel_target = target.starts_with('#') || target.starts_with('&');
    // The peer as the server knows it, which is not necessarily how the client
    // spelled it: nicks are case-insensitive, so a client may ask for a
    // conversation with FOO and the replayed messages still have to name foo.
    let (canonical_peer, peer_key_id) = if is_channel_target {
        (target.to_string(), String::new())
    } else {
        let state_r = state.read().await;
        (
            conversation_identity(&state_r, target).await,
            conversation_key_id(&state_r, target).await,
        )
    };
    let history_key = if is_channel_target {
        canonical_channel_key(target)
    } else {
        persist::direct_message_key(&requester_identity, &peer_key_id)
    };

    // Channel history is for members; a direct conversation is addressed by a key
    // built from the requester's own nick, so membership is implicit.
    let is_member = if is_channel_target {
        let ch_store = channels.read().await;
        match ch_store.channels.get(&history_key) {
            Some(ch) => ch.read().await.members.contains_key(&requester_user_id),
            None => false,
        }
    } else {
        true
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
                    // The third field is the subcommand that failed, so a
                    // client can tell which of several in flight this answers.
                    subcommand.clone(),
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
    tracing::debug!(client_id, subcommand = %subcommand, target, cursor, limit, "CHATHISTORY query");

    let entries = match (subcommand.as_str(), cursor) {
        ("AROUND", c) if c != "*" => {
            persist::read_channel_history_around(pool, &history_key, c, limit, include_events).await
        }
        ("BEFORE", c) if c != "*" => {
            persist::read_channel_history_before(pool, &history_key, c, limit, include_events).await
        }
        ("AFTER", c) if c != "*" => {
            persist::read_channel_history_after(pool, &history_key, c, limit, include_events).await
        }
        ("BETWEEN", c) if c != "*" => {
            let end = cursor2.unwrap_or("*");
            if end == "*" {
                persist::read_channel_history(pool, &history_key, limit, include_events).await
            } else {
                persist::read_channel_history_between(
                    pool,
                    &history_key,
                    c,
                    end,
                    limit,
                    include_events,
                )
                .await
            }
        }
        ("LATEST", c) if c != "*" => {
            persist::read_channel_history_latest_after(pool, &history_key, c, limit, include_events)
                .await
        }
        _ => persist::read_channel_history(pool, &history_key, limit, include_events).await,
    };

    // "No history" and "history could not be read" are different answers.
    cfg.db_health.note(entries.is_ok());
    let entries = match entries {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(client_id, target, error = %e.0, "CHATHISTORY: history unavailable");
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "CHATHISTORY".into(),
                        "MESSAGE_ERROR".into(),
                        subcommand.clone(),
                        target.to_string(),
                        "Messages could not be retrieved".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
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
        // In a direct conversation each side sees its own copy: a message the
        // requester sent was addressed to the other party, and vice versa.
        let reply_target = if is_channel_target {
            target.to_string()
        } else {
            let author = e.source.split('!').next().unwrap_or(&e.source);
            if author.eq_ignore_ascii_case(&requester_nick) {
                canonical_peer.clone()
            } else {
                requester_nick.clone()
            }
        };
        let target: &str = &reply_target;

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
            "TAGMSG" => {
                let mut m = Message::new("TAGMSG", vec![target.into()]);
                m.tags = parse_client_tags(&e.text);
                m
            }
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
            &SenderTags::default(), // replayed history carries no live sender state
        );
        send_to_client(&senders, client_id, tagged).await;
    }

    // If the client supports message-redaction, include REDACT events for any messages
    // that were soft-deleted within the returned time range, so the client can update
    // its local buffer on reconnect.
    if !entries.is_empty() && caps.contains("draft/message-redaction") {
        let redacted =
            persist::read_redacted_in_range(pool, &history_key, &oldest_ts, &newest_ts).await;
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
    senders: Senders,
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
    // Where a user has read up to belongs to the account, which comes back
    // tomorrow. A client with no account is keyed by its connection id so the
    // marker works for as long as the connection does — but that id never
    // returns, so it is not written to the database.
    let account = match client_arc {
        Some(c) => c.read().await.account.clone(),
        None => None,
    };
    let key = match account.clone() {
        Some(a) => a,
        None => state.read().await.user_id(client_id),
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
        // A marker that is not a timestamp would sort against the stored one as
        // arbitrary text, so it is rejected rather than stored.
        if chrono::DateTime::parse_from_rfc3339(&ts).is_err() {
            reply_to_client(
                &senders,
                client_id,
                Message::new(
                    "FAIL",
                    vec![
                        "MARKREAD".into(),
                        "INVALID_PARAMS".into(),
                        target.to_string(),
                        "Invalid timestamp".into(),
                    ],
                )
                .with_prefix(&cfg.server.name),
                label,
            )
            .await;
            return Ok(());
        }
        tracing::debug!(client_id, target, timestamp = %ts, "MARKREAD set");
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
        if let (Some(pool), true) = (cfg.db.as_ref(), account.is_some()) {
            persist::save_read_marker(pool, &key, target, &updated_ts).await;
        }
        let m = Message::new(
            "MARKREAD",
            vec![target.into(), format!("timestamp={}", updated_ts)],
        )
        .with_prefix(&cfg.server.name);
        // Where the user has read up to is the user's, not one connection's:
        // every session it has open needs to move its marker too.
        let user_id = state.read().await.user_id(client_id);
        let mut m_labelled = m;
        if let Some(l) = label {
            m_labelled.add_tag("label", Some(l.to_string()));
        }
        send_to_client(&senders, &user_id, m_labelled).await;
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
    senders: Senders,
    cfg: &Config,
    _label: Option<&str>,
) -> anyhow::Result<()> {
    if batch.messages.is_empty() {
        return Ok(());
    }

    let (source, sender_account, sender_tags, echo_message) = {
        let state_r = state.read().await;
        let client = match state_r.clients.get(client_id) {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        let g = client.read().await;
        let source = g.source().unwrap_or_else(|| client_id.to_string());
        let account = g.account.clone();
        let tags = SenderTags::new(g.bot, g.oper_name.clone());
        let echo = g.has_cap("echo-message");
        (source, account, tags, echo)
    };

    let state_r = state.read().await;
    let recipient_ids: Vec<String> =
        if batch.target.starts_with('#') || batch.target.starts_with('&') {
            let ch_key = canonical_channel_key(&batch.target);
            let ch_store = channels.read().await;
            match ch_store.channels.get(&ch_key) {
                Some(ch) => {
                    let ch = ch.read().await;
                    if !ch.is_member(&state_r.user_id(client_id)) {
                        return Ok(());
                    }
                    ch.members.keys().cloned().collect()
                }
                None => return Ok(()),
            }
        } else {
            match state_r.nick_to_id.get(&crate::casefold::upper(&batch.target)) {
                Some(tid) => vec![tid.clone()],
                None => return Ok(()),
            }
        };
    let self_id = state_r.user_id(client_id);
    drop(state_r);

    // Generate a server-side batch ref for each recipient (they can't share the client's ref tag)
    let server_ref = generate_msgid();

    for mid in &recipient_ids {
        // The connection that sent the batch gets it back only if it asked to.
        // Its owner's other connections always do.
        let skip = if *mid == self_id && !echo_message {
            Some(client_id)
        } else {
            None
        };
        if skip.is_some() && senders.read().await.sessions_of(mid).len() < 2 {
            continue;
        }
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
            deliver_skipping(&senders, mid, skip, batch_start).await;
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
                    &sender_tags,
                );
                deliver_skipping(&senders, mid, skip, tagged).await;
            }
            let batch_end =
                Message::new("BATCH", vec![format!("-{}", server_ref)]).with_prefix(&source);
            deliver_skipping(&senders, mid, skip, batch_end).await;
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
                    &sender_tags,
                );
                deliver_skipping(&senders, mid, skip, tagged).await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::mentions_nick;

    #[test]
    fn highlights_match_whole_nicks_only() {
        assert!(mentions_nick("kara: are you there?", "kara"));
        assert!(mentions_nick("thanks kara!", "kara"));
        assert!(mentions_nick("(kara)", "kara"));
        assert!(mentions_nick("KARA, hello", "kara"));
        assert!(mentions_nick("hello Kara", "kARa"));
        assert!(mentions_nick("ping kara", "KARA"));

        assert!(!mentions_nick("karaoke night", "kara"));
        assert!(!mentions_nick("mkara", "kara"));
        assert!(!mentions_nick("nothing to see", "kara"));
        assert!(!mentions_nick("", "kara"));
        assert!(!mentions_nick("anything", ""));
    }

    /// Nicks may contain []\`_^{|}- , so those must not act as word boundaries.
    #[test]
    fn nick_punctuation_is_part_of_the_nick() {
        assert!(mentions_nick("hey |away|_ how are you", "|away|_"));
        assert!(!mentions_nick("hey kara_ how are you", "kara"));
        assert!(!mentions_nick("hey kara-work", "kara"));
    }
}
