use crate::protocol::{generate_msgid, Message};
use crate::user::Senders;

/// What the connection that sent a command negotiated.
///
/// Not the user's capabilities: those are the union of its connections', and a
/// reply belongs to the one that asked. A client that never asked for
/// `extended-join` must not be answered in its form because another client on
/// the same account did.
pub async fn session_caps(senders: &Senders, client_id: &str) -> std::collections::HashSet<String> {
    senders.read().await.caps_of(client_id)
}

/// Sends a reply to the requesting client. If `label` is Some (labeled-response),
/// the message is sent with a `label` tag so the client can correlate the reply.
pub async fn reply_to_client(
    senders: &Senders,
    client_id: &str,
    mut msg: Message,
    label: Option<&str>,
) {
    if let Some(l) = label {
        msg.add_tag("label", Some(l.to_string()));
    }
    let registry = senders.read().await;
    if let Some(tx) = registry.get(client_id) {
        // Last gate before the socket: a reply carries only the tags this
        // connection asked for, whatever the code that built it believed.
        if !msg.tags.is_empty() {
            crate::protocol::retain_negotiated_tags(&mut msg, &registry.caps_of(client_id));
        }
        tx.send(msg);
    }
}

/// Send a labeled-response ACK for commands that produce no other response.
pub async fn send_labeled_ack(senders: &Senders, client_id: &str, label: &str, server_name: &str) {
    let mut ack = Message::new("ACK", vec![]);
    ack.prefix = Some(server_name.to_string());
    ack.add_tag("label", Some(label.to_string()));
    if let Some(tx) = senders.read().await.get(client_id) {
        tx.send(ack);
    }
}

/// Start a labeled-response batch. Returns the batch reference tag.
/// Sends BATCH +ref labeled-response with the label tag.
pub async fn start_labeled_batch(
    senders: &Senders,
    client_id: &str,
    label: &str,
    server_name: &str,
) -> String {
    let batch_ref = generate_msgid();
    let mut batch_start = Message::new(
        "BATCH",
        vec![format!("+{}", batch_ref), "labeled-response".into()],
    );
    batch_start.prefix = Some(server_name.to_string());
    batch_start.add_tag("label", Some(label.to_string()));
    if let Some(tx) = senders.read().await.get(client_id) {
        tx.send(batch_start);
    }
    batch_ref
}

/// End a labeled-response batch.
pub async fn end_labeled_batch(
    senders: &Senders,
    client_id: &str,
    batch_ref: &str,
    server_name: &str,
) {
    let mut batch_end = Message::new("BATCH", vec![format!("-{}", batch_ref)]);
    batch_end.prefix = Some(server_name.to_string());
    if let Some(tx) = senders.read().await.get(client_id) {
        tx.send(batch_end);
    }
}

/// Answer the client that sent the command, inside the batch when the command
/// opened one. A command naming several targets is one labeled response, so
/// its parts belong to a batch rather than each carrying the label.
pub async fn reply_to_sender(
    senders: &Senders,
    client_id: &str,
    msg: Message,
    label: Option<&str>,
    parent_batch: Option<&str>,
) {
    match parent_batch {
        Some(br) => reply_in_batch(senders, client_id, msg, br).await,
        None => reply_to_client(senders, client_id, msg, label).await,
    }
}

/// Send a reply inside a labeled-response batch (adds batch tag, no label tag).
pub async fn reply_in_batch(senders: &Senders, client_id: &str, mut msg: Message, batch_ref: &str) {
    msg.add_tag("batch", Some(batch_ref.to_string()));
    if let Some(tx) = senders.read().await.get(client_id) {
        tx.send(msg);
    }
}
