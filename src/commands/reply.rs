use crate::protocol::{generate_msgid, Message};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Sends a reply to the requesting client. If `label` is Some (labeled-response),
/// the message is sent with a `label` tag so the client can correlate the reply.
pub async fn reply_to_client(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    mut msg: Message,
    label: Option<&str>,
) {
    if let Some(l) = label {
        msg.add_tag("label", Some(l.to_string()));
    }
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(msg).await;
    }
}

/// Send a labeled-response ACK for commands that produce no other response.
pub async fn send_labeled_ack(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    label: &str,
    server_name: &str,
) {
    let mut ack = Message::new("ACK", vec![]);
    ack.prefix = Some(server_name.to_string());
    ack.add_tag("label", Some(label.to_string()));
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(ack).await;
    }
}

/// Start a labeled-response batch. Returns the batch reference tag.
/// Sends BATCH +ref labeled-response with the label tag.
pub async fn start_labeled_batch(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
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
        let _ = tx.send(batch_start).await;
    }
    batch_ref
}

/// End a labeled-response batch.
pub async fn end_labeled_batch(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    batch_ref: &str,
    server_name: &str,
) {
    let mut batch_end = Message::new("BATCH", vec![format!("-{}", batch_ref)]);
    batch_end.prefix = Some(server_name.to_string());
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(batch_end).await;
    }
}

/// Send a reply inside a labeled-response batch (adds batch tag, no label tag).
pub async fn reply_in_batch(
    senders: &Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>>,
    client_id: &str,
    mut msg: Message,
    batch_ref: &str,
) {
    msg.add_tag("batch", Some(batch_ref.to_string()));
    if let Some(tx) = senders.read().await.get(client_id) {
        let _ = tx.send(msg).await;
    }
}
