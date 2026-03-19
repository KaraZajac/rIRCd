use crate::protocol::Message;
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
