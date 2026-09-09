use crate::protocol::{format_message, parse_message, Message, ParseError};
use crate::server::ClientMessage;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const BUF_SIZE: usize = 8192;

/// Tell a connection why it is being refused, then close it.
async fn refuse_connection(mut stream: tokio::net::TcpStream, server_name: &str, reason: &str) {
    let line = format!(":{} ERROR :Closing link: {}\r\n", server_name, reason);
    let _ = stream.write_all(line.as_bytes()).await;
    let _ = stream.flush().await;
}

async fn refuse_connection_tls(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    server_name: &str,
    reason: &str,
) {
    let line = format!(":{} ERROR :Closing link: {}\r\n", server_name, reason);
    let _ = stream.write_all(line.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Tracks how many connections each address has open, so one host cannot exhaust
/// the server by opening sockets.
#[derive(Clone, Debug, Default)]
pub struct ConnectionLimits {
    pub max_per_ip: usize,
    pub max_total: usize,
    counts: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    total: Arc<std::sync::atomic::AtomicUsize>,
}

/// Releases a connection's slot when the connection ends.
pub struct ConnectionSlot {
    limits: ConnectionLimits,
    host: String,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.limits.counts.lock() {
            if let Some(n) = counts.get_mut(&self.host) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    counts.remove(&self.host);
                }
            }
        }
        self.limits
            .total
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl ConnectionLimits {
    pub fn new(max_per_ip: usize, max_total: usize) -> Self {
        Self {
            max_per_ip,
            max_total,
            ..Default::default()
        }
    }

    /// Claim a slot for `host`, or report why it was refused.
    pub fn claim(&self, host: &str) -> Result<ConnectionSlot, &'static str> {
        let total = self
            .total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if self.max_total > 0 && total > self.max_total {
            self.total
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return Err("Server is full");
        }
        {
            let mut counts = match self.counts.lock() {
                Ok(c) => c,
                Err(poisoned) => poisoned.into_inner(),
            };
            let entry = counts.entry(host.to_string()).or_insert(0);
            if self.max_per_ip > 0 && *entry >= self.max_per_ip {
                self.total
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                return Err("Too many connections from your address");
            }
            *entry += 1;
        }
        Ok(ConnectionSlot {
            limits: self.clone(),
            host: host.to_string(),
        })
    }
}

/// Outbound queue depth per client. Large enough for legitimate bursts such as a
/// NAMES reply on a busy channel; a client that lets it fill is not reading.
const SEND_QUEUE: usize = 1024;

/// Keepalive timeout values passed from config.
#[derive(Clone, Copy)]
pub struct KeepaliveConfig {
    pub ping_secs: u64,
    pub disconnect_secs: u64,
    pub registration_secs: u64,
    /// Commands a client may send back to back before being throttled.
    pub flood_burst: f64,
    /// Commands per second the allowance refills at.
    pub flood_rate: f64,
}

pub async fn handle_client_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    certfp: Option<String>,
    keepalive: KeepaliveConfig,
    limits: ConnectionLimits,
) {
    let addr = host.clone();
    info!("Client connected (TLS): {} from {}", client_id, addr);
    let _slot = match limits.claim(&host) {
        Ok(slot) => slot,
        Err(reason) => {
            refuse_connection_tls(stream, &server_name, reason).await;
            info!("Refused TLS connection from {}: {}", host, reason);
            return;
        }
    };
    handle_client_stream(
        stream,
        client_id,
        host,
        tx,
        server_name,
        certfp,
        true,
        keepalive,
    )
    .await;
}

pub async fn handle_client(
    stream: tokio::net::TcpStream,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    keepalive: KeepaliveConfig,
    limits: ConnectionLimits,
) {
    let addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    info!("Client connected: {} from {}", client_id, addr);
    let _slot = match limits.claim(&host) {
        Ok(slot) => slot,
        Err(reason) => {
            refuse_connection(stream, &server_name, reason).await;
            info!("Refused connection from {}: {}", host, reason);
            return;
        }
    };
    handle_client_stream(
        stream,
        client_id,
        host,
        tx,
        server_name,
        None,
        false,
        keepalive,
    )
    .await;
}

async fn handle_client_stream<S>(
    stream: S,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    certfp: Option<String>,
    is_tls: bool,
    keepalive: KeepaliveConfig,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(BUF_SIZE, reader);

    let (send_tx, mut send_rx) = mpsc::channel::<Message>(SEND_QUEUE);

    let client_id_clone = client_id.clone();
    let mut writer_task = tokio::spawn(async move {
        while let Some(msg) = send_rx.recv().await {
            let line = format_message(&msg);
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                error!("Write error for {}", client_id_clone);
                break;
            }
        }
    });

    // Raised when the outbound queue overflows: the peer is not reading, and the
    // server must not wait for it.
    let kill = Arc::new(tokio::sync::Notify::new());

    // Flood control: classic IRC token bucket
    let flood_capacity = keepalive.flood_burst;
    let flood_refill_rate = keepalive.flood_rate;
    let mut flood_tokens: f64 = flood_capacity;
    let mut flood_last_refill = tokio::time::Instant::now();
    // Reference tag of the batch this client currently has open, if any.
    let mut open_batch: Option<String> = None;

    // PING/PONG keepalive state
    let ping_timeout = tokio::time::Duration::from_secs(keepalive.ping_secs);
    let disconnect_timeout = tokio::time::Duration::from_secs(keepalive.disconnect_secs);
    let registration_timeout = tokio::time::Duration::from_secs(keepalive.registration_secs);
    let mut last_activity = tokio::time::Instant::now();
    let mut ping_sent = false;
    let mut registered = false; // switches to normal keepalive after first server-bound message
    let tx_clone = tx.clone();
    let mut quit_reason = "Connection closed";

    let mut buf = Vec::new();
    loop {
        // Compute the next keepalive deadline
        // Before registration completes, use the registration timeout as the initial deadline
        let deadline = if ping_sent {
            last_activity + disconnect_timeout
        } else if !registered {
            last_activity + registration_timeout
        } else {
            last_activity + ping_timeout
        };

        tokio::select! {
            // The outbound queue overflowed: this peer is not reading.
            _ = kill.notified() => {
                warn!(client = %client_id, "SendQ exceeded, disconnecting client");
                quit_reason = "SendQ exceeded";
                break;
            }
            result = reader.read_until(b'\n', &mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(_) => {
                        while buf.ends_with(b"\r") || buf.ends_with(b"\n") {
                            buf.pop();
                        }
                        if buf.is_empty() {
                            buf.clear();
                            continue;
                        }
                        let line = match std::str::from_utf8(&buf) {
                            Ok(s) => s,
                            Err(_) => {
                                let _ = send_tx
                        .try_send(
                                        Message::new(
                                            "FAIL",
                                            vec![
                                                "*".into(),
                                                "INVALID_UTF8".into(),
                                                "Message contained invalid UTF-8".into(),
                                            ],
                                        )
                                        .with_prefix(&server_name),
                                    );
                                buf.clear();
                                continue;
                            }
                        };

                        match parse_message(line) {
                            Ok(msg) => {
                                debug!(client = %client_id, command = %msg.command, "received");

                                // Any data from client resets keepalive
                                last_activity = tokio::time::Instant::now();
                                registered = true;
                                if msg.command == "PONG" {
                                    ping_sent = false;
                                }

                                if msg.command == "BATCH" {
                                    match msg.params.first().map(|p| p.as_str()) {
                                        Some(p) if p.starts_with('+') => {
                                            open_batch = Some(p[1..].to_string())
                                        }
                                        Some(p) if p.starts_with('-') => open_batch = None,
                                        _ => {}
                                    }
                                }

                                // Flood control
                                let now = tokio::time::Instant::now();
                                let elapsed = now.duration_since(flood_last_refill).as_secs_f64();
                                flood_tokens =
                                    (flood_tokens + elapsed * flood_refill_rate).min(flood_capacity);
                                flood_last_refill = now;

                                // PING is exempt because dropping it makes a
                                // responsive server look dead: the client is
                                // waiting for a PONG that will never come.
                                const FLOOD_EXEMPT: &[&str] = &[
                                    "CAP", "NICK", "USER", "PASS", "AUTHENTICATE", "PING", "PONG",
                                    "QUIT", "BATCH",
                                ];
                                // Lines inside an open batch form one logical message.
                                // Charging a token each makes the advertised multiline
                                // limits unusable, because max-lines is twice the bucket.
                                // The server bounds batch size itself, so this is not a
                                // way to flood.
                                let in_open_batch = open_batch.is_some()
                                    && msg.tags.get("batch").and_then(|v| v.as_deref())
                                        == open_batch.as_deref();
                                if !FLOOD_EXEMPT.contains(&msg.command.as_str()) && !in_open_batch {
                                    if flood_tokens < 1.0 {
                                        tracing::warn!(client = %client_id, command = %msg.command, "Flood control triggered");
                                        let reply = Message::new(
                                            "NOTICE",
                                            vec![
                                                "*".into(),
                                                "Flood control: you are sending messages too fast".into(),
                                            ],
                                        )
                                        .with_prefix(&server_name);
                                        let _ = send_tx.try_send(reply);
                                        buf.clear();
                                        continue;
                                    }
                                    flood_tokens -= 1.0;
                                }

                                if tx_clone
                                    .send(ClientMessage {
                                        client_id: client_id.clone(),
                                        host: host.clone(),
                                        msg,
                                        send_tx: send_tx.clone(),
                                        kill: kill.clone(),
                                        certfp: certfp.clone(),
                                        is_tls,
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e) => {
                                let line_preview = if line.len() > 80 {
                                    format!("{}...", crate::protocol::truncate_bytes(line, 80))
                                } else {
                                    line.to_string()
                                };
                                warn!(client = %client_id, error = %e, line = %line_preview, "parse failed");
                                let reply = match &e {
                                    ParseError::InputTooLong => Message::new(
                                        "417",
                                        vec!["*".into(), "Input line was too long".into()],
                                    )
                                    .with_prefix(&server_name),
                                    _ => Message::new(
                                        "NOTICE",
                                        vec!["*".into(), format!("Parse error: {}", e)],
                                    )
                                    .with_prefix(&server_name),
                                };
                                let _ = send_tx.try_send(reply);
                            }
                        }
                        buf.clear();
                    }
                    Err(e) => {
                        error!("Read error for {}: {}", client_id, e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                if ping_sent {
                    // No PONG received within disconnect timeout — drop connection
                    info!("Ping timeout for {}", client_id);
                    let _ = send_tx
                        .try_send(Message::new("ERROR", vec!["Closing link: Ping timeout".into()]));
                    quit_reason = "Ping timeout";
                    break;
                } else if !registered {
                    // Registration timeout — client never completed registration
                    info!("Registration timeout for {}", client_id);
                    let _ = send_tx
                        .try_send(Message::new(
                            "ERROR",
                            vec!["Closing link: Registration timeout".into()],
                        ));
                    quit_reason = "Registration timeout";
                    break;
                } else {
                    // Send PING to check if client is alive
                    let _ = send_tx
                        .try_send(
                            Message::new("PING", vec![server_name.clone()])
                                .with_prefix(&server_name),
                        );
                    ping_sent = true;
                }
            }
        }
    }

    info!("Client disconnected: {}", client_id);
    // Give the writer a moment to flush anything queued — a client being killed
    // or banned is owed the ERROR explaining why — then stop it, since it may be
    // blocked writing to a peer that has gone away.
    let quit_tx = send_tx.clone();
    drop(send_tx);
    if tokio::time::timeout(std::time::Duration::from_millis(250), &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }
    let _ = tx
        .send(ClientMessage {
            client_id: client_id.clone(),
            host,
            msg: Message::new("QUIT", vec![quit_reason.into()]),
            send_tx: quit_tx,
            kill,
            certfp,
            is_tls,
        })
        .await;
}

/// Handle an IRC client over a WebSocket connection (IRCv3 WebSocket transport).
/// Each WS text frame = one IRC message (no CRLF).
pub async fn handle_client_ws(
    mut socket: axum::extract::ws::WebSocket,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    certfp: Option<String>,
    keepalive: KeepaliveConfig,
    is_tls: bool,
    limits: ConnectionLimits,
) {
    use axum::extract::ws;

    info!("Client connected (WebSocket): {} from {}", client_id, host);
    let _slot = match limits.claim(&host) {
        Ok(slot) => slot,
        Err(reason) => {
            info!("Refused WebSocket connection from {}: {}", host, reason);
            let _ = socket
                .send(axum::extract::ws::Message::Text(
                    format!(":{} ERROR :Closing link: {}", server_name, reason).into(),
                ))
                .await;
            return;
        }
    };

    let (send_tx, mut send_rx) = mpsc::channel::<Message>(SEND_QUEUE);
    let kill = Arc::new(tokio::sync::Notify::new());

    // Flood control
    let flood_capacity = keepalive.flood_burst;
    let flood_refill_rate = keepalive.flood_rate;
    let mut flood_tokens: f64 = flood_capacity;
    let mut flood_last_refill = tokio::time::Instant::now();
    // Reference tag of the batch this client currently has open, if any.
    let mut open_batch: Option<String> = None;
    let tx_clone = tx.clone();

    // PING/PONG keepalive state
    let ping_timeout = tokio::time::Duration::from_secs(keepalive.ping_secs);
    let disconnect_timeout = tokio::time::Duration::from_secs(keepalive.disconnect_secs);
    let registration_timeout = tokio::time::Duration::from_secs(keepalive.registration_secs);
    let mut last_activity = tokio::time::Instant::now();
    let mut ping_sent = false;
    let mut registered = false;
    let mut quit_reason = "Connection closed";

    loop {
        let deadline = if ping_sent {
            last_activity + disconnect_timeout
        } else if !registered {
            last_activity + registration_timeout
        } else {
            last_activity + ping_timeout
        };

        tokio::select! {
            _ = kill.notified() => {
                warn!(client = %client_id, "SendQ exceeded, disconnecting WebSocket client");
                quit_reason = "SendQ exceeded";
                break;
            }
            // Write outgoing IRC messages to WebSocket as text frames (no CRLF)
            Some(msg) = send_rx.recv() => {
                let mut line = format_message(&msg);
                while line.ends_with('\n') || line.ends_with('\r') {
                    line.pop();
                }
                if socket.send(ws::Message::Text(line.into())).await.is_err() {
                    error!("WebSocket write error for {}", client_id);
                    break;
                }
            }
            // Read incoming WS frames as IRC messages (text or binary per IRCv3 WS spec)
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(ws::Message::Text(text))) => {
                        let line = text.trim();
                        if line.is_empty() {
                            continue;
                        }
                        match parse_message(line) {
                            Ok(msg) => {
                                debug!(client = %client_id, command = %msg.command, "received (ws)");

                                last_activity = tokio::time::Instant::now();
                                registered = true;
                                if msg.command == "PONG" {
                                    ping_sent = false;
                                }

                                if msg.command == "BATCH" {
                                    match msg.params.first().map(|p| p.as_str()) {
                                        Some(p) if p.starts_with('+') => {
                                            open_batch = Some(p[1..].to_string())
                                        }
                                        Some(p) if p.starts_with('-') => open_batch = None,
                                        _ => {}
                                    }
                                }

                                let now = tokio::time::Instant::now();
                                let elapsed = now.duration_since(flood_last_refill).as_secs_f64();
                                flood_tokens =
                                    (flood_tokens + elapsed * flood_refill_rate).min(flood_capacity);
                                flood_last_refill = now;

                                // PING is exempt because dropping it makes a
                                // responsive server look dead: the client is
                                // waiting for a PONG that will never come.
                                const FLOOD_EXEMPT: &[&str] = &[
                                    "CAP", "NICK", "USER", "PASS", "AUTHENTICATE", "PING", "PONG",
                                    "QUIT", "BATCH",
                                ];
                                // Lines inside an open batch form one logical message.
                                // Charging a token each makes the advertised multiline
                                // limits unusable, because max-lines is twice the bucket.
                                // The server bounds batch size itself, so this is not a
                                // way to flood.
                                let in_open_batch = open_batch.is_some()
                                    && msg.tags.get("batch").and_then(|v| v.as_deref())
                                        == open_batch.as_deref();
                                if !FLOOD_EXEMPT.contains(&msg.command.as_str()) && !in_open_batch {
                                    if flood_tokens < 1.0 {
                                        tracing::warn!(client = %client_id, command = %msg.command, "Flood control triggered (WS)");
                                        let reply = Message::new(
                                            "NOTICE",
                                            vec!["*".into(), "Flood control: you are sending messages too fast".into()],
                                        ).with_prefix(&server_name);
                                        let _ = send_tx.try_send(reply);
                                        continue;
                                    }
                                    flood_tokens -= 1.0;
                                }

                                if tx_clone.send(ClientMessage {
                                    client_id: client_id.clone(),
                                    host: host.clone(),
                                    msg,
                                    send_tx: send_tx.clone(),
                                    kill: kill.clone(),
                                    certfp: certfp.clone(),
                                    is_tls,
                                }).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(client = %client_id, error = %e, "WS parse failed");
                                let reply = match &e {
                                    ParseError::InputTooLong => Message::new(
                                        "417", vec!["*".into(), "Input line was too long".into()],
                                    ).with_prefix(&server_name),
                                    _ => Message::new(
                                        "NOTICE", vec!["*".into(), format!("Parse error: {}", e)],
                                    ).with_prefix(&server_name),
                                };
                                let _ = send_tx.try_send(reply);
                            }
                        }
                    }
                    Some(Ok(ws::Message::Binary(data))) => {
                        // binary.ircv3.net: binary frames contain IRC messages as raw bytes
                        let line = match std::str::from_utf8(&data) {
                            Ok(s) => s.trim(),
                            Err(_) => {
                                let _ = send_tx
                        .try_send(
                                        Message::new(
                                            "FAIL",
                                            vec![
                                                "*".into(),
                                                "INVALID_UTF8".into(),
                                                "Message contained invalid UTF-8".into(),
                                            ],
                                        )
                                        .with_prefix(&server_name),
                                    );
                                continue;
                            }
                        };
                        if line.is_empty() {
                            continue;
                        }
                        match parse_message(line) {
                            Ok(msg) => {
                                debug!(client = %client_id, command = %msg.command, "received (ws/bin)");

                                last_activity = tokio::time::Instant::now();
                                registered = true;
                                if msg.command == "PONG" {
                                    ping_sent = false;
                                }

                                if msg.command == "BATCH" {
                                    match msg.params.first().map(|p| p.as_str()) {
                                        Some(p) if p.starts_with('+') => {
                                            open_batch = Some(p[1..].to_string())
                                        }
                                        Some(p) if p.starts_with('-') => open_batch = None,
                                        _ => {}
                                    }
                                }

                                let now = tokio::time::Instant::now();
                                let elapsed = now.duration_since(flood_last_refill).as_secs_f64();
                                flood_tokens =
                                    (flood_tokens + elapsed * flood_refill_rate).min(flood_capacity);
                                flood_last_refill = now;

                                const FLOOD_EXEMPT_B: &[&str] = &[
                                    "CAP", "NICK", "USER", "PASS", "AUTHENTICATE", "PONG", "QUIT",
                                    "BATCH",
                                ];
                                // Lines inside an open batch form one logical message.
                                // Charging a token each makes the advertised multiline
                                // limits unusable, because max-lines is twice the bucket.
                                // The server bounds batch size itself, so this is not a
                                // way to flood.
                                let in_open_batch = open_batch.is_some()
                                    && msg.tags.get("batch").and_then(|v| v.as_deref())
                                        == open_batch.as_deref();
                                if !FLOOD_EXEMPT_B.contains(&msg.command.as_str()) && !in_open_batch {
                                    if flood_tokens < 1.0 {
                                        let reply = Message::new(
                                            "NOTICE",
                                            vec!["*".into(), "Flood control: you are sending messages too fast".into()],
                                        ).with_prefix(&server_name);
                                        let _ = send_tx.try_send(reply);
                                        continue;
                                    }
                                    flood_tokens -= 1.0;
                                }

                                if tx_clone.send(ClientMessage {
                                    client_id: client_id.clone(),
                                    host: host.clone(),
                                    msg,
                                    send_tx: send_tx.clone(),
                                    kill: kill.clone(),
                                    certfp: certfp.clone(),
                                    is_tls,
                                }).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(client = %client_id, error = %e, "WS binary parse failed");
                            }
                        }
                    }
                    Some(Ok(ws::Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // Ignore ping, pong frames
                    Some(Err(e)) => {
                        error!("WebSocket read error for {}: {}", client_id, e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                if ping_sent {
                    info!("Ping timeout for {} (ws)", client_id);
                    let _ = send_tx
                        .try_send(Message::new("ERROR", vec!["Closing link: Ping timeout".into()]));
                    quit_reason = "Ping timeout";
                    break;
                } else if !registered {
                    info!("Registration timeout for {} (ws)", client_id);
                    let _ = send_tx
                        .try_send(Message::new(
                            "ERROR",
                            vec!["Closing link: Registration timeout".into()],
                        ));
                    quit_reason = "Registration timeout";
                    break;
                } else {
                    let _ = send_tx
                        .try_send(
                            Message::new("PING", vec![server_name.clone()])
                                .with_prefix(&server_name),
                        );
                    ping_sent = true;
                }
            }
        }
    }

    info!("Client disconnected (WebSocket): {}", client_id);
    let _ = tx
        .send(ClientMessage {
            client_id: client_id.clone(),
            host,
            msg: Message::new("QUIT", vec![quit_reason.into()]),
            send_tx,
            kill,
            certfp,
            is_tls,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_address_limit_is_enforced_and_released() {
        let limits = ConnectionLimits::new(2, 0);

        let first = limits.claim("198.51.100.7").expect("first connection");
        let second = limits.claim("198.51.100.7").expect("second connection");
        assert_eq!(
            limits.claim("198.51.100.7").err(),
            Some("Too many connections from your address")
        );
        // A different address is unaffected.
        let other = limits.claim("203.0.113.9").expect("another address");

        drop(second);
        let third = limits.claim("198.51.100.7").expect("a slot was released");

        drop(first);
        drop(third);
        drop(other);
        assert!(limits.claim("198.51.100.7").is_ok(), "all slots released");
    }

    #[test]
    fn total_limit_is_enforced() {
        let limits = ConnectionLimits::new(0, 2);
        let a = limits.claim("198.51.100.1").expect("first");
        let _b = limits.claim("198.51.100.2").expect("second");
        assert_eq!(limits.claim("198.51.100.3").err(), Some("Server is full"));
        drop(a);
        assert!(limits.claim("198.51.100.3").is_ok(), "a slot was released");
    }

    #[test]
    fn zero_means_unlimited() {
        let limits = ConnectionLimits::new(0, 0);
        let mut held = Vec::new();
        for _ in 0..100 {
            held.push(limits.claim("198.51.100.5").expect("no limit"));
        }
    }
}
