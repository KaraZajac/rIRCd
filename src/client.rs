use crate::protocol::{format_message_within, parse_message_with_limit, Message, ParseError};
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

/// Bytes the writer will hold for a client that is behind. Past this it stops
/// taking from the queue, the queue fills, and the connection is dropped —
/// which is what "not reading" means, measured in how far behind the client is
/// rather than in how much it was sent.
const SEND_BACKLOG_BYTES: usize = 1 << 20;

/// Keepalive timeout values passed from config.
#[derive(Clone, Copy)]
pub struct KeepaliveConfig {
    pub ping_secs: u64,
    /// Longest message body accepted, before tags.
    pub max_line_length: usize,
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

/// Format queued messages onto a socket, batching whatever is already waiting
/// into one write.
///
/// Writing one message per syscall made the queue in front of this the real
/// limit on how much a client could be sent at once: a LIST on a busy server
/// outruns the socket, fills the queue, and the client that asked for it is
/// dropped for "not reading". Formatting everything that is already waiting
/// into one buffer lets the queue drain as fast as memory allows, so the limit
/// becomes how far behind a client may fall rather than how many lines it may
/// ask for — and a burst costs one write instead of one per line.
async fn write_loop<W>(
    writer: &mut W,
    send_rx: &mut mpsc::Receiver<Message>,
    out_line_limit: usize,
    client_id: &str,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut backlog: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut sent = 0usize;
    loop {
        if sent == backlog.len() {
            backlog.clear();
            sent = 0;
            let Some(first) = send_rx.recv().await else {
                return;
            };
            backlog.extend_from_slice(format_message_within(&first, out_line_limit).as_bytes());
        }
        // Whatever else is already queued goes in the same write.
        while backlog.len() < SEND_BACKLOG_BYTES {
            match send_rx.try_recv() {
                Ok(msg) => backlog
                    .extend_from_slice(format_message_within(&msg, out_line_limit).as_bytes()),
                Err(_) => break,
            }
        }
        match writer.write(&backlog[sent..]).await {
            Ok(0) => {
                error!("Write error for {}: peer closed", client_id);
                return;
            }
            Ok(n) => sent += n,
            Err(e) => {
                error!("Write error for {}: {}", client_id, e);
                return;
            }
        }
        if sent == backlog.len() && writer.flush().await.is_err() {
            error!("Write error for {}: flush failed", client_id);
            return;
        }
    }
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
    // Two bytes of the limit belong to the CRLF.
    let out_line_limit = keepalive.max_line_length.saturating_sub(2);
    // The limit counts the CRLF that ends the line, so what a message may
    // actually carry is two bytes less than the number the limit is written as.
    let in_line_limit = out_line_limit;
    let mut writer_task = tokio::spawn(async move {
        write_loop(&mut writer, &mut send_rx, out_line_limit, &client_id_clone).await;
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
                                // The line cannot be handled, but the command
                                // word is ASCII in any message that has one, so
                                // the client can still be told what was refused.
                                let command = {
                                    let lossy = String::from_utf8_lossy(&buf);
                                    parse_message_with_limit(&lossy, in_line_limit)
                                    .map(|m| m.command)
                                    .unwrap_or_else(|_| "*".to_string())
                                };
                                let _ = send_tx.try_send(
                                    Message::new(
                                        "FAIL",
                                        vec![
                                            command,
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

                        match parse_message_with_limit(line, in_line_limit) {
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

    // A client that negotiated binary.ircv3.net is expecting binary frames;
    // sending it text ones leaves it decoding the wrong type.
    let send_binary = socket
        .protocol()
        .and_then(|p| p.to_str().ok())
        .is_some_and(|p| p == "binary.ircv3.net");

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
    // A WebSocket frame carries no CRLF, but the limit is the same one, and a
    // client that can reach this server both ways should not find that the same
    // message fits over one and not the other.
    let ws_line_limit = keepalive.max_line_length.saturating_sub(2);

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
                let mut line =
                    format_message_within(&msg, keepalive.max_line_length.saturating_sub(2));
                while line.ends_with('\n') || line.ends_with('\r') {
                    line.pop();
                }
                let frame = if send_binary {
                    ws::Message::Binary(line.into_bytes().into())
                } else {
                    ws::Message::Text(line.into())
                };
                if socket.send(frame).await.is_err() {
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
                        match parse_message_with_limit(line, ws_line_limit) {
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
                                let command = {
                                    let lossy = String::from_utf8_lossy(&data);
                                    parse_message_with_limit(
                                        &lossy,
                                        keepalive.max_line_length,
                                    )
                                    .map(|m| m.command)
                                    .unwrap_or_else(|_| "*".to_string())
                                };
                                let _ = send_tx.try_send(
                                    Message::new(
                                        "FAIL",
                                        vec![
                                            command,
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
                        match parse_message_with_limit(line, ws_line_limit) {
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
mod writer_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn line(n: usize) -> Message {
        Message::new(
            "322",
            vec!["nick".into(), format!("#chan{n}"), "1".into(), "".into()],
        )
        .with_prefix("irc.example.org")
    }

    /// A client that asks for a long answer must get all of it. Before the
    /// writer batched, a reply longer than the queue outran the socket and the
    /// client that asked for it was dropped part-way through its own LIST.
    #[tokio::test]
    async fn a_reply_longer_than_the_queue_arrives_whole() {
        const LINES: usize = 20_000;
        let (mut client, server) = tokio::io::duplex(4096);
        let (tx, mut rx) = mpsc::channel::<Message>(SEND_QUEUE);

        let writer = tokio::spawn(async move {
            let mut server = server;
            write_loop(&mut server, &mut rx, 510, "test").await;
        });

        // The reader drains slowly enough that the socket buffer fills, which
        // is what puts back-pressure on the writer.
        let reader = tokio::spawn(async move {
            let mut got = String::new();
            let mut buf = [0u8; 1024];
            loop {
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.push_str(&String::from_utf8_lossy(&buf[..n])),
                }
                if got.matches("\r\n").count() >= LINES {
                    break;
                }
            }
            got
        });

        let feeder = tokio::spawn(async move {
            for n in 0..LINES {
                // The dispatch loop does not wait, so neither does this: if the
                // queue is full the client is being dropped, which is the
                // failure this test is about.
                if tx.try_send(line(n)).is_err() {
                    return Err(n);
                }
                if n.is_multiple_of(256) {
                    tokio::task::yield_now().await;
                }
            }
            Ok(())
        });

        let fed = tokio::time::timeout(std::time::Duration::from_secs(30), feeder)
            .await
            .expect("feeding did not finish")
            .expect("feeder task panicked");
        assert!(
            fed.is_ok(),
            "the queue filled at line {:?}",
            fed.unwrap_err()
        );

        let got = tokio::time::timeout(std::time::Duration::from_secs(30), reader)
            .await
            .expect("reading did not finish")
            .expect("reader task panicked");
        writer.abort();

        assert_eq!(got.matches("\r\n").count(), LINES, "not every line arrived");
        // ...and in the order they were queued.
        let first = got.find("#chan0 ").expect("first line missing");
        let last = got
            .find(&format!("#chan{} ", LINES - 1))
            .expect("last line missing");
        assert!(first < last, "lines arrived out of order");
    }

    /// The other half: a peer that has stopped reading altogether must not cost
    /// the server unbounded memory. The backlog has an end, and past it the
    /// queue fills — which is what marks the connection for disconnection.
    #[tokio::test]
    async fn a_peer_that_never_reads_fills_the_queue() {
        let (client, server) = tokio::io::duplex(64);
        let (tx, mut rx) = mpsc::channel::<Message>(SEND_QUEUE);
        let writer = tokio::spawn(async move {
            let mut server = server;
            write_loop(&mut server, &mut rx, 510, "test").await;
        });

        let mut queued = 0usize;
        let filled = loop {
            if tx.try_send(line(queued)).is_err() {
                break true;
            }
            queued += 1;
            if queued.is_multiple_of(128) {
                tokio::task::yield_now().await;
            }
            if queued > 200_000 {
                break false;
            }
        };
        writer.abort();
        drop(client);
        assert!(
            filled,
            "the queue never filled for a peer that read nothing: {queued} messages went in"
        );
    }
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
