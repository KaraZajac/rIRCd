use crate::protocol::{format_message, parse_message, Message, ParseError};
use crate::server::ClientMessage;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const BUF_SIZE: usize = 8192;

/// Keepalive timeout values passed from config.
#[derive(Clone, Copy)]
pub struct KeepaliveConfig {
    pub ping_secs: u64,
    pub disconnect_secs: u64,
    pub registration_secs: u64,
}

pub async fn handle_client_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    certfp: Option<String>,
    keepalive: KeepaliveConfig,
) {
    let addr = host.clone();
    info!("Client connected (TLS): {} from {}", client_id, addr);
    handle_client_stream(stream, client_id, host, tx, server_name, certfp, true, keepalive).await;
}

pub async fn handle_client(
    stream: tokio::net::TcpStream,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    keepalive: KeepaliveConfig,
) {
    let addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    info!("Client connected: {} from {}", client_id, addr);
    handle_client_stream(stream, client_id, host, tx, server_name, None, false, keepalive).await;
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

    let (send_tx, mut send_rx) = mpsc::channel::<Message>(64);

    let client_id_clone = client_id.clone();
    tokio::spawn(async move {
        while let Some(msg) = send_rx.recv().await {
            let line = format_message(&msg);
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                error!("Write error for {}", client_id_clone);
                break;
            }
        }
    });

    // Flood control: classic IRC token bucket
    const FLOOD_CAPACITY: f64 = 10.0;
    const FLOOD_REFILL_RATE: f64 = 1.0;
    let mut flood_tokens: f64 = FLOOD_CAPACITY;
    let mut flood_last_refill = tokio::time::Instant::now();

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
                                    .send(
                                        Message::new(
                                            "FAIL",
                                            vec![
                                                "*".into(),
                                                "INVALID_UTF8".into(),
                                                "Message contained invalid UTF-8".into(),
                                            ],
                                        )
                                        .with_prefix(&server_name),
                                    )
                                    .await;
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

                                // Flood control
                                let now = tokio::time::Instant::now();
                                let elapsed = now.duration_since(flood_last_refill).as_secs_f64();
                                flood_tokens =
                                    (flood_tokens + elapsed * FLOOD_REFILL_RATE).min(FLOOD_CAPACITY);
                                flood_last_refill = now;

                                const FLOOD_EXEMPT: &[&str] = &[
                                    "CAP", "NICK", "USER", "PASS", "AUTHENTICATE", "PONG", "QUIT",
                                ];
                                if !FLOOD_EXEMPT.contains(&msg.command.as_str()) {
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
                                        let _ = send_tx.send(reply).await;
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
                                    format!("{}...", &line[..80])
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
                                let _ = send_tx.send(reply).await;
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
                        .send(Message::new("ERROR", vec!["Closing link: Ping timeout".into()]))
                        .await;
                    quit_reason = "Ping timeout";
                    break;
                } else if !registered {
                    // Registration timeout — client never completed registration
                    info!("Registration timeout for {}", client_id);
                    let _ = send_tx
                        .send(Message::new(
                            "ERROR",
                            vec!["Closing link: Registration timeout".into()],
                        ))
                        .await;
                    quit_reason = "Registration timeout";
                    break;
                } else {
                    // Send PING to check if client is alive
                    let _ = send_tx
                        .send(
                            Message::new("PING", vec![server_name.clone()])
                                .with_prefix(&server_name),
                        )
                        .await;
                    ping_sent = true;
                }
            }
        }
    }

    info!("Client disconnected: {}", client_id);
    let _ = tx
        .send(ClientMessage {
            client_id: client_id.clone(),
            host,
            msg: Message::new("QUIT", vec![quit_reason.into()]),
            send_tx,
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
) {
    use axum::extract::ws;

    info!("Client connected (WebSocket): {} from {}", client_id, host);

    let (send_tx, mut send_rx) = mpsc::channel::<Message>(64);

    // Flood control
    const FLOOD_CAPACITY: f64 = 10.0;
    const FLOOD_REFILL_RATE: f64 = 1.0;
    let mut flood_tokens: f64 = FLOOD_CAPACITY;
    let mut flood_last_refill = tokio::time::Instant::now();
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

                                let now = tokio::time::Instant::now();
                                let elapsed = now.duration_since(flood_last_refill).as_secs_f64();
                                flood_tokens = (flood_tokens + elapsed * FLOOD_REFILL_RATE).min(FLOOD_CAPACITY);
                                flood_last_refill = now;

                                const FLOOD_EXEMPT: &[&str] = &[
                                    "CAP", "NICK", "USER", "PASS", "AUTHENTICATE", "PONG", "QUIT",
                                ];
                                if !FLOOD_EXEMPT.contains(&msg.command.as_str()) {
                                    if flood_tokens < 1.0 {
                                        tracing::warn!(client = %client_id, command = %msg.command, "Flood control triggered (WS)");
                                        let reply = Message::new(
                                            "NOTICE",
                                            vec!["*".into(), "Flood control: you are sending messages too fast".into()],
                                        ).with_prefix(&server_name);
                                        let _ = send_tx.send(reply).await;
                                        continue;
                                    }
                                    flood_tokens -= 1.0;
                                }

                                if tx_clone.send(ClientMessage {
                                    client_id: client_id.clone(),
                                    host: host.clone(),
                                    msg,
                                    send_tx: send_tx.clone(),
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
                                let _ = send_tx.send(reply).await;
                            }
                        }
                    }
                    Some(Ok(ws::Message::Binary(data))) => {
                        // binary.ircv3.net: binary frames contain IRC messages as raw bytes
                        let line = match std::str::from_utf8(&data) {
                            Ok(s) => s.trim(),
                            Err(_) => {
                                let _ = send_tx
                                    .send(
                                        Message::new(
                                            "FAIL",
                                            vec![
                                                "*".into(),
                                                "INVALID_UTF8".into(),
                                                "Message contained invalid UTF-8".into(),
                                            ],
                                        )
                                        .with_prefix(&server_name),
                                    )
                                    .await;
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

                                let now = tokio::time::Instant::now();
                                let elapsed = now.duration_since(flood_last_refill).as_secs_f64();
                                flood_tokens = (flood_tokens + elapsed * FLOOD_REFILL_RATE).min(FLOOD_CAPACITY);
                                flood_last_refill = now;

                                const FLOOD_EXEMPT_B: &[&str] = &[
                                    "CAP", "NICK", "USER", "PASS", "AUTHENTICATE", "PONG", "QUIT",
                                ];
                                if !FLOOD_EXEMPT_B.contains(&msg.command.as_str()) {
                                    if flood_tokens < 1.0 {
                                        let reply = Message::new(
                                            "NOTICE",
                                            vec!["*".into(), "Flood control: you are sending messages too fast".into()],
                                        ).with_prefix(&server_name);
                                        let _ = send_tx.send(reply).await;
                                        continue;
                                    }
                                    flood_tokens -= 1.0;
                                }

                                if tx_clone.send(ClientMessage {
                                    client_id: client_id.clone(),
                                    host: host.clone(),
                                    msg,
                                    send_tx: send_tx.clone(),
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
                        .send(Message::new("ERROR", vec!["Closing link: Ping timeout".into()]))
                        .await;
                    quit_reason = "Ping timeout";
                    break;
                } else if !registered {
                    info!("Registration timeout for {} (ws)", client_id);
                    let _ = send_tx
                        .send(Message::new(
                            "ERROR",
                            vec!["Closing link: Registration timeout".into()],
                        ))
                        .await;
                    quit_reason = "Registration timeout";
                    break;
                } else {
                    let _ = send_tx
                        .send(
                            Message::new("PING", vec![server_name.clone()])
                                .with_prefix(&server_name),
                        )
                        .await;
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
            certfp,
            is_tls,
        })
        .await;
}
