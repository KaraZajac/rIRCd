use crate::protocol::{parse_message, format_message, Message, ParseError};
use crate::server::ClientMessage;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const BUF_SIZE: usize = 8192;

pub async fn handle_client_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
) {
    let addr = host.clone();
    info!("Client connected (TLS): {} from {}", client_id, addr);
    handle_client_stream(stream, client_id, host, tx, server_name).await;
}

pub async fn handle_client(
    stream: tokio::net::TcpStream,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
) {
    let addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into());
    info!("Client connected: {} from {}", client_id, addr);
    handle_client_stream(stream, client_id, host, tx, server_name).await;
}

async fn handle_client_stream<S>(
    stream: S,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(BUF_SIZE, reader);

    let (send_tx, mut send_rx) = mpsc::channel::<Message>(64);

    let client_id_clone = client_id.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        while let Some(msg) = send_rx.recv().await {
            let line = format_message(&msg);
            if writer.write_all(line.as_bytes()).await.is_err()
                || writer.flush().await.is_err()
            {
                error!("Write error for {}", client_id_clone);
                break;
            }
        }
    });

    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => break,
            Ok(_) => {
                while buf.ends_with(&[b'\r']) || buf.ends_with(&[b'\n']) {
                    buf.pop();
                }
                if buf.is_empty() {
                    continue;
                }
                let line = match std::str::from_utf8(&buf) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = send_tx
                            .send(
                                Message::new(
                                    "FAIL",
                                    vec!["*".into(), "INVALID_UTF8".into(), "Message contained invalid UTF-8".into()],
                                )
                                .with_prefix(&server_name),
                            )
                            .await;
                        continue;
                    }
                };

                match parse_message(line) {
                    Ok(msg) => {
                        debug!(client = %client_id, command = %msg.command, "received");
                        if tx_clone
                            .send(ClientMessage {
                                client_id: client_id.clone(),
                                host: host.clone(),
                                msg,
                                send_tx: send_tx.clone(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let line_preview = if line.len() > 80 { format!("{}...", &line[..80]) } else { line.to_string() };
                        warn!(client = %client_id, error = %e, line = %line_preview, "parse failed");
                        let reply = match &e {
                            ParseError::InputTooLong => Message::new("417", vec!["*".into(), "Input line was too long".into()])
                                .with_prefix(&server_name),
                            _ => Message::new("NOTICE", vec!["*".into(), format!("Parse error: {}", e)])
                                .with_prefix(&server_name),
                        };
                        let _ = send_tx.send(reply).await;
                    }
                }
            }
            Err(e) => {
                error!("Read error for {}: {}", client_id, e);
                break;
            }
        }
    }

    info!("Client disconnected: {}", client_id);
    let _ = tx.send(ClientMessage {
        client_id: client_id.clone(),
        host,
        msg: Message::new("QUIT", vec!["Connection closed".into()]),
        send_tx,
    }).await;
}
