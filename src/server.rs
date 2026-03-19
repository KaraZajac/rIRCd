use crate::channel::ChannelStore;
use crate::client;
use crate::commands;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::ServerState;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Writes PID to file on creation, removes file on drop.
struct PidfileGuard {
    path: std::path::PathBuf,
}

impl PidfileGuard {
    fn new(path: &Path) -> anyhow::Result<Self> {
        let path = path.to_path_buf();
        std::fs::write(&path, std::process::id().to_string())?;
        info!("PID file: {}", path.display());
        Ok(Self { path })
    }
}

impl Drop for PidfileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct ClientMessage {
    pub client_id: String,
    pub host: String,
    pub msg: Message,
    pub send_tx: mpsc::Sender<Message>,
}

pub async fn run(cfg: Config, pidfile: Option<&Path>) -> anyhow::Result<()> {
    let _pidfile = pidfile.map(|p| PidfileGuard::new(p)).transpose()?;

    let state = ServerState::new();
    let channels = ChannelStore::new();
    // Load channels from the database: pre-create channels with topic and persisted operators/voice
    if let Some(ref pool) = cfg.db {
        let entries = crate::persist::load_channels(pool).await;
        let mut store = channels.write().await;
        for e in entries {
            let ch = store
                .channels
                .entry(e.name.clone())
                .or_insert_with(|| tokio::sync::RwLock::new(crate::channel::Channel::new(e.name.clone())));
            let mut ch_guard = ch.write().await;
            if !e.topic.is_empty() {
                ch_guard.topic = Some(e.topic.clone());
            }
            ch_guard.persisted_operators = e.operators;
            ch_guard.persisted_voice = e.voice;
            // Restore channel modes
            for c in e.mode_flags.chars() {
                match c {
                    'i' => ch_guard.modes.invite_only = true,
                    'm' => ch_guard.modes.moderated = true,
                    'n' => ch_guard.modes.no_external = true,
                    's' => ch_guard.modes.secret = true,
                    't' => ch_guard.modes.topic_protect = true,
                    'R' => ch_guard.modes.registered_only = true,
                    'c' => ch_guard.modes.no_colors = true,
                    'C' => ch_guard.modes.no_ctcp = true,
                    _ => {}
                }
            }
            ch_guard.key = e.mode_key;
            ch_guard.modes.user_limit = e.mode_limit;
            if e.created_at > 0 {
                ch_guard.created_at = e.created_at;
            }
        }
    }
    let senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx, mut rx) = mpsc::channel::<ClientMessage>(256);

    let tls_acceptor = if cfg.tls_enabled() {
        let cert_path = cfg.tls.cert.as_ref().unwrap();
        let key_path = cfg.tls.key.as_ref().unwrap();
        let mut cert_file = std::io::BufReader::new(fs::File::open(cert_path)?);
        let mut key_file = std::io::BufReader::new(fs::File::open(key_path)?);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_file).filter_map(|r| r.ok()).collect();
        let key = rustls_pemfile::private_key(&mut key_file)?.ok_or_else(|| anyhow::anyhow!("No private key found"))?;
        let cfg_tls = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Some(TlsAcceptor::from(Arc::new(cfg_tls)))
    } else {
        None
    };

    let server_name = cfg.server.name.clone();
    for listen_addr in &cfg.server.listen {
        let bind_addr = if listen_addr.starts_with(":") {
            format!("0.0.0.0{}", listen_addr)
        } else {
            listen_addr.clone()
        };

        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("Listening on {} (plain)", bind_addr);

        let tx = tx.clone();
        let server_name = server_name.clone();
        let mut client_counter = 0u64;
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        client_counter += 1;
                        let client_id = format!("client-{}", client_counter);
                        let host = addr.to_string();
                        let tx = tx.clone();
                        let server_name = server_name.clone();
                        tokio::spawn(async move {
                            client::handle_client(stream, client_id, host, tx, server_name).await;
                        });
                    }
                    Err(e) => error!("Accept error: {}", e),
                }
            }
        });
    }

    if let Some(ref acceptor) = tls_acceptor {
        let server_name_tls = server_name.clone();
        for listen_addr in &cfg.server.listen_tls {
            let bind_addr = if listen_addr.starts_with(":") {
                format!("0.0.0.0{}", listen_addr)
            } else {
                listen_addr.clone()
            };

            let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
            info!("Listening on {} (TLS)", bind_addr);

            let tx = tx.clone();
            let tls_acc = acceptor.clone();
            let server_name = server_name_tls.clone();
            let mut client_counter = 0u64;
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            client_counter += 1;
                            let client_id = format!("client-{}", client_counter);
                            let host = addr.to_string();
                            let tx = tx.clone();
                            let acc = tls_acc.clone();
                            let server_name = server_name.clone();
                            tokio::spawn(async move {
                                match acc.accept(stream).await {
                                    Ok(tls_stream) => client::handle_client_tls(tls_stream, client_id, host, tx, server_name).await,
                                    Err(e) => error!("TLS handshake failed: {}", e),
                                }
                            });
                        }
                        Err(e) => error!("Accept error: {}", e),
                    }
                }
            });
        }
    }

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                let cm = match msg {
                    Some(m) => m,
                    None => break,
                };
                let client_id = cm.client_id.clone();
                senders.write().await.insert(client_id.clone(), cm.send_tx.clone());

                let cmd = cm.msg.command.clone();
                let params_preview = cm.msg.params.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
                let trailing_preview = cm.msg.trailing().map(|t| if t.len() > 40 { format!("{}...", &t[..40]) } else { t.to_string() }).unwrap_or_default();

                debug!(client = %client_id, command = %cmd, "handling message");
                let result = commands::handle_message(
                    cm.client_id,
                    cm.host,
                    cm.msg,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    &cfg,
                )
                .await;

                if let Err(e) = result {
                    warn!(
                        client = %client_id,
                        command = %cmd,
                        params = %params_preview,
                        trailing = %trailing_preview,
                        error = %e,
                        "handle_message failed"
                    );
                    error!("Error handling message from {}: {} (command={})", client_id, e, cmd);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down (SIGINT)");
                break;
            }
            _ = async {
                #[cfg(unix)]
                {
                    sigterm.recv().await;
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Shutting down (SIGTERM)");
                break;
            }
        }
    }

    Ok(())
}
