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

// ─── TLS client certificate verifier (accepts any cert, for SASL EXTERNAL) ───

/// Accepts any client certificate without verifying against a CA.
/// Used when `[tls] client_certs = true` to enable SASL EXTERNAL.
#[derive(Debug)]
struct OptionalClientCertVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl OptionalClientCertVerifier {
    fn new() -> Self {
        Self {
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for OptionalClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Extract SHA-256 fingerprint from a TLS stream's peer certificate.
fn extract_certfp(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
    use sha2::Digest;
    let (_, session) = tls_stream.get_ref();
    session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| {
            let hash = sha2::Sha256::digest(cert.as_ref());
            hash.iter().map(|b| format!("{:02x}", b)).collect()
        })
}

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
    /// TLS client certificate SHA-256 fingerprint (hex), if available.
    pub certfp: Option<String>,
}

pub async fn run(cfg: Config, config_path: &Path, pidfile: Option<&Path>) -> anyhow::Result<()> {
    let _pidfile = pidfile.map(PidfileGuard::new).transpose()?;

    let state = ServerState::new();
    let channels = ChannelStore::new();
    // Load channels from the database: pre-create channels with topic and persisted operators/voice
    if let Some(ref pool) = cfg.db {
        let entries = crate::persist::load_channels(pool).await;
        let mut store = channels.write().await;
        for e in entries {
            let ch = store.channels.entry(e.name.clone()).or_insert_with(|| {
                tokio::sync::RwLock::new(crate::channel::Channel::new(e.name.clone()))
            });
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
        // Load read markers and metadata into server state
        let markers = crate::persist::load_read_markers(pool).await;
        let meta = crate::persist::load_all_metadata(pool).await;
        let mut state_w = state.write().await;
        state_w.read_markers = markers;
        state_w.metadata = meta;
    }
    // Store the config path so REHASH can reload from disk
    state.write().await.config_path = Some(config_path.to_path_buf());
    let senders: Arc<RwLock<HashMap<String, mpsc::Sender<Message>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx, mut rx) = mpsc::channel::<ClientMessage>(256);

    let tls_acceptor = if cfg.tls_enabled() {
        let cert_path = cfg.tls.cert.as_ref().unwrap();
        let key_path = cfg.tls.key.as_ref().unwrap();
        let mut cert_file = std::io::BufReader::new(fs::File::open(cert_path)?);
        let mut key_file = std::io::BufReader::new(fs::File::open(key_path)?);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_file)
            .filter_map(|r| r.ok())
            .collect();
        let key = rustls_pemfile::private_key(&mut key_file)?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
        let cfg_tls = if cfg.tls.client_certs {
            info!("TLS client certificates enabled (SASL EXTERNAL available)");
            tokio_rustls::rustls::ServerConfig::builder()
                .with_client_cert_verifier(Arc::new(OptionalClientCertVerifier::new()))
                .with_single_cert(certs, key)?
        } else {
            tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };
        Some(TlsAcceptor::from(Arc::new(cfg_tls)))
    } else {
        None
    };

    // ── Filehost HTTP endpoint ─────────────────────────────────────────────────
    if let Some(ref fh_cfg) = cfg.filehost {
        let upload_dir = std::path::PathBuf::from(&fh_cfg.upload_dir);
        if let Err(e) = std::fs::create_dir_all(&upload_dir) {
            error!(
                "Failed to create filehost upload dir {}: {}",
                upload_dir.display(),
                e
            );
        }

        let fh_state = Arc::new(crate::filehost::FilehostState {
            upload_dir,
            public_url: fh_cfg.public_url.clone(),
            max_size: fh_cfg.max_size,
            db_pool: cfg.db.clone().expect("database pool required for filehost"),
        });

        let app = crate::filehost::router(fh_state);
        let listen_addr = fh_cfg.listen.clone();
        let listener = tokio::net::TcpListener::bind(&listen_addr).await?;

        if fh_cfg.public_url.starts_with("https://") {
            if let Some(ref acceptor) = tls_acceptor {
                let acceptor = acceptor.clone();
                info!("Filehost HTTPS listening on {}", listen_addr);
                tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((stream, _addr)) => {
                                let acceptor = acceptor.clone();
                                let app = app.clone();
                                tokio::spawn(async move {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                                            let service =
                                                hyper_util::service::TowerToHyperService::new(app);
                                            if let Err(e) =
                                                hyper_util::server::conn::auto::Builder::new(
                                                    hyper_util::rt::TokioExecutor::new(),
                                                )
                                                .serve_connection(io, service)
                                                .await
                                            {
                                                tracing::debug!("Filehost connection error: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!("Filehost TLS handshake failed: {}", e);
                                        }
                                    }
                                });
                            }
                            Err(e) => error!("Filehost accept error: {}", e),
                        }
                    }
                });
            } else {
                error!(
                    "Filehost public_url is HTTPS but no [tls] cert/key configured — \
                     falling back to plain HTTP"
                );
                info!("Filehost HTTP listening on {}", listen_addr);
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app).await {
                        error!("Filehost server error: {}", e);
                    }
                });
            }
        } else {
            info!("Filehost HTTP listening on {}", listen_addr);
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, app).await {
                    error!("Filehost server error: {}", e);
                }
            });
        }
    } else {
        debug!("Filehost not configured (no [filehost] section in config)");
    }

    let server_name = cfg.server.name.clone();
    let keepalive = client::KeepaliveConfig {
        ping_secs: cfg.server.ping_timeout_secs,
        disconnect_secs: cfg.server.disconnect_timeout_secs,
        registration_secs: cfg.server.registration_timeout_secs,
    };

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
                        let host = addr.ip().to_string();
                        let tx = tx.clone();
                        let server_name = server_name.clone();
                        tokio::spawn(async move {
                            client::handle_client(stream, client_id, host, tx, server_name, keepalive).await;
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
                            let host = addr.ip().to_string();
                            let tx = tx.clone();
                            let acc = tls_acc.clone();
                            let server_name = server_name.clone();
                            tokio::spawn(async move {
                                match acc.accept(stream).await {
                                    Ok(tls_stream) => {
                                        let certfp = extract_certfp(&tls_stream);
                                        client::handle_client_tls(
                                            tls_stream,
                                            client_id,
                                            host,
                                            tx,
                                            server_name,
                                            certfp,
                                            keepalive,
                                        )
                                        .await
                                    }
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

    // ── WebSocket listeners (IRCv3 WebSocket transport) ─────────────────────────
    for listen_addr in &cfg.server.listen_ws {
        let bind_addr = if listen_addr.starts_with(':') {
            format!("0.0.0.0{}", listen_addr)
        } else {
            listen_addr.clone()
        };

        let tx_ws = tx.clone();
        let server_name_ws = server_name.clone();
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("Listening on {} (WebSocket)", bind_addr);

        #[derive(Clone)]
        struct WsState {
            tx: mpsc::Sender<ClientMessage>,
            server_name: String,
            counter: Arc<std::sync::atomic::AtomicU64>,
            keepalive: client::KeepaliveConfig,
        }

        let ws_state = WsState {
            tx: tx_ws,
            server_name: server_name_ws,
            counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            keepalive,
        };

        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(
                    |ws: axum::extract::ws::WebSocketUpgrade,
                     headers: axum::http::HeaderMap,
                     axum::extract::State(st): axum::extract::State<WsState>| async move {
                        let id = st.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let client_id = format!("ws-{}", id);
                        let host = headers
                            .get("x-forwarded-for")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("unknown")
                            .to_string();
                        ws.protocols(["text.ircv3.net", "binary.ircv3.net"]).on_upgrade(move |socket| {
                            client::handle_client_ws(
                                socket,
                                client_id,
                                host,
                                st.tx,
                                st.server_name,
                                None,
                                st.keepalive,
                            )
                        })
                    },
                ),
            )
            .with_state(ws_state);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("WebSocket server error: {}", e);
            }
        });
    }

    // WebSocket-over-TLS (WSS)
    if let Some(ref acceptor) = tls_acceptor {
        for listen_addr in &cfg.server.listen_wss {
            let bind_addr = if listen_addr.starts_with(':') {
                format!("0.0.0.0{}", listen_addr)
            } else {
                listen_addr.clone()
            };

            let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
            info!("Listening on {} (WebSocket TLS)", bind_addr);

            let tls_acc = acceptor.clone();
            let tx_wss = tx.clone();
            let server_name_wss = server_name.clone();
            tokio::spawn(async move {
                let mut counter = 0u64;
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            counter += 1;
                            let client_id = format!("wss-{}", counter);
                            let host = addr.ip().to_string();
                            let acc = tls_acc.clone();
                            let tx = tx_wss.clone();
                            let sn = server_name_wss.clone();
                            tokio::spawn(async move {
                                match acc.accept(stream).await {
                                    Ok(tls_stream) => {
                                        let certfp = extract_certfp(&tls_stream);
                                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                                        let tx_c = tx.clone();
                                        let sn_c = sn.clone();
                                        let host_c = host.clone();
                                        let cid = client_id.clone();
                                        let cfp = certfp.clone();

                                        let app = axum::Router::new().route(
                                            "/",
                                            axum::routing::get(
                                                move |ws: axum::extract::ws::WebSocketUpgrade| {
                                                    let tx = tx_c;
                                                    let sn = sn_c;
                                                    let host = host_c;
                                                    let client_id = cid;
                                                    let certfp = cfp;
                                                    async move {
                                                        ws.protocols(["text.ircv3.net", "binary.ircv3.net"])
                                                            .on_upgrade(move |socket| {
                                                                client::handle_client_ws(
                                                                    socket, client_id, host, tx,
                                                                    sn, certfp, keepalive,
                                                                )
                                                            })
                                                    }
                                                },
                                            ),
                                        );

                                        let service =
                                            hyper_util::service::TowerToHyperService::new(app);
                                        if let Err(e) =
                                            hyper_util::server::conn::auto::Builder::new(
                                                hyper_util::rt::TokioExecutor::new(),
                                            )
                                            .serve_connection(io, service)
                                            .await
                                        {
                                            tracing::debug!("WSS connection error: {}", e);
                                        }
                                    }
                                    Err(e) => error!("WSS TLS handshake failed: {}", e),
                                }
                            });
                        }
                        Err(e) => error!("WSS accept error: {}", e),
                    }
                }
            });
        }
    }

    // Wrap config in Arc<RwLock<>> so REHASH can reload it at runtime
    let cfg_arc = Arc::new(RwLock::new(cfg));

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

                // Store TLS client certificate fingerprint for SASL EXTERNAL
                if let Some(ref fp) = cm.certfp {
                    let mut state_w = state.write().await;
                    state_w.certfps.entry(client_id.clone()).or_insert_with(|| fp.clone());
                }

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
                    cfg_arc.clone(),
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
