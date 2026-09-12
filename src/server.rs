use crate::channel::ChannelStore;
use crate::client;
use crate::commands;
use crate::config::Config;
use crate::protocol::Message;
use crate::user::ServerState;
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
    /// Raised when this connection's outbound queue overflows, so the server can
    /// drop the client instead of waiting for it.
    pub kill: Arc<tokio::sync::Notify>,
    /// TLS client certificate SHA-256 fingerprint (hex), if available.
    pub certfp: Option<String>,
    /// True if this connection is over TLS.
    pub is_tls: bool,
}

/// Build a TLS acceptor from the certificate and key named in the configuration.
///
/// Separate so it can be called again on REHASH: certificates are renewed on a
/// schedule, and restarting the server to pick one up drops every connection.
/// The acceptor for link ports.
///
/// Always asks the peer for a certificate, whatever `[tls] client_certs` says
/// about clients: on a link it is not an optional extra but the thing a
/// `fingerprint` in the link block is checked against.
pub fn build_link_tls_acceptor(cfg: &Config) -> anyhow::Result<TlsAcceptor> {
    let cert_path = cfg
        .tls
        .cert
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("listen_links_tls needs a certificate under [tls]"))?;
    let key_path = cfg
        .tls
        .key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("listen_links_tls needs a key under [tls]"))?;
    let mut cert_file = std::io::BufReader::new(fs::File::open(cert_path)?);
    let mut key_file = std::io::BufReader::new(fs::File::open(key_path)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_file)
        .filter_map(|r| r.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut key_file)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
    let cfg_tls = tokio_rustls::rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(OptionalClientCertVerifier::new()))
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(cfg_tls)))
}

pub fn build_tls_acceptor(cfg: &Config) -> anyhow::Result<TlsAcceptor> {
    let cert_path = cfg
        .tls
        .cert
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no TLS certificate configured"))?;
    let key_path = cfg
        .tls
        .key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no TLS key configured"))?;
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
    Ok(TlsAcceptor::from(Arc::new(cfg_tls)))
}

/// The subprotocols we support, in the order the client asked for them.
fn supported_ws_protocols(headers: &axum::http::HeaderMap) -> Vec<String> {
    const SUPPORTED: &[&str] = &["text.ircv3.net", "binary.ircv3.net"];
    let offered: Vec<String> = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| SUPPORTED.contains(&p.as_str()))
                .collect()
        })
        .unwrap_or_default();
    if offered.is_empty() {
        SUPPORTED.iter().map(|s| s.to_string()).collect()
    } else {
        offered
    }
}

/// Longest a TLS handshake may take before the connection is dropped.
///
/// Without it, opening a socket and sending one byte holds a task and a file
/// descriptor for as long as the attacker likes: the per-address and total
/// connection limits are claimed after the handshake, so a stalled one is not
/// counted against anything. Any real client finishes in well under a second.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The forwarded-address rule, for tests.
#[doc(hidden)]
pub fn forwarded_for_for_test(
    headers: &axum::http::HeaderMap,
    peer: std::net::SocketAddr,
    trusted: &[String],
) -> String {
    forwarded_for(headers, peer, trusted)
}

/// Who a WebSocket client really is.
///
/// A plaintext WebSocket listener usually sits behind a reverse proxy, and
/// `X-Forwarded-For` is how the proxy says whose connection it is passing on.
/// It is also just a header, and anybody can send one — so it is believed only
/// when the connection carrying it came from an address the operator named as a
/// proxy. Otherwise the address that actually connected is the answer, because
/// letting a client choose its own would let it choose which bans apply to it,
/// which connection limit it counts against, whose failed-login budget it
/// spends, and what everybody else sees as its host.
///
/// The last entry is taken, not the first. A proxy appends what it saw to
/// whatever was already there, so a client that sends a header of its own
/// pushes its lie to the left and the truth is what the proxy put on the end.
fn forwarded_for(
    headers: &axum::http::HeaderMap,
    peer: std::net::SocketAddr,
    trusted: &[String],
) -> String {
    let actual = peer.ip().to_string();
    if !trusted.iter().any(|t| t == &actual) {
        return actual;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or(actual)
}

pub async fn run(
    mut cfg: Config,
    config_path: &Path,
    pidfile: Option<&Path>,
) -> anyhow::Result<()> {
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
            ch_guard.founder = e.founder;
            ch_guard.bans = e.bans;
            ch_guard.ban_exceptions = e.ban_exceptions;
            ch_guard.invite_exceptions = e.invite_exceptions;
            ch_guard.quiet_list = e.quiets;
            ch_guard.list_meta = e.list_meta;
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
        // Profiles used to be filed under a nick. Move them onto the account
        // they belong to before anything reads them, and drop the ones that
        // belong to nobody — a name somebody borrowed once is not an identity.
        let (moved, dropped) = crate::persist::migrate_metadata_to_accounts(pool).await;
        if moved > 0 || dropped > 0 {
            info!("Metadata: {moved} row(s) moved onto their account, {dropped} dropped");
        }
        // Standing channel status belongs to an account for the same reason.
        let ungrounded = crate::persist::drop_channel_access_without_accounts(pool).await;
        if ungrounded > 0 {
            info!(
                "Channel access: {ungrounded} row(s) named somebody with no account, dropped"
            );
        }
        let meta = crate::persist::load_all_metadata(pool).await;
        let memberships = crate::persist::load_account_channels(pool).await;
        let bans = crate::persist::load_server_bans(pool).await;
        if !bans.is_empty() {
            info!("Loaded {} server ban(s)", bans.len());
        }
        let mut state_w = state.write().await;
        state_w.read_markers = markers;
        state_w.metadata = meta;
        state_w.server_bans = bans;
        for (channel, account) in memberships {
            state_w
                .channel_accounts
                .entry(channel)
                .or_default()
                .insert(account);
        }
    }
    // Store the config path so REHASH can reload from disk
    state.write().await.config_path = Some(config_path.to_path_buf());
    let senders: crate::user::Senders = Arc::new(RwLock::new(Default::default()));

    let (tx, mut rx) = mpsc::channel::<ClientMessage>(256);

    let tls_acceptor = if cfg.tls_enabled() {
        let shared = Arc::new(RwLock::new(build_tls_acceptor(&cfg)?));
        cfg.tls_acceptor = Some(shared.clone());
        Some(shared)
    } else {
        None
    };

    // ── Filehost HTTP endpoint ─────────────────────────────────────────────────
    if let Some(ref fh_cfg) = cfg.filehost {
        // Uploads are authenticated against the user database, so without one
        // the filehost would accept anything from anyone. The rest of the
        // server is fine without it, so this is a refusal to start that one
        // listener rather than a reason to bring everything down.
        let Some(db_pool) = cfg.db.clone() else {
            anyhow::bail!(
                "[filehost] needs [database]: uploads are authenticated against the user database"
            );
        };
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
            db_pool,
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
                                    let acceptor = acceptor.read().await.clone();
                                    match tokio::time::timeout(
                                        TLS_HANDSHAKE_TIMEOUT,
                                        acceptor.accept(stream),
                                    )
                                    .await
                                    {
                                        Err(_) => {
                                            tracing::debug!("Filehost TLS handshake timed out");
                                        }
                                        Ok(Ok(tls_stream)) => {
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
                                        Ok(Err(e)) => {
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
    let limits =
        client::ConnectionLimits::new(cfg.limits.max_connections_per_ip, cfg.limits.max_clients);
    if limits.max_per_ip > 0 || limits.max_total > 0 {
        info!(
            "Connection limits: {} per address, {} in total",
            if limits.max_per_ip > 0 {
                limits.max_per_ip.to_string()
            } else {
                "unlimited".into()
            },
            if limits.max_total > 0 {
                limits.max_total.to_string()
            } else {
                "unlimited".into()
            },
        );
    }
    // One source of connection ids for every listener.
    //
    // A counter per listener means the plain port and the TLS port both hand
    // out "client-1", and a server that offers both — which is every real one —
    // gives two different people the same id. Everything about a user is keyed
    // by it: the second to register would take the first's place in the client
    // table and its sink, and the first would stop being addressable.
    let connections = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let keepalive = client::KeepaliveConfig {
        ping_secs: cfg.server.ping_timeout_secs,
        max_line_length: cfg.limits.max_line_length,
        disconnect_secs: cfg.server.disconnect_timeout_secs,
        registration_secs: cfg.server.registration_timeout_secs,
        flood_burst: cfg.limits.flood_burst,
        flood_rate: cfg.limits.flood_rate,
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
        // Counted against this door rather than against an address, when the
        // configuration says everything reaches it from the same one.
        let limits = limits.on_listener(
            &bind_addr,
            &cfg.limits.shared_address_listeners,
            cfg.limits.max_clients_behind_one_address,
        );
        let connections = connections.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let client_id = format!(
                            "client-{}",
                            connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        );
                        let host = addr.ip().to_string();
                        let tx = tx.clone();
                        let server_name = server_name.clone();
                        let limits = limits.clone();
                        tokio::spawn(async move {
                            client::handle_client(
                                stream,
                                client_id,
                                host,
                                tx,
                                server_name,
                                keepalive,
                                limits,
                            )
                            .await;
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
            let limits = limits.on_listener(
                &bind_addr,
                &cfg.limits.shared_address_listeners,
                cfg.limits.max_clients_behind_one_address,
            );
            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let client_id = format!(
                                "client-{}",
                                connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            );
                            let host = addr.ip().to_string();
                            let tx = tx.clone();
                            let acc = tls_acc.clone();
                            let server_name = server_name.clone();
                            let limits = limits.clone();
                            tokio::spawn(async move {
                                let acc = acc.read().await.clone();
                                match tokio::time::timeout(
                                    TLS_HANDSHAKE_TIMEOUT,
                                    acc.accept(stream),
                                )
                                .await
                                {
                                    Err(_) => debug!("TLS handshake timed out"),
                                    Ok(Ok(tls_stream)) => {
                                        let certfp = extract_certfp(&tls_stream);
                                        client::handle_client_tls(
                                            tls_stream,
                                            client_id,
                                            host,
                                            tx,
                                            server_name,
                                            certfp,
                                            keepalive,
                                            limits,
                                        )
                                        .await
                                    }
                                    Ok(Err(e)) => error!("TLS handshake failed: {}", e),
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
            limits: client::ConnectionLimits,
            trusted_proxies: Arc<Vec<String>>,
        }

        let ws_state = WsState {
            tx: tx_ws,
            server_name: server_name_ws,
            counter: connections.clone(),
            keepalive,
            limits: limits.on_listener(
                &bind_addr,
                &cfg.limits.shared_address_listeners,
                cfg.limits.max_clients_behind_one_address,
            ),
            trusted_proxies: Arc::new(cfg.server.trusted_proxies.clone()),
        };

        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(
                    |ws: axum::extract::ws::WebSocketUpgrade,
                     headers: axum::http::HeaderMap,
                     axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<
                        std::net::SocketAddr,
                    >,
                     axum::extract::State(st): axum::extract::State<WsState>| async move {
                        let id = st
                            .counter
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let client_id = format!("ws-{}", id);
                        let host = forwarded_for(&headers, peer, &st.trusted_proxies);
                        // The client lists subprotocols in its order of
                        // preference, and that is the order to choose from:
                        // offering ours instead would pick text for a client
                        // that asked for binary first.
                        ws.protocols(supported_ws_protocols(&headers))
                            .on_upgrade(move |socket| {
                                client::handle_client_ws(
                                    socket,
                                    client_id,
                                    host,
                                    st.tx,
                                    st.server_name,
                                    None,
                                    st.keepalive,
                                    false, // WS (plaintext)
                                    st.limits,
                                )
                            })
                    },
                ),
            )
            .with_state(ws_state);

        tokio::spawn(async move {
            // With connect info, so the handler can see who actually connected
            // rather than only what they claimed in a header.
            let service =
                app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            if let Err(e) = axum::serve(listener, service).await {
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
            let limits_wss = limits.on_listener(
                &bind_addr,
                &cfg.limits.shared_address_listeners,
                cfg.limits.max_clients_behind_one_address,
            );
            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let client_id = format!(
                                "wss-{}",
                                connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            );
                            let host = addr.ip().to_string();
                            let acc = tls_acc.clone();
                            let tx = tx_wss.clone();
                            let sn = server_name_wss.clone();
                            let limits = limits_wss.clone();
                            tokio::spawn(async move {
                                let acc = acc.read().await.clone();
                                match tokio::time::timeout(
                                    TLS_HANDSHAKE_TIMEOUT,
                                    acc.accept(stream),
                                )
                                .await
                                {
                                    Err(_) => debug!("WSS TLS handshake timed out"),
                                    Ok(Ok(tls_stream)) => {
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
                                                        ws.protocols([
                                                            "text.ircv3.net",
                                                            "binary.ircv3.net",
                                                        ])
                                                        .on_upgrade(move |socket| {
                                                            client::handle_client_ws(
                                                                socket, client_id, host, tx, sn,
                                                                certfp, keepalive,
                                                                true, // WSS (TLS)
                                                                limits,
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
                                    Ok(Err(e)) => error!("WSS TLS handshake failed: {}", e),
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
    // ── Server links ───────────────────────────────────────────────────────────
    // Which names count as the same name, decided once, before anything is
    // named. Every server on one network has to agree: a link between two that
    // disagree would put one channel in two places.
    let mapping = crate::casefold::configure(&cfg.server.casemapping);
    if mapping != cfg.server.casemapping {
        warn!(
            configured = %cfg.server.casemapping,
            using = %mapping,
            "Unknown casemapping; using the default"
        );
    }
    info!(casemapping = %mapping, "Names fold under");

    let links = Arc::new(RwLock::new(crate::link::LinkRegistry::default()));
    cfg.links_runtime = Some(links.clone());
    let sid = crate::link::our_sid(&cfg);
    if !cfg.links.is_empty() || !cfg.server.listen_links.is_empty() {
        if cfg.server.sid.is_none() {
            warn!(
                sid = %sid,
                "No [server] sid set; using one derived from the server name. \
                 Two servers can derive the same one — set it before linking."
            );
        } else {
            info!(sid = %sid, "Server id");
        }
    }

    state.write().await.sid = sid.clone();

    let cfg_arc = Arc::new(RwLock::new(cfg));

    {
        let link_ctx = crate::link::LinkContext {
            cfg: cfg_arc.clone(),
            state: state.clone(),
            channels: channels.clone(),
            senders: senders.clone(),
            links: links.clone(),
        };
        let cfg = cfg_arc.read().await;
        for addr in &cfg.server.listen_links {
            crate::link::listen(addr.clone(), link_ctx.clone()).await?;
        }
        if !cfg.server.listen_links_tls.is_empty() {
            let acceptor = build_link_tls_acceptor(&cfg)?;
            for addr in &cfg.server.listen_links_tls {
                crate::link::listen_tls(addr.clone(), link_ctx.clone(), acceptor.clone()).await?;
            }
        }
        for link in cfg.links.iter().filter(|l| l.autoconnect) {
            crate::link::autoconnect(link.clone(), link_ctx.clone());
        }
    }

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // A certificate is renewed on somebody else's schedule, and the acceptor is
    // behind a lock so a new one can be dropped in without anybody noticing.
    // SIGHUP is how that gets asked for from outside the network — it is what
    // `systemctl reload` sends, and what the unit file in distrib/ has always
    // told operators to send. Until this existed the default disposition
    // applied, which is to die: a documented way to take the server down.
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    loop {
        tokio::select! {
            msg = rx.recv() => {
                let cm = match msg {
                    Some(m) => m,
                    None => break,
                };
                let client_id = cm.client_id.clone();
                {
                    // A connection registers once. Re-registering it here would
                    // undo the link to its user when it is one of several
                    // sessions on an account.
                    let mut senders_w = senders.write().await;
                    if !senders_w.contains(&client_id) {
                        senders_w.insert_session(
                            &client_id,
                            &client_id,
                            crate::user::ClientSink::new(cm.send_tx.clone(), cm.kill.clone()),
                        );
                    }
                }

                // Store TLS client certificate fingerprint for SASL EXTERNAL
                if let Some(ref fp) = cm.certfp {
                    let mut state_w = state.write().await;
                    state_w.certfps.entry(client_id.clone()).or_insert_with(|| fp.clone());
                }

                // Store TLS status on pending connection (for STS and WHOIS)
                if cm.is_tls {
                    let mut state_w = state.write().await;
                    if let Some(pending) = state_w.pending.get_mut(&client_id) {
                        pending.is_tls = true;
                    }
                    if let Some(client) = state_w.clients.get(&client_id) {
                        client.write().await.is_tls = true;
                    }
                }

                let cmd = cm.msg.command.clone();
                let params_preview = cm.msg.params.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
                let trailing_preview = cm
                    .msg
                    .trailing()
                    .map(|t| {
                        if t.len() > 40 {
                            format!("{}...", crate::protocol::truncate_bytes(t, 40))
                        } else {
                            t.to_string()
                        }
                    })
                    .unwrap_or_default();

                debug!(client = %client_id, command = %cmd, "handling message");
                // Every client's messages go through this one loop, so a panic
                // in a handler would take the server down for everyone over one
                // client's input. Contain it: the connection that caused it is
                // closed, and the rest of the server carries on.
                //
                // Lock guards are released as the stack unwinds, so nothing is
                // left held; state may be inconsistent for that one command,
                // which is a smaller price than the whole server going away.
                use futures_util::future::FutureExt;
                let handled = std::panic::AssertUnwindSafe(commands::handle_message(
                    cm.client_id,
                    cm.host,
                    cm.msg,
                    state.clone(),
                    channels.clone(),
                    senders.clone(),
                    cfg_arc.clone(),
                ))
                .catch_unwind()
                .await;

                let result = match handled {
                    Ok(result) => result,
                    Err(panic) => {
                        let detail = panic
                            .downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "unknown panic".to_string());
                        error!(
                            client = %client_id,
                            command = %cmd,
                            params = %params_preview,
                            trailing = %trailing_preview,
                            panic = %detail,
                            "Handler panicked; closing that connection and carrying on"
                        );
                        let server_name = cfg_arc.read().await.server.name.clone();
                        senders.write().await.close_user(
                            &client_id,
                            Message::new(
                                "ERROR",
                                vec!["Closing link: the server could not handle that".into()],
                            )
                            .with_prefix(&server_name),
                        );
                        Ok(())
                    }
                };

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
            _ = async {
                #[cfg(unix)]
                {
                    sighup.recv().await;
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                let path = state.read().await.config_path.clone();
                match path {
                    Some(path) => {
                        match crate::commands::server_cmds::reload_config(
                            &state, &senders, &cfg_arc, &path,
                        )
                        .await
                        {
                            Ok(file) => info!(config = %file, "Reloaded on SIGHUP"),
                            Err(e) => error!(
                                "SIGHUP: keeping the configuration that is running: {}",
                                e
                            ),
                        }
                    }
                    None => warn!("SIGHUP: no configuration file to reload"),
                }
            }
        }
    }

    Ok(())
}
