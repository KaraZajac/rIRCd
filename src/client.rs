use crate::protocol::{format_message_within, parse_message_with_limit, Message, ParseError};
use crate::server::ClientMessage;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
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
    /// New connections one address may make in a minute; 0 for no limit.
    pub max_per_ip_per_minute: usize,
    counts: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    /// When each address last connected, newest last, kept only as far back
    /// as a minute. What bounds a client that connects and hangs up in a
    /// loop: each connection costs a handshake — a TLS one costs real work —
    /// and the concurrent limit never sees it, because it is never concurrent.
    arrivals: Arc<std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>>>,
    total: Arc<std::sync::atomic::AtomicUsize>,
    /// Set when this view serves a listener whose clients all arrive from the
    /// same address. See `on_listener`.
    shared: Option<SharedListener>,
    /// A blocklist to ask about every public address, if one is configured.
    dnsbl: Option<Arc<crate::dnsbl::Dnsbl>>,
    /// D-lines: addresses and networks turned away the moment they connect,
    /// before a nick, a handshake, or a database has cost anything. Shared
    /// with the server state that keeps them current.
    dlines: Option<Arc<std::sync::RwLock<Vec<crate::persist::ServerBan>>>>,
    /// Exemptions: who none of that applies to. Shared the same way.
    exempts: Option<Arc<std::sync::RwLock<Vec<crate::persist::ServerBan>>>>,
    /// Kinds of client, in the order they are tried. See `ClassConfig`.
    classes: Arc<Vec<Arc<crate::config::ClassConfig>>>,
    /// How many connections each class is holding.
    class_counts: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
}

/// A listener where counting by address cannot mean anything.
///
/// Behind a Tor hidden service, or any local proxy, every client arrives from
/// 127.0.0.1. The per-address limit then says "sixteen people may use this
/// server through Tor at once", which is not a rule anybody meant to write —
/// and it cannot be fixed by counting more carefully, because the addresses
/// genuinely are all the same. There is nothing to tell apart.
///
/// So the whole listener is capped instead. It is a weaker promise than the
/// per-address one, and it is the strongest one available: it bounds what the
/// door can let through without pretending to know who is coming through it.
#[derive(Clone, Debug)]
struct SharedListener {
    addr: String,
    max: usize,
    count: Arc<std::sync::atomic::AtomicUsize>,
}

/// Releases a connection's slot when the connection ends.
pub struct ConnectionSlot {
    limits: ConnectionLimits,
    host: String,
    /// The kind of client this connection was taken as, if any class named
    /// it. What it is allowed, and what `TRACE` and `STATS y` call it.
    class: Option<Arc<crate::config::ClassConfig>>,
}

impl ConnectionSlot {
    /// What this connection is called: its class, or how it arrived when no
    /// class named it.
    pub fn class_name(&self, transport: &'static str) -> Arc<str> {
        match self.class {
            Some(ref c) => Arc::from(c.name.as_str()),
            None => Arc::from(transport),
        }
    }

    /// The pacing for this connection: the server's, with whatever its class
    /// had an opinion about.
    pub fn paced(&self, base: KeepaliveConfig) -> KeepaliveConfig {
        let Some(ref class) = self.class else {
            return base;
        };
        KeepaliveConfig {
            ping_secs: class.ping_secs.unwrap_or(base.ping_secs),
            flood_burst: class.flood_burst.unwrap_or(base.flood_burst),
            flood_rate: class.flood_rate.unwrap_or(base.flood_rate),
            sendq: class.sendq.unwrap_or(base.sendq).clamp(16, 1 << 20),
            ..base
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        if let Some(ref class) = self.class {
            if let Ok(mut counts) = self.limits.class_counts.lock() {
                if let Some(n) = counts.get_mut(&class.name) {
                    *n = n.saturating_sub(1);
                }
            }
        }
        match self.limits.shared {
            Some(ref shared) => {
                shared
                    .count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
            None => {
                if let Ok(mut counts) = self.limits.counts.lock() {
                    if let Some(n) = counts.get_mut(&self.host) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            counts.remove(&self.host);
                        }
                    }
                }
            }
        }
        self.limits
            .total
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The key an address is counted under.
///
/// An IPv4 address is one machine, near enough. An IPv6 address is not: the
/// smallest allocation anybody is given is a /64, which is eighteen quintillion
/// addresses, and a client picks a fresh one for every connection if it likes.
/// Counting each of those separately would make every per-address limit on
/// this server — connections, failed logins, registrations — a limit on nobody
/// who has IPv6. So an IPv6 address is counted by its /64, which is the unit
/// that is actually handed to one person. Anything that is not an address is
/// counted as itself.
pub fn limit_key_for(host: &str) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let seg = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3])
            }
        },
        _ => host.to_string(),
    }
}

/// One spelling for a listen address, so configuration and bind agree.
///
/// `:6667` is how the rest of the configuration lets somebody write "every
/// address, this port", and it is turned into `0.0.0.0:6667` before binding.
/// A listener named in one spelling and bound in the other is the same
/// listener, and must not silently fail to match.
pub fn normalise_listen(addr: &str) -> String {
    let addr = addr.trim();
    if let Some(port) = addr.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        addr.to_string()
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

    /// The same limits, with a ceiling on how often one address may connect.
    pub fn with_rate(mut self, max_per_ip_per_minute: usize) -> Self {
        self.max_per_ip_per_minute = max_per_ip_per_minute;
        self
    }

    /// The same limits, asking a blocklist about every public address.
    pub fn with_dnsbl(mut self, dnsbl: Option<Arc<crate::dnsbl::Dnsbl>>) -> Self {
        self.dnsbl = dnsbl;
        self
    }

    /// The same limits, with kinds of client told apart.
    pub fn with_classes(mut self, classes: &[crate::config::ClassConfig]) -> Self {
        self.classes = Arc::new(classes.iter().cloned().map(Arc::new).collect());
        self
    }

    /// The class a connecting address belongs to, if any is configured for it.
    pub fn class_for(&self, host: &str) -> Option<Arc<crate::config::ClassConfig>> {
        let key = limit_key_for(host);
        self.classes
            .iter()
            .find(|c| c.covers(host) || c.covers(&key))
            .cloned()
    }

    /// How many connections each class is holding, for `STATS y`.
    pub fn class_counts(&self) -> std::collections::HashMap<String, usize> {
        self.class_counts
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// The same limits, turning D-lined addresses away on arrival.
    pub fn with_dlines(
        mut self,
        dlines: Arc<std::sync::RwLock<Vec<crate::persist::ServerBan>>>,
    ) -> Self {
        self.dlines = Some(dlines);
        self
    }

    /// Give this view the exemptions, so the door can tell who is vouched for.
    pub fn with_exempts(
        mut self,
        exempts: Arc<std::sync::RwLock<Vec<crate::persist::ServerBan>>>,
    ) -> Self {
        self.exempts = Some(exempts);
        self
    }

    /// Whether an exemption vouches for this address.
    ///
    /// Asked at the door, where a connection has an address and nothing else,
    /// so an exemption written as `*!*@host` or as a network is judged on the
    /// address alone.
    pub fn is_exempt(&self, host: &str) -> bool {
        let Some(exempts) = self.exempts.as_ref() else {
            return false;
        };
        let Ok(exempts) = exempts.read() else {
            return false;
        };
        let now = chrono::Utc::now().timestamp();
        exempts
            .iter()
            .any(|e| !e.is_expired(now) && e.matches("", host))
    }

    /// The reason this address is D-lined, if it is. Nothing on a listener
    /// behind one address, where the address is everybody's.
    pub fn dline_for(&self, host: &str) -> Option<String> {
        if self.shared.is_some() || self.is_exempt(host) {
            return None;
        }
        let dlines = self.dlines.as_ref()?.read().ok()?;
        let now = chrono::Utc::now().timestamp();
        dlines
            .iter()
            .find(|b| !b.is_expired(now) && b.matches("", host))
            .map(|b| b.reason.clone())
    }

    /// The zone that lists this address, if a blocklist is configured and one
    /// does. Nothing on a listener behind one address: the address there is
    /// everybody's.
    pub async fn dnsbl_listing(&self, host: &str) -> Option<String> {
        // An exempt address is not asked about. Every blocklist eventually
        // lists somebody who belongs here, and this is the answer to that
        // which does not mean disbelieving the list for everybody else.
        if self.shared.is_some() || self.is_exempt(host) {
            return None;
        }
        self.dnsbl.as_ref()?.listing(host).await
    }

    /// Whether a listing turns the connection away rather than being noted.
    pub fn dnsbl_rejects(&self) -> bool {
        self.dnsbl.as_ref().is_some_and(|d| d.rejects())
    }

    /// Addresses whose arrival history is remembered at once. Entries with
    /// nothing in the last minute are dropped as they are met, so the ceiling
    /// is reached only when that many addresses are arriving at once.
    const MAX_TRACKED_ARRIVALS: usize = 16384;

    /// Note an arrival and say whether this address has had too many lately.
    fn arriving_too_fast(&self, key: &str) -> bool {
        if self.max_per_ip_per_minute == 0 {
            return false;
        }
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);
        let mut arrivals = match self.arrivals.lock() {
            Ok(a) => a,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !arrivals.contains_key(key) {
            arrivals.retain(|_, when| {
                while when.front().is_some_and(|t| now.duration_since(*t) > window) {
                    when.pop_front();
                }
                !when.is_empty()
            });
            if arrivals.len() >= Self::MAX_TRACKED_ARRIVALS {
                // More addresses arriving at once than this can remember. The
                // concurrent limit still stands; being untracked here is not
                // a way in, only a way past the rate.
                return false;
            }
        }
        let when = arrivals.entry(key.to_string()).or_default();
        while when.front().is_some_and(|t| now.duration_since(*t) > window) {
            when.pop_front();
        }
        if when.len() >= self.max_per_ip_per_minute {
            return true;
        }
        when.push_back(now);
        false
    }

    /// A view of these limits for one listener.
    ///
    /// Naming a listener here says its clients all reach it from one address,
    /// so connections arriving on it are counted against the listener rather
    /// than against the address they appear to come from. Every other listener
    /// keeps the per-address limit, which is the stronger rule and is only
    /// given up where it has stopped meaning anything.
    pub fn on_listener(&self, addr: &str, shared_addresses: &[String], max: usize) -> Self {
        let mine = normalise_listen(addr);
        if !shared_addresses
            .iter()
            .any(|listed| normalise_listen(listed) == mine)
        {
            return self.clone();
        }
        Self {
            shared: Some(SharedListener {
                addr: mine,
                max,
                count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            ..self.clone()
        }
    }

    /// Claim a slot for `host`, or report why it was refused.
    ///
    /// `host` is the address as the connection has it; what it is counted
    /// under is `limit_key_for(host)`, so an IPv6 client is one client however
    /// many of its /64 it uses.
    pub fn claim(&self, host: &str) -> Result<ConnectionSlot, &'static str> {
        let class = self.class_for(host);
        let host = limit_key_for(host);
        let host = host.as_str();
        // A class holds what it says it holds, whatever the server's own
        // ceiling is — that is the whole point of having one.
        if let Some(ref class) = class {
            let mut counts = match self.class_counts.lock() {
                Ok(c) => c,
                Err(poisoned) => poisoned.into_inner(),
            };
            let taken = counts.entry(class.name.clone()).or_insert(0);
            match class.max_clients {
                Some(max) if max > 0 && *taken >= max => {
                    tracing::warn!(class = %class.name, max, "A class is full");
                    return Err("This class of connection is full");
                }
                _ => *taken += 1,
            }
        }
        let undo_class = || {
            if let Some(ref class) = class {
                if let Ok(mut counts) = self.class_counts.lock() {
                    if let Some(n) = counts.get_mut(&class.name) {
                        *n = n.saturating_sub(1);
                    }
                }
            }
        };
        let total = self
            .total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if self.max_total > 0 && total > self.max_total {
            self.total
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            undo_class();
            return Err("Server is full");
        }
        if self.shared.is_none() && self.arriving_too_fast(host) {
            self.total
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            undo_class();
            return Err("Connecting too often; try again in a minute");
        }
        if let Some(ref shared) = self.shared {
            let taken = shared
                .count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if shared.max > 0 && taken > shared.max {
                shared
                    .count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                self.total
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                undo_class();
                tracing::warn!(
                    listener = %shared.addr,
                    max = shared.max,
                    "A listener behind one address is full"
                );
                return Err("This entrance is full");
            }
            return Ok(ConnectionSlot {
                limits: self.clone(),
                host: host.to_string(),
                class,
            });
        }
        {
            let mut counts = match self.counts.lock() {
                Ok(c) => c,
                Err(poisoned) => poisoned.into_inner(),
            };
            let entry = counts.entry(host.to_string()).or_insert(0);
            // The class has the say when it has an opinion; a class that sets
            // 0 means this kind of client is not counted by address at all,
            // which is what a gateway needs.
            let per_ip = match class.as_ref().and_then(|c| c.max_per_ip) {
                Some(max) => max,
                None => self.max_per_ip,
            };
            if per_ip > 0 && *entry >= per_ip {
                self.total
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                drop(counts);
                undo_class();
                return Err("Too many connections from your address");
            }
            *entry += 1;
        }
        Ok(ConnectionSlot {
            limits: self.clone(),
            host: host.to_string(),
            class,
        })
    }
}

/// Outbound queue depth per client. Large enough for legitimate bursts such as a
/// NAMES reply on a busy channel; a client that lets it fill is not reading.
pub const SEND_QUEUE: usize = 1024;

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
    /// Messages that may be queued for this connection before it is dropped
    /// for not reading them.
    pub sendq: usize,
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
    if let Some(reason) = limits.dline_for(&host) {
        tracing::warn!(%host, %reason, "Refused a TLS connection from a D-lined address");
        refuse_connection_tls(stream, &server_name, &format!("banned ({reason})")).await;
        return;
    }
    if let Some(zone) = limits.dnsbl_listing(&host).await {
        if limits.dnsbl_rejects() {
            tracing::warn!(%host, %zone, "Refused a TLS connection from a listed address");
            refuse_connection_tls(stream, &server_name, &format!("Your address is listed in {zone}"))
                .await;
            return;
        }
        tracing::warn!(%host, %zone, "Connection from a listed address, allowed by configuration");
    }
    handle_client_stream(
        stream,
        client_id,
        host,
        tx,
        server_name,
        certfp,
        true,
        _slot.paced(keepalive),
        _slot.class_name("tls"),
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
    if let Some(reason) = limits.dline_for(&host) {
        tracing::warn!(%host, %reason, "Refused a connection from a D-lined address");
        refuse_connection(stream, &server_name, &format!("banned ({reason})")).await;
        return;
    }
    if let Some(zone) = limits.dnsbl_listing(&host).await {
        if limits.dnsbl_rejects() {
            tracing::warn!(%host, %zone, "Refused a connection from a listed address");
            refuse_connection(stream, &server_name, &format!("Your address is listed in {zone}")).await;
            return;
        }
        tracing::warn!(%host, %zone, "Connection from a listed address, allowed by configuration");
    }
    handle_client_stream(
        stream,
        client_id,
        host,
        tx,
        server_name,
        None,
        false,
        _slot.paced(keepalive),
        _slot.class_name("plain"),
    )
    .await;
}

/// Commands a batch collects. Only these are one logical message when they
/// carry an open batch's tag; anything else is an ordinary command wearing it.
const BATCHED_COMMANDS: &[&str] = &["PRIVMSG", "NOTICE", "TAGMSG"];

/// Whether a command is exempt from flood control.
///
/// Registration is exempt because a client has to get through it before it can
/// usefully be told to slow down, and PING because dropping it makes a
/// responsive server look dead: the client is waiting for a PONG that will
/// never come.
///
/// NICK belongs to registration only until the client has said who it is.
/// After that it is an ordinary command and an expensive one — every member of
/// every channel the client is in hears about a nick change, and so does every
/// other server on the network. Left exempt, one connection renaming itself as
/// fast as it can decides how much of this server everybody else gets, and the
/// backlog it builds outlives the connection that sent it.
///
/// The lines a batch collects are one logical message between them: charging a
/// token each would make the advertised multiline limits unusable, because
/// max-lines is twice the bucket, and the server bounds the batch itself. That
/// is true of the three commands a batch actually collects and of nothing else
/// — a WHO with a batch tag on it is a WHO.
fn flood_exempt(msg: &Message, has_said_who_they_are: bool, open_batch: Option<&str>) -> bool {
    if open_batch.is_some()
        && BATCHED_COMMANDS.contains(&msg.command.as_str())
        && msg.tags.get("batch").and_then(|v| v.as_deref()) == open_batch
    {
        return true;
    }
    match msg.command.as_str() {
        "CAP" | "USER" | "PASS" | "AUTHENTICATE" | "PING" | "PONG" | "QUIT" | "BATCH" => true,
        "NICK" => !has_said_who_they_are,
        _ => false,
    }
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
    stats: &crate::user::ConnStats,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut backlog: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut sent = 0usize;
    let mut queued = 0u64;
    loop {
        if sent == backlog.len() {
            backlog.clear();
            sent = 0;
            queued = 0;
            let Some(first) = send_rx.recv().await else {
                return;
            };
            backlog.extend_from_slice(format_message_within(&first, out_line_limit).as_bytes());
            queued += 1;
        }
        // Whatever else is already queued goes in the same write.
        while backlog.len() < SEND_BACKLOG_BYTES {
            match send_rx.try_recv() {
                Ok(msg) => {
                    backlog
                        .extend_from_slice(format_message_within(&msg, out_line_limit).as_bytes());
                    queued += 1;
                }
                Err(_) => break,
            }
        }
        match writer.write(&backlog[sent..]).await {
            Ok(0) => {
                error!("Write error for {}: peer closed", client_id);
                return;
            }
            Ok(n) => {
                sent += n;
                // The messages are counted once the last of their bytes is
                // away, so a half-written batch is not reported as sent.
                let done = if sent == backlog.len() {
                    std::mem::take(&mut queued)
                } else {
                    0
                };
                stats.wrote(n, done);
            }
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

#[allow(clippy::too_many_arguments)]
async fn handle_client_stream<S>(
    stream: S,
    client_id: String,
    host: String,
    tx: mpsc::Sender<ClientMessage>,
    server_name: String,
    certfp: Option<String>,
    is_tls: bool,
    keepalive: KeepaliveConfig,
    class: Arc<str>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(BUF_SIZE, reader);

    let (send_tx, mut send_rx) = mpsc::channel::<Message>(keepalive.sendq);

    let client_id_clone = client_id.clone();
    // Two bytes of the limit belong to the CRLF.
    let out_line_limit = keepalive.max_line_length.saturating_sub(2);
    // The limit counts the CRLF that ends the line, so what a message may
    // actually carry is two bytes less than the number the limit is written as.
    let in_line_limit = out_line_limit;
    // What one line may cost to read. Tags are counted separately from the body
    // and are allowed far more room, so the body limit is not a bound on the
    // line — this is.
    let mut lines =
        crate::linereader::BoundedLines::new(crate::protocol::MAX_TOTAL_TAGGED.max(in_line_limit));
    // What crosses this connection, counted where the bytes are.
    let stats = std::sync::Arc::new(crate::user::ConnStats::in_class(class));
    let writer_stats = stats.clone();
    let mut writer_task = tokio::spawn(async move {
        write_loop(
            &mut writer,
            &mut send_rx,
            out_line_limit,
            &client_id_clone,
            &writer_stats,
        )
        .await;
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
                                // NICK before USER is a client choosing its name; after it, a client
                                // changing it. Only the second is charged for.
    let mut said_who_they_are = false;
    let tx_clone = tx.clone();
    let mut quit_reason = "Connection closed";

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
            result = lines.next(&mut reader) => {
                match result {
                    Ok(crate::linereader::Line::Eof) => break,
                    // Refused before it was held: a peer that never ends its
                    // line does not get to decide how much memory this server
                    // spends on it.
                    Ok(crate::linereader::Line::TooLong) => {
                        let _ = send_tx.try_send(
                            Message::new("417", vec!["*".into(), "Input line was too long".into()])
                                .with_prefix(&server_name),
                        );
                        last_activity = tokio::time::Instant::now();
                        continue;
                    }
                    Ok(crate::linereader::Line::Read) => {
                        let buf = lines.line();
                        if buf.is_empty() {
                            continue;
                        }
                        // The line as it came off the wire, with the ending
                        // the reader stripped.
                        stats.read(buf.len() + 2);
                        let line = match std::str::from_utf8(buf) {
                            Ok(s) => s,
                            Err(_) => {
                                // The line cannot be handled, but the command
                                // word is ASCII in any message that has one, so
                                // the client can still be told what was refused.
                                let command = {
                                    let lossy = String::from_utf8_lossy(buf);
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
                                continue;
                            }
                        };

                        match parse_message_with_limit(line, in_line_limit) {
                            Ok(msg) => {
                                debug!(client = %client_id, command = %msg.command, "received");

                                // Any data from client resets keepalive
                                last_activity = tokio::time::Instant::now();
                                registered = true;
                                if msg.command == "USER" {
                                    said_who_they_are = true;
                                }
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

                                if !flood_exempt(&msg, said_who_they_are, open_batch.as_deref()) {
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
                                                continue;
                                    }
                                    flood_tokens -= 1.0;
                                }

                                if tx_clone
                                    .send(ClientMessage {
                                        stats: stats.clone(),
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
            stats: stats.clone(),
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
    if let Some(reason) = limits.dline_for(&host) {
        tracing::warn!(%host, %reason, "Refused a WebSocket connection from a D-lined address");
        let _ = socket
            .send(axum::extract::ws::Message::Text(
                format!(":{} ERROR :Closing link: banned ({})", server_name, reason).into(),
            ))
            .await;
        return;
    }
    if let Some(zone) = limits.dnsbl_listing(&host).await {
        if limits.dnsbl_rejects() {
            tracing::warn!(%host, %zone, "Refused a WebSocket connection from a listed address");
            let _ = socket
                .send(axum::extract::ws::Message::Text(
                    format!(":{} ERROR :Closing link: Your address is listed in {}", server_name, zone)
                        .into(),
                ))
                .await;
            return;
        }
        tracing::warn!(%host, %zone, "Connection from a listed address, allowed by configuration");
    }

    // The class has its say before anything is sized by it.
    let keepalive = _slot.paced(keepalive);
    let (send_tx, mut send_rx) = mpsc::channel::<Message>(keepalive.sendq);
    let kill = Arc::new(tokio::sync::Notify::new());
    // What crosses this connection. A frame is a message, which is the one
    // place a WebSocket client counts differently from a socket one.
    let stats = std::sync::Arc::new(crate::user::ConnStats::in_class(
        _slot.class_name("websocket"),
    ));

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
    // NICK before USER is a client choosing its name; after it, a client
    // changing it. Only the second is charged for.
    let mut said_who_they_are = false;
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
                let bytes = match &frame {
                    ws::Message::Binary(b) => b.len(),
                    ws::Message::Text(t) => t.len(),
                    _ => 0,
                };
                if socket.send(frame).await.is_err() {
                    error!("WebSocket write error for {}", client_id);
                    break;
                }
                stats.wrote(bytes, 1);
            }
            // Read incoming WS frames as IRC messages (text or binary per IRCv3 WS spec)
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(ws::Message::Text(text))) => {
                        let line = text.trim();
                        if line.is_empty() {
                            continue;
                        }
                        stats.read(text.len());
                        match parse_message_with_limit(line, ws_line_limit) {
                            Ok(msg) => {
                                debug!(client = %client_id, command = %msg.command, "received (ws)");

                                last_activity = tokio::time::Instant::now();
                                registered = true;
                                if msg.command == "USER" {
                                    said_who_they_are = true;
                                }
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

                                if !flood_exempt(&msg, said_who_they_are, open_batch.as_deref()) {
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
                                    stats: stats.clone(),
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
                        stats.read(data.len());
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
                                if msg.command == "USER" {
                                    said_who_they_are = true;
                                }
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

                                if !flood_exempt(&msg, said_who_they_are, open_batch.as_deref()) {
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
                                    stats: stats.clone(),
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
            stats: stats.clone(),
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
            write_loop(&mut server, &mut rx, 510, "test", &crate::user::ConnStats::new()).await;
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
            write_loop(&mut server, &mut rx, 510, "test", &crate::user::ConnStats::new()).await;
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

    #[test]
    fn an_ipv6_client_is_counted_by_its_prefix() {
        assert_eq!(limit_key_for("198.51.100.7"), "198.51.100.7");
        assert_eq!(
            limit_key_for("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            "2001:db8:1:2::/64"
        );
        assert_eq!(
            limit_key_for("2001:db8:1:2::1"),
            limit_key_for("2001:db8:1:2:ffff:ffff:ffff:ffff"),
            "the whole /64 is one client"
        );
        assert_ne!(limit_key_for("2001:db8:1:2::1"), limit_key_for("2001:db8:1:3::1"));
        assert_eq!(limit_key_for("::ffff:198.51.100.7"), "198.51.100.7");
        assert_eq!(limit_key_for("not-an-address"), "not-an-address");

        let limits = ConnectionLimits::new(2, 0);
        let _a = limits.claim("2001:db8:1:2::1").expect("first");
        let _b = limits.claim("2001:db8:1:2::2").expect("second");
        assert!(
            limits.claim("2001:db8:1:2::3").is_err(),
            "a third address in the same /64 is the same client, over the limit"
        );
        assert!(limits.claim("2001:db8:1:3::1").is_ok(), "another /64 is somebody else");
    }

    #[test]
    fn connecting_in_a_loop_is_refused_after_a_while() {
        let limits = ConnectionLimits::new(0, 0).with_rate(5);
        for i in 0..5 {
            // Each connection ends at once, so the concurrent count never grows.
            let slot = limits.claim("198.51.100.7").unwrap_or_else(|e| panic!("{i}: {e}"));
            drop(slot);
        }
        assert!(
            limits.claim("198.51.100.7").is_err(),
            "the sixth in a minute is one too many"
        );
        assert!(limits.claim("203.0.113.9").is_ok(), "another address is not held to it");
    }

    #[test]
    fn a_listener_behind_one_address_is_not_counted_by_address() {
        let limits = ConnectionLimits::new(2, 0);
        let onion = limits.on_listener("127.0.0.1:6667", &["127.0.0.1:6667".into()], 5);
        // Everybody arrives from the same place, which is the whole point.
        let mut held = Vec::new();
        for i in 0..5 {
            held.push(
                onion
                    .claim("127.0.0.1")
                    .unwrap_or_else(|e| panic!("connection {i} refused: {e}")),
            );
        }
        assert!(
            onion.claim("127.0.0.1").is_err(),
            "the listener's own cap still stops somewhere"
        );
        drop(held.pop());
        assert!(
            onion.claim("127.0.0.1").is_ok(),
            "a slot given back is a slot available"
        );
    }

    #[test]
    fn every_other_listener_keeps_the_per_address_limit() {
        let limits = ConnectionLimits::new(2, 0);
        let ordinary = limits.on_listener("0.0.0.0:6667", &["127.0.0.1:6667".into()], 5);
        let _a = ordinary.claim("198.51.100.7").expect("first");
        let _b = ordinary.claim("198.51.100.7").expect("second");
        assert!(
            ordinary.claim("198.51.100.7").is_err(),
            "the address limit is the stronger rule and is kept where it means something"
        );
    }

    #[test]
    fn a_shared_listener_is_named_in_whichever_spelling() {
        let limits = ConnectionLimits::new(1, 0);
        // `:6667` is how the configuration lets somebody say "every address".
        let onion = limits.on_listener("0.0.0.0:6667", &[":6667".into()], 4);
        let _a = onion.claim("127.0.0.1").expect("first");
        assert!(
            onion.claim("127.0.0.1").is_ok(),
            "the two spellings name the same listener"
        );
    }

    #[test]
    fn the_total_is_still_the_total() {
        let limits = ConnectionLimits::new(0, 2);
        let onion = limits.on_listener("127.0.0.1:6667", &["127.0.0.1:6667".into()], 0);
        let _a = onion.claim("127.0.0.1").expect("first");
        let _b = onion.claim("127.0.0.1").expect("second");
        assert!(
            onion.claim("127.0.0.1").is_err(),
            "a listener with no cap of its own is still inside max_clients"
        );
    }

}
