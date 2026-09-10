//! Server-to-server linking. See docs/server-linking.md for the protocol.
//!
//! A link is a connection to another rIRCd, authenticated before anything else
//! happens on it, over which the two servers tell each other about their users,
//! channels and traffic. Server traffic has its own listener: a client that
//! reaches it is refused, so a mistake in one configuration cannot become an
//! authentication bypass in the other.

use crate::channel::ChannelStore;
use crate::config::{Config, LinkConfig};
use crate::protocol::{parse_message_with_limit, Message};
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// The protocol version this server speaks. A peer announcing a version it does
/// not recognise is refused rather than guessed at.
pub const LINK_PROTOCOL: &str = "1";

/// Longest a link handshake may take. A peer that opens the connection and then
/// says nothing holds a socket, and unlike a client it is not counted against
/// any connection limit.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Longest line accepted from a peer. Server messages carry more than client
/// ones — a burst line names every member of a channel — so the client limit
/// does not apply, but it still has an end.
const MAX_LINK_LINE: usize = 16384;

/// How often each side asks the other whether it is still there.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether a string can be a SID: a digit, then two alphanumerics.
///
/// The shape is not decoration. A user's id is its server's SID followed by six
/// characters, so a fixed-width SID is what lets any server tell which server a
/// user is on by looking at the first three characters of its id.
pub fn valid_sid(sid: &str) -> bool {
    let b = sid.as_bytes();
    b.len() == 3
        && b[0].is_ascii_digit()
        && b[1].is_ascii_alphanumeric()
        && b[2].is_ascii_alphanumeric()
        && sid.chars().all(|c| !c.is_ascii_lowercase())
}

/// The SID to use when the configuration does not give one.
///
/// Derived from the server name so that it is at least stable across restarts.
/// It is a hash, so two servers can land on the same one; linking without
/// setting `sid` explicitly is a coin toss, and the server says so at startup.
pub fn derive_sid(server_name: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in server_name.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    let digit = (hash % 10) as u8;
    let second = ALPHABET[((hash >> 8) % ALPHABET.len() as u64) as usize];
    let third = ALPHABET[((hash >> 16) % ALPHABET.len() as u64) as usize];
    format!("{}{}{}", digit, second as char, third as char)
}

/// This server's SID: the configured one, or one derived from its name.
pub fn our_sid(cfg: &Config) -> String {
    match cfg.server.sid.as_deref() {
        Some(sid) if valid_sid(sid) => sid.to_string(),
        Some(bad) => {
            warn!(
                sid = %bad,
                "Configured sid is not a digit followed by two alphanumerics; using a derived one"
            );
            derive_sid(&cfg.server.name)
        }
        None => derive_sid(&cfg.server.name),
    }
}

/// The next user id for this server: its SID and six characters.
///
/// A user is named by this id everywhere it matters — in the client table, in
/// channel membership, and (once users cross links) on other servers. Deriving
/// it from the SID is what lets any server tell which server a user is on by
/// looking at the first three characters, and what keeps two servers from ever
/// choosing the same id for two different people.
pub fn next_uid(sid: &str, counter: &std::sync::atomic::AtomicU64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tail = [b'A'; 6];
    // Least significant first, so consecutive ids differ in the last character
    // and a log reads in the order the users arrived.
    for slot in tail.iter_mut().rev() {
        *slot = ALPHABET[(n % ALPHABET.len() as u64) as usize];
        n /= ALPHABET.len() as u64;
    }
    let mut uid = String::with_capacity(9);
    uid.push_str(sid);
    uid.push_str(std::str::from_utf8(&tail).unwrap_or("AAAAAA"));
    uid
}

/// Whether a string looks like a user id this network would have issued.
pub fn valid_uid(uid: &str) -> bool {
    uid.len() == 9
        && valid_sid(&uid[..3])
        && uid[3..]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// What a peer said about itself during the handshake.
#[derive(Debug, Clone)]
pub struct LinkGreeting {
    pub name: String,
    pub sid: String,
    pub description: String,
    pub protocol: String,
    pub capab: Vec<String>,
}

/// Why a handshake did not produce a link.
#[derive(Debug)]
pub enum LinkError {
    /// The peer said something before it had authenticated.
    OutOfOrder(String),
    /// The password was not the one this link expects.
    BadPassword,
    /// The peer is not the server this link was configured for.
    WrongPeer { expected: String, got: String },
    /// A protocol version this server does not speak.
    Unsupported(String),
    /// The connection went away, or would not say anything.
    Io(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::OutOfOrder(cmd) => write!(f, "{} before the link was authenticated", cmd),
            LinkError::BadPassword => write!(f, "password mismatch"),
            LinkError::WrongPeer { expected, got } => {
                write!(f, "expected {}, got {}", expected, got)
            }
            LinkError::Unsupported(v) => write!(f, "unsupported protocol version {}", v),
            LinkError::Io(e) => write!(f, "{}", e),
        }
    }
}

/// Where the password goes in the first line of a greeting.
const PASSWORD_SLOT: &str = "\u{0}password\u{0}";

/// The three lines a server sends to introduce itself, with the password left
/// to be filled in: which one to send depends on which link this turns out to
/// be, and that is not known until the peer has named itself.
pub fn greeting_lines(cfg: &Config) -> Vec<String> {
    let sid = our_sid(cfg);
    vec![
        format!("PASS {} TS {} {}", PASSWORD_SLOT, LINK_PROTOCOL, sid),
        "CAPAB :TAGS MSGID ACCOUNT CHATHISTORY METADATA".to_string(),
        format!("SERVER {} 1 :{}", cfg.server.name, cfg.server.description),
    ]
}

/// What a handshake needs from the configuration, taken before any network I/O.
struct Introduction {
    greeting: Vec<String>,
    links: Vec<LinkConfig>,
}

/// Write a greeting, putting the password in place.
async fn send_lines<W>(writer: &mut W, lines: &[String], password: &str) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    for line in lines {
        writer
            .write_all(line.replace(PASSWORD_SLOT, password).as_bytes())
            .await?;
        writer.write_all(b"\r\n").await?;
    }
    writer.flush().await
}

/// Read a peer's introduction: PASS, then anything it wants to say about its
/// capabilities, then SERVER. Nothing else is accepted before SERVER, because
/// nothing else has been authenticated yet.
pub fn read_greeting(lines: &[String], expected_password: &str) -> Result<LinkGreeting, LinkError> {
    let mut password: Option<String> = None;
    let mut protocol: Option<String> = None;
    let mut sid: Option<String> = None;
    let mut capab: Vec<String> = Vec::new();

    for line in lines {
        let msg = match parse_message_with_limit(line, MAX_LINK_LINE) {
            Ok(m) => m,
            Err(_) => return Err(LinkError::OutOfOrder("a line that is not a message".into())),
        };
        match msg.command.as_str() {
            "PASS" => {
                // PASS <password> TS <version> <sid>
                password = msg.params.first().cloned();
                protocol = msg.params.get(2).cloned();
                sid = msg.params.get(3).cloned();
            }
            "CAPAB" => {
                capab = msg
                    .params
                    .last()
                    .map(|p| p.split_whitespace().map(String::from).collect())
                    .unwrap_or_default();
            }
            "SERVER" => {
                let Some(given) = password.as_deref() else {
                    return Err(LinkError::OutOfOrder("SERVER".into()));
                };
                if !bool::from(<[u8] as subtle::ConstantTimeEq>::ct_eq(
                    given.as_bytes(),
                    expected_password.as_bytes(),
                )) {
                    return Err(LinkError::BadPassword);
                }
                let protocol = protocol.unwrap_or_default();
                if protocol != LINK_PROTOCOL {
                    return Err(LinkError::Unsupported(protocol));
                }
                let Some(sid) = sid.filter(|s| valid_sid(s)) else {
                    return Err(LinkError::OutOfOrder("PASS without a usable sid".into()));
                };
                let name = msg.params.first().cloned().unwrap_or_default();
                if name.is_empty() {
                    return Err(LinkError::OutOfOrder("SERVER without a name".into()));
                }
                return Ok(LinkGreeting {
                    name,
                    sid,
                    description: msg.params.get(2).cloned().unwrap_or_default(),
                    protocol,
                    capab,
                });
            }
            other => return Err(LinkError::OutOfOrder(other.to_string())),
        }
    }
    Err(LinkError::Io("the peer stopped before SERVER".into()))
}

/// Everything a link needs from the rest of the server.
///
/// A link is not a client: it reads and writes the same tables every command
/// handler does, and it does so on its own task for as long as the link is up.
/// Carrying them together keeps the shape of a link's signature from growing
/// every time it learns to relay something new.
#[derive(Clone)]
pub struct LinkContext {
    pub cfg: Arc<RwLock<Config>>,
    pub state: Arc<RwLock<ServerState>>,
    pub channels: Arc<RwLock<ChannelStore>>,
    pub senders: Senders,
    pub links: Arc<RwLock<LinkRegistry>>,
}

/// One server on the network, as this one knows it.
#[derive(Debug, Clone)]
pub struct RemoteServer {
    pub name: String,
    pub sid: String,
    pub description: String,
    /// How many links away. 1 is directly attached.
    pub hops: u32,
    /// The SID of the directly-attached server this one is behind, or None when
    /// it is the direct peer.
    pub behind: Option<String>,
}

/// Everything this server knows about its links.
#[derive(Debug, Default)]
pub struct LinkRegistry {
    /// Servers on the network other than this one, by SID.
    servers: std::collections::HashMap<String, RemoteServer>,
    /// Outbound queues to directly-attached servers, by SID.
    peers: std::collections::HashMap<String, tokio::sync::mpsc::Sender<Message>>,
}

impl LinkRegistry {
    /// Record a directly-attached server and the queue to reach it.
    pub fn attach(&mut self, server: RemoteServer, tx: tokio::sync::mpsc::Sender<Message>) {
        self.peers.insert(server.sid.clone(), tx);
        self.servers.insert(server.sid.clone(), server);
    }

    /// Record a server the peer told us about.
    pub fn introduce(&mut self, server: RemoteServer) {
        self.servers.insert(server.sid.clone(), server);
    }

    /// Forget a directly-attached server and everything behind it. Returns the
    /// servers that went, so their users can be quit.
    pub fn detach(&mut self, sid: &str) -> Vec<RemoteServer> {
        self.peers.remove(sid);
        let mut gone: Vec<RemoteServer> = Vec::new();
        if let Some(server) = self.servers.remove(sid) {
            gone.push(server);
        }
        // Anything that was reachable through it is gone too.
        let behind: Vec<String> = self
            .servers
            .values()
            .filter(|s| s.behind.as_deref() == Some(sid))
            .map(|s| s.sid.clone())
            .collect();
        for sid in behind {
            if let Some(server) = self.servers.remove(&sid) {
                gone.push(server);
            }
        }
        gone
    }

    pub fn is_linked(&self, sid: &str) -> bool {
        self.servers.contains_key(sid)
    }

    pub fn by_name(&self, name: &str) -> Option<&RemoteServer> {
        self.servers
            .values()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn all(&self) -> impl Iterator<Item = &RemoteServer> {
        self.servers.values()
    }

    pub fn count(&self) -> usize {
        self.servers.len()
    }

    /// Send to every directly-attached server except one — the rule for
    /// relaying anything that came in over a link.
    pub fn relay(&self, msg: &Message, except: Option<&str>) {
        for (sid, tx) in &self.peers {
            if Some(sid.as_str()) == except {
                continue;
            }
            let _ = tx.try_send(msg.clone());
        }
    }

    /// Whether a given peer is the one that carries a server: either it is that
    /// server, or that server was introduced from behind it.
    ///
    /// A link only speaks for what it carries. Without this a peer could
    /// announce users for a server on the far side of the network, and they
    /// would still be here after that link dropped, because nothing that went
    /// with it would name them.
    pub fn carried_by(&self, sid: &str, peer: &str) -> bool {
        if sid == peer {
            return true;
        }
        self.servers
            .get(sid)
            .and_then(|s| s.behind.as_deref())
            .is_some_and(|behind| behind == peer)
    }

    /// The queue that reaches a given server: its own if it is attached here,
    /// otherwise the queue of the peer it sits behind.
    pub fn route(&self, sid: &str) -> Option<&tokio::sync::mpsc::Sender<Message>> {
        if let Some(tx) = self.peers.get(sid) {
            return Some(tx);
        }
        let behind = self.servers.get(sid)?.behind.as_deref()?;
        self.peers.get(behind)
    }
}

/// Accept a link on the server port: read the greeting, check it against a
/// configured link, and hand back which one it was.
pub async fn accept_greeting<S>(
    stream: &mut BufReader<S>,
    configured: &[LinkConfig],
) -> Result<(LinkGreeting, LinkConfig), LinkError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        let read = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_line(&mut line))
            .await
            .map_err(|_| LinkError::Io("the peer did not finish its greeting".into()))?
            .map_err(|e| LinkError::Io(e.to_string()))?;
        if read == 0 {
            return Err(LinkError::Io("the peer closed the link".into()));
        }
        if line.len() > MAX_LINK_LINE {
            return Err(LinkError::Io("greeting line too long".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            continue;
        }
        let is_server = trimmed.split(' ').next() == Some("SERVER");
        lines.push(trimmed);
        if is_server {
            break;
        }
        if lines.len() > 8 {
            return Err(LinkError::OutOfOrder("too much before SERVER".into()));
        }
    }

    // The name is in the SERVER line, and the password is checked against the
    // link configured for that name — so an unknown server cannot make the
    // server try every password it holds.
    let name = lines
        .last()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or_default()
        .to_string();
    let Some(link) = configured
        .iter()
        .find(|l| l.name.eq_ignore_ascii_case(&name))
        .cloned()
    else {
        return Err(LinkError::WrongPeer {
            expected: "a configured link".into(),
            got: name,
        });
    };

    let greeting = read_greeting(&lines, &link.receive_password)?;
    if !greeting.sid.eq_ignore_ascii_case(&link.sid) {
        return Err(LinkError::WrongPeer {
            expected: link.sid.clone(),
            got: greeting.sid,
        });
    }
    Ok((greeting, link))
}

/// Read the answer to a greeting this server sent.
pub async fn read_answer<S>(
    stream: &mut BufReader<S>,
    link: &LinkConfig,
) -> Result<LinkGreeting, LinkError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        let read = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_line(&mut line))
            .await
            .map_err(|_| LinkError::Io("the peer did not answer".into()))?
            .map_err(|e| LinkError::Io(e.to_string()))?;
        if read == 0 {
            return Err(LinkError::Io("the peer closed the link".into()));
        }
        if line.len() > MAX_LINK_LINE {
            return Err(LinkError::Io("greeting line too long".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("ERROR") {
            return Err(LinkError::Io(trimmed));
        }
        let is_server = trimmed.split(' ').next() == Some("SERVER");
        lines.push(trimmed);
        if is_server {
            break;
        }
        if lines.len() > 8 {
            return Err(LinkError::OutOfOrder("too much before SERVER".into()));
        }
    }
    let greeting = read_greeting(&lines, &link.receive_password)?;
    if !greeting.name.eq_ignore_ascii_case(&link.name) {
        return Err(LinkError::WrongPeer {
            expected: link.name.clone(),
            got: greeting.name,
        });
    }
    if !greeting.sid.eq_ignore_ascii_case(&link.sid) {
        return Err(LinkError::WrongPeer {
            expected: link.sid.clone(),
            got: greeting.sid,
        });
    }
    Ok(greeting)
}

/// Run one accepted link connection.
///
/// Stage one: the handshake, the registry entry, and the keepalive that notices
/// when the peer goes away. Bursting users and channels comes next; a link that
/// carries nothing is still a link, and getting the handshake and the split
/// handling right first is what makes the rest safe to add.
pub async fn serve_link<S>(
    stream: S,
    peer_addr: String,
    ctx: LinkContext,
    // Set when this server dialled out: which link it was, so the answer can
    // be checked against the server it meant to reach.
    expect: Option<LinkConfig>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Everything the handshake needs, taken now. A handshake is network I/O
    // with a stranger at the other end of it: holding the configuration lock
    // for its duration would let an unauthenticated peer stall a REHASH, and
    // through it every command handler waiting to read the configuration.
    let intro = {
        let cfg = ctx.cfg.read().await;
        Introduction {
            greeting: greeting_lines(&cfg),
            links: cfg.links.clone(),
        }
    };

    let (greeting, link) = if let Some(expect) = expect {
        // Outbound: we greeted first, so this is the answer, and it has to come
        // from the server we dialled.
        if let Err(e) = send_lines(&mut writer, &intro.greeting, &expect.send_password).await {
            warn!(peer = %expect.name, "Could not greet: {}", e);
            return;
        }
        match read_answer(&mut reader, &expect).await {
            Ok(greeting) => (greeting, expect),
            Err(e) => {
                warn!(peer = %expect.name, "Link refused: {}", e);
                return;
            }
        }
    } else {
        match accept_greeting(&mut reader, &intro.links).await {
            Ok((greeting, link)) => {
                if let Err(e) = send_lines(&mut writer, &intro.greeting, &link.send_password).await
                {
                    warn!(peer = %greeting.name, "Could not answer the greeting: {}", e);
                    return;
                }
                (greeting, link)
            }
            Err(e) => {
                warn!(peer = %peer_addr, "Refusing link: {}", e);
                let _ = writer
                    .write_all(format!("ERROR :Closing link: {}\r\n", e).as_bytes())
                    .await;
                return;
            }
        }
    };

    if ctx.links.read().await.is_linked(&greeting.sid) {
        warn!(
            peer = %greeting.name,
            sid = %greeting.sid,
            "Refusing link: that server is already on the network"
        );
        let _ = writer
            .write_all(b"ERROR :Closing link: already linked\r\n")
            .await;
        return;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(4096);
    let remote = RemoteServer {
        name: greeting.name.clone(),
        sid: greeting.sid.clone(),
        description: greeting.description.clone(),
        hops: 1,
        behind: None,
    };
    ctx.links.write().await.attach(remote, tx.clone());
    info!(
        peer = %greeting.name,
        sid = %greeting.sid,
        configured = %link.name,
        capab = ?greeting.capab,
        "Linked"
    );

    // A link that has gone quiet is not obviously different from one with
    // nothing to say, so each side asks.
    let ping_tx = tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut token: u64 = 0;
        loop {
            tokio::time::sleep(KEEPALIVE_INTERVAL).await;
            token += 1;
            if ping_tx
                .send(Message::new("PING", vec![format!("{}", token)]))
                .await
                .is_err()
            {
                return;
            }
        }
    });

    // Anything queued for the peer goes out on its own task, so reading from it
    // is never held up by writing to it.
    let peer_name = greeting.name.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let line = crate::protocol::format_message(&msg);
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });

    // Everything we know goes out on its own task. Both sides burst at once,
    // and a burst big enough to fill the queue would otherwise stop this server
    // reading from the peer — while the peer, doing the same, waits for it.
    let burst_task = {
        let ctx = ctx.clone();
        let tx = tx.clone();
        let peer_sid = greeting.sid.clone();
        let our_sid = ctx.state.read().await.sid.clone();
        tokio::spawn(async move { send_burst(&ctx, &our_sid, &peer_sid, &tx).await })
    };

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                error!(peer = %peer_name, "Link read error: {}", e);
                break;
            }
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        match parse_message_with_limit(trimmed, MAX_LINK_LINE) {
            Ok(msg) => {
                if handle_link_message(&ctx, &msg, &greeting.sid, &tx)
                    .await
                    .is_break()
                {
                    break;
                }
            }
            Err(e) => {
                warn!(peer = %peer_name, "Unparseable line from a linked server: {}", e);
            }
        }
    }

    burst_task.abort();
    ping_task.abort();
    writer_task.abort();
    let gone = ctx.links.write().await.detach(&greeting.sid);
    for server in &gone {
        warn!(server = %server.name, "Netsplit: server is gone");
    }
    split_users(&ctx, &gone).await;
}

/// The users behind a link that dropped. They quit, because from here that is
/// what has happened to them.
async fn split_users(ctx: &LinkContext, gone: &[RemoteServer]) {
    if gone.is_empty() {
        return;
    }
    let sids: std::collections::HashSet<&str> = gone.iter().map(|s| s.sid.as_str()).collect();
    let lost: Vec<String> = {
        let state = ctx.state.read().await;
        state
            .users()
            .map(|(id, _)| id.clone())
            .filter(|id| owning_sid(id).is_some_and(|sid| sids.contains(sid)))
            .collect()
    };
    if lost.is_empty() {
        return;
    }
    info!(users = lost.len(), "Netsplit: forgetting users behind the split");
    // What everybody left behind sees is a room emptying: the reason names the
    // two servers that stopped being able to reach each other, which is the
    // convention every client already knows how to read.
    let ours = ctx.cfg.read().await.server.name.clone();
    for server in gone {
        let reason = format!("{} {}", ours, server.name);
        for uid in lost.iter().filter(|id| owning_sid(id) == Some(&server.sid)) {
            forget_remote_user(ctx, uid, &reason).await;
        }
    }
}

/// The server a user id belongs to: the first three characters of it.
fn owning_sid(uid: &str) -> Option<&str> {
    if valid_uid(uid) {
        Some(&uid[..3])
    } else {
        None
    }
}

/// How a user is announced to the rest of the network.
fn uid_message(sid: &str, c: &crate::user::Client) -> Message {
    Message::new(
        "UID",
        vec![
            c.nick.clone().unwrap_or_else(|| c.id.clone()),
            "1".to_string(),
            c.nick_ts.to_string(),
            c.display_user().to_string(),
            c.display_host().to_string(),
            c.id.clone(),
            c.account.clone().unwrap_or_else(|| "*".to_string()),
            c.realname.clone().unwrap_or_default(),
        ],
    )
    .with_prefix(sid)
}

/// Everything this server knows, sent as soon as a link is up.
///
/// Both sides burst at once and neither waits for the other: `EOB` says a side
/// has finished sending, not that it has finished receiving, and the state each
/// ends up with is the union of the two.
async fn send_burst(
    ctx: &LinkContext,
    our_sid: &str,
    peer_sid: &str,
    tx: &tokio::sync::mpsc::Sender<Message>,
) {
    // The servers we carry, so the peer learns the shape of the network beyond
    // us. The peer itself is not one of them.
    let servers: Vec<RemoteServer> = ctx
        .links
        .read()
        .await
        .all()
        .filter(|s| s.sid != peer_sid)
        .cloned()
        .collect();
    for server in servers {
        let _ = tx
            .send(
                Message::new(
                    "SERVER",
                    vec![
                        server.name.clone(),
                        (server.hops + 1).to_string(),
                        server.sid.clone(),
                        server.description.clone(),
                    ],
                )
                .with_prefix(our_sid),
            )
            .await;
    }

    // Every user, named by the server it is really on rather than by whoever
    // passed it along — and never back to the peer that told us about it.
    let users: Vec<Arc<RwLock<crate::user::Client>>> = {
        let state = ctx.state.read().await;
        state.users().map(|(_, c)| c.clone()).collect()
    };
    for user in users {
        let guard = user.read().await;
        if !guard.registered || guard.nick.is_none() {
            continue;
        }
        let origin = owning_sid(&guard.id).unwrap_or(our_sid);
        if origin == peer_sid {
            continue;
        }
        let _ = tx.send(uid_message(origin, &guard)).await;
    }

    // Every channel: who is in it and what they hold, then its topic and its
    // lists. A channel with nobody in it does not exist to burst.
    let channels: Vec<String> = ctx.channels.read().await.channels.keys().cloned().collect();
    for name in channels {
        let store = ctx.channels.read().await;
        let Some(channel) = store.channels.get(&name) else {
            continue;
        };
        let ch = channel.read().await;
        if ch.members.is_empty() {
            continue;
        }
        let (letters, mode_args) = ch.mode_string();
        let members = ch
            .members
            .iter()
            .map(|(id, m)| format!("{}{}", m.modes.prefixes_ordered(), id))
            .collect::<Vec<_>>()
            .join(" ");
        let mut params = vec![ch.created_at.to_string(), ch.name.clone(), letters];
        params.extend(mode_args);
        params.push(members);
        let sjoin = Message::new("SJOIN", params).with_prefix(our_sid);

        let topic = ch.topic.as_ref().map(|t| {
            Message::new(
                "TB",
                vec![
                    ch.name.clone(),
                    ch.topic_time.unwrap_or(ch.created_at).to_string(),
                    ch.topic_setter.clone().unwrap_or_else(|| "*".to_string()),
                    t.clone(),
                ],
            )
            .with_prefix(our_sid)
        });
        let lists: Vec<Message> = ['b', 'e', 'I', 'q']
            .into_iter()
            .filter_map(|letter| {
                let masks = ch.list_of(letter)?;
                if masks.is_empty() {
                    return None;
                }
                Some(
                    Message::new(
                        "BMASK",
                        vec![
                            ch.created_at.to_string(),
                            ch.name.clone(),
                            letter.to_string(),
                            masks.join(" "),
                        ],
                    )
                    .with_prefix(our_sid),
                )
            })
            .collect();
        drop(ch);
        drop(store);

        let _ = tx.send(sjoin).await;
        if let Some(topic) = topic {
            let _ = tx.send(topic).await;
        }
        for list in lists {
            let _ = tx.send(list).await;
        }
    }

    let _ = tx
        .send(Message::new("EOB", vec![]).with_prefix(our_sid))
        .await;
}

/// Tell the local watchers of a nick that it came online or went offline.
async fn monitor_notify(ctx: &LinkContext, nick: &str, online: bool, source: &str) {
    let watchers: Vec<String> = {
        let state = ctx.state.read().await;
        match state.monitor_watchers.watchers(&crate::casefold::lower(nick)) {
            Some(set) => set.iter().cloned().collect(),
            None => Vec::new(),
        }
    };
    if watchers.is_empty() {
        return;
    }
    let server = ctx.cfg.read().await.server.name.clone();
    let state = ctx.state.read().await;
    let registry = ctx.senders.read().await;
    let code = if online { "730" } else { "731" };
    let subject = if online { source } else { nick };
    for watcher in watchers {
        let watcher_nick = match state.clients.get(&watcher) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => continue,
        };
        registry.deliver(
            &watcher,
            &Message::new(code, vec![watcher_nick, subject.to_string()]).with_prefix(&server),
        );
    }
}

/// A user arrived from another server. It goes in the same tables as a local
/// one — a nick is a nick wherever it is held — with no connection behind it.
async fn accept_remote_user(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(nick), Some(nick_ts), Some(user), Some(host), Some(uid)) = (
        msg.params.first(),
        msg.params.get(2),
        msg.params.get(3),
        msg.params.get(4),
        msg.params.get(5),
    ) else {
        warn!(peer = %peer_sid, "Malformed UID from a linked server");
        return;
    };
    if !valid_uid(uid) {
        warn!(peer = %peer_sid, uid = %uid, "Refusing a user with an unusable id");
        return;
    }
    if ctx.state.read().await.clients.contains_key(uid) {
        // Already known. A burst and an announcement of the same user can cross
        // on a link that came up while somebody was registering, and the second
        // one to arrive is not a new person.
        return;
    }
    let account = msg.params.get(6).filter(|a| a.as_str() != "*").cloned();
    let realname = msg.params.get(7).cloned().unwrap_or_default();
    let origin = msg.prefix.clone().unwrap_or_else(|| peer_sid.to_string());
    if origin != uid[..3] {
        warn!(peer = %peer_sid, uid = %uid, origin = %origin, "A user's id does not match the server introducing it");
        return;
    }
    let server_name = {
        let links = ctx.links.read().await;
        if !links.carried_by(&origin, peer_sid) {
            warn!(peer = %peer_sid, origin = %origin, "Refusing a user for a server this link does not carry");
            return;
        }
        let named = links.all().find(|s| s.sid == origin).map(|s| s.name.clone());
        named.unwrap_or_else(|| origin.clone())
    };

    let mut client = crate::user::Client::new(uid.clone(), host.clone());
    client.nick = Some(nick.clone());
    client.user = Some(user.clone());
    client.realname = Some(realname);
    client.registered = true;
    client.account = account;
    client.nick_ts = nick_ts
        .parse()
        .unwrap_or_else(|_| chrono::Utc::now().timestamp());
    client.signon_at = client.nick_ts;
    client.server = Some(server_name);
    // Nothing on this server reads for it, so it has no connections.
    client.sessions.clear();
    let source = client.source().unwrap_or_else(|| nick.clone());

    let holder = ctx
        .state
        .read()
        .await
        .nick_to_id
        .get(&crate::casefold::upper(nick))
        .cloned();
    if let Some(holder) = holder {
        if holder != *uid {
            resolve_nick_collision(ctx, &holder, uid, nick, client.nick_ts).await;
        }
    }

    let kept_nick = {
        let mut state = ctx.state.write().await;
        let kept = !state.nick_to_id.contains_key(&crate::casefold::upper(nick));
        if !kept {
            // The collision was settled against the arriving user: it answers to
            // its own id until it picks another name.
            client.nick = Some(uid.clone());
        }
        state.add_remote_user(client).await;
        kept
    };
    // Nobody is watching for a user that arrived under its own id, and telling
    // them the nick came online when somebody else is holding it would be a lie.
    if kept_nick {
        monitor_notify(ctx, nick, true, &source).await;
    }
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// Two users hold one nick. The older claim keeps it; the newer is renamed to
/// its own id, and told so if it is ours.
///
/// Both servers run this on their own copy of the same two timestamps, so they
/// reach the same answer without having to agree on one first.
async fn resolve_nick_collision(
    ctx: &LinkContext,
    holder_id: &str,
    arriving_id: &str,
    nick: &str,
    arriving_ts: i64,
) {
    let holder_ts = {
        let state = ctx.state.read().await;
        match state.clients.get(holder_id) {
            Some(c) => c.read().await.nick_ts,
            None => return,
        }
    };
    if holder_ts <= arriving_ts {
        // The one already here is older and keeps the nick. The caller finds it
        // still taken and renames the arriving user.
        warn!(nick = %nick, kept = %holder_id, renamed = %arriving_id, "Nick collision");
        return;
    }
    warn!(nick = %nick, kept = %arriving_id, renamed = %holder_id, "Nick collision");
    let (source, is_local) = {
        let state = ctx.state.read().await;
        match state.clients.get(holder_id) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.source().unwrap_or_else(|| nick.to_string()),
                    g.server.is_none(),
                )
            }
            None => return,
        }
    };
    {
        let mut state = ctx.state.write().await;
        state.nick_to_id.remove(&crate::casefold::upper(nick));
        if let Some(c) = state.clients.get(holder_id) {
            c.write().await.nick = Some(holder_id.to_string());
        }
        state
            .nick_to_id
            .insert(crate::casefold::upper(holder_id), holder_id.to_string());
    }
    if is_local {
        ctx.senders.read().await.deliver(
            holder_id,
            &Message::new("NICK", vec![holder_id.to_string()]).with_prefix(&source),
        );
        // The rest of the network hears about our user's rename from us.
        let ts = chrono::Utc::now().timestamp();
        ctx.links.read().await.relay(
            &Message::new("NICK", vec![holder_id.to_string(), ts.to_string()])
                .with_prefix(holder_id),
            None,
        );
    }
}

/// A user changed its nick on another server.
async fn accept_remote_nick(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(new_nick)) = (msg.prefix.as_ref(), msg.params.first()) else {
        return;
    };
    let ts = msg
        .params
        .get(1)
        .and_then(|t| t.parse::<i64>().ok())
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let old = {
        let state = ctx.state.read().await;
        match state.clients.get(uid) {
            Some(c) => c.read().await.nick.clone(),
            None => {
                warn!(peer = %peer_sid, uid = %uid, "NICK for a user we do not know");
                return;
            }
        }
    };
    {
        let mut state = ctx.state.write().await;
        if let Some(ref o) = old {
            state.nick_to_id.remove(&crate::casefold::upper(o));
        }
        if let Some(c) = state.clients.get(uid) {
            let mut g = c.write().await;
            g.nick = Some(new_nick.clone());
            g.nick_ts = ts;
        }
        state
            .nick_to_id
            .insert(crate::casefold::upper(new_nick), uid.clone());
    }
    if let Some(o) = old {
        monitor_notify(ctx, &o, false, &o).await;
    }
    monitor_notify(ctx, new_nick, true, new_nick).await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// Take a user off this server altogether: out of every channel it was in, out
/// of the client tables, and out of the watch lists — telling the people who
/// shared a channel with it, because from here it has quit.
///
/// One place for it, because a user leaves in three ways — it quits, it is
/// killed, or the link it was behind drops — and a user left in a channel it
/// cannot be reached in is a member nobody can kick.
async fn forget_remote_user(ctx: &LinkContext, uid: &str, reason: &str) {
    let (source, channels, nick) = {
        let state = ctx.state.read().await;
        match state.clients.get(uid) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                    g.channels.keys().cloned().collect::<Vec<_>>(),
                    g.nick.clone(),
                )
            }
            None => return,
        }
    };
    let quit = Message::new("QUIT", vec![reason.to_string()]).with_prefix(&source);
    for key in &channels {
        let members = members_of(ctx, key).await;
        to_members(ctx, &members, &quit, Some(uid)).await;
        unseat_member(ctx, key, uid).await;
    }
    ctx.state.write().await.remove_client(uid).await;
    if let Some(nick) = nick {
        monitor_notify(ctx, &nick, false, &nick).await;
    }
}

/// A user on another server left the network.
async fn accept_remote_quit(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let Some(uid) = msg.prefix.clone() else {
        return;
    };
    let reason = msg.params.first().cloned().unwrap_or_else(|| "Quit".to_string());
    forget_remote_user(ctx, &uid, &reason).await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A message from a user on another server. Ours to deliver if it is addressed
/// to one of our users, otherwise ours to pass along.
async fn accept_remote_message(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(from), Some(target)) = (msg.prefix.clone(), msg.params.first().cloned()) else {
        return;
    };
    if target.starts_with('#') || target.starts_with('&') {
        accept_remote_channel_message(ctx, msg, &from, &target, peer_sid).await;
        return;
    }
    let Some(target_sid) = owning_sid(&target) else {
        return;
    };
    let our_sid = ctx.state.read().await.sid.clone();
    if target_sid != our_sid {
        // The server that holds the target is the one that delivers it.
        if let Some(tx) = ctx.links.read().await.route(target_sid) {
            let _ = tx.try_send(msg.clone());
        }
        return;
    }
    let (source, sender_account, sender_tags) = {
        let state = ctx.state.read().await;
        match state.clients.get(&from) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                    g.account.clone(),
                    crate::protocol::SenderTags::new(g.bot, g.oper_name.clone()),
                )
            }
            None => {
                warn!(peer = %peer_sid, from = %from, "Message from a user we do not know");
                return;
            }
        }
    };
    let (target_nick, target_caps) = {
        let state = ctx.state.read().await;
        match state.clients.get(&target) {
            Some(c) => {
                let g = c.read().await;
                (g.nick_or_id().to_string(), g.capabilities.clone())
            }
            None => return,
        }
    };

    // The recipient sees a message from a person, not from a user id, addressed
    // to the name they answer to here.
    let source_line = source.clone();
    let mut out = msg.clone();
    out.prefix = Some(source);
    out.params[0] = target_nick;
    // The msgid and the time came with it and are kept; everything else about
    // how the message looks is decided here, against what this recipient
    // negotiated with this server.
    let msgid = out.tags.get("msgid").cloned().flatten();
    let client_tag_deny = ctx.cfg.read().await.server.client_tag_deny.clone();
    let client_only: std::collections::HashMap<String, Option<String>> = out
        .tags
        .iter()
        .filter(|(k, _)| k.starts_with('+'))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let out = crate::protocol::add_tags_for_recipient(
        out,
        &target_caps,
        sender_account.as_deref(),
        msgid.as_deref(),
        Some(&client_only),
        client_tag_deny.as_deref(),
        &sender_tags,
    );
    ctx.senders.read().await.deliver(&target, &out);

    // Both ends of a conversation keep it, so the person who was written to can
    // ask their own server what was said without it having to ask the other.
    if msg.command == "PRIVMSG" {
        let (from_id, to_id) = {
            let state = ctx.state.read().await;
            (
                conversation_identity(&state, &from).await,
                conversation_identity(&state, &target).await,
            )
        };
        if let (Some(a), Some(b)) = (from_id, to_id) {
            let key = crate::persist::direct_message_key(&a, &b);
            let text = msg.params.get(1).cloned().unwrap_or_default();
            let at = out
                .tags
                .get("time")
                .cloned()
                .flatten()
                .unwrap_or_else(crate::protocol::server_time_now);
            let cfg = ctx.cfg.read().await;
            cfg.record_history_at(&key, &source_line, &text, msgid.as_deref(), "PRIVMSG", &at);
        }
    }
}

/// What a conversation with somebody is filed under: their account when they
/// have one, and their nick when they do not. It has to be worked out the same
/// way on both servers, or each would keep half a conversation.
async fn conversation_identity(state: &ServerState, uid: &str) -> Option<String> {
    let c = state.clients.get(uid)?;
    let g = c.read().await;
    Some(match g.account {
        Some(ref a) => crate::persist::account_id(a),
        None => crate::persist::nick_id(g.nick_or_id()),
    })
}

/// A message to a channel, from somebody on another server. Every server that
/// holds a member of the channel delivers to its own, so the message is written
/// once here for each person reading here.
async fn accept_remote_channel_message(
    ctx: &LinkContext,
    msg: &Message,
    from: &str,
    target: &str,
    peer_sid: &str,
) {
    let key = crate::channel::canonical_channel_key(target);
    let members = members_of(ctx, &key).await;
    // Passed along either way: a server between two others carries a channel it
    // may have nobody in.
    ctx.links.read().await.relay(msg, Some(peer_sid));
    if members.is_empty() {
        return;
    }
    let (source, sender_account, sender_tags) = {
        let state = ctx.state.read().await;
        match state.clients.get(from) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                    g.account.clone(),
                    crate::protocol::SenderTags::new(g.bot, g.oper_name.clone()),
                )
            }
            None => {
                warn!(peer = %peer_sid, from = %from, "Channel message from a user we do not know");
                return;
            }
        }
    };
    let mut base = msg.clone();
    base.prefix = Some(source.clone());
    let msgid = base.tags.get("msgid").cloned().flatten();
    let sent_at = base.tags.get("time").cloned().flatten();
    let client_only: std::collections::HashMap<String, Option<String>> = base
        .tags
        .iter()
        .filter(|(k, _)| k.starts_with('+'))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let client_tag_deny = ctx.cfg.read().await.server.client_tag_deny.clone();

    for member in &members {
        // A member on another server reads it from theirs.
        let caps = {
            let state = ctx.state.read().await;
            match state.clients.get(member) {
                Some(c) => {
                    let g = c.read().await;
                    if g.server.is_some() {
                        continue;
                    }
                    g.capabilities.clone()
                }
                None => continue,
            }
        };
        let out = crate::protocol::add_tags_for_recipient(
            base.clone(),
            &caps,
            sender_account.as_deref(),
            msgid.as_deref(),
            Some(&client_only),
            client_tag_deny.as_deref(),
            &sender_tags,
        );
        ctx.senders.read().await.deliver(member, &out);
    }

    // Kept here too, so chathistory on this server can answer for a
    // conversation that happened on another.
    if msg.command == "PRIVMSG" || msg.command == "NOTICE" {
        let text = msg.params.get(1).cloned().unwrap_or_default();
        let cfg = ctx.cfg.read().await;
        let at = sent_at.unwrap_or_else(crate::protocol::server_time_now);
        cfg.record_history_at(&key, &source, &text, msgid.as_deref(), &msg.command, &at);
    }
}

/// An operator on another server killed one of our users.
async fn accept_remote_kill(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(from), Some(target)) = (msg.prefix.clone(), msg.params.first().cloned()) else {
        return;
    };
    let reason = msg.params.get(1).cloned().unwrap_or_default();
    let Some(target_sid) = owning_sid(&target) else {
        return;
    };
    let our_sid = ctx.state.read().await.sid.clone();
    if target_sid != our_sid {
        // Not ours to carry out; the server that holds them does it.
        if let Some(tx) = ctx.links.read().await.route(target_sid) {
            let _ = tx.try_send(msg.clone());
        }
        return;
    }
    let killer = {
        let state = ctx.state.read().await;
        match state.clients.get(&from) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => from.clone(),
        }
    };
    if !ctx.state.read().await.clients.contains_key(&target) {
        return;
    }
    warn!(peer = %peer_sid, killer = %killer, target = %target, "Killed from another server");

    ctx.senders.write().await.close_user(
        &target,
        Message::new(
            "ERROR",
            vec![format!("Closing link: Killed ({} ({}))", killer, reason)],
        ),
    );

    let text = format!("Killed by {} ({})", killer, reason);
    forget_remote_user(ctx, &target, &text).await;
    // Every server hears about it as a QUIT, which is what it is to them — the
    // one that asked for the kill included, since that is how it learns the
    // user is gone.
    ctx.links.read().await.relay(
        &Message::new("QUIT", vec![text]).with_prefix(&target),
        None,
    );
}

/// A user on another server went away, or came back.
async fn accept_remote_away(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let Some(uid) = msg.prefix.as_ref() else {
        return;
    };
    let away = msg.params.first().filter(|m| !m.is_empty()).cloned();
    {
        let state = ctx.state.read().await;
        match state.clients.get(uid) {
            Some(c) => c.write().await.away_message = away,
            None => return,
        }
    }
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A member as it appears in a burst: its prefixes, then its id.
fn split_member(token: &str) -> (&str, &str) {
    let at = token
        .find(|c: char| c != '@' && c != '%' && c != '+')
        .unwrap_or(token.len());
    token.split_at(at)
}

fn member_modes_from(prefixes: &str) -> crate::channel::ChannelMemberModeSet {
    let mut modes = crate::channel::ChannelMemberModeSet::default();
    for c in prefixes.chars() {
        match c {
            '@' => modes.op = true,
            '%' => modes.halfop = true,
            '+' => modes.voice = true,
            _ => {}
        }
    }
    modes
}

/// How a user appears to the people who see what it did.
async fn source_of(ctx: &LinkContext, uid: &str) -> Option<String> {
    let state = ctx.state.read().await;
    let c = state.clients.get(uid)?;
    let g = c.read().await;
    Some(g.source().unwrap_or_else(|| g.nick_or_id().to_string()))
}

/// Send to every member of a channel. A member on another server has no
/// connection here, so it costs nothing to pass them over.
async fn to_members(ctx: &LinkContext, members: &[String], msg: &Message, except: Option<&str>) {
    let registry = ctx.senders.read().await;
    for member in members {
        if Some(member.as_str()) == except {
            continue;
        }
        registry.deliver(member, msg);
    }
}

/// The members of a channel, as ids.
async fn members_of(ctx: &LinkContext, key: &str) -> Vec<String> {
    let store = ctx.channels.read().await;
    match store.channels.get(key) {
        Some(ch) => ch.read().await.members.keys().cloned().collect(),
        None => Vec::new(),
    }
}

/// Put a user into a channel here, on both sides of the record: the channel's
/// member list and the user's own.
async fn seat_member(
    ctx: &LinkContext,
    key: &str,
    name: &str,
    uid: &str,
    modes: crate::channel::ChannelMemberModeSet,
) {
    {
        let mut store = ctx.channels.write().await;
        let entry = store
            .channels
            .entry(key.to_string())
            .or_insert_with(|| RwLock::new(crate::channel::Channel::new(name.to_string())));
        entry.write().await.members.insert(
            uid.to_string(),
            crate::channel::ChannelMembership {
                client_id: uid.to_string(),
                modes: modes.clone(),
            },
        );
    }
    let state = ctx.state.read().await;
    if let Some(c) = state.clients.get(uid) {
        c.write().await.channels.insert(
            key.to_string(),
            crate::channel::ChannelMembership {
                client_id: uid.to_string(),
                modes,
            },
        );
    }
}

/// Take a user out of a channel here, and remove the channel if that was the
/// last of them.
async fn unseat_member(ctx: &LinkContext, key: &str, uid: &str) {
    {
        let mut store = ctx.channels.write().await;
        let mut empty = false;
        if let Some(entry) = store.channels.get_mut(key) {
            let mut ch = entry.write().await;
            ch.members.remove(uid);
            ch.invite_list.remove(uid);
            empty = ch.members.is_empty();
        }
        if empty {
            store.channels.remove(key);
        }
    }
    let state = ctx.state.read().await;
    if let Some(c) = state.clients.get(uid) {
        c.write().await.channels.remove(key);
    }
}

/// A channel as another server has it. Two servers that both have a channel of
/// this name have to end up with one channel, and the older timestamp decides
/// whose it is — the rule every TS network uses, and the only one that
/// converges without a tie-break.
async fn accept_remote_sjoin(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    if msg.params.len() < 4 {
        warn!(peer = %peer_sid, "Malformed SJOIN from a linked server");
        return;
    }
    let Some(ts) = msg.params[0].parse::<i64>().ok() else {
        return;
    };
    let name = msg.params[1].clone();
    let letters = msg.params[2].clone();
    let members_field = msg.params[msg.params.len() - 1].clone();
    let mode_args: Vec<String> = msg.params[3..msg.params.len() - 1].to_vec();
    let key = crate::channel::canonical_channel_key(&name);

    // What happens to what is already here, decided before anybody is let in.
    let (existed, deopped, keep_prefixes) = {
        let mut store = ctx.channels.write().await;
        let existed = store.channels.contains_key(&key);
        let entry = store
            .channels
            .entry(key.clone())
            .or_insert_with(|| RwLock::new(crate::channel::Channel::new(name.clone())));
        let mut ch = entry.write().await;
        if !existed {
            ch.created_at = ts;
            ch.set_mode_string(&letters, &mode_args);
            (false, Vec::new(), true)
        } else if ts < ch.created_at {
            // Theirs is older. Ours gives way: its modes go, and so does every
            // prefix anybody here was holding.
            ch.created_at = ts;
            ch.set_mode_string(&letters, &mode_args);
            let deopped: Vec<String> = ch
                .members
                .iter()
                .filter(|(_, m)| m.modes.op || m.modes.halfop || m.modes.voice)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &deopped {
                if let Some(m) = ch.members.get_mut(id) {
                    m.modes = Default::default();
                }
            }
            (true, deopped, true)
        } else if ts == ch.created_at {
            ch.merge_mode_string(&letters, &mode_args);
            (true, Vec::new(), true)
        } else {
            // Ours is older and keeps its modes; theirs arrive with none.
            (true, Vec::new(), false)
        }
    };

    let before = members_of(ctx, &key).await;
    let mut arrived: Vec<(String, crate::channel::ChannelMemberModeSet)> = Vec::new();
    for token in members_field.split(' ').filter(|t| !t.is_empty()) {
        let (prefixes, uid) = split_member(token);
        if !valid_uid(uid) {
            continue;
        }
        let modes = if keep_prefixes {
            member_modes_from(prefixes)
        } else {
            Default::default()
        };
        if before.iter().any(|m| m == uid) {
            continue;
        }
        seat_member(ctx, &key, &name, uid, modes.clone()).await;
        arrived.push((uid.to_string(), modes));
    }

    // Everybody here watches the new arrivals come in, and watches their own
    // channel lose its operators when it was the younger one.
    let members = members_of(ctx, &key).await;
    let server = ctx.cfg.read().await.server.name.clone();
    if existed && !deopped.is_empty() {
        let mut nicks = Vec::new();
        {
            let state = ctx.state.read().await;
            for id in &deopped {
                if let Some(c) = state.clients.get(id) {
                    nicks.push(c.read().await.nick_or_id().to_string());
                }
            }
        }
        let mut params = vec![name.clone(), format!("-{}", "o".repeat(nicks.len()))];
        params.extend(nicks);
        to_members(
            ctx,
            &members,
            &Message::new("MODE", params).with_prefix(&server),
            None,
        )
        .await;
    }
    for (uid, modes) in &arrived {
        let Some(source) = source_of(ctx, uid).await else {
            continue;
        };
        let join = Message::new("JOIN", vec![name.clone()]).with_prefix(&source);
        to_members(ctx, &members, &join, Some(uid)).await;
        let prefixes = modes.prefixes_ordered();
        if !prefixes.is_empty() {
            let nick = {
                let state = ctx.state.read().await;
                match state.clients.get(uid) {
                    Some(c) => c.read().await.nick_or_id().to_string(),
                    None => continue,
                }
            };
            let letters: String = prefixes
                .chars()
                .map(|c| match c {
                    '@' => 'o',
                    '%' => 'h',
                    _ => 'v',
                })
                .collect();
            let mut params = vec![name.clone(), format!("+{}", letters)];
            for _ in letters.chars() {
                params.push(nick.clone());
            }
            to_members(
                ctx,
                &members,
                &Message::new("MODE", params).with_prefix(&server),
                None,
            )
            .await;
        }
    }
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A user on another server joined a channel.
async fn accept_remote_join(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(ts), Some(name)) = (
        msg.prefix.clone(),
        msg.params.first().and_then(|t| t.parse::<i64>().ok()),
        msg.params.get(1).cloned(),
    ) else {
        return;
    };
    let key = crate::channel::canonical_channel_key(&name);
    {
        let mut store = ctx.channels.write().await;
        let existed = store.channels.contains_key(&key);
        let entry = store
            .channels
            .entry(key.clone())
            .or_insert_with(|| RwLock::new(crate::channel::Channel::new(name.clone())));
        let mut ch = entry.write().await;
        if !existed || ts < ch.created_at {
            ch.created_at = ts;
        }
        if ch.members.contains_key(&uid) {
            return;
        }
    }
    seat_member(ctx, &key, &name, &uid, Default::default()).await;
    let Some(source) = source_of(ctx, &uid).await else {
        return;
    };
    let members = members_of(ctx, &key).await;
    let join = Message::new("JOIN", vec![name.clone()]).with_prefix(&source);
    to_members(ctx, &members, &join, Some(&uid)).await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A user on another server left a channel.
async fn accept_remote_part(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(name)) = (msg.prefix.clone(), msg.params.first().cloned()) else {
        return;
    };
    let key = crate::channel::canonical_channel_key(&name);
    let members = members_of(ctx, &key).await;
    if !members.contains(&uid) {
        return;
    }
    let Some(source) = source_of(ctx, &uid).await else {
        return;
    };
    let mut params = vec![name.clone()];
    if let Some(reason) = msg.params.get(1) {
        params.push(reason.clone());
    }
    to_members(
        ctx,
        &members,
        &Message::new("PART", params).with_prefix(&source),
        Some(&uid),
    )
    .await;
    unseat_member(ctx, &key, &uid).await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// Somebody on another server kicked somebody out of a channel.
async fn accept_remote_kick(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(by), Some(name), Some(target)) = (
        msg.prefix.clone(),
        msg.params.first().cloned(),
        msg.params.get(1).cloned(),
    ) else {
        return;
    };
    let key = crate::channel::canonical_channel_key(&name);
    let members = members_of(ctx, &key).await;
    if !members.contains(&target) {
        return;
    }
    let source = source_of(ctx, &by).await.unwrap_or_else(|| by.clone());
    let target_nick = {
        let state = ctx.state.read().await;
        match state.clients.get(&target) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => target.clone(),
        }
    };
    let reason = msg.params.get(2).cloned().unwrap_or_else(|| target_nick.clone());
    to_members(
        ctx,
        &members,
        &Message::new("KICK", vec![name.clone(), target_nick, reason]).with_prefix(&source),
        None,
    )
    .await;
    unseat_member(ctx, &key, &target).await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A channel's topic, set on another server.
async fn accept_remote_topic(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(name)) = (msg.prefix.clone(), msg.params.first().cloned()) else {
        return;
    };
    let topic = msg.params.get(1).cloned().unwrap_or_default();
    let key = crate::channel::canonical_channel_key(&name);
    let Some(source) = source_of(ctx, &uid).await else {
        return;
    };
    let setter = source.split('!').next().unwrap_or(&source).to_string();
    let now = chrono::Utc::now().timestamp();
    {
        let store = ctx.channels.read().await;
        let Some(entry) = store.channels.get(&key) else {
            return;
        };
        let mut ch = entry.write().await;
        ch.topic = if topic.is_empty() { None } else { Some(topic.clone()) };
        ch.topic_setter = Some(setter);
        ch.topic_time = Some(now);
    }
    let members = members_of(ctx, &key).await;
    to_members(
        ctx,
        &members,
        &Message::new("TOPIC", vec![name.clone(), topic]).with_prefix(&source),
        None,
    )
    .await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A topic in a burst: it is already set, so nobody is told it changed.
async fn accept_remote_topic_burst(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(name), Some(at), Some(setter), Some(topic)) = (
        msg.params.first().cloned(),
        msg.params.get(1).and_then(|t| t.parse::<i64>().ok()),
        msg.params.get(2).cloned(),
        msg.params.get(3).cloned(),
    ) else {
        return;
    };
    let key = crate::channel::canonical_channel_key(&name);
    let store = ctx.channels.read().await;
    let Some(entry) = store.channels.get(&key) else {
        return;
    };
    let mut ch = entry.write().await;
    // A topic already here was set on a channel this server has had for longer,
    // or at the same moment; either way it is not this one's to replace.
    if ch.topic.is_some() && ch.topic_time.unwrap_or(0) >= at {
        return;
    }
    ch.topic = Some(topic);
    ch.topic_setter = Some(setter);
    ch.topic_time = Some(at);
    drop(ch);
    drop(store);
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A channel's ban, exception, invite-exception or quiet list, in a burst.
async fn accept_remote_bmask(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(name), Some(letter), Some(masks)) = (
        msg.params.get(1).cloned(),
        msg.params.get(2).and_then(|l| l.chars().next()),
        msg.params.get(3).cloned(),
    ) else {
        return;
    };
    let key = crate::channel::canonical_channel_key(&name);
    {
        let store = ctx.channels.read().await;
        let Some(entry) = store.channels.get(&key) else {
            return;
        };
        let mut ch = entry.write().await;
        let Some(list) = ch.list_mut(letter) else {
            return;
        };
        for mask in masks.split(' ').filter(|m| !m.is_empty()) {
            if !list.iter().any(|m| m == mask) {
                list.push(mask.to_string());
            }
        }
    }
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A channel mode set on another server. Prefix modes name their target by id,
/// so a nick change in flight cannot move an operator status onto somebody
/// else; the people watching are shown nicks.
async fn accept_remote_mode(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(by), Some(name), Some(letters)) = (
        msg.prefix.clone(),
        msg.params.first().cloned(),
        msg.params.get(1).cloned(),
    ) else {
        return;
    };
    let key = crate::channel::canonical_channel_key(&name);
    let args: Vec<String> = msg.params[2..].to_vec();
    let source = source_of(ctx, &by)
        .await
        .unwrap_or_else(|| ctx.cfg.try_read().map(|c| c.server.name.clone()).unwrap_or(by));

    let mut shown = Vec::new();
    {
        let store = ctx.channels.read().await;
        let Some(entry) = store.channels.get(&key) else {
            return;
        };
        let mut ch = entry.write().await;
        let mut adding = true;
        let mut arg = args.iter();
        let state = ctx.state.read().await;
        for c in letters.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                'o' | 'h' | 'v' => {
                    let Some(target) = arg.next() else { continue };
                    let nick = match state.clients.get(target) {
                        Some(cl) => cl.read().await.nick_or_id().to_string(),
                        None => target.clone(),
                    };
                    if let Some(m) = ch.members.get_mut(target) {
                        match c {
                            'o' => m.modes.op = adding,
                            'h' => m.modes.halfop = adding,
                            _ => m.modes.voice = adding,
                        }
                    }
                    shown.push(nick);
                }
                'b' | 'e' | 'I' | 'q' => {
                    let Some(mask) = arg.next() else { continue };
                    if let Some(list) = ch.list_mut(c) {
                        if adding {
                            if !list.iter().any(|m| m == mask) {
                                list.push(mask.clone());
                            }
                        } else {
                            list.retain(|m| m != mask);
                        }
                    }
                    shown.push(mask.clone());
                }
                'k' => {
                    let value = arg.next().cloned();
                    ch.key = if adding { value.clone() } else { None };
                    shown.push(value.unwrap_or_else(|| "*".to_string()));
                }
                'l' => {
                    if adding {
                        let value = arg.next().cloned();
                        ch.modes.user_limit = value.as_ref().and_then(|v| v.parse().ok());
                        shown.push(value.unwrap_or_default());
                    } else {
                        ch.modes.user_limit = None;
                    }
                }
                'i' => ch.modes.invite_only = adding,
                'm' => ch.modes.moderated = adding,
                'n' => ch.modes.no_external = adding,
                's' => ch.modes.secret = adding,
                't' => ch.modes.topic_protect = adding,
                'p' => ch.modes.private = adding,
                'R' => ch.modes.registered_only = adding,
                'c' => ch.modes.no_colors = adding,
                'C' => ch.modes.no_ctcp = adding,
                _ => {}
            }
        }
    }
    let members = members_of(ctx, &key).await;
    let mut params = vec![name.clone(), letters];
    params.extend(shown);
    to_members(
        ctx,
        &members,
        &Message::new("MODE", params).with_prefix(&source),
        None,
    )
    .await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// Tell the people who share a channel with a user that something about that
/// user changed — but only the ones that asked to hear about it.
async fn to_shared_channels(ctx: &LinkContext, uid: &str, cap: &str, msg: &Message) {
    let channels: Vec<String> = {
        let state = ctx.state.read().await;
        match state.clients.get(uid) {
            Some(c) => c.read().await.channels.keys().cloned().collect(),
            None => return,
        }
    };
    let mut told: std::collections::HashSet<String> = std::collections::HashSet::new();
    told.insert(uid.to_string());
    for key in &channels {
        for member in members_of(ctx, key).await {
            if !told.insert(member.clone()) {
                continue;
            }
            let wants = {
                let state = ctx.state.read().await;
                match state.clients.get(&member) {
                    Some(c) => c.read().await.capabilities.contains(cap),
                    None => false,
                }
            };
            if wants {
                ctx.senders.read().await.deliver(&member, msg);
            }
        }
    }
}

/// A user on another server logged in to an account, or out of one.
async fn accept_remote_account(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(account)) = (msg.prefix.clone(), msg.params.first().cloned()) else {
        return;
    };
    let account = if account == "*" { None } else { Some(account) };
    let source = {
        let state = ctx.state.read().await;
        let Some(c) = state.clients.get(&uid) else {
            return;
        };
        let mut g = c.write().await;
        g.account = account.clone();
        g.source().unwrap_or_else(|| g.nick_or_id().to_string())
    };
    let shown = account.unwrap_or_else(|| "*".to_string());
    to_shared_channels(
        ctx,
        &uid,
        "account-notify",
        &Message::new("ACCOUNT", vec![shown]).with_prefix(&source),
    )
    .await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A user on another server is shown under a different user@host now.
async fn accept_remote_chghost(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(user), Some(host)) = (
        msg.prefix.clone(),
        msg.params.first().cloned(),
        msg.params.get(1).cloned(),
    ) else {
        return;
    };
    let source = {
        let state = ctx.state.read().await;
        let Some(c) = state.clients.get(&uid) else {
            return;
        };
        let g = c.read().await;
        g.source().unwrap_or_else(|| g.nick_or_id().to_string())
    };
    {
        let state = ctx.state.read().await;
        if let Some(c) = state.clients.get(&uid) {
            let mut g = c.write().await;
            g.vuser = Some(user.clone());
            g.vhost = Some(host.clone());
        }
    }
    to_shared_channels(
        ctx,
        &uid,
        "chghost",
        &Message::new("CHGHOST", vec![user, host]).with_prefix(&source),
    )
    .await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A user on another server changed the name it goes by.
async fn accept_remote_setname(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(realname)) = (msg.prefix.clone(), msg.params.first().cloned()) else {
        return;
    };
    let source = {
        let state = ctx.state.read().await;
        let Some(c) = state.clients.get(&uid) else {
            return;
        };
        let mut g = c.write().await;
        g.realname = Some(realname.clone());
        g.source().unwrap_or_else(|| g.nick_or_id().to_string())
    };
    to_shared_channels(
        ctx,
        &uid,
        "setname",
        &Message::new("SETNAME", vec![realname]).with_prefix(&source),
    )
    .await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// Somebody on another server invited one of our users into a channel.
async fn accept_remote_invite(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(by), Some(target), Some(name)) = (
        msg.prefix.clone(),
        msg.params.first().cloned(),
        msg.params.get(1).cloned(),
    ) else {
        return;
    };
    let Some(target_sid) = owning_sid(&target) else {
        return;
    };
    let our_sid = ctx.state.read().await.sid.clone();
    if target_sid != our_sid {
        if let Some(tx) = ctx.links.read().await.route(target_sid) {
            let _ = tx.try_send(msg.clone());
        }
        return;
    }
    let key = crate::channel::canonical_channel_key(&name);
    let (source, target_nick) = {
        let state = ctx.state.read().await;
        let source = match state.clients.get(&by) {
            Some(c) => {
                let g = c.read().await;
                g.source().unwrap_or_else(|| g.nick_or_id().to_string())
            }
            None => return,
        };
        let nick = match state.clients.get(&target) {
            Some(c) => c.read().await.nick_or_id().to_string(),
            None => return,
        };
        (source, nick)
    };
    // The invitation has to be on the channel here too, or the person it was
    // sent to would be turned away at a door they were asked through.
    {
        let store = ctx.channels.read().await;
        if let Some(entry) = store.channels.get(&key) {
            entry.write().await.invite_list.insert(target.clone());
        }
    }
    ctx.senders.read().await.deliver(
        &target,
        &Message::new("INVITE", vec![target_nick, name]).with_prefix(&source),
    );
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A key set on a user or a channel, somewhere else on the network.
async fn accept_remote_metadata(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(uid), Some(target), Some(key)) = (
        msg.prefix.clone(),
        msg.params.first().cloned(),
        msg.params.get(1).cloned(),
    ) else {
        return;
    };
    let value = msg.params.get(2).filter(|v| !v.is_empty()).cloned();
    let Some(source) = source_of(ctx, &uid).await else {
        return;
    };
    let store_key = crate::commands::metadata::metadata_key(&target);
    {
        let mut state = ctx.state.write().await;
        match value {
            Some(ref v) => {
                state
                    .metadata
                    .entry(store_key)
                    .or_default()
                    .insert(key.clone(), v.clone());
            }
            None => {
                if let Some(keys) = state.metadata.get_mut(&store_key) {
                    keys.remove(&key);
                }
            }
        }
    }
    let server = ctx.cfg.read().await.server.name.clone();
    crate::commands::metadata::broadcast_metadata_event(
        &ctx.state,
        &ctx.channels,
        &ctx.senders,
        &source,
        &uid,
        &server,
        &target,
        &key,
        value.as_deref(),
    )
    .await;
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// A server introduced behind the peer.
async fn accept_remote_server(ctx: &LinkContext, msg: &Message, peer_sid: &str) {
    let (Some(name), Some(hops), Some(sid)) =
        (msg.params.first(), msg.params.get(1), msg.params.get(2))
    else {
        return;
    };
    if !valid_sid(sid) {
        warn!(peer = %peer_sid, sid = %sid, "Refusing a server with an unusable id");
        return;
    }
    let our_sid = ctx.state.read().await.sid.clone();
    if *sid == our_sid {
        warn!(peer = %peer_sid, sid = %sid, "A linked server is using our own id");
        return;
    }
    ctx.links.write().await.introduce(RemoteServer {
        name: name.clone(),
        sid: sid.clone(),
        description: msg.params.get(3).cloned().unwrap_or_default(),
        hops: hops.parse().unwrap_or(2),
        behind: Some(peer_sid.to_string()),
    });
    info!(peer = %peer_sid, server = %name, sid = %sid, "Server introduced");
    ctx.links.read().await.relay(msg, Some(peer_sid));
}

/// Send a message to every link. Does nothing on a server that has none, which
/// is what lets the command handlers call these without asking first.
async fn broadcast(cfg: &Config, msg: Message) {
    let Some(ref links) = cfg.links_runtime else {
        return;
    };
    links.read().await.relay(&msg, None);
}

/// Tell the network about a user that just registered here.
pub async fn announce_user(cfg: &Config, client: &crate::user::Client) {
    if cfg.links_runtime.is_none() {
        return;
    }
    broadcast(cfg, uid_message(&our_sid(cfg), client)).await;
}

/// Tell the network that one of our users took a new nick.
pub async fn announce_nick(cfg: &Config, uid: &str, nick: &str, ts: i64) {
    broadcast(
        cfg,
        Message::new("NICK", vec![nick.to_string(), ts.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network that one of our users has gone.
pub async fn announce_quit(cfg: &Config, uid: &str, reason: &str) {
    broadcast(
        cfg,
        Message::new("QUIT", vec![reason.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network whether one of our users is away.
pub async fn announce_away(cfg: &Config, uid: &str, away: Option<&str>) {
    let params = away.map(|m| vec![m.to_string()]).unwrap_or_default();
    broadcast(cfg, Message::new("AWAY", params).with_prefix(uid)).await;
}

/// Tell the network about a channel one of our users just made.
///
/// A channel is announced whole — its timestamp, its modes and the person in
/// it — because the timestamp is what settles which channel it is when the
/// other side already has one of that name.
pub async fn announce_channel(cfg: &Config, ts: i64, name: &str, modes: (String, Vec<String>), member: &str) {
    let (letters, args) = modes;
    let mut params = vec![ts.to_string(), name.to_string(), letters];
    params.extend(args);
    params.push(member.to_string());
    broadcast(cfg, Message::new("SJOIN", params).with_prefix(our_sid(cfg))).await;
}

/// Tell the network that one of our users joined a channel that already exists.
pub async fn announce_join(cfg: &Config, uid: &str, ts: i64, name: &str) {
    broadcast(
        cfg,
        Message::new("JOIN", vec![ts.to_string(), name.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network that one of our users left a channel.
pub async fn announce_part(cfg: &Config, uid: &str, name: &str, reason: Option<&str>) {
    let mut params = vec![name.to_string()];
    if let Some(reason) = reason {
        params.push(reason.to_string());
    }
    broadcast(cfg, Message::new("PART", params).with_prefix(uid)).await;
}

/// Tell the network that somebody was kicked out of a channel.
pub async fn announce_kick(cfg: &Config, uid: &str, name: &str, target: &str, reason: &str) {
    broadcast(
        cfg,
        Message::new(
            "KICK",
            vec![name.to_string(), target.to_string(), reason.to_string()],
        )
        .with_prefix(uid),
    )
    .await;
}

/// Tell the network about a change to a channel's modes.
///
/// The arguments to `+o`, `+h` and `+v` are user ids, not nicks: a nick change
/// crossing a link would otherwise be able to hand somebody else the op.
pub async fn announce_channel_mode(cfg: &Config, uid: &str, name: &str, letters: &str, args: &[String]) {
    if letters.is_empty() || letters == "+" || letters == "-" {
        return;
    }
    let mut params = vec![name.to_string(), letters.to_string()];
    params.extend(args.iter().cloned());
    broadcast(cfg, Message::new("MODE", params).with_prefix(uid)).await;
}

/// Tell the network a channel has a new topic.
pub async fn announce_topic(cfg: &Config, uid: &str, name: &str, topic: &str) {
    broadcast(
        cfg,
        Message::new("TOPIC", vec![name.to_string(), topic.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Send a message to a channel's members on the other servers.
///
/// Every server that holds a member delivers to its own, so this goes out once
/// per link rather than once per person.
pub async fn announce_channel_message(cfg: &Config, uid: &str, name: &str, msg: &Message) {
    if cfg.links_runtime.is_none() {
        return;
    }
    let mut out = msg.clone();
    out.prefix = Some(uid.to_string());
    if out.params.is_empty() {
        out.params.push(name.to_string());
    } else {
        out.params[0] = name.to_string();
    }
    broadcast(cfg, out).await;
}

/// Tell the network that one of our users logged in to an account, or out.
pub async fn announce_account(cfg: &Config, uid: &str, account: Option<&str>) {
    broadcast(
        cfg,
        Message::new("ACCOUNT", vec![account.unwrap_or("*").to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network that one of our users is shown under a new user@host.
pub async fn announce_chghost(cfg: &Config, uid: &str, user: &str, host: &str) {
    broadcast(
        cfg,
        Message::new("CHGHOST", vec![user.to_string(), host.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network that one of our users changed the name it goes by.
pub async fn announce_setname(cfg: &Config, uid: &str, realname: &str) {
    broadcast(
        cfg,
        Message::new("SETNAME", vec![realname.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network that somebody was invited into a channel.
pub async fn announce_invite(cfg: &Config, uid: &str, target: &str, name: &str) {
    broadcast(
        cfg,
        Message::new("INVITE", vec![target.to_string(), name.to_string()]).with_prefix(uid),
    )
    .await;
}

/// Tell the network that a key on a user or a channel was set or cleared.
pub async fn announce_metadata(
    cfg: &Config,
    uid: &str,
    target: &str,
    key: &str,
    value: Option<&str>,
) {
    let mut params = vec![target.to_string(), key.to_string()];
    params.push(value.unwrap_or("").to_string());
    // An empty value is a key that went; a key cannot be set to nothing, so the
    // two do not need telling apart by anything but this.
    broadcast(cfg, Message::new("METADATA", params).with_prefix(uid)).await;
}

/// Send a message to a user on another server. Returns whether there was a way
/// to reach it — false means the target is not somewhere this server can get to,
/// and the caller answers as it would for a nick that is not here.
pub async fn route_to_user(cfg: &Config, from_uid: &str, target_uid: &str, msg: &Message) -> bool {
    let Some(ref links) = cfg.links_runtime else {
        return false;
    };
    let Some(sid) = owning_sid(target_uid) else {
        return false;
    };
    let mut out = msg.clone();
    out.prefix = Some(from_uid.to_string());
    if out.params.is_empty() {
        out.params.push(target_uid.to_string());
    } else {
        out.params[0] = target_uid.to_string();
    }
    match links.read().await.route(sid) {
        Some(tx) => tx.try_send(out).is_ok(),
        None => false,
    }
}

/// What to do with one message from a linked server.
///
/// Anything this server does not understand is ignored rather than guessed at:
/// a message it does not know is one a newer peer sent, and dropping it is
/// better than acting on half of it.
async fn handle_link_message(
    ctx: &LinkContext,
    msg: &Message,
    peer_sid: &str,
    peer: &tokio::sync::mpsc::Sender<Message>,
) -> std::ops::ControlFlow<()> {
    match msg.command.as_str() {
        "PING" => {
            let token = msg.params.last().cloned().unwrap_or_default();
            // Answered to the server that asked, and to nobody else.
            let _ = peer.try_send(Message::new("PONG", vec![token]));
            std::ops::ControlFlow::Continue(())
        }
        "PONG" => std::ops::ControlFlow::Continue(()),
        "SERVER" => {
            accept_remote_server(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "UID" => {
            accept_remote_user(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "NICK" => {
            accept_remote_nick(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "QUIT" => {
            accept_remote_quit(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "KILL" => {
            accept_remote_kill(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "SJOIN" => {
            accept_remote_sjoin(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "JOIN" => {
            accept_remote_join(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "PART" => {
            accept_remote_part(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "KICK" => {
            accept_remote_kick(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "MODE" => {
            accept_remote_mode(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "TOPIC" => {
            accept_remote_topic(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "TB" => {
            accept_remote_topic_burst(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "BMASK" => {
            accept_remote_bmask(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "ACCOUNT" => {
            accept_remote_account(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "CHGHOST" => {
            accept_remote_chghost(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "SETNAME" => {
            accept_remote_setname(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "INVITE" => {
            accept_remote_invite(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "METADATA" => {
            accept_remote_metadata(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "AWAY" => {
            accept_remote_away(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "PRIVMSG" | "NOTICE" | "TAGMSG" => {
            accept_remote_message(ctx, msg, peer_sid).await;
            std::ops::ControlFlow::Continue(())
        }
        "EOB" => {
            info!(peer = %peer_sid, "Burst complete");
            std::ops::ControlFlow::Continue(())
        }
        "SQUIT" | "ERROR" => {
            warn!(
                peer = %peer_sid,
                "Link closing: {}",
                msg.params.last().cloned().unwrap_or_default()
            );
            std::ops::ControlFlow::Break(())
        }
        other => {
            tracing::debug!(peer = %peer_sid, command = %other, "Ignoring a link message");
            std::ops::ControlFlow::Continue(())
        }
    }
}

/// Accept links on this server's link ports.
pub async fn listen(addr: String, ctx: LinkContext) -> std::io::Result<()> {
    let bind = if let Some(port) = addr.strip_prefix(':') {
        format!("0.0.0.0:{}", port)
    } else {
        addr.clone()
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("Listening on {} (server links)", bind);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        serve_link(stream, peer.ip().to_string(), ctx, None).await;
                    });
                }
                Err(e) => {
                    error!("Link accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    });
    Ok(())
}

/// Keep an outbound link up, retrying with a widening delay.
///
/// Both ends may be configured to connect to each other, and both may try at
/// once; the second link to arrive is refused as already linked, and whichever
/// one survives is the one the network uses. That is why the delay grows —
/// two servers retrying in lockstep would refuse each other for ever.
pub fn autoconnect(link: LinkConfig, ctx: LinkContext) {
    let Some(host) = link.host.clone() else {
        warn!(link = %link.name, "No host configured; waiting to be connected to instead");
        return;
    };
    tokio::spawn(async move {
        let mut delay = std::time::Duration::from_secs(2);
        loop {
            if ctx.links.read().await.is_linked(&link.sid) {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            let target = format!("{}:{}", host, link.port);
            match tokio::net::TcpStream::connect(&target).await {
                Ok(stream) => {
                    info!(link = %link.name, target = %target, "Connecting");
                    delay = std::time::Duration::from_secs(2);
                    serve_link(stream, target.clone(), ctx.clone(), Some(link.clone())).await;
                    warn!(link = %link.name, "Link closed");
                }
                Err(e) => {
                    warn!(link = %link.name, target = %target, "Cannot connect: {}", e);
                }
            }
            // A little jitter, so two servers that both dial do not keep
            // colliding at the same instant.
            let jitter = std::time::Duration::from_millis(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_millis())
                    .unwrap_or(0)
                    % 500) as u64,
            );
            tokio::time::sleep(delay + jitter).await;
            delay = (delay * 2).min(std::time::Duration::from_secs(60));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sid_is_a_digit_and_two_alphanumerics() {
        for good in ["1AA", "0ZZ", "9A0", "142"] {
            assert!(valid_sid(good), "{good} should be a sid");
        }
        for bad in ["", "A11", "1A", "1AAA", "1aa", "1A-", "1 A"] {
            assert!(!valid_sid(bad), "{bad} should not be a sid");
        }
    }

    #[test]
    fn user_ids_are_unique_and_carry_their_server() {
        let counter = std::sync::atomic::AtomicU64::new(0);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let uid = next_uid("1AA", &counter);
            assert!(valid_uid(&uid), "{uid} is not a usable user id");
            assert_eq!(&uid[..3], "1AA", "{uid} does not name its server");
            assert!(seen.insert(uid.clone()), "{uid} was issued twice");
        }
        // Two servers never choose the same id, however many they issue.
        let other = std::sync::atomic::AtomicU64::new(0);
        for _ in 0..1000 {
            assert!(!seen.contains(&next_uid("2BB", &other)));
        }
    }

    #[test]
    fn a_uid_that_is_not_one_is_refused() {
        for bad in [
            "",
            "1AA",
            "1AAAAAAA",
            "1AAAAAAAAA",
            "AAAAAAAAA",
            "1AAaaaaaa",
            "1AA-AAAAA",
        ] {
            assert!(!valid_uid(bad), "{bad} should not be a user id");
        }
    }

    #[test]
    fn a_derived_sid_is_usable_and_stable() {
        let a = derive_sid("irc.example.org");
        assert!(valid_sid(&a), "{a} is not a usable sid");
        assert_eq!(a, derive_sid("irc.example.org"), "not stable across calls");
        assert_ne!(a, derive_sid("irc2.example.org"));
    }

    fn greeting(password: &str, sid: &str, name: &str) -> Vec<String> {
        vec![
            format!("PASS {} TS {} {}", password, LINK_PROTOCOL, sid),
            "CAPAB :TAGS MSGID".to_string(),
            format!("SERVER {} 1 :Another server", name),
        ]
    }

    #[test]
    fn a_greeting_with_the_right_password_is_accepted() {
        let g = read_greeting(&greeting("secret", "2AA", "irc2.example.org"), "secret")
            .expect("should have been accepted");
        assert_eq!(g.sid, "2AA");
        assert_eq!(g.name, "irc2.example.org");
        assert_eq!(g.description, "Another server");
        assert_eq!(g.capab, vec!["TAGS", "MSGID"]);
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let e = read_greeting(&greeting("wrong", "2AA", "irc2.example.org"), "secret")
            .expect_err("should have been refused");
        assert!(matches!(e, LinkError::BadPassword), "{e}");
    }

    /// Nothing is accepted before SERVER, because nothing before it has been
    /// authenticated.
    #[test]
    fn nothing_is_accepted_before_the_server_line() {
        let lines = vec![
            "PASS secret TS 1 2AA".to_string(),
            "PRIVMSG #chan :hello".to_string(),
            "SERVER irc2.example.org 1 :Another".to_string(),
        ];
        let e = read_greeting(&lines, "secret").expect_err("should have been refused");
        assert!(
            matches!(e, LinkError::OutOfOrder(ref c) if c == "PRIVMSG"),
            "{e}"
        );
    }

    #[test]
    fn a_server_line_without_a_password_is_refused() {
        let lines = vec!["SERVER irc2.example.org 1 :Another".to_string()];
        let e = read_greeting(&lines, "secret").expect_err("should have been refused");
        assert!(
            matches!(e, LinkError::OutOfOrder(ref c) if c == "SERVER"),
            "{e}"
        );
    }

    #[test]
    fn a_protocol_version_we_do_not_speak_is_refused() {
        let lines = vec![
            "PASS secret TS 99 2AA".to_string(),
            "SERVER irc2.example.org 1 :Another".to_string(),
        ];
        let e = read_greeting(&lines, "secret").expect_err("should have been refused");
        assert!(
            matches!(e, LinkError::Unsupported(ref v) if v == "99"),
            "{e}"
        );
    }

    /// A split takes everything that was reachable through the link, not just
    /// the server on the other end of it.
    #[test]
    fn a_split_forgets_what_was_behind_the_link() {
        let mut reg = LinkRegistry::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        reg.attach(
            RemoteServer {
                name: "irc2.example.org".into(),
                sid: "2AA".into(),
                description: "peer".into(),
                hops: 1,
                behind: None,
            },
            tx,
        );
        reg.introduce(RemoteServer {
            name: "irc3.example.org".into(),
            sid: "3AA".into(),
            description: "behind the peer".into(),
            hops: 2,
            behind: Some("2AA".into()),
        });
        reg.introduce(RemoteServer {
            name: "irc4.example.org".into(),
            sid: "4AA".into(),
            description: "somewhere else".into(),
            hops: 2,
            behind: Some("9ZZ".into()),
        });
        assert_eq!(reg.count(), 3);

        let gone = reg.detach("2AA");
        let names: std::collections::HashSet<&str> = gone.iter().map(|s| s.sid.as_str()).collect();
        assert_eq!(names, ["2AA", "3AA"].into_iter().collect());
        assert!(reg.is_linked("4AA"), "an unrelated server should remain");
        assert_eq!(reg.count(), 1);
    }

    /// The burst line is the only thing the other server ever learns about a
    /// user, so every field has to survive being written and read back —
    /// including a realname with spaces in it, which is most of them.
    #[test]
    fn a_user_survives_the_wire() {
        let mut client = crate::user::Client::new("1AAAAAAAB".into(), "10.0.0.9".into());
        client.nick = Some("kara".into());
        client.user = Some("k".into());
        client.realname = Some("Kara of the Wire".into());
        client.account = Some("kara".into());
        client.nick_ts = 1_700_000_000;
        client.registered = true;

        let line = crate::protocol::format_message(&uid_message("1AA", &client));
        let parsed = parse_message_with_limit(line.trim_end_matches(['\r', '\n']), MAX_LINK_LINE)
            .expect("a burst line must parse");

        assert_eq!(parsed.prefix.as_deref(), Some("1AA"));
        assert_eq!(parsed.command, "UID");
        assert_eq!(parsed.params.first().map(String::as_str), Some("kara"));
        assert_eq!(
            parsed.params.get(2).map(String::as_str),
            Some("1700000000"),
            "the nick timestamp is what settles a collision"
        );
        assert_eq!(parsed.params.get(3).map(String::as_str), Some("k"));
        assert_eq!(parsed.params.get(4).map(String::as_str), Some("10.0.0.9"));
        assert_eq!(parsed.params.get(5).map(String::as_str), Some("1AAAAAAAB"));
        assert_eq!(parsed.params.get(6).map(String::as_str), Some("kara"));
        assert_eq!(
            parsed.params.get(7).map(String::as_str),
            Some("Kara of the Wire")
        );
    }

    /// A user with no account still has to produce eight parameters, or the
    /// realname would arrive where the account belongs.
    #[test]
    fn a_user_with_no_account_keeps_its_shape() {
        let mut client = crate::user::Client::new("1AAAAAAAC".into(), "host".into());
        client.nick = Some("nobody".into());
        client.user = Some("n".into());
        client.realname = Some("no account here".into());

        let msg = uid_message("1AA", &client);
        assert_eq!(msg.params.len(), 8);
        assert_eq!(msg.params[6], "*", "an absent account is a star, not a gap");
    }

    #[test]
    fn a_user_id_names_the_server_it_is_on() {
        assert_eq!(owning_sid("1AAAAAAAB"), Some("1AA"));
        // Connection ids are not user ids, and must never be mistaken for one:
        // routing on the first three characters of "client-12" would send a
        // message to a server called "cli".
        assert_eq!(owning_sid("client-12"), None);
        assert_eq!(owning_sid("ws-7"), None);
        assert_eq!(owning_sid(""), None);
    }

    /// A message for a server two links away goes out through the peer it sits
    /// behind, because that is the only queue this server has to it.
    #[test]
    fn a_route_follows_the_link_a_server_is_behind() {
        let mut reg = LinkRegistry::default();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Message>(4);
        reg.attach(
            RemoteServer {
                name: "irc2.example.org".into(),
                sid: "2AA".into(),
                description: "peer".into(),
                hops: 1,
                behind: None,
            },
            tx,
        );
        reg.introduce(RemoteServer {
            name: "irc3.example.org".into(),
            sid: "3AA".into(),
            description: "behind the peer".into(),
            hops: 2,
            behind: Some("2AA".into()),
        });
        assert!(reg.route("2AA").is_some(), "the peer itself is reachable");
        assert!(
            reg.route("3AA").is_some(),
            "and so is what sits behind it"
        );
        assert!(reg.route("9ZZ").is_none(), "a server nobody carries is not");
    }
}
