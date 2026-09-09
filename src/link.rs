//! Server-to-server linking. See docs/server-linking.md for the protocol.
//!
//! A link is a connection to another rIRCd, authenticated before anything else
//! happens on it, over which the two servers tell each other about their users,
//! channels and traffic. Server traffic has its own listener: a client that
//! reaches it is refused, so a mistake in one configuration cannot become an
//! authentication bypass in the other.

use crate::config::{Config, LinkConfig};
use crate::protocol::{parse_message_with_limit, Message};
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
    cfg_arc: Arc<RwLock<Config>>,
    links: Arc<RwLock<LinkRegistry>>,
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
        let cfg = cfg_arc.read().await;
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

    if links.read().await.is_linked(&greeting.sid) {
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
    links.write().await.attach(remote, tx.clone());
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
                if handle_link_message(&msg, &greeting.sid, &tx)
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

    ping_task.abort();
    writer_task.abort();
    let gone = links.write().await.detach(&greeting.sid);
    for server in &gone {
        warn!(server = %server.name, "Netsplit: server is gone");
    }
}

/// What to do with one message from a linked server.
///
/// Stage one carries the link itself: users, channels and traffic come next,
/// and anything else is ignored rather than guessed at — a message this server
/// does not understand is one a newer peer sent, and dropping it is better than
/// acting on half of it.
async fn handle_link_message(
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
pub async fn listen(
    addr: String,
    cfg_arc: Arc<RwLock<Config>>,
    links: Arc<RwLock<LinkRegistry>>,
) -> std::io::Result<()> {
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
                    let cfg_arc = cfg_arc.clone();
                    let links = links.clone();
                    tokio::spawn(async move {
                        serve_link(stream, peer.ip().to_string(), cfg_arc, links, None).await;
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
pub fn autoconnect(
    link: LinkConfig,
    cfg_arc: Arc<RwLock<Config>>,
    links: Arc<RwLock<LinkRegistry>>,
) {
    let Some(host) = link.host.clone() else {
        warn!(link = %link.name, "No host configured; waiting to be connected to instead");
        return;
    };
    tokio::spawn(async move {
        let mut delay = std::time::Duration::from_secs(2);
        loop {
            if links.read().await.is_linked(&link.sid) {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            let target = format!("{}:{}", host, link.port);
            match tokio::net::TcpStream::connect(&target).await {
                Ok(stream) => {
                    info!(link = %link.name, target = %target, "Connecting");
                    delay = std::time::Duration::from_secs(2);
                    serve_link(
                        stream,
                        target.clone(),
                        cfg_arc.clone(),
                        links.clone(),
                        Some(link.clone()),
                    )
                    .await;
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
}
