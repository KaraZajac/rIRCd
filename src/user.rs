use crate::channel::ChannelMembership;
use crate::protocol::Message;
use chrono::Utc;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

// ─── WHOWAS ───────────────────────────────────────────────────────────────────

const MAX_WHOWAS: usize = 5;

/// One WHOWAS history entry (recorded on NICK change or QUIT)
#[derive(Debug, Clone)]
pub struct WhowasEntry {
    pub nick: String,
    pub user: String,
    pub host: String,
    pub realname: String,
    pub server: String,
    pub timestamp: i64,
}

// ─── SCRAM server state ───────────────────────────────────────────────────────

/// Intermediate SASL SCRAM-SHA-256 server state (lives between step 1 and step 2)
#[derive(Debug)]
pub struct ScramServerState {
    pub username: String,
    pub full_nonce: String,
    pub client_first_bare: String,
    pub server_first: String,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

/// A connected client / user on the server
#[derive(Debug)]
pub struct Client {
    pub id: String,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub host: String,
    pub account: Option<String>,
    pub away_message: Option<String>,
    pub channels: HashMap<String, ChannelMembership>,
    pub registered: bool,
    pub capabilities: std::collections::HashSet<String>,
    /// Bot mode (umode +B); WHOIS returns RPL_WHOISBOT (335)
    pub bot: bool,
    /// MONITOR: nicks this client is monitoring (lowercase)
    pub monitor_list: std::collections::HashSet<String>,
    /// True after successful OPER
    pub oper: bool,
    /// Operator name from the successful OPER, used as the draft/oper tag value
    pub oper_name: Option<String>,
    /// What this operator may do; None means everything.
    pub oper_privileges: Option<Vec<String>>,
    /// Virtual host (cloak) shown to others; used in source() when set
    pub vhost: Option<String>,
    /// Virtual username shown to others; used in source() when set
    pub vuser: Option<String>,
    /// User mode +i: invisible (hidden from WHO unless sharing a channel)
    pub invisible: bool,
    /// User mode +w: receives WALLOPS broadcasts
    pub wallops: bool,
    /// Unix timestamp when the client completed registration (for WHOIS 317)
    pub signon_at: i64,
    /// Unix timestamp of the last message received from this client (for WHOIS 317 idle)
    pub last_active: i64,
    /// draft/metadata-2: keys this client has subscribed to for change notifications
    pub metadata_subscriptions: std::collections::HashSet<String>,
    /// True if this connection is over TLS (used for STS policy and WHOIS secure line)
    pub is_tls: bool,
}

impl Client {
    pub fn new(id: String, host: String) -> Self {
        Self {
            id,
            nick: None,
            user: None,
            realname: None,
            host,
            account: None,
            away_message: None,
            channels: HashMap::new(),
            registered: false,
            capabilities: std::collections::HashSet::new(),
            bot: false,
            monitor_list: std::collections::HashSet::new(),
            oper: false,
            oper_name: None,
            oper_privileges: None,
            vhost: None,
            vuser: None,
            invisible: false,
            wallops: false,
            signon_at: Utc::now().timestamp(),
            last_active: Utc::now().timestamp(),
            metadata_subscriptions: std::collections::HashSet::new(),
            is_tls: false,
        }
    }

    pub fn source(&self) -> Option<String> {
        let (n, u, h) = match (&self.nick, &self.user) {
            (Some(n), Some(u)) => {
                let display_user = self.vuser.as_deref().unwrap_or(u.as_str());
                let display_host = self.vhost.as_deref().unwrap_or(&self.host[..]);
                (n.as_str(), display_user, display_host)
            }
            _ => return None,
        };
        Some(format!("{}!{}@{}", n, u, h))
    }

    pub fn nick_or_id(&self) -> &str {
        self.nick.as_deref().unwrap_or(&self.id)
    }

    /// Host to show in WHO/WHOIS (vhost if set, else real host).
    pub fn display_host(&self) -> &str {
        self.vhost.as_deref().unwrap_or(self.host.as_str())
    }

    /// Username to show in WHO/WHOIS (vuser if set, else real user).
    pub fn display_user(&self) -> &str {
        self.vuser
            .as_deref()
            .unwrap_or_else(|| self.user.as_deref().unwrap_or("user"))
    }

    /// May this operator do `privilege`? Non-operators may not.
    pub fn may(&self, privilege: crate::config::OperPrivilege) -> bool {
        if !self.oper {
            return false;
        }
        match self.oper_privileges {
            None => true,
            Some(ref list) => list
                .iter()
                .any(|p| p.eq_ignore_ascii_case(privilege.name())),
        }
    }

    pub fn has_cap(&self, cap: &str) -> bool {
        self.capabilities.contains(cap)
    }
}

/// Pending (unregistered) connection
#[derive(Debug)]
pub struct PendingConnection {
    pub host: String,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub pass: Option<String>,
    pub capabilities: HashSet<String>,
    pub cap_ended: bool,
    /// True if client sent CAP LS (we wait for CAP END). False = legacy client, complete when we have NICK+USER.
    pub cap_negotiating: bool,
    pub account: Option<String>,
    /// Pre-away: AWAY during registration (applied when client completes registration)
    pub away_message: Option<String>,
    /// SASL PLAIN: accumulated base64 chunks (client may send in multiple AUTHENTICATE lines)
    pub sasl_plain_buffer: String,
    /// SASL PLAIN: number of chunks appended so far (for INFO logging).
    pub sasl_chunk_count: u32,
    /// True after we sent 904 for this connection; ignore further AUTHENTICATE so we don't later "succeed".
    pub sasl_failed: bool,
    /// Current SASL mechanism ("PLAIN" or "SCRAM-SHA-256"); set on first AUTHENTICATE
    pub sasl_mechanism: Option<String>,
    /// SCRAM-SHA-256: intermediate server state (set after step 1, consumed in step 2)
    pub sasl_scram: Option<ScramServerState>,
    /// True if this connection is over TLS
    pub is_tls: bool,
}

impl PendingConnection {
    pub fn new(host: String) -> Self {
        Self {
            host,
            nick: None,
            user: None,
            realname: None,
            pass: None,
            capabilities: HashSet::new(),
            cap_ended: false,
            cap_negotiating: false,
            account: None,
            away_message: None,
            sasl_plain_buffer: String::new(),
            sasl_chunk_count: 0,
            sasl_failed: false,
            sasl_mechanism: None,
            sasl_scram: None,
            is_tls: false,
        }
    }

    /// Ready to complete registration: have NICK+USER, either legacy client or CAP END, and SASL
    /// is not actively in progress (if the client requested the sasl cap, wait for it to complete).
    pub fn ready_to_register(&self) -> bool {
        let sasl_in_progress =
            self.sasl_mechanism.is_some() && self.account.is_none() && !self.sasl_failed;
        self.nick.is_some()
            && self.user.is_some()
            && (!self.cap_negotiating || self.cap_ended)
            && !sasl_in_progress
    }
}

use std::collections::HashSet;

/// Bounded store for message redaction: msgid -> (target channel/nick, sender_id).
const MAX_MSGID_ENTRIES: usize = 10000;

#[derive(Debug, Default)]
pub struct MsgIdStore {
    map: HashMap<String, (String, String)>,
    order: VecDeque<String>,
}

impl MsgIdStore {
    pub fn record(&mut self, msgid: String, target: String, sender_id: String) {
        if self.map.contains_key(&msgid) {
            return;
        }
        while self.map.len() >= MAX_MSGID_ENTRIES {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.order.push_back(msgid.clone());
        self.map.insert(msgid, (target, sender_id));
    }

    pub fn get(&self, msgid: &str) -> Option<(&str, &str)> {
        self.map.get(msgid).map(|(t, s)| (t.as_str(), s.as_str()))
    }

    /// Remove and return entry for msgid.
    pub fn take(&mut self, msgid: &str) -> Option<(String, String)> {
        let out = self.map.remove(msgid);
        if out.is_some() {
            self.order.retain(|k| k != msgid);
        }
        out
    }
}

/// Glob matching: `*` matches any sequence of chars, `?` matches any single char.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (pl, tl) = (p.len(), t.len());
    let mut dp = vec![vec![false; tl + 1]; pl + 1];
    dp[0][0] = true;
    for i in 1..=pl {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=pl {
        for j in 1..=tl {
            dp[i][j] = if p[i - 1] == '*' {
                dp[i - 1][j] || dp[i][j - 1]
            } else if p[i - 1] == '?' || p[i - 1] == t[j - 1] {
                dp[i - 1][j - 1]
            } else {
                false
            };
        }
    }
    dp[pl][tl]
}

/// Reverse index: nick (lowercase) -> set of client_ids that have this nick in their monitor list.
/// Used to send 730/731 only to watchers.
#[derive(Debug, Default)]
pub struct MonitorWatchers {
    pub by_nick: HashMap<String, std::collections::HashSet<String>>,
    /// extended-monitor: glob pattern -> set of client_ids watching that pattern.
    pub by_pattern: HashMap<String, std::collections::HashSet<String>>,
}

impl MonitorWatchers {
    pub fn add(&mut self, nick_lower: String, client_id: String) {
        self.by_nick
            .entry(nick_lower)
            .or_default()
            .insert(client_id);
    }
    pub fn remove(&mut self, nick_lower: &str, client_id: &str) {
        if let Some(set) = self.by_nick.get_mut(nick_lower) {
            set.remove(client_id);
            if set.is_empty() {
                self.by_nick.remove(nick_lower);
            }
        }
    }
    /// extended-monitor: add a glob pattern watcher.
    pub fn add_pattern(&mut self, pattern: String, client_id: String) {
        self.by_pattern
            .entry(pattern)
            .or_default()
            .insert(client_id);
    }
    /// extended-monitor: remove a glob pattern watcher.
    pub fn remove_pattern(&mut self, pattern: &str, client_id: &str) {
        if let Some(set) = self.by_pattern.get_mut(pattern) {
            set.remove(client_id);
            if set.is_empty() {
                self.by_pattern.remove(pattern);
            }
        }
    }
    /// Remove client_id from all nicks' watcher sets (e.g. on QUIT).
    pub fn remove_client(&mut self, client_id: &str, nicks: &std::collections::HashSet<String>) {
        for nick in nicks {
            self.remove(nick, client_id);
        }
    }
    /// Remove client_id from all pattern watcher sets (e.g. on QUIT).
    pub fn remove_client_patterns(
        &mut self,
        client_id: &str,
        patterns: &std::collections::HashSet<String>,
    ) {
        for pat in patterns {
            self.remove_pattern(pat, client_id);
        }
    }
    pub fn watchers(&self, nick_lower: &str) -> Option<&std::collections::HashSet<String>> {
        self.by_nick.get(nick_lower)
    }
    /// Return all client_ids whose patterns match `source_lower` (nick!user@host lowercase).
    pub fn pattern_watchers_for(&self, source_lower: &str) -> Vec<String> {
        let mut result = Vec::new();
        for (pat, clients) in &self.by_pattern {
            if glob_match(pat, source_lower) {
                result.extend(clients.iter().cloned());
            }
        }
        result
    }
}

/// The outbound side of one client connection.
///
/// Sends never wait. Every command in the server is handled by a single loop, so
/// awaiting a client that has stopped draining its queue would stall the server
/// for everyone; a client that falls that far behind is disconnected instead,
/// which is what "SendQ exceeded" has always meant on IRC.
#[derive(Clone, Debug)]
pub struct ClientSink {
    tx: mpsc::Sender<Message>,
    kill: Arc<tokio::sync::Notify>,
}

impl ClientSink {
    pub fn new(tx: mpsc::Sender<Message>, kill: Arc<tokio::sync::Notify>) -> Self {
        Self { tx, kill }
    }

    /// Send a last message and close the connection — how a server drops a client
    /// it has killed or banned, rather than leaving the socket open until the
    /// ping timeout notices.
    pub fn close(&self, msg: Message) {
        let _ = self.tx.try_send(msg);
        self.kill.notify_one();
    }

    /// Queue a message. Returns false if it could not be queued, in which case
    /// the connection has been marked for disconnection.
    pub fn send(&self, msg: Message) -> bool {
        match self.tx.try_send(msg) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // notify_one leaves a permit, so the connection sees this even if
                // it is not waiting on the signal at this instant.
                self.kill.notify_one();
                false
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// Outbound channels for every connected client, keyed by client id.
pub type Senders = Arc<RwLock<HashMap<String, ClientSink>>>;

/// Shared server state: all clients and channels
#[derive(Debug, Default)]
pub struct ServerState {
    pub clients: HashMap<String, Arc<RwLock<Client>>>,
    pub pending: HashMap<String, PendingConnection>,
    pub nick_to_id: HashMap<String, String>,
    pub msgid_store: MsgIdStore,
    pub monitor_watchers: MonitorWatchers,
    /// draft/read-marker: account_or_client -> target -> timestamp (ISO 8601)
    pub read_markers: HashMap<String, HashMap<String, String>>,
    /// draft/metadata-2: target (nick or #channel) -> key -> value
    pub metadata: HashMap<String, HashMap<String, String>>,
    /// draft/multiline: client_id -> in-flight batch (ref, target, command, lines)
    pub pending_multiline: HashMap<String, PendingMultilineBatch>,
    /// draft/client-batch: client_id -> in-flight generic client batch
    pub pending_client_batches: HashMap<String, PendingClientBatch>,
    /// WHOWAS history: nick_lower -> recent entries
    pub whowas: HashMap<String, VecDeque<WhowasEntry>>,
    /// Server start time (Unix timestamp)
    pub started_at: i64,
    /// Path to the config file on disk (used by REHASH to reload)
    pub config_path: Option<std::path::PathBuf>,
    /// TLS client certificate fingerprints: client_id → SHA-256 hex (for SASL EXTERNAL)
    pub certfps: HashMap<String, String>,
    /// Accounts known to be in each channel, including ones that are not
    /// connected right now. Used to notify absent users of mentions.
    pub channel_accounts: HashMap<String, HashSet<String>>,
    /// How many times each command has been handled, for STATS m.
    pub command_counts: HashMap<String, u64>,
    /// Server bans, matched on connection. Kept in memory so a connection never
    /// waits on the database.
    pub server_bans: Vec<crate::persist::ServerBan>,
}

/// In-flight draft/multiline batch for one client
#[derive(Debug)]
pub struct PendingMultilineBatch {
    pub ref_tag: String,
    pub target: String,
    pub command: String,
    pub lines: Vec<(bool, String)>,
}

/// In-flight draft/client-batch for one client
#[derive(Debug)]
pub struct PendingClientBatch {
    pub ref_tag: String,
    pub batch_type: String,
    pub target: String,
    pub messages: Vec<Message>,
}

impl ServerState {
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            started_at: chrono::Utc::now().timestamp(),
            ..Default::default()
        }))
    }

    /// Record a WHOWAS entry for the given client (call before removing the client or changing nick).
    /// Uses display_host/display_user to respect cloaking — WHOWAS should not leak real IPs.
    pub fn record_whowas(&mut self, client: &Client, server_name: &str) {
        let nick = match &client.nick {
            Some(n) => n.clone(),
            None => return,
        };
        let entry = WhowasEntry {
            nick: nick.clone(),
            user: client.display_user().to_string(),
            host: client.display_host().to_string(),
            realname: client.realname.as_deref().unwrap_or("").to_string(),
            server: server_name.to_string(),
            timestamp: Utc::now().timestamp(),
        };
        self.push_whowas(entry);
    }

    /// Record WHOWAS for a killed client by client_id (used by KILL handler).
    /// Uses display_host/display_user to respect cloaking.
    pub fn record_whowas_for_kill(&mut self, client_id: &str, server_name: &str) {
        let entry_opt = if let Some(c) = self.clients.get(client_id) {
            if let Ok(g) = c.try_read() {
                g.nick.as_ref().map(|nick| WhowasEntry {
                    nick: nick.clone(),
                    user: g.display_user().to_string(),
                    host: g.display_host().to_string(),
                    realname: g.realname.as_deref().unwrap_or("").to_string(),
                    server: server_name.to_string(),
                    timestamp: chrono::Utc::now().timestamp(),
                })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(entry) = entry_opt {
            self.push_whowas(entry);
        }
    }

    /// Push an already-built WhowasEntry (useful when the client borrow conflicts with &mut self).
    pub fn push_whowas(&mut self, entry: WhowasEntry) {
        let key = entry.nick.to_lowercase();
        let list = self.whowas.entry(key).or_default();
        list.push_back(entry);
        while list.len() > MAX_WHOWAS {
            list.pop_front();
        }
    }

    pub async fn add_client(&mut self, client: Client) -> Arc<RwLock<Client>> {
        let id = client.id.clone();
        let client = Arc::new(RwLock::new(client));
        self.clients.insert(id.clone(), client.clone());
        if let Some(ref nick) = client.read().await.nick {
            self.nick_to_id.insert(nick.to_uppercase(), id);
        }
        client
    }

    pub async fn remove_client(&mut self, id: &str) -> Option<Arc<RwLock<Client>>> {
        let client = self.clients.remove(id)?;
        let nick = client.read().await.nick.clone();
        if let Some(ref n) = nick {
            self.nick_to_id.remove(&n.to_uppercase());
        }
        Some(client)
    }

    pub async fn get_client(&self, id: &str) -> Option<Arc<RwLock<Client>>> {
        self.clients.get(id).cloned()
    }

    pub async fn get_client_by_nick(&self, nick: &str) -> Option<Arc<RwLock<Client>>> {
        let id = self.nick_to_id.get(&nick.to_uppercase())?;
        self.clients.get(id).cloned()
    }

    pub fn get_or_create_pending(&mut self, client_id: &str, host: &str) -> &mut PendingConnection {
        self.pending
            .entry(client_id.to_string())
            .or_insert_with(|| PendingConnection::new(host.to_string()))
    }

    /// The ban matching this user, if any. Expired entries are ignored.
    pub fn matching_ban(&self, source: &str, ip: &str) -> Option<&crate::persist::ServerBan> {
        let now = Utc::now().timestamp();
        let source_lower = source.to_lowercase();
        let ip_forms = [format!("*!*@{}", ip.to_lowercase()), ip.to_lowercase()];
        self.server_bans.iter().find(|ban| {
            if ban.is_expired(now) {
                return false;
            }
            let mask = ban.mask.to_lowercase();
            glob_match(&mask, &source_lower) || ip_forms.iter().any(|f| glob_match(&mask, f))
        })
    }

    pub fn record_msgid(&mut self, msgid: String, target: String, sender_id: String) {
        self.msgid_store.record(msgid, target, sender_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn msg() -> Message {
        Message::new("PRIVMSG", vec!["#chan".into(), "hi".into()])
    }

    /// The whole server is driven by one loop, so a send to a client that has
    /// stopped reading must fail immediately and mark that client for
    /// disconnection rather than wait for space.
    #[tokio::test]
    async fn sink_never_waits_on_a_full_queue() {
        let (tx, _rx) = mpsc::channel(1);
        let kill = Arc::new(tokio::sync::Notify::new());
        let sink = ClientSink::new(tx, kill.clone());

        assert!(sink.send(msg()), "first message fits");
        assert!(!sink.send(msg()), "second message must not block");

        tokio::time::timeout(Duration::from_secs(1), kill.notified())
            .await
            .expect("the connection is signalled to close");
    }

    #[tokio::test]
    async fn sink_reports_a_closed_connection() {
        let (tx, rx) = mpsc::channel(4);
        let kill = Arc::new(tokio::sync::Notify::new());
        let sink = ClientSink::new(tx, kill.clone());
        drop(rx);

        assert!(!sink.send(msg()), "a closed connection cannot be sent to");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), kill.notified())
                .await
                .is_err(),
            "an already-closed connection needs no kill signal"
        );
    }
}
