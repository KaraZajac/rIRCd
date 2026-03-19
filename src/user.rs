use crate::channel::ChannelMembership;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    /// Virtual host (cloak) shown to others; used in source() when set
    pub vhost: Option<String>,
    /// Virtual username shown to others; used in source() when set
    pub vuser: Option<String>,
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
            vhost: None,
            vuser: None,
        }
    }

    pub fn source(&self) -> Option<String> {
        let (n, u, h) = match (&self.nick, &self.user) {
            (Some(n), Some(u)) => {
                let display_user = self.vuser.as_deref().unwrap_or(u.as_str());
                let display_host = self.vhost.as_deref().map(|s| &s[..]).unwrap_or(&self.host[..]);
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
        }
    }

    /// Ready to complete registration: have NICK+USER and either legacy client or CAP END received
    pub fn ready_to_register(&self) -> bool {
        self.nick.is_some() && self.user.is_some() && (!self.cap_negotiating || self.cap_ended)
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

/// Reverse index: nick (lowercase) -> set of client_ids that have this nick in their monitor list.
/// Used to send 730/731 only to watchers.
#[derive(Debug, Default)]
pub struct MonitorWatchers {
    pub by_nick: HashMap<String, std::collections::HashSet<String>>,
}

impl MonitorWatchers {
    pub fn add(&mut self, nick_lower: String, client_id: String) {
        self.by_nick.entry(nick_lower).or_default().insert(client_id);
    }
    pub fn remove(&mut self, nick_lower: &str, client_id: &str) {
        if let Some(set) = self.by_nick.get_mut(nick_lower) {
            set.remove(client_id);
            if set.is_empty() {
                self.by_nick.remove(nick_lower);
            }
        }
    }
    /// Remove client_id from all nicks' watcher sets (e.g. on QUIT).
    pub fn remove_client(&mut self, client_id: &str, nicks: &std::collections::HashSet<String>) {
        for nick in nicks {
            self.remove(nick, client_id);
        }
    }
    pub fn watchers(&self, nick_lower: &str) -> Option<&std::collections::HashSet<String>> {
        self.by_nick.get(nick_lower)
    }
}

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
}

/// In-flight draft/multiline batch for one client
#[derive(Debug)]
pub struct PendingMultilineBatch {
    pub ref_tag: String,
    pub target: String,
    pub command: String,
    pub lines: Vec<(bool, String)>,
}

impl ServerState {
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self::default()))
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
        self.pending.entry(client_id.to_string()).or_insert_with(|| PendingConnection::new(host.to_string()))
    }

    pub fn record_msgid(&mut self, msgid: String, target: String, sender_id: String) {
        self.msgid_store.record(msgid, target, sender_id);
    }
}
