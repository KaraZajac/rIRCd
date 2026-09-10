use crate::channel::ChannelMembership;
use crate::protocol::Message;
use chrono::Utc;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

// ─── WHOWAS ───────────────────────────────────────────────────────────────────

const MAX_WHOWAS: usize = 5;
/// Nicks kept in the in-memory WHOWAS record. Past this the oldest name goes;
/// the database keeps a longer tail for the ones that matter.
const MAX_WHOWAS_NICKS: usize = 10_000;

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
    /// User mode +R: only people with an account may send direct messages.
    /// Advertised in `USERMODES`, so it has to do something.
    pub registered_only: bool,
    /// Unix timestamp when the client completed registration (for WHOIS 317)
    pub signon_at: i64,
    /// Unix timestamp of the last message received from this client (for WHOIS 317 idle)
    pub last_active: i64,
    /// draft/metadata-2: keys this client has subscribed to for change notifications
    pub metadata_subscriptions: std::collections::HashSet<String>,
    /// True if this connection is over TLS (used for STS policy and WHOIS secure line)
    pub is_tls: bool,
    /// Connections this user is reading on. Its own id is the first of them.
    /// A user on another server has none.
    pub sessions: Vec<String>,
    /// When this user took the nick it holds. A nick collision across a link is
    /// settled by this: the older claim keeps the name.
    pub nick_ts: i64,
    /// The server this user is on, when it is not this one. Remote users are
    /// carried in the same tables as local ones — a nick is a nick wherever it
    /// is — and this is what tells them apart.
    pub server: Option<String>,
}

impl Client {
    /// A new user. `id` is the user's own id — its UID on a linked network —
    /// and `session_id` the connection it arrived on, which is a different
    /// string as soon as a user can have more than one.
    /// A user whose id is also the connection it is on. Used where there is no
    /// separate user id yet: an unregistered connection, and the tests.
    pub fn new(id: String, host: String) -> Self {
        let session = id.clone();
        Self::new_on(id, session, host)
    }

    pub fn new_on(id: String, session_id: String, host: String) -> Self {
        let id_for_sessions = session_id;
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
            registered_only: false,
            signon_at: Utc::now().timestamp(),
            last_active: Utc::now().timestamp(),
            metadata_subscriptions: std::collections::HashSet::new(),
            is_tls: false,
            sessions: vec![id_for_sessions],
            nick_ts: Utc::now().timestamp(),
            server: None,
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
    /// When the credential check now running stops counting as in flight.
    ///
    /// Checking a password does not happen on the loop that serves everybody,
    /// so the answer arrives after the client has said whatever else it meant
    /// to say. Until then the attempt is still live: ending capability
    /// negotiation must not abandon it, and registration must not finish
    /// without it. It is a deadline rather than a flag so that a check which
    /// somehow never reports back cannot hold a connection open for ever.
    pub sasl_check_until: Option<std::time::Instant>,
    /// Current SASL mechanism ("PLAIN" or "SCRAM-SHA-256"); set on first AUTHENTICATE
    pub sasl_mechanism: Option<String>,
    /// SCRAM-SHA-256: intermediate server state (set after step 1, consumed in step 2)
    pub sasl_scram: Option<ScramServerState>,
    /// True if this connection is over TLS
    pub is_tls: bool,
    /// A nick this connection asked for and was refused because someone else
    /// holds it. REGISTER uses it to say the account is taken rather than that
    /// no nick was given.
    pub nick_in_use: Option<String>,
    /// draft/metadata before-connect: keys set during registration, moved to
    /// the user's own store once it has a nick to file them under.
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl PendingConnection {
    pub fn new(host: String) -> Self {
        Self {
            host,
            nick: None,
            user: None,
            realname: None,
            pass: None,
            metadata: std::collections::BTreeMap::new(),
            capabilities: HashSet::new(),
            cap_ended: false,
            cap_negotiating: false,
            account: None,
            away_message: None,
            sasl_plain_buffer: String::new(),
            sasl_chunk_count: 0,
            sasl_failed: false,
            sasl_check_until: None,
            sasl_mechanism: None,
            sasl_scram: None,
            is_tls: false,
            nick_in_use: None,
        }
    }

    /// True while a credential check for this connection is still expected to
    /// report back.
    pub fn sasl_checking(&self) -> bool {
        self.sasl_check_until
            .is_some_and(|until| std::time::Instant::now() < until)
    }

    /// Ready to complete registration: have NICK+USER, either legacy client or CAP END, and SASL
    /// is not actively in progress (if the client requested the sasl cap, wait for it to complete).
    pub fn ready_to_register(&self) -> bool {
        // Only wait for SASL if the client asked for it. An AUTHENTICATE from a
        // client that never negotiated the capability must not hold its
        // registration open for ever.
        let sasl_in_progress = self.sasl_checking()
            || (self.capabilities.contains("sasl")
                && self.sasl_mechanism.is_some()
                && self.account.is_none()
                && !self.sasl_failed);
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
/// Match an IRC mask such as `nick!user@host` against a source.
///
/// Nicks, usernames and hostnames are all case-insensitive in IRC, so a ban on
/// `bar!*@*` has to catch `Bar!user@host` — otherwise changing the case of a
/// nick walks straight through a ban.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = crate::casefold::lower(pattern).chars().collect();
    let t: Vec<char> = crate::casefold::lower(text).chars().collect();

    // Greedy match with one backtrack point, rather than a full dynamic
    // programming table: every ban, except and invite mask on a channel is
    // matched against every joining user, and a table costs
    // pattern x source bytes of scratch each time it is asked.
    let (mut i, mut j) = (0usize, 0usize);
    // Where the last `*` was, and how much of the text it has been made to
    // swallow so far. `None` means we have not seen one yet, so a mismatch
    // is final.
    let mut star: Option<usize> = None;
    let mut swallowed = 0usize;

    while j < t.len() {
        if i < p.len() && (p[i] == '?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            swallowed = j;
        } else if let Some(s) = star {
            // Give the `*` one more character and try the rest again.
            i = s + 1;
            swallowed += 1;
            j = swallowed;
        } else {
            return false;
        }
    }

    // Trailing `*`s match the empty remainder.
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
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
/// The connections the server can write to, and which user each belongs to.
///
/// A user may hold more than one connection at a time — a desktop and a phone
/// on the same account. Replies to a command go back to the connection that
/// sent it; anything addressed to the *user* goes to all of them. Keeping both
/// in one place is what lets the rest of the server carry on addressing a
/// single id without knowing which kind it is.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    /// One entry per live connection, keyed by its own id.
    sinks: HashMap<String, ClientSink>,
    /// Sessions belonging to each user, keyed by the user's id. The user's id
    /// is the id of the session that created it, and that session is in here
    /// too, so a user with one connection has one entry pointing at itself.
    sessions: HashMap<String, Vec<String>>,
    /// What each connection negotiated. Capabilities belong to a connection,
    /// not to the account behind it: one may speak IRCv3 and another not.
    session_caps: HashMap<String, std::collections::HashSet<String>>,
}

impl SessionRegistry {
    /// The sink for one connection. Used for replies, which belong to the
    /// connection that asked and not to the user's other ones.
    pub fn get(&self, session_id: &str) -> Option<&ClientSink> {
        self.sinks.get(session_id)
    }

    /// Add a connection, as a user's first session or an additional one.
    pub fn insert_session(&mut self, user_id: &str, session_id: &str, sink: ClientSink) {
        self.sinks.insert(session_id.to_string(), sink);
        let sessions = self.sessions.entry(user_id.to_string()).or_default();
        if !sessions.iter().any(|s| s == session_id) {
            sessions.push(session_id.to_string());
        }
    }

    /// Forget one connection. Returns its sink, and whether the user has any
    /// connections left.
    pub fn remove_session(
        &mut self,
        user_id: &str,
        session_id: &str,
    ) -> (Option<ClientSink>, bool) {
        let sink = self.sinks.remove(session_id);
        let mut any_left = false;
        if let Some(sessions) = self.sessions.get_mut(user_id) {
            sessions.retain(|s| s != session_id);
            any_left = !sessions.is_empty();
            if !any_left {
                self.sessions.remove(user_id);
            }
        }
        (sink, any_left)
    }

    /// Forget a connection without knowing which user it belongs to.
    pub fn remove(&mut self, id: &str) -> Option<ClientSink> {
        for sessions in self.sessions.values_mut() {
            sessions.retain(|s| s != id);
        }
        self.sessions.retain(|_, v| !v.is_empty());
        self.session_caps.remove(id);
        self.sinks.remove(id)
    }

    /// Every connection a user has. Falls back to the id itself so an id that
    /// names a connection rather than a user still reaches something.
    pub fn sessions_of(&self, user_id: &str) -> Vec<String> {
        match self.sessions.get(user_id) {
            Some(sessions) => sessions.clone(),
            None => vec![user_id.to_string()],
        }
    }

    /// What one connection negotiated.
    pub fn caps_of(&self, session_id: &str) -> std::collections::HashSet<String> {
        self.session_caps
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn set_session_caps(&mut self, session_id: &str, caps: std::collections::HashSet<String>) {
        self.session_caps.insert(session_id.to_string(), caps);
    }

    /// Everything any of a user's connections negotiated. Messages are built
    /// for this set and trimmed back per connection on the way out, so a
    /// capability one connection asked for is not lost because another did not.
    pub fn union_caps(&self, user_id: &str) -> std::collections::HashSet<String> {
        let mut union = std::collections::HashSet::new();
        for session in self.sessions_of(user_id) {
            if let Some(caps) = self.session_caps.get(&session) {
                union.extend(caps.iter().cloned());
            }
        }
        union
    }

    /// Send to every connection a user has, each seeing only the tags it
    /// negotiated.
    pub fn deliver(&self, user_id: &str, msg: &Message) {
        self.deliver_to(user_id, None, msg)
    }

    /// Send to every connection a user has except one.
    ///
    /// The connection that sent a command is answered for separately — with the
    /// label it asked under, and only if it asked to see its own message at all.
    /// Its owner's other connections did not send anything, so they see the
    /// event the way everybody else in the channel does.
    pub fn deliver_except(&self, user_id: &str, except: &str, msg: &Message) {
        self.deliver_to(user_id, Some(except), msg)
    }

    /// Send to a user's connections, giving each the form it asked for.
    ///
    /// A capability is negotiated by a connection, not by the person behind it.
    /// One client may have asked for `away-notify` and another not, and a user's
    /// capabilities are the union of its connections' — so deciding from that
    /// whether to send at all would hand the second client a message it never
    /// agreed to parse. `with` goes to the connections that negotiated `cap`,
    /// `without` to the rest, and either may be nothing at all.
    pub fn deliver_by_cap(
        &self,
        user_id: &str,
        cap: &str,
        with: Option<&Message>,
        without: Option<&Message>,
    ) {
        self.deliver_by_cap_except(user_id, cap, None, with, without)
    }

    /// The same, skipping the connection that caused the event.
    pub fn deliver_by_cap_except(
        &self,
        user_id: &str,
        cap: &str,
        except: Option<&str>,
        with: Option<&Message>,
        without: Option<&Message>,
    ) {
        for session in self.sessions_of(user_id) {
            if Some(session.as_str()) == except {
                continue;
            }
            let Some(sink) = self.sinks.get(&session) else {
                continue;
            };
            let caps = self.caps_of(&session);
            let Some(msg) = (if caps.contains(cap) { with } else { without }) else {
                continue;
            };
            let mut copy = msg.clone();
            if !copy.tags.is_empty() {
                crate::protocol::retain_negotiated_tags(&mut copy, &caps);
            }
            sink.send(copy);
        }
    }

    /// Send only to the connections that asked for a capability. The shorthand
    /// for an event that exists because of one.
    pub fn deliver_requiring(&self, user_id: &str, cap: &str, msg: &Message) {
        self.deliver_by_cap(user_id, cap, Some(msg), None)
    }

    /// The same, skipping the connection that caused the event.
    pub fn deliver_requiring_except(
        &self,
        user_id: &str,
        cap: &str,
        except: Option<&str>,
        msg: &Message,
    ) {
        self.deliver_by_cap_except(user_id, cap, except, Some(msg), None)
    }

    /// Which of a user's connections negotiated a capability, for the few
    /// events that are more than one message either way.
    pub fn sessions_with_cap(&self, user_id: &str, cap: &str, want: bool) -> Vec<String> {
        self.sessions_of(user_id)
            .into_iter()
            .filter(|s| self.caps_of(s).contains(cap) == want)
            .collect()
    }

    fn deliver_to(&self, user_id: &str, except: Option<&str>, msg: &Message) {
        for session in self.sessions_of(user_id) {
            if Some(session.as_str()) == except {
                continue;
            }
            let Some(sink) = self.sinks.get(&session) else {
                continue;
            };
            if msg.tags.is_empty() {
                sink.send(msg.clone());
                continue;
            }
            let mut copy = msg.clone();
            crate::protocol::retain_negotiated_tags(&mut copy, &self.caps_of(&session));
            sink.send(copy);
        }
    }

    pub fn contains(&self, session_id: &str) -> bool {
        self.sinks.contains_key(session_id)
    }

    /// Move a connection that was its own user into another user's set of
    /// sessions, keeping its sink.
    pub fn reassign_session(&mut self, user_id: &str, session_id: &str) {
        self.sessions.remove(session_id);
        let sessions = self.sessions.entry(user_id.to_string()).or_default();
        if !sessions.iter().any(|s| s == session_id) {
            sessions.push(session_id.to_string());
        }
    }

    /// Disconnect a user: every connection it has, not just one of them.
    /// Killing a user that left another session open would leave that session
    /// on the server after the user was told it was gone.
    pub fn close_user(&mut self, user_id: &str, msg: Message) {
        for session in self.sessions_of(user_id) {
            if let Some(sink) = self.sinks.remove(&session) {
                sink.close(msg.clone());
            }
            self.session_caps.remove(&session);
        }
        self.sessions.remove(user_id);
    }

    /// Every live connection, for the few things addressed to the whole server.
    pub fn all_sinks(&self) -> impl Iterator<Item = &ClientSink> {
        self.sinks.values()
    }
}

pub type Senders = Arc<RwLock<SessionRegistry>>;

/// Shared server state: all clients and channels
#[derive(Debug, Default)]
pub struct ServerState {
    /// Every connection, keyed by its own id. All of a user's connections map
    /// to the same `Client`, so looking one up by any of its session ids finds
    /// the same nick, channels and account.
    pub clients: HashMap<String, Arc<RwLock<Client>>>,
    /// Which user each connection belongs to. A user's id is the id of the
    /// connection that created it, so for a user with one connection this maps
    /// an id to itself.
    pub session_to_user: HashMap<String, String>,
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
    /// This server's id on a linked network, and the counter behind the ids it
    /// gives its users. Empty until the server sets it at startup.
    pub sid: String,
    pub uid_counter: std::sync::atomic::AtomicU64,
    /// The nicks in `whowas`, oldest first. WHOWAS is a record of who was here
    /// recently, and without a bound on how many names it keeps, a map entry
    /// is left behind by every distinct nick that ever connected.
    pub whowas_order: VecDeque<String>,
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
    /// What each address has spent failing to log in. Checking a password is
    /// expensive on purpose, so an address that keeps getting it wrong is told
    /// no before anything is checked.
    pub auth_cost: crate::authcost::AuthCost,
    /// Most clients connected at once since start, for the `max` field of
    /// RPL_LOCALUSERS/RPL_GLOBALUSERS. Clients come and go, so the current
    /// count is not a high-water mark.
    pub max_clients: usize,
}

/// In-flight draft/multiline batch for one client
#[derive(Debug)]
pub struct PendingMultilineBatch {
    pub ref_tag: String,
    pub target: String,
    pub command: String,
    pub lines: Vec<(bool, String)>,
    /// The label from the opening BATCH. The whole response belongs to that
    /// command, but it is only delivered when the closing BATCH arrives.
    pub label: Option<String>,
    /// Client-only tags from the opening BATCH. They describe the message as a
    /// whole, so they are relayed on its opening line.
    pub tags: HashMap<String, Option<String>>,
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
        let key = crate::casefold::lower(&entry.nick);
        if !self.whowas.contains_key(&key) {
            self.whowas_order.push_back(key.clone());
        }
        let list = self.whowas.entry(key).or_default();
        list.push_back(entry);
        while list.len() > MAX_WHOWAS {
            list.pop_front();
        }
        while self.whowas.len() > MAX_WHOWAS_NICKS {
            match self.whowas_order.pop_front() {
                Some(oldest) => {
                    self.whowas.remove(&oldest);
                }
                None => break,
            }
        }
    }

    /// Whether a member id names the same user as the connection that sent a
    /// command.
    ///
    /// The two are different strings: a user has an id of its own, and may hold
    /// several connections. Comparing them directly was right only while every
    /// user had exactly one connection whose id it borrowed.
    pub fn is_self(&self, member_id: &str, session_id: &str) -> bool {
        self.user_id(session_id) == member_id
    }

    /// The user a connection belongs to. An id that names no known connection
    /// is returned unchanged, so callers that already hold a user id are safe.
    pub fn user_id(&self, session_id: &str) -> String {
        self.session_to_user
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| session_id.to_string())
    }

    pub async fn add_client(&mut self, client: Client, session_id: &str) -> Arc<RwLock<Client>> {
        let id = client.id.clone();
        let client = Arc::new(RwLock::new(client));
        self.clients.insert(id.clone(), client.clone());
        // The user answers to its own id, and so does the connection it came in
        // on — which is a different string once users have ids of their own.
        self.session_to_user.insert(id.clone(), id.clone());
        if session_id != id {
            self.clients.insert(session_id.to_string(), client.clone());
            self.session_to_user
                .insert(session_id.to_string(), id.clone());
        }
        self.max_clients = self.max_clients.max(self.user_count());
        if let Some(ref nick) = client.read().await.nick {
            self.nick_to_id.insert(crate::casefold::upper(nick), id);
        }
        client
    }

    /// Record a user that is on another server. It has no connection here, so
    /// nothing writes to it directly — anything addressed to it goes out over
    /// the link it came from — but it holds a nick, and everything that asks
    /// about nicks has to find it.
    pub async fn add_remote_user(&mut self, client: Client) -> Arc<RwLock<Client>> {
        let id = client.id.clone();
        let nick = client.nick.clone();
        let client = Arc::new(RwLock::new(client));
        self.clients.insert(id.clone(), client.clone());
        self.session_to_user.insert(id.clone(), id.clone());
        if let Some(nick) = nick {
            self.nick_to_id.insert(crate::casefold::upper(&nick), id);
        }
        self.max_clients = self.max_clients.max(self.user_count());
        client
    }

    /// Every user here, once each.
    ///
    /// The client table answers to a user's own id and to every connection id
    /// that reaches it, so iterating it counts a user with two connections
    /// twice — and with ids of their own, every user has at least two entries.
    pub fn users(&self) -> impl Iterator<Item = (&String, &Arc<RwLock<Client>>)> {
        self.clients.iter().filter(|(id, _)| {
            self.session_to_user
                .get(*id)
                .map(|user| user == *id)
                .unwrap_or(true)
        })
    }

    /// How many people are here, as against how many connections.
    pub fn user_count(&self) -> usize {
        self.users().count()
    }

    /// Remove a user and every connection it had.
    pub async fn remove_client(&mut self, id: &str) -> Option<Arc<RwLock<Client>>> {
        let user_id = self.user_id(id);
        let client = self.clients.get(&user_id).cloned()?;
        let sessions = client.read().await.sessions.clone();
        for session in &sessions {
            self.clients.remove(session);
            self.session_to_user.remove(session);
        }
        self.clients.remove(&user_id);
        self.session_to_user.remove(&user_id);
        let (nick, account) = {
            let g = client.read().await;
            (g.nick.clone(), g.account.clone())
        };
        if let Some(ref n) = nick {
            self.nick_to_id.remove(&crate::casefold::upper(n));
            // Metadata is filed under the nick, and a nick with no account
            // behind it belongs to whoever holds it next. Leaving the keys
            // there would hand somebody else's display name and avatar to the
            // next person to take the name, and would grow without bound as
            // names came and went.
            if account.is_none() {
                self.metadata.remove(&crate::casefold::upper(n));
            }
        }
        Some(client)
    }

    /// Add another connection to a user that is already here.
    pub async fn attach_session(&mut self, user_id: &str, session_id: &str) -> bool {
        let Some(client) = self.clients.get(user_id).cloned() else {
            return false;
        };
        {
            let mut guard = client.write().await;
            if !guard.sessions.iter().any(|s| s == session_id) {
                guard.sessions.push(session_id.to_string());
            }
        }
        self.clients.insert(session_id.to_string(), client);
        self.session_to_user
            .insert(session_id.to_string(), user_id.to_string());
        true
    }

    /// Drop one connection. Returns whether the user still has others; when it
    /// has none the caller removes the user itself.
    pub async fn detach_session(&mut self, session_id: &str) -> bool {
        let user_id = self.user_id(session_id);
        let Some(client) = self.clients.get(&user_id).cloned() else {
            return false;
        };
        let remaining = {
            let mut guard = client.write().await;
            guard.sessions.retain(|s| s != session_id);
            guard.sessions.len()
        };
        // The connection the user was created from keeps its entry until the
        // user itself goes, because its id is the user's id.
        if session_id != user_id {
            self.clients.remove(session_id);
            self.session_to_user.remove(session_id);
        }
        remaining > 0
    }

    pub async fn get_client(&self, id: &str) -> Option<Arc<RwLock<Client>>> {
        self.clients.get(id).cloned()
    }

    pub async fn get_client_by_nick(&self, nick: &str) -> Option<Arc<RwLock<Client>>> {
        let id = self.nick_to_id.get(&crate::casefold::upper(nick))?;
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
        let source_lower = crate::casefold::lower(source);
        let ip_forms = [format!("*!*@{}", ip.to_lowercase()), ip.to_lowercase()];
        self.server_bans.iter().find(|ban| {
            if ban.is_expired(now) {
                return false;
            }
            let mask = crate::casefold::lower(&ban.mask);
            glob_match(&mask, &source_lower) || ip_forms.iter().any(|f| glob_match(&mask, f))
        })
    }

    pub fn record_msgid(&mut self, msgid: String, target: String, sender_id: String) {
        self.msgid_store.record(msgid, target, sender_id);
    }
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    /// A ban on `bar!*@*` has to catch `Bar!user@host`: matching by case let
    /// anyone walk through a ban by capitalising their nick.
    #[test]
    fn masks_match_regardless_of_case() {
        assert!(glob_match("bar!*@*", "Bar!username@127.0.0.1"));
        assert!(glob_match("BAR!*@*", "bar!username@127.0.0.1"));
        assert!(glob_match("*!*@Example.COM", "nick!user@example.com"));
        assert!(!glob_match("baz!*@*", "Bar!username@127.0.0.1"));
    }

    /// The straightforward table-based glob, kept only to check the greedy one
    /// against. It is obviously correct and obviously too expensive to run on
    /// every join.
    fn glob_match_reference(pattern: &str, text: &str) -> bool {
        let p: Vec<char> = crate::casefold::lower(pattern).chars().collect();
        let t: Vec<char> = crate::casefold::lower(text).chars().collect();
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

    /// Exhaustively over a small alphabet: the fast matcher has to agree with
    /// the table on every pattern and every string, or a ban that used to hold
    /// stops holding.
    #[test]
    fn fast_glob_agrees_with_the_table() {
        let alphabet = ['a', 'b', '*', '?'];
        let mut patterns = vec![String::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for p in &patterns {
                for c in alphabet {
                    next.push(format!("{p}{c}"));
                }
            }
            patterns.extend(next);
        }
        let mut texts = vec![String::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for t in &texts {
                for c in ['a', 'b'] {
                    next.push(format!("{t}{c}"));
                }
            }
            texts.extend(next);
        }
        for p in &patterns {
            for t in &texts {
                assert_eq!(
                    glob_match(p, t),
                    glob_match_reference(p, t),
                    "pattern {p:?} against {t:?}"
                );
            }
        }
    }

    /// WHOWAS remembers who was here recently, not everyone who ever was: a
    /// server that never forgets a nick keeps a map entry for each one that
    /// ever connected, which is a leak an attacker can drive with a script.
    #[test]
    fn whowas_forgets_the_oldest_nicks() {
        let mut state = ServerState::default();
        let entry = |nick: &str| WhowasEntry {
            nick: nick.to_string(),
            user: "u".into(),
            host: "h".into(),
            realname: "r".into(),
            server: "s".into(),
            timestamp: 0,
        };

        for i in 0..(MAX_WHOWAS_NICKS + 500) {
            state.push_whowas(entry(&format!("nick{i}")));
        }
        assert_eq!(state.whowas.len(), MAX_WHOWAS_NICKS);
        assert!(
            !state.whowas.contains_key("nick0"),
            "the oldest nick should have gone"
        );
        assert!(state
            .whowas
            .contains_key(&format!("nick{}", MAX_WHOWAS_NICKS + 499)));

        // Several visits by one nick are still one entry in the record, with
        // the last few kept.
        let mut state = ServerState::default();
        for _ in 0..(MAX_WHOWAS + 3) {
            state.push_whowas(entry("recurring"));
        }
        assert_eq!(state.whowas.len(), 1);
        assert_eq!(state.whowas["recurring"].len(), MAX_WHOWAS);
        assert_eq!(state.whowas_order.len(), 1);
    }

    /// A mask built to make a backtracking matcher work hardest still has to
    /// come back, and without allocating a table the size of the two inputs.
    #[test]
    fn a_pathological_mask_still_terminates() {
        let mask = format!("{}b", "a*".repeat(200));
        let source = "a".repeat(400);
        assert!(!glob_match(&mask, &source));
        assert!(glob_match(&mask, &format!("{source}b")));
    }

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

#[cfg(test)]
mod session_tests {
    use super::*;
    use std::collections::HashSet;

    fn sink() -> (ClientSink, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(16);
        (
            ClientSink::new(tx, Arc::new(tokio::sync::Notify::new())),
            rx,
        )
    }

    fn caps(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn tagged() -> Message {
        let mut m = Message::new("PRIVMSG", vec!["#chan".into(), "hi".into()]);
        m.tags
            .insert("time".into(), Some("2026-01-01T00:00:00.000Z".into()));
        m.tags.insert("msgid".into(), Some("abc".into()));
        m
    }

    /// Anything addressed to the user reaches every connection it has open.
    #[tokio::test]
    async fn delivery_reaches_all_of_a_users_connections() {
        let mut registry = SessionRegistry::default();
        let (desktop, mut desktop_rx) = sink();
        let (phone, mut phone_rx) = sink();
        registry.insert_session("user", "user", desktop);
        registry.insert_session("user", "phone", phone);

        registry.deliver(
            "user",
            &Message::new("PRIVMSG", vec!["#chan".into(), "hi".into()]),
        );

        assert!(desktop_rx.try_recv().is_ok());
        assert!(phone_rx.try_recv().is_ok());
    }

    /// Capabilities belong to a connection, so each copy carries only the tags
    /// that connection negotiated. A client that never asked for tags may not
    /// be able to parse a line that has them.
    #[tokio::test]
    async fn each_connection_sees_only_the_tags_it_negotiated() {
        let mut registry = SessionRegistry::default();
        let (modern, mut modern_rx) = sink();
        let (plain, mut plain_rx) = sink();
        registry.insert_session("user", "user", modern);
        registry.insert_session("user", "plain", plain);
        registry.set_session_caps("user", caps(&["server-time", "message-tags"]));
        registry.set_session_caps("plain", caps(&[]));

        registry.deliver("user", &tagged());

        let to_modern = modern_rx.try_recv().expect("delivered");
        assert!(to_modern.tags.contains_key("time"));
        assert!(to_modern.tags.contains_key("msgid"));

        let to_plain = plain_rx.try_recv().expect("delivered");
        assert!(to_plain.tags.is_empty(), "got {:?}", to_plain.tags);
    }

    /// A message is built for everything any connection asked for, then trimmed
    /// per connection, so one connection's capability is not lost because
    /// another lacks it.
    #[tokio::test]
    async fn a_users_capabilities_are_the_union_of_its_connections() {
        let mut registry = SessionRegistry::default();
        let (a, _a_rx) = sink();
        let (b, _b_rx) = sink();
        registry.insert_session("user", "user", a);
        registry.insert_session("user", "phone", b);
        registry.set_session_caps("user", caps(&["server-time"]));
        registry.set_session_caps("phone", caps(&["message-tags"]));

        let union = registry.union_caps("user");
        assert!(union.contains("server-time"));
        assert!(union.contains("message-tags"));
    }

    /// A reply belongs to the connection that asked, not to the user's others.
    #[tokio::test]
    async fn a_reply_goes_only_to_the_connection_that_asked() {
        let mut registry = SessionRegistry::default();
        let (desktop, mut desktop_rx) = sink();
        let (phone, mut phone_rx) = sink();
        registry.insert_session("user", "user", desktop);
        registry.insert_session("user", "phone", phone);

        registry
            .get("phone")
            .expect("session is here")
            .send(Message::new("PONG", vec!["token".into()]));

        assert!(phone_rx.try_recv().is_ok());
        assert!(
            desktop_rx.try_recv().is_err(),
            "the other connection heard a reply that was not its own"
        );
    }

    /// An id that names no session still reaches the connection it names, so
    /// callers holding a plain connection id are not silently dropped.
    #[tokio::test]
    async fn an_unknown_user_falls_back_to_the_id_itself() {
        let registry = SessionRegistry::default();
        assert_eq!(registry.sessions_of("nobody"), vec!["nobody".to_string()]);
    }

}
