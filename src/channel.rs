use std::collections::{BTreeMap, HashSet};

/// Channel membership with mode prefixes
#[derive(Debug, Clone)]
pub struct ChannelMembership {
    pub client_id: String,
    pub modes: ChannelMemberModeSet,
}

#[derive(Debug, Clone, Default)]
pub struct ChannelMemberModeSet {
    pub op: bool,
    pub voice: bool,
    pub halfop: bool,
}

impl ChannelMemberModeSet {
    pub fn prefix(&self) -> &'static str {
        if self.op {
            "@"
        } else if self.halfop {
            "%"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }

    /// All prefixes in rank order (op, halfop, voice) for multi-prefix cap.
    pub fn prefixes_ordered(&self) -> String {
        let mut s = String::new();
        if self.op {
            s.push('@');
        }
        if self.halfop {
            s.push('%');
        }
        if self.voice {
            s.push('+');
        }
        s
    }
}

/// A channel on the server
#[derive(Debug)]
pub struct Channel {
    pub name: String,
    pub topic: Option<String>,
    pub topic_setter: Option<String>,
    pub topic_time: Option<i64>,
    pub members: BTreeMap<String, ChannelMembership>,
    pub modes: ChannelModeSet,
    pub key: Option<String>,
    pub invite_list: HashSet<String>,
    /// Ban list: hostmasks or ~a:account (account-extban)
    pub bans: Vec<String>,
    /// Quiet list (+q masks): user can join but not speak
    pub quiet_list: Vec<String>,
    /// Ban exceptions (+e masks): users matching these are exempt from bans
    pub ban_exceptions: Vec<String>,
    /// Invite exceptions (+I masks): users matching these can join invite-only channels
    pub invite_exceptions: Vec<String>,
    /// From channels.toml: nicks/accounts that get @ when they join
    pub persisted_operators: Vec<String>,
    /// From channels.toml: nicks/accounts that get + when they join
    pub persisted_voice: Vec<String>,
    /// Channel creation time (Unix timestamp); sent as 329 RPL_CREATIONTIME
    pub created_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ChannelModeSet {
    pub secret: bool,          // +s
    pub private: bool,         // +p
    pub invite_only: bool,     // +i
    pub topic_protect: bool,   // +t
    pub no_external: bool,     // +n
    pub moderated: bool,       // +m
    pub registered_only: bool, // +R: only authed users may join/speak
    pub no_colors: bool,       // +c: strip mIRC color codes
    pub no_ctcp: bool,         // +C: block CTCP to channel
    pub user_limit: Option<u32>,
}

impl Channel {
    pub fn new(name: String) -> Self {
        Self {
            name,
            topic: None,
            topic_setter: None,
            topic_time: None,
            members: BTreeMap::new(),
            modes: ChannelModeSet::default(),
            key: None,
            invite_list: HashSet::new(),
            bans: Vec::new(),
            quiet_list: Vec::new(),
            ban_exceptions: Vec::new(),
            invite_exceptions: Vec::new(),
            persisted_operators: Vec::new(),
            persisted_voice: Vec::new(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Check if a source (nick!user@host) or account is on the quiet list.
    pub fn is_quieted(&self, account: Option<&str>, source: &str) -> bool {
        for mask in &self.quiet_list {
            if let Some(account_mask) = mask.strip_prefix("~a:") {
                if account
                    .map(|a| a.eq_ignore_ascii_case(account_mask))
                    .unwrap_or(false)
                {
                    return true;
                }
            } else if mask == source {
                return true;
            }
        }
        false
    }

    /// Returns (op, voice) for a joining user based on nick/account and persisted lists.
    pub fn persisted_modes_for(&self, nick: &str, account: Option<&str>) -> (bool, bool) {
        let nick_lower = nick.to_lowercase();
        let account_str = account.unwrap_or("").to_lowercase();
        let is_op = self
            .persisted_operators
            .iter()
            .any(|s| s.to_lowercase() == nick_lower || s.to_lowercase() == account_str);
        let is_voice = self
            .persisted_voice
            .iter()
            .any(|s| s.to_lowercase() == nick_lower || s.to_lowercase() == account_str);
        (is_op, is_voice)
    }

    /// Check if the client is banned (account-extban ~a: or hostmask match).
    pub fn is_banned(&self, account: Option<&str>, source: &str) -> bool {
        for ban in &self.bans {
            if let Some(account_ban) = ban.strip_prefix("~a:") {
                if account.map(|a| a == account_ban).unwrap_or(false) {
                    return true;
                }
            } else if ban == source {
                return true;
            }
        }
        false
    }

    /// Check if source/account matches a ban exception (+e).
    pub fn is_ban_exempt(&self, account: Option<&str>, source: &str) -> bool {
        for exc in &self.ban_exceptions {
            if let Some(acc) = exc.strip_prefix("~a:") {
                if account
                    .map(|a| a.eq_ignore_ascii_case(acc))
                    .unwrap_or(false)
                {
                    return true;
                }
            } else if crate::user::glob_match(exc, source) {
                return true;
            }
        }
        false
    }

    /// Check if source/account matches an invite exception (+I).
    pub fn is_invite_exempt(&self, account: Option<&str>, source: &str) -> bool {
        for exc in &self.invite_exceptions {
            if let Some(acc) = exc.strip_prefix("~a:") {
                if account
                    .map(|a| a.eq_ignore_ascii_case(acc))
                    .unwrap_or(false)
                {
                    return true;
                }
            } else if crate::user::glob_match(exc, source) {
                return true;
            }
        }
        false
    }

    pub fn is_member(&self, client_id: &str) -> bool {
        self.members.contains_key(client_id)
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

/// Canonical key for channel lookups. # and & channels are case-insensitive per IRC; use lowercase.
#[inline]
pub fn canonical_channel_key(name: &str) -> String {
    if name.is_empty() {
        return name.to_string();
    }
    if name.starts_with('#') || name.starts_with('&') {
        format!("{}{}", &name[..1], name[1..].to_lowercase())
    } else {
        name.to_string()
    }
}

/// Server-wide channel storage
#[derive(Debug, Default)]
pub struct ChannelStore {
    pub channels: std::collections::HashMap<String, tokio::sync::RwLock<Channel>>,
}

impl ChannelStore {
    pub fn new() -> Arc<tokio::sync::RwLock<Self>> {
        Arc::new(tokio::sync::RwLock::new(Self {
            channels: std::collections::HashMap::new(),
        }))
    }
}

use std::sync::Arc;
