use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Who set each ban, exception, invite exception or quiet, and when. Keyed
    /// by the list letter followed by the mask.
    pub list_meta: HashMap<String, (String, i64)>,
    /// Account that created the channel; always opped on join.
    pub founder: String,
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
            list_meta: HashMap::new(),
            founder: String::new(),
        }
    }

    /// Whether one mask covers this source. `~a:` matches the account rather
    /// than the hostmask; everything else is a glob, exactly like the ban list —
    /// an exact-match check would silence nobody, since these are almost always
    /// written nick!*@*.
    fn mask_covers(mask: &str, account: Option<&str>, source: &str) -> bool {
        match mask.strip_prefix("~a:") {
            Some(account_mask) => account
                .map(|a| a.eq_ignore_ascii_case(account_mask))
                .unwrap_or(false),
            None => crate::user::glob_match(mask, source),
        }
    }

    /// Whether this source is kept from speaking: the quiet list (+q), or a
    /// mute extban (+b ~m:mask), which is a ban on talking rather than on
    /// coming in. A ban exception lifts either.
    pub fn is_muted(&self, account: Option<&str>, source: &str) -> bool {
        // Only a mute exception lifts a mute. A plain +e is an exception to a
        // ban on coming in, and says nothing about who may talk.
        let exempt = self
            .ban_exceptions
            .iter()
            .filter_map(|e| e.strip_prefix("~m:"))
            .any(|e| Self::mask_covers(e, account, source));
        if exempt {
            return false;
        }
        self.quiet_list
            .iter()
            .any(|m| Self::mask_covers(m, account, source))
            || self
                .bans
                .iter()
                .filter_map(|b| b.strip_prefix("~m:"))
                .any(|m| Self::mask_covers(m, account, source))
    }

    /// Returns (op, voice) for a joining user based on nick/account and persisted lists.
    pub fn persisted_modes_for(&self, nick: &str, account: Option<&str>) -> (bool, bool) {
        let nick_lower = crate::casefold::lower(nick);
        let account_str = crate::casefold::lower(account.unwrap_or(""));
        let is_op = self
            .persisted_operators
            .iter()
            .any(|s| crate::casefold::lower(s) == nick_lower || crate::casefold::lower(s) == account_str);
        let is_voice = self
            .persisted_voice
            .iter()
            .any(|s| crate::casefold::lower(s) == nick_lower || crate::casefold::lower(s) == account_str);
        (is_op, is_voice)
    }

    /// Check if the client is banned (account-extban ~a: or hostmask glob match).
    pub fn is_banned(&self, account: Option<&str>, source: &str) -> bool {
        self.bans
            .iter()
            // A mute extban lives on the ban list but is not a ban on entry.
            .filter(|b| !b.starts_with("~m:"))
            .any(|b| Self::mask_covers(b, account, source))
    }

    /// Check if source/account matches a ban exception (+e).
    pub fn is_ban_exempt(&self, account: Option<&str>, source: &str) -> bool {
        self.ban_exceptions
            .iter()
            // A mute exception lifts a mute, not a ban on coming in.
            .filter(|e| !e.starts_with("~m:"))
            .any(|e| Self::mask_covers(e, account, source))
    }

    /// Check if source/account matches an invite exception (+I).
    pub fn is_invite_exempt(&self, account: Option<&str>, source: &str) -> bool {
        self.invite_exceptions
            .iter()
            .any(|e| Self::mask_covers(e, account, source))
    }

    /// Who set a list entry and when, for RPL_BANLIST and its kin. An entry
    /// that predates this being recorded is attributed to the server at the
    /// time the channel was created.
    pub fn list_entry_meta(&self, list: char, mask: &str, server: &str) -> (String, i64) {
        match self.list_meta.get(&format!("{}{}", list, mask)) {
            Some((by, at)) if !by.is_empty() => (by.clone(), *at),
            _ => (server.to_string(), self.created_at),
        }
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
        format!("{}{}", &name[..1], crate::casefold::lower(&name[1..]))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn chan() -> Channel {
        Channel::new("#chan".to_string())
    }

    /// A mute extban lives on the ban list but only stops someone talking.
    /// Treating it as a ban would lock out everyone it was meant to quiet.
    #[test]
    fn a_mute_extban_does_not_keep_anyone_out() {
        let mut ch = chan();
        ch.bans.push("~m:bar!*@*".to_string());
        assert!(!ch.is_banned(None, "bar!user@host"));
        assert!(ch.is_muted(None, "bar!user@host"));
        assert!(!ch.is_muted(None, "someoneelse!user@host"));
    }

    #[test]
    fn a_plain_ban_still_keeps_someone_out() {
        let mut ch = chan();
        ch.bans.push("bar!*@*".to_string());
        assert!(ch.is_banned(None, "bar!user@host"));
        // ...and is not, by itself, a mute.
        assert!(!ch.is_muted(None, "bar!user@host"));
    }

    #[test]
    fn a_mute_exception_lifts_a_mute() {
        let mut ch = chan();
        ch.bans.push("~m:qux!*@*".to_string());
        ch.ban_exceptions.push("~m:*!*evan@*".to_string());
        assert!(!ch.is_muted(None, "qux!evan@host"));
        assert!(ch.is_muted(None, "qux!other@host"));
    }

    /// A plain +e excepts from a ban on coming in, and says nothing about who
    /// may talk — so a quiet set alongside one still holds.
    #[test]
    fn a_plain_exception_does_not_lift_a_quiet() {
        let mut ch = chan();
        ch.quiet_list.push("bar!*@*".to_string());
        ch.ban_exceptions.push("bar!*@*".to_string());
        assert!(ch.is_muted(None, "bar!user@host"));
    }

    /// A mute exception is not a ban exception: it says who may talk, not who
    /// may come in past a ban.
    #[test]
    fn a_mute_exception_does_not_excuse_a_ban() {
        let mut ch = chan();
        ch.bans.push("qux!*@*".to_string());
        ch.ban_exceptions.push("~m:*!*evan@*".to_string());
        assert!(ch.is_banned(None, "qux!evan@host"));
    }

    #[test]
    fn the_quiet_list_mutes_too() {
        let mut ch = chan();
        ch.quiet_list.push("bar!*@*".to_string());
        assert!(ch.is_muted(None, "bar!user@host"));
        assert!(!ch.is_banned(None, "bar!user@host"));
    }

    #[test]
    fn account_extbans_match_the_account_not_the_host() {
        let mut ch = chan();
        ch.bans.push("~a:evan".to_string());
        assert!(ch.is_banned(Some("Evan"), "someone!user@host"));
        assert!(!ch.is_banned(Some("other"), "someone!user@host"));
        assert!(!ch.is_banned(None, "someone!user@host"));
    }

    /// Nicks and hosts are case-insensitive in IRC, so a ban has to hold when
    /// its target changes the case of its nick.
    #[test]
    fn masks_hold_regardless_of_case() {
        let mut ch = chan();
        ch.bans.push("bar!*@example.com".to_string());
        assert!(ch.is_banned(None, "BAR!user@EXAMPLE.COM"));
    }

    #[test]
    fn a_list_entry_without_recorded_meta_falls_back_to_the_server() {
        let mut ch = chan();
        ch.bans.push("bar!*@*".to_string());
        let (by, at) = ch.list_entry_meta('b', "bar!*@*", "irc.example.org");
        assert_eq!(by, "irc.example.org");
        assert_eq!(at, ch.created_at);

        ch.list_meta
            .insert("bbar!*@*".to_string(), ("chanop".to_string(), 1700000000));
        let (by, at) = ch.list_entry_meta('b', "bar!*@*", "irc.example.org");
        assert_eq!(by, "chanop");
        assert_eq!(at, 1700000000);
    }
}
