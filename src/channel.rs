use std::collections::{BTreeMap, HashMap, HashSet};

/// Operators or voices a channel may remember at once.
///
/// Status that outlives a visit has to be written down, and anything written
/// down needs a ceiling or it is somewhere to put things. The same number the
/// ban list uses: a channel that needs a hundred standing operators is not
/// being run by its operators.
pub const MAX_CHANNEL_ACCESS: usize = 100;

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
    /// Accounts that get @ when they join.
    ///
    /// Accounts, not nicks. Status that outlives a visit belongs to whoever
    /// can prove they are the same person, and a nick proves nothing: names
    /// are given up and taken. Matching one here would mean that taking a name
    /// was enough to inherit what it had been given — and nick reservation,
    /// which is what would normally stop that, deliberately fails open when the
    /// database is unreachable.
    pub persisted_operators: Vec<String>,
    /// Accounts that get + when they join. Accounts for the same reason.
    pub persisted_voice: Vec<String>,
    /// Channel creation time (Unix timestamp); sent as 329 RPL_CREATIONTIME
    pub created_at: i64,
    /// Who set each ban, exception, invite exception or quiet, and when. Keyed
    /// by the list letter followed by the mask.
    pub list_meta: HashMap<String, (String, i64)>,
    /// Account that created the channel; always opped on join.
    pub founder: String,
    /// When people joined lately, for `+j`. Only kept while the mode is set,
    /// and only as far back as its window; never written anywhere.
    pub recent_joins: std::collections::VecDeque<i64>,
    /// When the database was last told somebody who holds this channel was
    /// in it. Once an hour is often enough for a clock that counts in days.
    pub use_noted_at: i64,
    /// When each member last spoke, for `+f`. Behind its own small lock so
    /// the message path, which only reads the channel, can still count.
    pub spoke_at: std::sync::Mutex<HashMap<String, std::collections::VecDeque<i64>>>,
    /// The founder's mode lock, `+nt-k` and the like: what the appointed
    /// operators may not undo. Empty is no lock.
    pub mode_lock: String,
}

/// Members whose speaking record is kept before the oldest are forgotten.
/// A channel does not have this many people talking in one window.
const MAX_SPEAKERS_TRACKED: usize = 4096;

#[derive(Debug, Clone, Default)]
pub struct ChannelModeSet {
    pub secret: bool,          // +s
    pub private: bool,         // +p
    pub invite_only: bool,     // +i
    pub topic_protect: bool,   // +t
    pub no_external: bool,     // +n
    pub moderated: bool,       // +m
    pub registered_only: bool, // +R: only authed users may join/speak
    /// +M: anybody may join, but only somebody logged in may speak — unless
    /// they have been given a voice or ops, the way +m works. The anti-spam
    /// mode a channel reaches for when it wants to stay open to lurkers.
    pub registered_speak: bool,
    /// +Z: only connections over TLS may join, and it cannot be set while
    /// anybody in the channel is not. What is said in a +Z channel has never
    /// crossed a wire in the clear, on any hop this server controls.
    pub tls_only: bool,
    pub no_colors: bool,       // +c: strip mIRC color codes
    pub no_ctcp: bool,         // +C: block CTCP to channel
    pub user_limit: Option<u32>,
    /// +j `<joins>:<seconds>`: no more than this many joins in this many
    /// seconds. The people the channel would let past a full room — whoever
    /// holds it, whoever it invited — are let past this too, so a join flood
    /// slows the crowd without locking the owner out of the door.
    pub join_throttle: Option<(u32, u32)>,
    /// +f `<lines>:<seconds>`: more lines than that from one person in that
    /// many seconds, and the server shows them the door. Channel staff — ops
    /// and half-ops — and operators are not the crowd it is for.
    pub msg_flood: Option<(u32, u32)>,
    /// +N: nobody changes their nick while in here, unless they are staff.
    pub no_nick_change: bool,
    /// +T: no NOTICEs to the channel from anybody who is not staff.
    pub no_notices: bool,
    /// +z: what somebody who may not speak says goes to the ops instead of
    /// nowhere — moderation the moderators can see.
    pub op_moderated: bool,
    /// +O: operators only.
    pub oper_only: bool,
    /// +L `#overflow`: where somebody is sent when the channel is full.
    pub redirect: Option<String>,
}

/// Read a `+j` argument. Both halves have to be there and be positive; a
/// window longer than a day is a mistake, not a slower throttle.
pub fn parse_throttle(raw: &str) -> Option<(u32, u32)> {
    let (joins, secs) = raw.split_once(':')?;
    let joins: u32 = joins.parse().ok()?;
    let secs: u32 = secs.parse().ok()?;
    if joins == 0 || secs == 0 || secs > 86_400 || joins > 100_000 {
        return None;
    }
    Some((joins, secs))
}

/// How a `+j` or `+f` limit is shown: the way it was set.
pub fn throttle_string(t: (u32, u32)) -> String {
    format!("{}:{}", t.0, t.1)
}

/// Of two rate limits, the one that allows more per second.
fn looser(a: Option<(u32, u32)>, b: Option<(u32, u32)>) -> Option<(u32, u32)> {
    match (a, b) {
        (Some(a), Some(b)) => {
            let a_rate = u64::from(a.0) * u64::from(b.1);
            let b_rate = u64::from(b.0) * u64::from(a.1);
            Some(if a_rate >= b_rate { a } else { b })
        }
        (a, b) => a.or(b),
    }
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
            recent_joins: std::collections::VecDeque::new(),
            use_noted_at: 0,
            spoke_at: std::sync::Mutex::new(HashMap::new()),
            mode_lock: String::new(),
        }
    }

    /// Whether an empty channel is still somebody's.
    ///
    /// A channel nobody is in is normally forgotten: it was a name two people
    /// used for an afternoon, and remembering it costs memory for nothing. A
    /// channel that belongs to somebody is different. Its founder, its
    /// operators, its bans and its modes live in the database, and the
    /// database is only read at startup — so dropping it here would not park
    /// it somewhere safe, it would hand it blank to whoever walked in next.
    ///
    /// What counts is somebody who can run the place: a founder, or an
    /// operator whose status was granted to last. Modes and bans on their own
    /// do not, however permanent they look. Nobody owns such a channel, so
    /// nobody could ever lift what is set on it — keeping a `+k` that no
    /// living person knows the key to would not be preserving a channel, it
    /// would be sealing one.
    ///
    /// Whoever is kept for is also exempt from the channel's own doors, which
    /// is what makes this safe to keep: see the join path in `channel_cmds`.
    pub fn is_registered(&self) -> bool {
        !self.founder.is_empty() || !self.persisted_operators.is_empty()
    }

    /// Whether this account owns the channel.
    ///
    /// The founder is an account rather than a nick, so whoever is logged in
    /// as it is the owner — on any connection, under any name. Somebody who is
    /// not logged in owns nothing, which is why a bare `None` is never a match
    /// even when the channel has no founder at all.
    pub fn is_founder(&self, account: Option<&str>) -> bool {
        match account {
            Some(account) if !self.founder.is_empty() => {
                account.eq_ignore_ascii_case(&self.founder)
            }
            _ => false,
        }
    }

    /// Whether one mask covers this source. `~a:` matches the account rather
    /// than the hostmask; everything else is a glob, exactly like the ban list —
    /// an exact-match check would silence nobody, since these are almost always
    /// written nick!*@*.
    fn mask_covers(mask: &str, account: Option<&str>, source: &str) -> bool {
        // A timed mask is the mask under it, for as long as it lasts.
        let mask = crate::timed_bans::peel_timed(mask);
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
                .filter_map(|b| crate::timed_bans::peel_timed(b).strip_prefix("~m:"))
                .any(|m| Self::mask_covers(m, account, source))
    }

    /// Returns (op, voice) for a joining user based on nick/account and persisted lists.
    pub fn persisted_modes_for(&self, account: Option<&str>) -> (bool, bool) {
        let Some(account) = account else {
            return (false, false);
        };
        let wanted = crate::casefold::lower(account);
        let held = |list: &[String]| list.iter().any(|s| crate::casefold::lower(s) == wanted);
        (held(&self.persisted_operators), held(&self.persisted_voice))
    }

    /// Check if the client is banned (account-extban ~a: or hostmask glob match).
    pub fn is_banned(&self, account: Option<&str>, source: &str) -> bool {
        self.bans
            .iter()
            // A mute extban lives on the ban list but is not a ban on entry.
            .filter(|b| !crate::timed_bans::peel_timed(b).starts_with("~m:"))
            .any(|b| Self::mask_covers(b, account, source))
    }

    /// Whether the founder's mode lock says this change may not be made:
    /// `+nt-k` locks `n` and `t` on and `k` off.
    pub fn lock_forbids(&self, letter: char, plus: bool) -> bool {
        let mut adding = true;
        for c in self.mode_lock.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                c if c == letter => return adding != plus,
                _ => {}
            }
        }
        false
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

    /// The channel's modes as they go over a link: the letters, then the
    /// arguments the letters that take one need, in the same order.
    ///
    /// Written once here so the burst and the reply to `MODE #channel` cannot
    /// drift apart into two different ideas of what this channel is set to.
    pub fn mode_string(&self) -> (String, Vec<String>) {
        let mut letters = String::from("+");
        let mut args = Vec::new();
        for (set, letter) in [
            (self.modes.invite_only, 'i'),
            (self.modes.moderated, 'm'),
            (self.modes.no_external, 'n'),
            (self.modes.secret, 's'),
            (self.modes.topic_protect, 't'),
            (self.modes.private, 'p'),
            (self.modes.registered_only, 'R'),
            (self.modes.registered_speak, 'M'),
            (self.modes.tls_only, 'Z'),
            (self.modes.no_colors, 'c'),
            (self.modes.no_ctcp, 'C'),
            (self.modes.no_nick_change, 'N'),
            (self.modes.no_notices, 'T'),
            (self.modes.op_moderated, 'z'),
            (self.modes.oper_only, 'O'),
        ] {
            if set {
                letters.push(letter);
            }
        }
        if let Some(ref key) = self.key {
            letters.push('k');
            args.push(key.clone());
        }
        if let Some(ref target) = self.modes.redirect {
            letters.push('L');
            args.push(target.clone());
        }
        if let Some(limit) = self.modes.user_limit {
            letters.push('l');
            args.push(limit.to_string());
        }
        if let Some(t) = self.modes.join_throttle {
            letters.push('j');
            args.push(throttle_string(t));
        }
        if let Some(t) = self.modes.msg_flood {
            letters.push('f');
            args.push(throttle_string(t));
        }
        (letters, args)
    }

    /// Count one line from a member against `+f`, and say whether it was one
    /// too many. Nothing is kept for a channel without the mode.
    pub fn floods(&self, user_id: &str, now: i64) -> bool {
        let Some((lines, secs)) = self.modes.msg_flood else {
            return false;
        };
        let Ok(mut spoke) = self.spoke_at.lock() else {
            return false;
        };
        let horizon = now.saturating_sub(i64::from(secs));
        if spoke.len() >= MAX_SPEAKERS_TRACKED && !spoke.contains_key(user_id) {
            spoke.retain(|_, when| when.back().is_some_and(|t| *t >= horizon));
        }
        let when = spoke.entry(user_id.to_string()).or_default();
        while when.front().is_some_and(|t| *t < horizon) {
            when.pop_front();
        }
        when.push_back(now);
        when.len() > lines as usize
    }

    /// `-f`, or a member leaving: nothing to hold against anybody.
    pub fn forget_speaking(&self, user_id: Option<&str>) {
        if let Ok(mut spoke) = self.spoke_at.lock() {
            match user_id {
                Some(id) => {
                    spoke.remove(id);
                }
                None => spoke.clear(),
            }
        }
    }

    /// Whether `+j` says no to one more join right now. Forgets joins older
    /// than the window as it goes, so the record stays as small as the mode.
    pub fn join_throttled(&mut self, now: i64) -> bool {
        let Some((joins, secs)) = self.modes.join_throttle else {
            self.recent_joins.clear();
            return false;
        };
        let horizon = now.saturating_sub(i64::from(secs));
        while self.recent_joins.front().is_some_and(|t| *t < horizon) {
            self.recent_joins.pop_front();
        }
        self.recent_joins.len() >= joins as usize
    }

    /// Count a join against `+j`. Somebody the throttle let past still
    /// counts: the window is about how fast the room is filling, not who
    /// was refused.
    pub fn note_join(&mut self, now: i64) {
        if self.modes.join_throttle.is_none() {
            return;
        }
        self.join_throttled(now);
        self.recent_joins.push_back(now);
    }

    /// Take the modes from a link, replacing whatever was set here.
    ///
    /// Used where the other side's channel is the older one and this side has
    /// to give way: half-applying its modes would leave a channel that is
    /// neither its own nor the one it agreed to.
    pub fn set_mode_string(&mut self, letters: &str, args: &[String]) {
        self.modes = ChannelModeSet::default();
        self.key = None;
        let mut arg = args.iter();
        for c in letters.chars() {
            match c {
                '+' | '-' => {}
                'i' => self.modes.invite_only = true,
                'm' => self.modes.moderated = true,
                'n' => self.modes.no_external = true,
                's' => self.modes.secret = true,
                't' => self.modes.topic_protect = true,
                'p' => self.modes.private = true,
                'R' => self.modes.registered_only = true,
                'M' => self.modes.registered_speak = true,
                'Z' => self.modes.tls_only = true,
                'c' => self.modes.no_colors = true,
                'C' => self.modes.no_ctcp = true,
                'N' => self.modes.no_nick_change = true,
                'T' => self.modes.no_notices = true,
                'z' => self.modes.op_moderated = true,
                'O' => self.modes.oper_only = true,
                'L' => self.modes.redirect = arg.next().cloned(),
                'k' => self.key = arg.next().cloned(),
                'l' => self.modes.user_limit = arg.next().and_then(|v| v.parse().ok()),
                'j' => self.modes.join_throttle = arg.next().and_then(|v| parse_throttle(v)),
                'f' => self.modes.msg_flood = arg.next().and_then(|v| parse_throttle(v)),
                // A letter from a newer peer. Dropping it is better than
                // guessing whether it takes an argument and losing the rest.
                _ => {}
            }
        }
    }

    /// Add the modes from a link to the ones already set.
    ///
    /// Two channels of the same age are the same channel, met from two sides,
    /// and neither side's modes are more right than the other's.
    pub fn merge_mode_string(&mut self, letters: &str, args: &[String]) {
        let mut arg = args.iter();
        for c in letters.chars() {
            match c {
                '+' | '-' => {}
                'i' => self.modes.invite_only = true,
                'm' => self.modes.moderated = true,
                'n' => self.modes.no_external = true,
                's' => self.modes.secret = true,
                't' => self.modes.topic_protect = true,
                'p' => self.modes.private = true,
                'R' => self.modes.registered_only = true,
                'M' => self.modes.registered_speak = true,
                'Z' => self.modes.tls_only = true,
                'c' => self.modes.no_colors = true,
                'C' => self.modes.no_ctcp = true,
                'N' => self.modes.no_nick_change = true,
                'T' => self.modes.no_notices = true,
                'z' => self.modes.op_moderated = true,
                'O' => self.modes.oper_only = true,
                'L' => {
                    let v = arg.next().cloned();
                    if self.modes.redirect.is_none() {
                        self.modes.redirect = v;
                    }
                }
                'k' => {
                    let v = arg.next().cloned();
                    if self.key.is_none() {
                        self.key = v;
                    }
                }
                'l' => {
                    let v = arg.next().and_then(|v| v.parse::<u32>().ok());
                    // The looser limit wins: nobody is thrown out of a channel
                    // by two servers meeting.
                    self.modes.user_limit = match (self.modes.user_limit, v) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                }
                'j' => {
                    let v = arg.next().and_then(|v| parse_throttle(v));
                    // The looser throttle wins, for the same reason: the one
                    // that lets more people in per second.
                    self.modes.join_throttle = looser(self.modes.join_throttle, v);
                }
                'f' => {
                    let v = arg.next().and_then(|v| parse_throttle(v));
                    self.modes.msg_flood = looser(self.modes.msg_flood, v);
                }
                _ => {}
            }
        }
    }

    /// Whether one of the channel's lists already holds a mask.
    ///
    /// Masks are matched without regard to case, so `BAR!*@*` and `bar!*@*` are
    /// one ban and setting the second over the first would leave two entries
    /// that ban the same person and take two commands to lift.
    pub fn list_contains(&self, letter: char, mask: &str) -> bool {
        let wanted = crate::casefold::lower(mask);
        self.list_of(letter)
            .is_some_and(|l| l.iter().any(|m| crate::casefold::lower(m) == wanted))
    }

    /// Take a mask off one of the channel's lists, however it was capitalised
    /// when it was put there. Returns whether anything went.
    pub fn remove_from_list(&mut self, letter: char, mask: &str) -> bool {
        let wanted = crate::casefold::lower(mask);
        let Some(list) = self.list_mut(letter) else {
            return false;
        };
        let gone: Vec<String> = list
            .iter()
            .filter(|m| crate::casefold::lower(m) == wanted)
            .cloned()
            .collect();
        list.retain(|m| crate::casefold::lower(m) != wanted);
        for m in &gone {
            self.list_meta.remove(&format!("{}{}", letter, m));
        }
        !gone.is_empty()
    }

    /// The list a mode letter names, for the burst and for a link that changes
    /// one.
    pub fn list_mut(&mut self, letter: char) -> Option<&mut Vec<String>> {
        match letter {
            'b' => Some(&mut self.bans),
            'e' => Some(&mut self.ban_exceptions),
            'I' => Some(&mut self.invite_exceptions),
            'q' => Some(&mut self.quiet_list),
            _ => None,
        }
    }

    pub fn list_of(&self, letter: char) -> Option<&Vec<String>> {
        match letter {
            'b' => Some(&self.bans),
            'e' => Some(&self.ban_exceptions),
            'I' => Some(&self.invite_exceptions),
            'q' => Some(&self.quiet_list),
            _ => None,
        }
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

    /// `+j` is `<joins>:<seconds>`, both positive, and nothing else.
    #[test]
    fn a_join_throttle_is_joins_and_seconds() {
        assert_eq!(parse_throttle("2:60"), Some((2, 60)));
        assert_eq!(parse_throttle("0:60"), None);
        assert_eq!(parse_throttle("2:0"), None);
        assert_eq!(parse_throttle("2"), None);
        assert_eq!(parse_throttle("two:60"), None);
        assert_eq!(parse_throttle("2:100000"), None, "longer than a day is a mistake");
        assert_eq!(parse_throttle(""), None);
        assert_eq!(throttle_string((2, 60)), "2:60");
    }

    /// The throttle counts joins inside its window and forgets the rest as
    /// it goes; with no throttle set, nothing is counted at all.
    #[test]
    fn a_join_throttle_forgets_joins_outside_its_window() {
        let mut ch = Channel::new("#j".into());
        ch.note_join(1_000);
        assert!(ch.recent_joins.is_empty(), "nothing is kept without the mode");
        ch.modes.join_throttle = Some((2, 10));
        assert!(!ch.join_throttled(1_000));
        ch.note_join(1_000);
        ch.note_join(1_001);
        assert!(ch.join_throttled(1_002), "two joins in ten seconds is the limit");
        assert!(ch.join_throttled(1_010), "the first join is still inside the window");
        assert!(!ch.join_throttled(1_011), "and then it is not");
        assert_eq!(ch.recent_joins.len(), 1);
        ch.modes.join_throttle = None;
        assert!(!ch.join_throttled(1_011));
        assert!(ch.recent_joins.is_empty(), "the record goes with the mode");
    }

    /// `+f` counts each member's lines in its window and says when one is
    /// one too many; a member kicked or a mode lifted is forgotten.
    #[test]
    fn a_flood_limit_counts_each_member_separately() {
        let ch = Channel::new("#f".into());
        assert!(!ch.floods("a", 1_000), "no mode, no limit");
        let mut ch = ch;
        ch.modes.msg_flood = Some((2, 10));
        assert!(!ch.floods("a", 1_000));
        assert!(!ch.floods("a", 1_001));
        assert!(ch.floods("a", 1_002), "the third line in ten seconds is one too many");
        assert!(!ch.floods("b", 1_002), "somebody else's lines are their own");
        assert!(ch.floods("a", 1_011), "still over: three of the last four are inside the window");
        assert!(!ch.floods("a", 1_030), "the window has moved on");
        ch.forget_speaking(Some("a"));
        assert!(!ch.floods("a", 1_031));
        assert!(!ch.floods("a", 1_031));
        assert!(ch.floods("a", 1_031));
        ch.forget_speaking(None);
        assert!(!ch.floods("a", 1_031), "nothing held against anybody after -f");
    }

    /// Two servers meeting keep the throttle that lets more people in, for
    /// the same reason they keep the larger +l.
    #[test]
    fn two_servers_meeting_keep_the_looser_throttle() {
        let mut ch = Channel::new("#j".into());
        ch.modes.join_throttle = Some((2, 60));
        ch.merge_mode_string("+j", &["10:60".to_string()]);
        assert_eq!(ch.modes.join_throttle, Some((10, 60)));
        ch.merge_mode_string("+j", &["1:60".to_string()]);
        assert_eq!(ch.modes.join_throttle, Some((10, 60)));
        ch.merge_mode_string("+j", &["1:10".to_string()]);
        assert_eq!(ch.modes.join_throttle, Some((10, 60)), "six a minute is slower than ten");
        ch.merge_mode_string("+j", &["1:5".to_string()]);
        assert_eq!(ch.modes.join_throttle, Some((1, 5)), "twelve a minute is not");
        ch.modes.join_throttle = Some((10, 60));
        ch.merge_mode_string("+j", &["30:60".to_string()]);
        assert_eq!(ch.modes.join_throttle, Some((30, 60)));
        let mut fresh = Channel::new("#k".into());
        fresh.merge_mode_string("+j", &["3:30".to_string()]);
        assert_eq!(fresh.modes.join_throttle, Some((3, 30)));
        fresh.set_mode_string("+nt", &[]);
        assert_eq!(fresh.modes.join_throttle, None, "taking a peer's modes wholesale drops it");
    }

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
