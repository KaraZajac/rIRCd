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
    /// `+x`, shown as `^`: the person the channel belongs to.
    pub founder: bool,
    /// `+a`, shown as `&`: somebody the founder has put above the operators.
    pub admin: bool,
    pub op: bool,
    pub voice: bool,
    pub halfop: bool,
}

impl ChannelMemberModeSet {
    pub fn prefix(&self) -> &'static str {
        if self.founder {
            "^"
        } else if self.admin {
            "&"
        } else if self.op {
            "@"
        } else if self.halfop {
            "%"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }

    /// All prefixes in rank order for the multi-prefix cap.
    pub fn prefixes_ordered(&self) -> String {
        let mut s = String::new();
        if self.founder {
            s.push('^');
        }
        if self.admin {
            s.push('&');
        }
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

    /// Whether this member has an operator's powers.
    ///
    /// Asked wherever the question is "may they do this", rather than "do they
    /// hold `+o`". A founder and an admin can do everything an operator can —
    /// that is what putting them above the operators means — so a check written
    /// against `op` alone would give the person who owns the room less than the
    /// people they appointed.
    pub fn is_op(&self) -> bool {
        self.founder || self.admin || self.op
    }

    /// Whether they may do what a half-operator may.
    pub fn at_least_halfop(&self) -> bool {
        self.is_op() || self.halfop
    }

    /// Whether they hold any status at all — the question `+m` asks.
    pub fn at_least_voice(&self) -> bool {
        self.at_least_halfop() || self.voice
    }

    /// How far up the ladder this member stands: founder 4, admin 3, op 2,
    /// half-operator 1, and 0 for everybody else.
    ///
    /// Status is given and taken by people who have some of their own, and the
    /// rule throughout is that nobody reaches above themselves. One number is
    /// the whole of that comparison.
    pub fn rank(&self) -> u8 {
        if self.founder {
            4
        } else if self.admin {
            3
        } else if self.op {
            2
        } else if self.halfop {
            1
        } else {
            0
        }
    }
}


#[cfg(test)]
mod prefix_tests {
    use super::*;

    fn with(founder: bool, admin: bool, op: bool, halfop: bool, voice: bool) -> ChannelMemberModeSet {
        ChannelMemberModeSet { founder, admin, op, halfop, voice }
    }

    /// A founder and an admin can do everything an operator can. A check
    /// written against `op` alone would give the person who owns the room less
    /// than the people they appointed.
    #[test]
    fn standing_above_an_operator_includes_standing_as_one() {
        assert!(with(true, false, false, false, false).is_op(), "the founder");
        assert!(with(false, true, false, false, false).is_op(), "an admin");
        assert!(with(false, false, true, false, false).is_op(), "an operator");
        assert!(!with(false, false, false, true, false).is_op(), "a half-operator is not");
        assert!(with(false, false, false, true, false).at_least_halfop());
        assert!(with(true, false, false, false, false).at_least_halfop(), "the founder is above one");
        assert!(with(false, false, false, false, true).at_least_voice());
        assert!(with(true, false, false, false, false).at_least_voice());
        assert!(!with(false, false, false, false, false).at_least_voice());
    }

    /// The prefix shown is the highest held, and multi-prefix lists them all
    /// strongest first — in the order `PREFIX` in ISUPPORT promises.
    #[test]
    fn the_prefix_is_the_highest_and_the_list_is_in_order() {
        assert_eq!(with(true, true, true, false, true).prefix(), "^");
        assert_eq!(with(false, true, true, false, false).prefix(), "&");
        assert_eq!(with(false, false, true, false, false).prefix(), "@");
        assert_eq!(with(false, false, false, true, false).prefix(), "%");
        assert_eq!(with(false, false, false, false, true).prefix(), "+");
        assert_eq!(with(false, false, false, false, false).prefix(), "");
        assert_eq!(with(true, true, true, true, true).prefixes_ordered(), "^&@%+");
        assert_eq!(with(true, false, false, false, true).prefixes_ordered(), "^+");
    }

    /// The order in `PREFIX_CHARS` is the order `prefixes_ordered` uses, and
    /// the two lists are the same length. A mode added to one and not the
    /// other is how a server ends up advertising a prefix it never sends.
    #[test]
    fn the_advertised_prefixes_are_the_ones_given_out() {
        assert_eq!(PREFIX_MODES.len(), PREFIX_CHARS.len());
        assert_eq!(
            with(true, true, true, true, true).prefixes_ordered(),
            PREFIX_CHARS,
            "everything held at once spells the advertised list"
        );
        for letter in PREFIX_MODES.chars() {
            assert!(mode_takes_param(letter, true), "+{letter} names somebody");
            assert!(mode_takes_param(letter, false), "-{letter} names somebody");
        }
        // The quiet list keeps its letter, which is why the founder has x.
        assert!(CHANMODES_LIST.contains('q'));
        assert!(!PREFIX_MODES.contains('q'));
    }

    /// Nobody reaches above themselves.
    #[test]
    fn rank_puts_them_in_order() {
        assert!(with(true, false, false, false, false).rank() > with(false, true, false, false, false).rank());
        assert!(with(false, true, false, false, false).rank() > with(false, false, true, false, false).rank());
        assert!(with(false, false, true, false, false).rank() > with(false, false, false, true, false).rank());
        assert!(with(false, false, false, true, false).rank() > with(false, false, false, false, true).rank());
        assert_eq!(with(false, false, false, false, true).rank(), 0, "voice is not a rung");
    }
}

// ─── What this server says it has ─────────────────────────────────────────────
//
// Every answer that names a mode reads these: `ISUPPORT`'s `CHANMODES`,
// `USERMODES` and `PREFIX`, `RPL_MYINFO`, and the MODE parser deciding which
// letters carry a parameter. A mode added in one place and forgotten in
// another is a server that says it cannot do something it does, which is how
// `RPL_MYINFO` came to be describing a version several releases old.

/// Channel modes that hold a list of masks. `CHANMODES` group A.
pub const CHANMODES_LIST: &str = "beIq";
/// Channel modes that carry a parameter whichever way they are set. Group B.
pub const CHANMODES_PARAM_ALWAYS: &str = "k";
/// Channel modes that carry a parameter only when set. Group C.
pub const CHANMODES_PARAM_SET: &str = "fjlL";
/// Channel modes that never carry one. Group D.
pub const CHANMODES_FLAG: &str = "imnstpRcCMZNOTz";
/// The modes that give a member a prefix, strongest first.
///
/// `x` is the founder and `a` the admin. Not `q` and `a` as on the servers
/// that have these: `q` is this server's quiet list, which is persisted, takes
/// timed bans and feeds `+z`, and was not worth breaking for a letter. The
/// prefix characters are what clients show, and those are read from `PREFIX`
/// in ISUPPORT rather than assumed.
pub const PREFIX_MODES: &str = "xaohv";
/// The prefixes they give, in the same order.
pub const PREFIX_CHARS: &str = "^&@%+";
/// User modes that carry a parameter when set: the server notice mask.
pub const USERMODES_PARAM_SET: &str = "s";
/// User modes that never carry one.
pub const USERMODES_FLAG: &str = "BgiorRw";
/// The extended ban types this server understands, the letters after `~`.
pub const EXTBAN_TYPES: &str = "OSajmnrt";

/// The same letters in one sorted string, which is how `RPL_MYINFO` wants
/// them: a set rather than a grammar.
fn sorted(parts: &[&str]) -> String {
    let mut letters: Vec<char> = parts.iter().flat_map(|p| p.chars()).collect();
    letters.sort_unstable();
    letters.dedup();
    letters.into_iter().collect()
}

/// Every channel mode there is: `RPL_MYINFO`'s fifth parameter.
pub fn all_channel_modes() -> String {
    sorted(&[
        CHANMODES_LIST,
        CHANMODES_PARAM_ALWAYS,
        CHANMODES_PARAM_SET,
        CHANMODES_FLAG,
        PREFIX_MODES,
    ])
}

/// The channel modes that carry a parameter: `RPL_MYINFO`'s sixth.
pub fn parameterised_channel_modes() -> String {
    sorted(&[
        CHANMODES_LIST,
        CHANMODES_PARAM_ALWAYS,
        CHANMODES_PARAM_SET,
        PREFIX_MODES,
    ])
}

/// Every user mode there is: `RPL_MYINFO`'s fourth parameter.
pub fn all_user_modes() -> String {
    sorted(&[USERMODES_PARAM_SET, USERMODES_FLAG])
}

/// Whether a channel mode letter carries a parameter. A list mode, a group B
/// mode and a prefix mode always do; a group C mode does only when set.
/// The mode letter a prefix character stands for, if it is one.
///
/// `PREFIX_CHARS` and `PREFIX_MODES` are the same list in the same order, so
/// this is a lookup rather than a second copy of the mapping. Written once
/// because the two places that had it written out by hand both stopped at
/// `+` and silently dropped everything above an operator.
pub fn mode_letter_for_prefix(prefix: char) -> Option<char> {
    PREFIX_CHARS
        .chars()
        .position(|c| c == prefix)
        .and_then(|i| PREFIX_MODES.chars().nth(i))
}

/// Whether this character is one of the prefixes a member may wear.
pub fn is_prefix_char(c: char) -> bool {
    PREFIX_CHARS.contains(c)
}


pub fn mode_takes_param(letter: char, plus: bool) -> bool {
    PREFIX_MODES.contains(letter)
        || CHANMODES_LIST.contains(letter)
        || CHANMODES_PARAM_ALWAYS.contains(letter)
        || (CHANMODES_PARAM_SET.contains(letter) && plus)
}

/// Everything a channel's masks can be asked about.
///
/// A mask used to be matched against a `nick!user@host` and, for `~a:`, an
/// account. Each new extended ban wanted one more thing, and threading one
/// more argument through every caller each time is how a server ends up with
/// a ban type that quietly works in one place and not another. This carries
/// the whole person instead.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    /// `nick!user@host`, as everybody else sees it — the cloak, not the
    /// address behind it.
    pub source: &'a str,
    /// The account they are logged in to, if any.
    pub account: Option<&'a str>,
    /// Their real name, for `~r:`.
    pub realname: &'a str,
    /// The channels they are in, keyed as channels are, for `~j:`.
    pub channels: &'a [String],
    /// The TLS client certificate they presented, for `~S:`.
    pub certfp: Option<&'a str>,
    /// Whether they are a server operator, for `~O`.
    pub is_oper: bool,
}

impl<'a> Subject<'a> {
    /// Somebody named only by their `nick!user@host`.
    pub fn from_source(source: &'a str) -> Self {
        Self {
            source,
            account: None,
            realname: "",
            channels: &[],
            certfp: None,
            is_oper: false,
        }
    }

    pub fn with_account(mut self, account: Option<&'a str>) -> Self {
        self.account = account;
        self
    }

    pub fn with_realname(mut self, realname: &'a str) -> Self {
        self.realname = realname;
        self
    }

    pub fn in_channels(mut self, channels: &'a [String]) -> Self {
        self.channels = channels;
        self
    }

    pub fn with_certfp(mut self, certfp: Option<&'a str>) -> Self {
        self.certfp = certfp;
        self
    }

    pub fn oper(mut self, is_oper: bool) -> Self {
        self.is_oper = is_oper;
        self
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

    /// Whether one mask covers this person.
    ///
    /// A plain mask is a glob over `nick!user@host`, which is what almost
    /// every mask is. An extended ban — the `~` types named in `EXTBAN` —
    /// asks about something else instead: the account behind the connection,
    /// the real name, another channel they are in. They compose, because the
    /// prefixes peel one at a time: `~t:1h:~r:*viagra*` is a real-name ban
    /// that lifts itself in an hour, and `~m:~r:*viagra*` mutes rather than
    /// bans.
    fn mask_covers(mask: &str, subject: &Subject) -> bool {
        // A timed mask is the mask under it, for as long as it lasts.
        let mask = crate::timed_bans::peel_timed(mask);
        if let Some(account_mask) = mask.strip_prefix("~a:") {
            return subject
                .account
                .map(|a| a.eq_ignore_ascii_case(account_mask))
                .unwrap_or(false);
        }
        if let Some(realname_mask) = mask.strip_prefix("~r:") {
            // A glob, because a real name is a sentence and nobody bans one
            // exactly. Somebody who gave none matches only `*`.
            //
            // A mode parameter cannot hold a space, and a real name is mostly
            // spaces, so `_` stands for one — the spelling every other server
            // uses. Both sides are read that way, so `~r:*seedy_marketing*`
            // and a mask sent as the trailing parameter with real spaces in
            // it mean the same thing.
            let pattern = realname_mask.replace(' ', "_");
            let realname = subject.realname.replace(' ', "_");
            return crate::user::glob_match(&pattern, &realname);
        }
        if let Some(fingerprint) = mask.strip_prefix("~S:") {
            // A glob, so `~S:*` is everybody who brought a certificate and
            // `+e ~S:*` is "anybody who can prove who they are is exempt".
            return subject
                .certfp
                .is_some_and(|have| crate::user::glob_match(fingerprint, have));
        }
        if mask.eq_ignore_ascii_case("~O") {
            // Mostly written as `+e ~O`: the operators are exempt. As a ban
            // it is legal and does nothing useful, which is the operator's
            // business rather than the server's.
            return subject.is_oper;
        }
        if let Some(channel) = mask.strip_prefix("~j:") {
            let wanted = canonical_channel_key(channel);
            return subject
                .channels
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&wanted));
        }
        crate::user::glob_match(mask, subject.source)
    }

    /// Whether this source is kept from speaking: the quiet list (+q), or a
    /// mute extban (+b ~m:mask), which is a ban on talking rather than on
    /// coming in. A ban exception lifts either.
    pub fn is_muted(&self, subject: &Subject) -> bool {
        // Only a mute exception lifts a mute. A plain +e is an exception to a
        // ban on coming in, and says nothing about who may talk.
        let exempt = self
            .ban_exceptions
            .iter()
            .filter_map(|e| e.strip_prefix("~m:"))
            .any(|e| Self::mask_covers(e, subject));
        if exempt {
            return false;
        }
        self.quiet_list
            .iter()
            .any(|m| Self::mask_covers(m, subject))
            || self
                .bans
                .iter()
                .filter_map(|b| crate::timed_bans::peel_timed(b).strip_prefix("~m:"))
                .any(|m| Self::mask_covers(m, subject))
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
    pub fn is_banned(&self, subject: &Subject) -> bool {
        self.bans
            .iter()
            // A mute or a nick lock lives on the ban list but is not a ban on
            // coming in: they are about what somebody may do once they are
            // here.
            .filter(|b| {
                let peeled = crate::timed_bans::peel_timed(b);
                !peeled.starts_with("~m:") && !peeled.starts_with("~n:")
            })
            .any(|b| Self::mask_covers(b, subject))
    }

    /// Whether this channel keeps this person's name still: `+b ~n:mask`,
    /// the one-person version of `+N`. Lifted by `+e ~n:mask`, as a mute is.
    pub fn forbids_nick_change(&self, subject: &Subject) -> bool {
        let exempt = self
            .ban_exceptions
            .iter()
            .filter_map(|e| crate::timed_bans::peel_timed(e).strip_prefix("~n:"))
            .any(|m| Self::mask_covers(m, subject));
        if exempt {
            return false;
        }
        self.bans
            .iter()
            .filter_map(|b| crate::timed_bans::peel_timed(b).strip_prefix("~n:"))
            .any(|m| Self::mask_covers(m, subject))
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
    pub fn is_ban_exempt(&self, subject: &Subject) -> bool {
        self.ban_exceptions
            .iter()
            // A mute exception lifts a mute, not a ban on coming in.
            .filter(|e| !e.starts_with("~m:"))
            .any(|e| Self::mask_covers(e, subject))
    }

    /// Check if source/account matches an invite exception (+I).
    pub fn is_invite_exempt(&self, subject: &Subject) -> bool {
        self.invite_exceptions
            .iter()
            .any(|e| Self::mask_covers(e, subject))
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

    /// Somebody named only by their `nick!user@host`, which is what most of
    /// these masks are about.
    fn sub(source: &str) -> Subject<'_> {
        Subject::from_source(source)
    }

    /// `~r:` asks about the real name, which a hostmask never sees.
    #[test]
    fn a_realname_extban_matches_the_gecos_rather_than_the_source() {
        let mut ch = Channel::new("#r".into());
        ch.bans.push("~r:*seedy marketing*".into());
        assert!(ch.is_banned(&sub("bob!u@host").with_realname("A Seedy Marketing Firm")));
        // A mode parameter holds no spaces, so `_` stands for one — and a
        // mask that did manage to carry spaces means the same thing.
        let mut underscored = Channel::new("#r".into());
        underscored.bans.push("~r:*seedy_marketing*".into());
        assert!(underscored.is_banned(&sub("bob!u@host").with_realname("A Seedy Marketing Firm")));
        assert!(underscored.is_banned(&sub("bob!u@host").with_realname("seedy_marketing_ltd")));
        assert!(!ch.is_banned(&sub("bob!u@host").with_realname("Bob")));
        assert!(
            !ch.is_banned(&sub("seedy marketing!u@host")),
            "the source is not the real name"
        );
        assert!(!ch.is_banned(&sub("bob!u@host")), "nobody gave a real name to match");
    }

    /// `~j:` asks which other rooms somebody is in.
    #[test]
    fn a_channel_extban_matches_being_somewhere_else() {
        let mut ch = Channel::new("#a".into());
        ch.bans.push("~j:#Raiders".into());
        let raiding = vec![canonical_channel_key("#raiders")];
        let elsewhere = vec![canonical_channel_key("#books")];
        assert!(ch.is_banned(&sub("eve!u@host").in_channels(&raiding)));
        assert!(!ch.is_banned(&sub("eve!u@host").in_channels(&elsewhere)));
        assert!(!ch.is_banned(&sub("eve!u@host")), "in no channel at all");
    }

    /// The prefixes peel one at a time, so they stack: a mute by real name,
    /// and a channel ban that lifts itself.
    #[test]
    fn extended_bans_compose_with_a_mute_and_with_a_clock() {
        let mut ch = Channel::new("#c".into());
        ch.bans.push("~m:~r:*spam*".into());
        let seller = sub("bob!u@host").with_realname("I sell spam");
        assert!(ch.is_muted(&seller), "muted by what their real name says");
        assert!(!ch.is_banned(&seller), "a mute is not a ban on coming in");

        let raiding = vec![canonical_channel_key("#raiders")];
        ch.bans.push("~t:1h:~j:#raiders".into());
        assert!(ch.is_banned(&sub("eve!u@host").in_channels(&raiding)));
        assert!(!ch.is_banned(&sub("eve!u@host")));
    }

    /// `~n:` keeps one person's name still without keeping the room's still.
    #[test]
    fn a_nick_extban_locks_a_name_without_being_a_ban() {
        let mut ch = Channel::new("#n".into());
        ch.bans.push("~n:fidget!*@*".into());
        let fidget = sub("fidget!u@host");
        assert!(ch.forbids_nick_change(&fidget));
        assert!(!ch.is_banned(&fidget), "a nick lock is not a ban on coming in");
        assert!(!ch.forbids_nick_change(&sub("steady!u@host")));
        ch.ban_exceptions.push("~n:fidget!*@*".into());
        assert!(!ch.forbids_nick_change(&fidget), "an exception lifts it");
    }

    /// `~S:` asks for the certificate, `~O` for the badge.
    #[test]
    fn a_certificate_and_a_badge_are_things_a_mask_can_ask_about() {
        let mut ch = Channel::new("#s".into());
        ch.bans.push("~S:*".into());
        assert!(ch.is_banned(&sub("bob!u@host").with_certfp(Some("beef"))));
        assert!(!ch.is_banned(&sub("bob!u@host")), "brought no certificate");
        let mut exact = Channel::new("#s".into());
        exact.bans.push("~S:beef*".into());
        assert!(exact.is_banned(&sub("bob!u@host").with_certfp(Some("beefcafe"))));
        assert!(!exact.is_banned(&sub("bob!u@host").with_certfp(Some("cafe"))));

        let mut opers = Channel::new("#o".into());
        opers.bans.push("*!*@host".into());
        opers.ban_exceptions.push("~O".into());
        let staff = sub("bob!u@host").oper(true);
        assert!(opers.is_banned(&staff));
        assert!(opers.is_ban_exempt(&staff), "an operator is excepted by ~O");
        assert!(!opers.is_ban_exempt(&sub("bob!u@host")));
    }

    /// An exception lifts an extended ban the same way it lifts a plain one.
    #[test]
    fn an_exception_lifts_an_extended_ban() {
        let mut ch = Channel::new("#e".into());
        ch.bans.push("~r:*bot*".into());
        let bot = sub("helper!u@host").with_realname("a helpful bot");
        assert!(ch.is_banned(&bot));
        ch.ban_exceptions.push("~r:*helpful*".into());
        assert!(ch.is_ban_exempt(&bot));
    }

    /// What the server shows and what it says it has are the same list.
    ///
    /// `RPL_MYINFO` used to be a string somebody typed once, and by the time
    /// anybody looked it was describing a server several releases old. The
    /// literal below is written out in full on purpose: adding a mode to
    /// `ChannelModeSet` stops this compiling until somebody decides whether
    /// it is advertised.
    #[test]
    fn every_mode_the_server_can_show_is_one_it_advertises() {
        let mut ch = Channel::new("#m".into());
        ch.modes = ChannelModeSet {
            secret: true,
            private: true,
            invite_only: true,
            topic_protect: true,
            no_external: true,
            moderated: true,
            registered_only: true,
            registered_speak: true,
            tls_only: true,
            no_colors: true,
            no_ctcp: true,
            user_limit: Some(5),
            join_throttle: Some((2, 60)),
            msg_flood: Some((3, 10)),
            no_nick_change: true,
            no_notices: true,
            op_moderated: true,
            oper_only: true,
            redirect: Some("#overflow".into()),
        };
        ch.key = Some("key".into());
        let (letters, args) = ch.mode_string();
        let advertised = all_channel_modes();
        for c in letters.chars().filter(|c| *c != '+') {
            assert!(
                advertised.contains(c),
                "a channel can show +{c} but ISUPPORT does not name it"
            );
        }
        // Every letter shown with an argument is one that says it takes one.
        let with_args: usize = letters
            .chars()
            .filter(|c| *c != '+' && mode_takes_param(*c, true))
            .count();
        assert_eq!(with_args, args.len(), "a shown mode's arguments and its letters disagree");
    }

    #[test]
    fn the_mode_classes_agree_with_each_other() {
        assert_eq!(PREFIX_MODES.len(), PREFIX_CHARS.len());
        // No letter is in two classes: CHANMODES would then be ambiguous.
        let all: Vec<char> = [
            CHANMODES_LIST,
            CHANMODES_PARAM_ALWAYS,
            CHANMODES_PARAM_SET,
            CHANMODES_FLAG,
            PREFIX_MODES,
        ]
        .iter()
        .flat_map(|p| p.chars())
        .collect();
        let mut seen = all.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), all.len(), "a mode letter is in two classes");
        assert_eq!(all_channel_modes().len(), all.len());

        for c in CHANMODES_LIST.chars().chain(CHANMODES_PARAM_ALWAYS.chars()).chain(PREFIX_MODES.chars()) {
            assert!(mode_takes_param(c, true) && mode_takes_param(c, false), "+{c} carries one either way");
        }
        for c in CHANMODES_PARAM_SET.chars() {
            assert!(mode_takes_param(c, true) && !mode_takes_param(c, false), "+{c} carries one only when set");
        }
        for c in CHANMODES_FLAG.chars() {
            assert!(!mode_takes_param(c, true) && !mode_takes_param(c, false), "+{c} never carries one");
        }
        assert_eq!(all_user_modes(), "BRgiorsw", "the user modes MODE implements");
    }

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
        assert!(!ch.is_banned(&sub("bar!user@host")));
        assert!(ch.is_muted(&sub("bar!user@host")));
        assert!(!ch.is_muted(&sub("someoneelse!user@host")));
    }

    #[test]
    fn a_plain_ban_still_keeps_someone_out() {
        let mut ch = chan();
        ch.bans.push("bar!*@*".to_string());
        assert!(ch.is_banned(&sub("bar!user@host")));
        // ...and is not, by itself, a mute.
        assert!(!ch.is_muted(&sub("bar!user@host")));
    }

    #[test]
    fn a_mute_exception_lifts_a_mute() {
        let mut ch = chan();
        ch.bans.push("~m:qux!*@*".to_string());
        ch.ban_exceptions.push("~m:*!*evan@*".to_string());
        assert!(!ch.is_muted(&sub("qux!evan@host")));
        assert!(ch.is_muted(&sub("qux!other@host")));
    }

    /// A plain +e excepts from a ban on coming in, and says nothing about who
    /// may talk — so a quiet set alongside one still holds.
    #[test]
    fn a_plain_exception_does_not_lift_a_quiet() {
        let mut ch = chan();
        ch.quiet_list.push("bar!*@*".to_string());
        ch.ban_exceptions.push("bar!*@*".to_string());
        assert!(ch.is_muted(&sub("bar!user@host")));
    }

    /// A mute exception is not a ban exception: it says who may talk, not who
    /// may come in past a ban.
    #[test]
    fn a_mute_exception_does_not_excuse_a_ban() {
        let mut ch = chan();
        ch.bans.push("qux!*@*".to_string());
        ch.ban_exceptions.push("~m:*!*evan@*".to_string());
        assert!(ch.is_banned(&sub("qux!evan@host")));
    }

    #[test]
    fn the_quiet_list_mutes_too() {
        let mut ch = chan();
        ch.quiet_list.push("bar!*@*".to_string());
        assert!(ch.is_muted(&sub("bar!user@host")));
        assert!(!ch.is_banned(&sub("bar!user@host")));
    }

    #[test]
    fn account_extbans_match_the_account_not_the_host() {
        let mut ch = chan();
        ch.bans.push("~a:evan".to_string());
        assert!(ch.is_banned(&sub("someone!user@host").with_account(Some("Evan"))));
        assert!(!ch.is_banned(&sub("someone!user@host").with_account(Some("other"))));
        assert!(!ch.is_banned(&sub("someone!user@host")));
    }

    /// Nicks and hosts are case-insensitive in IRC, so a ban has to hold when
    /// its target changes the case of its nick.
    #[test]
    fn masks_hold_regardless_of_case() {
        let mut ch = chan();
        ch.bans.push("bar!*@example.com".to_string());
        assert!(ch.is_banned(&sub("BAR!user@EXAMPLE.COM")));
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
