//! Patterns an operator would rather never see again.
//!
//! What Unreal calls a spamfilter: a pattern, what it is looked for in, and
//! what happens when it is found. Every line a client sends that could carry
//! a payload — a message, a nick, a topic, a quit reason, a real name — is
//! held against the list before anything else is done with it.
//!
//! Two rules shape the design. The first is that this runs on the one
//! dispatch loop, for every line, so the cost has to be bounded and small:
//! the list is capped, patterns are capped, and a regular expression is
//! compiled once when it is added rather than each time it is used, by a
//! crate that promises to match in time linear in the subject. A pattern
//! that could take exponential time is a pattern an operator could wedge
//! their own server with.
//!
//! The second is that a spammer is not told what they hit. A refusal says
//! the message was not delivered and nothing else; which pattern caught it
//! goes to the operators and the log. Telling somebody exactly what tripped
//! is handing them the way around it.

use crate::config::Config;
use crate::protocol::Message;
use crate::user::{Senders, ServerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// How many filters the list may hold. Every line is held against all of
/// them, so this is a budget rather than a preference.
pub const MAX_FILTERS: usize = 64;
/// The longest pattern that may be added.
pub const MAX_PATTERN: usize = 512;
/// The longest subject that is matched. Past this a line is judged on its
/// beginning; a filter is not a reason to walk a megabyte of text twice.
const MAX_SUBJECT: usize = 4096;

/// What a filter looks at. One letter each, because they are typed together:
/// `pc` is private and channel messages.
pub const TARGET_LETTERS: &str = "pcntqr";

/// What each target letter means, for HELP.
pub fn target_meaning(letter: char) -> &'static str {
    match letter {
        'p' => "private messages",
        'c' => "channel messages",
        'n' => "nicks",
        't' => "topics",
        'q' => "quit reasons",
        'r' => "real names",
        _ => "",
    }
}

/// What happens when a filter matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Let it through and tell the operators. What a new filter should wear
    /// until somebody has watched it for a day.
    Warn,
    /// Refuse the line. The sender is told it was not delivered.
    Block,
    /// Refuse the line and close the connection.
    Kill,
    /// Refuse the line and ban the address for `duration` seconds.
    Kline,
    Dline,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Warn => "warn",
            Action::Block => "block",
            Action::Kill => "kill",
            Action::Kline => "kline",
            Action::Dline => "dline",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "warn" => Action::Warn,
            "block" => Action::Block,
            "kill" => Action::Kill,
            "kline" => Action::Kline,
            "dline" => Action::Dline,
            _ => return None,
        })
    }
}

/// A pattern, compiled. A glob by default, because most patterns are one
/// phrase and a glob is what an operator expects; `/…/` for a regular
/// expression when a glob will not say it.
#[derive(Debug, Clone)]
enum Pattern {
    Glob(String),
    Regex(std::sync::Arc<regex::Regex>),
}

/// One filter.
#[derive(Debug, Clone)]
pub struct SpamFilter {
    /// The pattern as it was typed, which is also its identity: two servers
    /// hold the same filter when they hold the same pattern.
    pub pattern: String,
    compiled: Pattern,
    /// Letters from `TARGET_LETTERS`.
    pub targets: String,
    pub action: Action,
    /// Seconds a `kline` or `dline` lasts; 0 for no end.
    pub duration: i64,
    pub set_by: String,
    pub set_at: i64,
    /// How many times it has matched since this server started.
    pub hits: u64,
}

impl SpamFilter {
    /// Compile a pattern, or say why it cannot be one.
    pub fn compile(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("a filter needs a pattern".into());
        }
        if pattern.len() > MAX_PATTERN {
            return Err(format!("a pattern is at most {MAX_PATTERN} characters"));
        }
        let compiled = match pattern.strip_prefix('/').and_then(|p| p.strip_suffix('/')) {
            Some(re) if !re.is_empty() => {
                // Bounded on purpose: a pattern that compiles to a large
                // automaton is memory this server did not agree to spend.
                let built = regex::RegexBuilder::new(re)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .dfa_size_limit(1 << 20)
                    .build()
                    .map_err(|e| format!("that is not a regular expression: {e}"))?;
                Pattern::Regex(std::sync::Arc::new(built))
            }
            _ => {
                // A glob with nothing but wildcards matches everything, and a
                // filter that matches everything is a server that carries
                // nothing.
                if pattern.chars().all(|c| matches!(c, '*' | '?')) {
                    return Err("a pattern made only of wildcards would match every line".into());
                }
                Pattern::Glob(pattern.to_string())
            }
        };
        Ok(Self {
            pattern: pattern.to_string(),
            compiled,
            targets: String::new(),
            action: Action::Warn,
            duration: 0,
            set_by: String::new(),
            set_at: 0,
            hits: 0,
        })
    }

    /// Whether this filter looks at that kind of line.
    pub fn watches(&self, kind: char) -> bool {
        self.targets.contains(kind)
    }

    /// Whether the text matches. A glob is matched as a ban mask is, so a
    /// pattern without wildcards has to be the whole line — `*spam*` is how
    /// an operator says "anywhere in it", the same as everywhere else here.
    pub fn matches(&self, text: &str) -> bool {
        let text = if text.len() > MAX_SUBJECT {
            match text.char_indices().nth(MAX_SUBJECT) {
                Some((i, _)) => &text[..i],
                None => text,
            }
        } else {
            text
        };
        match &self.compiled {
            Pattern::Glob(p) => crate::user::glob_match(p, text),
            Pattern::Regex(re) => re.is_match(text),
        }
    }

    /// A short, stable name for this filter, so `SPAMFILTER DEL` can take
    /// one rather than the whole pattern, and mean the same on every server.
    pub fn id(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.pattern.as_bytes());
        digest[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// What the caller should do with the line it was about to handle.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing matched, or what matched only wanted to be noted.
    Allow,
    /// Do not deliver it. The sender has not been told anything yet.
    Refuse,
}

/// Hold a line against the list, and do what the first matching filter says.
///
/// `kind` is one of `TARGET_LETTERS`; `who` is the client the line came
/// from. Returns whether the caller should go on with it. Nothing here
/// tells the sender anything: what a refusal looks like belongs to the
/// command that was refused.
pub async fn screen(
    kind: char,
    text: &str,
    client_id: &str,
    state: &Arc<RwLock<ServerState>>,
    senders: &Senders,
    cfg: &Config,
) -> Verdict {
    // The common case is an empty list, and it costs one read lock to say so.
    let hit = {
        let state_r = state.read().await;
        if state_r.spam_filters.is_empty() {
            return Verdict::Allow;
        }
        state_r
            .spam_filters
            .iter()
            .position(|f| f.watches(kind) && f.matches(text))
    };
    let Some(index) = hit else {
        return Verdict::Allow;
    };
    let (filter, source, host, is_oper) = {
        let mut state_w = state.write().await;
        let Some(filter) = state_w.spam_filters.get_mut(index) else {
            return Verdict::Allow;
        };
        filter.hits += 1;
        let filter = filter.clone();
        let (source, host, is_oper) = match state_w.clients.get(client_id) {
            Some(c) => {
                let g = c.read().await;
                (
                    g.source().unwrap_or_else(|| g.nick_or_id().to_string()),
                    g.host.clone(),
                    g.oper,
                )
            }
            None => match state_w.pending.get(client_id) {
                Some(p) => (
                    p.nick.clone().unwrap_or_else(|| "*".to_string()),
                    p.host.clone(),
                    false,
                ),
                None => return Verdict::Allow,
            },
        };
        (filter, source, host, is_oper)
    };

    // An operator is not the crowd this is for, and a filter that kills the
    // person who could lift it is a server nobody can get back into.
    if is_oper {
        tracing::info!(
            client_id, %source, pattern = %filter.pattern, %kind,
            "Spam filter matched an operator; letting it through"
        );
        return Verdict::Allow;
    }

    let shown: String = text.chars().take(80).collect();
    tracing::warn!(
        client_id,
        %source,
        pattern = %filter.pattern,
        action = filter.action.name(),
        %kind,
        "Spam filter matched: {shown}"
    );
    crate::commands::registration::notify_opers(
        state,
        senders,
        &cfg.server.name,
        'f',
        &format!(
            "Spam filter [{}] {} matched {} from {}: {}",
            filter.id(),
            filter.pattern,
            match kind {
                'p' => "a private message",
                'c' => "a channel message",
                'n' => "a nick",
                't' => "a topic",
                'q' => "a quit reason",
                _ => "a real name",
            },
            source,
            shown
        ),
    )
    .await;

    match filter.action {
        Action::Warn => Verdict::Allow,
        Action::Block => Verdict::Refuse,
        Action::Kill => {
            senders.write().await.close_user(
                &state.read().await.user_id(client_id),
                Message::new("ERROR", vec!["Closing link: filtered".into()])
                    .with_prefix(&cfg.server.name),
            );
            Verdict::Refuse
        }
        Action::Kline | Action::Dline => {
            let (mask, kind) = if filter.action == Action::Dline {
                (host.clone(), crate::persist::BanKind::Dline)
            } else {
                (format!("*!*@{host}"), crate::persist::BanKind::Kline)
            };
            let ban = crate::persist::ServerBan {
                mask,
                reason: format!("Filtered ({})", filter.id()),
                set_by: cfg.server.name.clone(),
                set_at: chrono::Utc::now().timestamp(),
                expires_at: (filter.duration > 0)
                    .then(|| chrono::Utc::now().timestamp().saturating_add(filter.duration)),
                kind,
            };
            if let Some(ref pool) = cfg.db {
                if let Err(e) = crate::persist::save_server_ban(pool, &ban).await {
                    tracing::error!(mask = %ban.mask, "Spam filter: could not store the ban: {e}");
                }
            }
            crate::link::announce_kline(cfg, &ban).await;
            crate::commands::server_cmds::enforce_ban(state, senders, &cfg.server.name, &ban).await;
            Verdict::Refuse
        }
    }
}

/// Add a filter to this server's list, replacing one with the same pattern.
/// Returns false when the list is full.
pub fn install(state: &mut ServerState, filter: SpamFilter) -> bool {
    if let Some(existing) = state
        .spam_filters
        .iter_mut()
        .find(|f| f.pattern == filter.pattern)
    {
        let hits = existing.hits;
        *existing = filter;
        existing.hits = hits;
        return true;
    }
    if state.spam_filters.len() >= MAX_FILTERS {
        return false;
    }
    state.spam_filters.push(filter);
    true
}

/// Take a filter off the list, by its id or its pattern. Returns the
/// pattern that went.
pub fn remove(state: &mut ServerState, id_or_pattern: &str) -> Option<String> {
    let index = state.spam_filters.iter().position(|f| {
        f.pattern == id_or_pattern || f.id().eq_ignore_ascii_case(id_or_pattern)
    })?;
    Some(state.spam_filters.remove(index).pattern)
}

/// Read a filter back from the database, or from a peer.
pub fn rebuild(
    pattern: &str,
    targets: &str,
    action: &str,
    duration: i64,
    set_by: &str,
    set_at: i64,
) -> Result<SpamFilter, String> {
    let mut filter = SpamFilter::compile(pattern)?;
    filter.targets = normalise_targets(targets)?;
    filter.action = Action::parse(action).ok_or("that is not an action")?;
    filter.duration = duration.clamp(0, 366 * 86_400);
    filter.set_by = set_by.to_string();
    filter.set_at = set_at;
    Ok(filter)
}

/// The letters a filter looks at, in one order, with `*` meaning all of
/// them. An unknown letter is a mistake rather than something to ignore:
/// a filter that watches less than the operator thought is worse than none.
pub fn normalise_targets(targets: &str) -> Result<String, String> {
    if targets == "*" {
        return Ok(TARGET_LETTERS.to_string());
    }
    let mut seen: Vec<char> = Vec::new();
    for c in targets.chars() {
        if !TARGET_LETTERS.contains(c) {
            return Err(format!("{c} is not something a filter can look at"));
        }
        if !seen.contains(&c) {
            seen.push(c);
        }
    }
    if seen.is_empty() {
        return Err("a filter has to look at something".into());
    }
    let mut out = String::new();
    for c in TARGET_LETTERS.chars() {
        if seen.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_glob_matches_the_way_a_ban_mask_does() {
        let mut f = SpamFilter::compile("*buy now*").unwrap();
        f.targets = "pc".into();
        assert!(f.matches("hello, BUY NOW please"));
        assert!(!f.matches("nothing to see"));
        assert!(f.watches('p') && f.watches('c') && !f.watches('n'));
    }

    #[test]
    fn a_pattern_between_slashes_is_a_regular_expression() {
        let f = SpamFilter::compile(r"/https?:\/\/\S+\.(tk|top)\b/").unwrap();
        assert!(f.matches("come to http://spam.tk now"));
        assert!(!f.matches("http://example.org is fine"));
    }

    #[test]
    fn a_pattern_that_cannot_be_one_is_refused() {
        assert!(SpamFilter::compile("").is_err());
        assert!(SpamFilter::compile("***").is_err(), "would match every line");
        assert!(SpamFilter::compile("/(/").is_err(), "not a regular expression");
        assert!(SpamFilter::compile(&"x".repeat(MAX_PATTERN + 1)).is_err());
        // A pattern that would take exponential time in a backtracking engine
        // is merely a pattern here, and is answered rather than hung on.
        let f = SpamFilter::compile("/(a+)+b/").unwrap();
        assert!(!f.matches(&"a".repeat(40)));
    }

    #[test]
    fn the_same_pattern_has_the_same_name_everywhere() {
        let a = SpamFilter::compile("*spam*").unwrap();
        let b = SpamFilter::compile("*spam*").unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.id().len(), 8);
        assert_ne!(a.id(), SpamFilter::compile("*ham*").unwrap().id());
    }

    #[test]
    fn targets_are_kept_in_one_order_and_checked() {
        assert_eq!(normalise_targets("cp").unwrap(), "pc");
        assert_eq!(normalise_targets("ppc").unwrap(), "pc");
        assert_eq!(normalise_targets("*").unwrap(), TARGET_LETTERS);
        assert!(normalise_targets("pz").is_err());
        assert!(normalise_targets("").is_err());
    }
}
