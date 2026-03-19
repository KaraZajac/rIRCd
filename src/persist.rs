//! Persistent data: users.toml, channels.toml, and channel history under history/.

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_CONFIG_DIR: &str = "/etc/rIRCd";

/// One registered user from users.toml ([[user]]).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserEntry {
    pub nick: String,
    /// Bcrypt hash (use rircd genpasswd to generate).
    pub password: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub public_key: String,
}

/// One channel config from channels.toml ([[channel]]).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChannelEntry {
    pub name: String,
    #[serde(default)]
    pub topic: String,
    /// Nicks or account names that should get @ (op) when they join.
    #[serde(default)]
    pub operators: Vec<String>,
    /// Nicks or account names that should get + (voice) when they join.
    #[serde(default)]
    pub voice: Vec<String>,
}

/// Wrapper to parse TOML array of tables: [[user]] / [[channel]].
#[derive(Debug, Deserialize, Serialize)]
struct UsersFile {
    #[serde(rename = "user", default)]
    users: Vec<UserEntry>,
}

#[derive(Debug, Deserialize)]
struct ChannelsFile {
    #[serde(rename = "channel", default)]
    channels: Vec<ChannelEntry>,
}

/// Load all users from users.toml. Returns empty list on missing file or parse error.
pub fn load_users(config_dir: &Path) -> Vec<UserEntry> {
    let path = config_dir.join("users.toml");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let file: UsersFile = match toml::from_str(&content) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    file.users
}

/// Error from register_user
#[derive(Debug)]
pub enum RegisterError {
    AccountExists,
    WeakPassword,
    Io(std::io::Error),
}

/// Register a new account: append to users.toml. Returns error if nick already exists or password too weak.
pub fn register_user(
    config_dir: &Path,
    nick: &str,
    password: &str,
    email: Option<&str>,
) -> Result<(), RegisterError> {
    if password.len() < 6 {
        return Err(RegisterError::WeakPassword);
    }
    let users = load_users(config_dir);
    let nick_lower = nick.to_lowercase();
    if users.iter().any(|u| u.nick.to_lowercase() == nick_lower) {
        return Err(RegisterError::AccountExists);
    }
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| {
        RegisterError::Io(std::io::Error::new(std::io::ErrorKind::Other, "bcrypt hash failed"))
    })?;
    let path = config_dir.join("users.toml");
    let mut file = UsersFile {
        users: load_users(config_dir),
    };
    file.users.push(UserEntry {
        nick: nick.to_string(),
        password: hash,
        email: email.unwrap_or("").to_string(),
        public_key: String::new(),
    });
    let content = toml::to_string_pretty(&file).map_err(|e| {
        RegisterError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;
    std::fs::write(&path, content).map_err(RegisterError::Io)?;
    Ok(())
}

/// Verify account (nick) and password against users.toml.
/// Returns true only if the account exists and the password matches the stored bcrypt hash.
pub fn verify_user(config_dir: &Path, account: &str, password: &str) -> bool {
    let users = load_users(config_dir);
    let account_lower = account.to_lowercase();
    let user = match users.iter().find(|u| u.nick.to_lowercase() == account_lower) {
        Some(u) => u,
        None => {
            tracing::info!(
                account = %account,
                config_dir = %config_dir.display(),
                users_count = users.len(),
                "SASL: account not found in users.toml (check config_dir and that account is registered)"
            );
            return false;
        }
    };
    let ok = bcrypt::verify(password, &user.password).unwrap_or(false);
    if !ok {
        tracing::info!(
            account = %account,
            "SASL: password verification failed for account (hash mismatch)"
        );
    }
    ok
}

/// Load all channel configs from channels.toml. Returns empty list on missing file or parse error.
pub fn load_channels(config_dir: &Path) -> Vec<ChannelEntry> {
    let path = config_dir.join("channels.toml");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let file: ChannelsFile = match toml::from_str(&content) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    file.channels
}

/// Map channel name (e.g. "#foo") to a safe filename without leading #.
pub fn channel_history_filename(channel_name: &str) -> String {
    channel_name
        .trim_start_matches('#')
        .trim_start_matches('&')
        .to_string()
}

/// One line in channel history (serialized in channel_name.toml).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryEntry {
    pub ts: String,
    pub source: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msgid: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ChannelHistoryFile {
    #[serde(default)]
    pub messages: Vec<HistoryEntry>,
}

const MAX_HISTORY_ENTRIES: usize = 1000;

/// Append a message to a channel's history file. Creates history dir and file if needed.
pub fn append_channel_history(
    config_dir: &Path,
    channel_name: &str,
    source: &str,
    text: &str,
    msgid: Option<&str>,
) -> std::io::Result<()> {
    let history_dir = config_dir.join("history");
    std::fs::create_dir_all(&history_dir)?;
    let base = channel_history_filename(channel_name);
    let path = history_dir.join(format!("{}.toml", base));

    let mut file = ChannelHistoryFile::default();
    if path.exists() {
        if let Ok(c) = std::fs::read_to_string(&path) {
            let _ = toml::from_str::<ChannelHistoryFile>(&c).map(|f| file = f);
        }
    }

    let ts = chrono::Utc::now().to_rfc3339();
    file.messages.push(HistoryEntry {
        ts,
        source: source.to_string(),
        text: text.to_string(),
        msgid: msgid.map(String::from),
    });
    if file.messages.len() > MAX_HISTORY_ENTRIES {
        file.messages.drain(0..file.messages.len() - MAX_HISTORY_ENTRIES);
    }
    let content = toml::to_string_pretty(&file).unwrap_or_else(|_| "messages = []\n".to_string());
    std::fs::write(path, content)
}

/// Read channel history (newest last). Returns empty vec on missing file or parse error.
pub fn read_channel_history(config_dir: &Path, channel_name: &str, limit: usize) -> Vec<HistoryEntry> {
    let history_dir = config_dir.join("history");
    let base = channel_history_filename(channel_name);
    let path = history_dir.join(format!("{}.toml", base));
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let file: ChannelHistoryFile = match toml::from_str(&content) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let len = file.messages.len();
    let start = if limit >= len { 0 } else { len - limit };
    file.messages[start..].to_vec()
}
