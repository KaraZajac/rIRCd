//! Persistent data backed by MariaDB via sqlx.
//!
//! All tables are created automatically on first startup via `init_schema`.
//! The pool is held in `Config::db` and passed to every function here.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Error from `register_user`.
#[derive(Debug)]
pub enum RegisterError {
    AccountExists,
    WeakPassword,
    /// Database or hashing error (description string).
    Io(String),
}

/// One channel config row from the database.
#[derive(Debug, Clone)]
pub struct ChannelEntry {
    pub name: String,
    pub topic: String,
    /// Nicks or account names that get @ (op) on join.
    pub operators: Vec<String>,
    /// Nicks or account names that get + (voice) on join.
    pub voice: Vec<String>,
    /// Persisted mode flags string (e.g. "imns")
    pub mode_flags: String,
    /// Persisted channel key (+k)
    pub mode_key: Option<String>,
    /// Persisted user limit (+l)
    pub mode_limit: Option<u32>,
    /// Channel creation Unix timestamp
    pub created_at: i64,
}

/// One line of channel history from the database.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryEntry {
    pub ts: String,
    pub source: String,
    pub text: String,
    pub msgid: Option<String>,
    /// IRC command: PRIVMSG, NOTICE, JOIN, PART, QUIT, TOPIC, NICK (for event-playback)
    pub command: String,
    /// If this message was edited, the msgid it replaced (for draft/message-edit replay)
    pub original_msgid: Option<String>,
}

/// Maximum number of history rows retained per channel.
const MAX_HISTORY_ENTRIES: i64 = 1000;

// ─── Schema ──────────────────────────────────────────────────────────────────

/// Create all required tables if they do not already exist.
pub async fn init_schema(pool: &sqlx::MySqlPool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id              BIGINT AUTO_INCREMENT PRIMARY KEY,
            nick            VARCHAR(64)  NOT NULL,
            nick_lower      VARCHAR(64)  NOT NULL UNIQUE,
            password        VARCHAR(255) NOT NULL,
            email           VARCHAR(255) NOT NULL DEFAULT '',
            scram_salt      VARCHAR(64)  NOT NULL DEFAULT '',
            scram_iterations INT UNSIGNED NOT NULL DEFAULT 4096,
            scram_stored_key VARCHAR(64) NOT NULL DEFAULT '',
            scram_server_key VARCHAR(64) NOT NULL DEFAULT '',
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    // Migrate existing tables that were created before SCRAM columns were added
    for col_def in &[
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS scram_salt VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS scram_iterations INT UNSIGNED NOT NULL DEFAULT 4096",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS scram_stored_key VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS scram_server_key VARCHAR(64) NOT NULL DEFAULT ''",
    ] {
        let _ = sqlx::query(col_def).execute(pool).await;
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channels (
            id          BIGINT AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(64)  NOT NULL UNIQUE,
            topic       TEXT         NOT NULL DEFAULT '',
            mode_flags  VARCHAR(32)  NOT NULL DEFAULT '',
            mode_key    VARCHAR(64)  NULL,
            mode_limit  INT UNSIGNED NULL,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    // Migrate existing channels table
    for col_def in &[
        "ALTER TABLE channels ADD COLUMN IF NOT EXISTS mode_flags VARCHAR(32) NOT NULL DEFAULT ''",
        "ALTER TABLE channels ADD COLUMN IF NOT EXISTS mode_key VARCHAR(64) NULL",
        "ALTER TABLE channels ADD COLUMN IF NOT EXISTS mode_limit INT UNSIGNED NULL",
    ] {
        let _ = sqlx::query(col_def).execute(pool).await;
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_operators (
            channel_id     BIGINT      NOT NULL,
            nick_or_account VARCHAR(64) NOT NULL,
            PRIMARY KEY (channel_id, nick_or_account),
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_voice (
            channel_id      BIGINT      NOT NULL,
            nick_or_account VARCHAR(64) NOT NULL,
            PRIMARY KEY (channel_id, nick_or_account),
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_history (
            id      BIGINT AUTO_INCREMENT PRIMARY KEY,
            channel VARCHAR(64)  NOT NULL,
            ts      VARCHAR(64)  NOT NULL,
            source  VARCHAR(512) NOT NULL,
            text    TEXT         NOT NULL,
            msgid   VARCHAR(128) DEFAULT NULL,
            INDEX idx_channel_ts (channel, id)
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    // Migrate existing channel_history table to add soft-delete support
    sqlx::query(
        "ALTER TABLE channel_history ADD COLUMN IF NOT EXISTS redacted TINYINT NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await
    .ok(); // ok() because IF NOT EXISTS makes this idempotent

    sqlx::query(
        "ALTER TABLE channel_history ADD INDEX IF NOT EXISTS idx_channel_redacted (channel, redacted, id)",
    )
    .execute(pool)
    .await
    .ok();

    // Migrate: add command column for event-playback (JOIN/PART/QUIT/TOPIC/NICK events)
    sqlx::query(
        "ALTER TABLE channel_history ADD COLUMN IF NOT EXISTS command VARCHAR(16) NOT NULL DEFAULT 'PRIVMSG'",
    )
    .execute(pool)
    .await
    .ok();

    // Migrate: add original_msgid column for edit replay in CHATHISTORY
    sqlx::query(
        "ALTER TABLE channel_history ADD COLUMN IF NOT EXISTS original_msgid VARCHAR(128) DEFAULT NULL",
    )
    .execute(pool)
    .await
    .ok();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS read_markers (
            account   VARCHAR(64)  NOT NULL,
            target    VARCHAR(128) NOT NULL,
            timestamp VARCHAR(64)  NOT NULL,
            PRIMARY KEY (account, target)
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS metadata (
            target    VARCHAR(128) NOT NULL,
            meta_key  VARCHAR(128) NOT NULL,
            value     TEXT         NOT NULL,
            PRIMARY KEY (target, meta_key)
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    // Migrate: add certfp column for SASL EXTERNAL (TLS client certificate fingerprint)
    sqlx::query(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS certfp VARCHAR(128) DEFAULT NULL",
    )
    .execute(pool)
    .await
    .ok();

    sqlx::query(
        "ALTER TABLE users ADD INDEX IF NOT EXISTS idx_certfp (certfp)",
    )
    .execute(pool)
    .await
    .ok();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS whowas (
            id         BIGINT AUTO_INCREMENT PRIMARY KEY,
            nick       VARCHAR(64)  NOT NULL,
            nick_lower VARCHAR(64)  NOT NULL,
            username   VARCHAR(64)  NOT NULL,
            host       VARCHAR(255) NOT NULL,
            realname   VARCHAR(255) NOT NULL DEFAULT '',
            server     VARCHAR(255) NOT NULL,
            quit_time  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_whowas_nick (nick_lower)
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    tracing::info!("Database schema ready");
    Ok(())
}

// ─── SASL EXTERNAL (certfp) ──────────────────────────────────────────────────

/// Look up an account by TLS client certificate fingerprint (SHA-256 hex).
pub async fn lookup_account_by_certfp(pool: &sqlx::MySqlPool, certfp: &str) -> Option<String> {
    use sqlx::Row;
    sqlx::query("SELECT nick FROM users WHERE certfp = ? LIMIT 1")
        .bind(certfp)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.get("nick"))
}

/// Associate a TLS certificate fingerprint with an account.
pub async fn set_certfp(pool: &sqlx::MySqlPool, account: &str, certfp: &str) {
    let account_lower = account.to_lowercase();
    let _ = sqlx::query("UPDATE users SET certfp = ? WHERE nick_lower = ?")
        .bind(certfp)
        .bind(&account_lower)
        .execute(pool)
        .await;
}

// ─── Channels ─────────────────────────────────────────────────────────────────

/// Load all channel configs from the database.
pub async fn load_channels(pool: &sqlx::MySqlPool) -> Vec<ChannelEntry> {
    use sqlx::Row;

    let rows = match sqlx::query(
        "SELECT id, name, topic, mode_flags, mode_key, mode_limit, UNIX_TIMESTAMP(created_at) AS created_ts FROM channels",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to load channels from database: {}", e);
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for row in rows {
        let id: i64 = row.get("id");
        let name: String = row.get("name");
        let topic: String = row.get("topic");
        let mode_flags: String = row.try_get("mode_flags").unwrap_or_default();
        let mode_key: Option<String> = row.try_get("mode_key").unwrap_or(None);
        let mode_limit: Option<u32> = row.try_get("mode_limit").unwrap_or(None);
        let created_at: i64 = row.try_get("created_ts").unwrap_or(0);

        let ops: Vec<String> =
            sqlx::query("SELECT nick_or_account FROM channel_operators WHERE channel_id = ?")
                .bind(id)
                .fetch_all(pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r: sqlx::mysql::MySqlRow| r.get("nick_or_account"))
                .collect();

        let voice: Vec<String> =
            sqlx::query("SELECT nick_or_account FROM channel_voice WHERE channel_id = ?")
                .bind(id)
                .fetch_all(pool)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r: sqlx::mysql::MySqlRow| r.get("nick_or_account"))
                .collect();

        entries.push(ChannelEntry {
            name,
            topic,
            operators: ops,
            voice,
            mode_flags,
            mode_key,
            mode_limit,
            created_at,
        });
    }
    entries
}

// ─── Channel mode persistence ─────────────────────────────────────────────────

/// Upsert the mode_flags, mode_key, and mode_limit for a channel by name.
pub async fn save_channel_modes(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    mode_flags: &str,
    mode_key: Option<&str>,
    mode_limit: Option<u32>,
) {
    let _ = sqlx::query(
        "INSERT INTO channels (name, mode_flags, mode_key, mode_limit)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE mode_flags = VALUES(mode_flags), mode_key = VALUES(mode_key), mode_limit = VALUES(mode_limit)",
    )
    .bind(channel_name)
    .bind(mode_flags)
    .bind(mode_key)
    .bind(mode_limit)
    .execute(pool)
    .await;
}

// ─── Read markers ─────────────────────────────────────────────────────────────

/// Upsert a read marker timestamp for an account+target.
pub async fn save_read_marker(
    pool: &sqlx::MySqlPool,
    account: &str,
    target: &str,
    timestamp: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO read_markers (account, target, timestamp) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE timestamp = VALUES(timestamp)",
    )
    .bind(account)
    .bind(target)
    .bind(timestamp)
    .execute(pool)
    .await;
}

/// Load all read markers from the database into a nested HashMap.
pub async fn load_read_markers(
    pool: &sqlx::MySqlPool,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    use sqlx::Row;
    let mut out: std::collections::HashMap<String, std::collections::HashMap<String, String>> =
        Default::default();
    let rows = sqlx::query("SELECT account, target, timestamp FROM read_markers")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for row in rows {
        let account: String = row.get("account");
        let target: String = row.get("target");
        let timestamp: String = row.get("timestamp");
        out.entry(account).or_default().insert(target, timestamp);
    }
    out
}

// ─── Metadata ─────────────────────────────────────────────────────────────────

/// Upsert a metadata key-value for a target.
pub async fn save_metadata(pool: &sqlx::MySqlPool, target: &str, key: &str, value: &str) {
    let _ = sqlx::query(
        "INSERT INTO metadata (target, meta_key, value) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value)",
    )
    .bind(target)
    .bind(key)
    .bind(value)
    .execute(pool)
    .await;
}

/// Delete a metadata key for a target.
pub async fn delete_metadata(pool: &sqlx::MySqlPool, target: &str, key: &str) {
    let _ = sqlx::query("DELETE FROM metadata WHERE target = ? AND meta_key = ?")
        .bind(target)
        .bind(key)
        .execute(pool)
        .await;
}

/// Delete all metadata for a target.
pub async fn clear_metadata(pool: &sqlx::MySqlPool, target: &str) {
    let _ = sqlx::query("DELETE FROM metadata WHERE target = ?")
        .bind(target)
        .execute(pool)
        .await;
}

/// Load all metadata from the database.
pub async fn load_all_metadata(
    pool: &sqlx::MySqlPool,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    use sqlx::Row;
    let mut out: std::collections::HashMap<String, std::collections::HashMap<String, String>> =
        Default::default();
    let rows = sqlx::query("SELECT target, meta_key, value FROM metadata")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for row in rows {
        let target: String = row.get("target");
        let key: String = row.get("meta_key");
        let value: String = row.get("value");
        out.entry(target).or_default().insert(key, value);
    }
    out
}

// ─── SCRAM-SHA-256 helpers ────────────────────────────────────────────────────

const SCRAM_ITERATIONS: u32 = 4096;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

/// Compute SCRAM-SHA-256 (StoredKey, ServerKey) from a cleartext password.
pub fn scram_compute(password: &str, salt: &[u8], iterations: u32) -> ([u8; 32], [u8; 32]) {
    let salted = pbkdf2_sha256(password.as_bytes(), salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let server_key = hmac_sha256(&salted, b"Server Key");
    (stored_key, server_key)
}

/// SCRAM credentials retrieved from the database.
pub struct ScramCredentials {
    pub salt_b64: String,
    pub iterations: u32,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

/// Retrieve SCRAM-SHA-256 credentials for an account. Returns None if account not found or not enrolled.
pub async fn get_scram_credentials(
    pool: &sqlx::MySqlPool,
    account: &str,
) -> Option<ScramCredentials> {
    use sqlx::Row;

    let account_lower = account.to_lowercase();
    let row = sqlx::query(
        "SELECT scram_salt, scram_iterations, scram_stored_key, scram_server_key
         FROM users WHERE nick_lower = ?",
    )
    .bind(&account_lower)
    .fetch_optional(pool)
    .await
    .ok()??;

    let salt_b64: String = row.get("scram_salt");
    let iterations: u32 = row.get("scram_iterations");
    let stored_b64: String = row.get("scram_stored_key");
    let server_b64: String = row.get("scram_server_key");

    if salt_b64.is_empty() || stored_b64.is_empty() {
        return None; // Not SCRAM-enrolled (registered before this feature)
    }

    let stored_key: [u8; 32] = B64.decode(&stored_b64).ok()?.try_into().ok()?;
    let server_key: [u8; 32] = B64.decode(&server_b64).ok()?.try_into().ok()?;

    Some(ScramCredentials {
        salt_b64,
        iterations,
        stored_key,
        server_key,
    })
}

// ─── Users ────────────────────────────────────────────────────────────────────

/// Register a new account. Fails if nick already exists or password is too short.
pub async fn register_user(
    pool: &sqlx::MySqlPool,
    nick: &str,
    password: &str,
    email: Option<&str>,
) -> Result<(), RegisterError> {
    if password.len() < 6 {
        return Err(RegisterError::WeakPassword);
    }

    let nick_lower = nick.to_lowercase();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE nick_lower = ?")
        .bind(&nick_lower)
        .fetch_one(pool)
        .await
        .map_err(|e| RegisterError::Io(e.to_string()))?;

    if count > 0 {
        return Err(RegisterError::AccountExists);
    }

    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| RegisterError::Io(e.to_string()))?;

    // Compute SCRAM-SHA-256 credentials at registration time
    let salt: [u8; 16] = rand::thread_rng().gen();
    let (stored_key, server_key) = scram_compute(password, &salt, SCRAM_ITERATIONS);
    let salt_b64 = B64.encode(salt);
    let stored_b64 = B64.encode(stored_key);
    let server_b64 = B64.encode(server_key);

    sqlx::query(
        "INSERT INTO users (nick, nick_lower, password, email, scram_salt, scram_iterations, scram_stored_key, scram_server_key)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(nick)
    .bind(&nick_lower)
    .bind(&hash)
    .bind(email.unwrap_or(""))
    .bind(&salt_b64)
    .bind(SCRAM_ITERATIONS)
    .bind(&stored_b64)
    .bind(&server_b64)
    .execute(pool)
    .await
    .map_err(|e| RegisterError::Io(e.to_string()))?;

    Ok(())
}

/// Verify an account's password against the stored bcrypt hash.
pub async fn verify_user(pool: &sqlx::MySqlPool, account: &str, password: &str) -> bool {
    use sqlx::Row;

    let account_lower = account.to_lowercase();

    let row = sqlx::query("SELECT password FROM users WHERE nick_lower = ?")
        .bind(&account_lower)
        .fetch_optional(pool)
        .await;

    match row {
        Ok(Some(r)) => {
            let hash: String = r.get("password");
            let ok = bcrypt::verify(password, &hash).unwrap_or(false);
            if !ok {
                tracing::info!(
                    account = %account,
                    "SASL: password verification failed (hash mismatch)"
                );
            }
            ok
        }
        Ok(None) => {
            tracing::info!(
                account = %account,
                "SASL: account not found in database"
            );
            false
        }
        Err(e) => {
            tracing::warn!("Database error verifying user '{}': {}", account, e);
            false
        }
    }
}

// ─── Channel history ──────────────────────────────────────────────────────────

/// Append a message or event to channel history. Prunes oldest rows beyond the per-channel cap.
/// `command` is the IRC command: "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT", "TOPIC", "NICK".
pub async fn append_channel_history(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    source: &str,
    text: &str,
    msgid: Option<&str>,
    command: &str,
) -> anyhow::Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO channel_history (channel, ts, source, text, msgid, command) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(channel_name)
    .bind(&ts)
    .bind(source)
    .bind(text)
    .bind(msgid)
    .bind(command)
    .execute(pool)
    .await?;

    // Prune rows beyond the cap using MariaDB's DELETE ... ORDER BY ... LIMIT
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channel_history WHERE channel = ?")
        .bind(channel_name)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    if count > MAX_HISTORY_ENTRIES {
        let excess = count - MAX_HISTORY_ENTRIES;
        sqlx::query("DELETE FROM channel_history WHERE channel = ? ORDER BY id ASC LIMIT ?")
            .bind(channel_name)
            .bind(excess)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Convert a sqlx row into a HistoryEntry.
fn row_to_entry(r: &sqlx::mysql::MySqlRow) -> HistoryEntry {
    use sqlx::Row;
    HistoryEntry {
        ts: r.get("ts"),
        source: r.get("source"),
        text: r.get("text"),
        msgid: r.get("msgid"),
        command: r
            .try_get::<String, _>("command")
            .unwrap_or_else(|_| "PRIVMSG".into()),
        original_msgid: r.try_get("original_msgid").unwrap_or(None),
    }
}

/// Read the most recent `limit` entries for a channel, oldest-first (for CHATHISTORY playback).
/// If `include_events` is false, only PRIVMSG and NOTICE are returned.
pub async fn read_channel_history(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    limit: usize,
    include_events: bool,
) -> Vec<HistoryEntry> {
    let event_filter = if include_events {
        ""
    } else {
        " AND (command = 'PRIVMSG' OR command = 'NOTICE')"
    };
    let sql = format!(
        "SELECT ts, source, text, msgid, command, original_msgid
         FROM (
             SELECT id, ts, source, text, msgid, command, original_msgid
             FROM channel_history
             WHERE channel = ? AND redacted=0{event_filter}
             ORDER BY id DESC
             LIMIT ?
         ) AS recent
         ORDER BY id ASC"
    );
    let rows = sqlx::query(&sql)
        .bind(channel_name)
        .bind(limit as i64)
        .fetch_all(pool)
        .await;

    match rows {
        Ok(rows) => rows.iter().map(row_to_entry).collect(),
        Err(e) => {
            tracing::warn!(
                "Failed to read channel history for '{}': {}",
                channel_name,
                e
            );
            Vec::new()
        }
    }
}

/// Resolve a CHATHISTORY cursor (`msgid=xxx` or `timestamp=xxx`) to a row id.
/// For msgid cursors, returns the id of that exact row.
/// For timestamp cursors, returns the id of the last row at or before that timestamp.
async fn resolve_cursor(pool: &sqlx::MySqlPool, channel_name: &str, cursor: &str) -> Option<i64> {
    use sqlx::Row;
    if let Some(msgid) = cursor.strip_prefix("msgid=") {
        sqlx::query("SELECT id FROM channel_history WHERE channel = ? AND msgid = ? LIMIT 1")
            .bind(channel_name)
            .bind(msgid)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .map(|r: sqlx::mysql::MySqlRow| r.get::<i64, _>("id"))
    } else if let Some(ts) = cursor.strip_prefix("timestamp=") {
        sqlx::query(
            "SELECT id FROM channel_history WHERE channel = ? AND ts <= ? ORDER BY id DESC LIMIT 1",
        )
        .bind(channel_name)
        .bind(ts)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r: sqlx::mysql::MySqlRow| r.get::<i64, _>("id"))
    } else {
        None
    }
}

/// Read up to `limit` entries strictly BEFORE the cursor, returned oldest-first.
pub async fn read_channel_history_before(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    cursor: &str,
    limit: usize,
    include_events: bool,
) -> Vec<HistoryEntry> {
    let pivot = match resolve_cursor(pool, channel_name, cursor).await {
        Some(id) => id,
        None => return Vec::new(),
    };
    let event_filter = if include_events {
        ""
    } else {
        " AND (command = 'PRIVMSG' OR command = 'NOTICE')"
    };
    let sql = format!(
        "SELECT ts, source, text, msgid, command, original_msgid
         FROM (
             SELECT id, ts, source, text, msgid, command, original_msgid
             FROM channel_history
             WHERE channel = ? AND id < ? AND redacted=0{event_filter}
             ORDER BY id DESC
             LIMIT ?
         ) AS sub
         ORDER BY id ASC"
    );
    sqlx::query(&sql)
        .bind(channel_name)
        .bind(pivot)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .iter()
        .map(row_to_entry)
        .collect()
}

/// Read up to `limit` entries strictly AFTER the cursor, returned oldest-first.
pub async fn read_channel_history_after(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    cursor: &str,
    limit: usize,
    include_events: bool,
) -> Vec<HistoryEntry> {
    let pivot = match resolve_cursor(pool, channel_name, cursor).await {
        Some(id) => id,
        None => return Vec::new(),
    };
    let event_filter = if include_events {
        ""
    } else {
        " AND (command = 'PRIVMSG' OR command = 'NOTICE')"
    };
    let sql = format!(
        "SELECT id, ts, source, text, msgid, command, original_msgid
         FROM channel_history
         WHERE channel = ? AND id > ? AND redacted=0{event_filter}
         ORDER BY id ASC
         LIMIT ?"
    );
    sqlx::query(&sql)
        .bind(channel_name)
        .bind(pivot)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .iter()
        .map(row_to_entry)
        .collect()
}

/// Read entries centered around a reference point (`msgid=xxx` or `timestamp=xxx`), oldest-first.
pub async fn read_channel_history_around(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    cursor: &str,
    limit: usize,
    include_events: bool,
) -> Vec<HistoryEntry> {
    let half = limit.div_ceil(2).max(1) as i64;
    let pivot_id = match resolve_cursor(pool, channel_name, cursor).await {
        Some(id) => id,
        None => return Vec::new(),
    };

    let event_filter = if include_events {
        ""
    } else {
        " AND (command = 'PRIVMSG' OR command = 'NOTICE')"
    };

    let before_sql = format!(
        "SELECT id, ts, source, text, msgid, command, original_msgid FROM channel_history WHERE channel = ? AND id <= ? AND redacted=0{event_filter} ORDER BY id DESC LIMIT ?"
    );
    let before = sqlx::query(&before_sql)
        .bind(channel_name)
        .bind(pivot_id)
        .bind(half)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let after_sql = format!(
        "SELECT id, ts, source, text, msgid, command, original_msgid FROM channel_history WHERE channel = ? AND id > ? AND redacted=0{event_filter} ORDER BY id ASC LIMIT ?"
    );
    let after = sqlx::query(&after_sql)
        .bind(channel_name)
        .bind(pivot_id)
        .bind(half)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    before
        .iter()
        .rev()
        .chain(after.iter())
        .map(row_to_entry)
        .collect()
}

/// List channels that have history between two timestamps, paired with their latest message timestamp.
/// Returns at most `limit` results, ordered by most-recently-active first.
pub async fn list_history_targets(
    pool: &sqlx::MySqlPool,
    from_ts: &str,
    to_ts: &str,
    limit: usize,
) -> Vec<(String, String)> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT channel, MAX(ts) AS latest_ts FROM channel_history WHERE ts >= ? AND ts <= ? GROUP BY channel ORDER BY latest_ts DESC LIMIT ?",
    )
    .bind(from_ts)
    .bind(to_ts)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|r| {
            (
                r.get::<String, _>("channel"),
                r.get::<String, _>("latest_ts"),
            )
        })
        .collect()
}

/// Read entries BETWEEN two cursors (inclusive start, exclusive end), oldest-first.
/// Used by CHATHISTORY BETWEEN subcommand.
pub async fn read_channel_history_between(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    start_cursor: &str,
    end_cursor: &str,
    limit: usize,
    include_events: bool,
) -> Vec<HistoryEntry> {
    let start_id = match resolve_cursor(pool, channel_name, start_cursor).await {
        Some(id) => id,
        None => return Vec::new(),
    };
    let end_id = match resolve_cursor(pool, channel_name, end_cursor).await {
        Some(id) => id,
        None => return Vec::new(),
    };
    let event_filter = if include_events {
        ""
    } else {
        " AND (command = 'PRIVMSG' OR command = 'NOTICE')"
    };
    let sql = format!(
        "SELECT id, ts, source, text, msgid, command, original_msgid
         FROM channel_history
         WHERE channel = ? AND id >= ? AND id < ? AND redacted=0{event_filter}
         ORDER BY id ASC
         LIMIT ?"
    );
    sqlx::query(&sql)
        .bind(channel_name)
        .bind(start_id)
        .bind(end_id)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .iter()
        .map(row_to_entry)
        .collect()
}

/// Fetch redacted (soft-deleted) messages for a channel within a time range.
/// Returns (msgid, source) pairs. Used to include REDACT events in CHATHISTORY responses.
pub async fn read_redacted_in_range(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    since_ts: &str,
    until_ts: &str,
) -> Vec<(String, String)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT msgid, source FROM channel_history
         WHERE channel = ? AND redacted = 1 AND ts >= ? AND ts <= ? AND msgid IS NOT NULL
         ORDER BY id ASC",
    )
    .bind(channel_name)
    .bind(since_ts)
    .bind(until_ts)
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => rows
            .iter()
            .filter_map(|r| {
                let msgid: Option<String> = r.get("msgid");
                let source: String = r.get("source");
                msgid.map(|m| (m, source))
            })
            .collect(),
        Err(e) => {
            tracing::warn!(
                "read_redacted_in_range failed for channel={}: {}",
                channel_name,
                e
            );
            Vec::new()
        }
    }
}

/// Soft-delete a single message from channel history by its msgid (used by REDACT).
/// Marks the row as redacted=1 instead of physically deleting it, so CHATHISTORY
/// replays can include REDACT events for clients to update their local buffers.
/// Returns the number of rows affected (0 means the msgid wasn't in the DB or was already redacted).
pub async fn delete_channel_history_by_msgid(pool: &sqlx::MySqlPool, msgid: &str) -> u64 {
    match sqlx::query("UPDATE channel_history SET redacted=1 WHERE msgid = ? AND redacted=0")
        .bind(msgid)
        .execute(pool)
        .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!(
                "delete_channel_history_by_msgid failed for msgid={}: {}",
                msgid,
                e
            );
            0
        }
    }
}

/// Look up a channel history entry by msgid.
/// Returns (channel, source) where source is the original nick!user@host of the sender.
pub async fn lookup_channel_history_by_msgid(
    pool: &sqlx::MySqlPool,
    msgid: &str,
) -> Option<(String, String)> {
    use sqlx::Row;
    sqlx::query("SELECT channel, source FROM channel_history WHERE msgid = ? LIMIT 1")
        .bind(msgid)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| (r.get("channel"), r.get("source")))
}

/// Update the text (and replace the msgid) of a channel history entry identified by the original
/// msgid. Used when a client edits a previously-sent message via `+draft/edit`.
/// Returns the number of rows affected (0 if the message was not found or already redacted).
pub async fn update_channel_history_message(
    pool: &sqlx::MySqlPool,
    original_msgid: &str,
    new_text: &str,
    new_msgid: &str,
) -> u64 {
    // Set original_msgid to preserve the edit chain for CHATHISTORY replay.
    // Only set it if original_msgid column is still NULL (first edit keeps the true original).
    match sqlx::query(
        "UPDATE channel_history SET text = ?, msgid = ?, original_msgid = COALESCE(original_msgid, ?) WHERE msgid = ? AND redacted = 0",
    )
    .bind(new_text)
    .bind(new_msgid)
    .bind(original_msgid)  // only written if original_msgid IS NULL
    .bind(original_msgid)
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!(original_msgid, ?e, "EDIT DB update failed");
            0
        }
    }
}

// ─── WHOWAS persistence ────────────────────────────────────────────────────

/// Maximum number of WHOWAS entries retained per nick in the database.
const MAX_WHOWAS_DB: i64 = 20;

/// Persist a WHOWAS entry and prune old entries for the same nick.
pub async fn save_whowas(
    pool: &sqlx::MySqlPool,
    nick: &str,
    username: &str,
    host: &str,
    realname: &str,
    server: &str,
) {
    let nick_lower = nick.to_lowercase();
    if let Err(e) = sqlx::query(
        "INSERT INTO whowas (nick, nick_lower, username, host, realname, server) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(nick)
    .bind(&nick_lower)
    .bind(username)
    .bind(host)
    .bind(realname)
    .bind(server)
    .execute(pool)
    .await
    {
        tracing::warn!(%nick, ?e, "failed to persist WHOWAS entry");
        return;
    }
    // Prune oldest entries beyond the limit
    let _ = sqlx::query(
        "DELETE FROM whowas WHERE nick_lower = ? AND id NOT IN (
            SELECT id FROM (SELECT id FROM whowas WHERE nick_lower = ? ORDER BY quit_time DESC LIMIT ?) AS keep
        )",
    )
    .bind(&nick_lower)
    .bind(&nick_lower)
    .bind(MAX_WHOWAS_DB)
    .execute(pool)
    .await;
}

/// Load WHOWAS entries for a nick (most recent first).
pub async fn load_whowas(
    pool: &sqlx::MySqlPool,
    nick: &str,
    limit: i64,
) -> Vec<crate::user::WhowasEntry> {
    use sqlx::Row;
    let nick_lower = nick.to_lowercase();
    let rows = match sqlx::query(
        "SELECT nick, username, host, realname, server, UNIX_TIMESTAMP(quit_time) AS ts FROM whowas WHERE nick_lower = ? ORDER BY quit_time DESC LIMIT ?",
    )
    .bind(&nick_lower)
    .bind(limit)
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%nick, ?e, "failed to load WHOWAS entries");
            return Vec::new();
        }
    };
    rows.iter()
        .map(|r| crate::user::WhowasEntry {
            nick: r.get::<String, _>("nick"),
            user: r.get::<String, _>("username"),
            host: r.get::<String, _>("host"),
            realname: r.get::<String, _>("realname"),
            server: r.get::<String, _>("server"),
            timestamp: r.get::<i64, _>("ts"),
        })
        .collect()
}
