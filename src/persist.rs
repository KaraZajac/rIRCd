//! Persistent data backed by MariaDB via sqlx.
//!
//! All tables are created automatically on first startup via `init_schema`.
//! The pool is held in `Config::db` and passed to every function here.

use serde::{Deserialize, Serialize};

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
}

/// One line of channel history from the database.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryEntry {
    pub ts: String,
    pub source: String,
    pub text: String,
    pub msgid: Option<String>,
}

/// Maximum number of history rows retained per channel.
const MAX_HISTORY_ENTRIES: i64 = 1000;

// ─── Schema ──────────────────────────────────────────────────────────────────

/// Create all required tables if they do not already exist.
pub async fn init_schema(pool: &sqlx::MySqlPool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id       BIGINT AUTO_INCREMENT PRIMARY KEY,
            nick     VARCHAR(64)  NOT NULL,
            nick_lower VARCHAR(64) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            email    VARCHAR(255) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channels (
            id    BIGINT AUTO_INCREMENT PRIMARY KEY,
            name  VARCHAR(64) NOT NULL UNIQUE,
            topic TEXT        NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4",
    )
    .execute(pool)
    .await?;

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

    tracing::info!("Database schema ready");
    Ok(())
}

// ─── Channels ─────────────────────────────────────────────────────────────────

/// Load all channel configs from the database.
pub async fn load_channels(pool: &sqlx::MySqlPool) -> Vec<ChannelEntry> {
    use sqlx::Row;

    let rows = match sqlx::query("SELECT id, name, topic FROM channels")
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

        let ops: Vec<String> = sqlx::query(
            "SELECT nick_or_account FROM channel_operators WHERE channel_id = ?",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r: sqlx::mysql::MySqlRow| r.get("nick_or_account"))
        .collect();

        let voice: Vec<String> = sqlx::query(
            "SELECT nick_or_account FROM channel_voice WHERE channel_id = ?",
        )
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
        });
    }
    entries
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

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE nick_lower = ?",
    )
    .bind(&nick_lower)
    .fetch_one(pool)
    .await
    .map_err(|e| RegisterError::Io(e.to_string()))?;

    if count > 0 {
        return Err(RegisterError::AccountExists);
    }

    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| RegisterError::Io(e.to_string()))?;

    sqlx::query(
        "INSERT INTO users (nick, nick_lower, password, email) VALUES (?, ?, ?, ?)",
    )
    .bind(nick)
    .bind(&nick_lower)
    .bind(&hash)
    .bind(email.unwrap_or(""))
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

/// Append a message to channel history. Prunes oldest rows beyond the per-channel cap.
pub async fn append_channel_history(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    source: &str,
    text: &str,
    msgid: Option<&str>,
) -> anyhow::Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO channel_history (channel, ts, source, text, msgid) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(channel_name)
    .bind(&ts)
    .bind(source)
    .bind(text)
    .bind(msgid)
    .execute(pool)
    .await?;

    // Prune rows beyond the cap using MariaDB's DELETE ... ORDER BY ... LIMIT
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_history WHERE channel = ?")
            .bind(channel_name)
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    if count > MAX_HISTORY_ENTRIES {
        let excess = count - MAX_HISTORY_ENTRIES;
        sqlx::query(
            "DELETE FROM channel_history WHERE channel = ? ORDER BY id ASC LIMIT ?",
        )
        .bind(channel_name)
        .bind(excess)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Read the most recent `limit` messages for a channel, oldest-first (for CHATHISTORY playback).
pub async fn read_channel_history(
    pool: &sqlx::MySqlPool,
    channel_name: &str,
    limit: usize,
) -> Vec<HistoryEntry> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT ts, source, text, msgid
         FROM (
             SELECT id, ts, source, text, msgid
             FROM channel_history
             WHERE channel = ?
             ORDER BY id DESC
             LIMIT ?
         ) AS recent
         ORDER BY id ASC",
    )
    .bind(channel_name)
    .bind(limit as i64)
    .fetch_all(pool)
    .await;

    match rows {
        Ok(rows) => rows
            .into_iter()
            .map(|r| HistoryEntry {
                ts: r.get("ts"),
                source: r.get("source"),
                text: r.get("text"),
                msgid: r.get("msgid"),
            })
            .collect(),
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
