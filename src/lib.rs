pub mod capability;
pub mod channel;
pub mod client;
pub mod commands;
pub mod config;
pub mod filehost;
pub mod mail;
pub mod persist;
pub mod protocol;
pub mod server;
pub mod user;
pub mod webpush;

use config::Config;
use std::path::Path;

pub fn init_cmd(dir: &Path) -> anyhow::Result<()> {
    config::init_config_dir(dir)
}

pub async fn run_server(mut cfg: Config, config_path: &Path) -> anyhow::Result<()> {
    // Connect to MariaDB and store the pool in cfg so all handlers can access it.
    let url = cfg.database.connection_url();
    tracing::info!(
        "Connecting to database at {}:{}/{}",
        cfg.database.host,
        cfg.database.port,
        cfg.database.database
    );
    // Every command is handled by one loop, and handlers await the database
    // inline: with the default 30-second acquire timeout, a database outage
    // stalls the whole server behind each query. Fail fast instead.
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(3))
        .idle_timeout(std::time::Duration::from_secs(600))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&url)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to connect to MariaDB ({}): {}",
                // Replacing an empty password would insert the mask between
                // every character of the URL.
                if cfg.database.password.is_empty() {
                    url.clone()
                } else {
                    url.replace(&cfg.database.password, "***")
                },
                e
            )
        })?;
    persist::init_schema(&pool).await?;

    if let Some(ref email) = cfg.email {
        tracing::info!(
            "Email verification enabled: REGISTER requires a valid address, \
             mail relayed via {}:{}",
            email.smtp_host,
            email.smtp_port
        );
        let purged = persist::purge_expired_unverified(&pool, None).await;
        if purged > 0 {
            tracing::info!("Removed {} expired unverified account(s)", purged);
        }
    }

    if let Some(ref wp) = cfg.webpush {
        match webpush::WebpushRuntime::new(wp) {
            Ok(runtime) => {
                tracing::info!(
                    "Web Push enabled: contact={}, VAPID public key {}",
                    wp.contact,
                    runtime.key.public_b64()
                );
                cfg.webpush_runtime = Some(std::sync::Arc::new(runtime));
            }
            Err(e) => {
                tracing::error!(
                    "Web Push disabled: could not set up VAPID key from {}: {}",
                    wp.key_file,
                    e
                );
            }
        }
    }

    cfg.history = Some(persist::HistoryWriter::spawn(
        pool.clone(),
        cfg.db_health.clone(),
    ));
    cfg.db = Some(pool);

    if let Some(ref fh) = cfg.filehost {
        tracing::info!(
            "Filehost configured: listen={}, url={}",
            fh.listen,
            fh.public_url
        );
    }

    let pidfile = Some(config::pidfile_path(config_path));
    server::run(cfg, config_path, pidfile.as_deref()).await
}

pub fn genpasswd_cmd() -> anyhow::Result<()> {
    config::genpasswd()
}

/// Create an account without going through a connected client.
///
/// Registering over IRC means fitting the whole REGISTER into one 512-byte
/// line, which a long passphrase does not; and an operator setting up a server
/// should not have to connect to it first to make the first account.
pub async fn adduser_cmd(cfg: Config, nick: &str, password: &str) -> anyhow::Result<()> {
    let url = cfg.database.connection_url();
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to the database: {}", e))?;
    persist::init_schema(&pool).await?;

    match persist::register_user(
        &pool,
        nick,
        password,
        None,
        None,
        cfg.limits.min_password_length,
    )
    .await
    {
        Ok(()) => {
            println!("Created account {}.", nick);
            Ok(())
        }
        Err(persist::RegisterError::AccountExists) => {
            anyhow::bail!("An account named {} already exists.", nick)
        }
        Err(persist::RegisterError::WeakPassword) => anyhow::bail!(
            "Password is shorter than the configured minimum of {} characters.",
            cfg.limits.min_password_length
        ),
        Err(e) => anyhow::bail!("Could not create the account: {:?}", e),
    }
}

pub fn stop_cmd(config_path: &Path) -> anyhow::Result<()> {
    config::stop_cmd(config_path)
}

pub fn status_cmd(config_path: &Path) -> anyhow::Result<()> {
    config::status_cmd(config_path)
}
