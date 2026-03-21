pub mod capability;
pub mod channel;
pub mod client;
pub mod commands;
pub mod config;
pub mod filehost;
pub mod persist;
pub mod protocol;
pub mod server;
pub mod user;

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
    let pool = sqlx::MySqlPool::connect(&url).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to MariaDB ({}): {}",
            url.replace(&cfg.database.password, "***"),
            e
        )
    })?;
    persist::init_schema(&pool).await?;
    cfg.db = Some(pool);

    if let Some(ref fh) = cfg.filehost {
        tracing::info!("Filehost configured: listen={}, url={}", fh.listen, fh.public_url);
    }

    let pidfile = Some(config::pidfile_path(config_path));
    server::run(cfg, config_path, pidfile.as_deref()).await
}

pub fn genpasswd_cmd() -> anyhow::Result<()> {
    config::genpasswd()
}

pub fn stop_cmd(config_path: &Path) -> anyhow::Result<()> {
    config::stop_cmd(config_path)
}

pub fn status_cmd(config_path: &Path) -> anyhow::Result<()> {
    config::status_cmd(config_path)
}
