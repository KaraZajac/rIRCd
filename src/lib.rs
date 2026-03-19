pub mod capability;
pub mod channel;
pub mod client;
pub mod commands;
pub mod config;
pub mod persist;
pub mod protocol;
pub mod server;
pub mod user;

use config::Config;
use std::path::Path;

pub fn init_cmd(dir: &Path) -> anyhow::Result<()> {
    config::init_config_dir(dir)
}

pub async fn run_server(cfg: Config, config_path: &Path) -> anyhow::Result<()> {
    let pidfile = Some(config::pidfile_path(config_path));
    server::run(cfg, pidfile.as_deref()).await
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
