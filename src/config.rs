use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Write};
use bcrypt::{hash, DEFAULT_COST};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/rIRCd";

// ─── Top-level Config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub opers: Vec<OperConfig>,
    #[serde(default)]
    pub webirc: Option<WebircConfig>,
    /// MariaDB connection settings.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Live connection pool — populated after `load()`, not serialised.
    #[serde(skip)]
    pub db: Option<sqlx::MySqlPool>,
}

// ─── Database ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_host")]
    pub host: String,
    #[serde(default = "default_db_port")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_db_name")]
    pub database: String,
}

fn default_db_host() -> String { "localhost".into() }
fn default_db_port() -> u16 { 3306 }
fn default_db_name() -> String { "rircdb".into() }

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: default_db_host(),
            port: default_db_port(),
            user: String::new(),
            password: String::new(),
            database: default_db_name(),
        }
    }
}

impl DatabaseConfig {
    pub fn connection_url(&self) -> String {
        format!(
            "mysql://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.database
        )
    }
}

// ─── Server ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebircConfig {
    /// Password gateways must send to use WEBIRC.
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_name")]
    pub name: String,
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,
    #[serde(default)]
    pub listen_tls: Vec<String>,
    /// MOTD text displayed to clients on connect (inline, not a file path).
    #[serde(default = "default_motd")]
    pub motd: String,
    #[serde(default = "default_registration_timeout")]
    pub registration_timeout_secs: u64,
    #[serde(default = "default_ping_timeout")]
    pub ping_timeout_secs: u64,
    #[serde(default = "default_disconnect_timeout")]
    pub disconnect_timeout_secs: u64,
    /// If set, 005 CLIENTTAGDENY=... and relay drops these client-only tags.
    #[serde(default)]
    pub client_tag_deny: Option<Vec<String>>,
}

fn default_server_name() -> String { "rIRCd.local".into() }
fn default_listen() -> Vec<String> { vec![":6667".into()] }
fn default_motd() -> String { "Welcome to rIRCd!".into() }
fn default_registration_timeout() -> u64 { 60 }
fn default_ping_timeout() -> u64 { 90 }
fn default_disconnect_timeout() -> u64 { 150 }

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: default_server_name(),
            listen: default_listen(),
            listen_tls: Vec::new(),
            motd: default_motd(),
            registration_timeout_secs: default_registration_timeout(),
            ping_timeout_secs: default_ping_timeout(),
            disconnect_timeout_secs: default_disconnect_timeout(),
            client_tag_deny: None,
        }
    }
}

// ─── Network ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_network_name")]
    pub name: String,
}

fn default_network_name() -> String { "rIRCd".into() }

impl Default for NetworkConfig {
    fn default() -> Self { Self { name: default_network_name() } }
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self { Self { cert: None, key: None } }
}

// ─── Limits ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_channels")]
    pub max_channels_per_client: usize,
    #[serde(default = "default_max_line_length")]
    pub max_line_length: usize,
}

fn default_max_channels() -> usize { 50 }
fn default_max_line_length() -> usize { 8191 }

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_channels_per_client: default_max_channels(),
            max_line_length: default_max_line_length(),
        }
    }
}

// ─── Opers ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperConfig {
    pub name: String,
    pub hostmask: Option<String>,
    pub password_hash: String,
}

// ─── Methods ──────────────────────────────────────────────────────────────────

impl Config {
    pub fn tls_enabled(&self) -> bool {
        self.tls.cert.is_some() && self.tls.key.is_some()
    }
}

// ─── Load / init ──────────────────────────────────────────────────────────────

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

/// Path to the PID file for a given config path.
pub fn pidfile_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new(DEFAULT_CONFIG_DIR))
        .join("rircd.pid")
}

/// Initialise /etc/rIRCd with a default config.toml.
/// Users, channels, and history are stored in the database — no extra files needed.
pub fn init_config_dir(dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;

    let config_toml = include_str!("../default-config.toml");
    let config_path = dir.join("config.toml");
    if !config_path.exists() {
        fs::write(&config_path, config_toml)?;
        println!("Created {}", config_path.display());
    } else {
        println!("{} already exists, skipping", config_path.display());
    }

    println!("\nSetup complete.");
    println!("Edit {} then run: rircd run", config_path.display());
    println!("The database schema is created automatically on first startup.");
    Ok(())
}

pub fn genpasswd() -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Enter password: ").unwrap_or_else(|_| {
        print!("Enter password: ");
        io::stdout().flush().unwrap();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
        s.trim().to_string()
    });

    let hash = hash(password, DEFAULT_COST)?;
    println!("{}", hash);
    Ok(())
}

// ─── Process management ───────────────────────────────────────────────────────

fn read_pidfile(pidfile: &Path) -> Option<nix::unistd::Pid> {
    let s = fs::read_to_string(pidfile).ok()?;
    let pid: i32 = s.trim().parse().ok()?;
    if pid <= 0 { return None; }
    Some(nix::unistd::Pid::from_raw(pid))
}

pub fn stop_cmd(config_path: &Path) -> anyhow::Result<()> {
    let pidfile = pidfile_path(config_path);
    let pid = read_pidfile(&pidfile)
        .ok_or_else(|| anyhow::anyhow!("No PID file at {} (is the server running?)", pidfile.display()))?;

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        kill(pid, Signal::SIGTERM)?;
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        anyhow::bail!("rircd stop is only supported on Unix");
    }

    println!("Sent SIGTERM to rIRCd (PID {})", pid);
    Ok(())
}

pub fn status_cmd(config_path: &Path) -> anyhow::Result<()> {
    let pidfile = pidfile_path(config_path);
    let pid = match read_pidfile(&pidfile) {
        Some(p) => p,
        None => {
            println!("rIRCd is not running (no PID file at {})", pidfile.display());
            return Ok(());
        }
    };

    #[cfg(unix)]
    {
        use nix::sys::signal::kill;
        match kill(pid, None) {
            Ok(()) => println!("rIRCd is running (PID {})", pid),
            Err(nix::errno::Errno::ESRCH) => println!("rIRCd is not running (stale PID file)"),
            Err(e) => println!("rIRCd status: {} (PID {})", e, pid),
        }
    }
    #[cfg(not(unix))]
    {
        println!("rIRCd status: PID file present (PID {}), run only supported on Unix", pid);
    }

    Ok(())
}
