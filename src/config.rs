use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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
    /// File hosting endpoint (draft/filehost).
    #[serde(default)]
    pub filehost: Option<FilehostConfig>,
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

fn default_db_host() -> String {
    "localhost".into()
}
fn default_db_port() -> u16 {
    3306
}
fn default_db_name() -> String {
    "rircdb".into()
}

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

// ─── Filehost ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilehostConfig {
    /// HTTP listen address (e.g. "0.0.0.0:8080").
    #[serde(default = "default_filehost_listen")]
    pub listen: String,
    /// Public base URL that clients use to reach uploads (e.g. "https://irc.example.com/uploads").
    pub public_url: String,
    /// Directory on disk where uploaded files are stored.
    #[serde(default = "default_filehost_dir")]
    pub upload_dir: String,
    /// Maximum upload size in bytes (default 50 MiB).
    #[serde(default = "default_filehost_max_size")]
    pub max_size: usize,
}

fn default_filehost_listen() -> String {
    "0.0.0.0:8080".into()
}
fn default_filehost_dir() -> String {
    "/var/lib/rircd/uploads".into()
}
fn default_filehost_max_size() -> usize {
    50 * 1024 * 1024
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
    /// If set, connecting clients receive an HMAC-SHA256-based virtual host cloak.
    #[serde(default)]
    pub cloak_key: Option<String>,
}

fn default_server_name() -> String {
    "rIRCd.local".into()
}
fn default_listen() -> Vec<String> {
    vec![":6667".into()]
}
fn default_motd() -> String {
    "Welcome to rIRCd!".into()
}
fn default_registration_timeout() -> u64 {
    60
}
fn default_ping_timeout() -> u64 {
    90
}
fn default_disconnect_timeout() -> u64 {
    150
}

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
            cloak_key: None,
        }
    }
}

// ─── Network ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_network_name")]
    pub name: String,
    /// Optional URL to a network icon image (draft/network-icon; advertised as ICON= in ISUPPORT).
    #[serde(default)]
    pub icon: Option<String>,
}

fn default_network_name() -> String {
    "rIRCd".into()
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            name: default_network_name(),
            icon: None,
        }
    }
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
}

// ─── Limits ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_channels")]
    pub max_channels_per_client: usize,
    #[serde(default = "default_max_line_length")]
    pub max_line_length: usize,
}

fn default_max_channels() -> usize {
    50
}
fn default_max_line_length() -> usize {
    8191
}

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

// ─── Interactive init helpers ─────────────────────────────────────────────────

fn prompt(label: &str, default: &str) -> String {
    if default.is_empty() {
        print!("  {}: ", label);
    } else {
        print!("  {} [{}]: ", label, default);
    }
    io::stdout().flush().unwrap();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    let s = s.trim().to_string();
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

fn prompt_bool(label: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("  {} [{}]: ", label, hint);
    io::stdout().flush().unwrap();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        default
    } else {
        s.starts_with('y')
    }
}

fn prompt_password_twice(label: &str) -> String {
    loop {
        let p1 = rpassword::prompt_password(format!("  {}: ", label)).unwrap_or_default();
        let p2 = rpassword::prompt_password(format!("  {} (confirm): ", label)).unwrap_or_default();
        if p1 == p2 {
            return p1;
        }
        println!("  Passwords do not match, try again.");
    }
}

/// Initialise /etc/rIRCd with an interactively generated config.toml.
/// Users, channels, and history are stored in the database — no extra files needed.
pub fn init_config_dir(dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;
    let config_path = dir.join("config.toml");

    if config_path.exists() {
        println!("{} already exists.", config_path.display());
        print!("  Overwrite it? [y/N]: ");
        io::stdout().flush().unwrap();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();
        if !s.trim().to_lowercase().starts_with('y') {
            println!("Keeping existing config. Run: rircd run");
            return Ok(());
        }
    }

    println!("\nrIRCd interactive setup");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Press Enter to accept the [default] value.\n");

    // ── Server ────────────────────────────────────────────────────────────────
    println!("[Server]");
    let server_name = prompt("Server hostname", "irc.example.com");
    let network_name = prompt("Network name", "rIRCd");
    let plain_port = prompt("Plain-text IRC port", "6667");
    let motd_line = prompt("Message of the day", "Welcome to rIRCd!");

    // ── TLS ───────────────────────────────────────────────────────────────────
    println!("\n[TLS]");
    let want_tls = prompt_bool("Enable TLS listener?", false);
    let (tls_port, tls_cert, tls_key) = if want_tls {
        let port = prompt("TLS port", "6697");
        let cert = prompt("Path to certificate (PEM)", "/etc/rIRCd/cert.pem");
        let key = prompt("Path to private key (PEM)", "/etc/rIRCd/key.pem");
        (Some(port), Some(cert), Some(key))
    } else {
        (None, None, None)
    };

    // ── Database ──────────────────────────────────────────────────────────────
    println!("\n[Database]");
    println!("  (rIRCd requires MariaDB/MySQL for user accounts and channel history.)");
    let db_host = prompt("Database host", "localhost");
    let db_port = prompt("Database port", "3306");
    let db_name = prompt("Database name", "rircdb");
    let db_user = prompt("Database user", "rirc");
    let db_pass = rpassword::prompt_password("  Database password: ").unwrap_or_default();

    // ── IRC Operator ──────────────────────────────────────────────────────────
    println!("\n[IRC Operator]");
    let want_oper = prompt_bool("Create an IRC operator account?", true);
    let oper_block = if want_oper {
        let oper_name = prompt("Operator name", "admin");
        let oper_pass = prompt_password_twice("Operator password");
        if oper_pass.is_empty() {
            println!("  Empty password, skipping operator creation.");
            String::new()
        } else {
            match hash(&oper_pass, DEFAULT_COST) {
                Ok(h) => format!(
                    "\n[[opers]]\nname = \"{}\"\nhostmask = \"*\"\npassword_hash = \"{}\"\n",
                    oper_name, h
                ),
                Err(e) => {
                    println!("  Failed to hash password ({}), skipping oper.", e);
                    String::new()
                }
            }
        }
    } else {
        String::new()
    };

    // ── Assemble config ───────────────────────────────────────────────────────
    let listen_tls_line = match &tls_port {
        Some(p) => format!("\nlisten_tls = [\":{}\"]", p),
        None => String::new(),
    };
    let tls_block = match (&tls_cert, &tls_key) {
        (Some(cert), Some(key)) => format!("\n[tls]\ncert = \"{}\"\nkey  = \"{}\"\n", cert, key),
        _ => String::new(),
    };

    let config_content = format!(
        r#"# rIRCd configuration — generated by `rircd init`
# https://github.com/KaraZajac/rIRCd

[server]
name = "{server_name}"
listen = [":{plain_port}"]{listen_tls_line}
motd = """
{motd_line}
"""

registration_timeout_secs = 60
ping_timeout_secs = 90
disconnect_timeout_secs = 150

[network]
name = "{network_name}"

[database]
host = "{db_host}"
port = {db_port}
user = "{db_user}"
password = "{db_pass}"
database = "{db_name}"
{tls_block}
[limits]
max_channels_per_client = 50
max_line_length = 8191
{oper_block}"#
    );

    fs::write(&config_path, &config_content)?;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Config written to {}", config_path.display());
    println!("The database schema is created automatically on first startup.");
    println!("\nStart the server with:  rircd run");
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
    if pid <= 0 {
        return None;
    }
    Some(nix::unistd::Pid::from_raw(pid))
}

pub fn stop_cmd(config_path: &Path) -> anyhow::Result<()> {
    let pidfile = pidfile_path(config_path);
    let pid = read_pidfile(&pidfile).ok_or_else(|| {
        anyhow::anyhow!(
            "No PID file at {} (is the server running?)",
            pidfile.display()
        )
    })?;

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
            println!(
                "rIRCd is not running (no PID file at {})",
                pidfile.display()
            );
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
        println!(
            "rIRCd status: PID file present (PID {}), run only supported on Unix",
            pid
        );
    }

    Ok(())
}
