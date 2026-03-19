use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Write};
use bcrypt::{hash, DEFAULT_COST};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/rIRCd";

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
    /// Set by load() from config file path; used for users.toml, channels.toml, history/
    #[serde(skip)]
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebircConfig {
    /// Password gateways must send to use WEBIRC (enables real IP/host from gateway).
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
    #[serde(default = "default_motd")]
    pub motd: String,
    #[serde(default = "default_registration_timeout")]
    pub registration_timeout_secs: u64,
    #[serde(default = "default_ping_timeout")]
    pub ping_timeout_secs: u64,
    #[serde(default = "default_disconnect_timeout")]
    pub disconnect_timeout_secs: u64,
    /// If set, 005 CLIENTTAGDENY=... and relay drops these client-only tags (e.g. ["+typing"] or ["*"]).
    #[serde(default)]
    pub client_tag_deny: Option<Vec<String>>,
}

fn default_server_name() -> String {
    "rIRCd.local".into()
}
fn default_listen() -> Vec<String> {
    vec![":6667".into()]
}
fn default_motd() -> String {
    "/etc/rIRCd/motd".into()
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
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_network_name")]
    pub name: String,
}

fn default_network_name() -> String {
    "rIRCd".into()
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            name: default_network_name(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert: None,
            key: None,
        }
    }
}

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperConfig {
    pub name: String,
    pub hostmask: Option<String>,
    pub password_hash: String,
}

impl Config {
    pub fn tls_enabled(&self) -> bool {
        self.tls.cert.is_some() && self.tls.key.is_some()
    }
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&content)?;
    config.config_dir = path.parent().map(PathBuf::from);
    Ok(config)
}

/// Path to the PID file for a given config path (e.g. /etc/rIRCd/config.toml -> /etc/rIRCd/rircd.pid).
pub fn pidfile_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new(DEFAULT_CONFIG_DIR))
        .join("rircd.pid")
}

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

    let users_toml = r#"# Registered user accounts for SASL
# Use: rircd genpasswd to generate password hashes

[[user]]
nick = "nick"
password = "$2a$12$..."
email = "user@example.com"
public_key = ""

"#;
    let users_path = dir.join("users.toml");
    if !users_path.exists() {
        fs::write(&users_path, users_toml)?;
        println!("Created {}", users_path.display());
    } else {
        println!("{} already exists, skipping", users_path.display());
    }

    let channels_toml = r##"# Persistent channel config: topic and roles (op/voice) applied on join
# name = channel name; topic = channel topic; operators/voice = nicks or account names

[[channel]]
name = "#general"
topic = "Welcome"
operators = ["alice", "bob"]
voice = ["charlie"]

"##;
    let channels_path = dir.join("channels.toml");
    if !channels_path.exists() {
        fs::write(&channels_path, channels_toml)?;
        println!("Created {}", channels_path.display());
    } else {
        println!("{} already exists, skipping", channels_path.display());
    }

    let history_dir = dir.join("history");
    if !history_dir.exists() {
        fs::create_dir_all(&history_dir)?;
        println!("Created {}", history_dir.display());
    }

    let motd = include_str!("../default-motd.txt");
    let motd_path = dir.join("motd");
    if !motd_path.exists() {
        fs::write(&motd_path, motd)?;
        println!("Created {}", motd_path.display());
    } else {
        println!("{} already exists, skipping", motd_path.display());
    }

    println!("\nSetup complete. Edit {} and run: rircd run", config_path.display());
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

/// Read PID from pidfile. Returns None if file missing or invalid.
fn read_pidfile(pidfile: &Path) -> Option<nix::unistd::Pid> {
    let s = fs::read_to_string(pidfile).ok()?;
    let pid: i32 = s.trim().parse().ok()?;
    if pid <= 0 {
        return None;
    }
    Some(nix::unistd::Pid::from_raw(pid))
}

/// Stop the running rIRCd server (sends SIGTERM to the process in the pidfile).
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

/// Print whether the server is running (based on pidfile and process existence).
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
