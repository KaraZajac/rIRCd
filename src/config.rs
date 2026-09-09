use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/rIRCd";

// ─── Top-level Config ─────────────────────────────────────────────────────────

#[derive(Clone, Deserialize, Serialize)]
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
    /// Outgoing mail, used to send account verification codes
    /// (draft/account-registration VERIFY). Present = verification required.
    #[serde(default)]
    pub email: Option<EmailConfig>,
    /// Web Push notifications (draft/webpush).
    #[serde(default)]
    pub webpush: Option<WebpushConfig>,
    /// VAPID key and HTTP client for draft/webpush — built at startup, not serialised.
    #[serde(skip)]
    pub webpush_runtime: Option<std::sync::Arc<crate::webpush::WebpushRuntime>>,
    /// MariaDB connection settings.
    #[serde(default)]
    pub database: DatabaseConfig,
    /// Live connection pool — populated after `load()`, not serialised.
    #[serde(skip)]
    pub db: Option<sqlx::MySqlPool>,
    /// Whether the database is answering; consulted before work that would
    /// otherwise stall the command loop. Not serialised.
    #[serde(skip)]
    pub db_health: crate::persist::DbHealth,
    /// Background writer for channel and conversation history, not serialised.
    #[serde(skip)]
    pub history: Option<crate::persist::HistoryWriter>,
    /// The TLS acceptor the listeners consult per connection, so REHASH can swap
    /// in a renewed certificate without dropping anyone.
    #[serde(skip)]
    pub tls_acceptor: Option<std::sync::Arc<tokio::sync::RwLock<tokio_rustls::TlsAcceptor>>>,
}

impl std::fmt::Debug for Config {
    /// Hand-written because the TLS acceptor has no Debug, and because printing a
    /// configuration should not print its passwords.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server", &self.server)
            .field("network", &self.network)
            .field("limits", &self.limits)
            .field("opers", &self.opers.len())
            .field("tls_enabled", &self.tls_enabled())
            .field("filehost", &self.filehost.is_some())
            .field("email", &self.email.is_some())
            .field("webpush", &self.webpush.is_some())
            .field("database", &self.database.database)
            .finish()
    }
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

// ─── Email ────────────────────────────────────────────────────────────────────

/// SMTP settings for account verification mail. Configuring this section turns on
/// email verification: REGISTER then requires a real address and replies
/// VERIFICATION_REQUIRED until the account is confirmed with VERIFY.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailConfig {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP port (587 for STARTTLS submission, 465 for implicit TLS, 25 for plain).
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// SMTP username; omit for an unauthenticated relay.
    #[serde(default)]
    pub smtp_user: Option<String>,
    /// SMTP password; omit for an unauthenticated relay.
    #[serde(default)]
    pub smtp_password: Option<String>,
    /// Connection security: "starttls" (default), "tls" (implicit) or "none".
    #[serde(default = "default_smtp_encryption")]
    pub encryption: String,
    /// From address, e.g. "ExampleNet <noreply@example.com>".
    pub from: String,
    /// Subject line of the verification mail.
    #[serde(default = "default_email_subject")]
    pub subject: String,
    /// How long a verification code stays valid, in seconds (default 24h).
    #[serde(default = "default_code_expiry")]
    pub code_expiry_secs: i64,
}

fn default_smtp_port() -> u16 {
    587
}
fn default_smtp_encryption() -> String {
    "starttls".into()
}
fn default_email_subject() -> String {
    "Your IRC account verification code".into()
}
fn default_code_expiry() -> i64 {
    86_400
}

// ─── Web Push ─────────────────────────────────────────────────────────────────

/// Web Push notifications (draft/webpush). Configuring this section lets clients
/// register push endpoints with `WEBPUSH REGISTER` and receive direct messages and
/// highlights while their app is asleep.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebpushConfig {
    /// VAPID contact, used as the JWT `sub` claim. Push services require a
    /// `mailto:` or `https:` URL identifying the operator.
    pub contact: String,
    /// Where the VAPID private key lives; generated on first start if absent.
    #[serde(default = "default_vapid_key_file")]
    pub key_file: String,
    /// Maximum push endpoints one account may have registered at a time.
    #[serde(default = "default_max_subscriptions")]
    pub max_subscriptions_per_account: usize,
    /// TTL (seconds) asked of the push service for each notification.
    #[serde(default = "default_push_ttl")]
    pub ttl_secs: u32,
    /// Consecutive delivery failures tolerated before a subscription is dropped.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
    /// Allow endpoints that resolve to loopback or private addresses. Off by
    /// default; only turn it on to test against a push service on your own network.
    #[serde(default)]
    pub allow_private_endpoints: bool,
}

fn default_vapid_key_file() -> String {
    "/etc/rIRCd/vapid.key".into()
}
fn default_max_subscriptions() -> usize {
    5
}
fn default_push_ttl() -> u32 {
    3600
}
fn default_max_failures() -> u32 {
    5
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
    /// WebSocket listen addresses (e.g. [":7667"]).
    #[serde(default)]
    pub listen_ws: Vec<String>,
    /// WebSocket-over-TLS listen addresses (e.g. [":7697"]).
    #[serde(default)]
    pub listen_wss: Vec<String>,
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
    /// Contact shown by the ADMIN command; who runs this server.
    #[serde(default)]
    pub admin_name: Option<String>,
    /// Location or description shown by ADMIN.
    #[serde(default)]
    pub admin_location: Option<String>,
    /// Contact address shown by ADMIN.
    #[serde(default)]
    pub admin_email: Option<String>,
    /// Reserve registered nicks for the account that owns them. On by default:
    /// registering an account is what claims the nick.
    #[serde(default = "default_nick_protection")]
    pub nick_protection: bool,
    /// Comma-separated list of channels to suggest to clients that enable draft/auto-join.
    /// Example: "#general, #help, #dev"
    #[serde(default)]
    pub auto_join: Option<String>,
    /// One-line description of this server, shown by LINKS.
    #[serde(default = "default_server_description")]
    pub description: String,
    /// Allow REGISTER before the client has finished connecting. Advertised as
    /// `before-connect` in the draft/account-registration capability.
    #[serde(default = "default_register_before_connect")]
    pub register_before_connect: bool,
}

fn default_register_before_connect() -> bool {
    true
}

fn default_server_description() -> String {
    format!("rIRCd v{}", env!("CARGO_PKG_VERSION"))
}

fn default_nick_protection() -> bool {
    true
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
            listen_ws: Vec::new(),
            listen_wss: Vec::new(),
            motd: default_motd(),
            registration_timeout_secs: default_registration_timeout(),
            ping_timeout_secs: default_ping_timeout(),
            disconnect_timeout_secs: default_disconnect_timeout(),
            client_tag_deny: None,
            cloak_key: None,
            admin_name: None,
            admin_location: None,
            admin_email: None,
            nick_protection: default_nick_protection(),
            auto_join: None,
            description: default_server_description(),
            register_before_connect: default_register_before_connect(),
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
    /// Request (but don't require) TLS client certificates for SASL EXTERNAL.
    #[serde(default)]
    pub client_certs: bool,
}

// ─── Limits ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_channels")]
    pub max_channels_per_client: usize,
    /// Connections allowed from one address at a time; 0 for no limit.
    #[serde(default = "default_max_per_ip")]
    pub max_connections_per_ip: usize,
    /// Connections allowed in total; 0 for no limit.
    #[serde(default)]
    pub max_clients: usize,
    /// Longest message body accepted, before tags. 512 is the protocol's own
    /// limit and the default; raising it lets clients send the long SASL
    /// responses and passwords that some do. Advertised as LINELEN.
    #[serde(default = "default_max_line_length")]
    pub max_line_length: usize,
    /// Commands a client may send back to back before being throttled.
    #[serde(default = "default_flood_burst")]
    pub flood_burst: f64,
    /// Commands per second the flood allowance refills at.
    #[serde(default = "default_flood_rate")]
    pub flood_rate: f64,
    /// Shortest password REGISTER will accept. Advertised to clients in the
    /// draft/account-registration capability, so the two cannot drift apart.
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,
}

fn default_max_channels() -> usize {
    50
}
fn default_max_per_ip() -> usize {
    16
}
fn default_max_line_length() -> usize {
    crate::protocol::DEFAULT_MAX_MESSAGE_BODY
}
fn default_flood_burst() -> f64 {
    10.0
}
fn default_flood_rate() -> f64 {
    1.0
}
fn default_min_password_length() -> usize {
    6
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_channels_per_client: default_max_channels(),
            max_connections_per_ip: default_max_per_ip(),
            max_clients: 0,
            max_line_length: default_max_line_length(),
            flood_burst: default_flood_burst(),
            flood_rate: default_flood_rate(),
            min_password_length: default_min_password_length(),
        }
    }
}

// ─── Opers ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperConfig {
    pub name: String,
    pub hostmask: Option<String>,
    pub password_hash: String,
    /// What this operator may do: any of "kill", "ban", "rehash", "die",
    /// "sethost", "wallops". Omit for all of them.
    #[serde(default)]
    pub privileges: Option<Vec<String>>,
}

/// One thing an operator may be allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperPrivilege {
    Kill,
    Ban,
    Rehash,
    Die,
    SetHost,
    Wallops,
}

impl OperPrivilege {
    pub fn name(self) -> &'static str {
        match self {
            Self::Kill => "kill",
            Self::Ban => "ban",
            Self::Rehash => "rehash",
            Self::Die => "die",
            Self::SetHost => "sethost",
            Self::Wallops => "wallops",
        }
    }
}

impl OperConfig {
    /// An operator with no `privileges` list may do everything, which is how
    /// every operator behaved before the list existed.
    pub fn may(&self, privilege: OperPrivilege) -> bool {
        match self.privileges {
            None => true,
            Some(ref list) => list
                .iter()
                .any(|p| p.eq_ignore_ascii_case(privilege.name())),
        }
    }
}

// ─── Methods ──────────────────────────────────────────────────────────────────

impl Config {
    /// Queue a history row for `target` (a channel, or a direct-conversation key).
    ///
    /// Returns immediately: history is written by a background task, so a
    /// database round-trip never delays delivering the message.
    pub fn record_history(
        &self,
        target: &str,
        source: &str,
        text: &str,
        msgid: Option<&str>,
        command: &str,
    ) {
        if let Some(ref writer) = self.history {
            writer.append(crate::persist::HistoryWrite {
                target: target.to_string(),
                source: source.to_string(),
                text: text.to_string(),
                msgid: msgid.map(String::from),
                command: command.to_string(),
                ts: crate::protocol::server_time_now(),
            });
        }
    }

    /// Wait for queued history to reach the database, before reading or changing
    /// it by msgid.
    pub async fn flush_history(&self) {
        if let Some(ref writer) = self.history {
            writer.flush().await;
        }
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls.cert.is_some() && self.tls.key.is_some()
    }

    /// Port of the first TLS listener, when TLS is configured. Used to advertise
    /// `sts=port=<N>` to plaintext clients.
    pub fn tls_port(&self) -> Option<u16> {
        if !self.tls_enabled() {
            return None;
        }
        self.server
            .listen_tls
            .first()
            .and_then(|addr| addr.rsplit(':').next())
            .and_then(|p| p.parse().ok())
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

    // ── Email verification ────────────────────────────────────────────────────
    println!("\n[Email verification]");
    println!("  (Requires accounts registered with REGISTER to confirm an address with VERIFY.)");
    let want_email = prompt_bool("Enable email verification?", false);
    let email_block = if want_email {
        let smtp_host = prompt("SMTP host", "smtp.example.com");
        let smtp_port = prompt("SMTP port", "587");
        let encryption = prompt("Connection security (starttls/tls/none)", "starttls");
        let from = prompt(
            "From address",
            &format!("{} <noreply@{}>", network_name, server_name),
        );
        let smtp_user = prompt("SMTP username (blank for none)", "");
        let smtp_pass = if smtp_user.is_empty() {
            String::new()
        } else {
            rpassword::prompt_password("  SMTP password: ").unwrap_or_default()
        };
        let credentials = if smtp_user.is_empty() {
            String::new()
        } else {
            format!(
                "smtp_user = \"{}\"\nsmtp_password = \"{}\"\n",
                smtp_user, smtp_pass
            )
        };
        format!(
            "\n[email]\nsmtp_host = \"{}\"\nsmtp_port = {}\nencryption = \"{}\"\nfrom = \"{}\"\n{}",
            smtp_host, smtp_port, encryption, from, credentials
        )
    } else {
        String::new()
    };

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
{email_block}{oper_block}"#
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
