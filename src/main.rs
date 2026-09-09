use clap::{Parser, Subcommand};
use rircd::{adduser_cmd, config, genpasswd_cmd, init_cmd, run_server, status_cmd, stop_cmd};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "rircd")]
#[command(about = "Bleeding-edge IRC server in Rust")]
struct Cli {
    #[arg(long, default_value = "/etc/rIRCd/config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize configuration directory with defaults
    Init {
        #[arg(long, default_value = "/etc/rIRCd")]
        dir: PathBuf,
    },
    /// Run the IRC server
    Run,
    /// Stop the running server (sends SIGTERM)
    Stop,
    /// Show whether the server is running
    Status,
    /// Generate bcrypt hash for passwords
    Genpasswd,
    /// Create an account directly, without connecting as a client
    Adduser {
        /// Account name (must be a valid nickname)
        nick: String,
        /// Password; read from stdin when omitted
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install ring as the rustls CryptoProvider before any TLS work.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("rircd=info".parse()?),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init { dir }) => init_cmd(&dir)?,
        Some(Commands::Run) => {
            let cfg = config::load(&cli.config)?;
            run_server(cfg, &cli.config).await?;
        }
        Some(Commands::Stop) => stop_cmd(&cli.config)?,
        Some(Commands::Status) => status_cmd(&cli.config)?,
        Some(Commands::Genpasswd) => genpasswd_cmd()?,
        Some(Commands::Adduser { nick, password }) => {
            let cfg = config::load(&cli.config)?;
            let password = match password {
                Some(p) => p,
                None => {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    line.trim_end_matches(['\r', '\n']).to_string()
                }
            };
            adduser_cmd(cfg, &nick, &password).await?;
        }
        None => {
            // Default to run
            let cfg = config::load(&cli.config)?;
            run_server(cfg, &cli.config).await?;
        }
    }

    Ok(())
}
