//! Arbiter: MCP tool-call firewall.
//!
//! Single binary that starts both the proxy (with full middleware chain)
//! and the lifecycle admin API on separate ports.

use std::path::PathBuf;
use std::sync::Arc;

use arbiter::config::ArbiterConfig;
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Arbiter: MCP tool-call firewall.
#[derive(Parser, Debug)]
#[command(name = "arbiter", about = "MCP tool-call firewall")]
struct Cli {
    /// Path to the arbiter.toml configuration file.
    #[arg(short, long, default_value = "arbiter.toml", env = "ARBITER_CONFIG")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "ARBITER_LOG_LEVEL")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing with the specified log level.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    let config = ArbiterConfig::from_file(&cli.config)
        .map_err(|e| anyhow::anyhow!("failed to load config from {}: {e}", cli.config.display()))?;

    // Validate configuration and surface problems before starting.
    let warnings = config.validate();
    let mut has_errors = false;
    for w in &warnings {
        if w.is_error() {
            tracing::error!("{w}");
            has_errors = true;
        } else {
            tracing::warn!("{w}");
        }
    }
    if has_errors {
        anyhow::bail!(
            "configuration has errors; fix the issues above and restart. \
             See arbiter.example.toml for reference."
        );
    }

    tracing::info!(config = ?cli.config, "loaded configuration");

    let config = Arc::new(config);

    // Start both proxy and admin API, shut down on signal.
    arbiter::server::run(config).await
}
