use std::path::PathBuf;

use arbiter_proxy::config::ProxyConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load config from CLI arg or default path.
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("arbiter-proxy.toml"));

    let config = ProxyConfig::from_file(&config_path).map_err(|e| {
        anyhow::anyhow!("failed to load config from {}: {e}", config_path.display())
    })?;

    tracing::info!(config = ?config_path, "loaded configuration");

    arbiter_proxy::server::run(config).await
}
