//! Configuration for the arbiter proxy, loaded from TOML.

use serde::Deserialize;
use std::path::Path;

/// Top-level proxy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Server listen configuration.
    pub server: ServerConfig,
    /// Upstream target configuration.
    pub upstream: UpstreamConfig,
    /// Middleware pipeline configuration.
    #[serde(default)]
    pub middleware: MiddlewareConfig,
    /// Audit logging configuration.
    #[serde(default)]
    pub audit: AuditConfig,
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging.
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,
    /// Path to an append-only audit log file (optional).
    #[serde(default)]
    pub file_path: Option<String>,
    /// Sensitive field patterns for argument redaction (overrides defaults).
    #[serde(default)]
    pub redaction_patterns: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file_path: None,
            redaction_patterns: Vec::new(),
        }
    }
}

fn default_audit_enabled() -> bool {
    true
}

/// Server bind address and port.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Listen address, e.g. "127.0.0.1".
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Listen port.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Maximum request/response body size in bytes. Default: 10 MB.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Timeout for upstream requests in seconds. Default: 30s.
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,
    /// Timeout for reading client request headers in seconds. Default: 10s.
    #[serde(default = "default_header_read_timeout_secs")]
    pub header_read_timeout_secs: u64,
    /// Maximum number of concurrent connections. Default: 1024.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

/// Upstream server to proxy requests to.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// Full base URL of the upstream, e.g. "http://127.0.0.1:8081".
    pub url: String,
}

/// Default max body size: 10 MB.
fn default_max_body_bytes() -> usize {
    10 * 1024 * 1024
}

/// Default upstream request timeout: 30 seconds.
fn default_upstream_timeout_secs() -> u64 {
    30
}

/// Default connection header read timeout: 10 seconds.
fn default_header_read_timeout_secs() -> u64 {
    10
}

/// Default max concurrent connections: 1024.
fn default_max_connections() -> usize {
    1024
}

/// Configuration for the middleware pipeline.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MiddlewareConfig {
    /// Paths to block (exact match).
    #[serde(default)]
    pub blocked_paths: Vec<String>,
    /// Required headers. Requests missing any of these are rejected.
    #[serde(default)]
    pub required_headers: Vec<String>,
}

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_listen_port() -> u16 {
    8080
}

impl ProxyConfig {
    /// Load configuration from a TOML file at the given path.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: ProxyConfig = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Parse configuration from a TOML string (useful for tests).
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let config: ProxyConfig = toml::from_str(s)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[server]
listen_addr = "0.0.0.0"
listen_port = 9090

[upstream]
url = "http://localhost:3000"
"#;
        let config = ProxyConfig::parse(toml).unwrap();
        assert_eq!(config.server.listen_addr, "0.0.0.0");
        assert_eq!(config.server.listen_port, 9090);
        assert_eq!(config.upstream.url, "http://localhost:3000");
        assert!(config.middleware.blocked_paths.is_empty());
    }

    #[test]
    fn parse_config_with_middleware() {
        let toml = r#"
[server]
listen_port = 8080

[upstream]
url = "http://backend:8081"

[middleware]
blocked_paths = ["/admin", "/secret"]
required_headers = ["x-api-key"]
"#;
        let config = ProxyConfig::parse(toml).unwrap();
        assert_eq!(config.middleware.blocked_paths.len(), 2);
        assert_eq!(config.middleware.required_headers, vec!["x-api-key"]);
    }

    #[test]
    fn defaults_applied() {
        let toml = r#"
[server]

[upstream]
url = "http://localhost:3000"
"#;
        let config = ProxyConfig::parse(toml).unwrap();
        assert_eq!(config.server.listen_addr, "127.0.0.1");
        assert_eq!(config.server.listen_port, 8080);
    }
}
