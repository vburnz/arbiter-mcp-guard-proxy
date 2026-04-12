//! Unified configuration for Arbiter, loaded from a single TOML file.
//!
//! Sections: `[proxy]`, `[oauth]`, `[policy]`, `[sessions]`, `[audit]`, `[metrics]`, `[admin]`.

use std::path::Path;

use serde::Deserialize;

/// Top-level Arbiter configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ArbiterConfig {
    /// Proxy server and upstream configuration.
    #[serde(default)]
    pub proxy: ProxySection,

    /// OAuth / JWT validation configuration.
    #[serde(default)]
    pub oauth: Option<OAuthSection>,

    /// Authorization policy configuration.
    #[serde(default)]
    pub policy: PolicySection,

    /// Session management configuration.
    #[serde(default)]
    pub sessions: SessionsSection,

    /// Audit logging configuration.
    #[serde(default)]
    pub audit: AuditSection,

    /// Metrics configuration.
    #[serde(default)]
    pub metrics: MetricsSection,

    /// Admin / lifecycle API configuration.
    #[serde(default)]
    pub admin: AdminSection,

    /// Credential injection configuration.
    #[serde(default)]
    pub credentials: Option<CredentialsSection>,

    /// Storage backend configuration.
    #[serde(default)]
    pub storage: StorageSection,
}

/// `[proxy]` section: server listen address and upstream target.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxySection {
    /// Listen address for the proxy.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Listen port for the proxy.
    #[serde(default = "default_proxy_port")]
    pub listen_port: u16,

    /// Upstream MCP server URL.
    #[serde(default = "default_upstream_url")]
    pub upstream_url: String,

    /// Paths to block (exact match).
    #[serde(default)]
    pub blocked_paths: Vec<String>,

    /// Require a valid x-arbiter-session header for MCP traffic.
    /// When true (default), MCP requests without a session header are denied.
    #[serde(default = "default_true")]
    pub require_session: bool,

    /// Reject non-MCP POST traffic when session enforcement is active.
    /// When true (default), POST requests with non-JSON-RPC bodies are denied.
    #[serde(default = "default_true")]
    pub strict_mcp: bool,

    /// Maximum request body size in bytes. Requests exceeding this are rejected
    /// with 413 Payload Too Large. Default: 10 MiB. Prevents OOM from oversized payloads.
    /// no body size limits allowed unbounded memory allocation.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,

    /// Maximum response body size in bytes. Responses exceeding this are rejected
    /// with 502 Bad Gateway. Default: 10 MiB. Prevents
    /// unbounded response buffering.
    #[serde(default = "default_max_response_body_bytes")]
    pub max_response_body_bytes: usize,

    /// Timeout in seconds for upstream requests. Default: 60.
    /// no timeout on upstream requests allowed indefinite blocking.
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    /// Deny non-POST HTTP methods on the proxy port. Default: true.
    ///
    /// MCP is a POST-only protocol. Non-POST methods (GET, PUT, DELETE, PATCH)
    /// bypass session validation, policy evaluation, and behavioral anomaly
    /// detection. When true, non-POST requests receive 405 Method Not Allowed.
    /// Set to false only if you intentionally proxy non-MCP REST traffic through
    /// Arbiter and accept that it will not be subject to authorization policies.
    #[serde(default = "default_true")]
    pub deny_non_post_methods: bool,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_proxy_port(),
            upstream_url: default_upstream_url(),
            blocked_paths: Vec::new(),
            require_session: true,
            strict_mcp: true,
            max_request_body_bytes: default_max_request_body_bytes(),
            max_response_body_bytes: default_max_response_body_bytes(),
            upstream_timeout_secs: default_upstream_timeout_secs(),
            deny_non_post_methods: true,
        }
    }
}

/// `[oauth]` section: optional JWT validation.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthSection {
    /// JWKS cache TTL in seconds.
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_secs: u64,

    /// Configured identity providers.
    #[serde(default)]
    pub issuers: Vec<IssuerEntry>,
}

/// A single OAuth issuer entry.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuerEntry {
    pub name: String,
    pub issuer_url: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub introspection_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// `[policy]` section: path to policy file or inline policies.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicySection {
    /// Path to a TOML policy file. If set, policies are loaded from this file.
    #[serde(default)]
    pub file: Option<String>,

    /// Inline policies (used if `file` is not set).
    #[serde(default)]
    pub policies: Vec<arbiter_policy::Policy>,

    /// Enable file-system watching for automatic policy hot-reload.
    /// Only applies when `file` is set. Default: false.
    #[serde(default)]
    pub watch: bool,

    /// Debounce duration in milliseconds for the file watcher.
    /// Rapid-fire filesystem events within this window are coalesced into
    /// a single reload. Default: 500.
    #[serde(default = "default_watch_debounce_ms")]
    pub watch_debounce_ms: u64,
}

fn default_watch_debounce_ms() -> u64 {
    500
}

/// `[sessions]` section: session management defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionsSection {
    /// Default time limit for sessions in seconds.
    #[serde(default = "default_session_time_limit")]
    pub default_time_limit_secs: u64,

    /// Default call budget per session.
    #[serde(default = "default_call_budget")]
    pub default_call_budget: u64,

    /// Whether behavioral anomalies should escalate to deny (hard block).
    /// Defaults to true: anomalies are denied, not just logged. Set to false
    /// for advisory-only mode where anomalies are flagged but requests proceed.
    #[serde(default = "default_true")]
    pub escalate_anomalies: bool,

    /// Keywords that indicate a session's intent is read-only.
    /// If the intent matches any of these (case-insensitive word boundary),
    /// write/delete/admin operations are flagged as anomalies.
    /// Defaults to: read, analyze, summarize, review, inspect, view, check, list, search, query, describe, explain.
    #[serde(default = "default_read_intent_keywords")]
    pub read_intent_keywords: Vec<String>,

    /// Keywords that indicate a session's intent includes writes.
    /// Write-intent sessions may read and write, but admin operations are flagged.
    /// Defaults to: write, create, update, modify, edit, deploy, build, generate, publish, upload.
    #[serde(default = "default_write_intent_keywords")]
    pub write_intent_keywords: Vec<String>,

    /// Keywords that indicate a session's intent is administrative.
    /// Admin-intent sessions may perform any operation without anomaly flags.
    /// Defaults to: admin, manage, configure, setup, install, maintain, operate, provision.
    #[serde(default = "default_admin_intent_keywords")]
    pub admin_intent_keywords: Vec<String>,

    /// Suspicious argument patterns that trigger anomaly detection in read sessions.
    #[serde(default)]
    pub suspicious_arg_patterns: Vec<String>,

    /// Percentage threshold for session budget/time warnings.
    /// When remaining budget or time drops to this percentage or below,
    /// X-Arbiter-Warning headers are emitted. Default: 20.0 (20%).
    ///
    /// Why 20%: matches the "one-fifth remaining" heuristic from battery
    /// indicators and cloud quota systems: enough margin to react without
    /// being noisy during normal operation.
    #[serde(default = "default_warning_threshold_pct")]
    pub warning_threshold_pct: f64,

    /// Duration of the sliding rate-limit window in seconds.
    /// Sessions with `rate_limit_per_minute` use this window to track call
    /// frequency. Default: 60 (one minute, matching the "per_minute" semantics).
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,

    /// Interval in seconds for expired session cleanup.
    /// A background task runs at this interval to remove sessions that have
    /// exceeded their time limit. Default: 60 (one cleanup per minute).
    #[serde(default = "default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,

    /// Maximum number of concurrent active sessions per agent.
    ///
    /// P0: Per-agent session cap to prevent session multiplication attacks.
    /// An agent creating N sessions * M budget each = N*M tool calls,
    /// effectively bypassing per-session rate limits. Default: 10.
    /// Set to `None` (omit from config) to disable the cap.
    #[serde(default = "default_max_concurrent_sessions_per_agent")]
    pub max_concurrent_sessions_per_agent: Option<u64>,
}

fn default_read_intent_keywords() -> Vec<String> {
    vec![
        "read".into(),
        "analyze".into(),
        "summarize".into(),
        "review".into(),
        "inspect".into(),
        "view".into(),
        "check".into(),
        "list".into(),
        "search".into(),
        "query".into(),
        "describe".into(),
        "explain".into(),
    ]
}

fn default_write_intent_keywords() -> Vec<String> {
    vec![
        "write".into(),
        "create".into(),
        "update".into(),
        "modify".into(),
        "edit".into(),
        "deploy".into(),
        "build".into(),
        "generate".into(),
        "publish".into(),
        "upload".into(),
    ]
}

fn default_admin_intent_keywords() -> Vec<String> {
    vec![
        "admin".into(),
        "manage".into(),
        "configure".into(),
        "setup".into(),
        "install".into(),
        "maintain".into(),
        "operate".into(),
        "provision".into(),
    ]
}

fn default_warning_threshold_pct() -> f64 {
    20.0
}

fn default_rate_limit_window_secs() -> u64 {
    60
}

fn default_cleanup_interval_secs() -> u64 {
    60
}

fn default_max_concurrent_sessions_per_agent() -> Option<u64> {
    Some(10)
}

impl Default for SessionsSection {
    fn default() -> Self {
        Self {
            default_time_limit_secs: default_session_time_limit(),
            default_call_budget: default_call_budget(),
            escalate_anomalies: true,
            read_intent_keywords: default_read_intent_keywords(),
            write_intent_keywords: default_write_intent_keywords(),
            admin_intent_keywords: default_admin_intent_keywords(),
            suspicious_arg_patterns: Vec::new(),
            warning_threshold_pct: default_warning_threshold_pct(),
            rate_limit_window_secs: default_rate_limit_window_secs(),
            cleanup_interval_secs: default_cleanup_interval_secs(),
            max_concurrent_sessions_per_agent: default_max_concurrent_sessions_per_agent(),
        }
    }
}

/// `[audit]` section: audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditSection {
    /// Enable audit logging.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to an append-only audit log file.
    #[serde(default)]
    pub file_path: Option<String>,

    /// Sensitive field patterns for argument redaction.
    #[serde(default)]
    pub redaction_patterns: Vec<String>,

    /// When true (default), deny all requests if the audit sink is degraded.
    /// Prevents attackers from blinding the audit trail (e.g., filling the disk)
    /// and then operating without forensic evidence. Set to false only for
    /// development environments where audit availability is not critical.
    #[serde(default = "default_true")]
    pub require_healthy: bool,
}

impl Default for AuditSection {
    fn default() -> Self {
        Self {
            enabled: true,
            file_path: None,
            redaction_patterns: Vec::new(),
            require_healthy: true,
        }
    }
}

/// `[metrics]` section: metrics endpoint configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsSection {
    /// Enable the /metrics endpoint on the proxy.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Require API key authentication for the /metrics endpoint.
    /// When true, the /metrics endpoint requires the admin API key via
    /// the `x-api-key` header. Prevents reconnaissance via operational
    /// telemetry (tool names, allow/deny rates, active session counts).
    /// Default: false (standard Prometheus scraping without auth).
    #[serde(default)]
    pub require_auth: bool,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            require_auth: false,
        }
    }
}

/// `[admin]` section: lifecycle admin API configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminSection {
    /// Listen address for the admin API.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Listen port for the admin API.
    #[serde(default = "default_admin_port")]
    pub listen_port: u16,

    /// API key for admin endpoints.
    #[serde(default = "default_admin_api_key")]
    pub api_key: String,

    /// HMAC signing secret for agent tokens.
    #[serde(default = "default_signing_secret")]
    pub signing_secret: String,

    /// Token expiry in seconds.
    #[serde(default = "default_token_expiry")]
    pub token_expiry_secs: i64,
}

impl Default for AdminSection {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            listen_port: default_admin_port(),
            api_key: default_admin_api_key(),
            signing_secret: default_signing_secret(),
            token_expiry_secs: default_token_expiry(),
        }
    }
}

/// `[storage]` section: storage backend configuration.
///
/// REQ-007: Storage behind async trait; swappable backends.
/// Design decision: SQLite chosen, designed for swappable.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageSection {
    /// Storage backend: "memory" (default) or "sqlite".
    /// NOTE: The "memory" backend loses all session state on restart,
    /// including unexpired sessions and their remaining budgets. This means
    /// agents will need to re-create sessions after a gateway restart.
    /// Use "sqlite" for production deployments where session persistence matters.
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// Path to the SQLite database file (only used when backend = "sqlite").
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            sqlite_path: default_sqlite_path(),
        }
    }
}

/// `[credentials]` section: credential injection configuration.
///
/// When present, enables the credential injection pipeline: `${CRED:ref}`
/// patterns in request bodies and headers are resolved against a pluggable
/// credential provider. Response bodies are scrubbed to prevent credential
/// leakage back to agents.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialsSection {
    /// Provider type: "file" or "env".
    #[serde(default = "default_credential_provider")]
    pub provider: String,

    /// Path to the TOML credentials file (when provider = "file").
    /// The file should contain a `[credentials]` table mapping ref names
    /// to secret values.
    #[serde(default)]
    pub file_path: Option<String>,

    /// Environment variable prefix (when provider = "env").
    /// Credentials are resolved from env vars matching this prefix.
    #[serde(default = "default_credential_env_prefix")]
    pub env_prefix: String,
}

fn default_credential_provider() -> String {
    "file".to_string()
}

fn default_credential_env_prefix() -> String {
    "ARBITER_CRED".to_string()
}

fn default_storage_backend() -> String {
    "memory".to_string()
}

fn default_sqlite_path() -> String {
    "arbiter.db".to_string()
}

// --- Defaults ---

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_proxy_port() -> u16 {
    8080
}

fn default_admin_port() -> u16 {
    3000
}

fn default_upstream_url() -> String {
    "http://127.0.0.1:8081".to_string()
}

fn default_jwks_cache_ttl() -> u64 {
    3600
}

fn default_session_time_limit() -> u64 {
    3600
}

fn default_call_budget() -> u64 {
    1000
}

fn default_true() -> bool {
    true
}

fn default_max_request_body_bytes() -> usize {
    10 * 1024 * 1024 // 10 MiB
}
fn default_max_response_body_bytes() -> usize {
    10 * 1024 * 1024 // 10 MiB
}
fn default_upstream_timeout_secs() -> u64 {
    60
}

fn default_admin_api_key() -> String {
    "arbiter-dev-key".to_string()
}

fn default_signing_secret() -> String {
    "arbiter-dev-secret-change-in-production".to_string()
}

fn default_token_expiry() -> i64 {
    3600
}

/// Well-known default values for admin secrets.
/// Used to detect insecure configurations at startup.
const DEFAULT_API_KEY: &str = "arbiter-dev-key";
const DEFAULT_SIGNING_SECRET: &str = "arbiter-dev-secret-change-in-production";

impl ArbiterConfig {
    /// Load configuration from a TOML file.
    ///
    /// After deserialising, environment variables are checked for secret
    /// overrides (P0 credential fix; secrets should live outside config
    /// files in production):
    /// - `ARBITER_ADMIN_API_KEY` overrides `[admin] api_key`
    /// - `ARBITER_SIGNING_SECRET` overrides `[admin] signing_secret`
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: ArbiterConfig = toml::from_str(&contents)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Parse configuration from a TOML string (useful for tests).
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let config: ArbiterConfig = toml::from_str(s)?;
        // Note: tests intentionally skip apply_env_overrides() so that
        // unit tests remain deterministic. Integration tests that need
        // env-based secrets should call apply_env_overrides() explicitly.
        Ok(config)
    }

    /// Security hardening: prefer environment variables for secrets (P0 credential fix).
    ///
    /// When `ARBITER_ADMIN_API_KEY` or `ARBITER_SIGNING_SECRET` are set in
    /// the process environment, they take precedence over whatever was
    /// deserialized from the config file. This keeps secrets out of TOML
    /// files that might be committed to version control.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(key) = std::env::var("ARBITER_ADMIN_API_KEY")
            && !key.is_empty()
        {
            tracing::info!("admin API key loaded from ARBITER_ADMIN_API_KEY env var");
            self.admin.api_key = key;
        }
        if let Ok(secret) = std::env::var("ARBITER_SIGNING_SECRET")
            && !secret.is_empty()
        {
            tracing::info!("signing secret loaded from ARBITER_SIGNING_SECRET env var");
            self.admin.signing_secret = secret;
        }
    }

    /// Validate the configuration, returning all problems found.
    /// Call at startup to catch misconfigurations before they cause runtime failures.
    pub fn validate(&self) -> Vec<ConfigWarning> {
        let mut warnings = Vec::new();

        // Upstream URL must be parseable.
        if self.proxy.upstream_url.parse::<hyper::Uri>().is_err() {
            warnings.push(ConfigWarning::Error(format!(
                "[proxy] upstream_url '{}' is not a valid URL",
                self.proxy.upstream_url
            )));
        }

        // Port conflict detection.
        if self.proxy.listen_port == self.admin.listen_port
            && self.proxy.listen_addr == self.admin.listen_addr
        {
            warnings.push(ConfigWarning::Error(format!(
                "[proxy] listen_port ({}) conflicts with [admin] listen_port; \
                 both would bind to {}:{}",
                self.proxy.listen_port, self.proxy.listen_addr, self.proxy.listen_port
            )));
        }

        // P0: Warn on default secrets.
        // These dev defaults are fine for local development but must not
        // reach production. The tracing::warn!() calls ensure they appear
        // in structured logs even when the caller ignores the returned
        // ConfigWarning vec.
        // Default secrets now block startup.
        // Previously these were warnings that operators could miss.
        if self.admin.api_key == DEFAULT_API_KEY {
            tracing::warn!(
                "SECURITY: Admin API key is the default development value. \
                 Set ARBITER_ADMIN_API_KEY environment variable for production."
            );
            warnings.push(ConfigWarning::Error(
                "[admin] api_key is the default dev key. \
                 Set ARBITER_ADMIN_API_KEY env var or a unique key in config for production. \
                 Arbiter refuses to start with default credentials."
                    .into(),
            ));
        }
        if self.admin.signing_secret == DEFAULT_SIGNING_SECRET {
            tracing::warn!(
                "SECURITY: Signing secret is the default development value. \
                 Set ARBITER_SIGNING_SECRET environment variable for production."
            );
            warnings.push(ConfigWarning::Error(
                "[admin] signing_secret is the default dev secret. \
                 Set ARBITER_SIGNING_SECRET env var or a unique secret in config for production. \
                 Arbiter refuses to start with default credentials."
                    .into(),
            ));
        }

        // Non-POST forwarding weakens authorization boundary.
        if !self.proxy.deny_non_post_methods {
            warnings.push(ConfigWarning::Warn(
                "[proxy] deny_non_post_methods = false: non-POST requests bypass session, \
                 policy, and behavior checks. Only x-agent-id attribution is enforced."
                    .into(),
            ));
        }

        // Policy file existence check.
        if let Some(ref path) = self.policy.file
            && !Path::new(path).exists()
        {
            warnings.push(ConfigWarning::Error(format!(
                "[policy] file '{}' does not exist",
                path
            )));
        }

        // Audit file path parent directory must exist.
        if let Some(ref path) = self.audit.file_path
            && let Some(parent) = Path::new(path).parent()
            && !parent.exists()
        {
            warnings.push(ConfigWarning::Error(format!(
                "[audit] file_path parent directory '{}' does not exist",
                parent.display()
            )));
        }

        // Warn when credential injection is configured with HTTP upstream.
        // Injected credentials travel in plaintext over HTTP, enabling MITM attacks.
        if self.credentials.is_some() && self.proxy.upstream_url.starts_with("http://") {
            warnings.push(ConfigWarning::Warn(
                "[credentials] configured with an HTTP upstream URL; injected credentials \
                 will travel in plaintext. Use HTTPS for production."
                    .into(),
            ));
        }

        // Credentials validation.
        if let Some(ref creds) = self.credentials {
            match creds.provider.as_str() {
                "file" => {
                    if let Some(ref path) = creds.file_path {
                        if !Path::new(path).exists() {
                            warnings.push(ConfigWarning::Error(format!(
                                "[credentials] file_path '{}' does not exist",
                                path
                            )));
                        }
                    } else {
                        warnings.push(ConfigWarning::Error(
                            "[credentials] provider = \"file\" requires file_path".into(),
                        ));
                    }
                }
                "env" => {}
                other => {
                    warnings.push(ConfigWarning::Error(format!(
                        "[credentials] provider must be 'file' or 'env', got '{other}'"
                    )));
                }
            }
        }

        // Storage backend validation.
        match self.storage.backend.as_str() {
            "memory" => {
                warnings.push(ConfigWarning::Warn(
                    "[storage] backend = \"memory\": all session state (budgets, rate limits) \
                     will be lost on restart. Use \"sqlite\" for production deployments."
                        .into(),
                ));
            }
            "sqlite" => {}
            other => {
                warnings.push(ConfigWarning::Error(format!(
                    "[storage] backend must be 'memory' or 'sqlite', got '{other}'"
                )));
            }
        }

        // Proxy body/timeout validation.
        if self.proxy.max_request_body_bytes == 0 {
            warnings.push(ConfigWarning::Error(
                "[proxy] max_request_body_bytes must be > 0".into(),
            ));
        }
        if self.proxy.upstream_timeout_secs == 0 {
            warnings.push(ConfigWarning::Error(
                "[proxy] upstream_timeout_secs must be > 0".into(),
            ));
        }

        // Session threshold / window validation.
        if !(0.0..=100.0).contains(&self.sessions.warning_threshold_pct) {
            warnings.push(ConfigWarning::Error(format!(
                "[sessions] warning_threshold_pct must be 0..100, got {}",
                self.sessions.warning_threshold_pct
            )));
        }
        if self.sessions.rate_limit_window_secs == 0 {
            warnings.push(ConfigWarning::Error(
                "[sessions] rate_limit_window_secs must be > 0 (zero would allow unlimited burst)"
                    .into(),
            ));
        }

        // Session budget sanity.
        if self.sessions.default_call_budget == 0 {
            warnings.push(ConfigWarning::Warn(
                "[sessions] default_call_budget is 0; all sessions will be immediately exhausted"
                    .into(),
            ));
        }
        if self.sessions.default_time_limit_secs == 0 {
            warnings.push(ConfigWarning::Warn(
                "[sessions] default_time_limit_secs is 0; all sessions will expire immediately"
                    .into(),
            ));
        }

        // Warn when credential injection is enabled with an HTTP (not HTTPS) upstream.
        // Credentials injected over plaintext HTTP are visible to network observers.
        if self.credentials.is_some() && self.proxy.upstream_url.starts_with("http://") {
            warnings.push(ConfigWarning::Warn(
                "[proxy] upstream_url uses HTTP with [credentials] enabled; \
                 injected secrets will be transmitted in plaintext. \
                 Use HTTPS for production deployments."
                    .into(),
            ));
        }

        // Warn when SQLite backend is configured without encryption.
        // Field-level encryption protects session data at rest but is opt-in.
        // Operators should be aware that data is stored in plaintext by default.
        if self.storage.backend == "sqlite"
            && std::env::var("ARBITER_STORAGE_ENCRYPTION_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_none()
        {
            tracing::warn!(
                "SECURITY: SQLite storage encryption is disabled. \
                 Set ARBITER_STORAGE_ENCRYPTION_KEY for encryption at rest."
            );
            warnings.push(ConfigWarning::Warn(
                "[storage] SQLite backend without ARBITER_STORAGE_ENCRYPTION_KEY; \
                 session data stored in plaintext. Set the env var for encryption at rest."
                    .into(),
            ));
        }

        warnings
    }
}

/// A configuration validation finding, either a hard error or a warning.
#[derive(Debug, Clone)]
pub enum ConfigWarning {
    /// A problem that will cause runtime failures. Should block startup.
    Error(String),
    /// A suspicious configuration value that may indicate a mistake.
    Warn(String),
}

impl ConfigWarning {
    pub fn is_error(&self) -> bool {
        matches!(self, ConfigWarning::Error(_))
    }
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigWarning::Error(msg) => write!(f, "ERROR: {msg}"),
            ConfigWarning::Warn(msg) => write!(f, "WARN: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        assert_eq!(config.proxy.upstream_url, "http://localhost:9000");
        assert_eq!(config.proxy.listen_port, 8080);
        assert_eq!(config.admin.listen_port, 3000);
        assert!(config.audit.enabled);
        assert!(config.proxy.require_session);
        assert!(config.proxy.strict_mcp);
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[proxy]
listen_addr = "0.0.0.0"
listen_port = 9090
upstream_url = "http://mcp-server:8081"
blocked_paths = ["/admin"]

[sessions]
default_time_limit_secs = 7200
default_call_budget = 500

[audit]
enabled = true
file_path = "/var/log/arbiter/audit.jsonl"
redaction_patterns = ["password", "secret"]

[metrics]
enabled = true

[admin]
listen_addr = "0.0.0.0"
listen_port = 3001
api_key = "my-secure-key"
signing_secret = "my-hmac-secret"
token_expiry_secs = 1800
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        assert_eq!(config.proxy.listen_addr, "0.0.0.0");
        assert_eq!(config.proxy.listen_port, 9090);
        assert_eq!(config.sessions.default_time_limit_secs, 7200);
        assert_eq!(config.sessions.default_call_budget, 500);
        assert_eq!(config.admin.listen_port, 3001);
        assert_eq!(config.admin.api_key, "my-secure-key");
    }

    #[test]
    fn validate_port_conflict() {
        let toml = r#"
[proxy]
listen_port = 8080
upstream_url = "http://localhost:9000"

[admin]
listen_port = 8080
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(|w| w.is_error()),
            "should detect port conflict"
        );
    }

    #[test]
    fn validate_dev_secrets_error() {
        let config =
            ArbiterConfig::parse("[proxy]\nupstream_url = \"http://localhost:9000\"").unwrap();
        let warnings = config.validate();
        // Default secrets now produce errors, not warnings.
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::Error(msg) if msg.contains("api_key"))),
            "should error about default api_key"
        );
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::Error(msg) if msg.contains("signing_secret"))),
            "should error about default signing_secret"
        );
        // Default secrets must block startup.
        assert!(
            warnings.iter().any(|w| w.is_error()),
            "dev defaults should be errors that block startup"
        );
    }

    #[test]
    fn validate_missing_policy_file() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"

[policy]
file = "/nonexistent/path/policies.toml"

[admin]
api_key = "real-key"
signing_secret = "real-secret"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::Error(msg) if msg.contains("does not exist"))),
            "should error on missing policy file"
        );
    }

    #[test]
    fn validate_zero_budget_warns() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"

[sessions]
default_call_budget = 0

[admin]
api_key = "real-key"
signing_secret = "real-secret"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::Warn(msg) if msg.contains("budget"))),
            "should warn about zero budget"
        );
    }

    #[test]
    fn validate_bad_warning_threshold() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"

[sessions]
warning_threshold_pct = 150.0

[admin]
api_key = "real-key"
signing_secret = "real-secret"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(
                |w| matches!(w, ConfigWarning::Error(msg) if msg.contains("warning_threshold_pct"))
            ),
            "should error on threshold > 100"
        );
    }

    #[test]
    fn validate_zero_rate_limit_window() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"

[sessions]
rate_limit_window_secs = 0

[admin]
api_key = "real-key"
signing_secret = "real-secret"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(
                |w| matches!(w, ConfigWarning::Error(msg) if msg.contains("rate_limit_window_secs"))
            ),
            "should error on zero rate limit window"
        );
    }

    #[test]
    fn validate_clean_config_no_errors() {
        let toml = r#"
[proxy]
listen_port = 8080
upstream_url = "http://localhost:9000"

[admin]
listen_port = 3000
api_key = "production-key-abc123"
signing_secret = "production-secret-xyz789"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            !warnings.iter().any(|w| w.is_error()),
            "clean config should have no errors"
        );
    }

    /// Unknown credential provider should produce a validation error.
    #[test]
    fn validate_unknown_credential_provider() {
        let toml = r#"
[proxy]
upstream_url = "https://localhost:9000"

[admin]
api_key = "production-key-abc123"
signing_secret = "production-secret-xyz789"

[credentials]
provider = "vault"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(
                |w| matches!(w, ConfigWarning::Error(msg) if msg.contains("provider") && msg.contains("vault"))
            ),
            "should error on unknown credential provider 'vault': {warnings:?}"
        );
    }

    /// "env" credential provider should pass validation.
    #[test]
    fn validate_env_credential_provider() {
        let toml = r#"
[proxy]
upstream_url = "https://localhost:9000"

[admin]
api_key = "production-key-abc123"
signing_secret = "production-secret-xyz789"

[credentials]
provider = "env"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            !warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::Error(msg) if msg.contains("provider"))),
            "env credential provider should not produce a provider error: {warnings:?}"
        );
    }

    /// Unknown storage backend should produce a validation error.
    #[test]
    fn validate_unknown_storage_backend() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"

[admin]
api_key = "production-key-abc123"
signing_secret = "production-secret-xyz789"

[storage]
backend = "postgres"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(
                |w| matches!(w, ConfigWarning::Error(msg) if msg.contains("backend") && msg.contains("postgres"))
            ),
            "should error on unsupported storage backend 'postgres': {warnings:?}"
        );
    }

    /// HTTP upstream with credentials should produce a warning.
    #[test]
    fn validate_http_upstream_with_credentials_warns() {
        let toml = r#"
[proxy]
upstream_url = "http://example.com"

[admin]
api_key = "production-key-abc123"
signing_secret = "production-secret-xyz789"

[credentials]
provider = "env"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(
                |w| matches!(w, ConfigWarning::Warn(msg) if msg.contains("HTTP") || msg.contains("plaintext"))
            ),
            "should warn about HTTP upstream with credentials: {warnings:?}"
        );
    }

    /// Audit file_path with a nonexistent parent directory should produce an error.
    #[test]
    fn validate_audit_missing_parent_directory() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:9000"

[admin]
api_key = "production-key-abc123"
signing_secret = "production-secret-xyz789"

[audit]
file_path = "/nonexistent/path/audit.jsonl"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        let warnings = config.validate();
        assert!(
            warnings.iter().any(
                |w| matches!(w, ConfigWarning::Error(msg) if msg.contains("audit") && msg.contains("does not exist"))
            ),
            "should error on missing audit file parent directory: {warnings:?}"
        );
    }

    /// RT-204: escalate_anomalies defaults to true when omitted from config.
    #[test]
    fn escalate_anomalies_defaults_to_true() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:8080"

[sessions]
# escalate_anomalies deliberately omitted

[admin]
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        assert!(
            config.sessions.escalate_anomalies,
            "escalate_anomalies should default to true when omitted"
        );
    }

    /// escalate_anomalies can be explicitly set to false.
    #[test]
    fn escalate_anomalies_explicit_false() {
        let toml = r#"
[proxy]
upstream_url = "http://localhost:8080"

[sessions]
escalate_anomalies = false

[admin]
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
        let config = ArbiterConfig::parse(toml).unwrap();
        assert!(
            !config.sessions.escalate_anomalies,
            "escalate_anomalies should be false when explicitly set"
        );
    }
}
