use arbiter_audit::AuditSink;
use arbiter_identity::{AnyRegistry, InMemoryRegistry};
use arbiter_metrics::ArbiterMetrics;
use arbiter_policy::PolicyConfig;
use arbiter_session::{AnySessionStore, SessionStore};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use uuid::Uuid;

use crate::token::TokenConfig;

/// Simple sliding-window rate limiter for admin API endpoints.
///
/// Without rate limiting, an attacker who compromises the admin
/// API key can make unlimited requests, enabling rapid brute-force enumeration
/// of agents/sessions and denial-of-service against the control plane.
///
/// This implements a global sliding window: it tracks timestamps of recent
/// requests and rejects new ones when the window is full.
pub struct AdminRateLimiter {
    /// Timestamps of requests within the current window.
    window: Mutex<VecDeque<Instant>>,
    /// Maximum requests allowed per window.
    max_requests: u64,
    /// Sliding window duration.
    window_duration: Duration,
}

impl AdminRateLimiter {
    /// Create a new rate limiter with the given capacity and window duration.
    pub fn new(max_requests: u64, window_duration: Duration) -> Self {
        Self {
            window: Mutex::new(VecDeque::new()),
            max_requests,
            window_duration,
        }
    }

    /// Check whether a request should be allowed.
    ///
    /// Returns `true` if the request is within the rate limit, `false` if it
    /// should be rejected. Automatically evicts expired entries from the window.
    pub fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let mut window = self.window.lock().unwrap_or_else(|e| e.into_inner());

        // Evict timestamps outside the sliding window.
        while let Some(&front) = window.front() {
            if now.duration_since(front) > self.window_duration {
                window.pop_front();
            } else {
                break;
            }
        }

        if (window.len() as u64) >= self.max_requests {
            false
        } else {
            window.push_back(now);
            true
        }
    }
}

/// Shared application state for the lifecycle API.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<AnyRegistry>,
    pub admin_api_key: String,
    pub token_config: TokenConfig,
    pub session_store: AnySessionStore,
    pub policy_config: Arc<watch::Sender<Arc<Option<PolicyConfig>>>>,
    /// Audit sink for querying per-session stats on close.
    pub audit_sink: Option<Arc<AuditSink>>,
    /// Path to the policy TOML file (for hot-reload).
    pub policy_file_path: Option<String>,
    /// Percentage threshold for session budget/time warnings.
    pub warning_threshold_pct: f64,
    /// Default rate-limit window duration in seconds for new sessions.
    pub default_rate_limit_window_secs: u64,
    /// Shared metrics for gauge updates (active_sessions, registered_agents).
    pub metrics: Arc<ArbiterMetrics>,
    /// Maximum concurrent active sessions per agent (None = no limit).
    /// P0: Per-agent session cap to prevent session multiplication attacks.
    pub max_concurrent_sessions_per_agent: Option<u64>,
    /// Rate limiter for admin API endpoints.
    /// Shared via Arc so the Clone-based axum state sharing works correctly.
    pub admin_rate_limiter: Arc<AdminRateLimiter>,
}

/// Default admin API rate limit: 60 requests per minute.
const DEFAULT_ADMIN_MAX_REQUESTS_PER_MINUTE: u64 = 60;

impl AppState {
    /// Create a new application state with the given admin API key.
    pub fn new(admin_api_key: String) -> Self {
        Self {
            registry: Arc::new(AnyRegistry::InMemory(InMemoryRegistry::new())),
            admin_api_key,
            token_config: TokenConfig::default(),
            session_store: AnySessionStore::InMemory(SessionStore::new()),
            policy_config: Arc::new(watch::channel(Arc::new(None)).0),
            audit_sink: None,
            policy_file_path: None,
            warning_threshold_pct: 20.0,
            default_rate_limit_window_secs: 60,
            metrics: Arc::new(ArbiterMetrics::new().expect("metrics registry init")),
            max_concurrent_sessions_per_agent: Some(10),
            admin_rate_limiter: Arc::new(AdminRateLimiter::new(
                DEFAULT_ADMIN_MAX_REQUESTS_PER_MINUTE,
                Duration::from_secs(60),
            )),
        }
    }

    /// Create a new application state with custom token config.
    pub fn with_token_config(admin_api_key: String, token_config: TokenConfig) -> Self {
        Self {
            registry: Arc::new(AnyRegistry::InMemory(InMemoryRegistry::new())),
            admin_api_key,
            token_config,
            session_store: AnySessionStore::InMemory(SessionStore::new()),
            policy_config: Arc::new(watch::channel(Arc::new(None)).0),
            audit_sink: None,
            policy_file_path: None,
            warning_threshold_pct: 20.0,
            default_rate_limit_window_secs: 60,
            metrics: Arc::new(ArbiterMetrics::new().expect("metrics registry init")),
            max_concurrent_sessions_per_agent: Some(10),
            admin_rate_limiter: Arc::new(AdminRateLimiter::new(
                DEFAULT_ADMIN_MAX_REQUESTS_PER_MINUTE,
                Duration::from_secs(60),
            )),
        }
    }

    /// Create a rate limiter with a custom max requests per minute.
    pub fn with_admin_rate_limit(mut self, max_requests_per_minute: u64) -> Self {
        self.admin_rate_limiter = Arc::new(AdminRateLimiter::new(
            max_requests_per_minute,
            Duration::from_secs(60),
        ));
        self
    }

    /// Log an admin API operation with structured fields for audit trail.
    ///
    /// All admin operations are now logged at info level with
    /// structured tracing fields for observability and forensic analysis.
    pub fn admin_audit_log(&self, operation: &str, agent_id: Option<Uuid>, detail: &str) {
        match agent_id {
            Some(id) => {
                tracing::info!(
                    operation = operation,
                    agent_id = %id,
                    detail = detail,
                    "ADMIN_AUDIT: admin API operation"
                );
            }
            None => {
                tracing::info!(
                    operation = operation,
                    detail = detail,
                    "ADMIN_AUDIT: admin API operation"
                );
            }
        }
    }
}
