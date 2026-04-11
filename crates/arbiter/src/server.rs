//! Server orchestration: starts the proxy and admin API concurrently.

use std::net::SocketAddr;
use std::sync::Arc;

use arbiter_audit::{AuditSink, AuditSinkConfig, RedactionConfig};
use arbiter_behavior::AnomalyConfig;
use arbiter_credential::CredentialProvider;
use arbiter_identity::{AnyRegistry, InMemoryRegistry};
use arbiter_lifecycle::TokenConfig;
use arbiter_metrics::ArbiterMetrics;
use arbiter_proxy::config::MiddlewareConfig;
use arbiter_proxy::middleware::MiddlewareChain;
use arbiter_session::{AnySessionStore, SessionStore};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::signal;

use crate::config::ArbiterConfig;
use crate::handler::{ArbiterState, handle_request};

/// Run the proxy and admin API concurrently. Blocks until shutdown signal.
pub async fn run(config: Arc<ArbiterConfig>) -> anyhow::Result<()> {
    // Build storage backend based on config.
    // REQ-007: Storage behind async trait; swappable backends.
    let (registry, session_store) = build_storage(&config).await?;

    // Build metrics.
    let metrics = Arc::new(
        ArbiterMetrics::new().map_err(|e| anyhow::anyhow!("failed to create metrics: {e}"))?,
    );

    // Build audit sink (community: stdout + file only).
    let (audit_sink, redaction_config) = build_audit(&config.audit);

    // Build middleware chain from proxy config.
    let middleware_config = MiddlewareConfig {
        blocked_paths: config.proxy.blocked_paths.clone(),
        required_headers: Vec::new(),
    };
    let middleware = MiddlewareChain::from_config(&middleware_config);

    // Build anomaly config.
    let anomaly_config = AnomalyConfig {
        escalate_to_deny: config.sessions.escalate_anomalies,
        read_intent_keywords: config.sessions.read_intent_keywords.clone(),
        write_intent_keywords: config.sessions.write_intent_keywords.clone(),
        admin_intent_keywords: config.sessions.admin_intent_keywords.clone(),
        suspicious_arg_patterns: config.sessions.suspicious_arg_patterns.clone(),
    };

    // Build policy config from inline policies or policy file.
    // Policy load failure is a startup-blocking error when a file is configured.
    // The gateway must never serve traffic with a misconfigured authorization policy.
    let policy_config = build_policy_config(&config.policy)?;
    let (policy_tx, policy_rx) = tokio::sync::watch::channel(Arc::new(policy_config));
    let shared_policy = Arc::new(policy_tx);

    // Optionally start the policy file watcher for hot-reload (REQ-005).
    #[cfg(feature = "watch")]
    let _policy_watcher = if config.policy.watch {
        if let Some(ref path) = config.policy.file {
            let debounce = std::time::Duration::from_millis(config.policy.watch_debounce_ms);
            match arbiter_policy::PolicyWatcher::start(path, shared_policy.clone(), debounce) {
                Ok(w) => {
                    tracing::info!(
                        path,
                        debounce_ms = config.policy.watch_debounce_ms,
                        "policy file watcher started"
                    );
                    Some(w)
                }
                Err(e) => {
                    tracing::error!(path, error = %e, "failed to start policy file watcher");
                    None
                }
            }
        } else {
            tracing::warn!(
                "policy.watch = true but no policy.file configured; watcher not started"
            );
            None
        }
    } else {
        None
    };

    // Build credential provider (if configured).
    let credential_provider: Option<Arc<dyn CredentialProvider>> =
        build_credential_provider(&config).await;

    // Build admin API state, sharing the session store with the proxy.
    let token_config = TokenConfig {
        signing_secret: config.admin.signing_secret.clone(),
        expiry_seconds: config.admin.token_expiry_secs,
        issuer: "arbiter".into(),
    };
    let admin_state = arbiter_lifecycle::AppState {
        registry: registry.clone(),
        admin_api_key: config.admin.api_key.clone(),
        token_config,
        session_store: session_store.clone(),
        policy_config: shared_policy.clone(),
        audit_sink: audit_sink.clone(),
        policy_file_path: config.policy.file.clone(),
        warning_threshold_pct: config.sessions.warning_threshold_pct,
        default_rate_limit_window_secs: config.sessions.rate_limit_window_secs,
        metrics: metrics.clone(),
        max_concurrent_sessions_per_agent: config.sessions.max_concurrent_sessions_per_agent,
        admin_rate_limiter: std::sync::Arc::new(arbiter_lifecycle::AdminRateLimiter::new(
            60,
            std::time::Duration::from_secs(60),
        )),
    };

    // Build full arbiter state with all middleware components wired:
    // tracing → metrics → audit → oauth → mcp-parse → session → policy → behavior → cred-inject → forward
    let arbiter_state = Arc::new(ArbiterState::new(
        config.proxy.upstream_url.clone(),
        middleware,
        audit_sink,
        redaction_config,
        metrics.clone(),
        session_store.clone(),
        anomaly_config,
        registry.clone(),
        policy_rx,
        credential_provider,
        config.proxy.require_session,
        config.proxy.strict_mcp,
        config.proxy.deny_non_post_methods,
        config.metrics.require_auth,
        config.admin.api_key.clone(),
        config.sessions.warning_threshold_pct,
        config.proxy.max_request_body_bytes,
        config.proxy.max_response_body_bytes,
        config.proxy.upstream_timeout_secs,
        config.audit.require_healthy,
    ));

    // Spawn background task to clean up expired sessions.
    let cleanup_store = session_store.clone();
    let cleanup_metrics = metrics.clone();
    let cleanup_interval = config.sessions.cleanup_interval_secs;
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval));
        loop {
            interval.tick().await;
            let removed = cleanup_store.cleanup_expired().await;
            if removed > 0 {
                tracing::info!(removed, "cleaned up expired sessions");
                for _ in 0..removed {
                    cleanup_metrics.active_sessions.dec();
                }
            }
        }
    });

    let admin_router = arbiter_lifecycle::router(admin_state);

    // Proxy address.
    let proxy_addr: SocketAddr =
        format!("{}:{}", config.proxy.listen_addr, config.proxy.listen_port).parse()?;

    // Admin API address.
    let admin_addr: SocketAddr =
        format!("{}:{}", config.admin.listen_addr, config.admin.listen_port).parse()?;

    // Start proxy listener.
    let proxy_listener = TcpListener::bind(proxy_addr).await?;
    tracing::info!(
        %proxy_addr,
        upstream = %config.proxy.upstream_url,
        "proxy listening"
    );

    // Start admin API listener.
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    tracing::info!(%admin_addr, "admin API listening");

    // Run admin API with axum.
    let admin_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(admin_listener, admin_router).await {
            tracing::error!(error = %e, "admin API error");
        }
    });

    // Run proxy with full middleware chain.
    // Use a JoinSet to track in-flight connections for graceful shutdown.
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = proxy_listener.accept() => {
                let (stream, remote_addr) = result?;
                let state = Arc::clone(&arbiter_state);
                tracing::debug!(%remote_addr, "accepted connection");

                connections.spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        handle_request(state, req)
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::error!(error = %e, %remote_addr, "connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, draining in-flight connections");
                // Stop accepting new connections, wait for in-flight to finish.
                let inflight = connections.len();
                if inflight > 0 {
                    tracing::info!(inflight, "waiting for in-flight requests to complete");
                    // Give connections a grace period to finish.
                    let drain = async {
                        while connections.join_next().await.is_some() {}
                    };
                    match tokio::time::timeout(std::time::Duration::from_secs(30), drain).await {
                        Ok(()) => tracing::info!("all in-flight connections drained"),
                        Err(_) => tracing::warn!("drain timeout; aborting remaining connections"),
                    }
                }
                admin_handle.abort();
                cleanup_handle.abort();
                break;
            }
        }
        // Clean up completed connection tasks to prevent unbounded growth.
        while connections.try_join_next().is_some() {}
    }

    Ok(())
}

/// Build a [`PolicyConfig`] from the arbiter policy config section.
///
/// Returns an error if a policy file is configured but cannot be read/parsed,
/// blocking startup. The gateway must not serve traffic with a broken policy.
fn build_policy_config(
    config: &crate::config::PolicySection,
) -> anyhow::Result<Option<arbiter_policy::PolicyConfig>> {
    // Load from file if specified.
    if let Some(ref path) = config.file {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read policy file '{}': {e}", path))?;
        let pc = arbiter_policy::PolicyConfig::from_toml(&contents)
            .map_err(|e| anyhow::anyhow!("failed to parse policy file '{}': {e}", path))?;
        tracing::info!(path, policies = pc.policies.len(), "loaded policy file");
        return Ok(Some(pc));
    }

    // Use inline policies if any.
    if !config.policies.is_empty() {
        let mut pc = arbiter_policy::PolicyConfig {
            policies: config.policies.clone(),
        };
        pc.compile()
            .map_err(|e| anyhow::anyhow!("failed to compile inline policy regexes: {e}"))?;
        tracing::info!(policies = pc.policies.len(), "loaded inline policies");
        return Ok(Some(pc));
    }

    Ok(None)
}

/// Build an [`AuditSink`] and [`RedactionConfig`] from the arbiter audit config.
fn build_audit(config: &crate::config::AuditSection) -> (Option<Arc<AuditSink>>, RedactionConfig) {
    if !config.enabled {
        return (None, RedactionConfig::default());
    }

    let redaction_config = if config.redaction_patterns.is_empty() {
        RedactionConfig::default()
    } else {
        RedactionConfig {
            patterns: config.redaction_patterns.clone(),
        }
    };

    let sink_config = AuditSinkConfig {
        write_stdout: true,
        file_path: config.file_path.as_ref().map(std::path::PathBuf::from),
        ..Default::default()
    };
    let sink = Arc::new(AuditSink::new(sink_config));

    (Some(sink), redaction_config)
}

/// Build a credential provider from the `[credentials]` config section.
///
/// Returns `None` if the section is absent, allowing zero-config startup.
/// When configured, the provider resolves `${CRED:ref}` patterns in request
/// bodies against either a TOML file or environment variables.
async fn build_credential_provider(config: &ArbiterConfig) -> Option<Arc<dyn CredentialProvider>> {
    let creds = config.credentials.as_ref()?;

    match creds.provider.as_str() {
        "file" => {
            let path = match creds.file_path.as_ref() {
                Some(p) => p,
                None => {
                    tracing::error!("credentials provider = \"file\" but no file_path configured");
                    return None;
                }
            };
            match arbiter_credential::FileProvider::from_path(path).await {
                Ok(provider) => {
                    tracing::info!(path, "credential file provider loaded");
                    Some(Arc::new(provider) as Arc<dyn CredentialProvider>)
                }
                Err(e) => {
                    tracing::error!(path, error = %e, "failed to load credential file");
                    None
                }
            }
        }
        "env" => {
            let prefix = format!("{}_", creds.env_prefix);
            tracing::info!(prefix = %prefix, "credential env provider initialized");
            Some(
                Arc::new(arbiter_credential::EnvProvider::with_prefix(prefix))
                    as Arc<dyn CredentialProvider>,
            )
        }
        other => {
            tracing::error!(provider = other, "unknown credential provider type");
            None
        }
    }
}

/// Build the storage backend based on configuration.
///
/// Returns an `(AnyRegistry, AnySessionStore)` pair. When backend = "memory",
/// this returns the original in-memory implementations for backward compatibility.
/// When backend = "sqlite", it creates a WAL-mode SQLite pool, runs migrations,
/// and wraps the storage-backed implementations.
///
/// REQ-007: Storage behind async trait; swappable backends.
/// Design decision: SQLite chosen, designed for swappable.
async fn build_storage(
    config: &ArbiterConfig,
) -> anyhow::Result<(Arc<AnyRegistry>, AnySessionStore)> {
    match config.storage.backend.as_str() {
        "memory" => {
            tracing::info!("using in-memory storage backend");
            let registry = Arc::new(AnyRegistry::InMemory(InMemoryRegistry::new()));
            let session_store = AnySessionStore::InMemory(SessionStore::new());
            Ok((registry, session_store))
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            let db_url = format!("sqlite:{}", config.storage.sqlite_path);
            tracing::info!(path = %config.storage.sqlite_path, "initializing SQLite storage backend");

            let sqlite = arbiter_storage::sqlite::SqliteStorage::new(&db_url)
                .await
                .map_err(|e| anyhow::anyhow!("failed to initialize SQLite storage: {e}"))?;

            let sqlite_arc: std::sync::Arc<arbiter_storage::sqlite::SqliteStorage> =
                std::sync::Arc::new(sqlite);

            // Build storage-backed registry.
            let storage_registry = arbiter_identity::StorageBackedRegistry::new(
                sqlite_arc.clone(),
                sqlite_arc.clone(),
            );
            let registry = Arc::new(AnyRegistry::StorageBacked(storage_registry));

            // Build storage-backed session store.
            let storage_session_store = arbiter_session::StorageBackedSessionStore::new(sqlite_arc)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("failed to initialize storage-backed session store: {e}")
                })?;
            let session_store = AnySessionStore::StorageBacked(storage_session_store);

            tracing::info!(path = %config.storage.sqlite_path, "SQLite storage backend ready");
            Ok((registry, session_store))
        }
        #[cfg(not(feature = "sqlite"))]
        "sqlite" => {
            anyhow::bail!(
                "[storage] backend = \"sqlite\" requires the 'sqlite' feature. \
                 Rebuild with: cargo build --features sqlite"
            );
        }
        other => {
            anyhow::bail!(
                "[storage] unknown backend '{}'; expected 'memory' or 'sqlite'",
                other
            );
        }
    }
}

/// Wait for SIGTERM or SIGINT.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install ctrl-c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_audit_from_config() {
        let config = crate::config::AuditSection {
            enabled: true,
            file_path: None,
            redaction_patterns: vec!["password".into()],
            ..Default::default()
        };
        let (sink, redaction) = build_audit(&config);
        assert!(sink.is_some());
        assert_eq!(redaction.patterns, vec!["password"]);
    }

    #[test]
    fn audit_disabled_returns_none() {
        let config = crate::config::AuditSection {
            enabled: false,
            ..Default::default()
        };
        let (sink, _) = build_audit(&config);
        assert!(sink.is_none());
    }
}
