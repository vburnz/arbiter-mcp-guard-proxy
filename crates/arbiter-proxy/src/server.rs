//! Server bootstrap and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;

use arbiter_metrics::ArbiterMetrics;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::signal;

use crate::config::ProxyConfig;
use crate::middleware::MiddlewareChain;
use crate::proxy::{ProxyState, build_audit, handle_request};

/// Run the proxy server. Blocks until a shutdown signal is received.
pub async fn run(config: ProxyConfig) -> anyhow::Result<()> {
    // Validate upstream URL at startup, not at first request.
    let upstream_uri: hyper::Uri = config
        .upstream
        .url
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid upstream URL '{}': {e}", config.upstream.url))?;
    match upstream_uri.scheme_str() {
        Some("http") | Some("https") => {}
        Some(scheme) => {
            anyhow::bail!(
                "upstream URL scheme '{}' is not supported; use http or https",
                scheme
            );
        }
        None => {
            anyhow::bail!(
                "upstream URL '{}' has no scheme; use http:// or https://",
                config.upstream.url
            );
        }
    }

    let addr: SocketAddr = format!(
        "{}:{}",
        config.server.listen_addr, config.server.listen_port
    )
    .parse()?;

    let middleware = MiddlewareChain::from_config(&config.middleware);

    let (audit_sink, redaction_config) = build_audit(&config.audit);
    let metrics = Arc::new(
        ArbiterMetrics::new().map_err(|e| anyhow::anyhow!("failed to create metrics: {e}"))?,
    );

    let state = Arc::new(ProxyState::new(
        config.upstream.url.clone(),
        middleware,
        audit_sink,
        redaction_config,
        metrics,
        config.server.max_body_bytes,
        std::time::Duration::from_secs(config.server.upstream_timeout_secs),
    ));

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, upstream = %config.upstream.url, "proxy listening");

    let header_read_timeout =
        std::time::Duration::from_secs(config.server.header_read_timeout_secs);

    // Connection concurrency limit to prevent resource exhaustion from connection floods.
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(config.server.max_connections));
    tracing::info!(
        max_connections = config.server.max_connections,
        "connection limit configured"
    );

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, remote_addr) = result?;
                let state = Arc::clone(&state);
                tracing::debug!(%remote_addr, "accepted connection");

                let sem = Arc::clone(&connection_semaphore);
                tokio::spawn(async move {
                    // Acquire a permit before serving; drop releases it.
                    let _permit = match sem.acquire().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            tracing::error!("connection semaphore closed");
                            return;
                        }
                    };
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        handle_request(state, req)
                    });
                    if let Err(e) = http1::Builder::new()
                        .header_read_timeout(header_read_timeout)
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::error!(error = %e, %remote_addr, "connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, stopping");
                break;
            }
        }
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT (ctrl-c).
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
