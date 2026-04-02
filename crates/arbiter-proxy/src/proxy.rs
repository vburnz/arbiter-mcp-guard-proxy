//! HTTP proxy handler: routes health checks and metrics, runs middleware,
//! forwards to upstream, and records audit + metrics for each request.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use arbiter_audit::{AuditCapture, AuditSink, RedactionConfig};
use arbiter_metrics::ArbiterMetrics;

use crate::config::AuditConfig;
use crate::middleware::MiddlewareChain;

/// Shared state for the proxy handler.
pub struct ProxyState {
    /// Upstream base URL (no trailing slash).
    pub upstream_url: String,
    /// The middleware chain applied to every proxied request.
    pub middleware: MiddlewareChain,
    /// HTTP client for forwarding requests upstream.
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
    /// Audit sink for writing structured audit entries.
    pub audit_sink: Option<Arc<AuditSink>>,
    /// Redaction config for audit argument scrubbing.
    pub redaction_config: RedactionConfig,
    /// Prometheus metrics.
    pub metrics: Arc<ArbiterMetrics>,
}

impl ProxyState {
    /// Create a new proxy state with the given upstream URL and middleware chain.
    pub fn new(
        upstream_url: String,
        middleware: MiddlewareChain,
        audit_sink: Option<Arc<AuditSink>>,
        redaction_config: RedactionConfig,
        metrics: Arc<ArbiterMetrics>,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            upstream_url: upstream_url.trim_end_matches('/').to_string(),
            middleware,
            client,
            audit_sink,
            redaction_config,
            metrics,
        }
    }
}

/// Handle an incoming request: health check, metrics, middleware, then proxy upstream.
pub async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // Health check endpoint; bypass middleware and audit.
    if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
        tracing::debug!("health check");
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("OK")))
            .expect("building static response cannot fail"));
    }

    // Prometheus metrics endpoint; bypass middleware and audit.
    if req.method() == hyper::Method::GET && req.uri().path() == "/metrics" {
        tracing::debug!("metrics endpoint");
        return match state.metrics.render() {
            Ok(body) => Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .expect("building static response cannot fail")),
            Err(e) => {
                tracing::error!(error = %e, "failed to render metrics");
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Internal Server Error")))
                    .expect("building static response cannot fail"))
            }
        };
    }

    // Start audit capture and request timing.
    let mut capture = AuditCapture::begin(state.redaction_config.clone());
    let request_start = Instant::now();

    // Extract audit context from headers (best-effort).
    if let Some(agent_id) = req
        .headers()
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
    {
        capture.set_agent_id(agent_id);
    }
    if let Some(session_id) = req
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
    {
        capture.set_task_session_id(session_id);
    }
    if let Some(chain) = req
        .headers()
        .get("x-delegation-chain")
        .and_then(|v| v.to_str().ok())
    {
        capture.set_delegation_chain(chain);
    }

    let tool = format!("{} {}", req.method(), req.uri().path());
    capture.set_tool_called(&tool);

    // Run middleware chain.
    let req = match state.middleware.execute(req) {
        Ok(r) => {
            capture.set_authorization_decision("allow");
            r
        }
        Err(rejection) => {
            let status = rejection.status().as_u16();
            tracing::info!(status, "request rejected by middleware");
            capture.set_authorization_decision("deny");
            state.metrics.record_request("deny");
            state
                .metrics
                .observe_request_duration(request_start.elapsed().as_secs_f64());

            let entry = capture.finalize(Some(status));
            if let Some(sink) = &state.audit_sink {
                if let Err(e) = sink.write(&entry).await {
                    tracing::error!(error = %e, "failed to write audit entry");
                }
            }

            return Ok(*rejection);
        }
    };

    // Build upstream URI.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri: hyper::Uri = format!("{}{}", state.upstream_url, path_and_query).parse()?;

    tracing::info!(upstream = %upstream_uri, method = %req.method(), "forwarding request");

    // Record tool call metric.
    state.metrics.record_tool_call(req.uri().path());

    // Rebuild the request with the upstream URI.
    let (parts, body) = req.into_parts();
    let mut upstream_req = Request::from_parts(parts, body);
    *upstream_req.uri_mut() = upstream_uri;
    // Remove the Host header so hyper sets the correct one.
    upstream_req.headers_mut().remove(hyper::header::HOST);

    // Forward to upstream and time it.
    let upstream_start = Instant::now();
    let response = match state.client.request(upstream_req).await {
        Ok(resp) => {
            state
                .metrics
                .observe_upstream_duration(upstream_start.elapsed().as_secs_f64());
            let (parts, body) = resp.into_parts();
            let body_bytes = body.collect().await?.to_bytes();
            let status = parts.status.as_u16();
            state.metrics.record_request("allow");
            state
                .metrics
                .observe_request_duration(request_start.elapsed().as_secs_f64());

            let entry = capture.finalize(Some(status));
            if let Some(sink) = &state.audit_sink {
                if let Err(e) = sink.write(&entry).await {
                    tracing::error!(error = %e, "failed to write audit entry");
                }
            }

            Ok(Response::from_parts(parts, Full::new(body_bytes)))
        }
        Err(e) => {
            state
                .metrics
                .observe_upstream_duration(upstream_start.elapsed().as_secs_f64());
            tracing::error!(error = %e, "upstream request failed");
            state.metrics.record_request("allow");
            state
                .metrics
                .observe_request_duration(request_start.elapsed().as_secs_f64());

            let entry = capture.finalize(None);
            if let Some(sink) = &state.audit_sink {
                if let Err(e) = sink.write(&entry).await {
                    tracing::error!(error = %e, "failed to write audit entry");
                }
            }

            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Bad Gateway")))
                .expect("building static response cannot fail"))
        }
    };

    response
}

/// Build an [`AuditSink`] and [`RedactionConfig`] from the proxy's audit config.
pub fn build_audit(config: &AuditConfig) -> (Option<Arc<AuditSink>>, RedactionConfig) {
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

    let sink_config = arbiter_audit::AuditSinkConfig {
        write_stdout: true,
        file_path: config.file_path.as_ref().map(std::path::PathBuf::from),
    };
    let sink = Arc::new(AuditSink::new(sink_config));

    (Some(sink), redaction_config)
}
