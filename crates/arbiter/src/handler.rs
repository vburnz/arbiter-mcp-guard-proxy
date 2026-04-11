//! Full middleware chain handler for the Arbiter gateway.
//!
//! Orchestrates all middleware stages in order:
//! tracing → metrics → audit → oauth → mcp-parse → session → policy → behavior → forward-upstream
//!
//! This handler lives in the integration binary (not arbiter-proxy) because
//! it ties together all crates in the workspace.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

use arbiter_audit::{AuditCapture, AuditSink, CompiledRedaction, RedactionConfig};
use arbiter_behavior::{AnomalyConfig, AnomalyDetector};
use arbiter_credential::CredentialProvider;
use arbiter_identity::AnyRegistry;
use arbiter_mcp::parser::{ParseResult, parse_mcp_body};
use arbiter_metrics::ArbiterMetrics;
use arbiter_policy::{PolicyConfig, PolicyTrace};
use arbiter_proxy::middleware::MiddlewareChain;
use arbiter_session::AnySessionStore;

/// Shared state for the full Arbiter request handler.
pub struct ArbiterState {
    /// Upstream base URL (no trailing slash).
    pub upstream_url: String,
    /// Basic middleware chain (path blocking, required headers).
    pub middleware: MiddlewareChain,
    /// HTTP/HTTPS client for forwarding requests upstream.
    /// Now supports HTTPS for secure credential transit.
    pub client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    /// Audit sink for writing structured audit entries.
    pub audit_sink: Option<Arc<AuditSink>>,
    /// Pre-compiled redaction patterns for audit argument scrubbing.
    pub compiled_redaction: Arc<CompiledRedaction>,
    /// Prometheus metrics.
    pub metrics: Arc<ArbiterMetrics>,
    /// Session store for task session management.
    pub session_store: AnySessionStore,
    /// Behavioral anomaly detector.
    pub anomaly_detector: AnomalyDetector,
    /// Agent registry for policy evaluation context.
    pub registry: Arc<AnyRegistry>,
    /// Policy configuration for authorization evaluation (lock-free hot-reload via watch channel).
    pub policy_config: tokio::sync::watch::Receiver<Arc<Option<PolicyConfig>>>,
    /// Credential provider for `${CRED:ref}` injection (None = disabled).
    pub credential_provider: Option<Arc<dyn CredentialProvider>>,
    /// Require a valid session header for MCP traffic.
    pub require_session: bool,
    /// Reject non-MCP POST traffic.
    pub strict_mcp: bool,
    /// Deny non-POST HTTP methods (405 Method Not Allowed).
    pub deny_non_post_methods: bool,
    /// Require API key for /metrics endpoint.
    pub metrics_require_auth: bool,
    /// Admin API key (for metrics auth).
    pub metrics_auth_key: String,
    /// Percentage threshold for session budget/time warnings.
    pub warning_threshold_pct: f64,
    /// Maximum request body size in bytes.
    pub max_request_body_bytes: usize,
    /// Maximum response body size in bytes.
    pub max_response_body_bytes: usize,
    /// Timeout for upstream requests.
    pub upstream_timeout: std::time::Duration,
    /// When true, deny all requests if audit sink is degraded.
    pub require_audit_healthy: bool,
    /// Per-agent anomaly counter for trust degradation with time-based decay.
    /// When an agent accumulates enough anomaly flags, its trust level is demoted.
    /// Key: agent_id, Value: (accumulated count, last increment timestamp).
    /// Counter halves every `ANOMALY_DECAY_INTERVAL` since last increment.
    pub anomaly_counts:
        tokio::sync::Mutex<std::collections::HashMap<uuid::Uuid, (u32, std::time::Instant)>>,
    /// Threshold of anomaly flags before trust degradation triggers.
    pub trust_degradation_threshold: u32,
}

impl ArbiterState {
    /// Create a new Arbiter state with all middleware components.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream_url: String,
        middleware: MiddlewareChain,
        audit_sink: Option<Arc<AuditSink>>,
        redaction_config: RedactionConfig,
        metrics: Arc<ArbiterMetrics>,
        session_store: AnySessionStore,
        anomaly_config: AnomalyConfig,
        registry: Arc<AnyRegistry>,
        policy_config: tokio::sync::watch::Receiver<Arc<Option<PolicyConfig>>>,
        credential_provider: Option<Arc<dyn CredentialProvider>>,
        require_session: bool,
        strict_mcp: bool,
        deny_non_post_methods: bool,
        metrics_require_auth: bool,
        metrics_auth_key: String,
        warning_threshold_pct: f64,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        upstream_timeout_secs: u64,
        require_audit_healthy: bool,
    ) -> Self {
        // Use HTTPS-capable connector for upstream requests.
        // Previously used build_http() which only supported plaintext HTTP,
        // meaning all injected credentials traveled in cleartext to the upstream.
        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https_connector);
        Self {
            upstream_url: upstream_url.trim_end_matches('/').to_string(),
            middleware,
            client,
            audit_sink,
            compiled_redaction: Arc::new(redaction_config.compile()),
            metrics,
            session_store,
            anomaly_detector: AnomalyDetector::new(anomaly_config),
            registry,
            policy_config,
            credential_provider,
            require_session,
            strict_mcp,
            deny_non_post_methods,
            metrics_require_auth,
            metrics_auth_key,
            warning_threshold_pct,
            max_request_body_bytes,
            max_response_body_bytes,
            upstream_timeout: std::time::Duration::from_secs(upstream_timeout_secs),
            require_audit_healthy,
            anomaly_counts: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            trust_degradation_threshold: 5,
        }
    }
}

/// Handle an incoming request through the full Arbiter middleware chain:
/// tracing → metrics → audit → oauth → mcp-parse → session → policy → behavior → forward-upstream
pub async fn handle_request(
    state: Arc<ArbiterState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    // ── Stage 0: Health and metrics bypass ──────────────────────────
    if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
        tracing::debug!("health check");
        let audit_degraded = state.audit_sink.as_ref().is_some_and(|s| s.is_degraded());
        let status = if audit_degraded {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        };
        // Reduce health endpoint information disclosure.
        // Previously exposed audit consecutive_failures count, which let attackers
        // monitor the progress of a DoS attack against the audit system.
        let body = serde_json::json!({
            "status": if audit_degraded { "degraded" } else { "healthy" },
        });
        return Ok(Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .expect("health response"));
    }

    if req.method() == hyper::Method::GET && req.uri().path() == "/metrics" {
        tracing::debug!("metrics endpoint");
        // Optional authentication for /metrics to prevent reconnaissance.
        // Tool call names, allow/deny rates, and active session counts are
        // operational telemetry that aids attacker planning.
        if state.metrics_require_auth {
            let key = req
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq(key.as_bytes(), state.metrics_auth_key.as_bytes()) {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"metrics endpoint requires x-api-key header"}"#,
                    )))
                    .expect("static response"));
            }
        }
        return match state.metrics.render() {
            Ok(body) => Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .expect("static response")),
            Err(e) => {
                tracing::error!(error = %e, "failed to render metrics");
                Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &ArbiterError {
                        code: ErrorCode::UpstreamError,
                        message: "Internal Server Error".into(),
                        detail: None,
                        hint: None,
                        request_id: None,
                        policy_trace: None,
                    },
                ))
            }
        };
    }

    // ── Stage 0.5: Audit health gate ────────────────────────────────
    // Deny requests when audit is degraded (if configured).
    // Prevents attackers from operating without audit trail by causing audit failures.
    if state.require_audit_healthy
        && let Some(ref sink) = state.audit_sink
        && sink.is_degraded()
    {
        return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"error":{"code":"AUDIT_REQUIRED","message":"Service unavailable: audit system is degraded"}}"#,
                    )))
                    .expect("static response"));
    }

    // ── Stage 1: Tracing ────────────────────────────────────────────
    let request_id = ::uuid::Uuid::new_v4();
    let request_start = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    tracing::info!(%request_id, %method, %path, "incoming request");

    // ── Stage 2: Metrics (start timing) ─────────────────────────────
    // (timing started above, recorded at the end)

    // ── Stage 3: Audit (begin capture) ──────────────────────────────
    let mut capture =
        AuditCapture::begin_with_id_compiled(request_id, Arc::clone(&state.compiled_redaction));

    // Extract identity headers for audit context.
    let agent_id_header = req
        .headers()
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let session_id_header = req
        .headers()
        .get("x-arbiter-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let delegation_chain_header = req
        .headers()
        .get("x-delegation-chain")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    capture.set_agent_id(&agent_id_header);
    capture.set_task_session_id(&session_id_header);
    capture.set_delegation_chain(&delegation_chain_header);
    capture.set_tool_called(format!("{method} {path}"));

    // ── Stage 4: Basic middleware (path blocking, required headers) ──
    let req = match state.middleware.execute(req) {
        Ok(r) => r,
        Err(rejection) => {
            let status = rejection.status().as_u16();
            tracing::info!(status, "request rejected by middleware");
            capture.set_authorization_decision("deny");
            state.metrics.record_request("deny");
            state
                .metrics
                .observe_request_duration(request_start.elapsed().as_secs_f64());

            let entry = capture.finalize(Some(status));
            write_audit(&state, &entry).await;
            return Ok(*rejection);
        }
    };

    // ── Stage 5: OAuth ──────────────────────────────────────────────
    // NOTE: OAuth middleware exists (arbiter-oauth crate) but is not yet
    // wired into the proxy request path. Agent identity is currently
    // established by the x-agent-id header (advisory, not cryptographic).
    // When OAuth is integrated, cross-reference claims.sub with the
    // session's agent owner to close the identity binding gap (RT-303/RT-312).

    // ── Stage 6: Buffer body + MCP Parse ────────────────────────────
    let (mut parts, body) = req.into_parts();
    // Stream-limited request body collection to prevent OOM.
    // Uses http_body_util::Limited to cap memory allocation DURING streaming.
    // Previously, the full body was collected before checking the size limit,
    // allowing an attacker to cause OOM with a multi-gigabyte request payload.
    let body_bytes = {
        let limited = Limited::new(body, state.max_request_body_bytes);
        match limited.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                tracing::warn!(
                    limit = state.max_request_body_bytes,
                    "request body exceeds size limit during streaming collection"
                );
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    None,
                    ArbiterError {
                        code: ErrorCode::MiddlewareRejected,
                        message: "Request body too large".into(),
                        detail: None,
                        hint: None,
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                )
                .await);
            }
        }
    };

    // Block WebSocket upgrade requests that would hang the handler.
    if parts.headers.get(hyper::header::UPGRADE).is_some() {
        tracing::warn!("WebSocket/upgrade request rejected");
        return Ok(deny(
            &state,
            capture,
            request_id,
            request_start,
            StatusCode::NOT_IMPLEMENTED,
            None,
            ArbiterError {
                code: ErrorCode::MiddlewareRejected,
                message: "Protocol upgrades are not supported".into(),
                detail: None,
                hint: Some("Arbiter does not support WebSocket or other protocol upgrades".into()),
                request_id: Some(request_id.to_string()),
                policy_trace: None,
            },
        )
        .await);
    }

    let mcp_context = parse_mcp_body(&body_bytes);
    let mut tool_name_for_audit = format!("{method} {path}");

    if let ParseResult::Mcp(ref ctx) = mcp_context {
        // Record ALL tool calls in a batch, not just the first.
        // Previously only ctx.requests.first() was captured, allowing attackers to hide
        // malicious operations behind a benign leading request in a batch.
        let mut batch_tool_names: Vec<String> = Vec::new();
        for mcp_req in &ctx.requests {
            if let Some(ref name) = mcp_req.tool_name {
                batch_tool_names.push(format!("{} ({})", name, mcp_req.method));
                state.metrics.record_tool_call(name);
            } else {
                batch_tool_names.push(mcp_req.method.clone());
            }
        }
        if !batch_tool_names.is_empty() {
            tool_name_for_audit = batch_tool_names.join("; ");
            capture.set_tool_called(&tool_name_for_audit);
        }
        // Record arguments from the first request for backward compatibility.
        if let Some(first) = ctx.requests.first()
            && let Some(ref args) = first.arguments
        {
            capture.set_arguments(args.clone());
        }
        tracing::debug!(
            requests = ctx.requests.len(),
            tool_calls = ctx.has_tool_calls(),
            tools = %tool_name_for_audit,
            "parsed MCP request"
        );
    }

    // ── Stage 6.5: Enforcement gates ──────────────────────────────────
    if state.require_session
        && let ParseResult::Mcp(_) = &mcp_context
        && session_id_header.is_empty()
    {
        tracing::warn!("MCP request without session header, denied");
        return Ok(deny(
            &state,
            capture,
            request_id,
            request_start,
            StatusCode::FORBIDDEN,
            None,
            ArbiterError::session_required(),
        )
        .await);
    }

    // ── Stage 6.5a: Non-POST method gate ────────────────────────────
    // MCP is POST-only. Non-POST methods bypass session, policy, and behavior
    // checks entirely. Deny by default to enforce deny-by-default semantics
    // across ALL HTTP methods, not just MCP traffic.
    if method != "POST" {
        if state.deny_non_post_methods {
            tracing::warn!(
                %method, %path,
                "non-POST method denied (MCP is POST-only; set deny_non_post_methods = false to allow)"
            );
            return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                StatusCode::METHOD_NOT_ALLOWED,
                None,
                ArbiterError {
                    code: ErrorCode::MiddlewareRejected,
                    message: "Method not allowed".into(),
                    detail: Some(format!(
                        "HTTP method {} is not permitted. MCP uses POST exclusively.",
                        method
                    )),
                    hint: Some(
                        "Only POST requests are accepted on the proxy port. \
                         Non-POST methods bypass authorization and are denied by default."
                            .into(),
                    ),
                    request_id: Some(request_id.to_string()),
                    policy_trace: None,
                },
            )
            .await);
        } else {
            // Operator explicitly opted into forwarding non-POST methods.
            // Require x-agent-id header for identity attribution even though
            // session/policy/behavior checks are not applied. This prevents
            // fully anonymous access to the upstream via non-POST methods.
            if agent_id_header.is_empty() {
                tracing::warn!(
                    %method, %path,
                    "non-POST method denied: x-agent-id required for identity attribution"
                );
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::BAD_REQUEST,
                    None,
                    ArbiterError {
                        code: ErrorCode::MiddlewareRejected,
                        message: "x-agent-id header required".into(),
                        detail: Some(
                            "Non-POST requests require an x-agent-id header for audit attribution."
                                .into(),
                        ),
                        hint: None,
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                )
                .await);
            }
            // When require_session is true AND a session header is provided,
            // validate the session even for non-POST methods. This prevents
            // non-POST requests from bypassing session expiry, budget, and
            // agent-binding checks.
            if state.require_session && !session_id_header.is_empty() {
                if let Some(sid) = arbiter_session::parse_session_header(&session_id_header) {
                    let agent_uuid = agent_id_header.parse::<uuid::Uuid>().ok();
                    match state.session_store.get(sid).await {
                        Ok(session) => {
                            if session.is_expired() {
                                return Ok(deny(
                                    &state, capture, request_id, request_start,
                                    StatusCode::REQUEST_TIMEOUT, None,
                                    ArbiterError::session_error(&arbiter_session::SessionError::Expired(sid)),
                                ).await);
                            }
                            if let Some(aid) = agent_uuid {
                                if aid != session.agent_id {
                                    return Ok(deny(
                                        &state, capture, request_id, request_start,
                                        StatusCode::FORBIDDEN, None,
                                        ArbiterError::session_error(&arbiter_session::SessionError::AgentMismatch {
                                            session_id: sid, expected: session.agent_id, actual: aid,
                                        }),
                                    ).await);
                                }
                            }
                        }
                        Err(_) => {
                            return Ok(deny(
                                &state, capture, request_id, request_start,
                                StatusCode::NOT_FOUND, None,
                                ArbiterError::session_error(&arbiter_session::SessionError::NotFound(sid)),
                            ).await);
                        }
                    }
                }
            }
            tracing::info!(
                %method, %path, agent_id = %agent_id_header,
                "non-POST method forwarded (deny_non_post_methods = false)"
            );
            capture.set_authorization_decision("allow");
        }
    }

    if let ParseResult::NonMcp = &mcp_context {
        if method == "POST" {
            if state.strict_mcp {
                tracing::warn!("non-MCP POST body rejected in strict mode");
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::FORBIDDEN,
                    None,
                    ArbiterError::non_mcp_rejected(),
                )
                .await);
            }
            // Even in non-strict mode, if policies are configured, NonMcp POST
            // traffic must be denied. Otherwise an attacker can wrap a forbidden
            // tool call in slightly malformed JSON-RPC to bypass all policy eval.
            if (*state.policy_config.borrow()).is_some() {
                tracing::warn!(
                    "non-MCP POST body denied: policies are configured but body \
                     is not valid JSON-RPC; cannot evaluate authorization"
                );
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::FORBIDDEN,
                    None,
                    ArbiterError::non_mcp_rejected(),
                )
                .await);
            }
        }
    }

    // ── Shared preconditions for stages 7-9 ────────────────────────
    // Explicitly reject malformed session headers
    // instead of silently ignoring them.
    let parsed_session_id = if !session_id_header.is_empty() {
        match arbiter_session::parse_session_header(&session_id_header) {
            Some(id) => Some(id),
            None => {
                tracing::warn!(session_header = %session_id_header, "malformed session header");
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::BAD_REQUEST,
                    None,
                    ArbiterError {
                        code: ErrorCode::SessionInvalid,
                        message: "Malformed session header".into(),
                        detail: Some(format!(
                            "x-arbiter-session header value '{}' is not a valid UUID",
                            session_id_header
                        )),
                        hint: Some(
                            "The x-arbiter-session header must contain a valid UUID v4".into(),
                        ),
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                )
                .await);
            }
        }
    } else {
        None
    };

    // ── Stage 7: Session validation ─────────────────────────────────
    // Fetch the session ONCE and reuse throughout the pipeline.
    // Previously queried the session store 3 times (binding, delegation, tool auth),
    // creating a TOCTOU window where session state could change between checks.
    let fetched_session = if let (Some(session_id), ParseResult::Mcp(ctx)) =
        (parsed_session_id, &mcp_context)
    {
        // Verify session-agent binding.
        if agent_id_header.is_empty() {
            tracing::warn!(
                %session_id,
                "session present but x-agent-id header missing, denying to prevent session hijacking"
            );
            return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                StatusCode::BAD_REQUEST,
                None,
                ArbiterError {
                    code: ErrorCode::SessionInvalid,
                    message: "x-agent-id header is required when a session is active".into(),
                    detail: None,
                    hint: Some(
                        "Include the x-agent-id header matching the agent that owns this session"
                            .into(),
                    ),
                    request_id: Some(request_id.to_string()),
                    policy_trace: None,
                },
            )
            .await);
        }
        let header_agent_id = match agent_id_header.parse::<uuid::Uuid>() {
            Ok(id) => id,
            Err(_) => {
                tracing::warn!(
                    agent_id = %agent_id_header,
                    "x-agent-id header is not a valid UUID"
                );
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::BAD_REQUEST,
                    None,
                    ArbiterError {
                        code: ErrorCode::SessionInvalid,
                        message: "x-agent-id header must be a valid UUID".into(),
                        detail: None,
                        hint: None,
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                )
                .await);
            }
        };

        // Single session fetch — reused for binding, delegation, tool auth, and lifecycle warnings.
        let session = match state.session_store.get(session_id).await {
            Ok(s) => s,
            Err(_) => {
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::FORBIDDEN,
                    None,
                    ArbiterError {
                        code: ErrorCode::SessionInvalid,
                        message: "Session not found".into(),
                        detail: None,
                        hint: None,
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                )
                .await);
            }
        };

        // Binding check against the single fetched session.
        if session.agent_id != header_agent_id {
            tracing::warn!(
                session_agent = %session.agent_id,
                header_agent = %header_agent_id,
                "session-agent mismatch: possible session hijacking attempt"
            );
            return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                StatusCode::FORBIDDEN,
                None,
                ArbiterError {
                    code: ErrorCode::SessionInvalid,
                    message: "Session does not belong to this agent".into(),
                    detail: None,
                    hint: None,
                    request_id: Some(request_id.to_string()),
                    policy_trace: None,
                },
            )
            .await);
        }

        // Log delegation chain header mismatch with session snapshot.
        if !delegation_chain_header.is_empty() {
            let session_chain = session.delegation_chain_snapshot.join(",");
            if !session_chain.is_empty() && delegation_chain_header != session_chain {
                tracing::warn!(
                    header_chain = %delegation_chain_header,
                    session_chain = %session_chain,
                    "delegation chain header differs from session snapshot; \
                     policy evaluation will use session snapshot, not client header"
                );
            }
        }

        if let StageVerdict::Deny {
            status,
            policy_matched,
            error,
        } = validate_session_tools(&state.session_store, session_id, Some(header_agent_id), &ctx.requests).await
        {
            return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                status,
                policy_matched.as_deref(),
                error,
            )
            .await);
        }

        // Use the session's delegation chain snapshot for audit instead of
        // the client-supplied header, which is advisory and unverified.
        if !session.delegation_chain_snapshot.is_empty() {
            capture.set_delegation_chain(&session.delegation_chain_snapshot.join(","));
        }

        Some(session)
    } else {
        None
    };

    // ── Stage 7.5: Session lifecycle warnings ──────────────────────
    // Uses the single fetched session from Stage 7 (no re-query).
    // The local session variable has a stale `calls_made` value because
    // `validate_session_tools` already incremented the store's copy.
    // Adjust by the batch size to report accurate remaining calls.
    let calls_consumed_this_request = match &mcp_context {
        ParseResult::Mcp(ctx) => ctx.requests.len() as u64,
        _ => 0,
    };
    let mut session_warnings: Vec<(String, String)> = Vec::new();
    if let Some(ref session) = fetched_session {
        let calls_remaining = session
            .call_budget
            .saturating_sub(session.calls_made + calls_consumed_this_request);
        let budget_pct_remaining = if session.call_budget > 0 {
            (calls_remaining as f64 / session.call_budget as f64) * 100.0
        } else {
            0.0
        };
        let time_remaining_secs = {
            let expires_at = session.created_at + session.time_limit;
            (expires_at - chrono::Utc::now()).num_seconds().max(0)
        };
        let time_pct_remaining = if session.time_limit.num_seconds() > 0 {
            (time_remaining_secs as f64 / session.time_limit.num_seconds() as f64) * 100.0
        } else {
            0.0
        };

        // Always include usage headers for observability.
        session_warnings.push((
            "x-arbiter-calls-remaining".into(),
            calls_remaining.to_string(),
        ));
        session_warnings.push((
            "x-arbiter-seconds-remaining".into(),
            time_remaining_secs.to_string(),
        ));

        // Warning headers when approaching limits.
        if budget_pct_remaining <= state.warning_threshold_pct && session.call_budget > 0 {
            session_warnings.push((
                "x-arbiter-warning".into(),
                format!(
                    "budget low: {} of {} calls remaining ({:.0}%)",
                    calls_remaining, session.call_budget, budget_pct_remaining
                ),
            ));
        }
        if time_pct_remaining <= state.warning_threshold_pct && time_remaining_secs > 0 {
            session_warnings.push((
                "x-arbiter-warning".into(),
                format!(
                    "time low: {}s remaining ({:.0}%)",
                    time_remaining_secs, time_pct_remaining
                ),
            ));
        }
    }

    // ── Stage 8: Policy evaluation ──────────────────────────────────
    // Low-contention snapshot via watch channel; Arc ref-count bump, brief lock hold.
    let policy_snapshot = state.policy_config.borrow().clone();
    let has_policies = policy_snapshot
        .as_ref()
        .as_ref()
        .is_some_and(|pc| !pc.policies.is_empty());

    // Policy evaluation now runs regardless of session presence.
    // Previously, policy evaluation was gated on `parsed_session_id`, meaning
    // `require_session = false` bypassed ALL authorization (policy + behavior).
    // When NO policies are loaded, MCP traffic is now DENIED rather than
    // silently allowed. Deny-by-default means "if I don't know what to do, deny."
    if let ParseResult::Mcp(_) = mcp_context
        && !has_policies
    {
        tracing::warn!("no policies loaded, denying MCP traffic (deny-by-default)");
        return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                StatusCode::FORBIDDEN,
                None,
                ArbiterError {
                    code: ErrorCode::PolicyDenied,
                    message: "No authorization policies are loaded; all MCP traffic is denied".into(),
                    detail: Some("deny-by-default: the gateway has no policies configured to authorize this request".into()),
                    hint: None,
                    request_id: Some(request_id.to_string()),
                    policy_trace: None,
                },
            )
            .await);
    }
    if let (true, ParseResult::Mcp(ctx)) = (has_policies, &mcp_context) {
        let policy_config = (*policy_snapshot).as_ref().unwrap(); // safe: has_policies

        let eval_ctx = if let Some(ref session) = fetched_session {
            // Preferred path: build context from the single fetched session.
            Some(build_eval_context(&state.registry, session, &delegation_chain_header).await)
        } else if parsed_session_id.is_some() {
            // Session ID was provided but fetch failed (already handled in Stage 7).
            None
        } else {
            // Fallback: build minimal context from x-agent-id header.
            build_eval_context_from_header(
                &state.registry,
                &agent_id_header,
                &delegation_chain_header,
            )
            .await
        };

        if let Some(eval_ctx) = eval_ctx {
            let (verdict, policy_id) =
                evaluate_mcp_policies(policy_config, &eval_ctx, &ctx.requests);
            if let Some(pid) = &policy_id {
                capture.set_policy_matched(pid);
            }
            if let StageVerdict::Deny {
                status,
                policy_matched,
                error,
            } = verdict
            {
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    status,
                    policy_matched.as_deref(),
                    error,
                )
                .await);
            }
        } else if parsed_session_id.is_none() {
            // No session and no identifiable agent. Deny MCP traffic when policies are loaded.
            tracing::warn!(
                "MCP request without session or agent identity, denied by policy enforcement"
            );
            return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                StatusCode::FORBIDDEN,
                None,
                ArbiterError {
                    code: ErrorCode::PolicyDenied,
                    message: "Cannot evaluate authorization without agent identity".into(),
                    detail: None,
                    hint: None,
                    request_id: Some(request_id.to_string()),
                    policy_trace: None,
                },
            )
            .await);
        }
    }
    drop(policy_snapshot);

    // ── Stage 9: Behavior anomaly detection ─────────────────────────
    // Use the single fetched session from Stage 7 instead of re-querying the store.
    // Previously this called state.session_store.get(session_id) again, creating a
    // TOCTOU window inconsistent with the single-fetch pattern established in Stage 7.
    // (RT-003 F-11: behavioral anomaly re-fetches session)
    if let (ParseResult::Mcp(ctx), Some(session)) = (&mcp_context, &fetched_session) {
        let (verdict, flags) = detect_behavioral_anomalies(
            &state.anomaly_detector,
            &session.declared_intent,
            &ctx.requests,
        );
        if !flags.is_empty() {
            state.metrics.record_anomaly();
            capture.set_anomaly_flags(flags.clone());

            // Trust degradation feedback loop with time-based decay.
            // Accumulate anomaly flags per agent. Counter halves every hour
            // since last increment, preventing stale flags from months ago
            // from triggering demotion. AIMD-inspired: fast demotion, slow recovery.
            const ANOMALY_DECAY_INTERVAL: std::time::Duration =
                std::time::Duration::from_secs(3600);
            if let Ok(agent_uuid) = agent_id_header.parse::<uuid::Uuid>() {
                let should_demote = {
                    let mut counts = state.anomaly_counts.lock().await;
                    let now = std::time::Instant::now();
                    let (count, last_time) = counts.entry(agent_uuid).or_insert((0, now));
                    // Time-based decay: halve the counter for each decay interval elapsed.
                    let elapsed = now.duration_since(*last_time);
                    let decay_periods = elapsed.as_secs() / ANOMALY_DECAY_INTERVAL.as_secs();
                    if decay_periods > 0 {
                        *count = count.checked_shr(decay_periods as u32).unwrap_or(0);
                    }
                    *count += flags.len() as u32;
                    *last_time = now;
                    *count >= state.trust_degradation_threshold
                };
                if should_demote {
                    use arbiter_identity::AgentRegistry;
                    if let Ok(agent) = state.registry.get_agent(agent_uuid).await {
                        let demoted = match agent.trust_level {
                            arbiter_identity::TrustLevel::Trusted => {
                                arbiter_identity::TrustLevel::Verified
                            }
                            arbiter_identity::TrustLevel::Verified => {
                                arbiter_identity::TrustLevel::Basic
                            }
                            arbiter_identity::TrustLevel::Basic => {
                                arbiter_identity::TrustLevel::Untrusted
                            }
                            arbiter_identity::TrustLevel::Untrusted => {
                                arbiter_identity::TrustLevel::Untrusted
                            }
                        };
                        if demoted != agent.trust_level {
                            tracing::warn!(
                                agent_id = %agent_uuid,
                                from = ?agent.trust_level,
                                to = ?demoted,
                                "trust level demoted due to accumulated behavioral anomalies; \
                                 aborting current request before credential injection"
                            );
                            let _ = state.registry.update_trust_level(agent_uuid, demoted).await;
                            // Reset counter after demotion.
                            let mut counts = state.anomaly_counts.lock().await;
                            counts.insert(agent_uuid, (0, std::time::Instant::now()));

                            // Abort the current request. The trust demotion must
                            // take effect immediately, not on the next request.
                            // Without this, the current request proceeds to
                            // credential injection with the old trust level.
                            return Ok(deny(
                                &state,
                                capture,
                                request_id,
                                request_start,
                                StatusCode::FORBIDDEN,
                                None,
                                ArbiterError::behavioral_anomaly(
                                    "request aborted: agent trust level demoted"
                                ),
                            )
                            .await);
                        }
                    }
                }
            }
        }
        if let StageVerdict::Deny {
            status,
            policy_matched,
            error,
        } = verdict
        {
            return Ok(deny(
                &state,
                capture,
                request_id,
                request_start,
                status,
                policy_matched.as_deref(),
                error,
            )
            .await);
        }
    }

    // ── Stage 9.5a: Canonicalize MCP body ──────────────────────────
    // Reconstruct the forwarded body from the parsed MCP representation
    // BEFORE credential injection, so that parser differentials (duplicate
    // keys, unicode tricks) are eliminated. Credential injection then
    // operates on the canonical form.
    let body_bytes = if let ParseResult::Mcp(ref ctx) = mcp_context {
        Bytes::from(ctx.to_canonical_body())
    } else {
        body_bytes
    };

    // ── Stage 9.5b: Credential injection ─────────────────────────────
    // Only inject credentials when a session has been validated.
    // Non-POST requests and NonMcp traffic skip session validation (stages 7/8/9),
    // so they must NOT receive credential injection. Without this guard, any
    // client sending a non-POST request with ${CRED:ref} patterns would receive
    // resolved secrets with no authorization check.
    let mut injected_secrets: Vec<secrecy::SecretString> = Vec::new();
    let body_bytes = if fetched_session.is_some() && state.credential_provider.is_some() {
        let provider = state.credential_provider.as_ref().unwrap();
        // Reject non-UTF-8 request bodies when credential injection is active.
        // Previously used from_utf8_lossy, which could break ${CRED:ref} patterns spanning
        // invalid UTF-8 boundaries, causing literal credential reference patterns to be forwarded
        // to the upstream in plaintext.
        let body_str = match String::from_utf8(body_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!(
                    "request body contains invalid UTF-8 with credential injection active; rejecting"
                );
                return Ok(deny(
                    &state,
                    capture,
                    request_id,
                    request_start,
                    StatusCode::BAD_REQUEST,
                    None,
                    ArbiterError {
                        code: ErrorCode::MiddlewareRejected,
                        message:
                            "Request body must be valid UTF-8 when credential injection is enabled"
                                .into(),
                        detail: None,
                        hint: None,
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                )
                .await);
            }
        };
        let body_str = std::borrow::Cow::Owned(body_str);

        // Collect headers that contain credential reference patterns.
        let header_pairs: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let v = value.to_str().ok()?;
                if v.contains("${CRED:") {
                    Some((name.to_string(), v.to_string()))
                } else {
                    None
                }
            })
            .collect();

        let body_refs = arbiter_credential::inject::find_refs(&body_str);
        let has_body_refs = !body_refs.is_empty();

        // Validate each credential reference against the session's authorized_credentials.
        // The session's authorized_credentials list (set at creation time) controls
        // which credentials this session may resolve, preventing agents from
        // injecting ${CRED:admin_password} inside an authorized tool call.
        if let Some(ref session) = fetched_session {
            for cred_ref in &body_refs {
                if !session.is_credential_authorized(cred_ref) {
                    tracing::warn!(
                        credential_ref = cred_ref,
                        session_id = %session.session_id,
                        "credential reference not authorized for this session"
                    );
                    return Ok(deny(
                        &state,
                        capture,
                        request_id,
                        request_start,
                        StatusCode::FORBIDDEN,
                        None,
                        ArbiterError {
                            code: ErrorCode::SessionInvalid,
                            message: "credential reference not authorized for this session".into(),
                            detail: None,
                            hint: None,
                            request_id: Some(request_id.to_string()),
                            policy_trace: None,
                        },
                    )
                    .await);
                }
            }
        }

        if !has_body_refs && header_pairs.is_empty() {
            body_bytes
        } else {
            match arbiter_credential::inject_credentials(
                &body_str,
                &header_pairs,
                provider.as_ref(),
            )
            .await
            {
                Ok(result) => {
                    if !result.resolved_refs.is_empty() {
                        tracing::info!(
                            count = result.resolved_refs.len(),
                            "credentials injected into request"
                        );
                        // Use values captured at injection time.
                        // Previously re-resolved from the provider, which could return
                        // different values if credentials were rotated between calls.
                        injected_secrets = result.resolved_values;
                    }
                    // Apply injected headers back to the request.
                    for (name, value) in &result.headers {
                        if let (Ok(header_name), Ok(header_value)) = (
                            hyper::header::HeaderName::from_bytes(name.as_bytes()),
                            hyper::header::HeaderValue::from_str(value),
                        ) {
                            parts.headers.insert(header_name, header_value);
                        }
                    }
                    Bytes::from(result.body)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "credential injection failed");
                    return Ok(deny(
                        &state,
                        capture,
                        request_id,
                        request_start,
                        StatusCode::BAD_REQUEST,
                        None,
                        ArbiterError::credential_error(&e.to_string()),
                    )
                    .await);
                }
            }
        }
    } else {
        body_bytes
    };

    // ── Stage 10: Forward to upstream ───────────────────────────────
    capture.set_authorization_decision("allow");

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri: hyper::Uri = format!("{}{}", state.upstream_url, path_and_query).parse()?;

    tracing::info!(upstream = %upstream_uri, %method, "forwarding request");

    // Remove the original content-length before
    // constructing the upstream request. Credential injection may modify the body,
    // making the original content-length stale. hyper will set it correctly from
    // the Full<Bytes> body's size_hint().
    parts.headers.remove(hyper::header::CONTENT_LENGTH);

    let mut upstream_req = Request::from_parts(parts, Full::new(body_bytes));
    *upstream_req.uri_mut() = upstream_uri;
    upstream_req.headers_mut().remove(hyper::header::HOST);

    // Strip x-arbiter-* headers from outbound requests.
    // The upstream should not see session metadata (session ID, calls remaining, etc.)
    // that could aid timing attacks or reveal internal gateway state.
    let arbiter_req_headers: Vec<hyper::header::HeaderName> = upstream_req
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("x-arbiter-"))
        .cloned()
        .collect();
    for name in arbiter_req_headers {
        upstream_req.headers_mut().remove(&name);
    }

    // Strip Accept-Encoding to prevent compressed responses that bypass credential scrubbing.
    if state.credential_provider.is_some() {
        upstream_req
            .headers_mut()
            .remove(hyper::header::ACCEPT_ENCODING);
    }

    let upstream_start = Instant::now();
    // Enforce upstream request timeout to prevent indefinite blocking.
    match tokio::time::timeout(state.upstream_timeout, state.client.request(upstream_req)).await {
        Err(_elapsed) => {
            state
                .metrics
                .observe_upstream_duration(upstream_start.elapsed().as_secs_f64());
            tracing::error!(
                timeout_secs = state.upstream_timeout.as_secs(),
                "upstream request timed out"
            );
            state.metrics.record_request("timeout");
            state
                .metrics
                .observe_request_duration(request_start.elapsed().as_secs_f64());

            let entry = capture.finalize(None);
            write_audit(&state, &entry).await;

            Ok(error_response(
                StatusCode::GATEWAY_TIMEOUT,
                &ArbiterError {
                    code: ErrorCode::UpstreamError,
                    message: "Gateway Timeout".into(),
                    detail: Some(format!(
                        "upstream did not respond within {} seconds",
                        state.upstream_timeout.as_secs()
                    )),
                    // Don't expose config key names in hints.
                    hint: None,
                    request_id: Some(request_id.to_string()),
                    policy_trace: None,
                },
            ))
        }
        Ok(result) => match result {
            Ok(resp) => {
                state
                    .metrics
                    .observe_upstream_duration(upstream_start.elapsed().as_secs_f64());
                let (mut resp_parts, resp_body) = resp.into_parts();
                // Stream-limited response collection to prevent OOM.
                // Previously, the full response was collected before checking the size limit,
                // allowing a malicious upstream to cause OOM with a multi-gigabyte response.
                let limited_resp = Limited::new(resp_body, state.max_response_body_bytes);
                let mut resp_bytes = match limited_resp.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(_) => {
                        tracing::warn!(
                            limit = state.max_response_body_bytes,
                            "upstream response exceeded size limit during streaming collection"
                        );
                        state
                            .metrics
                            .observe_upstream_duration(upstream_start.elapsed().as_secs_f64());
                        state.metrics.record_request("deny");
                        state
                            .metrics
                            .observe_request_duration(request_start.elapsed().as_secs_f64());
                        let entry = capture.finalize(None);
                        write_audit(&state, &entry).await;
                        return Ok(error_response(
                            StatusCode::BAD_GATEWAY,
                            &ArbiterError {
                                code: ErrorCode::UpstreamError,
                                message: "Upstream response too large".into(),
                                detail: Some(
                                    "upstream response exceeded the configured size limit".into(),
                                ),
                                hint: None,
                                request_id: Some(request_id.to_string()),
                                policy_trace: None,
                            },
                        ));
                    }
                };
                let status = resp_parts.status.as_u16();

                // ── Stage 10.4: Decompress response for scrubbing ─────
                // Defense-in-depth: even though we strip Accept-Encoding from
                // outbound requests, a malicious upstream could ignore that and
                // return compressed content to bypass credential scrubbing.
                if !injected_secrets.is_empty()
                    && let Some(encoding) = resp_parts.headers.get(hyper::header::CONTENT_ENCODING)
                {
                    let encoding_str = encoding.to_str().unwrap_or("");
                    let decompressed =
                        decompress_body(&resp_bytes, encoding_str, state.max_response_body_bytes);
                    match decompressed {
                        Ok(bytes) => {
                            tracing::info!(
                                encoding = encoding_str,
                                "decompressed response body before credential scrubbing"
                            );
                            resp_bytes = bytes;
                            // Remove Content-Encoding since we've decompressed.
                            resp_parts.headers.remove(hyper::header::CONTENT_ENCODING);
                        }
                        Err(e) => {
                            // Can't decompress: reject to prevent scrub bypass.
                            tracing::warn!(
                                encoding = encoding_str,
                                error = %e,
                                "cannot decompress response with active credential injection; \
                                 rejecting to prevent scrub bypass"
                            );
                            resp_bytes = Bytes::from(
                                "{\"error\": \"upstream response uses unsupported content encoding\"}",
                            );
                            resp_parts.status = hyper::StatusCode::BAD_GATEWAY;
                        }
                    }
                }

                // ── Stage 10.5: Response credential scrubbing ───────────
                if !injected_secrets.is_empty() {
                    // Reject non-UTF-8 responses when credentials were injected.
                    // Previously used from_utf8_lossy, which replaced invalid bytes with U+FFFD,
                    // allowing an upstream to embed credentials in invalid UTF-8 sequences to evade scrubbing.
                    match String::from_utf8(resp_bytes.to_vec()) {
                        Ok(resp_str) => {
                            let scrubbed =
                                arbiter_credential::scrub_response(&resp_str, &injected_secrets);
                            if scrubbed != resp_str {
                                tracing::warn!(
                                    "credential values detected in upstream response, scrubbed"
                                );
                            }
                            resp_bytes = Bytes::from(scrubbed);
                        }
                        Err(_) => {
                            tracing::warn!(
                                "upstream response contains invalid UTF-8 with active credential injection; rejecting to prevent scrub bypass"
                            );
                            resp_bytes = Bytes::from(
                                "{\"error\": \"upstream response contained invalid encoding\"}",
                            );
                            resp_parts.status = hyper::StatusCode::BAD_GATEWAY;
                        }
                    }
                }

                // ── Stage 10.6: Response data classification ────────────
                // Scan the response body for sensitive data patterns and enforce
                // the session's data_sensitivity_ceiling. This prevents upstream
                // services from returning data that exceeds the session's authorization.
                if let Some(ref session) = fetched_session {
                    // Use strict UTF-8 for data classification, consistent with
                    // credential scrubbing (Stage 10.5). Previously used from_utf8_lossy,
                    // which could allow a malicious upstream to hide sensitive data
                    // in non-UTF-8 sequences that disrupt pattern matching.
                    let resp_str = match String::from_utf8(resp_bytes.to_vec()) {
                        Ok(s) => s,
                        Err(_) => {
                            tracing::warn!(
                                "response contains non-UTF-8 bytes; \
                                     skipping data classification (defense-in-depth only)"
                            );
                            String::new() // skip classification for non-UTF-8 responses
                        }
                    };
                    let findings =
                        arbiter_credential::response_classifier::scan_response(&resp_str);
                    if !findings.is_empty() {
                        let ceiling = session.data_sensitivity_ceiling;
                        let mut finding_descriptions: Vec<String> = Vec::new();
                        let mut max_detected: Option<arbiter_session::DataSensitivity> = None;

                        for finding in &findings {
                            let mapped = match finding.sensitivity {
                                arbiter_credential::DetectedSensitivity::Internal => {
                                    arbiter_session::DataSensitivity::Internal
                                }
                                arbiter_credential::DetectedSensitivity::Confidential => {
                                    arbiter_session::DataSensitivity::Confidential
                                }
                                arbiter_credential::DetectedSensitivity::Restricted => {
                                    arbiter_session::DataSensitivity::Restricted
                                }
                            };
                            finding_descriptions.push(format!(
                                "{:?}: {}",
                                finding.sensitivity, finding.pattern_name
                            ));
                            max_detected = Some(
                                max_detected
                                    .map_or(mapped, |prev: arbiter_session::DataSensitivity| {
                                        prev.max(mapped)
                                    }),
                            );
                        }

                        if let Some(detected) = max_detected {
                            if detected > ceiling {
                                tracing::warn!(
                                    session_id = %session.session_id,
                                    ?ceiling,
                                    ?detected,
                                    findings = ?finding_descriptions,
                                    "response contains data exceeding session sensitivity ceiling"
                                );
                                capture.add_inspection_findings(finding_descriptions.clone());

                                // Restricted data in a non-Restricted session: block entirely
                                if detected == arbiter_session::DataSensitivity::Restricted
                                    && ceiling != arbiter_session::DataSensitivity::Restricted
                                {
                                    state.metrics.record_request("deny");
                                    state.metrics.observe_request_duration(
                                        request_start.elapsed().as_secs_f64(),
                                    );
                                    let entry = capture.finalize(Some(status));
                                    write_audit(&state, &entry).await;
                                    return Ok(error_response(
                                            StatusCode::BAD_GATEWAY,
                                            &ArbiterError {
                                                code: ErrorCode::UpstreamError,
                                                message:
                                                    "Response blocked: contained restricted data"
                                                        .into(),
                                                detail: Some(
                                                    "The upstream response contained data classified as Restricted, \
                                                     which exceeds this session's data sensitivity ceiling"
                                                        .into(),
                                                ),
                                                hint: None,
                                                request_id: Some(request_id.to_string()),
                                                policy_trace: None,
                                            },
                                        ));
                                }
                                // Non-Restricted findings that exceed ceiling: log + audit but forward
                            } else {
                                // Findings are within the ceiling — still record them for audit
                                capture.add_inspection_findings(finding_descriptions);
                            }
                        }
                    }
                }

                // Update content-length after response scrubbing may have changed body size.
                if let Ok(len_val) =
                    hyper::header::HeaderValue::from_str(&resp_bytes.len().to_string())
                {
                    resp_parts
                        .headers
                        .insert(hyper::header::CONTENT_LENGTH, len_val);
                }

                // Removed audit degradation info leak from response headers.
                // Previously, x-arbiter-audit-degraded with consecutive_failures count was sent to
                // clients, allowing attackers to monitor DoS progress against the audit system.
                // Audit degradation status is now only visible via the /health endpoint and server logs.
                if let Some(ref sink) = state.audit_sink
                    && sink.is_degraded()
                {
                    tracing::warn!(
                        "audit sink degraded; response forwarded without header disclosure"
                    );
                }

                // Strip upstream X-Arbiter-* headers.
                // A malicious upstream could inject spoofed x-arbiter-warning,
                // x-arbiter-calls-remaining, or x-arbiter-seconds-remaining headers
                // to mislead agents about their session state. Remove ALL x-arbiter-*
                // headers from the upstream response before injecting Arbiter's own.
                let arbiter_header_names: Vec<hyper::header::HeaderName> = resp_parts
                    .headers
                    .keys()
                    .filter(|name| name.as_str().starts_with("x-arbiter-"))
                    .cloned()
                    .collect();
                for name in arbiter_header_names {
                    resp_parts.headers.remove(&name);
                }

                // Inject session lifecycle warning headers.
                for (name, value) in &session_warnings {
                    if let (Ok(header_name), Ok(header_value)) = (
                        hyper::header::HeaderName::from_bytes(name.as_bytes()),
                        hyper::header::HeaderValue::from_str(value),
                    ) {
                        resp_parts.headers.append(header_name, header_value);
                    }
                }

                state.metrics.record_request("allow");
                state
                    .metrics
                    .observe_request_duration(request_start.elapsed().as_secs_f64());

                let entry = capture.finalize(Some(status));
                write_audit(&state, &entry).await;

                Ok(Response::from_parts(resp_parts, Full::new(resp_bytes)))
            }
            Err(e) => {
                state
                    .metrics
                    .observe_upstream_duration(upstream_start.elapsed().as_secs_f64());
                tracing::error!(error = %e, "upstream request failed");
                state.metrics.record_request("error");
                state
                    .metrics
                    .observe_request_duration(request_start.elapsed().as_secs_f64());

                let entry = capture.finalize(None);
                write_audit(&state, &entry).await;

                Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    &ArbiterError {
                        code: ErrorCode::UpstreamError,
                        message: "Bad Gateway".into(),
                        // Don't expose upstream error details to agents.
                        // Internal network topology (IPs, DNS names, ports) may leak via error messages.
                        detail: Some("upstream server returned an error or is unreachable".into()),
                        hint: None,
                        request_id: Some(request_id.to_string()),
                        policy_trace: None,
                    },
                ))
            }
        }, // close `match result`
    } // close `match tokio::time::timeout`
}

// ── Structured error responses ───────────────────────────────────────

/// Arbiter error codes. Each denial reason has a unique, greppable code.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum ErrorCode {
    /// MCP request was received without a session header.
    #[serde(rename = "SESSION_REQUIRED")]
    SessionRequired,
    /// Non-MCP POST traffic rejected in strict mode.
    #[serde(rename = "NON_MCP_REJECTED")]
    NonMcpRejected,
    /// Session not found, expired, budget exceeded, or tool not authorized.
    #[serde(rename = "SESSION_INVALID")]
    SessionInvalid,
    /// No policy matched (deny-by-default) or an explicit deny policy matched.
    #[serde(rename = "POLICY_DENIED")]
    PolicyDenied,
    /// Policy requires human-in-the-loop escalation.
    #[serde(rename = "ESCALATION_REQUIRED")]
    EscalationRequired,
    /// Behavioral anomaly detected and escalated to deny.
    #[serde(rename = "BEHAVIORAL_ANOMALY")]
    BehavioralAnomaly,
    /// Request rejected by basic middleware (path block, missing headers).
    #[serde(rename = "MIDDLEWARE_REJECTED")]
    MiddlewareRejected,
    /// Credential injection failed (missing or unresolvable reference).
    #[serde(rename = "CREDENTIAL_ERROR")]
    CredentialError,
    /// Upstream server returned an error or is unreachable.
    #[serde(rename = "UPSTREAM_ERROR")]
    UpstreamError,
}

/// Structured JSON error body returned for every denial.
#[derive(Debug, Serialize)]
pub struct ArbiterError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Request ID for correlating this error with audit log entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Policy evaluation trace: shows which policies were considered and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_trace: Option<Vec<PolicyTrace>>,
}

impl ArbiterError {
    fn session_required() -> Self {
        Self {
            code: ErrorCode::SessionRequired,
            message: "MCP requests require an active session".into(),
            detail: None,
            // Don't reveal admin API endpoint structure.
            hint: Some(
                "An active session is required. Include a valid session ID \
                 in the x-arbiter-session header."
                    .into(),
            ),
            request_id: None,
            policy_trace: None,
        }
    }

    fn non_mcp_rejected() -> Self {
        Self {
            code: ErrorCode::NonMcpRejected,
            message: "Only MCP JSON-RPC traffic is allowed on this endpoint".into(),
            detail: None,
            hint: Some(
                "Ensure your POST body is a valid JSON-RPC 2.0 request with \
                 \"jsonrpc\": \"2.0\". Non-MCP traffic is rejected when strict_mcp is enabled"
                    .into(),
            ),
            request_id: None,
            policy_trace: None,
        }
    }

    pub(crate) fn session_error(err: &arbiter_session::SessionError) -> Self {
        use arbiter_session::SessionError;
        let (detail, hint) = match err {
            SessionError::NotFound(id) => (
                format!("session {id} does not exist"),
                "Verify the session ID in the x-arbiter-session header. \
                 Sessions may have been purged on server restart (in-memory store)."
                    .to_string(),
            ),
            SessionError::Expired(id) => (
                format!("session {id} has expired"),
                // Don't expose config key names in hints.
                "Create a new session. Session time limits are set at creation time.".to_string(),
            ),
            SessionError::BudgetExceeded {
                session_id, ..
            } => (
                format!("session {session_id} budget exhausted"),
                "Create a new session with a higher call budget.".to_string(),
            ),
            SessionError::ToolNotAuthorized { session_id, tool } => (
                format!("tool '{tool}' is not authorized for session {session_id}"),
                "Check that the tool is permitted by the applicable policy.".to_string(),
            ),
            SessionError::AlreadyClosed(id) => (
                format!("session {id} has been closed"),
                "Create a new session. Closed sessions cannot be reused.".to_string(),
            ),
            SessionError::RateLimited {
                session_id, ..
            } => (
                format!("session {session_id} rate limited"),
                "Wait before retrying, or create a session with a higher rate limit.".to_string(),
            ),
            SessionError::TooManySessions {
                agent_id, ..
            } => (
                format!("agent {agent_id} has too many active sessions"),
                "Close existing sessions before creating new ones.".to_string(),
            ),
            SessionError::AgentMismatch { session_id, .. } => (
                format!("session {session_id} is not bound to this agent"),
                "The session belongs to a different agent. Each session is bound to the agent that created it.".to_string(),
            ),
            SessionError::StorageWriteThrough { session_id, .. } => (
                format!("session {session_id} storage write failed"),
                "The session state update could not be persisted. Retry the request.".to_string(),
            ),
        };
        Self {
            code: ErrorCode::SessionInvalid,
            message: format!("Session error: {err}"),
            detail: Some(detail),
            hint: Some(hint),
            request_id: None,
            policy_trace: None,
        }
    }

    pub(crate) fn policy_denied_with_trace(reason: &str, trace: Vec<PolicyTrace>) -> Self {
        // Policy traces revealed all policy IDs, effects, specificity
        // scores, and skip reasons to denied agents, enabling reverse-engineering of the
        // full policy configuration. Traces are now logged for operator diagnostics only.
        tracing::debug!(?trace, "policy evaluation trace (not returned to client)");
        Self {
            code: ErrorCode::PolicyDenied,
            message: format!("Policy: {reason}"),
            detail: None,
            hint: Some(
                "Request denied by authorization policy. Contact your \
                 administrator to debug policy evaluation."
                    .into(),
            ),
            request_id: None,
            policy_trace: None,
        }
    }

    pub(crate) fn escalation_required(reason: &str) -> Self {
        Self {
            code: ErrorCode::EscalationRequired,
            message: format!("Escalation required: {reason}"),
            detail: None,
            hint: Some(
                "This operation requires human-in-the-loop approval. \
                 The matching policy has effect = \"escalate\"."
                    .into(),
            ),
            request_id: None,
            policy_trace: None,
        }
    }

    /// Don't expose credential reference names in error responses.
    pub(crate) fn credential_error(_internal_detail: &str) -> Self {
        Self {
            code: ErrorCode::CredentialError,
            message: "Credential injection failed".into(),
            detail: None, // Internal detail intentionally omitted to prevent credential name enumeration
            hint: Some(
                "A ${CRED:ref} pattern in the request could not be resolved. \
                 Check that the credential reference exists in the configured provider."
                    .into(),
            ),
            request_id: None,
            policy_trace: None,
        }
    }

    pub(crate) fn behavioral_anomaly(reason: &str) -> Self {
        Self {
            code: ErrorCode::BehavioralAnomaly,
            message: format!("Behavioral anomaly: {reason}"),
            detail: None,
            // Don't expose config key names in error hints.
            hint: Some(
                "The tool call doesn't match the session's declared intent. \
                 Create a new session with the appropriate intent for this operation."
                    .into(),
            ),
            request_id: None,
            policy_trace: None,
        }
    }
}

/// Decompress a response body based on Content-Encoding header.
/// Supports gzip and deflate. Returns an error for unsupported encodings
/// so the caller can reject the response rather than forwarding unscrubbable content.
///
/// `max_bytes` caps the decompressed output to prevent compression bomb DoS.
/// A malicious upstream could return a small compressed payload that expands to
/// gigabytes, causing OOM. The compressed size is checked by `Limited` before
/// this function is called, but decompression can amplify size dramatically.
fn decompress_body(body: &Bytes, encoding: &str, max_bytes: usize) -> Result<Bytes, String> {
    use flate2::read::{DeflateDecoder, GzDecoder};
    use std::io::Read;

    let encoding = encoding.trim().to_lowercase();
    if encoding == "identity" || encoding.is_empty() {
        return Ok(body.clone());
    }

    // Read in chunks with a size limit to prevent compression bomb DoS.
    fn read_limited(reader: &mut dyn Read, max_bytes: usize) -> Result<Vec<u8>, String> {
        let mut decompressed = Vec::with_capacity(max_bytes.min(1 << 20));
        let mut buf = [0u8; 8192];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("decompression failed: {e}"))?;
            if n == 0 {
                break;
            }
            if decompressed.len() + n > max_bytes {
                return Err(format!(
                    "decompressed response exceeds {} byte limit (compression bomb suspected)",
                    max_bytes
                ));
            }
            decompressed.extend_from_slice(&buf[..n]);
        }
        Ok(decompressed)
    }

    let decompressed = if encoding == "gzip" || encoding == "x-gzip" {
        let mut decoder = GzDecoder::new(body.as_ref());
        read_limited(&mut decoder, max_bytes)?
    } else if encoding == "deflate" {
        let mut decoder = DeflateDecoder::new(body.as_ref());
        read_limited(&mut decoder, max_bytes)?
    } else {
        return Err(format!("unsupported Content-Encoding: {encoding}"));
    };

    Ok(Bytes::from(decompressed))
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
///
/// Uses the `subtle` crate (`ConstantTimeEq`) — the Rust cryptographic community
/// standard for constant-time operations. Pads both slices to the same length
/// to avoid leaking length information through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let max_len = a.len().max(b.len());
    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);
    let bytes_equal: bool = a_padded.ct_eq(&b_padded).into();
    let len_equal: bool = (a.len() as u64).ct_eq(&(b.len() as u64)).into();
    bytes_equal & len_equal
}

/// Build a structured JSON error response.
fn error_response(status: StatusCode, error: &ArbiterError) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": error });
    let payload = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(payload)))
        .expect("static response")
}

// ── Denial helper ────────────────────────────────────────────────────

/// Records a denial in audit + metrics and builds the HTTP response.
///
/// Every denial path in the handler was repeating the same 7 lines.
/// This helper captures the pattern once. Takes `capture` by value
/// since denial paths always return immediately. Injects the request ID
/// into the error response for audit log correlation.
async fn deny(
    state: &ArbiterState,
    mut capture: AuditCapture,
    request_id: ::uuid::Uuid,
    request_start: Instant,
    status: StatusCode,
    policy_matched: Option<&str>,
    mut error: ArbiterError,
) -> Response<Full<Bytes>> {
    capture.set_authorization_decision("deny");
    if let Some(pm) = policy_matched {
        capture.set_policy_matched(pm);
    }
    error.request_id = Some(request_id.to_string());
    state.metrics.record_request("deny");
    state
        .metrics
        .observe_request_duration(request_start.elapsed().as_secs_f64());

    let entry = capture.finalize(Some(status.as_u16()));
    write_audit(state, &entry).await;
    error_response(status, &error)
}

// Stage functions are in the `stages` module.
pub use crate::stages::StageVerdict;
pub use crate::stages::anomaly_detection::detect_behavioral_anomalies;
pub use crate::stages::policy_evaluation::{
    build_eval_context, build_eval_context_from_header, evaluate_mcp_policies,
};
pub use crate::stages::session_enforcement::validate_session_tools;

/// Write an audit entry to the sink.
async fn write_audit(state: &ArbiterState, entry: &arbiter_audit::AuditEntry) {
    if let Some(sink) = &state.audit_sink
        && let Err(e) = sink.write(entry).await
    {
        tracing::error!(error = %e, "failed to write audit entry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RT-201: constant_time_eq ──────────────────────────────────────

    #[test]
    fn constant_time_eq_equal_strings() {
        assert!(constant_time_eq(b"test-key", b"test-key"));
    }

    #[test]
    fn constant_time_eq_different_strings() {
        assert!(!constant_time_eq(b"test-key", b"wrong-key"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"much-longer-key"));
    }

    #[test]
    fn constant_time_eq_empty_strings() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_one_empty() {
        assert!(!constant_time_eq(b"", b"notempty"));
        assert!(!constant_time_eq(b"notempty", b""));
    }

    // ── RT-203: decompress_body ───────────────────────────────────────

    #[test]
    fn decompress_identity_passthrough() {
        let body = Bytes::from("hello world");
        let result = decompress_body(&body, "identity", 1024).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn decompress_empty_encoding_passthrough() {
        let body = Bytes::from("raw data");
        let result = decompress_body(&body, "", 1024).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn decompress_gzip_valid() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"the quick brown fox jumps over the lazy dog";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_body(&Bytes::from(compressed), "gzip", 1024).unwrap();
        assert_eq!(result.as_ref(), original);
    }

    #[test]
    fn decompress_deflate_valid() {
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"deflate test payload";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_body(&Bytes::from(compressed), "deflate", 1024).unwrap();
        assert_eq!(result.as_ref(), original);
    }

    #[test]
    fn decompress_unsupported_encoding_rejected() {
        let body = Bytes::from("data");
        let result = decompress_body(&body, "br", 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported"));
    }

    #[test]
    fn decompress_gzip_bomb_rejected() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        // Create a payload that compresses well: 100KB of zeros.
        // Set max_bytes to 1024 — decompression should fail when output exceeds limit.
        let original = vec![0u8; 100_000];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        // The compressed payload is small, but decompresses to 100KB.
        assert!(compressed.len() < 1000, "compressed should be small");

        let result = decompress_body(&Bytes::from(compressed), "gzip", 1024);
        assert!(
            result.is_err(),
            "should reject decompression exceeding limit"
        );
        assert!(
            result.unwrap_err().contains("compression bomb"),
            "error message should mention compression bomb"
        );
    }

    #[test]
    fn decompress_within_limit_succeeds() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = vec![0u8; 500];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        // max_bytes = 1024, original is 500 bytes — should succeed.
        let result = decompress_body(&Bytes::from(compressed), "gzip", 1024).unwrap();
        assert_eq!(result.len(), 500);
    }

    #[test]
    fn decompress_exact_limit_succeeds() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = vec![42u8; 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Exactly at the limit should succeed.
        let result = decompress_body(&Bytes::from(compressed), "gzip", 1024).unwrap();
        assert_eq!(result.len(), 1024);
    }
}
