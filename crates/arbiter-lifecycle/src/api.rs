use std::sync::Arc;

use arbiter_identity::{AgentRegistry, TrustLevel};
use arbiter_mcp::context::McpRequest;
use arbiter_policy::{EvalContext, PolicyTrace};
use arbiter_session::{CreateSessionRequest, DataSensitivity};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;
use crate::token::issue_token;

/// Request body for POST /agents.
#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub owner: String,
    pub model: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default = "default_trust_level")]
    pub trust_level: TrustLevel,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_trust_level() -> TrustLevel {
    TrustLevel::Untrusted
}

/// Response body for POST /agents.
#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: Uuid,
    pub token: String,
}

/// Request body for POST /agents/:id/delegate.
#[derive(Debug, Deserialize)]
pub struct DelegateRequest {
    pub to: Uuid,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request body for POST /agents/:id/token.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    #[serde(default)]
    pub expiry_seconds: Option<i64>,
}

/// Request body for POST /sessions.
#[derive(Debug, Deserialize)]
pub struct CreateSessionApiRequest {
    pub agent_id: Uuid,
    #[serde(default)]
    pub delegation_chain_snapshot: Vec<String>,
    pub declared_intent: String,
    #[serde(default)]
    pub authorized_tools: Vec<String>,
    #[serde(default = "default_time_limit")]
    pub time_limit_secs: i64,
    #[serde(default = "default_call_budget")]
    pub call_budget: u64,
    #[serde(default)]
    pub rate_limit_per_minute: Option<u64>,
    /// Override the global rate-limit window duration for this session (seconds).
    /// If omitted, uses the server default from `[sessions].rate_limit_window_secs`.
    #[serde(default)]
    pub rate_limit_window_secs: Option<u64>,
    #[serde(default = "default_data_sensitivity")]
    pub data_sensitivity_ceiling: DataSensitivity,
}

fn default_time_limit() -> i64 {
    3600
}

fn default_call_budget() -> u64 {
    1000
}

fn default_data_sensitivity() -> DataSensitivity {
    DataSensitivity::Internal
}

/// Response body for POST /sessions.
#[derive(Debug, Serialize)]
pub struct CreateSessionResponse {
    pub session_id: Uuid,
    pub declared_intent: String,
    pub authorized_tools: Vec<String>,
    pub call_budget: u64,
    pub time_limit_secs: i64,
}

/// Response body for GET /sessions/:id.
#[derive(Debug, Serialize)]
pub struct SessionStatusResponse {
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub status: String,
    pub declared_intent: String,
    pub authorized_tools: Vec<String>,
    pub calls_made: u64,
    pub call_budget: u64,
    pub calls_remaining: u64,
    pub rate_limit_per_minute: Option<u64>,
    pub data_sensitivity_ceiling: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub seconds_remaining: i64,
    pub warnings: Vec<String>,
}

/// Response for token issuance.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: i64,
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Constant-time byte comparison to prevent timing side-channel attacks
/// on the admin API key (P0 credential fix).
///
/// Uses the `subtle` crate (`ConstantTimeEq`) instead
/// of a hand-rolled implementation with fragile `black_box`/`#[inline(never)]`
/// barriers. The `subtle` crate is the Rust cryptographic community standard
/// and is designed to resist compiler optimizations that break constant-time
/// guarantees. Pads both inputs to equal length and checks lengths separately
/// to avoid leaking length information through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    // Pad both slices to the same length so ct_eq can compare equal-length
    // slices, then separately check that the original lengths match.
    // This avoids leaking length information through timing.
    let max_len = std::cmp::max(a.len(), b.len());
    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);
    let bytes_equal: bool = a_padded.ct_eq(&b_padded).into();
    let len_equal: bool = (a.len() as u64).ct_eq(&(b.len() as u64)).into();
    bytes_equal & len_equal
}

/// Sanitize user-provided strings for safe inclusion in log messages.
/// Replaces control characters (newlines, carriage returns, tabs) with
/// their escaped representations to prevent log injection attacks.
/// (RT-003 F-04: log injection via user input)
fn sanitize_for_log(input: &str) -> String {
    input
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Validate the admin API key from headers.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
fn validate_admin_key(
    headers: &HeaderMap,
    expected: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing x-api-key header".into(),
                }),
            )
        })?;

    // P0 credential fix: constant-time comparison to prevent timing attacks.
    if !constant_time_eq(key.as_bytes(), expected.as_bytes()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "invalid API key".into(),
            }),
        ));
    }

    Ok(())
}

/// Check the admin API rate limiter and return 429 if the limit is exceeded.
///
/// Rate limiting prevents an attacker with a compromised API key
/// from making unlimited requests to enumerate agents, create sessions, or
/// overwhelm the control plane.
fn check_admin_rate_limit(state: &AppState) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !state.admin_rate_limiter.check_rate_limit() {
        tracing::warn!("ADMIN_AUDIT: rate limit exceeded on admin API");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "admin API rate limit exceeded, try again later".into(),
            }),
        ));
    }
    Ok(())
}

/// POST /agents: register a new agent.
pub async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    match state
        .registry
        .register_agent(
            req.owner.clone(),
            req.model,
            req.capabilities,
            req.trust_level,
            req.expires_at,
        )
        .await
    {
        Ok(agent) => {
            let token = match issue_token(agent.id, &req.owner, &state.token_config) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = %e, "failed to issue token");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "token issuance failed".into(),
                        }),
                    )
                        .into_response();
                }
            };

            state.metrics.registered_agents.inc();
            state.admin_audit_log(
                "register_agent",
                Some(agent.id),
                &format!("owner={}", sanitize_for_log(&req.owner)),
            );

            (
                StatusCode::CREATED,
                Json(RegisterAgentResponse {
                    agent_id: agent.id,
                    token,
                }),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to register agent");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// GET /agents/:id: get agent details.
pub async fn get_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("get_agent", Some(id), "");

    match state.registry.get_agent(id).await {
        Ok(agent) => match serde_json::to_value(&agent) {
            Ok(val) => (StatusCode::OK, Json(val)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// POST /agents/:id/delegate: create delegation to sub-agent.
pub async fn delegate_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(from_id): Path<Uuid>,
    Json(req): Json<DelegateRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("delegate_agent", Some(from_id), &format!("to={}", req.to));

    match state
        .registry
        .create_delegation(from_id, req.to, req.scopes, req.expires_at)
        .await
    {
        Ok(link) => match serde_json::to_value(&link) {
            Ok(val) => (StatusCode::CREATED, Json(val)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        },
        Err(e) => {
            let status = match &e {
                arbiter_identity::IdentityError::DelegationSourceNotFound(_)
                | arbiter_identity::IdentityError::DelegationTargetNotFound(_) => {
                    StatusCode::NOT_FOUND
                }
                arbiter_identity::IdentityError::ScopeNarrowingViolation { .. }
                | arbiter_identity::IdentityError::DelegateFromDeactivated(_)
                | arbiter_identity::IdentityError::CircularDelegation { .. } => {
                    StatusCode::BAD_REQUEST
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// GET /agents/:id/delegations: list incoming and outgoing delegations.
pub async fn list_delegations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("list_delegations", Some(id), "");

    // Verify agent exists.
    if let Err(e) = state.registry.get_agent(id).await {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    let outgoing = state.registry.list_delegations_from(id).await;
    let incoming = state.registry.list_delegations_to(id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "agent_id": id,
            "outgoing": outgoing,
            "incoming": incoming,
            "outgoing_count": outgoing.len(),
            "incoming_count": incoming.len(),
        })),
    )
        .into_response()
}

/// DELETE /agents/:id: deactivate agent + cascade.
pub async fn deactivate_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("deactivate_agent", Some(id), "cascade");

    match state.registry.cascade_deactivate(id).await {
        Ok(deactivated) => {
            // Close sessions for all deactivated agents.
            let mut total_sessions_closed = 0usize;
            for &agent_id in &deactivated {
                let closed = state.session_store.close_sessions_for_agent(agent_id).await;
                total_sessions_closed += closed;
                state.metrics.registered_agents.dec();
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "deactivated": deactivated,
                    "count": deactivated.len(),
                    "sessions_closed": total_sessions_closed,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let status = match &e {
                arbiter_identity::IdentityError::AgentNotFound(_) => StatusCode::NOT_FOUND,
                arbiter_identity::IdentityError::AgentDeactivated(_) => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// POST /agents/:id/token: issue new short-lived credential.
pub async fn issue_agent_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Option<Json<TokenRequest>>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("issue_agent_token", Some(id), "");

    let agent = match state.registry.get_agent(id).await {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    if !agent.active {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("agent {} is deactivated", id),
            }),
        )
            .into_response();
    }

    let mut config = state.token_config.clone();
    if let Some(Json(req)) = body {
        if let Some(expiry) = req.expiry_seconds {
            // P4: Reject non-positive expiry to prevent creating immediately-invalid tokens.
            // (RT-003 F-09: token expiry accepts negative values)
            if expiry <= 0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "expiry_seconds must be positive".into(),
                    }),
                )
                    .into_response();
            }
            config.expiry_seconds = expiry;
        }
    }

    match issue_token(agent.id, &agent.owner, &config) {
        Ok(token) => (
            StatusCode::OK,
            Json(TokenResponse {
                token,
                expires_in: config.expiry_seconds,
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to issue token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "token issuance failed".into(),
                }),
            )
                .into_response()
        }
    }
}

/// GET /agents: list all agents.
pub async fn list_agents(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("list_agents", None, "");

    let agents = state.registry.list_agents().await;
    match serde_json::to_value(&agents) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// POST /sessions: create a new task session.
pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionApiRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log(
        "create_session",
        Some(req.agent_id),
        &format!("intent={}", sanitize_for_log(&req.declared_intent)),
    );

    // P0: Validate agent exists, is active, and not expired before creating session.
    // Without this check, sessions can be created for non-existent or deactivated agents,
    // bypassing the entire identity model (RT-003 F-01: ghost agent sessions).
    let agent = match state.registry.get_agent(req.agent_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                agent_id = %req.agent_id,
                error = %e,
                "session creation denied: agent not found"
            );
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("agent {} not found", req.agent_id),
                }),
            )
                .into_response();
        }
    };

    if !agent.active {
        tracing::warn!(
            agent_id = %req.agent_id,
            "session creation denied: agent is deactivated"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("agent {} is deactivated", req.agent_id),
            }),
        )
            .into_response();
    }

    if let Some(expires_at) = agent.expires_at {
        if expires_at < Utc::now() {
            tracing::warn!(
                agent_id = %req.agent_id,
                expires_at = %expires_at,
                "session creation denied: agent has expired"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("agent {} has expired", req.agent_id),
                }),
            )
                .into_response();
        }
    }

    // P0: Per-agent session cap to prevent session multiplication attacks.
    // An agent creating N sessions * M budget each = N*M tool calls,
    // bypassing per-session rate limits.
    if let Some(max_sessions) = state.max_concurrent_sessions_per_agent {
        let active_count = state
            .session_store
            .count_active_for_agent(req.agent_id)
            .await;
        if active_count >= max_sessions {
            tracing::warn!(
                agent_id = %req.agent_id,
                active = active_count,
                max = max_sessions,
                "session creation denied: per-agent concurrent session cap reached"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!(
                        "agent {} has too many concurrent sessions ({}/{})",
                        req.agent_id, active_count, max_sessions
                    ),
                }),
            )
                .into_response();
        }
    }

    // Validate session creation parameters.
    if req.time_limit_secs <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "time_limit_secs must be positive".into(),
            }),
        )
            .into_response();
    }
    // Validate session creation parameters.
    if req.time_limit_secs > 86400 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "time_limit_secs cannot exceed 86400 (24 hours)".into(),
            }),
        )
            .into_response();
    }
    if req.call_budget == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "call_budget must be positive".into(),
            }),
        )
            .into_response();
    }
    if req.call_budget > 1_000_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "call_budget cannot exceed 1000000".into(),
            }),
        )
            .into_response();
    }
    if req.declared_intent.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "declared_intent must not be empty".into(),
            }),
        )
            .into_response();
    }

    // P1: Validate rate_limit_window_secs bounds to prevent rate limit bypass.
    // A window of 0 disables rate limiting entirely; a window of 1 second converts
    // "per minute" limits into "per second" (100x amplification).
    // (RT-003 F-03: rate limit window manipulation)
    if let Some(window) = req.rate_limit_window_secs {
        if window == 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "rate_limit_window_secs must be positive".into(),
                }),
            )
                .into_response();
        }
        if window < 10 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "rate_limit_window_secs must be at least 10 seconds".into(),
                }),
            )
                .into_response();
        }
        if window > 3600 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "rate_limit_window_secs cannot exceed 3600 (1 hour)".into(),
                }),
            )
                .into_response();
        }
    }

    let create_req = CreateSessionRequest {
        agent_id: req.agent_id,
        delegation_chain_snapshot: req.delegation_chain_snapshot,
        declared_intent: req.declared_intent,
        authorized_tools: req.authorized_tools,
        time_limit: chrono::Duration::seconds(req.time_limit_secs),
        call_budget: req.call_budget,
        rate_limit_per_minute: req.rate_limit_per_minute,
        rate_limit_window_secs: req
            .rate_limit_window_secs
            .unwrap_or(state.default_rate_limit_window_secs),
        data_sensitivity_ceiling: req.data_sensitivity_ceiling,
    };

    let session = state.session_store.create(create_req).await;

    state.metrics.active_sessions.inc();

    (
        StatusCode::CREATED,
        Json(CreateSessionResponse {
            session_id: session.session_id,
            declared_intent: session.declared_intent,
            authorized_tools: session.authorized_tools,
            call_budget: session.call_budget,
            time_limit_secs: req.time_limit_secs,
        }),
    )
        .into_response()
}

/// GET /sessions/:id: get live session status.
pub async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("get_session", None, &format!("session_id={}", id));

    let session = match state.session_store.get(id).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let now = Utc::now();
    let expires_at = session.created_at + session.time_limit;
    let seconds_remaining = (expires_at - now).num_seconds().max(0);
    let calls_remaining = session.call_budget.saturating_sub(session.calls_made);

    let mut warnings = Vec::new();
    let budget_pct_remaining = if session.call_budget > 0 {
        (calls_remaining as f64 / session.call_budget as f64) * 100.0
    } else {
        0.0
    };
    let time_pct_remaining = if session.time_limit.num_seconds() > 0 {
        (seconds_remaining as f64 / session.time_limit.num_seconds() as f64) * 100.0
    } else {
        0.0
    };
    if budget_pct_remaining <= state.warning_threshold_pct && session.call_budget > 0 {
        warnings.push(format!(
            "budget low: {} of {} calls remaining",
            calls_remaining, session.call_budget
        ));
    }
    if time_pct_remaining <= state.warning_threshold_pct && seconds_remaining > 0 {
        warnings.push(format!("time low: {}s remaining", seconds_remaining));
    }

    let status_str = format!("{:?}", session.status).to_lowercase();
    let sensitivity_str = serde_json::to_value(session.data_sensitivity_ceiling)
        .unwrap_or_default()
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    (
        StatusCode::OK,
        Json(SessionStatusResponse {
            session_id: session.session_id,
            agent_id: session.agent_id,
            status: status_str,
            declared_intent: session.declared_intent,
            authorized_tools: session.authorized_tools,
            calls_made: session.calls_made,
            call_budget: session.call_budget,
            calls_remaining,
            rate_limit_per_minute: session.rate_limit_per_minute,
            data_sensitivity_ceiling: sensitivity_str,
            created_at: session.created_at,
            expires_at,
            seconds_remaining,
            warnings,
        }),
    )
        .into_response()
}

/// Response body for POST /sessions/:id/close.
#[derive(Debug, Serialize)]
pub struct SessionCloseResponse {
    pub session_id: Uuid,
    pub status: String,
    pub declared_intent: String,
    pub total_calls: u64,
    pub call_budget: u64,
    pub budget_utilization_pct: f64,
    pub time_used_secs: i64,
    pub time_limit_secs: i64,
    /// Number of denied requests during this session (from audit log).
    pub denied_attempts: u64,
    /// Number of requests that triggered anomaly flags (from audit log).
    pub anomalies_detected: u64,
}

/// POST /sessions/:id/close: close a session and return summary.
pub async fn close_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("close_session", None, &format!("session_id={}", id));

    let session = match state.session_store.close(id).await {
        Ok(s) => {
            state.metrics.active_sessions.dec();
            s
        }
        Err(e) => {
            let status = match &e {
                arbiter_session::SessionError::NotFound(_) => StatusCode::NOT_FOUND,
                arbiter_session::SessionError::AlreadyClosed(_) => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    let now = Utc::now();
    let time_used_secs = (now - session.created_at).num_seconds();
    let budget_utilization_pct = if session.call_budget > 0 {
        (session.calls_made as f64 / session.call_budget as f64) * 100.0
    } else {
        0.0
    };

    // Query audit stats for this session.
    let session_id_str = id.to_string();
    let (denied_attempts, anomalies_detected) = if let Some(ref sink) = state.audit_sink {
        let stats = sink.stats().stats_for_session(&session_id_str).await;
        // Clean up stats now that session is closed.
        sink.stats().remove_session(&session_id_str).await;
        (stats.denied_count, stats.anomaly_count)
    } else {
        (0, 0)
    };

    (
        StatusCode::OK,
        Json(SessionCloseResponse {
            session_id: session.session_id,
            status: "closed".into(),
            declared_intent: session.declared_intent,
            total_calls: session.calls_made,
            call_budget: session.call_budget,
            budget_utilization_pct,
            time_used_secs,
            time_limit_secs: session.time_limit.num_seconds(),
            denied_attempts,
            anomalies_detected,
        }),
    )
        .into_response()
}

/// Request body for POST /policy/explain.
#[derive(Debug, Deserialize)]
pub struct PolicyExplainRequest {
    pub agent_id: Uuid,
    pub declared_intent: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    #[serde(default)]
    pub principal: Option<String>,
}

/// Response body for POST /policy/explain.
#[derive(Debug, Serialize)]
pub struct PolicyExplainResponse {
    pub decision: String,
    pub matched_policy: Option<String>,
    pub reason: Option<String>,
    pub trace: Vec<PolicyTrace>,
}

/// POST /policy/explain: dry-run policy evaluation without executing.
pub async fn explain_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PolicyExplainRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log(
        "explain_policy",
        Some(req.agent_id),
        &format!("tool={}", sanitize_for_log(&req.tool)),
    );

    let policy_snapshot = tokio::sync::watch::Sender::borrow(&state.policy_config).clone();
    let policy_config = match policy_snapshot.as_ref() {
        Some(pc) => pc,
        None => {
            return (
                StatusCode::OK,
                Json(PolicyExplainResponse {
                    decision: "allow".into(),
                    matched_policy: None,
                    reason: Some("no policies configured".into()),
                    trace: vec![],
                }),
            )
                .into_response();
        }
    };

    let agent = match state.registry.get_agent(req.agent_id).await {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("agent not found: {e}"),
                }),
            )
                .into_response();
        }
    };

    let principal = req.principal.unwrap_or_else(|| agent.owner.clone());

    let eval_ctx = EvalContext {
        agent,
        delegation_chain: vec![],
        declared_intent: req.declared_intent,
        principal_sub: principal,
        principal_groups: vec![],
    };

    let mcp_req = McpRequest {
        id: None,
        method: "tools/call".into(),
        tool_name: Some(req.tool.clone()),
        arguments: req.arguments,
        resource_uri: None,
    };

    let result = arbiter_policy::evaluate_explained(policy_config, &eval_ctx, &mcp_req);

    let (decision, matched_policy, reason) = match result.decision {
        arbiter_policy::Decision::Allow { policy_id } => ("allow".into(), Some(policy_id), None),
        arbiter_policy::Decision::Deny { reason } => ("deny".into(), None, Some(reason)),
        arbiter_policy::Decision::Escalate { reason } => ("escalate".into(), None, Some(reason)),
        arbiter_policy::Decision::Annotate { policy_id, reason } => {
            ("annotate".into(), Some(policy_id), Some(reason))
        }
    };

    (
        StatusCode::OK,
        Json(PolicyExplainResponse {
            decision,
            matched_policy,
            reason,
            trace: result.trace,
        }),
    )
        .into_response()
}

/// Request body for POST /policy/validate.
#[derive(Debug, Deserialize)]
pub struct PolicyValidateRequest {
    pub policy_toml: String,
}

/// POST /policy/validate: validate a policy TOML string without loading it.
pub async fn validate_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PolicyValidateRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("validate_policy", None, "");

    let result = arbiter_policy::PolicyConfig::validate_toml(&req.policy_toml);
    (StatusCode::OK, Json(result)).into_response()
}

/// POST /policy/reload: re-read the policy file and atomically swap the config.
pub async fn reload_policy(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("reload_policy", None, "");

    let path = match &state.policy_file_path {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "no policy file configured; policies are inline or absent".into(),
                }),
            )
                .into_response();
        }
    };

    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            // Do not leak filesystem paths in error responses.
            tracing::error!(path = %path, error = %e, "failed to read policy file");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "failed to read policy file".into(),
                }),
            )
                .into_response();
        }
    };

    let new_config = match arbiter_policy::PolicyConfig::from_toml(&contents) {
        Ok(pc) => pc,
        Err(e) => {
            // Log parse errors internally, don't expose details.
            tracing::error!(error = %e, "failed to parse policy file");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "failed to parse policy file".into(),
                }),
            )
                .into_response();
        }
    };

    let policy_count = new_config.policies.len();
    let _ = state.policy_config.send_replace(Arc::new(Some(new_config)));

    // Audit log policy reload events for change tracking.
    tracing::warn!(
        path,
        policy_count,
        "AUDIT: policy configuration reloaded via admin API"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "reloaded": true,
            "policies_loaded": policy_count,
            "policy_count": policy_count,
            "file": path,
        })),
    )
        .into_response()
}

/// GET /policy/schema: returns the policy TOML schema as JSON Schema.
pub async fn policy_schema(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = validate_admin_key(&headers, &state.admin_api_key) {
        return e.into_response();
    }
    if let Err(e) = check_admin_rate_limit(&state) {
        return e.into_response();
    }

    state.admin_audit_log("policy_schema", None, "");

    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Arbiter Policy Configuration",
        "description": "Defines authorization policies for the Arbiter MCP gateway. Policies are evaluated top-to-bottom; the most specific match wins. If no policy matches, the request is denied (deny-by-default).",
        "type": "object",
        "properties": {
            "policies": {
                "type": "array",
                "description": "Ordered list of authorization policies. Evaluated by specificity score; the most specific matching policy's effect applies.",
                "items": {
                    "$ref": "#/$defs/Policy"
                }
            }
        },
        "$defs": {
            "Policy": {
                "type": "object",
                "description": "A single authorization policy rule.",
                "required": ["id", "effect"],
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Unique identifier for this policy. Used in audit logs and policy traces."
                    },
                    "effect": {
                        "$ref": "#/$defs/Effect"
                    },
                    "agent_match": {
                        "$ref": "#/$defs/AgentMatch"
                    },
                    "principal_match": {
                        "$ref": "#/$defs/PrincipalMatch"
                    },
                    "intent_match": {
                        "$ref": "#/$defs/IntentMatch"
                    },
                    "allowed_tools": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Tools this policy applies to. Empty array means 'all tools'."
                    },
                    "parameter_constraints": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/ParameterConstraint" },
                        "description": "Per-parameter bounds on tool arguments."
                    },
                    "priority": {
                        "type": "integer",
                        "default": 0,
                        "description": "Manual priority override. 0 = auto-computed from match specificity. Higher wins ties."
                    }
                }
            },
            "Effect": {
                "type": "string",
                "enum": ["allow", "deny", "escalate"],
                "description": "allow = permit the request. deny = block it. escalate = require human-in-the-loop approval."
            },
            "AgentMatch": {
                "type": "object",
                "description": "Criteria for matching the requesting agent. All specified fields must match.",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "Match a specific agent by UUID. Specificity: +100."
                    },
                    "trust_level": {
                        "$ref": "#/$defs/TrustLevel"
                    },
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Agent must have all listed capabilities. Specificity: +25 each."
                    }
                }
            },
            "TrustLevel": {
                "type": "string",
                "enum": ["untrusted", "basic", "verified", "trusted"],
                "description": "Agent trust tier. untrusted < basic < verified < trusted. Matches agents at or above the specified level. Specificity: +50."
            },
            "PrincipalMatch": {
                "type": "object",
                "description": "Criteria for matching the human principal on whose behalf the agent acts.",
                "properties": {
                    "sub": {
                        "type": "string",
                        "description": "Exact principal subject identifier (e.g., 'user:alice'). Specificity: +40."
                    },
                    "groups": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Principal must belong to at least one of these groups. Specificity: +20 each."
                    }
                }
            },
            "IntentMatch": {
                "type": "object",
                "description": "Criteria for matching the session's declared intent.",
                "properties": {
                    "keywords": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Case-insensitive substrings that must appear in the declared intent. Specificity: +10 each."
                    },
                    "regex": {
                        "type": "string",
                        "description": "Regex pattern the declared intent must match. Compiled at config load time. Specificity: +30."
                    }
                }
            },
            "ParameterConstraint": {
                "type": "object",
                "description": "A constraint on a tool call parameter.",
                "required": ["key"],
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Dotted path to the parameter (e.g., 'arguments.max_tokens')."
                    },
                    "max_value": {
                        "type": "number",
                        "description": "Maximum numeric value allowed."
                    },
                    "min_value": {
                        "type": "number",
                        "description": "Minimum numeric value allowed."
                    },
                    "allowed_values": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Whitelist of allowed string values."
                    }
                }
            },
            "DataSensitivity": {
                "type": "string",
                "enum": ["public", "internal", "confidential", "restricted"],
                "description": "Data sensitivity ceiling for sessions. public < internal < confidential < restricted."
            }
        }
    });

    (StatusCode::OK, Json(schema)).into_response()
}

/// Build the axum router for the lifecycle API.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/agents", axum::routing::post(register_agent))
        .route("/agents", axum::routing::get(list_agents))
        .route("/agents/{id}", axum::routing::get(get_agent))
        .route("/agents/{id}", axum::routing::delete(deactivate_agent))
        .route("/agents/{id}/delegate", axum::routing::post(delegate_agent))
        .route(
            "/agents/{id}/delegations",
            axum::routing::get(list_delegations),
        )
        .route("/agents/{id}/token", axum::routing::post(issue_agent_token))
        .route("/sessions", axum::routing::post(create_session))
        .route("/sessions/{id}", axum::routing::get(get_session))
        .route("/sessions/{id}/close", axum::routing::post(close_session))
        .route("/policy/explain", axum::routing::post(explain_policy))
        .route("/policy/validate", axum::routing::post(validate_policy))
        .route("/policy/reload", axum::routing::post(reload_policy))
        .route("/admin/policies/reload", axum::routing::post(reload_policy))
        .route("/policy/schema", axum::routing::get(policy_schema))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RT-003 F-04: sanitize_for_log replaces control characters.
    #[test]
    fn sanitize_for_log_strips_newlines() {
        assert_eq!(
            sanitize_for_log("read config\nINFO ADMIN_AUDIT: fake"),
            "read config\\nINFO ADMIN_AUDIT: fake"
        );
    }

    #[test]
    fn sanitize_for_log_strips_carriage_return() {
        assert_eq!(sanitize_for_log("line1\r\nline2"), "line1\\r\\nline2");
    }

    #[test]
    fn sanitize_for_log_strips_tabs() {
        assert_eq!(sanitize_for_log("key\tvalue"), "key\\tvalue");
    }

    #[test]
    fn sanitize_for_log_preserves_normal_text() {
        assert_eq!(sanitize_for_log("read configuration files"), "read configuration files");
    }
}
