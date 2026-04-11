//! Stage 7: Validate all MCP tool calls against the session.

use arbiter_session::AnySessionStore;
use hyper::StatusCode;

use super::StageVerdict;
use crate::handler::ArbiterError;

/// Validate each MCP request's tool against the session whitelist and budgets.
///
/// Uses atomic batch validation so that budget is only consumed
/// when ALL tools in the batch pass validation. Prevents partial budget
/// consumption on batch failures and eliminates interleaving from concurrent
/// requests.
pub async fn validate_session_tools(
    store: &AnySessionStore,
    session_id: uuid::Uuid,
    requesting_agent_id: Option<uuid::Uuid>,
    requests: &[arbiter_mcp::context::McpRequest],
) -> StageVerdict {
    let tool_names: Vec<&str> = requests
        .iter()
        .map(|req| req.tool_name.as_deref().unwrap_or(&req.method))
        .collect();

    match store.use_session_batch(session_id, &tool_names, requesting_agent_id).await {
        Ok(_) => {
            tracing::debug!(
                %session_id,
                batch_size = tool_names.len(),
                "session batch validated"
            );
            StageVerdict::Continue
        }
        Err(e) => {
            let status_code = arbiter_session::status_code_for_error(&e);
            tracing::warn!(
                %session_id, error = %e, status = status_code,
                "session validation failed"
            );
            StageVerdict::Deny {
                status: StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN),
                policy_matched: Some(format!("session-whitelist: {e}")),
                error: ArbiterError::session_error(&e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbiter_session::SessionStore;

    fn mcp_tool_call(tool: &str) -> arbiter_mcp::context::McpRequest {
        arbiter_mcp::context::McpRequest {
            id: None,
            method: "tools/call".into(),
            tool_name: Some(tool.into()),
            arguments: None,
            resource_uri: None,
        }
    }

    #[tokio::test]
    async fn allows_authorized() {
        let inner = SessionStore::new();
        let session = inner
            .create(arbiter_session::CreateSessionRequest {
                agent_id: uuid::Uuid::new_v4(),
                delegation_chain_snapshot: vec![],
                declared_intent: "read files".into(),
                authorized_tools: vec!["read_file".into()],
            authorized_credentials: vec![],
                time_limit: chrono::Duration::hours(1),
                call_budget: 100,
                rate_limit_per_minute: None,
                rate_limit_window_secs: 60,
                data_sensitivity_ceiling: arbiter_session::DataSensitivity::Internal,
            })
            .await;

        let store = AnySessionStore::InMemory(inner);
        let requests = vec![mcp_tool_call("read_file")];
        let verdict = validate_session_tools(&store, session.session_id, None, &requests).await;
        assert!(matches!(verdict, StageVerdict::Continue));
    }

    #[tokio::test]
    async fn denies_unauthorized() {
        let inner = SessionStore::new();
        let session = inner
            .create(arbiter_session::CreateSessionRequest {
                agent_id: uuid::Uuid::new_v4(),
                delegation_chain_snapshot: vec![],
                declared_intent: "read files".into(),
                authorized_tools: vec!["read_file".into()],
            authorized_credentials: vec![],
                time_limit: chrono::Duration::hours(1),
                call_budget: 100,
                rate_limit_per_minute: None,
                rate_limit_window_secs: 60,
                data_sensitivity_ceiling: arbiter_session::DataSensitivity::Internal,
            })
            .await;

        let store = AnySessionStore::InMemory(inner);
        let requests = vec![mcp_tool_call("delete_file")];
        let verdict = validate_session_tools(&store, session.session_id, None, &requests).await;
        assert!(matches!(verdict, StageVerdict::Deny { .. }));
    }
}
