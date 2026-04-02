//! Stage 8: Policy evaluation against the authorization engine.

use arbiter_identity::{AgentRegistry, AnyRegistry};
use arbiter_policy::{Decision, EvalContext, PolicyConfig};
use hyper::StatusCode;

use super::StageVerdict;
use crate::handler::ArbiterError;

/// Build the policy evaluation context from session + registry.
pub async fn build_eval_context(
    registry: &AnyRegistry,
    session: &arbiter_session::TaskSession,
    delegation_chain: &str,
) -> EvalContext {
    let principal = delegation_chain.split('>').next().unwrap_or("").to_string();
    // Fallback to Untrusted (not Basic) when agent is not found in registry.
    // A missing agent should never be implicitly trusted — deny-by-default
    // semantics require the lowest trust level for unknown identities.
    // (RT-003 F-08: non-existent agent gets Basic trust in policy eval)
    let agent = registry
        .get_agent(session.agent_id)
        .await
        .unwrap_or_else(|_| arbiter_identity::Agent {
            id: session.agent_id,
            owner: principal.clone(),
            model: String::new(),
            capabilities: vec![],
            trust_level: arbiter_identity::TrustLevel::Untrusted,
            created_at: chrono::Utc::now(),
            expires_at: None,
            active: true,
        });
    EvalContext {
        agent,
        delegation_chain: vec![],
        declared_intent: session.declared_intent.clone(),
        principal_sub: principal,
        principal_groups: vec![],
    }
}

/// Build an EvalContext from the x-agent-id header
/// when no session is available. This allows policy evaluation to run even
/// when `require_session = false`, preventing the complete authorization bypass
/// that occurred when MCP traffic had no session header.
pub async fn build_eval_context_from_header(
    registry: &AnyRegistry,
    agent_id_header: &str,
    delegation_chain: &str,
) -> Option<EvalContext> {
    let agent_uuid = agent_id_header.parse::<uuid::Uuid>().ok()?;
    let principal = delegation_chain.split('>').next().unwrap_or("").to_string();
    let agent = registry
        .get_agent(agent_uuid)
        .await
        .unwrap_or_else(|_| arbiter_identity::Agent {
            id: agent_uuid,
            owner: principal.clone(),
            model: String::new(),
            capabilities: vec![],
            trust_level: arbiter_identity::TrustLevel::Untrusted,
            created_at: chrono::Utc::now(),
            expires_at: None,
            active: true,
        });
    Some(EvalContext {
        agent,
        delegation_chain: vec![],
        declared_intent: String::new(),
        principal_sub: principal,
        principal_groups: vec![],
    })
}

/// Evaluate MCP requests against the policy engine.
/// Returns verdict + optional policy_matched for audit.
pub fn evaluate_mcp_policies(
    policy_config: &PolicyConfig,
    eval_ctx: &EvalContext,
    requests: &[arbiter_mcp::context::McpRequest],
) -> (StageVerdict, Option<String>) {
    let mut last_policy_id = None;
    for mcp_req in requests {
        let result = arbiter_policy::evaluate_explained(policy_config, eval_ctx, mcp_req);
        match result.decision {
            Decision::Allow { policy_id } => {
                tracing::debug!(%policy_id, "policy allowed");
                last_policy_id = Some(policy_id);
            }
            Decision::Deny { reason } => {
                tracing::warn!(%reason, "policy denied");
                return (
                    StageVerdict::Deny {
                        status: StatusCode::FORBIDDEN,
                        policy_matched: Some(reason.clone()),
                        error: ArbiterError::policy_denied_with_trace(&reason, result.trace),
                    },
                    None,
                );
            }
            Decision::Escalate { reason } => {
                tracing::warn!(%reason, "policy escalation required");
                return (
                    StageVerdict::Deny {
                        status: StatusCode::FORBIDDEN,
                        policy_matched: Some(format!("escalate: {reason}")),
                        error: ArbiterError::escalation_required(&reason),
                    },
                    None,
                );
            }
            Decision::Annotate { policy_id, reason } => {
                tracing::info!(%policy_id, %reason, "policy annotated (forwarding)");
                last_policy_id = Some(policy_id);
            }
        }
    }
    (StageVerdict::Continue, last_policy_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mcp_tool_call(tool: &str) -> arbiter_mcp::context::McpRequest {
        arbiter_mcp::context::McpRequest {
            id: None,
            method: "tools/call".into(),
            tool_name: Some(tool.into()),
            arguments: None,
            resource_uri: None,
        }
    }

    #[test]
    fn deny_by_default() {
        let config = PolicyConfig::from_toml("").unwrap();
        let eval_ctx = EvalContext {
            agent: arbiter_identity::Agent {
                id: uuid::Uuid::new_v4(),
                owner: "user:test".into(),
                model: "test".into(),
                capabilities: vec![],
                trust_level: arbiter_identity::TrustLevel::Basic,
                created_at: chrono::Utc::now(),
                expires_at: None,
                active: true,
            },
            delegation_chain: vec![],
            declared_intent: "read files".into(),
            principal_sub: "user:test".into(),
            principal_groups: vec![],
        };
        let requests = vec![mcp_tool_call("read_file")];
        let (verdict, _) = evaluate_mcp_policies(&config, &eval_ctx, &requests);
        assert!(matches!(verdict, StageVerdict::Deny { .. }));
    }

    #[test]
    fn allows_matching() {
        let config = PolicyConfig::from_toml(
            r#"
[[policies]]
id = "allow-read"
effect = "allow"
allowed_tools = ["read_file"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
"#,
        )
        .unwrap();
        let eval_ctx = EvalContext {
            agent: arbiter_identity::Agent {
                id: uuid::Uuid::new_v4(),
                owner: "user:test".into(),
                model: "test".into(),
                capabilities: vec![],
                trust_level: arbiter_identity::TrustLevel::Basic,
                created_at: chrono::Utc::now(),
                expires_at: None,
                active: true,
            },
            delegation_chain: vec![],
            declared_intent: "read configuration".into(),
            principal_sub: "user:test".into(),
            principal_groups: vec![],
        };
        let requests = vec![mcp_tool_call("read_file")];
        let (verdict, policy_id) = evaluate_mcp_policies(&config, &eval_ctx, &requests);
        assert!(matches!(verdict, StageVerdict::Continue));
        assert_eq!(policy_id.as_deref(), Some("allow-read"));
    }

    /// RT-003 F-08: build_eval_context falls back to Untrusted (not Basic) for unknown agents.
    #[tokio::test]
    async fn build_eval_context_falls_back_to_untrusted_for_unknown_agent() {
        let registry = AnyRegistry::InMemory(arbiter_identity::InMemoryRegistry::new());
        let unknown_agent_id = uuid::Uuid::new_v4();
        let session = arbiter_session::TaskSession {
            session_id: uuid::Uuid::new_v4(),
            agent_id: unknown_agent_id,
            delegation_chain_snapshot: vec![],
            declared_intent: "read files".into(),
            authorized_tools: vec![],
            time_limit: chrono::Duration::hours(1),
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: None,
            rate_window_start: chrono::Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: arbiter_session::DataSensitivity::Internal,
            created_at: chrono::Utc::now(),
            status: arbiter_session::model::SessionStatus::Active,
        };

        let ctx = build_eval_context(&registry, &session, "user:unknown").await;
        assert_eq!(
            ctx.agent.trust_level,
            arbiter_identity::TrustLevel::Untrusted,
            "unknown agent should fall back to Untrusted, not Basic"
        );
    }

    #[tokio::test]
    async fn build_eval_context_uses_delegation_chain() {
        let inner = arbiter_identity::InMemoryRegistry::new();
        let agent = inner
            .register_agent(
                "user:alice".into(),
                "test-model".into(),
                vec![],
                arbiter_identity::TrustLevel::Basic,
                None,
            )
            .await
            .unwrap();
        let registry = AnyRegistry::InMemory(inner);
        let session = arbiter_session::TaskSession {
            session_id: uuid::Uuid::new_v4(),
            agent_id: agent.id,
            delegation_chain_snapshot: vec![],
            declared_intent: "read logs".into(),
            authorized_tools: vec![],
            time_limit: chrono::Duration::hours(1),
            call_budget: 100,
            calls_made: 0,
            rate_limit_per_minute: None,
            rate_window_start: chrono::Utc::now(),
            rate_window_calls: 0,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: arbiter_session::DataSensitivity::Internal,
            created_at: chrono::Utc::now(),
            status: arbiter_session::model::SessionStatus::Active,
        };

        let ctx = build_eval_context(&registry, &session, "user:alice>agent:bot").await;
        assert_eq!(ctx.principal_sub, "user:alice");
        assert_eq!(ctx.declared_intent, "read logs");
        assert_eq!(ctx.agent.owner, "user:alice");
    }
}
