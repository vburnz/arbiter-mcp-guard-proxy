use proptest::prelude::*;

use arbiter_identity::{Agent, TrustLevel};
use arbiter_mcp::context::McpRequest;
use arbiter_policy::model::{
    AgentMatch, Disposition, Effect, IntentMatch, ParameterConstraint, Policy, PrincipalMatch,
};
use arbiter_policy::{Decision, EvalContext, PolicyConfig, evaluate};
use chrono::Utc;
use uuid::Uuid;

/// Build a minimal EvalContext for testing.
fn make_context(intent: &str) -> EvalContext {
    EvalContext {
        agent: Agent {
            id: Uuid::new_v4(),
            owner: "user:test".into(),
            model: "test-model".into(),
            capabilities: vec![],
            trust_level: TrustLevel::Basic,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        },
        delegation_chain: vec![],
        declared_intent: intent.to_string(),
        principal_sub: "user:test".into(),
        principal_groups: vec![],
    }
}

/// Build a minimal McpRequest for a tools/call.
fn make_request(tool_name: &str, arguments: Option<serde_json::Value>) -> McpRequest {
    McpRequest {
        id: Some(serde_json::json!(1)),
        method: "tools/call".into(),
        tool_name: Some(tool_name.to_string()),
        arguments,
        resource_uri: None,
    }
}

/// Build a single allow-all policy (matches any agent, principal, intent, tool).
/// Uses the explicit `"*"` wildcard because Allow policies with an empty
/// allowed_tools AND empty resource_match are rejected at compile() time.
fn allow_all_policy() -> Policy {
    Policy {
        id: "allow-all".into(),
        agent_match: AgentMatch::default(),
        principal_match: PrincipalMatch::default(),
        intent_match: IntentMatch::default(),
        allowed_tools: vec!["*".into()],
        resource_match: vec![],
        parameter_constraints: vec![],
        effect: Effect::Allow,
        disposition: Disposition::Block,
        priority: 0,
    }
}

/// Strategy for tool name strings.
fn tool_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,31}"
}

/// Strategy for intent strings.
fn intent_strategy() -> impl Strategy<Value = String> {
    "[a-z ]{1,64}"
}

proptest! {
    /// evaluate() is deterministic: same (config, context, request) always produces
    /// the same Decision.
    #[test]
    fn evaluate_is_deterministic(
        tool_name in tool_name_strategy(),
        intent in intent_strategy(),
    ) {
        let mut config = PolicyConfig {
            policies: vec![allow_all_policy()],
        };
        config.compile().unwrap();

        let ctx = make_context(&intent);
        let request = make_request(&tool_name, None);

        let decision1 = evaluate(&config, &ctx, &request);
        let decision2 = evaluate(&config, &ctx, &request);

        prop_assert_eq!(decision1, decision2);
    }

    /// With no policies, every request is denied (deny-by-default).
    #[test]
    fn no_policies_denies_everything(
        tool_name in tool_name_strategy(),
        intent in intent_strategy(),
    ) {
        let config = PolicyConfig { policies: vec![] };
        let ctx = make_context(&intent);
        let request = make_request(&tool_name, None);

        let decision = evaluate(&config, &ctx, &request);

        match decision {
            Decision::Deny { reason } => {
                prop_assert!(
                    reason.contains("deny-by-default") || reason.contains("no matching policy"),
                    "deny reason should mention deny-by-default, got: {}", reason
                );
            }
            other => {
                prop_assert!(false, "expected Deny, got: {:?}", other);
            }
        }
    }

    /// A single allow-all policy allows any tool name.
    #[test]
    fn allow_all_policy_allows_any_tool(
        tool_name in tool_name_strategy(),
        intent in intent_strategy(),
    ) {
        let mut config = PolicyConfig {
            policies: vec![allow_all_policy()],
        };
        config.compile().unwrap();

        let ctx = make_context(&intent);
        let request = make_request(&tool_name, None);

        let decision = evaluate(&config, &ctx, &request);

        match decision {
            Decision::Allow { policy_id } => {
                prop_assert_eq!(policy_id, "allow-all");
            }
            other => {
                prop_assert!(false, "expected Allow, got: {:?}", other);
            }
        }
    }

    /// Policy with parameter_constraints.max_value rejects any value above the max.
    #[test]
    fn parameter_max_rejects_above(
        max_val in 1.0f64..1000.0,
        offset in 0.01f64..500.0,
    ) {
        let tool_name = "constrained_tool";
        let above_max = max_val + offset;

        let policy = Policy {
            id: "constrained".into(),
            agent_match: AgentMatch::default(),
            principal_match: PrincipalMatch::default(),
            intent_match: IntentMatch::default(),
            allowed_tools: vec![tool_name.into()],
            resource_match: vec![],
            parameter_constraints: vec![ParameterConstraint {
                key: "max_tokens".into(),
                max_value: Some(max_val),
                min_value: None,
                allowed_values: vec![],
            }],
            effect: Effect::Allow,
            disposition: Disposition::Block,
            priority: 0,
        };

        let mut config = PolicyConfig {
            policies: vec![policy],
        };
        config.compile().unwrap();

        let ctx = make_context("test intent");
        let request = make_request(
            tool_name,
            Some(serde_json::json!({ "max_tokens": above_max })),
        );

        let decision = evaluate(&config, &ctx, &request);

        // The constrained policy should not match (param exceeds max),
        // and with no fallback, deny-by-default kicks in.
        match decision {
            Decision::Deny { .. } => {} // expected
            other => {
                prop_assert!(
                    false,
                    "value {} exceeds max {}, expected Deny, got: {:?}",
                    above_max, max_val, other
                );
            }
        }
    }

    /// Policy with parameter_constraints.max_value allows any value at or below the max.
    #[test]
    fn parameter_max_allows_at_or_below(
        max_val in 1.0f64..1000.0,
        fraction in 0.0f64..=1.0,
    ) {
        let tool_name = "constrained_tool";
        let at_or_below = max_val * fraction;

        let policy = Policy {
            id: "constrained".into(),
            agent_match: AgentMatch::default(),
            principal_match: PrincipalMatch::default(),
            intent_match: IntentMatch::default(),
            allowed_tools: vec![tool_name.into()],
            resource_match: vec![],
            parameter_constraints: vec![ParameterConstraint {
                key: "max_tokens".into(),
                max_value: Some(max_val),
                min_value: None,
                allowed_values: vec![],
            }],
            effect: Effect::Allow,
            disposition: Disposition::Block,
            priority: 0,
        };

        let mut config = PolicyConfig {
            policies: vec![policy],
        };
        config.compile().unwrap();

        let ctx = make_context("test intent");
        let request = make_request(
            tool_name,
            Some(serde_json::json!({ "max_tokens": at_or_below })),
        );

        let decision = evaluate(&config, &ctx, &request);

        match decision {
            Decision::Allow { policy_id } => {
                prop_assert_eq!(policy_id, "constrained");
            }
            other => {
                prop_assert!(
                    false,
                    "value {} <= max {}, expected Allow, got: {:?}",
                    at_or_below, max_val, other
                );
            }
        }
    }

    /// Determinism with parameter constraints: same inputs always produce same result.
    #[test]
    fn deterministic_with_constraints(
        max_val in 1.0f64..1000.0,
        test_val in 0.0f64..2000.0,
    ) {
        let tool_name = "constrained_tool";

        let policy = Policy {
            id: "constrained".into(),
            agent_match: AgentMatch::default(),
            principal_match: PrincipalMatch::default(),
            intent_match: IntentMatch::default(),
            allowed_tools: vec![tool_name.into()],
            resource_match: vec![],
            parameter_constraints: vec![ParameterConstraint {
                key: "value".into(),
                max_value: Some(max_val),
                min_value: None,
                allowed_values: vec![],
            }],
            effect: Effect::Allow,
            disposition: Disposition::Block,
            priority: 0,
        };

        let mut config = PolicyConfig {
            policies: vec![policy],
        };
        config.compile().unwrap();

        let ctx = make_context("test intent");
        let request = make_request(
            tool_name,
            Some(serde_json::json!({ "value": test_val })),
        );

        let d1 = evaluate(&config, &ctx, &request);
        let d2 = evaluate(&config, &ctx, &request);

        prop_assert_eq!(d1, d2);
    }
}
