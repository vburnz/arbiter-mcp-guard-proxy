//! Policy evaluation engine.
//!
//! Given an evaluation context (agent, principal, intent, MCP request),
//! evaluates all loaded policies and returns an authorization decision.
//! Uses deny-by-default semantics with most-specific-match-wins ordering.

use arbiter_identity::{Agent, DelegationLink, TrustLevel};
use arbiter_mcp::context::McpRequest;
use regex::Regex;
use serde::Serialize;

use crate::model::{Effect, IntentMatch, ParameterConstraint, Policy, PolicyConfig};

/// Context for policy evaluation: everything needed to make a decision.
#[derive(Debug, Clone)]
pub struct EvalContext {
    /// The agent making the request.
    pub agent: Agent,
    /// The delegation chain from root principal to this agent.
    pub delegation_chain: Vec<DelegationLink>,
    /// The declared task intent (free-form string).
    pub declared_intent: String,
    /// The principal's subject identifier (OAuth sub).
    pub principal_sub: String,
    /// The principal's groups.
    pub principal_groups: Vec<String>,
}

/// Authorization decision from policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Request is allowed; includes the list of authorized tools.
    Allow {
        /// The policy that matched.
        policy_id: String,
    },
    /// Request is denied.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
    },
    /// Request requires escalation (human-in-the-loop).
    Escalate {
        /// Human-readable reason for escalation.
        reason: String,
    },
    /// Request is denied but annotated (forwarded with governance metadata).
    Annotate {
        /// The policy that matched.
        policy_id: String,
        /// The reason for annotation.
        reason: String,
    },
}

/// Evaluate policies against the given context and MCP request.
///
/// Returns a [`Decision`] based on the most specific matching policy.
/// If no policy matches, returns [`Decision::Deny`] (deny-by-default).
pub fn evaluate(config: &PolicyConfig, ctx: &EvalContext, request: &McpRequest) -> Decision {
    evaluate_explained(config, ctx, request).decision
}

/// A single policy evaluation trace entry. Shows what happened during matching.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyTrace {
    /// The policy ID.
    pub policy_id: String,
    /// Whether this policy matched the request.
    pub matched: bool,
    /// The policy's effect (allow/deny/escalate).
    pub effect: String,
    /// The specificity score.
    pub specificity: i32,
    /// The policy's disposition (block/annotate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    /// Why it didn't match (if it didn't).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Result of policy evaluation with full reasoning trace.
#[derive(Debug, Clone)]
pub struct EvalResult {
    /// The authorization decision.
    pub decision: Decision,
    /// Trace of every policy that was evaluated, in order.
    pub trace: Vec<PolicyTrace>,
}

/// Evaluate policies with a full reasoning trace. Shows which policies were
/// considered, which matched, and why the final decision was reached.
pub fn evaluate_explained(
    config: &PolicyConfig,
    ctx: &EvalContext,
    request: &McpRequest,
) -> EvalResult {
    let mut trace = Vec::new();

    let mut matching: Vec<(&Policy, i32)> = Vec::new();

    for policy in &config.policies {
        let skip = explain_mismatch(policy, ctx, request);
        let specificity = policy.specificity();

        if skip.is_none() {
            matching.push((policy, specificity));
            trace.push(PolicyTrace {
                policy_id: policy.id.clone(),
                matched: true,
                effect: format!("{:?}", policy.effect).to_lowercase(),
                specificity,
                disposition: Some(format!("{:?}", policy.disposition).to_lowercase()),
                skip_reason: None,
            });
        } else {
            trace.push(PolicyTrace {
                policy_id: policy.id.clone(),
                matched: false,
                effect: format!("{:?}", policy.effect).to_lowercase(),
                specificity,
                disposition: Some(format!("{:?}", policy.disposition).to_lowercase()),
                skip_reason: skip,
            });
        }
    }

    matching.sort_by(|a, b| b.1.cmp(&a.1));

    let decision = match matching.first() {
        Some((policy, _)) => {
            tracing::debug!(
                policy_id = %policy.id,
                effect = ?policy.effect,
                agent_id = %ctx.agent.id,
                "policy matched"
            );
            match policy.effect {
                Effect::Allow => Decision::Allow {
                    policy_id: policy.id.clone(),
                },
                Effect::Deny => {
                    let reason = format!("denied by policy '{}'", policy.id);
                    match policy.disposition {
                        crate::model::Disposition::Block => Decision::Deny { reason },
                        crate::model::Disposition::Annotate => Decision::Annotate {
                            policy_id: policy.id.clone(),
                            reason,
                        },
                    }
                }
                Effect::Escalate => Decision::Escalate {
                    reason: format!("escalation required by policy '{}'", policy.id),
                },
            }
        }
        None => {
            tracing::warn!(
                agent_id = %ctx.agent.id,
                intent = %ctx.declared_intent,
                "no policy matched, deny by default"
            );
            Decision::Deny {
                reason: "no matching policy found (deny-by-default)".into(),
            }
        }
    };

    EvalResult { decision, trace }
}

/// Explain why a policy doesn't match. Returns None if it does match.
fn explain_mismatch(policy: &Policy, ctx: &EvalContext, request: &McpRequest) -> Option<String> {
    if !matches_agent(&policy.agent_match, ctx) {
        return Some("agent criteria not met".into());
    }
    if !matches_principal(&policy.principal_match, ctx) {
        return Some("principal criteria not met".into());
    }
    if !matches_intent(&policy.intent_match, &ctx.declared_intent) {
        return Some("intent criteria not met".into());
    }
    if !matches_tool(policy, request) {
        let tool = request.tool_name.as_deref().unwrap_or("(none)");
        return Some(format!("tool '{}' not in allowed_tools", tool));
    }
    if !matches_parameter_constraints(&policy.parameter_constraints, request) {
        return Some("parameter constraints not met".into());
    }
    None
}

/// Collect all tools authorized by Allow policies for the given context.
/// Used at session creation to build the tool whitelist.
pub fn authorized_tools(config: &PolicyConfig, ctx: &EvalContext) -> Vec<String> {
    let mut tools = Vec::new();
    for policy in &config.policies {
        if policy.effect != Effect::Allow {
            continue;
        }
        if matches_agent(&policy.agent_match, ctx)
            && matches_principal(&policy.principal_match, ctx)
            && matches_intent(&policy.intent_match, &ctx.declared_intent)
        {
            tools.extend(policy.allowed_tools.iter().cloned());
        }
    }
    tools.sort();
    tools.dedup();
    tools
}

/// Check agent matching criteria.
fn matches_agent(agent_match: &crate::model::AgentMatch, ctx: &EvalContext) -> bool {
    // If agent_id is specified, it must match exactly.
    if let Some(required_id) = agent_match.agent_id
        && ctx.agent.id != required_id
    {
        return false;
    }

    // If trust_level is specified, the agent must be at or above that level.
    if let Some(required_level) = agent_match.trust_level
        && !trust_level_gte(ctx.agent.trust_level, required_level)
    {
        return false;
    }

    // All required capabilities must be present.
    for cap in &agent_match.capabilities {
        if !ctx.agent.capabilities.contains(cap) {
            return false;
        }
    }

    true
}

/// Check principal matching criteria.
fn matches_principal(principal_match: &crate::model::PrincipalMatch, ctx: &EvalContext) -> bool {
    if let Some(ref required_sub) = principal_match.sub
        && ctx.principal_sub != *required_sub
    {
        return false;
    }

    if !principal_match.groups.is_empty()
        && !principal_match
            .groups
            .iter()
            .any(|g| ctx.principal_groups.contains(g))
    {
        return false;
    }

    true
}

/// Check intent matching criteria.
/// Uses pre-compiled regexes from `PolicyConfig::compile()` when available,
/// falling back to on-demand compilation for programmatically-built policies.
fn matches_intent(intent_match: &IntentMatch, declared_intent: &str) -> bool {
    let lower_intent = declared_intent.to_lowercase();

    // Use pre-compiled word-boundary regexes.
    // Previously compiled a new Regex for each keyword on every evaluation.
    if !intent_match.compiled_keywords.is_empty() {
        for re in &intent_match.compiled_keywords {
            if !re.is_match(&lower_intent) {
                return false;
            }
        }
    } else {
        // Fallback for programmatically-built policies without compile().
        for keyword in &intent_match.keywords {
            let lower_kw = keyword.to_lowercase();
            let pattern = format!(r"\b{}\b", regex::escape(&lower_kw));
            match Regex::new(&pattern) {
                Ok(re) => {
                    if !re.is_match(&lower_intent) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    if let Some(ref compiled) = intent_match.compiled_regex {
        if !compiled.is_match(declared_intent) {
            return false;
        }
    } else if let Some(ref pattern) = intent_match.regex {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(declared_intent) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }

    true
}

/// Check if the request tool matches the policy's allowed tools.
fn matches_tool(policy: &Policy, request: &McpRequest) -> bool {
    // Empty allowed_tools means "applies to all tools".
    if policy.allowed_tools.is_empty() {
        return true;
    }

    // For tool calls, the tool name must be in the allowed list.
    if let Some(ref tool_name) = request.tool_name {
        return policy.allowed_tools.iter().any(|t| t == tool_name);
    }

    // Non-tool-call requests (resources/read, etc.) must also
    // be checked against allowed_tools. Use the MCP method as the "tool name" for
    // matching. If the method isn't in the allowed list, the policy doesn't match,
    // and deny-by-default will catch it.
    policy.allowed_tools.iter().any(|t| t == &request.method)
}

/// Check parameter constraints against request arguments.
fn matches_parameter_constraints(
    constraints: &[ParameterConstraint],
    request: &McpRequest,
) -> bool {
    if constraints.is_empty() {
        return true;
    }

    let args = match &request.arguments {
        Some(args) => args,
        // No arguments but constraints exist means
        // all constrained keys are missing, so fail.
        None => return false,
    };

    for constraint in constraints {
        if let Some(value) = args.get(&constraint.key) {
            // Type confusion bypass prevention.
            // Constraints must reject values whose type doesn't match what the
            // constraint expects. Previously, sending a string where a number was
            // expected (or vice versa) silently bypassed the constraint.
            let has_numeric_constraint =
                constraint.max_value.is_some() || constraint.min_value.is_some();
            let has_string_constraint = !constraint.allowed_values.is_empty();

            // Check numeric bounds.
            if has_numeric_constraint {
                if let Some(num) = value.as_f64() {
                    if let Some(max) = constraint.max_value
                        && num > max
                    {
                        return false;
                    }
                    if let Some(min) = constraint.min_value
                        && num < min
                    {
                        return false;
                    }
                } else {
                    // Value is not a number but constraint requires numeric bounds.
                    tracing::debug!(
                        key = %constraint.key,
                        "parameter value is not numeric but constraint has numeric bounds, denying"
                    );
                    return false;
                }
            }

            // Check allowed string values.
            if has_string_constraint {
                if let Some(s) = value.as_str() {
                    if !constraint.allowed_values.contains(&s.to_string()) {
                        return false;
                    }
                } else {
                    // Value is not a string but constraint requires allowed_values.
                    tracing::debug!(
                        key = %constraint.key,
                        "parameter value is not a string but constraint has allowed_values, denying"
                    );
                    return false;
                }
            }
        } else {
            // Missing constrained parameter key now fails the constraint.
            // Previously, if a policy required max_tokens <= 1000 but the request had no max_tokens,
            // the constraint silently passed. Now it fails, preventing unbounded parameter values.
            tracing::debug!(
                key = %constraint.key,
                "constrained parameter missing from request, denying"
            );
            return false;
        }
    }

    true
}

/// Returns true if `agent_level` is greater than or equal to `required_level`.
fn trust_level_gte(agent_level: TrustLevel, required_level: TrustLevel) -> bool {
    trust_level_rank(agent_level) >= trust_level_rank(required_level)
}

fn trust_level_rank(level: TrustLevel) -> u8 {
    match level {
        TrustLevel::Untrusted => 0,
        TrustLevel::Basic => 1,
        TrustLevel::Verified => 2,
        TrustLevel::Trusted => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Disposition;
    use crate::model::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn test_agent(trust: TrustLevel, caps: Vec<&str>) -> Agent {
        Agent {
            id: Uuid::new_v4(),
            owner: "user:alice".into(),
            model: "test-model".into(),
            capabilities: caps.into_iter().map(String::from).collect(),
            trust_level: trust,
            created_at: Utc::now(),
            expires_at: None,
            active: true,
        }
    }

    fn test_ctx(agent: Agent, intent: &str) -> EvalContext {
        EvalContext {
            principal_sub: agent.owner.clone(),
            principal_groups: vec!["developers".into()],
            declared_intent: intent.into(),
            delegation_chain: vec![],
            agent,
        }
    }

    fn tool_call_request(tool: &str) -> McpRequest {
        McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some(tool.into()),
            arguments: None,
            resource_uri: None,
        }
    }

    #[test]
    fn allow_matching_policy() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-read".into(),
                agent_match: AgentMatch {
                    trust_level: Some(TrustLevel::Basic),
                    ..Default::default()
                },
                principal_match: Default::default(),
                intent_match: IntentMatch {
                    keywords: vec!["read".into()],
                    ..Default::default()
                },
                allowed_tools: vec!["read_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec!["read"]);
        let ctx = test_ctx(agent, "read the config file");
        let request = tool_call_request("read_file");

        let decision = evaluate(&config, &ctx, &request);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "allow-read".into()
            }
        );
    }

    #[test]
    fn deny_explicit_policy() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "deny-delete".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["delete_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Deny,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Trusted, vec!["admin"]);
        let ctx = test_ctx(agent, "delete everything");
        let request = tool_call_request("delete_file");

        let decision = evaluate(&config, &ctx, &request);
        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn deny_by_default_no_matching_policy() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-read-only".into(),
                agent_match: AgentMatch {
                    trust_level: Some(TrustLevel::Verified),
                    ..Default::default()
                },
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["read_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        // Agent is Untrusted; doesn't meet the Verified requirement.
        let agent = test_agent(TrustLevel::Untrusted, vec![]);
        let ctx = test_ctx(agent, "do something");
        let request = tool_call_request("read_file");

        let decision = evaluate(&config, &ctx, &request);
        assert!(
            matches!(decision, Decision::Deny { reason } if reason.contains("deny-by-default"))
        );
    }

    #[test]
    fn escalate_on_scope_violation() {
        let config = PolicyConfig {
            policies: vec![
                Policy {
                    id: "allow-read".into(),
                    agent_match: AgentMatch {
                        trust_level: Some(TrustLevel::Basic),
                        ..Default::default()
                    },
                    principal_match: Default::default(),
                    intent_match: IntentMatch {
                        keywords: vec!["read".into()],
                        ..Default::default()
                    },
                    allowed_tools: vec!["read_file".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Allow,
                    disposition: Disposition::Block,
                    priority: 0,
                },
                Policy {
                    id: "escalate-write-for-readers".into(),
                    agent_match: AgentMatch {
                        trust_level: Some(TrustLevel::Basic),
                        ..Default::default()
                    },
                    principal_match: Default::default(),
                    intent_match: IntentMatch {
                        keywords: vec!["read".into()],
                        ..Default::default()
                    },
                    allowed_tools: vec!["write_file".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Escalate,
                    disposition: Disposition::Block,
                    priority: 0,
                },
            ],
        };

        let agent = test_agent(TrustLevel::Basic, vec!["read"]);
        let ctx = test_ctx(agent, "read the config file");
        // Agent declared read intent but is trying to write.
        let request = tool_call_request("write_file");

        let decision = evaluate(&config, &ctx, &request);
        assert!(matches!(decision, Decision::Escalate { .. }));
    }

    #[test]
    fn parameter_constraint_enforcement() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-with-limits".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["generate".into()],
                parameter_constraints: vec![ParameterConstraint {
                    key: "max_tokens".into(),
                    max_value: Some(1000.0),
                    min_value: None,
                    allowed_values: vec![],
                }],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "generate text");

        // Within bounds, should allow.
        let ok_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": 500})),
            resource_uri: None,
        };
        assert!(matches!(
            evaluate(&config, &ctx, &ok_request),
            Decision::Allow { .. }
        ));

        // Exceeds bounds; should deny by default (constraint doesn't match).
        let bad_request = McpRequest {
            id: Some(serde_json::json!(2)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": 5000})),
            resource_uri: None,
        };
        assert!(matches!(
            evaluate(&config, &ctx, &bad_request),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn most_specific_match_wins() {
        let specific_agent_id = Uuid::new_v4();

        let config = PolicyConfig {
            policies: vec![
                Policy {
                    id: "general-deny".into(),
                    agent_match: AgentMatch {
                        trust_level: Some(TrustLevel::Basic),
                        ..Default::default()
                    },
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec!["admin_tool".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Deny,
                    disposition: Disposition::Block,
                    priority: 0,
                },
                Policy {
                    id: "specific-allow".into(),
                    agent_match: AgentMatch {
                        agent_id: Some(specific_agent_id),
                        ..Default::default()
                    },
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec!["admin_tool".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Allow,
                    disposition: Disposition::Block,
                    priority: 0,
                },
            ],
        };

        let mut agent = test_agent(TrustLevel::Basic, vec!["admin"]);
        agent.id = specific_agent_id;
        let ctx = test_ctx(agent, "admin operation");
        let request = tool_call_request("admin_tool");

        // The agent_id-specific Allow should beat the trust_level-based Deny.
        let decision = evaluate(&config, &ctx, &request);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "specific-allow".into()
            }
        );
    }

    #[test]
    fn intent_regex_matching() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "regex-match".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: IntentMatch {
                    keywords: vec![],
                    regex: Some(r"^(read|analyze)\b".into()),
                    ..Default::default()
                },
                allowed_tools: vec![],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);

        let ctx_match = test_ctx(agent.clone(), "read the logs");
        let request = tool_call_request("any_tool");
        assert!(matches!(
            evaluate(&config, &ctx_match, &request),
            Decision::Allow { .. }
        ));

        let ctx_no_match = test_ctx(agent, "delete the logs");
        assert!(matches!(
            evaluate(&config, &ctx_no_match, &request),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn authorized_tools_collects_from_allow_policies() {
        let config = PolicyConfig {
            policies: vec![
                Policy {
                    id: "p1".into(),
                    agent_match: Default::default(),
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec!["read_file".into(), "list_dir".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Allow,
                    disposition: Disposition::Block,
                    priority: 0,
                },
                Policy {
                    id: "p2".into(),
                    agent_match: Default::default(),
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec!["read_file".into(), "search".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Allow,
                    disposition: Disposition::Block,
                    priority: 0,
                },
                Policy {
                    id: "p3-deny".into(),
                    agent_match: Default::default(),
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec!["delete_file".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Deny,
                    disposition: Disposition::Block,
                    priority: 0,
                },
            ],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "do stuff");
        let tools = authorized_tools(&config, &ctx);
        assert_eq!(tools, vec!["list_dir", "read_file", "search"]);
    }

    #[test]
    fn deny_with_annotate_disposition() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "annotate-writes".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["write_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Deny,
                disposition: Disposition::Annotate,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "write a file");
        let request = tool_call_request("write_file");

        let result = evaluate_explained(&config, &ctx, &request);
        assert!(matches!(result.decision, Decision::Annotate { .. }));
        if let Decision::Annotate { policy_id, .. } = &result.decision {
            assert_eq!(policy_id, "annotate-writes");
        }
    }

    #[test]
    fn deny_with_block_disposition_is_deny() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "block-writes".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["write_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Deny,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "write a file");
        let request = tool_call_request("write_file");

        let result = evaluate_explained(&config, &ctx, &request);
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn trace_includes_disposition() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "annotate-policy".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec![],
                parameter_constraints: vec![],
                effect: Effect::Deny,
                disposition: Disposition::Annotate,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "anything");
        let request = tool_call_request("any_tool");

        let result = evaluate_explained(&config, &ctx, &request);
        assert_eq!(result.trace[0].disposition.as_deref(), Some("annotate"));
    }

    // -----------------------------------------------------------------------
    // Security-invariant and edge-case tests
    // -----------------------------------------------------------------------

    /// Core security invariant: an empty policy set must ALWAYS deny.
    /// This proves the deny-by-default property algebraically — if there are
    /// zero policies, no policy can match, so the result must be Deny regardless
    /// of the agent's trust level, intent, or requested tool.
    #[test]
    fn deny_by_default_empty_policy_set() {
        let config = PolicyConfig { policies: vec![] };

        // Try every trust level — all must be denied.
        for trust in [
            TrustLevel::Untrusted,
            TrustLevel::Basic,
            TrustLevel::Verified,
            TrustLevel::Trusted,
        ] {
            let agent = test_agent(trust, vec!["admin", "read", "write"]);
            let ctx = test_ctx(agent, "do anything at all");
            let request = tool_call_request("any_tool");

            let decision = evaluate(&config, &ctx, &request);
            assert!(
                matches!(decision, Decision::Deny { ref reason } if reason.contains("deny-by-default")),
                "empty policy set must deny for trust level {:?}, got {:?}",
                trust,
                decision
            );
        }

        // Also verify with a resource request (non-tool-call).
        let agent = test_agent(TrustLevel::Trusted, vec![]);
        let ctx = test_ctx(agent, "read resource");
        let resource_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "resources/read".into(),
            tool_name: None,
            arguments: None,
            resource_uri: Some("file:///etc/passwd".into()),
        };
        let decision = evaluate(&config, &ctx, &resource_request);
        assert!(
            matches!(decision, Decision::Deny { ref reason } if reason.contains("deny-by-default")),
            "empty policy set must deny resource requests too, got {:?}",
            decision
        );
    }

    /// Prove deny-by-default across the trust hierarchy. A policy that requires
    /// TrustLevel::Trusted must reject Untrusted, Basic, and Verified agents.
    /// Only Trusted agents should pass. This algebraically verifies the trust
    /// ordering: Untrusted < Basic < Verified < Trusted.
    #[test]
    fn deny_by_default_proven_across_trust_levels() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "trusted-only".into(),
                agent_match: AgentMatch {
                    trust_level: Some(TrustLevel::Trusted),
                    ..Default::default()
                },
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["secret_tool".into()],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let request = tool_call_request("secret_tool");

        // These three levels are below Trusted and MUST be denied.
        for trust in [
            TrustLevel::Untrusted,
            TrustLevel::Basic,
            TrustLevel::Verified,
        ] {
            let agent = test_agent(trust, vec![]);
            let ctx = test_ctx(agent, "access secret");
            let decision = evaluate(&config, &ctx, &request);
            assert!(
                matches!(decision, Decision::Deny { .. }),
                "trust level {:?} must be denied when policy requires Trusted, got {:?}",
                trust,
                decision
            );
        }

        // Trusted agent MUST be allowed.
        let trusted_agent = test_agent(TrustLevel::Trusted, vec![]);
        let trusted_ctx = test_ctx(trusted_agent, "access secret");
        let decision = evaluate(&config, &trusted_ctx, &request);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "trusted-only".into()
            },
            "Trusted agent must be allowed by a Trusted-level policy"
        );
    }

    /// A policy with parameter constraints must
    /// deny requests that are missing the constrained key entirely. Previously,
    /// a missing key silently passed the constraint, allowing unbounded values.
    #[test]
    fn parameter_constraint_missing_key_denied() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "constrained-generate".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["generate".into()],
                parameter_constraints: vec![ParameterConstraint {
                    key: "max_tokens".into(),
                    max_value: Some(1000.0),
                    min_value: None,
                    allowed_values: vec![],
                }],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "generate text");

        // Case 1: arguments present but missing the constrained key "max_tokens".
        let request_missing_key = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"prompt": "hello"})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &request_missing_key);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "missing constrained key 'max_tokens' must deny, got {:?}",
            decision
        );

        // Case 2: arguments entirely absent (None).
        let request_no_args = McpRequest {
            id: Some(serde_json::json!(2)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: None,
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &request_no_args);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "None arguments with parameter constraints must deny, got {:?}",
            decision
        );

        // Case 3: key present and within bounds — should allow (sanity check).
        let request_ok = McpRequest {
            id: Some(serde_json::json!(3)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": 500})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &request_ok);
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "valid constrained key must allow, got {:?}",
            decision
        );
    }

    /// When a policy's allowed_tools is empty, it acts as a wildcard and matches
    /// ANY tool. This is by design (documented in model.rs) but must be verified
    /// to avoid regressions.
    #[test]
    fn empty_allowed_tools_matches_all_tools() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "wildcard-allow".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec![], // empty = wildcard
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "do stuff");

        // Verify multiple different tool names all match.
        for tool in [
            "read_file",
            "write_file",
            "delete_file",
            "admin_nuke_everything",
            "some_obscure_tool",
        ] {
            let request = tool_call_request(tool);
            let decision = evaluate(&config, &ctx, &request);
            assert_eq!(
                decision,
                Decision::Allow {
                    policy_id: "wildcard-allow".into()
                },
                "empty allowed_tools should match tool '{}', got {:?}",
                tool,
                decision
            );
        }
    }

    /// For MCP methods that are NOT "tools/call" (e.g., "resources/read"),
    /// verify that tool matching uses the method name as the match target.
    /// A policy with specific allowed_tools should only match if the method
    /// name is in the list; otherwise deny-by-default applies.
    #[test]
    fn non_tool_call_method_skips_tool_matching() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-read-tool".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["read_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "read a resource");

        // A "resources/read" request has no tool_name. The policy only allows
        // "read_file", so "resources/read" won't match and deny-by-default applies.
        let resource_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "resources/read".into(),
            tool_name: None,
            arguments: None,
            resource_uri: Some("file:///data/config.toml".into()),
        };
        let decision = evaluate(&config, &ctx, &resource_request);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "resources/read must not match policy allowing 'read_file', got {:?}",
            decision
        );

        // Now verify that a policy explicitly listing "resources/read" in
        // allowed_tools DOES match the method-based lookup.
        let config_with_resource = PolicyConfig {
            policies: vec![Policy {
                id: "allow-resource-read".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["resources/read".into()],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };
        let decision = evaluate(&config_with_resource, &ctx, &resource_request);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "allow-resource-read".into()
            },
            "policy with 'resources/read' in allowed_tools must match resources/read requests"
        );

        // And verify that an empty allowed_tools (wildcard) also matches
        // non-tool-call methods.
        let config_wildcard = PolicyConfig {
            policies: vec![Policy {
                id: "wildcard-policy".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec![], // wildcard
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };
        let decision = evaluate(&config_wildcard, &ctx, &resource_request);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "wildcard-policy".into()
            },
            "wildcard allowed_tools must match non-tool-call methods too"
        );
    }

    // -----------------------------------------------------------------------
    // Policy evaluation ordering determinism (same specificity)
    // -----------------------------------------------------------------------

    /// Two policies with identical specificity scores must produce a deterministic
    /// result across repeated evaluations. The engine sorts by specificity and
    /// picks the first match; with equal scores, the original ordering in the
    /// config vector is the tiebreaker (stable sort property).
    #[test]
    fn deterministic_ordering_same_specificity() {
        // Both policies match the same agent, tool, and intent.
        // Both have the same specificity (trust_level=50 each, no other criteria).
        // One is Allow, the other is Deny.
        let config = PolicyConfig {
            policies: vec![
                Policy {
                    id: "first-allow".into(),
                    agent_match: AgentMatch {
                        trust_level: Some(TrustLevel::Basic),
                        ..Default::default()
                    },
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec![],
                    parameter_constraints: vec![],
                    effect: Effect::Allow,
                    disposition: Disposition::Block,
                    priority: 0,
                },
                Policy {
                    id: "second-deny".into(),
                    agent_match: AgentMatch {
                        trust_level: Some(TrustLevel::Basic),
                        ..Default::default()
                    },
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec![],
                    parameter_constraints: vec![],
                    effect: Effect::Deny,
                    disposition: Disposition::Block,
                    priority: 0,
                },
            ],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "do something");
        let request = tool_call_request("any_tool");

        // Run 100 times and verify every result is identical.
        let first_decision = evaluate(&config, &ctx, &request);
        for i in 1..100 {
            let decision = evaluate(&config, &ctx, &request);
            assert_eq!(
                decision, first_decision,
                "evaluation #{} produced different result than first: {:?} vs {:?}",
                i, decision, first_decision
            );
        }
    }

    // -----------------------------------------------------------------------
    // Parameter constraint NaN/infinity handling
    // -----------------------------------------------------------------------

    /// NaN/Infinity handling in parameter constraints.
    ///
    /// serde_json serializes f64::NAN, f64::INFINITY, and f64::NEG_INFINITY
    /// as JSON `null`. Since JSON has no representation for these IEEE 754
    /// special values, `value.as_f64()` returns `None` for them, and the
    /// numeric bounds check is skipped entirely. The value IS present in
    /// the arguments map (as null), so the "missing key" check also passes.
    ///
    /// This means NaN/Infinity effectively bypass numeric constraints through
    /// JSON serialization. This test documents the current behavior as a
    /// known gap and verifies that explicit non-numeric JSON types
    /// (strings, nulls) also bypass numeric bounds.
    #[test]
    fn parameter_constraint_nan_infinity() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "bounded-generate".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["generate".into()],
                parameter_constraints: vec![ParameterConstraint {
                    key: "max_tokens".into(),
                    max_value: Some(100.0),
                    min_value: Some(0.0),
                    allowed_values: vec![],
                }],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "generate text");

        // serde_json::json! converts f64::INFINITY to null. The key "max_tokens"
        // is present (as null), so the missing-key check passes. as_f64() on null
        // returns None, so numeric bounds are never checked. Result: Allow.
        // non-numeric JSON values bypass numeric constraints.
        let inf_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": f64::INFINITY})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &inf_request);
        // f64::INFINITY becomes JSON null,
        // which is not a number, so the type-confusion check denies it.
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "f64::INFINITY (JSON null) must be denied by type check. Got: {:?}",
            decision
        );

        // Same for NaN and -Infinity.
        let nan_request = McpRequest {
            id: Some(serde_json::json!(2)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": f64::NAN})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &nan_request);
        // NaN becomes JSON null → type check denies.
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "f64::NAN (JSON null) must be denied by type check. Got: {:?}",
            decision
        );

        // String value: "not_a_number" — type check now denies non-numeric values
        // when constraint has numeric bounds.
        let string_request = McpRequest {
            id: Some(serde_json::json!(3)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": "not_a_number"})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &string_request);
        // String value with numeric constraint → denied.
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "string value must be denied when numeric bounds exist. Got: {:?}",
            decision
        );

        // Sanity check: a valid numeric value that exceeds the max IS denied.
        let over_max_request = McpRequest {
            id: Some(serde_json::json!(4)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": 200})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &over_max_request);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "valid numeric 200 > max 100 must deny, got {:?}",
            decision
        );

        // Sanity check: a valid numeric value within bounds IS allowed.
        let ok_request = McpRequest {
            id: Some(serde_json::json!(5)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": 50})),
            resource_uri: None,
        };
        let decision = evaluate(&config, &ctx, &ok_request);
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "valid numeric 50 within [0, 100] must allow, got {:?}",
            decision
        );
    }

    // -----------------------------------------------------------------------
    // Case-insensitive intent matching
    // -----------------------------------------------------------------------

    #[test]
    fn case_insensitive_intent_matching() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "case-test".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: IntentMatch {
                    keywords: vec!["read".into()],
                    ..Default::default()
                },
                allowed_tools: vec![],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);

        // "READ files" should match keyword "read" (case-insensitive).
        let ctx = test_ctx(agent.clone(), "READ files");
        let request = tool_call_request("any");
        let decision = evaluate(&config, &ctx, &request);
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "uppercase 'READ' must match keyword 'read', got {:?}",
            decision
        );

        // "Read Files" mixed case should also match.
        let ctx2 = test_ctx(agent, "Read Files");
        let decision2 = evaluate(&config, &ctx2, &request);
        assert!(
            matches!(decision2, Decision::Allow { .. }),
            "mixed case 'Read' must match keyword 'read', got {:?}",
            decision2
        );
    }

    // -----------------------------------------------------------------------
    // Empty intent match (no keywords, no regex) matches everything
    // -----------------------------------------------------------------------

    #[test]
    fn empty_intent_match_always_matches() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "empty-intent".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: IntentMatch {
                    keywords: vec![],
                    regex: None,
                    compiled_regex: None,
                    compiled_keywords: vec![],
                },
                allowed_tools: vec![],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let request = tool_call_request("anything");

        // Various intents should all match the empty intent criteria.
        for intent in [
            "read files",
            "delete everything",
            "",
            "some random text with special chars !@#$%",
        ] {
            let ctx = test_ctx(agent.clone(), intent);
            let decision = evaluate(&config, &ctx, &request);
            assert!(
                matches!(decision, Decision::Allow { .. }),
                "empty IntentMatch must match intent '{}', got {:?}",
                intent,
                decision
            );
        }
    }

    // -----------------------------------------------------------------------
    // Delegation chain preserved in EvalContext
    // -----------------------------------------------------------------------

    #[test]
    fn delegation_chain_in_eval_context() {
        let agent = test_agent(TrustLevel::Basic, vec![]);
        let chain = vec![DelegationLink {
            from: Uuid::new_v4(),
            to: agent.id,
            scope_narrowing: vec!["read".into()],
            created_at: Utc::now(),
            expires_at: None,
        }];

        let ctx = EvalContext {
            principal_sub: agent.owner.clone(),
            principal_groups: vec![],
            declared_intent: "read files".into(),
            delegation_chain: chain.clone(),
            agent,
        };

        // Verify the delegation chain is stored and accessible.
        assert_eq!(ctx.delegation_chain.len(), 1);
        assert_eq!(ctx.delegation_chain[0].scope_narrowing, vec!["read"]);
        assert_eq!(ctx.delegation_chain[0].to, ctx.agent.id);

        // Verify evaluation still works with a non-empty chain (it should
        // not interfere with matching since the engine doesn't filter on it).
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-all".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec![],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };
        let request = tool_call_request("any_tool");
        let decision = evaluate(&config, &ctx, &request);
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "delegation chain must not interfere with evaluation, got {:?}",
            decision
        );
    }

    // -----------------------------------------------------------------------
    // Deny-by-default applies even to high-trust agents
    // -----------------------------------------------------------------------

    /// Proves that deny-by-default is not bypassed by high trust levels.
    /// A Trusted agent requesting a tool that no policy covers must still be
    /// denied. The existing `deny_by_default_proven_across_trust_levels` test
    /// verifies trust ordering (lower levels rejected by a Trusted-only policy),
    /// but does NOT test the case where a Trusted agent calls a tool with zero
    /// matching policies. This test closes that gap.
    #[test]
    fn deny_by_default_applies_to_trusted_agents() {
        // The only policy covers "read_file". There is NO policy for "deploy_nuke".
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-read".into(),
                agent_match: AgentMatch {
                    trust_level: Some(TrustLevel::Basic),
                    ..Default::default()
                },
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["read_file".into()],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        // Agent has the highest trust level — Trusted.
        let agent = test_agent(TrustLevel::Trusted, vec!["admin", "deploy"]);
        let ctx = test_ctx(agent, "deploy to production");
        // Request a tool that no policy mentions.
        let request = tool_call_request("deploy_nuke");

        let decision = evaluate(&config, &ctx, &request);
        assert!(
            matches!(decision, Decision::Deny { ref reason } if reason.contains("deny-by-default")),
            "Trusted agent requesting an uncovered tool must be denied by default, got {:?}",
            decision
        );
    }

    // -----------------------------------------------------------------------
    // Overlapping allow/deny with specificity resolution
    // -----------------------------------------------------------------------

    /// When a broad Allow (wildcard tools) and a specific Deny (named tool)
    /// overlap, the higher-specificity Deny must win for the denied tool,
    /// while the Allow still applies to other tools. This verifies that
    /// priority-based specificity correctly resolves overlapping policies.
    #[test]
    fn overlapping_allow_deny_specificity_resolution() {
        let config = PolicyConfig {
            policies: vec![
                // Low-priority Allow that matches all tools (wildcard).
                Policy {
                    id: "broad-allow".into(),
                    agent_match: Default::default(),
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec![], // empty = wildcard, matches everything
                    parameter_constraints: vec![],
                    effect: Effect::Allow,
                    disposition: Disposition::Block,
                    priority: 10, // low priority
                },
                // High-priority Deny targeting a specific tool.
                Policy {
                    id: "specific-deny-delete".into(),
                    agent_match: Default::default(),
                    principal_match: Default::default(),
                    intent_match: Default::default(),
                    allowed_tools: vec!["delete_file".into()],
                    parameter_constraints: vec![],
                    effect: Effect::Deny,
                    disposition: Disposition::Block,
                    priority: 100, // high priority
                },
            ],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "manage files");

        // Request the specifically denied tool — the high-priority Deny must win.
        let denied_request = tool_call_request("delete_file");
        let decision = evaluate(&config, &ctx, &denied_request);
        assert!(
            matches!(decision, Decision::Deny { ref reason } if reason.contains("specific-deny-delete")),
            "high-priority Deny must override low-priority Allow for 'delete_file', got {:?}",
            decision
        );

        // Request a different tool — the broad Allow should apply since the
        // specific Deny only matches "delete_file" and won't match "read_file".
        let allowed_request = tool_call_request("read_file");
        let decision = evaluate(&config, &ctx, &allowed_request);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "broad-allow".into()
            },
            "broad Allow must apply to tools not covered by the specific Deny"
        );
    }

    // -----------------------------------------------------------------------
    // Parameter constraint type confusion bypass
    // -----------------------------------------------------------------------

    /// ATTACK: Send a string where a number is expected to bypass numeric constraints.
    /// If max_tokens constraint says max_value=1000 but we send {"max_tokens": "99999"},
    /// the as_f64() check doesn't fire because it's a string, not a number.
    #[test]
    fn parameter_type_confusion_string_bypasses_numeric_constraint() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-with-limit".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["generate".into()],
                parameter_constraints: vec![ParameterConstraint {
                    key: "max_tokens".into(),
                    max_value: Some(1000.0),
                    min_value: None,
                    allowed_values: vec![],
                }],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "generate text");

        // ATTACK: Send max_tokens as a string instead of a number
        let attack_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some("generate".into()),
            arguments: Some(serde_json::json!({"max_tokens": "99999"})),
            resource_uri: None,
        };

        let decision = evaluate(&config, &ctx, &attack_request);
        // This SHOULD deny because 99999 > 1000, but the type confusion means
        // the numeric check doesn't fire on a string value
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "TYPE CONFUSION BYPASS: string '99999' bypassed numeric constraint max_value=1000, got {:?}",
            decision
        );
    }

    /// ATTACK: Send a number where a string is expected to bypass allowed_values.
    /// If path constraint says allowed_values=["/etc", "/var"] but we send {"path": 42},
    /// the string check doesn't fire because it's a number.
    #[test]
    fn parameter_type_confusion_number_bypasses_string_constraint() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-with-path".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["read_file".into()],
                parameter_constraints: vec![ParameterConstraint {
                    key: "path".into(),
                    max_value: None,
                    min_value: None,
                    allowed_values: vec!["/etc".into(), "/var".into()],
                }],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "read files");

        // ATTACK: Send path as a number instead of string
        let attack_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some("read_file".into()),
            arguments: Some(serde_json::json!({"path": 42})),
            resource_uri: None,
        };

        let decision = evaluate(&config, &ctx, &attack_request);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "TYPE CONFUSION BYPASS: number 42 bypassed allowed_values for path, got {:?}",
            decision
        );
    }

    /// ATTACK: Send an array where a scalar is expected.
    #[test]
    fn parameter_type_confusion_array_bypasses_constraint() {
        let config = PolicyConfig {
            policies: vec![Policy {
                id: "allow-with-path".into(),
                agent_match: Default::default(),
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec!["read_file".into()],
                parameter_constraints: vec![ParameterConstraint {
                    key: "path".into(),
                    max_value: None,
                    min_value: None,
                    allowed_values: vec!["/etc".into(), "/var".into()],
                }],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            }],
        };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "read files");

        // ATTACK: Send path as an array
        let attack_request = McpRequest {
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            tool_name: Some("read_file".into()),
            arguments: Some(serde_json::json!({"path": ["/etc/shadow", "/root/.ssh/id_rsa"]})),
            resource_uri: None,
        };

        let decision = evaluate(&config, &ctx, &attack_request);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "TYPE CONFUSION BYPASS: array bypassed allowed_values for path, got {:?}",
            decision
        );
    }

    // -----------------------------------------------------------------------
    // Policy evaluation scales to 1000 policies
    // -----------------------------------------------------------------------

    /// Verify that the policy engine handles a large policy set (1000 policies)
    /// without hanging, panicking, or producing incorrect results. Each policy
    /// allows a single unique tool (`tool_0` through `tool_999`). Requesting
    /// a tool in the middle (`tool_500`) must return Allow, and requesting a
    /// nonexistent tool must return Deny (deny-by-default).
    #[test]
    fn policy_evaluation_scales_to_1000_policies() {
        let policies: Vec<Policy> = (0..1000)
            .map(|i| Policy {
                id: format!("policy-{}", i),
                agent_match: AgentMatch {
                    trust_level: Some(TrustLevel::Basic),
                    ..Default::default()
                },
                principal_match: Default::default(),
                intent_match: Default::default(),
                allowed_tools: vec![format!("tool_{}", i)],
                parameter_constraints: vec![],
                effect: Effect::Allow,
                disposition: Disposition::Block,
                priority: 0,
            })
            .collect();

        let config = PolicyConfig { policies };

        let agent = test_agent(TrustLevel::Basic, vec![]);
        let ctx = test_ctx(agent, "do stuff");

        // tool_500 should match policy-500 and return Allow.
        let request_500 = tool_call_request("tool_500");
        let decision = evaluate(&config, &ctx, &request_500);
        assert_eq!(
            decision,
            Decision::Allow {
                policy_id: "policy-500".into()
            },
            "tool_500 must match policy-500 in a 1000-policy config, got {:?}",
            decision
        );

        // tool_nonexistent has no matching policy — deny-by-default.
        let request_missing = tool_call_request("tool_nonexistent");
        let decision = evaluate(&config, &ctx, &request_missing);
        assert!(
            matches!(decision, Decision::Deny { ref reason } if reason.contains("deny-by-default")),
            "nonexistent tool must be denied by default in a 1000-policy config, got {:?}",
            decision
        );
    }
}
