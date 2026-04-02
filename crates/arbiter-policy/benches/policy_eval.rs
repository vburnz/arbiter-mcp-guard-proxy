use criterion::{Criterion, black_box, criterion_group, criterion_main};

use arbiter_policy::{EvalContext, PolicyConfig, evaluate};

/// Build a minimal agent for policy evaluation context.
fn make_eval_context() -> EvalContext {
    use arbiter_identity::{Agent, TrustLevel};
    use chrono::Utc;
    use uuid::Uuid;

    let agent = Agent {
        id: Uuid::new_v4(),
        owner: "user:bench".into(),
        model: "bench-model".into(),
        capabilities: vec!["file_access".into()],
        trust_level: TrustLevel::Verified,
        created_at: Utc::now(),
        expires_at: None,
        active: true,
    };

    EvalContext {
        agent,
        delegation_chain: vec![],
        declared_intent: "read and analyze log files".into(),
        principal_sub: "user:bench".into(),
        principal_groups: vec!["engineers".into()],
    }
}

/// Build an McpRequest representing a tools/call.
fn make_mcp_request(tool_name: &str) -> arbiter_mcp::context::McpRequest {
    arbiter_mcp::context::McpRequest {
        id: Some(serde_json::json!(1)),
        method: "tools/call".into(),
        tool_name: Some(tool_name.into()),
        arguments: Some(serde_json::json!({"path": "/var/log/app.log"})),
        resource_uri: None,
    }
}

fn bench_single_allow_policy(c: &mut Criterion) {
    let toml_str = r#"
[[policies]]
id = "allow-read"
effect = "allow"
allowed_tools = ["read_file", "list_dir", "get_status"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read", "analyze"]
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    let ctx = make_eval_context();
    let request = make_mcp_request("read_file");

    c.bench_function("eval_single_allow_matching", |b| {
        b.iter(|| evaluate(black_box(&config), black_box(&ctx), black_box(&request)))
    });
}

fn bench_ten_mixed_policies(c: &mut Criterion) {
    // Build 10 policies: a mix of allow/deny with different specificity.
    // The matching policy is the 7th one (id = "target-allow").
    let toml_str = r#"
[[policies]]
id = "deny-admin-1"
effect = "deny"
allowed_tools = ["admin_panel"]
[policies.intent_match]
keywords = ["admin"]

[[policies]]
id = "deny-delete"
effect = "deny"
allowed_tools = ["delete_file", "remove_dir"]
[policies.intent_match]
keywords = ["cleanup"]

[[policies]]
id = "allow-deploy"
effect = "allow"
allowed_tools = ["deploy_app"]
[policies.intent_match]
keywords = ["deploy"]

[[policies]]
id = "deny-write-1"
effect = "deny"
allowed_tools = ["write_file"]
[policies.intent_match]
keywords = ["write"]

[[policies]]
id = "allow-search"
effect = "allow"
allowed_tools = ["search_index"]
[policies.intent_match]
keywords = ["search"]

[[policies]]
id = "deny-escalate"
effect = "escalate"
allowed_tools = ["configure_settings"]
[policies.intent_match]
keywords = ["configure"]

[[policies]]
id = "target-allow"
effect = "allow"
allowed_tools = ["read_file", "list_dir"]
[policies.agent_match]
trust_level = "basic"
[policies.intent_match]
keywords = ["read", "analyze"]

[[policies]]
id = "deny-broad"
effect = "deny"
allowed_tools = ["execute_shell"]
[policies.intent_match]
keywords = ["execute"]

[[policies]]
id = "allow-report"
effect = "allow"
allowed_tools = ["generate_report"]
[policies.intent_match]
keywords = ["report"]

[[policies]]
id = "deny-all-fallback"
effect = "deny"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    let ctx = make_eval_context();
    let request = make_mcp_request("read_file");

    c.bench_function("eval_10_mixed_policies", |b| {
        b.iter(|| evaluate(black_box(&config), black_box(&ctx), black_box(&request)))
    });
}

fn bench_parameter_constraints(c: &mut Criterion) {
    let toml_str = r#"
[[policies]]
id = "allow-bounded"
effect = "allow"
allowed_tools = ["process_data"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read", "analyze"]

[[policies.parameter_constraints]]
key = "arguments.max_tokens"
min_value = 1.0
max_value = 8192.0

[[policies.parameter_constraints]]
key = "arguments.temperature"
min_value = 0.0
max_value = 2.0
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    let ctx = make_eval_context();
    let request = arbiter_mcp::context::McpRequest {
        id: Some(serde_json::json!(1)),
        method: "tools/call".into(),
        tool_name: Some("process_data".into()),
        arguments: Some(serde_json::json!({
            "max_tokens": 4096,
            "temperature": 0.7
        })),
        resource_uri: None,
    };

    c.bench_function("eval_parameter_constraints", |b| {
        b.iter(|| evaluate(black_box(&config), black_box(&ctx), black_box(&request)))
    });
}

fn bench_regex_pattern_matching(c: &mut Criterion) {
    let toml_str = r#"
[[policies]]
id = "allow-file-ops"
effect = "allow"
allowed_tools = ["read_file", "list_dir", "get_file_info", "search_files"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
regex = "(?i)(read|analyz|inspect|review).*\\b(file|log|report|data)s?\\b"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    let ctx = make_eval_context();
    let request = make_mcp_request("read_file");

    c.bench_function("eval_regex_intent_match", |b| {
        b.iter(|| evaluate(black_box(&config), black_box(&ctx), black_box(&request)))
    });
}

criterion_group!(
    benches,
    bench_single_allow_policy,
    bench_ten_mixed_policies,
    bench_parameter_constraints,
    bench_regex_pattern_matching,
);
criterion_main!(benches);
