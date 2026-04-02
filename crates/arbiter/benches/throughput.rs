use criterion::{black_box, criterion_group, criterion_main, Criterion};

use arbiter::config::ArbiterConfig;

/// A realistic minimal TOML config string for benchmarking parse speed.
const MINIMAL_CONFIG: &str = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = 8080
upstream_url = "http://127.0.0.1:9000"

[admin]
api_key = "bench-api-key-not-default"
signing_secret = "bench-signing-secret-not-default"

[sessions]
default_time_limit_secs = 3600
default_call_budget = 1000

[audit]
enabled = true

[metrics]
enabled = true
"#;

/// A full production-like config with all sections populated.
const FULL_CONFIG: &str = r#"
[proxy]
listen_addr = "0.0.0.0"
listen_port = 8443
upstream_url = "https://mcp-server.internal:8081"
blocked_paths = ["/admin", "/debug", "/internal"]
require_session = true
strict_mcp = true
max_request_body_bytes = 10485760
max_response_body_bytes = 10485760
upstream_timeout_secs = 30

[sessions]
default_time_limit_secs = 7200
default_call_budget = 500
escalate_anomalies = false
warning_threshold_pct = 20.0
rate_limit_window_secs = 60
cleanup_interval_secs = 60

[audit]
enabled = true
redaction_patterns = ["password", "secret", "token", "key", "credential"]

[metrics]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = 3000
api_key = "production-key-abc123xyz"
signing_secret = "production-secret-hmac-key-456"
token_expiry_secs = 1800

[credentials]
provider = "env"
env_prefix = "ARBITER_CRED"

[storage]
backend = "memory"

[policy]
watch = false

[[policy.policies]]
id = "allow-read-ops"
effect = "allow"
allowed_tools = ["read_file", "list_dir", "get_status", "search_files"]

[policy.policies.agent_match]
trust_level = "basic"

[policy.policies.intent_match]
keywords = ["read", "analyze", "review"]

[[policy.policies]]
id = "deny-admin"
effect = "deny"
allowed_tools = ["configure_settings", "admin_panel"]

[[policy.policies]]
id = "allow-write-verified"
effect = "allow"
allowed_tools = ["write_file", "create_dir"]

[policy.policies.agent_match]
trust_level = "verified"

[policy.policies.intent_match]
keywords = ["write", "create", "deploy"]
"#;

fn bench_config_parse_minimal(c: &mut Criterion) {
    c.bench_function("config_parse_minimal", |b| {
        b.iter(|| {
            let config = ArbiterConfig::parse(black_box(MINIMAL_CONFIG)).unwrap();
            black_box(config);
        })
    });
}

fn bench_config_parse_full(c: &mut Criterion) {
    c.bench_function("config_parse_full", |b| {
        b.iter(|| {
            let config = ArbiterConfig::parse(black_box(FULL_CONFIG)).unwrap();
            black_box(config);
        })
    });
}

fn bench_config_validate(c: &mut Criterion) {
    let config = ArbiterConfig::parse(FULL_CONFIG).unwrap();

    c.bench_function("config_validate", |b| {
        b.iter(|| {
            let warnings = black_box(&config).validate();
            black_box(warnings);
        })
    });
}

fn bench_end_to_end_mcp_pipeline(c: &mut Criterion) {
    use arbiter_behavior::{classify_operation, AnomalyConfig, AnomalyDetector};
    use arbiter_mcp::parser::{parse_mcp_body, ParseResult};
    use arbiter_policy::{evaluate, EvalContext, PolicyConfig};

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Set up all components that would be used in a single request.
    let policy_config = PolicyConfig::from_toml(
        r#"
[[policies]]
id = "allow-read"
effect = "allow"
allowed_tools = ["read_file", "list_dir"]
[policies.agent_match]
trust_level = "basic"
[policies.intent_match]
keywords = ["read", "analyze"]
"#,
    )
    .unwrap();

    let detector = AnomalyDetector::new(AnomalyConfig::default());

    let eval_ctx = {
        use arbiter_identity::{Agent, TrustLevel};
        use chrono::Utc;
        use uuid::Uuid;

        EvalContext {
            agent: Agent {
                id: Uuid::new_v4(),
                owner: "user:bench".into(),
                model: "bench-model".into(),
                capabilities: vec!["file_access".into()],
                trust_level: TrustLevel::Verified,
                created_at: Utc::now(),
                expires_at: None,
                active: true,
            },
            delegation_chain: vec![],
            declared_intent: "read and analyze log files".into(),
            principal_sub: "user:bench".into(),
            principal_groups: vec!["engineers".into()],
        }
    };

    // Set up a session store with a pre-created session.
    let session_store = arbiter_session::SessionStore::new();
    let session = rt.block_on(async {
        use arbiter_session::model::DataSensitivity;
        use arbiter_session::store::CreateSessionRequest;

        let req = CreateSessionRequest {
            agent_id: eval_ctx.agent.id,
            delegation_chain_snapshot: vec![],
            declared_intent: "read and analyze log files".into(),
            authorized_tools: vec!["read_file".into(), "list_dir".into()],
            time_limit: chrono::Duration::hours(1),
            call_budget: u64::MAX,
            rate_limit_per_minute: None,
            rate_limit_window_secs: 60,
            data_sensitivity_ceiling: DataSensitivity::Internal,
        };
        session_store.create(req).await
    });

    let request_body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/var/log/app.log" }
        }
    }))
    .unwrap();

    c.bench_function("e2e_mcp_parse_policy_session_behavior", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Stage 1: MCP parsing
                let parsed = parse_mcp_body(black_box(&request_body));
                let mcp_request = match &parsed {
                    ParseResult::Mcp(ctx) => &ctx.requests[0],
                    ParseResult::NonMcp => panic!("expected MCP"),
                };

                // Stage 2: Policy evaluation
                let decision = evaluate(
                    black_box(&policy_config),
                    black_box(&eval_ctx),
                    black_box(mcp_request),
                );
                black_box(&decision);

                // Stage 3: Session enforcement
                let session_result = session_store
                    .use_session(
                        black_box(session.session_id),
                        black_box("read_file"),
                    )
                    .await;
                black_box(&session_result);

                // Stage 4: Behavior detection
                let tool_name = mcp_request.tool_name.as_deref().unwrap_or("");
                let op_type = classify_operation(&mcp_request.method, Some(tool_name));
                let anomaly = detector.detect(
                    black_box("read and analyze log files"),
                    black_box(op_type),
                    black_box(tool_name),
                );
                black_box(anomaly);
            })
        })
    });
}

criterion_group!(
    benches,
    bench_config_parse_minimal,
    bench_config_parse_full,
    bench_config_validate,
    bench_end_to_end_mcp_pipeline,
);
criterion_main!(benches);
