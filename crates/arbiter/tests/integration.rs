//! Integration test: start arbiter, register agent via admin API,
//! make proxied request with MCP parsing, verify audit log entry.

use std::io::Write as _;
use std::net::TcpListener;
use std::time::Duration;

/// Find an available port by binding to port 0 then releasing it.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Start a simple echo HTTP server that returns the request body/path as a response.
async fn start_echo_server(port: u16) {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                use http_body_util::BodyExt;
                let path = req.uri().path().to_string();
                let method = req.method().to_string();
                let body_bytes = req.into_body().collect().await?.to_bytes();

                // For POST with JSON body, echo as JSON-RPC response.
                if method == "POST" && !body_bytes.is_empty() {
                    if let Ok(req_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                        let resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": req_json.get("id"),
                            "result": {
                                "echo": true,
                                "method": req_json.get("method"),
                                "params": req_json.get("params"),
                            }
                        });
                        let payload = serde_json::to_vec(&resp).unwrap();
                        return Ok::<_, anyhow::Error>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(http_body_util::Full::new(bytes::Bytes::from(payload)))
                                .unwrap(),
                        );
                    }
                }

                let body = format!("echo: {method} {path}");
                Ok::<_, anyhow::Error>(Response::new(http_body_util::Full::new(
                    bytes::Bytes::from(body),
                )))
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

#[tokio::test]
async fn full_lifecycle_integration() {
    // 1. Pick free ports for proxy, admin, and upstream.
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    // 2. Start the echo upstream.
    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Write a temp config.
    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("audit.jsonl");

    // Tests must include policies because the gateway now
    // denies all MCP traffic when no policies are loaded (true deny-by-default).
    let policy_path = audit_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
deny_non_post_methods = false

[policy]
file = "{policy}"

[sessions]
escalate_anomalies = false

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        audit = audit_path.display(),
        policy = policy_path.display(),
    );

    let config_file = audit_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    // 4. Start arbiter in background.
    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });

    // Give servers time to start.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // 5. Health check on proxy.
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let health: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(health["status"], "healthy");

    // 6. Register an agent via admin API.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "gpt-4",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("agent_id").is_some());
    assert!(body.get("token").is_some());
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // 7. List agents.
    let resp = client
        .get(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 1);

    // 8. Create a task session for the agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read configuration files",
            "authorized_tools": ["read_file", "list_dir"],
            "time_limit_secs": 3600,
            "call_budget": 100
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // 9. Make a proxied GET request (non-MCP, should pass through).
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/v1/tools"))
        .header("x-agent-id", &agent_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body_text = resp.text().await.unwrap();
    assert!(body_text.contains("echo:"));

    // 10. MCP request WITHOUT session header → should be denied (403) with structured JSON error.
    let mcp_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/etc/hosts" }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("content-type", "application/json")
        .json(&mcp_request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "MCP without session should be denied");
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_REQUIRED"),
        "structured error should have SESSION_REQUIRED code"
    );
    assert!(
        error_body["error"]["hint"].as_str().is_some(),
        "structured error should include a hint"
    );
    assert!(
        error_body["error"]["request_id"].as_str().is_some(),
        "structured error should include a request_id for audit correlation"
    );

    // 11. MCP request WITH valid session header → should succeed (200).
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "MCP with valid session should succeed");
    let mcp_resp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(mcp_resp["jsonrpc"], "2.0");
    assert!(mcp_resp["result"]["echo"].as_bool().unwrap_or(false));

    // 12. Non-MCP POST body → should be denied in strict mode (403) with structured error.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "text/plain")
        .body("this is not JSON-RPC")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-MCP POST should be denied");
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("NON_MCP_REJECTED"),
        "structured error should have NON_MCP_REJECTED code"
    );

    // 13. Unauthorized tool call → should be denied by session whitelist (403) with structured error.
    let bad_tool_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "delete_file",
            "arguments": { "path": "/etc/hosts" }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("content-type", "application/json")
        .json(&bad_tool_request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "unauthorized tool should be denied");
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "session-whitelist denial should have SESSION_INVALID code"
    );
    assert!(
        error_body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("delete_file"),
        "error detail should mention the denied tool"
    );

    // 14. Check metrics endpoint.
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let metrics_text = resp.text().await.unwrap();
    assert!(metrics_text.contains("requests_total"));
    // Should show both allow and deny decisions.
    assert!(
        metrics_text.contains(r#"decision="deny"#),
        "metrics should record deny decisions"
    );
    assert!(
        metrics_text.contains(r#"decision="allow"#),
        "metrics should record allow decisions"
    );

    // 15. Wait for audit to flush and verify audit log entries.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let audit_content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        !audit_content.is_empty(),
        "audit log should have at least one entry"
    );

    // There should be at least 5 audit entries:
    // GET /v1/tools, MCP denied (no session), MCP allowed, non-MCP denied, unauthorized tool denied
    let lines: Vec<&str> = audit_content.lines().collect();
    assert!(
        lines.len() >= 5,
        "expected at least 5 audit entries, got {}",
        lines.len()
    );

    // Find the successful MCP entry; should have tool_called with read_file.
    let mcp_allow_entry = lines.iter().find(|line| {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        v["authorization_decision"].as_str() == Some("allow")
            && v["tool_called"]
                .as_str()
                .unwrap_or("")
                .contains("read_file")
    });
    assert!(
        mcp_allow_entry.is_some(),
        "should have an allowed read_file audit entry"
    );

    // Verify the allowed entry has arguments captured.
    let entry: serde_json::Value = serde_json::from_str(mcp_allow_entry.unwrap()).unwrap();
    assert!(
        !entry["arguments"].is_null(),
        "allowed MCP entry should have arguments captured"
    );

    // Find the denied entry for unauthorized tool (delete_file).
    let deny_entry = lines.iter().find(|line| {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        v["authorization_decision"].as_str() == Some("deny")
            && v["tool_called"]
                .as_str()
                .unwrap_or("")
                .contains("delete_file")
    });
    assert!(
        deny_entry.is_some(),
        "should have a denied delete_file audit entry"
    );

    // Verify the denied entry has policy_matched showing session-whitelist.
    let entry: serde_json::Value = serde_json::from_str(deny_entry.unwrap()).unwrap();
    assert!(
        entry["policy_matched"]
            .as_str()
            .unwrap_or("")
            .contains("session-whitelist"),
        "denied entry should show session-whitelist as policy_matched"
    );

    // 16. Session warning headers: create a session with budget=5, use 4, verify warnings.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read configuration files",
            "authorized_tools": ["read_file"],
            "time_limit_secs": 3600,
            "call_budget": 5
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let small_session: serde_json::Value = resp.json().await.unwrap();
    let small_session_id = small_session["session_id"].as_str().unwrap().to_string();

    // Use 4 of 5 calls.
    for i in 0..4 {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 100 + i,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/etc/hosts" }
            }
        });
        let resp = client
            .post(format!("http://127.0.0.1:{proxy_port}/"))
            .header("x-agent-id", &agent_id)
            .header("x-arbiter-session", &small_session_id)
            .header("x-delegation-chain", "user:alice")
            .header("content-type", "application/json")
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "call {} should succeed", i + 1);
    }

    // 5th call: budget at 20% (1 of 5 remaining). Should get warning header.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 200,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/etc/hosts" }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &small_session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "5th call should succeed");

    // Verify observability headers are present.
    let calls_remaining = resp
        .headers()
        .get("x-arbiter-calls-remaining")
        .and_then(|v| v.to_str().ok());
    assert!(
        calls_remaining.is_some(),
        "response should include x-arbiter-calls-remaining header"
    );

    // After 5 calls on a budget of 5, the session is exhausted. Verify warning was present.
    // The warning fires when remaining <= 20%, so at 1/5 (20%) or 0/5 (0%) it should fire.
    let warning = resp
        .headers()
        .get("x-arbiter-warning")
        .and_then(|v| v.to_str().ok());
    assert!(
        warning.is_some(),
        "response should include x-arbiter-warning header when budget is low"
    );
    assert!(
        warning.unwrap().contains("budget low"),
        "warning should mention budget: got {:?}",
        warning
    );

    // 17. Budget exhaustion: 6th call should fail.
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 201,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/etc/hosts" }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &small_session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "6th call should be budget-exceeded");
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "budget exceeded should return SESSION_INVALID"
    );
    assert!(
        error_body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("budget"),
        "error detail should mention budget"
    );

    // ── Cycle 6: Lifecycle endpoint integration tests ───────────────

    // 18. Delegation introspection: agent should have no delegations yet.
    let resp = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/agents/{agent_id}/delegations"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let delegations: serde_json::Value = resp.json().await.unwrap();
    assert!(
        delegations["incoming"].as_array().unwrap().is_empty(),
        "new agent should have no incoming delegations"
    );
    assert!(
        delegations["outgoing"].as_array().unwrap().is_empty(),
        "new agent should have no outgoing delegations"
    );

    // 19. Session close with summary. Close the small_session (already exhausted).
    let resp = client
        .post(format!(
            "http://127.0.0.1:{admin_port}/sessions/{small_session_id}/close"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let close_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(close_body["status"].as_str(), Some("closed"));
    assert_eq!(close_body["total_calls"].as_u64(), Some(5));
    assert_eq!(close_body["call_budget"].as_u64(), Some(5));
    assert!(
        close_body["budget_utilization_pct"].as_f64().unwrap() > 99.0,
        "budget utilization should be ~100%"
    );
    // Audit stats: at least 1 denied attempt (the 6th call that exceeded budget).
    assert!(
        close_body["denied_attempts"].as_u64().unwrap() >= 1,
        "should have at least 1 denied attempt"
    );

    // 20. Policy validation: valid TOML.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/policy/validate"))
        .header("x-api-key", "test-key")
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "policy_toml": "[[policies]]\nid = \"allow-all\"\neffect = \"allow\"\n"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let validation: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(validation["valid"].as_bool(), Some(true));
    assert_eq!(validation["policy_count"].as_u64(), Some(1));

    // 21. Policy validation: invalid TOML with duplicate IDs.
    let resp = client
        .post(format!(
            "http://127.0.0.1:{admin_port}/policy/validate"
        ))
        .header("x-api-key", "test-key")
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "policy_toml": "[[policies]]\nid = \"dup\"\neffect = \"allow\"\n\n[[policies]]\nid = \"dup\"\neffect = \"deny\"\n"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let validation: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(validation["valid"].as_bool(), Some(false));
    assert!(
        validation["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["message"].as_str().unwrap_or("").contains("duplicate")),
        "should detect duplicate policy ID"
    );

    // 22. Clean up.
    arbiter_handle.abort();
}

/// Policy hot-reload E2E: start with deny-all, verify denial, rewrite file
/// to allow-all, reload, verify the next request succeeds.
#[tokio::test]
async fn policy_hot_reload_e2e() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Write initial deny-all policy file (empty = deny by default).
    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policies.toml");
    // A policy that only allows a tool nobody calls. All other tools
    // are denied by the deny-by-default rule.
    std::fs::write(
        &policy_path,
        "[[policies]]\nid = \"allow-noop\"\neffect = \"allow\"\nallowed_tools = [\"noop_tool\"]\n",
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[audit]
enabled = true

[policy]
file = "{policy_file}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy_file = policy_path.display()
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent + create session.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // MCP request with empty policy file → deny-by-default.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "empty policy file should deny by default"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(error_body["error"]["code"].as_str(), Some("POLICY_DENIED"));

    // Rewrite the policy file with an allow-all policy.
    let allow_policy = r#"
[[policies]]
id = "allow-all-read"
effect = "allow"
allowed_tools = ["read_file"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
"#;
    std::fs::write(&policy_path, allow_policy).unwrap();

    // Call POST /policy/reload.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/policy/reload"))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let reload_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(reload_body["reloaded"].as_bool(), Some(true));
    assert_eq!(reload_body["policy_count"].as_u64(), Some(1));

    // Same MCP request should now succeed.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "after reload, policy should allow the request"
    );
    let mcp_resp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(mcp_resp["jsonrpc"], "2.0");
    assert!(mcp_resp["result"]["echo"].as_bool().unwrap_or(false));

    arbiter_handle.abort();
}

/// Behavioral anomaly detection: a read-intent session calling a write tool
/// should succeed (soft flag), but the audit log should record the anomaly.
#[tokio::test]
async fn behavioral_anomaly_in_audit_log() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let audit_path = temp_dir.path().join("audit.jsonl");

    // Tests must include policies.
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[sessions]
escalate_anomalies = false

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        audit = audit_path.display(),
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create a read-intent session that authorizes write_file.
    // The session whitelist allows it, but the behavior detector should flag it.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read configuration files",
            "authorized_tools": ["read_file", "write_file"],
            "call_budget": 10,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Call a read tool. Should succeed with no anomaly.
    let read_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test.txt" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&read_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read tool in read session should succeed"
    );

    // Call a write tool. Should succeed (soft flag) but have anomaly in audit.
    let write_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "write_file", "arguments": { "path": "/tmp/out.txt", "content": "hello" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&write_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "write tool in read session should succeed (soft flag, not deny)"
    );

    // Wait for audit to flush.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Read audit log and verify anomaly flags.
    let audit_content = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = audit_content.lines().collect();
    assert!(
        lines.len() >= 2,
        "expected at least 2 audit entries, got {}",
        lines.len()
    );

    // Find the write_file entry; should have non-empty anomaly_flags.
    // tool_called format is "write_file (tools/call)".
    let write_entry = lines.iter().find(|line| {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        v["tool_called"]
            .as_str()
            .unwrap_or("")
            .contains("write_file")
    });
    assert!(
        write_entry.is_some(),
        "should have an audit entry for write_file"
    );
    let entry: serde_json::Value = serde_json::from_str(write_entry.unwrap()).unwrap();
    let flags = entry["anomaly_flags"].as_array().unwrap();
    assert!(
        !flags.is_empty(),
        "write_file in read-intent session should have anomaly flags, got: {entry}"
    );
    assert!(
        flags[0].as_str().unwrap().contains("read"),
        "anomaly flag should mention read-only intent: {:?}",
        flags
    );

    // The read_file entry should have empty anomaly_flags.
    let read_entry = lines.iter().find(|line| {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        v["tool_called"]
            .as_str()
            .unwrap_or("")
            .contains("read_file")
    });
    assert!(
        read_entry.is_some(),
        "should have an audit entry for read_file"
    );
    let entry: serde_json::Value = serde_json::from_str(read_entry.unwrap()).unwrap();
    let flags = entry["anomaly_flags"].as_array().unwrap();
    assert!(
        flags.is_empty(),
        "read_file in read-intent session should have no anomaly flags"
    );

    // Close session and verify anomalies_detected > 0.
    let resp = client
        .post(format!(
            "http://127.0.0.1:{admin_port}/sessions/{session_id}/close"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let close_body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        close_body["anomalies_detected"].as_u64().unwrap() >= 1,
        "session close should report at least 1 anomaly"
    );

    arbiter_handle.abort();
}

/// Test that the gateway handles adversarial / malformed inputs gracefully:
/// no panics, no 500s, appropriate error responses.
#[tokio::test]
async fn adversarial_inputs() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("audit.jsonl");
    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        audit = audit_path.display()
    );

    let config_file = audit_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();
    let proxy = format!("http://127.0.0.1:{proxy_port}");

    // ── 1. Completely invalid JSON body ──────────────────────────────
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .body("this is not json at all {{{")
        .send()
        .await
        .unwrap();
    // Should not panic or return 500. Strict MCP mode rejects non-MCP POSTs.
    assert!(
        resp.status().as_u16() == 403 || resp.status().as_u16() == 400,
        "malformed JSON should be rejected, got {}",
        resp.status()
    );

    // ── 2. Empty POST body ───────────────────────────────────────────
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().as_u16() == 403 || resp.status().as_u16() == 400,
        "empty POST should be rejected, got {}",
        resp.status()
    );

    // ── 3. Valid JSON but not JSON-RPC (missing method/jsonrpc) ──────
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .body(r#"{"hello": "world"}"#)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().as_u16() == 403 || resp.status().as_u16() == 400,
        "non-JSON-RPC POST should be rejected, got {}",
        resp.status()
    );

    // ── 4. JSON-RPC with null method ─────────────────────────────────
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc": "2.0", "id": 1, "method": null}"#)
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status().as_u16(),
        500,
        "null method should not cause 500"
    );

    // ── 5. JSON-RPC with extremely long tool name ────────────────────
    let long_name = "a".repeat(10_000);
    let body = format!(
        r#"{{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {{"name": "{long_name}"}}}}"#
    );
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status().as_u16(),
        500,
        "long tool name should not cause 500"
    );

    // ── 6. Session header with injection attempt ─────────────────────
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .header("x-session-id", "'; DROP TABLE sessions; --")
        .body(r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "test"}}"#)
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status().as_u16(),
        500,
        "injection in session header should not cause 500"
    );

    // ── 7. Deeply nested JSON params ─────────────────────────────────
    // Build 100-level deep nesting: {"a": {"a": {"a": ...}}}
    let mut nested = String::from("\"leaf\"");
    for _ in 0..100 {
        nested = format!(r#"{{"a": {nested}}}"#);
    }
    let body = format!(
        r#"{{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {{"name": "test", "arguments": {nested}}}}}"#
    );
    let resp = client
        .post(&proxy)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status().as_u16(),
        500,
        "deeply nested JSON should not cause 500"
    );

    // All adversarial inputs handled without panic or 500.
    arbiter_handle.abort();
}

// ── Compositional security tests ─────────────────────────────────
// These tests verify cross-stage interactions in the middleware pipeline
// that per-component unit tests cannot catch.

/// Agent isolation across sessions.
/// A session is bound to the agent that created it. Using a valid session
/// with a different agent's x-agent-id header must be rejected.
/// This catches session-hijacking where agent B tries to ride on agent A's session.
#[tokio::test]
async fn agent_isolation_cross_session() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent A.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_a_id = body["agent_id"].as_str().unwrap().to_string();

    // Register agent B.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:bob",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_b_id = body["agent_id"].as_str().unwrap().to_string();

    // Create a session for agent A.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_a_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 10,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_a_id = session_body["session_id"].as_str().unwrap().to_string();

    // Sanity check: agent A using its own session should work.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_a_id)
        .header("x-arbiter-session", &session_a_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "agent A using its own session should succeed"
    );

    // Agent B tries to use agent A's session. This is the cross-session hijack.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_b_id)
        .header("x-arbiter-session", &session_a_id)
        .header("x-delegation-chain", "user:bob")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "agent B using agent A's session must be denied (session-agent binding mismatch)"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "session-agent mismatch should return SESSION_INVALID"
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("does not belong"),
        "error message should indicate session ownership mismatch: got {:?}",
        error_body["error"]["message"]
    );

    arbiter_handle.abort();
}

/// Session close prevents reuse.
/// Once a session is closed via the admin API, any subsequent MCP request
/// referencing that session must be rejected. This verifies that the session
/// lifecycle stage and the proxy handler interact correctly.
#[tokio::test]
async fn session_close_prevents_reuse() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create a session.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Use the session once to confirm it works.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "session should work before close");

    // Close the session via admin API.
    let resp = client
        .post(format!(
            "http://127.0.0.1:{admin_port}/sessions/{session_id}/close"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "session close should succeed");
    let close_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(close_body["status"].as_str(), Some("closed"));

    // Attempt to reuse the closed session. Must be denied.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 403 || status == 408 || status == 410,
        "closed session must be denied, got {status}"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "closed session should return SESSION_INVALID"
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("closed"),
        "error should mention the session is closed: got {:?}",
        error_body["error"]["message"]
    );

    arbiter_handle.abort();
}

/// Policy deny overrides session allow (cross-stage interaction).
/// A session may authorize a tool, but if a policy explicitly denies it,
/// the policy stage (which runs after the session stage) must block the request.
/// This confirms that policy enforcement is not short-circuited by session authorization.
#[tokio::test]
async fn policy_deny_overrides_session_allow() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    // Policy: allow read_file, but explicitly deny write_file with higher priority.
    // The deny policy has priority=10 so it wins over the allow-all at priority=0.
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "allow-reads"
effect = "allow"
allowed_tools = []

[[policies]]
id = "deny-write-file"
effect = "deny"
priority = 10
allowed_tools = ["write_file"]
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create session that explicitly authorizes write_file.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "write configuration files",
            "authorized_tools": ["read_file", "write_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // read_file should succeed (session allows, policy allows).
    let read_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&read_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read_file should succeed (session allows, policy allows)"
    );

    // write_file should be denied by POLICY even though session authorizes it.
    let write_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "write_file", "arguments": { "path": "/tmp/out", "content": "x" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&write_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "write_file must be denied by policy even though session authorizes it"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("POLICY_DENIED"),
        "policy deny should produce POLICY_DENIED, not SESSION_INVALID"
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("deny-write-file"),
        "error should reference the deny policy ID: got {:?}",
        error_body["error"]["message"]
    );

    arbiter_handle.abort();
}

/// Anomaly escalation: hard deny mode.
/// With `escalate_anomalies = true`, a behavioral anomaly (write tool in a
/// read-intent session) is upgraded from a soft flag to a hard 403 deny with
/// error code BEHAVIORAL_ANOMALY. This verifies that the anomaly detection
/// stage and the escalation config interact correctly end-to-end.
#[tokio::test]
async fn anomaly_escalation_hard_deny() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    // Key config: escalate_anomalies = true turns behavioral flags into hard denies.
    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[sessions]
escalate_anomalies = true

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create a read-intent session that authorizes write_file.
    // The session whitelist allows it, but the behavioral anomaly detector
    // should catch the intent-action mismatch.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read configuration files",
            "authorized_tools": ["read_file", "write_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Read operation should succeed -- consistent with declared intent.
    let read_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&read_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read_file in read-intent session should succeed"
    );

    // Write operation should be HARD DENIED (not just flagged) because
    // escalate_anomalies = true. The session authorizes write_file and the
    // policy allows all tools, but the anomaly detector catches the
    // read-intent vs. write-action mismatch and escalates to deny.
    let write_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "write_file", "arguments": { "path": "/tmp/out", "content": "x" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&write_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "write_file in read-intent session must be hard denied with escalate_anomalies=true"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("BEHAVIORAL_ANOMALY"),
        "escalated anomaly should produce BEHAVIORAL_ANOMALY error code"
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("anomaly"),
        "error message should mention anomaly: got {:?}",
        error_body["error"]["message"]
    );

    arbiter_handle.abort();
}

// ── Gap-closing tests ──────────────────────────────────────────────
// Tests below close CRITICAL and HIGH audit gaps found during security audit.

/// WebSocket upgrade requests must be rejected with 501 NOT IMPLEMENTED.
/// The gateway does not support protocol upgrades; allowing them would let
/// an agent open a persistent, unmonitored bidirectional channel to the upstream.
#[tokio::test]
async fn websocket_upgrade_rejected() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Send a request with Upgrade: websocket header.
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/"))
        .header("Upgrade", "websocket")
        .header("Connection", "upgrade")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        501,
        "WebSocket upgrade request should return 501 NOT IMPLEMENTED"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("MIDDLEWARE_REJECTED"),
        "WebSocket rejection should use MIDDLEWARE_REJECTED error code"
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("upgrade"),
        "error message should mention protocol upgrades: got {:?}",
        error_body["error"]["message"]
    );

    // Also verify POST with Upgrade header is rejected.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("Upgrade", "websocket")
        .header("Connection", "upgrade")
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "test"}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        501,
        "POST with Upgrade header should also be rejected"
    );

    arbiter_handle.abort();
}

/// Missing x-agent-id with a valid session must be rejected.
/// previously, omitting x-agent-id entirely bypassed the
/// session-agent binding check, enabling session hijacking.
#[tokio::test]
async fn missing_agent_id_with_session_rejected() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create session.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Send MCP request with valid session but NO x-agent-id header.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        // Deliberately omit x-agent-id header.
        .header("x-arbiter-session", &session_id)
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "MCP request with session but no x-agent-id should return 400 BAD REQUEST"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("agent-id"),
        "error message should mention x-agent-id requirement: got {:?}",
        error_body["error"]["message"]
    );

    arbiter_handle.abort();
}

/// Invalid (non-UUID) x-agent-id with a valid session must be rejected.
/// Prevents agents from bypassing identity resolution with garbage values.
#[tokio::test]
async fn invalid_uuid_agent_id_rejected() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create session.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Send MCP request with valid session but INVALID x-agent-id.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", "not-a-valid-uuid")
        .header("x-arbiter-session", &session_id)
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "MCP request with invalid UUID x-agent-id should return 400 BAD REQUEST"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("uuid"),
        "error message should mention UUID validation: got {:?}",
        error_body["error"]["message"]
    );

    arbiter_handle.abort();
}

/// Request body size limit enforcement.
/// Requests exceeding max_request_body_bytes must be rejected with 413.
/// This prevents OOM attacks from oversized payloads.
#[tokio::test]
async fn request_body_too_large_rejected() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    // Key: set max_request_body_bytes to a very small value (100 bytes).
    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
max_request_body_bytes = 100

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Send a request body that exceeds 100 bytes.
    let large_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/this/is/a/long/path/to/exceed/the/very/small/body/limit/that/we/set/in/config",
                "extra_data": "padding to make the body larger than 100 bytes for testing purposes"
            }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .json(&large_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        413,
        "request exceeding max_request_body_bytes should return 413 PAYLOAD TOO LARGE"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("too large"),
        "error message should mention body too large: got {:?}",
        error_body["error"]["message"]
    );

    // Verify that a small request still works (health check).
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "health check should still work");

    arbiter_handle.abort();
}

/// Malformed (non-UUID) session header must be rejected with 400.
/// Ensures the session parsing stage rejects garbage values explicitly
/// rather than silently ignoring them.
#[tokio::test]
async fn malformed_session_header_rejected() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Send MCP request with a malformed session header.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", "00000000-0000-0000-0000-000000000000")
        .header("x-arbiter-session", "not-a-uuid")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "malformed session header should return 400 BAD REQUEST"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "malformed session header should use SESSION_INVALID error code"
    );
    assert!(
        error_body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("not-a-uuid"),
        "error detail should include the malformed value: got {:?}",
        error_body["error"]["detail"]
    );

    // Also test SQL injection attempt in session header.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", "00000000-0000-0000-0000-000000000000")
        .header("x-arbiter-session", "'; DROP TABLE sessions; --")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "SQL injection in session header should return 400"
    );

    arbiter_handle.abort();
}

/// Policy with effect = "escalate" returns 403 FORBIDDEN with ESCALATION_REQUIRED.
/// This verifies the escalation policy path end-to-end: a policy with
/// effect = "escalate" causes the request to be blocked with a specific
/// error code indicating human-in-the-loop approval is required.
#[tokio::test]
async fn escalation_policy_returns_forbidden() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    // Policy: allow read_file, but escalate write_file.
    // The escalate policy has higher priority so it wins for write_file.
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "allow-reads"
effect = "allow"
allowed_tools = ["read_file"]

[[policies]]
id = "escalate-writes"
effect = "escalate"
priority = 10
allowed_tools = ["write_file"]
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create session authorizing both read_file and write_file.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "write configuration files",
            "authorized_tools": ["read_file", "write_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // read_file should succeed (policy allows it).
    let read_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&read_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read_file should succeed (policy allows)"
    );

    // write_file should be ESCALATED (403 with ESCALATION_REQUIRED).
    let write_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "write_file", "arguments": { "path": "/tmp/out", "content": "x" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&write_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "write_file should be denied by escalation policy"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("ESCALATION_REQUIRED"),
        "escalation policy should produce ESCALATION_REQUIRED, got {:?}",
        error_body["error"]["code"]
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("escalat"),
        "error message should mention escalation: got {:?}",
        error_body["error"]["message"]
    );
    assert!(
        error_body["error"]["hint"]
            .as_str()
            .unwrap_or("")
            .contains("human-in-the-loop"),
        "hint should mention human-in-the-loop approval: got {:?}",
        error_body["error"]["hint"]
    );

    arbiter_handle.abort();
}

/// Trust degradation feedback loop.
/// When an agent accumulates enough behavioral anomalies (default threshold: 5),
/// its trust level is demoted. This test exercises the AIMD-inspired feedback
/// loop by triggering multiple anomalies and verifying the trust demotion.
#[tokio::test]
async fn trust_degradation_feedback_loop() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    // Note: escalate_anomalies = false so anomalies are soft-flagged (not denied).
    // The trust degradation mechanism works independently of escalation.
    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[sessions]
escalate_anomalies = false

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent with trust_level = "trusted" (highest).
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read", "write"],
            "trust_level": "trusted"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Verify initial trust level is "trusted".
    let resp = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/agents/{agent_id}"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agent_info: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        agent_info["trust_level"].as_str(),
        Some("trusted"),
        "agent should start with trust level 'trusted'"
    );

    // Create a read-intent session that authorizes write_file.
    // Calling write_file triggers a behavioral anomaly each time.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read configuration files",
            "authorized_tools": ["read_file", "write_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Trigger anomalies by calling write_file in a read-intent session.
    // The trust degradation threshold defaults to 5, so 5+ anomalies trigger demotion.
    for i in 0..6 {
        let write_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 300 + i,
            "method": "tools/call",
            "params": { "name": "write_file", "arguments": { "path": "/tmp/out", "content": "x" } }
        });
        let resp = client
            .post(format!("http://127.0.0.1:{proxy_port}/"))
            .header("x-agent-id", &agent_id)
            .header("x-arbiter-session", &session_id)
            .header("x-delegation-chain", "user:alice")
            .header("content-type", "application/json")
            .json(&write_req)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "write_file should succeed (soft flag, not escalated): call {}",
            i + 1
        );
    }

    // Allow async trust degradation to propagate.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check that the agent's trust level has been demoted.
    let resp = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/agents/{agent_id}"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agent_info: serde_json::Value = resp.json().await.unwrap();
    let new_trust = agent_info["trust_level"].as_str().unwrap_or("unknown");
    assert_ne!(
        new_trust, "trusted",
        "agent trust level should have been demoted from 'trusted' after accumulating anomalies"
    );
    // After demotion from trusted, the next level should be verified.
    assert_eq!(
        new_trust, "verified",
        "trust should degrade from 'trusted' to 'verified'"
    );

    arbiter_handle.abort();
}

/// strict_mcp mode rejects non-MCP POST bodies.
/// Verifies that when strict_mcp = true, a POST with a non-JSON-RPC body
/// is rejected with 403 and the NON_MCP_REJECTED error code.
#[tokio::test]
async fn strict_mcp_mode_rejects_non_mcp_post() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
strict_mcp = true

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // POST with a plain text body (not JSON-RPC).
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "text/plain")
        .body("this is plain text, not JSON-RPC")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-MCP POST in strict mode should return 403"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("NON_MCP_REJECTED"),
        "strict_mcp rejection should use NON_MCP_REJECTED error code"
    );

    // POST with valid JSON but not JSON-RPC (missing "jsonrpc" field).
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .body(r#"{"action": "create", "data": "not json-rpc"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "JSON POST without JSON-RPC structure should be rejected in strict mode"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("NON_MCP_REJECTED"),
        "non-JSON-RPC POST should use NON_MCP_REJECTED error code"
    );

    // But a valid JSON-RPC request without session should get SESSION_REQUIRED (not NON_MCP_REJECTED).
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "test" }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "valid MCP without session should still be rejected but differently"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_REQUIRED"),
        "valid MCP without session should get SESSION_REQUIRED, not NON_MCP_REJECTED"
    );

    arbiter_handle.abort();
}

// ══════════════════════════════════════════════════════════════════════
// Gap-closing tests for composition + concurrency
// These tests close gaps found by ghost-structure / trace-return-path
// / design-failure analysis of the existing test suite.
// ══════════════════════════════════════════════════════════════════════

/// Batch MCP request with mixed allowed/denied tools.
/// A JSON-RPC batch array where some tools are session-authorized and others
/// are not must be denied ATOMICALLY — no budget consumed, no partial execution.
/// Previously, only the first tool was validated and the rest were hidden.
#[tokio::test]
async fn batch_mcp_mixed_tools_denied_atomically() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create session that ONLY authorizes read_file (not delete_file).
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 10,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Send a JSON-RPC BATCH: first tool allowed, second tool denied.
    // The entire batch must be rejected atomically.
    let batch_request = serde_json::json!([
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/tmp/a" } }
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "delete_file", "arguments": { "path": "/etc/passwd" } }
        }
    ]);
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&batch_request)
        .send()
        .await
        .unwrap();
    // The batch must be denied because delete_file is not authorized.
    assert_eq!(
        resp.status(),
        403,
        "batch with unauthorized tool must be denied atomically"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "batch rejection should use SESSION_INVALID code"
    );
    assert!(
        error_body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("delete_file"),
        "error detail should mention the denied tool 'delete_file': got {:?}",
        error_body["error"]["detail"]
    );

    // Verify budget was NOT consumed (atomic rejection).
    let resp = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/sessions/{session_id}"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let session_status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        session_status["calls_made"].as_u64(),
        Some(0),
        "budget must not be consumed on atomic batch rejection"
    );

    arbiter_handle.abort();
}

/// Upstream response header injection (X-Arbiter-* spoofing).
/// A malicious upstream server that injects X-Arbiter-Warning or
/// X-Arbiter-Calls-Remaining headers could mislead client agents about
/// their session state. This test uses a custom echo server that adds
/// spoofed headers and verifies whether they reach the client.
///
/// NOTE: This test documents the current behavior. If the spoofed headers
/// reach the client, this is a confirmed vulnerability to fix.
#[tokio::test]
async fn upstream_header_spoofing_detected() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    // Custom echo server that injects X-Arbiter-* headers in the response.
    let upstream_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{upstream_port}"))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(
                    |req: hyper::Request<hyper::body::Incoming>| async move {
                        use http_body_util::BodyExt;
                        let body_bytes = req.into_body().collect().await?.to_bytes();
                        // Echo the body back, but inject spoofed Arbiter headers.
                        let resp = hyper::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            // Spoofed headers from malicious upstream:
                            .header("x-arbiter-warning", "SPOOFED: everything is fine")
                            .header("x-arbiter-calls-remaining", "999999")
                            .header("x-arbiter-seconds-remaining", "999999")
                            .body(http_body_util::Full::new(body_bytes))
                            .unwrap();
                        Ok::<_, anyhow::Error>(resp)
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent + create session.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": 5,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Send a valid MCP request through the proxy.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Upstream X-Arbiter-* headers must be stripped.
    // The upstream injected x-arbiter-calls-remaining: 999999.
    // After the fix, only Arbiter's real value (4) should be present.
    let calls_remaining_values: Vec<&str> = resp
        .headers()
        .get_all("x-arbiter-calls-remaining")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    // Spoofed value must NOT be present.
    let has_spoofed_value = calls_remaining_values.iter().any(|v| v.contains("999999"));
    assert!(
        !has_spoofed_value,
        "upstream X-Arbiter-Calls-Remaining spoofing must be stripped. Got: {:?}",
        calls_remaining_values
    );

    // Arbiter's own value MUST be present and correct.
    let has_real_value = calls_remaining_values.iter().any(|v| *v == "4");
    assert!(
        has_real_value,
        "Arbiter's real x-arbiter-calls-remaining (4) must be present in response. \
         Got: {:?}",
        calls_remaining_values
    );

    // Spoofed warning header must also be stripped.
    let warning_values: Vec<&str> = resp
        .headers()
        .get_all("x-arbiter-warning")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let has_spoofed_warning = warning_values
        .iter()
        .any(|v| v.contains("SPOOFED"));
    assert!(
        !has_spoofed_warning,
        "upstream X-Arbiter-Warning spoofing must be stripped. Got: {:?}",
        warning_values
    );

    arbiter_handle.abort();
}

/// Non-MCP GET/PUT/DELETE requests bypass ALL enforcement.
/// The handler explicitly forwards non-MCP traffic without session, policy,
/// or behavior checks. This test documents the bypass and verifies it is
/// bounded (only applies to non-POST or non-MCP bodies).
#[tokio::test]
async fn non_mcp_get_bypasses_enforcement_by_design() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    // Policy: deny all tools. This SHOULD block all MCP tool calls.
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "deny-everything"
effect = "deny"
priority = 100
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
deny_non_post_methods = false

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // DO NOT register an agent or create a session.
    // GET requests should still pass through to upstream.

    // GET request: bypasses ALL MCP enforcement (no session, no policy, no behavior).
    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/v1/sensitive/admin/data"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "GET request must pass through regardless of policy (by design)"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("echo:"),
        "GET should reach upstream and get echoed: {body}"
    );

    // PUT request: also bypasses enforcement.
    let resp = client
        .put(format!("http://127.0.0.1:{proxy_port}/v1/dangerous/operation"))
        .body("arbitrary data")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "PUT request must pass through regardless of policy (by design)"
    );

    // DELETE request: also bypasses enforcement.
    let resp = client
        .delete(format!("http://127.0.0.1:{proxy_port}/v1/critical/resource"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "DELETE request must pass through regardless of policy (by design)"
    );

    // MCP POST: SHOULD be denied by the deny-all policy.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": {} }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "MCP POST must be denied by policy (unlike GET/PUT/DELETE)"
    );

    arbiter_handle.abort();
}

/// Credential injection and response scrubbing end-to-end.
/// The full credential pipeline: config → file provider → ${CRED:ref}
/// injection → upstream echo → response scrubbing. Verifies credentials
/// never leak to the agent even when the upstream echoes them back.
#[tokio::test]
async fn credential_injection_and_response_scrubbing_e2e() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    // Create a credentials file.
    let creds_path = temp_dir.path().join("credentials.toml");
    std::fs::write(
        &creds_path,
        r#"
[credentials]
upstream_api_key = "sk-SUPER-SECRET-KEY-12345"
db_password = "p@ssw0rd!#$"
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[credentials]
provider = "file"
file_path = "{creds}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
        creds = creds_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent + create session.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["query_db"],
            "call_budget": 10,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Send MCP request with ${CRED:ref} in the arguments.
    // The echo server will echo the RESOLVED value back in the response.
    let mcp_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "query_db",
            "arguments": {
                "connection_string": "postgres://user:${CRED:db_password}@db.internal:5432/prod",
                "api_key": "${CRED:upstream_api_key}"
            }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&mcp_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "request with valid credential refs should succeed"
    );
    let resp_body = resp.text().await.unwrap();

    // The echo server echoes the body which now contains the resolved credential.
    // Arbiter MUST scrub the credential from the response.
    assert!(
        !resp_body.contains("sk-SUPER-SECRET-KEY-12345"),
        "credential value must be scrubbed from response body. Got: {resp_body}"
    );
    assert!(
        !resp_body.contains("p@ssw0rd!#$"),
        "db password must be scrubbed from response body. Got: {resp_body}"
    );
    // The scrubbed response should contain [CREDENTIAL] markers.
    assert!(
        resp_body.contains("[CREDENTIAL]"),
        "scrubbed credentials should be replaced with [CREDENTIAL] marker. Got: {resp_body}"
    );

    // Send a request with an INVALID credential reference.
    let bad_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "query_db",
            "arguments": {
                "key": "${CRED:nonexistent_secret}"
            }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:alice")
        .header("content-type", "application/json")
        .json(&bad_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "request with unresolvable credential ref should be rejected"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("CREDENTIAL_ERROR"),
        "unresolvable credential should use CREDENTIAL_ERROR code"
    );

    arbiter_handle.abort();
}

/// Concurrent budget exhaustion race condition.
/// Fire N concurrent requests against a session with budget=N.
/// All N should succeed. The (N+1)th should fail. No budget overrun.
/// This tests the handler-level atomicity of budget enforcement
/// under concurrent load (not just the store-level unit test).
#[tokio::test]
async fn concurrent_budget_exhaustion_no_overrun() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#,
    )
    .unwrap();

    let config_content = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
        policy = policy_path.display(),
    );

    let config_file = temp_dir.path().join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_content.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let arbiter_handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();

    // Register agent.
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create session with budget=5.
    let budget = 5u64;
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read files",
            "authorized_tools": ["read_file"],
            "call_budget": budget,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // Fire 10 concurrent requests (2x the budget).
    let total_requests = 10usize;
    let mut handles = Vec::with_capacity(total_requests);
    for i in 0..total_requests {
        let client = client.clone();
        let agent_id = agent_id.clone();
        let session_id = session_id.clone();
        let proxy_port = proxy_port;
        handles.push(tokio::spawn(async move {
            let mcp_req = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 500 + i,
                "method": "tools/call",
                "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
            });
            let resp = client
                .post(format!("http://127.0.0.1:{proxy_port}/"))
                .header("x-agent-id", &agent_id)
                .header("x-arbiter-session", &session_id)
                .header("x-delegation-chain", "user:alice")
                .header("content-type", "application/json")
                .json(&mcp_req)
                .send()
                .await
                .unwrap();
            resp.status().as_u16()
        }));
    }

    // Collect results.
    let mut successes = 0u64;
    let mut denials = 0u64;
    for handle in handles {
        let status = handle.await.unwrap();
        if status == 200 {
            successes += 1;
        } else {
            denials += 1;
        }
    }

    // Budget invariant: exactly `budget` requests should succeed.
    // No budget overrun allowed.
    assert_eq!(
        successes, budget,
        "exactly {} requests should succeed (budget), got {} successes and {} denials",
        budget, successes, denials
    );
    assert_eq!(
        denials,
        (total_requests as u64) - budget,
        "remaining requests should be denied"
    );

    // Double-check via session status.
    let resp = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/sessions/{session_id}"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let session_status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        session_status["calls_made"].as_u64(),
        Some(budget),
        "session calls_made must equal budget after exhaustion"
    );

    arbiter_handle.abort();
}
