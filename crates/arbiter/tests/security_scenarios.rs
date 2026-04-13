//! Security scenario integration tests.
//!
//! Each test corresponds to one of the 10 security demonstration scenarios
//! from the demos/ directory. Tests are marked `#[ignore]` because they spawn
//! full arbiter proxy + admin instances and a mock upstream, making them slow
//! relative to unit tests. Run with: `cargo test --test security_scenarios -- --ignored`

use std::io::Write as _;
use std::net::TcpListener;
use std::time::Duration;

// ── Shared helpers (mirrored from integration.rs) ──────────────────────

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

/// Convenience: spin up arbiter with the given TOML config string.
/// Returns (proxy_port, admin_port, JoinHandle).
async fn spawn_arbiter(
    config_toml: &str,
    config_dir: &std::path::Path,
) -> tokio::task::JoinHandle<()> {
    let config_file = config_dir.join("arbiter.toml");
    {
        let mut f = std::fs::File::create(&config_file).unwrap();
        f.write_all(config_toml.as_bytes()).unwrap();
    }

    let config = arbiter::config::ArbiterConfig::from_file(&config_file).unwrap();
    let config = std::sync::Arc::new(config);
    let config_clone = config.clone();

    let handle = tokio::spawn(async move {
        arbiter::server::run(config_clone).await.unwrap();
    });

    // Give servers time to bind.
    tokio::time::sleep(Duration::from_millis(300)).await;
    handle
}

/// Register an agent via the admin API. Returns (agent_id, token).
async fn register_agent(
    client: &reqwest::Client,
    admin_port: u16,
    owner: &str,
    capabilities: &[&str],
) -> (String, String) {
    let caps: Vec<String> = capabilities.iter().map(|s| s.to_string()).collect();
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": owner,
            "model": "test-model",
            "capabilities": caps,
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "agent registration should succeed");
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();
    let token = body["token"].as_str().unwrap().to_string();
    (agent_id, token)
}

/// Create a session via the admin API. Returns session_id.
async fn create_session(
    client: &reqwest::Client,
    admin_port: u16,
    session_json: serde_json::Value,
) -> String {
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&session_json)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "session creation should succeed");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["session_id"].as_str().unwrap().to_string()
}

/// Build a standard MCP tools/call JSON-RPC request.
fn mcp_tool_call(id: u64, tool_name: &str, arguments: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    })
}

/// Build a basic config TOML with allow-all policy.
fn base_config(proxy_port: u16, admin_port: u16, upstream_port: u16, policy_path: &str) -> String {
    format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy_path}"

[audit]
enabled = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#,
    )
}

// ── Scenario 1: Unauthenticated Access ─────────────────────────────────
// Demo 01: POST without session header -> 403 SESSION_REQUIRED

#[tokio::test]
#[ignore]
async fn test_unauthenticated_access() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = base_config(
        proxy_port,
        admin_port,
        upstream_port,
        &policy_path.display().to_string(),
    );
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    // Attack: MCP tool call with no session header.
    let mcp_request = mcp_tool_call(1, "read_file", serde_json::json!({"path": "/etc/passwd"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .json(&mcp_request)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "Demo 01: MCP request without session header must be denied with 403"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_REQUIRED"),
        "Demo 01: error code must be SESSION_REQUIRED when no session header is present"
    );
    assert!(
        error_body["error"]["hint"].as_str().is_some(),
        "Demo 01: structured error should include a hint for the caller"
    );
    assert!(
        error_body["error"]["request_id"].as_str().is_some(),
        "Demo 01: structured error should include request_id for audit correlation"
    );

    handle.abort();
}

// ── Scenario 2: Protocol Injection ─────────────────────────────────────
// Demo 02: Non-MCP POST body (SQL injection, malformed JSON) -> 403 NON_MCP_REJECTED

#[tokio::test]
#[ignore]
async fn test_protocol_injection() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = base_config(
        proxy_port,
        admin_port,
        upstream_port,
        &policy_path.display().to_string(),
    );
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    // Attack 1: Plain text SQL injection payload.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "text/plain")
        .body("DELETE FROM users WHERE 1=1;")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Demo 02: plain text SQL injection POST must be rejected with 403"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("NON_MCP_REJECTED"),
        "Demo 02: plain text POST must return NON_MCP_REJECTED error code"
    );

    // Attack 2: Valid JSON but not JSON-RPC 2.0 (missing jsonrpc/method fields).
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .body(r#"{"action": "drop_table", "target": "users"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Demo 02: non-JSON-RPC JSON POST must be rejected with 403"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("NON_MCP_REJECTED"),
        "Demo 02: malformed JSON (not JSON-RPC) must return NON_MCP_REJECTED"
    );

    // Attack 3: Completely broken JSON.
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("content-type", "application/json")
        .body("this is not json at all {{{")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 403 || resp.status() == 400,
        "Demo 02: malformed JSON body must be rejected, got {}",
        resp.status()
    );

    handle.abort();
}

// ── Scenario 3: Tool Escalation ────────────────────────────────────────
// Demo 03: Agent authorized for read_file calls delete_file -> 403 SESSION_INVALID

#[tokio::test]
#[ignore]
async fn test_tool_escalation() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = base_config(
        proxy_port,
        admin_port,
        upstream_port,
        &policy_path.display().to_string(),
    );
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    // Setup: register agent with read capabilities.
    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-reader", &["read"]).await;

    // Create session scoped to read_file and list_dir only.
    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read and list project files",
            "authorized_tools": ["read_file", "list_dir"],
            "time_limit_secs": 3600,
            "call_budget": 100
        }),
    )
    .await;

    // Legitimate: read_file should pass session whitelist check.
    let read_req = mcp_tool_call(1, "read_file", serde_json::json!({"path": "/src/main.rs"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:demo-reader")
        .header("content-type", "application/json")
        .json(&read_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Demo 03: read_file (authorized tool) should succeed"
    );

    // Attack: delete_file is NOT in the session whitelist.
    let delete_req = mcp_tool_call(2, "delete_file", serde_json::json!({"path": "/etc/passwd"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("content-type", "application/json")
        .json(&delete_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Demo 03: delete_file (not in session whitelist) must be denied with 403"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "Demo 03: tool escalation must return SESSION_INVALID error code"
    );
    assert!(
        error_body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("delete_file"),
        "Demo 03: error detail should mention the denied tool name 'delete_file'"
    );

    handle.abort();
}

// ── Scenario 4: Resource Exhaustion - Rate Limit ───────────────────────
// Demo 04 Part A: Exceed rate_limit_per_minute=3 -> 4th call gets 429

#[tokio::test]
#[ignore]
async fn test_resource_exhaustion_rate_limit() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[sessions]
rate_limit_window_secs = 60

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

    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-exhaust", &["read"]).await;

    // Create session with rate_limit_per_minute = 3, large budget.
    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read project files",
            "authorized_tools": ["read_file"],
            "time_limit_secs": 3600,
            "call_budget": 100,
            "rate_limit_per_minute": 3
        }),
    )
    .await;

    // First 3 calls should succeed (within rate limit).
    for i in 1..=3 {
        let req = mcp_tool_call(
            i,
            "read_file",
            serde_json::json!({"path": format!("/file-{i}.txt")}),
        );
        let resp = client
            .post(format!("http://127.0.0.1:{proxy_port}/"))
            .header("x-agent-id", &agent_id)
            .header("x-arbiter-session", &session_id)
            .header("x-delegation-chain", "user:demo-exhaust")
            .header("content-type", "application/json")
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "Demo 04a: call {i} of 3 should succeed (within rate limit)"
        );
    }

    // 4th call should be rate-limited (429).
    let req = mcp_tool_call(4, "read_file", serde_json::json!({"path": "/file-4.txt"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:demo-exhaust")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "Demo 04a: 4th call must be rate-limited with 429 (rate_limit_per_minute=3)"
    );

    handle.abort();
}

// ── Scenario 5: Resource Exhaustion - Budget ───────────────────────────
// Demo 04 Part B: Exceed call_budget=5 -> 6th call gets 429

#[tokio::test]
#[ignore]
async fn test_resource_exhaustion_budget() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = base_config(
        proxy_port,
        admin_port,
        upstream_port,
        &policy_path.display().to_string(),
    );
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-budget", &["read"]).await;

    // Create session with call_budget = 5 (no rate limit).
    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read project files",
            "authorized_tools": ["read_file"],
            "time_limit_secs": 3600,
            "call_budget": 5
        }),
    )
    .await;

    // First 5 calls should succeed (within budget).
    for i in 1..=5 {
        let req = mcp_tool_call(
            i,
            "read_file",
            serde_json::json!({"path": format!("/file-{i}.txt")}),
        );
        let resp = client
            .post(format!("http://127.0.0.1:{proxy_port}/"))
            .header("x-agent-id", &agent_id)
            .header("x-arbiter-session", &session_id)
            .header("x-delegation-chain", "user:demo-budget")
            .header("content-type", "application/json")
            .json(&req)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "Demo 04b: call {i} of 5 should succeed (within budget)"
        );
    }

    // 6th call should exceed budget (429).
    let req = mcp_tool_call(6, "read_file", serde_json::json!({"path": "/file-6.txt"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:demo-budget")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "Demo 04b: 6th call must return 429 (call_budget=5 exhausted)"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "Demo 04b: budget exhaustion must return SESSION_INVALID error code"
    );
    assert!(
        error_body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("budget"),
        "Demo 04b: error detail should mention 'budget'"
    );

    handle.abort();
}

// ── Scenario 6: Session Replay - Expired ───────────────────────────────
// Demo 05 Part A: Use session after time_limit expires -> 408 or 403

#[tokio::test]
#[ignore]
async fn test_session_replay_expired() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = base_config(
        proxy_port,
        admin_port,
        upstream_port,
        &policy_path.display().to_string(),
    );
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-replay", &["read"]).await;

    // Create session with a very short TTL (2 seconds).
    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read project files",
            "authorized_tools": ["read_file"],
            "time_limit_secs": 2,
            "call_budget": 100
        }),
    )
    .await;

    // Immediate call should succeed (session is fresh).
    let req = mcp_tool_call(1, "read_file", serde_json::json!({"path": "/readme.txt"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:demo-replay")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Demo 05a: immediate call on fresh session should succeed"
    );

    // Wait for the session to expire.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Replay attempt: use the expired session.
    let req = mcp_tool_call(2, "read_file", serde_json::json!({"path": "/readme.txt"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:demo-replay")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 408 || status == 403,
        "Demo 05a: expired session replay must return 408 or 403, got {status}"
    );

    handle.abort();
}

// ── Scenario 7: Session Replay - Closed ────────────────────────────────
// Demo 05 Part B: Use session after closing it -> 410 or 403

#[tokio::test]
#[ignore]
async fn test_session_replay_closed() {
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
allowed_tools = ["*"]
"#,
    )
    .unwrap();

    let config = base_config(
        proxy_port,
        admin_port,
        upstream_port,
        &policy_path.display().to_string(),
    );
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-replay-close", &["read"]).await;

    // Create a long-lived session.
    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read project files",
            "authorized_tools": ["read_file"],
            "time_limit_secs": 3600,
            "call_budget": 100
        }),
    )
    .await;

    // Close the session via admin API.
    let resp = client
        .post(format!(
            "http://127.0.0.1:{admin_port}/sessions/{session_id}/close"
        ))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Demo 05b: closing session via admin API should succeed"
    );

    // Replay attempt: use the closed session.
    let req = mcp_tool_call(1, "read_file", serde_json::json!({"path": "/readme.txt"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:demo-replay-close")
        .header("content-type", "application/json")
        .json(&req)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 410 || status == 403,
        "Demo 05b: closed session replay must return 410 or 403, got {status}"
    );

    handle.abort();
}

// ── Scenario 8: Zero-Trust Policy ──────────────────────────────────────
// Demo 06: Wrong principal for policy-restricted tool -> 403 POLICY_DENIED

#[tokio::test]
#[ignore]
async fn test_zero_trust_policy() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    // Only user:trusted-team can use deploy_service. All others are denied.
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "allow-trusted-deploy"
effect = "allow"
allowed_tools = ["deploy_service"]
[policies.principal_match]
sub = "user:trusted-team"
[policies.intent_match]
keywords = ["deploy"]
"#,
    )
    .unwrap();

    let config = format!(
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
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    // Register the attacker agent (user:rogue-contractor, NOT user:trusted-team).
    let (agent_id, _token) = register_agent(
        &client,
        admin_port,
        "user:rogue-contractor",
        &["read", "deploy"],
    )
    .await;

    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "deploy the application to production",
            "authorized_tools": ["deploy_service"],
            "time_limit_secs": 3600,
            "call_budget": 100
        }),
    )
    .await;

    // Attack: rogue-contractor tries deploy_service.
    // Policy requires principal = user:trusted-team but attacker is user:rogue-contractor.
    let deploy_req = mcp_tool_call(
        1,
        "deploy_service",
        serde_json::json!({
            "service": "payment-gateway",
            "environment": "production",
            "version": "9.9.9-backdoor"
        }),
    );
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header(
            "x-delegation-chain",
            format!("user:rogue-contractor>{agent_id}"),
        )
        .header("content-type", "application/json")
        .json(&deploy_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Demo 06: unauthorized principal must be denied with 403 (deny-by-default)"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("POLICY_DENIED"),
        "Demo 06: no matching Allow policy must return POLICY_DENIED error code"
    );

    handle.abort();
}

// ── Scenario 9: Parameter Tampering ────────────────────────────────────
// Demo 07: max_tokens=50000 when policy max is 1000 -> 403 POLICY_DENIED

#[tokio::test]
#[ignore]
async fn test_parameter_tampering() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    // Allow generate_text only when max_tokens <= 1000 and temperature in [0, 2].
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "allow-generate-bounded"
effect = "allow"
allowed_tools = ["generate_text"]
[[policies.parameter_constraints]]
key = "max_tokens"
max_value = 1000.0
min_value = 1.0
[[policies.parameter_constraints]]
key = "temperature"
max_value = 2.0
min_value = 0.0
"#,
    )
    .unwrap();

    let config = format!(
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
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-tamper", &["generate"]).await;

    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "generate text summaries",
            "authorized_tools": ["generate_text"],
            "time_limit_secs": 3600,
            "call_budget": 100
        }),
    )
    .await;

    // Legitimate: max_tokens = 500 (within constraint).
    let legit_req = mcp_tool_call(
        1,
        "generate_text",
        serde_json::json!({
            "prompt": "Summarize the quarterly report",
            "max_tokens": 500,
            "temperature": 0.7
        }),
    );
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", format!("user:demo-tamper>{agent_id}"))
        .header("content-type", "application/json")
        .json(&legit_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Demo 07: generate_text with max_tokens=500 (within 1000 limit) should succeed"
    );

    // Attack: max_tokens = 50000 (exceeds policy constraint of 1000).
    let tamper_req = mcp_tool_call(
        2,
        "generate_text",
        serde_json::json!({
            "prompt": "Generate an extremely long document to consume resources",
            "max_tokens": 50000,
            "temperature": 0.7
        }),
    );
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", format!("user:demo-tamper>{agent_id}"))
        .header("content-type", "application/json")
        .json(&tamper_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Demo 07: max_tokens=50000 (exceeding 1000 limit) must be denied with 403"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("POLICY_DENIED"),
        "Demo 07: parameter constraint violation must return POLICY_DENIED"
    );

    handle.abort();
}

// ── Scenario 10: Intent Drift ──────────────────────────────────────────
// Demo 08: Read-intent session calling write tool with escalate_anomalies -> 403 BEHAVIORAL_ANOMALY

#[tokio::test]
#[ignore]
async fn test_intent_drift() {
    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.toml");
    // Allow both read and write tools at the policy level.
    // The behavioral anomaly detector catches the intent mismatch.
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "allow-all-file-ops"
effect = "allow"
allowed_tools = ["read_file", "list_dir", "write_file", "delete_file"]
"#,
    )
    .unwrap();

    // Key: escalate_anomalies = true turns soft behavioral flags into hard denies.
    let config = format!(
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
    let handle = spawn_arbiter(&config, temp_dir.path()).await;
    let client = reqwest::Client::new();

    let (agent_id, _token) =
        register_agent(&client, admin_port, "user:demo-drifter", &["read", "write"]).await;

    // Create a session with read-only INTENT but write tools in the whitelist.
    // Policy allows write tools. Session whitelist allows write tools.
    // But the declared intent is "read and analyze" -- a read-only intent.
    let session_id = create_session(
        &client,
        admin_port,
        serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "read and analyze the source code",
            "authorized_tools": ["read_file", "list_dir", "write_file", "delete_file"],
            "time_limit_secs": 3600,
            "call_budget": 100
        }),
    )
    .await;

    // Legitimate: read_file matches the "read and analyze" intent.
    let read_req = mcp_tool_call(1, "read_file", serde_json::json!({"path": "/src/main.rs"}));
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header(
            "x-delegation-chain",
            format!("user:demo-drifter>{agent_id}"),
        )
        .header("content-type", "application/json")
        .json(&read_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Demo 08: read_file in read-intent session should succeed"
    );

    // Attack: write_file contradicts the declared read-only intent.
    // Session whitelist and policy both allow it, but the behavioral anomaly
    // detector catches the read-intent vs. write-action mismatch.
    // With escalate_anomalies = true, this escalates to a hard deny.
    let write_req = mcp_tool_call(
        2,
        "write_file",
        serde_json::json!({
            "path": "/etc/shadow",
            "content": "root::0:0:root:/root:/bin/bash"
        }),
    );
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header(
            "x-delegation-chain",
            format!("user:demo-drifter>{agent_id}"),
        )
        .header("content-type", "application/json")
        .json(&write_req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "Demo 08: write_file in read-intent session must be hard denied with escalate_anomalies=true"
    );
    let error_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        error_body["error"]["code"].as_str(),
        Some("BEHAVIORAL_ANOMALY"),
        "Demo 08: intent drift must return BEHAVIORAL_ANOMALY error code"
    );
    assert!(
        error_body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("anomaly"),
        "Demo 08: error message should mention 'anomaly', got: {:?}",
        error_body["error"]["message"]
    );

    handle.abort();
}
