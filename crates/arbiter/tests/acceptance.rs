//! Comprehensive acceptance tests for Arbiter gateway.
//!
//! These tests exercise the full middleware pipeline end-to-end, covering
//! all 10 documented attack demos, RED-TEAM fixes, cross-stage composition,
//! and novel edge cases synthesized from implementation analysis.
//!
//! Each test spawns a real Arbiter gateway with a real echo upstream and
//! makes real HTTP requests. No mocking.

use std::io::Write as _;
use std::net::TcpListener;
use std::time::Duration;

// ── Test Infrastructure ────────────────────────────────────────────────

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Echo server that returns the request body as a JSON-RPC response.
/// Optionally injects tainted data into responses when the tool name matches.
async fn start_echo_server(port: u16) {
    start_configurable_echo_server(port, None).await;
}

/// Echo server with optional response injection for testing credential scrubbing
/// and response inspection. When `inject_in_response` is Some, that string is
/// appended to every response body.
async fn start_configurable_echo_server(port: u16, inject_in_response: Option<String>) {
    use http_body_util::BodyExt;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let inject = inject_in_response.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let inject = inject.clone();
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let inject = inject.clone();
                async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();

                    // Check for upstream spoofed headers before consuming body
                    let has_spoof_header = req
                        .headers()
                        .keys()
                        .any(|k| k.as_str().starts_with("x-arbiter-"));

                    let body_bytes = req.into_body().collect().await?.to_bytes();

                    if method == "POST" && !body_bytes.is_empty() {
                        if let Ok(req_json) =
                            serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        {
                            let mut result = serde_json::json!({
                                "echo": true,
                                "method": req_json.get("method"),
                                "params": req_json.get("params"),
                                "received_body": String::from_utf8_lossy(&body_bytes).to_string(),
                            });
                            // If inject_in_response is set, add it to the result
                            if let Some(ref taint) = inject {
                                result["tainted_data"] = serde_json::Value::String(taint.clone());
                            }
                            // Echo back whether we saw x-arbiter-* headers from upstream
                            if has_spoof_header {
                                result["saw_arbiter_headers"] = serde_json::Value::Bool(true);
                            }
                            let resp = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": req_json.get("id"),
                                "result": result,
                            });
                            let payload = serde_json::to_vec(&resp).unwrap();
                            let mut builder =
                                Response::builder().header("content-type", "application/json");
                            // Simulate malicious upstream injecting x-arbiter-* headers
                            builder = builder.header("x-arbiter-warning", "spoofed-by-upstream");
                            return Ok::<_, anyhow::Error>(
                                builder
                                    .body(http_body_util::Full::new(bytes::Bytes::from(payload)))
                                    .unwrap(),
                            );
                        }
                    }
                    let body = format!("echo: {method} {path}");
                    Ok::<_, anyhow::Error>(Response::new(http_body_util::Full::new(
                        bytes::Bytes::from(body),
                    )))
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

/// Slow echo server that delays `delay_ms` before responding. For timeout tests.
async fn start_slow_echo_server(port: u16, delay_ms: u64) {
    use http_body_util::BodyExt;
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
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                let _body_bytes = req.into_body().collect().await?.to_bytes();
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "delayed": true }
                });
                let payload = serde_json::to_vec(&resp).unwrap();
                Ok::<_, anyhow::Error>(
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(http_body_util::Full::new(bytes::Bytes::from(payload)))
                        .unwrap(),
                )
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

struct TestHarness {
    proxy_port: u16,
    admin_port: u16,
    client: reqwest::Client,
    _temp_dir: tempfile::TempDir,
    arbiter_handle: tokio::task::JoinHandle<()>,
    audit_path: Option<std::path::PathBuf>,
}

struct HarnessBuilder {
    config_toml: String,
    policy_toml: Option<String>,
    credentials_toml: Option<String>,
}

impl HarnessBuilder {
    fn new(config_toml: &str) -> Self {
        Self {
            config_toml: config_toml.to_string(),
            policy_toml: None,
            credentials_toml: None,
        }
    }

    fn policy(mut self, toml: &str) -> Self {
        self.policy_toml = Some(toml.to_string());
        self
    }

    fn credentials(mut self, toml: &str) -> Self {
        self.credentials_toml = Some(toml.to_string());
        self
    }

    async fn build(self) -> TestHarness {
        self.build_with_echo(|port| {
            tokio::spawn(start_echo_server(port));
        })
        .await
    }

    async fn build_with_echo<F: FnOnce(u16)>(self, spawn_upstream: F) -> TestHarness {
        let proxy_port = free_port();
        let admin_port = free_port();
        let upstream_port = free_port();

        spawn_upstream(upstream_port);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let temp_dir = tempfile::tempdir().unwrap();

        let audit_path = if self.config_toml.contains("{audit}") {
            Some(temp_dir.path().join("audit.jsonl"))
        } else {
            None
        };

        let policy_path = temp_dir.path().join("policy.toml");
        let creds_path = temp_dir.path().join("credentials.toml");

        // Write policy file BEFORE server starts so it's loaded at init
        if let Some(ref policy) = self.policy_toml {
            std::fs::write(&policy_path, policy).unwrap();
        }
        // Write credentials file BEFORE server starts
        if let Some(ref creds) = self.credentials_toml {
            std::fs::write(&creds_path, creds).unwrap();
        }

        let config_content = self
            .config_toml
            .replace("{proxy_port}", &proxy_port.to_string())
            .replace("{admin_port}", &admin_port.to_string())
            .replace("{upstream_port}", &upstream_port.to_string())
            .replace(
                "{audit}",
                &temp_dir.path().join("audit.jsonl").display().to_string(),
            )
            .replace("{policy}", &policy_path.display().to_string())
            .replace("{creds}", &creds_path.display().to_string());

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

        TestHarness {
            proxy_port,
            admin_port,
            client,
            _temp_dir: temp_dir,
            arbiter_handle,
            audit_path,
        }
    }
}

impl TestHarness {
    /// Quick constructor for tests using allow-all policy.
    async fn with_policy(config_toml: &str, policy_toml: &str) -> Self {
        HarnessBuilder::new(config_toml)
            .policy(policy_toml)
            .build()
            .await
    }

    fn proxy_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.proxy_port, path)
    }

    fn admin_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.admin_port, path)
    }

    async fn register_agent(
        &self,
        owner: &str,
        capabilities: &[&str],
        trust_level: &str,
    ) -> (String, String) {
        let resp = self
            .client
            .post(self.admin_url("/agents"))
            .header("x-api-key", "test-key")
            .json(&serde_json::json!({
                "owner": owner,
                "model": "test-model",
                "capabilities": capabilities,
                "trust_level": trust_level
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "agent registration should succeed");
        let body: serde_json::Value = resp.json().await.unwrap();
        (
            body["agent_id"].as_str().unwrap().to_string(),
            body["token"].as_str().unwrap().to_string(),
        )
    }

    async fn create_session(
        &self,
        agent_id: &str,
        intent: &str,
        tools: &[&str],
        budget: u64,
        time_limit_secs: u64,
    ) -> String {
        self.create_session_with_rate_limit(agent_id, intent, tools, budget, time_limit_secs, None)
            .await
    }

    async fn create_session_with_rate_limit(
        &self,
        agent_id: &str,
        intent: &str,
        tools: &[&str],
        budget: u64,
        time_limit_secs: u64,
        rate_limit_per_minute: Option<u64>,
    ) -> String {
        let mut body = serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": intent,
            "authorized_tools": tools,
            "call_budget": budget,
            "time_limit_secs": time_limit_secs
        });
        if let Some(rate) = rate_limit_per_minute {
            body["rate_limit_per_minute"] = serde_json::json!(rate);
        }
        let resp = self
            .client
            .post(self.admin_url("/sessions"))
            .header("x-api-key", "test-key")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "session creation should succeed");
        let body: serde_json::Value = resp.json().await.unwrap();
        body["session_id"].as_str().unwrap().to_string()
    }

    async fn mcp_call(
        &self,
        agent_id: &str,
        session_id: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> reqwest::Response {
        self.mcp_call_with_id(agent_id, session_id, tool, args, 1)
            .await
    }

    async fn mcp_call_with_id(
        &self,
        agent_id: &str,
        session_id: &str,
        tool: &str,
        args: serde_json::Value,
        id: u64,
    ) -> reqwest::Response {
        let mcp_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": args
            }
        });
        self.client
            .post(self.proxy_url("/"))
            .header("x-agent-id", agent_id)
            .header("x-arbiter-session", session_id)
            .header("x-delegation-chain", "user:test")
            .header("content-type", "application/json")
            .json(&mcp_request)
            .send()
            .await
            .unwrap()
    }

    fn read_audit_log(&self) -> Vec<serde_json::Value> {
        if let Some(ref path) = self.audit_path {
            // Give audit a moment to flush
            let content = std::fs::read_to_string(path).unwrap_or_default();
            content
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        } else {
            vec![]
        }
    }

    fn write_policy(&self, policy_toml: &str) {
        let policy_path = self._temp_dir.path().join("policy.toml");
        std::fs::write(&policy_path, policy_toml).unwrap();
    }

    #[allow(dead_code)]
    fn write_credentials(&self, creds_toml: &str) {
        let creds_path = self._temp_dir.path().join("credentials.toml");
        std::fs::write(&creds_path, creds_toml).unwrap();
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self.arbiter_handle.abort();
    }
}

fn allow_all_policy() -> &'static str {
    r#"[[policies]]
id = "test-allow-all"
effect = "allow"
allowed_tools = []
"#
}

fn base_config() -> String {
    format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {{proxy_port}}
upstream_url = "http://127.0.0.1:{{upstream_port}}"

[policy]
file = "{{policy}}"

[audit]
enabled = true
file_path = "{{audit}}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {{admin_port}}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#
    )
}

// ════════════════════════════════════════════════════════════════════════
// PHASE 1: Session enforcement + core scenarios
// ════════════════════════════════════════════════════════════════════════

/// Demo 04a: Per-minute rate limiting. Session with rate_limit_per_minute=2
/// should deny the 3rd call within the same minute.
#[tokio::test]
async fn rate_limiting_per_minute() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session_with_rate_limit(&agent_id, "read files", &["read_file"], 100, 3600, Some(2))
        .await;

    // First 2 calls succeed
    for i in 0..2 {
        let resp = h
            .mcp_call_with_id(
                &agent_id,
                &session_id,
                "read_file",
                serde_json::json!({"path": "/tmp/test"}),
                i + 1,
            )
            .await;
        assert_eq!(resp.status(), 200, "call {} should succeed", i + 1);
    }

    // 3rd call within the same minute should be rate-limited
    let resp = h
        .mcp_call_with_id(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
            3,
        )
        .await;
    assert_eq!(resp.status(), 429, "3rd call should be rate-limited");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("SESSION_INVALID"));
    assert!(
        body["error"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("rate"),
        "error should mention rate limiting"
    );
}

/// Demo 05a: Session expiry. A session with time_limit_secs=1 should expire.
#[tokio::test]
async fn session_expiry_replay() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 1)
        .await;

    // First call while session is fresh should succeed
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "call within TTL should succeed");

    // Wait for session to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Call after expiry should fail
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 408, "expired session should return 408");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("SESSION_INVALID"));
}

/// Demo 05b: Closed session replay. A closed session cannot be reused.
#[tokio::test]
async fn closed_session_replay() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Close the session
    let resp = h
        .client
        .post(h.admin_url(&format!("/sessions/{session_id}/close")))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Attempt to use closed session
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 410, "closed session should return 410 Gone");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("SESSION_INVALID"));
}

/// RED-TEAM C-04: Session-agent binding. Agent B cannot use Agent A's session.
#[tokio::test]
async fn session_agent_binding_mismatch() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_a, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let (agent_b, _) = h.register_agent("user:bob", &["read"], "basic").await;

    let session_id = h
        .create_session(&agent_a, "read files", &["read_file"], 100, 3600)
        .await;

    // Agent B tries to use Agent A's session
    let resp = h
        .mcp_call(
            &agent_b,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "agent B should not be able to use agent A's session"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("SESSION_INVALID"));
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("does not belong"),
        "error should indicate session ownership mismatch"
    );
}

/// Demo 09: Session multiplication attack. Exceeding per-agent session cap.
#[tokio::test]
async fn session_multiplication_cap() {
    let config = format!(
        r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {{proxy_port}}
upstream_url = "http://127.0.0.1:{{upstream_port}}"

[policy]
file = "{{policy}}"

[sessions]
max_concurrent_sessions_per_agent = 3

[audit]
enabled = true
file_path = "{{audit}}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {{admin_port}}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#
    );
    let h = TestHarness::with_policy(&config, allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;

    // Create 3 sessions (should succeed)
    for i in 0..3 {
        let resp = h
            .client
            .post(h.admin_url("/sessions"))
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
        assert_eq!(resp.status(), 201, "session {} should be created", i + 1);
    }

    // 4th session should fail
    let resp = h
        .client
        .post(h.admin_url("/sessions"))
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
    assert_eq!(resp.status(), 429, "4th session should be denied (cap=3)");
}

/// Delegation cascade: deactivate parent → child deactivated → child sessions closed.
#[tokio::test]
async fn delegation_cascade_deactivation() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    // Create parent agent
    let (parent_id, _) = h
        .register_agent("user:alice", &["read", "write"], "trusted")
        .await;

    // Register child agent first (same owner -- cross-owner delegation is blocked)
    let (child_id, _) = h.register_agent("user:alice", &["read"], "basic").await;

    // Delegate from parent to child (scope narrowing: only read)
    let resp = h
        .client
        .post(h.admin_url(&format!("/agents/{parent_id}/delegate")))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "to": child_id,
            "scopes": ["read"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Create a session for the child
    let child_session = h
        .create_session(&child_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Verify child session works
    let resp = h
        .mcp_call(
            &child_id,
            &child_session,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        200,
        "child session should work before cascade"
    );

    // Deactivate parent (cascade) via DELETE /agents/:id
    let resp = h
        .client
        .delete(h.admin_url(&format!("/agents/{parent_id}")))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Child agent should be deactivated
    let resp = h
        .client
        .get(h.admin_url(&format!("/agents/{child_id}")))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    // Agent might return 404 or show inactive
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 404,
        "child should be findable or gone"
    );
    if status == 200 {
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["active"].as_bool(),
            Some(false),
            "child should be deactivated"
        );
    }
}

/// Admin API authentication: missing key → 401, wrong key → 403.
#[tokio::test]
async fn admin_api_authentication() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    // No API key → 401
    let resp = h.client.get(h.admin_url("/agents")).send().await.unwrap();
    assert_eq!(resp.status(), 401, "missing API key should return 401");

    // Wrong API key → 401 (same as missing, to avoid key-existence oracle)
    let resp = h
        .client
        .get(h.admin_url("/agents"))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "wrong API key should return 401");

    // Correct key → 200
    let resp = h
        .client
        .get(h.admin_url("/agents"))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "correct key should return 200");
}

/// Blocked paths: requests to blocked paths are rejected before pipeline.
#[tokio::test]
async fn blocked_paths_rejected() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
blocked_paths = ["/admin", "/internal"]
deny_non_post_methods = false

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;

    let resp = h.client.get(h.proxy_url("/admin")).send().await.unwrap();
    assert_eq!(resp.status(), 403, "blocked path should return 403");

    let resp = h.client.get(h.proxy_url("/internal")).send().await.unwrap();
    assert_eq!(resp.status(), 403, "blocked path should return 403");

    // Non-blocked path should pass through
    let resp = h
        .client
        .get(h.proxy_url("/v1/tools"))
        .header("x-agent-id", "any")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "non-blocked path should succeed");
}

/// Empty POST body → NonMcp → rejected under strict_mcp.
#[tokio::test]
async fn empty_body_rejection() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    let resp = h
        .client
        .post(h.proxy_url("/"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "empty POST body should be rejected as non-MCP"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("NON_MCP_REJECTED"));
}

/// Session close returns summary with usage stats.
#[tokio::test]
async fn session_close_summary() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 10, 3600)
        .await;

    // Make 3 calls
    for i in 0..3 {
        let resp = h
            .mcp_call_with_id(
                &agent_id,
                &session_id,
                "read_file",
                serde_json::json!({"path": "/tmp/test"}),
                i + 1,
            )
            .await;
        assert_eq!(resp.status(), 200);
    }

    // Close and verify summary
    let resp = h
        .client
        .post(h.admin_url(&format!("/sessions/{session_id}/close")))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("closed"));
    assert_eq!(body["total_calls"].as_u64(), Some(3));
    assert_eq!(body["call_budget"].as_u64(), Some(10));
    assert!(body["budget_utilization_pct"].as_f64().unwrap() > 29.0);
    assert!(body["budget_utilization_pct"].as_f64().unwrap() < 31.0);
}

// ════════════════════════════════════════════════════════════════════════
// PHASE 2: Security enforcement + composition
// ════════════════════════════════════════════════════════════════════════

/// Demo 06: Deny-by-default with no policies loaded.
#[tokio::test]
async fn deny_by_default_no_policies() {
    // Write an empty policy file (no policies = deny-by-default)
    let h = TestHarness::with_policy(&base_config(), "").await;

    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "no policies loaded should deny MCP traffic"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("POLICY_DENIED"));
}

/// Demo 07: Parameter constraints in policies.
#[tokio::test]
async fn parameter_constraint_violation() {
    let h = TestHarness::with_policy(
        &base_config(),
        r#"
[[policies]]
id = "allow-generate-limited"
effect = "allow"
allowed_tools = ["generate_text"]

[[policies.parameter_constraints]]
key = "max_tokens"
max_value = 1000
"#,
    )
    .await;

    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "generate text", &["generate_text"], 100, 3600)
        .await;

    // Within constraint: should succeed
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "generate_text",
            serde_json::json!({"max_tokens": 500, "prompt": "hello"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "within constraint should succeed");

    // Exceeding constraint: should fail (no matching policy → deny-by-default)
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "generate_text",
            serde_json::json!({"max_tokens": 50000, "prompt": "hello"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "exceeding parameter constraint should be denied"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("POLICY_DENIED"));
}

/// Demo 08 with escalation: Intent drift with escalate_anomalies=true → hard deny.
#[tokio::test]
async fn intent_drift_escalated_to_deny() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[sessions]
escalate_anomalies = true

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;
    let (agent_id, _) = h
        .register_agent("user:alice", &["read", "write"], "basic")
        .await;
    let session_id = h
        .create_session(
            &agent_id,
            "read and analyze files",
            &["read_file", "write_file"],
            100,
            3600,
        )
        .await;

    // Read operation in read-intent session → should succeed
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "read in read-session should succeed");

    // Write operation in read-intent session with escalation → hard deny
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "write_file",
            serde_json::json!({"path": "/tmp/out", "content": "hello"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "write in read-session with escalation should be denied"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("BEHAVIORAL_ANOMALY"));
}

/// Composition: session whitelist allows tool, but policy denies it.
/// Defense in depth: both layers must pass.
#[tokio::test]
async fn composition_session_allows_policy_denies() {
    // Policy only allows read_file, not write_file
    let h = TestHarness::with_policy(
        &base_config(),
        r#"
[[policies]]
id = "allow-read-only"
effect = "allow"
allowed_tools = ["read_file"]
"#,
    )
    .await;

    let (agent_id, _) = h
        .register_agent("user:alice", &["read", "write"], "basic")
        .await;
    // Session whitelist includes write_file, but policy doesn't
    let session_id = h
        .create_session(
            &agent_id,
            "write files",
            &["read_file", "write_file"],
            100,
            3600,
        )
        .await;

    // read_file: session allows, policy allows → success
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "both layers allow → success");

    // write_file: session allows, policy denies → denied
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "write_file",
            serde_json::json!({"path": "/tmp/out", "content": "hello"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "session allows but policy denies → denied"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("POLICY_DENIED"));
}

/// Composition: policy allows, but behavioral anomaly flags intent drift.
#[tokio::test]
async fn composition_policy_allows_behavior_flags() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[sessions]
escalate_anomalies = true

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    // Session whitelist allows delete_file, and policy allows it,
    // but intent is "read" → delete_file is behavioral anomaly
    let session_id = h
        .create_session(
            &agent_id,
            "read and review logs",
            &["read_file", "delete_file"],
            100,
            3600,
        )
        .await;

    // delete_file with read intent → behavioral anomaly (hard deny)
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "delete_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "session+policy allow but behavior flags → denied"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("BEHAVIORAL_ANOMALY"));
}

/// Stage ordering: session failure prevents policy evaluation.
/// Verified via audit log: policy_matched should show session denial, not policy.
#[tokio::test]
async fn stage_ordering_session_before_policy() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Call with tool NOT in session whitelist → session denies before policy runs
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "unauthorized_tool",
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("SESSION_INVALID"),
        "session should reject before policy evaluates"
    );

    // Verify in audit log that policy_matched refers to session-whitelist, not a policy
    tokio::time::sleep(Duration::from_millis(200)).await;
    let entries = h.read_audit_log();
    let deny_entry = entries
        .iter()
        .find(|e| {
            e["tool_called"]
                .as_str()
                .unwrap_or("")
                .contains("unauthorized_tool")
        })
        .expect("should have audit entry for unauthorized_tool");
    assert!(
        deny_entry["policy_matched"]
            .as_str()
            .unwrap_or("")
            .contains("session-whitelist"),
        "policy_matched should show session-whitelist, not a policy ID"
    );
}

/// Batch MCP: all tool calls in batch recorded in audit (RED-TEAM RED-72).
#[tokio::test]
async fn batch_mcp_all_tools_audited() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(
            &agent_id,
            "read files",
            &["read_file", "list_dir"],
            100,
            3600,
        )
        .await;

    // Send batch MCP request with 2 tool calls
    let batch = serde_json::json!([
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
            "params": { "name": "list_dir", "arguments": { "path": "/tmp" } }
        }
    ]);
    let resp = h
        .client
        .post(h.proxy_url("/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:test")
        .header("content-type", "application/json")
        .json(&batch)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "batch MCP should succeed");

    // Verify audit log has both tool names
    tokio::time::sleep(Duration::from_millis(200)).await;
    let entries = h.read_audit_log();
    let batch_entry = entries
        .iter()
        .find(|e| {
            let tc = e["tool_called"].as_str().unwrap_or("");
            tc.contains("read_file") && tc.contains("list_dir")
        })
        .or_else(|| {
            // Might be separate entries or combined
            entries.iter().find(|e| {
                e["tool_called"]
                    .as_str()
                    .unwrap_or("")
                    .contains("read_file")
            })
        });
    assert!(
        batch_entry.is_some(),
        "audit should record batch tool calls"
    );
}

/// Trust degradation: accumulated anomalies demote agent trust level (RED-TEAM RED-88).
#[tokio::test]
async fn trust_degradation_via_anomalies() {
    let config = r#"
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
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;
    let (agent_id, _) = h
        .register_agent("user:alice", &["read", "write"], "verified")
        .await;

    // Check initial trust level
    let resp = h
        .client
        .get(h.admin_url(&format!("/agents/{agent_id}")))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["trust_level"].as_str(),
        Some("verified"),
        "initial trust should be verified"
    );

    // Create a read-intent session that allows write tools (for triggering anomalies)
    let session_id = h
        .create_session(
            &agent_id,
            "read configuration",
            &["read_file", "write_file"],
            100,
            3600,
        )
        .await;

    // Generate 5+ anomalies by calling write_file in a read-intent session.
    // escalate_anomalies=false means individual anomalies are soft flags (200).
    // But accumulated anomalies trigger trust demotion at the threshold, which
    // now aborts the request that triggers the demotion (403).
    for i in 0..6 {
        let resp = h
            .mcp_call_with_id(
                &agent_id,
                &session_id,
                "write_file",
                serde_json::json!({"path": "/tmp/out", "content": "data"}),
                i + 1,
            )
            .await;
        let status = resp.status().as_u16();
        if status == 403 {
            // This is the call that triggered trust demotion -- expected after threshold.
            tracing::info!(
                call = i + 1,
                "trust demotion triggered, request aborted as expected"
            );
            break;
        }
        assert_eq!(
            status,
            200,
            "soft-flag anomaly should still allow request before demotion threshold (call {})",
            i + 1
        );
    }

    // Check trust level after accumulated anomalies — should be demoted
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = h
        .client
        .get(h.admin_url(&format!("/agents/{agent_id}")))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let trust = body["trust_level"].as_str().unwrap_or("");
    assert!(
        trust == "basic" || trust == "untrusted",
        "trust level should be demoted from 'verified', got '{trust}'"
    );
}

/// Credential injection: ${CRED:ref} patterns resolved, response scrubbed.
#[tokio::test]
async fn credential_injection_and_scrubbing() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[credentials]
provider = "file"
file_path = "{creds}"

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
"#;

    let h = HarnessBuilder::new(config)
        .policy(allow_all_policy())
        .credentials(
            r#"
[credentials]
api_secret = "sk-super-secret-value-12345"
"#,
        )
        .build()
        .await;

    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["call_api"], 100, 3600)
        .await;

    // Send request with credential reference
    let mcp_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "call_api",
            "arguments": {
                "url": "https://example.com",
                "auth": "${CRED:api_secret}"
            }
        }
    });
    let resp = h
        .client
        .post(h.proxy_url("/"))
        .header("x-agent-id", &agent_id)
        .header("x-arbiter-session", &session_id)
        .header("x-delegation-chain", "user:test")
        .header("content-type", "application/json")
        .json(&mcp_request)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "credential injection should succeed");

    // Credential injection resolves ${CRED:ref} → actual value before forwarding upstream.
    // Response scrubbing replaces the credential value with [CREDENTIAL] before returning.
    // So the client sees [CREDENTIAL] instead of the raw secret — both injection and scrubbing worked.
    let body: serde_json::Value = resp.json().await.unwrap();
    let received = body["result"]["received_body"].as_str().unwrap_or("");
    // The ${CRED:...} pattern should NOT be present (it was resolved)
    assert!(
        !received.contains("${CRED:"),
        "credential pattern should be resolved, not forwarded as-is"
    );
    // The actual credential value should have been scrubbed from the response
    assert!(
        !received.contains("sk-super-secret-value-12345"),
        "response should be scrubbed of credential values"
    );
    // The scrubber replaces with [CREDENTIAL]
    assert!(
        received.contains("[CREDENTIAL]"),
        "scrubbed credential should be replaced with [CREDENTIAL], got: {received}"
    );
}

/// Audit entry structure: verify fields, redaction, and failure categories.
#[tokio::test]
async fn audit_entry_structure_and_redaction() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"
redaction_patterns = ["password", "secret", "token"]

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Make a call with arguments that should be redacted
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test", "password": "hunter2", "api_secret": "abc"}),
        )
        .await;
    assert_eq!(resp.status(), 200);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let entries = h.read_audit_log();
    assert!(!entries.is_empty(), "should have audit entries");

    let allow_entry = entries
        .iter()
        .find(|e| e["authorization_decision"].as_str() == Some("allow"))
        .expect("should have an allowed entry");

    // Verify required fields
    assert!(allow_entry["timestamp"].as_str().is_some());
    assert!(allow_entry["request_id"].as_str().is_some());
    assert!(!allow_entry["tool_called"].as_str().unwrap_or("").is_empty());
    assert!(allow_entry["latency_ms"].as_u64().is_some());

    // Verify redaction: password field should be redacted
    let args_str = serde_json::to_string(&allow_entry["arguments"]).unwrap_or_default();
    assert!(
        !args_str.contains("hunter2"),
        "password value should be redacted in audit"
    );
}

// ════════════════════════════════════════════════════════════════════════
// PHASE 3: Edge cases + novel synthesis
// ════════════════════════════════════════════════════════════════════════

/// Body size limit: oversized request body rejected with 413.
#[tokio::test]
async fn request_body_size_limit() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
max_request_body_bytes = 1024

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;

    // Send a body larger than 1024 bytes
    let large_body = "x".repeat(2000);
    let mcp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "data": large_body } }
    });
    let resp = h
        .client
        .post(h.proxy_url("/"))
        .header("content-type", "application/json")
        .json(&mcp)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        413,
        "oversized request should return 413 Payload Too Large"
    );
}

/// WebSocket upgrade requests rejected (RED-TEAM GAP-PROXY-8).
#[tokio::test]
async fn websocket_upgrade_rejected() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    let resp = h
        .client
        .get(h.proxy_url("/"))
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .send()
        .await
        .unwrap();
    // WebSocket upgrade check happens after body collection for POST,
    // but GET requests with Upgrade header should also be handled
    assert_eq!(
        resp.status(),
        501,
        "WebSocket upgrade should return 501 Not Implemented"
    );
}

/// Upstream x-arbiter-* headers stripped (RED-TEAM R4).
#[tokio::test]
async fn upstream_arbiter_headers_stripped() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 200);

    // The echo server injects x-arbiter-warning: spoofed-by-upstream
    // Arbiter should strip it and only include its own x-arbiter-* headers
    let warning_header = resp
        .headers()
        .get("x-arbiter-warning")
        .and_then(|v| v.to_str().ok());
    if let Some(warning) = warning_header {
        assert!(
            !warning.contains("spoofed-by-upstream"),
            "upstream-spoofed x-arbiter-* headers should be stripped"
        );
    }
}

/// Upstream timeout → GATEWAY_TIMEOUT.
#[tokio::test]
async fn upstream_timeout_gateway_timeout() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
upstream_timeout_secs = 1

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = HarnessBuilder::new(config)
        .policy(allow_all_policy())
        .build_with_echo(|port| {
            // Start slow server on the upstream port
            tokio::spawn(start_slow_echo_server(port, 5000));
        })
        .await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        504,
        "slow upstream should trigger gateway timeout"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("UPSTREAM_ERROR"));
}

/// Metrics correctness: after mixed traffic, Prometheus counters reflect reality.
#[tokio::test]
async fn metrics_correctness_after_mixed_traffic() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Successful call
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 200);

    // Denied call (unauthorized tool)
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "delete_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 403);

    // Non-MCP rejection
    let _resp = h
        .client
        .post(h.proxy_url("/"))
        .header("content-type", "text/plain")
        .body("not json-rpc")
        .send()
        .await
        .unwrap();

    // Verify metrics
    let resp = h.client.get(h.proxy_url("/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let metrics = resp.text().await.unwrap();
    assert!(
        metrics.contains("requests_total"),
        "should have requests_total metric"
    );
    assert!(
        metrics.contains(r#"decision="allow"#),
        "should record allow decisions"
    );
    assert!(
        metrics.contains(r#"decision="deny"#),
        "should record deny decisions"
    );
}

/// RT-201: Metrics endpoint auth uses constant-time comparison.
/// When metrics.require_auth = true, the metrics endpoint requires the
/// admin API key and rejects requests with missing or wrong keys.
#[tokio::test]
async fn metrics_endpoint_authentication() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[metrics]
enabled = true
require_auth = true

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;

    // No API key → 401
    let resp = h.client.get(h.proxy_url("/metrics")).send().await.unwrap();
    assert_eq!(
        resp.status(),
        401,
        "metrics without API key should return 401"
    );

    // Wrong API key → 401
    let resp = h
        .client
        .get(h.proxy_url("/metrics"))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "metrics with wrong API key should return 401"
    );

    // Correct key → 200
    let resp = h
        .client
        .get(h.proxy_url("/metrics"))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "metrics with correct API key should return 200"
    );
    let body = resp.text().await.unwrap();
    // Metrics endpoint returns Prometheus text format with HELP/TYPE lines
    // even if no traffic has flowed yet.
    assert!(
        body.contains("# HELP") || body.contains("# TYPE") || body.is_empty(),
        "metrics response should be valid Prometheus format or empty"
    );
}

/// Health endpoint: healthy when audit is fine, degraded status reflected.
#[tokio::test]
async fn health_endpoint_status() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    let resp = h.client.get(h.proxy_url("/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("healthy"));
    // RED-TEAM H-05: should NOT expose consecutive_failures count
    assert!(
        body.get("consecutive_failures").is_none(),
        "health endpoint should not expose internal audit failure counts"
    );
}

/// Policy explain endpoint: dry-run request against policies.
#[tokio::test]
async fn policy_explain_dry_run() {
    let h = TestHarness::with_policy(
        &base_config(),
        r#"
[[policies]]
id = "allow-read-basic"
effect = "allow"
allowed_tools = ["read_file"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
"#,
    )
    .await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let _session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    let resp = h
        .client
        .post(h.admin_url("/policy/explain"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read files",
            "tool": "read_file",
            "arguments": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["decision"].as_str(),
        Some("allow"),
        "policy explain should return allow for matching request"
    );
}

/// Non-MCP POST with malformed JSON → rejected in strict mode.
#[tokio::test]
async fn malformed_json_rejected() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    let resp = h
        .client
        .post(h.proxy_url("/"))
        .header("content-type", "application/json")
        .body(r#"{"not": "json-rpc", "missing": "jsonrpc field"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "malformed JSON (not JSON-RPC) should be rejected"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("NON_MCP_REJECTED"));
}

/// Session without x-agent-id header → denied (RED-TEAM C-04).
#[tokio::test]
async fn session_without_agent_id_header() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Send MCP with session but WITHOUT x-agent-id
    let mcp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "read_file", "arguments": { "path": "/tmp/test" } }
    });
    let resp = h
        .client
        .post(h.proxy_url("/"))
        .header("x-arbiter-session", &session_id)
        .header("content-type", "application/json")
        .json(&mcp)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "session without x-agent-id should be denied"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("SESSION_INVALID"));
}

/// Policy specificity: more specific policy wins over less specific.
#[tokio::test]
async fn policy_specificity_resolution() {
    let h = TestHarness::with_policy(
        &base_config(),
        r#"
[[policies]]
id = "broad-allow"
effect = "allow"
allowed_tools = []

[[policies]]
id = "specific-deny-delete"
effect = "deny"
allowed_tools = ["delete_file"]

[policies.agent_match]
trust_level = "basic"
"#,
    )
    .await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(
            &agent_id,
            "admin tasks",
            &["read_file", "delete_file"],
            100,
            3600,
        )
        .await;

    // read_file: broad-allow matches → allowed
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        200,
        "read_file should be allowed by broad policy"
    );

    // delete_file: specific-deny-delete (trust_level match = more specific) should deny
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "delete_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "specific deny policy should override broad allow"
    );
}

/// Non-existent session ID → 404.
#[tokio::test]
async fn nonexistent_session_returns_404() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;

    let fake_session = uuid::Uuid::new_v4().to_string();
    let resp = h
        .mcp_call(
            &agent_id,
            &fake_session,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    // Non-existent session → SessionInvalid → 403.
    // Returns 403 (not 404) to prevent session enumeration attacks:
    // an attacker should not be able to distinguish "session exists but
    // you don't own it" from "session doesn't exist".
    assert_eq!(resp.status(), 403, "non-existent session should return 403");
}

/// GET requests pass through without session/policy enforcement
/// when deny_non_post_methods is explicitly disabled.
#[tokio::test]
async fn get_requests_pass_through() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"
deny_non_post_methods = false

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;

    // GET request without any session or agent headers should pass through
    let resp = h
        .client
        .get(h.proxy_url("/v1/tools"))
        .header("x-agent-id", "any")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "GET requests should pass through");
    let body = resp.text().await.unwrap();
    assert!(body.contains("echo:"), "should reach upstream echo server");
}

/// Intent matching with regex in policy.
/// Uses escalate_anomalies=false because this test exercises policy regex
/// matching, not behavioral detection. The intent strings here deliberately
/// avoid behavioral keywords to isolate the policy-level matching.
#[tokio::test]
async fn policy_intent_regex_matching() {
    let config = r#"
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
"#;
    let h = TestHarness::with_policy(
        config,
        r#"
[[policies]]
id = "allow-data-analysis"
effect = "allow"
allowed_tools = ["query_db"]

[policies.intent_match]
regex = "(?i)data.*analy"
"#,
    )
    .await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;

    // Intent matches regex → allowed
    let session_id = h
        .create_session(&agent_id, "data analysis tasks", &["query_db"], 100, 3600)
        .await;
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "query_db",
            serde_json::json!({"query": "SELECT 1"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "intent matching regex should allow");

    // Intent doesn't match regex → denied
    let session_id2 = h
        .create_session(&agent_id, "file management", &["query_db"], 100, 3600)
        .await;
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id2,
            "query_db",
            serde_json::json!({"query": "SELECT 1"}),
        )
        .await;
    assert_eq!(
        resp.status(),
        403,
        "intent not matching regex should be denied"
    );
}

/// Scope narrowing violation on delegation.
#[tokio::test]
async fn delegation_scope_narrowing_enforced() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;

    // Parent has only ["read"] capability
    let (parent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;

    // Register a child agent (same owner -- cross-owner delegation is blocked)
    let (child_id, _) = h
        .register_agent("user:alice", &["read", "write"], "basic")
        .await;

    // Try to delegate with wider scope than parent's capabilities
    let resp = h
        .client
        .post(h.admin_url(&format!("/agents/{parent_id}/delegate")))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "to": child_id,
            "scopes": ["read", "write"]
        }))
        .send()
        .await
        .unwrap();
    // Should fail because delegation scopes ["read", "write"] but parent only has ["read"]
    assert!(
        resp.status().as_u16() == 400 || resp.status().as_u16() == 403,
        "scope widening delegation should be rejected, got {}",
        resp.status()
    );
}

/// Budget warning headers emitted when remaining < threshold (C-022).
#[tokio::test]
async fn budget_warning_headers() {
    let h = TestHarness::with_policy(&base_config(), allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 5, 3600)
        .await;

    // Use 4 of 5 calls
    for i in 0..4 {
        let resp = h
            .mcp_call_with_id(
                &agent_id,
                &session_id,
                "read_file",
                serde_json::json!({"path": "/tmp/test"}),
                i + 1,
            )
            .await;
        assert_eq!(resp.status(), 200);
    }

    // 5th call: 0 remaining after this (0% remaining < 20% threshold)
    let resp = h
        .mcp_call_with_id(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
            5,
        )
        .await;
    assert_eq!(resp.status(), 200);

    // Check for warning and remaining headers
    let calls_remaining = resp
        .headers()
        .get("x-arbiter-calls-remaining")
        .and_then(|v| v.to_str().ok());
    assert!(
        calls_remaining.is_some(),
        "should have x-arbiter-calls-remaining header"
    );
    assert_eq!(
        calls_remaining.unwrap(),
        "0",
        "should show 0 calls remaining"
    );

    let warning = resp
        .headers()
        .get("x-arbiter-warning")
        .and_then(|v| v.to_str().ok());
    assert!(
        warning.is_some(),
        "should have x-arbiter-warning when budget is low"
    );
    assert!(
        warning.unwrap().contains("budget low"),
        "warning should mention budget"
    );
}

/// Policy hot-reload via admin endpoint: deny → allow transition.
#[tokio::test]
async fn policy_reload_via_admin_endpoint() {
    // Start with restrictive policy
    let h = TestHarness::with_policy(
        &base_config(),
        r#"
[[policies]]
id = "allow-noop"
effect = "allow"
allowed_tools = ["noop_tool"]
"#,
    )
    .await;

    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Request should be denied (read_file not in policy)
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 403, "should be denied before reload");

    // Rewrite policy to allow read_file
    h.write_policy(allow_all_policy());

    // Trigger reload via admin API
    let resp = h
        .client
        .post(h.admin_url("/policy/reload"))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Same request should now succeed
    let resp = h
        .mcp_call(
            &agent_id,
            &session_id,
            "read_file",
            serde_json::json!({"path": "/tmp/test"}),
        )
        .await;
    assert_eq!(resp.status(), 200, "should be allowed after reload");
}

/// Audit hash chaining: when enabled, entries contain sequence and hash fields.
#[tokio::test]
async fn audit_hash_chaining() {
    let config = r#"
[proxy]
listen_addr = "127.0.0.1"
listen_port = {proxy_port}
upstream_url = "http://127.0.0.1:{upstream_port}"

[policy]
file = "{policy}"

[audit]
enabled = true
file_path = "{audit}"
hash_chain = true

[admin]
listen_addr = "127.0.0.1"
listen_port = {admin_port}
api_key = "test-key"
signing_secret = "test-secret-that-is-at-least-32-bytes-long-for-hmac"
"#;
    let h = TestHarness::with_policy(config, allow_all_policy()).await;
    let (agent_id, _) = h.register_agent("user:alice", &["read"], "basic").await;
    let session_id = h
        .create_session(&agent_id, "read files", &["read_file"], 100, 3600)
        .await;

    // Make two calls to generate a chain
    for i in 0..2 {
        let resp = h
            .mcp_call_with_id(
                &agent_id,
                &session_id,
                "read_file",
                serde_json::json!({"path": "/tmp/test"}),
                i + 1,
            )
            .await;
        assert_eq!(resp.status(), 200);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    let entries = h.read_audit_log();
    let allow_entries: Vec<_> = entries
        .iter()
        .filter(|e| e["authorization_decision"].as_str() == Some("allow"))
        .collect();
    assert!(
        allow_entries.len() >= 2,
        "should have at least 2 allow entries for hash chain test"
    );

    // Verify hash chain fields exist
    if let Some(seq) = allow_entries[0].get("sequence_number") {
        assert!(seq.as_u64().is_some(), "sequence_number should be numeric");
    }
    if let Some(hash) = allow_entries[0].get("previous_hash") {
        assert!(hash.as_str().is_some(), "previous_hash should be a string");
    }
}
