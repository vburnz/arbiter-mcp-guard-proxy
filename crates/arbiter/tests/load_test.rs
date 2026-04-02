//! Throughput / load test for arbiter-gateway.
//!
//! Spawns a mock upstream, the full arbiter proxy, registers an agent,
//! creates a session, then drives N concurrent connections each sending
//! M MCP tool-call requests through the proxy.
//!
//! Env-var knobs:
//!   LOAD_TEST_CONNECTIONS        – concurrent workers   (default 50)
//!   LOAD_TEST_REQUESTS_PER_CONN  – requests per worker  (default 20)
//!
//! Run with:
//!   cargo test --test load_test -- --ignored --nocapture

use std::io::Write as _;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Helpers (mirrored from integration.rs) ──────────────────────────

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
                    if let Ok(req_json) =
                        serde_json::from_slice::<serde_json::Value>(&body_bytes)
                    {
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

// ── Load test ───────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn load_test_throughput() {
    let connections: u64 = std::env::var("LOAD_TEST_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let requests_per_conn: u64 = std::env::var("LOAD_TEST_REQUESTS_PER_CONN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let total_expected = connections * requests_per_conn;

    eprintln!("=== Arbiter load test ===");
    eprintln!("  connections:        {connections}");
    eprintln!("  requests/conn:      {requests_per_conn}");
    eprintln!("  total requests:     {total_expected}");
    eprintln!();

    // ── 1. Infrastructure: echo server, arbiter, config ─────────────

    let proxy_port = free_port();
    let admin_port = free_port();
    let upstream_port = free_port();

    tokio::spawn(start_echo_server(upstream_port));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let temp_dir = tempfile::tempdir().unwrap();
    let audit_path = temp_dir.path().join("audit.jsonl");

    // Allow-all policy so every tool call goes through.
    let policy_path = temp_dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        r#"
[[policies]]
id = "load-test-allow-all"
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

    // Wait for servers to be ready.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(connections as usize)
        .build()
        .unwrap();

    // ── 2. Health check ─────────────────────────────────────────────

    let resp = client
        .get(format!("http://127.0.0.1:{proxy_port}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "proxy must be healthy before load test");

    // ── 3. Register agent + create session ──────────────────────────

    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/agents"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "owner": "user:load-tester",
            "model": "load-test-model",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Budget must accommodate the full load.
    let call_budget = total_expected + 100; // some headroom
    let resp = client
        .post(format!("http://127.0.0.1:{admin_port}/sessions"))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "agent_id": &agent_id,
            "declared_intent": "load test",
            "authorized_tools": ["read_file"],
            "time_limit_secs": 3600,
            "call_budget": call_budget
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let session_body: serde_json::Value = resp.json().await.unwrap();
    let session_id = session_body["session_id"].as_str().unwrap().to_string();

    // ── 4. Drive load ───────────────────────────────────────────────

    let success_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let mut handles = Vec::with_capacity(connections as usize);

    for conn_idx in 0..connections {
        let client = client.clone();
        let agent_id = agent_id.clone();
        let session_id = session_id.clone();
        let success = Arc::clone(&success_count);
        let errors = Arc::clone(&error_count);

        handles.push(tokio::spawn(async move {
            for req_idx in 0..requests_per_conn {
                let id = conn_idx * requests_per_conn + req_idx;
                let mcp_request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": { "path": "/etc/hosts" }
                    }
                });

                let result = client
                    .post(format!("http://127.0.0.1:{proxy_port}/"))
                    .header("x-agent-id", &agent_id)
                    .header("x-arbiter-session", &session_id)
                    .header("x-delegation-chain", "user:load-tester")
                    .header("content-type", "application/json")
                    .json(&mcp_request)
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        // Consume the body to release the connection.
                        let _ = resp.bytes().await;
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        eprintln!(
                            "  [conn {conn_idx} req {req_idx}] non-success: {status} {body}"
                        );
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("  [conn {conn_idx} req {req_idx}] transport error: {e}");
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Wait for all workers to finish.
    for h in handles {
        h.await.unwrap();
    }

    let elapsed = start.elapsed();

    // ── 5. Report ───────────────────────────────────────────────────

    let successes = success_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);
    let total = successes + errors;
    let rps = if elapsed.as_secs_f64() > 0.0 {
        total as f64 / elapsed.as_secs_f64()
    } else {
        f64::INFINITY
    };
    let error_rate = if total > 0 {
        errors as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!("=== Load test results ===");
    eprintln!("  Total requests:     {total}");
    eprintln!("  Successful:         {successes}");
    eprintln!("  Errors:             {errors}");
    eprintln!("  Error rate:         {error_rate:.2}%");
    eprintln!("  Elapsed:            {:.3}s", elapsed.as_secs_f64());
    eprintln!("  Requests/sec:       {rps:.1}");
    eprintln!();

    // ── 6. Assertions ───────────────────────────────────────────────

    assert_eq!(
        total, total_expected,
        "all requests should have been attempted"
    );
    assert!(
        error_rate < 5.0,
        "error rate {error_rate:.2}% exceeds 5% threshold"
    );
    assert!(
        successes > 0,
        "at least some requests must succeed"
    );

    // ── 7. Cleanup ──────────────────────────────────────────────────

    arbiter_handle.abort();
}
