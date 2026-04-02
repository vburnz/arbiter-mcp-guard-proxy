use arbiter_lifecycle::AppState;
use arbiter_policy::PolicyConfig;
use tokio::net::TcpListener;

const API_KEY: &str = "test-admin-key";

async fn spawn_server() -> String {
    let state = AppState::new(API_KEY.into());
    let app = arbiter_lifecycle::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_server_with_policy(policy_toml: &str) -> String {
    let state = AppState::new(API_KEY.into());
    let _ = state.policy_config.send_replace(std::sync::Arc::new(Some(
        PolicyConfig::from_toml(policy_toml).unwrap(),
    )));
    let app = arbiter_lifecycle::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

#[tokio::test]
async fn register_and_get_agent() {
    let base = spawn_server().await;
    let c = client();

    // Register
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "claude-opus-4-6",
            "capabilities": ["read", "write"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();
    assert!(!body["token"].as_str().unwrap().is_empty());

    // Get
    let res = c
        .get(format!("{base}/agents/{agent_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let agent: serde_json::Value = res.json().await.unwrap();
    assert_eq!(agent["owner"], "user:alice");
    assert_eq!(agent["model"], "claude-opus-4-6");
    assert!(agent["active"].as_bool().unwrap());
}

#[tokio::test]
async fn delegate_and_verify_chain() {
    let base = spawn_server().await;
    let c = client();

    // Register parent
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "parent-model",
            "capabilities": ["read", "write", "admin"]
        }))
        .send()
        .await
        .unwrap();
    let parent: serde_json::Value = res.json().await.unwrap();
    let parent_id = parent["agent_id"].as_str().unwrap();

    // Register child
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "child-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let child: serde_json::Value = res.json().await.unwrap();
    let child_id = child["agent_id"].as_str().unwrap();

    // Delegate
    let res = c
        .post(format!("{base}/agents/{parent_id}/delegate"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "to": child_id,
            "scopes": ["read"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
    let link: serde_json::Value = res.json().await.unwrap();
    assert_eq!(link["from"], parent_id);
    assert_eq!(link["to"], child_id);
}

#[tokio::test]
async fn cascade_deactivation() {
    let base = spawn_server().await;
    let c = client();

    // Register root, mid, leaf
    async fn register_agent(c: &reqwest::Client, base: &str, model: &str, caps: &[&str]) -> String {
        let res = c
            .post(format!("{base}/agents"))
            .header("x-api-key", API_KEY)
            .json(&serde_json::json!({
                "owner": "user:alice",
                "model": model,
                "capabilities": caps
            }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        body["agent_id"].as_str().unwrap().to_string()
    }

    let root_id = register_agent(&c, &base, "root", &["read", "write"]).await;
    let mid_id = register_agent(&c, &base, "mid", &["read"]).await;
    let leaf_id = register_agent(&c, &base, "leaf", &["read"]).await;

    // Delegate root -> mid -> leaf
    c.post(format!("{base}/agents/{root_id}/delegate"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({ "to": mid_id, "scopes": ["read"] }))
        .send()
        .await
        .unwrap();

    c.post(format!("{base}/agents/{mid_id}/delegate"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({ "to": leaf_id, "scopes": ["read"] }))
        .send()
        .await
        .unwrap();

    // Cascade deactivate root
    let res = c
        .delete(format!("{base}/agents/{root_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["count"], 3);

    // Verify all are deactivated
    for id in [&root_id, &mid_id, &leaf_id] {
        let res = c
            .get(format!("{base}/agents/{id}"))
            .header("x-api-key", API_KEY)
            .send()
            .await
            .unwrap();
        let agent: serde_json::Value = res.json().await.unwrap();
        assert!(!agent["active"].as_bool().unwrap());
    }
}

#[tokio::test]
async fn token_issuance() {
    let base = spawn_server().await;
    let c = client();

    // Register
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:bob",
            "model": "test-model",
            "capabilities": []
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Issue token with custom expiry
    let res = c
        .post(format!("{base}/agents/{agent_id}/token"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({ "expiry_seconds": 1800 }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let token_resp: serde_json::Value = res.json().await.unwrap();
    assert!(!token_resp["token"].as_str().unwrap().is_empty());
    assert_eq!(token_resp["expires_in"], 1800);
}

#[tokio::test]
async fn unauthorized_without_api_key() {
    let base = spawn_server().await;
    let c = client();

    let res = c.get(format!("{base}/agents")).send().await.unwrap();

    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn policy_explain_no_policies() {
    let base = spawn_server().await;
    let c = client();

    // Register agent first.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Explain with no policies configured → allow with "no policies configured".
    let res = c
        .post(format!("{base}/policy/explain"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read config files",
            "tool": "read_file"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["decision"], "allow");
    assert_eq!(body["reason"], "no policies configured");
}

#[tokio::test]
async fn policy_explain_with_allow_policy() {
    let policy_toml = r#"
[[policies]]
id = "allow-read"
effect = "allow"
allowed_tools = ["read_file", "list_dir"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
"#;
    let base = spawn_server_with_policy(policy_toml).await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"],
            "trust_level": "basic"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Explain: allowed tool with matching intent → allow.
    let res = c
        .post(format!("{base}/policy/explain"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read configuration files",
            "tool": "read_file"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["decision"], "allow");
    assert_eq!(body["matched_policy"], "allow-read");
    assert!(body["trace"].as_array().unwrap().len() > 0);

    // Explain: unauthorized tool → deny.
    let res = c
        .post(format!("{base}/policy/explain"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read configuration files",
            "tool": "delete_file"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["decision"], "deny");
    assert!(body["trace"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn get_session_status() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Create session.
    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let session: serde_json::Value = res.json().await.unwrap();
    let session_id = session["session_id"].as_str().unwrap();

    // GET session status.
    let res = c
        .get(format!("{base}/sessions/{session_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let status: serde_json::Value = res.json().await.unwrap();
    assert_eq!(status["session_id"], session_id);
    assert_eq!(status["status"], "active");
    assert_eq!(status["calls_made"], 0);
    assert_eq!(status["call_budget"], 50);
    assert_eq!(status["calls_remaining"], 50);
    assert_eq!(status["declared_intent"], "read logs");
    assert!(status["seconds_remaining"].as_i64().unwrap() > 0);
    assert!(status["expires_at"].as_str().is_some());
    assert!(status["warnings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_session_not_found() {
    let base = spawn_server().await;
    let c = client();

    let fake_id = uuid::Uuid::new_v4();
    let res = c
        .get(format!("{base}/sessions/{fake_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn get_session_with_budget_warning() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Create session with small budget.
    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": [],
            "call_budget": 5,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    let session: serde_json::Value = res.json().await.unwrap();
    let session_id = session["session_id"].as_str().unwrap();

    // Use 4 of 5 calls via the session store directly is not possible through the API,
    // but we can check the GET endpoint returns warnings when budget is at 20%.
    // With call_budget=5 and 0 calls made, there's no warning yet.
    let res = c
        .get(format!("{base}/sessions/{session_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    let status: serde_json::Value = res.json().await.unwrap();
    // 5 remaining out of 5 = 100%, so no warning.
    assert!(status["warnings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn policy_schema_endpoint() {
    let base = spawn_server().await;
    let c = client();

    let res = c
        .get(format!("{base}/policy/schema"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let schema: serde_json::Value = res.json().await.unwrap();

    // Verify structure.
    assert_eq!(schema["title"], "Arbiter Policy Configuration");
    assert!(schema["$defs"]["Policy"].is_object());
    assert!(schema["$defs"]["Effect"].is_object());
    assert!(schema["$defs"]["AgentMatch"].is_object());
    assert!(schema["$defs"]["TrustLevel"].is_object());
    assert!(schema["$defs"]["PrincipalMatch"].is_object());
    assert!(schema["$defs"]["IntentMatch"].is_object());
    assert!(schema["$defs"]["ParameterConstraint"].is_object());

    // Verify enums are documented.
    let effects = schema["$defs"]["Effect"]["enum"].as_array().unwrap();
    assert!(effects.contains(&serde_json::json!("allow")));
    assert!(effects.contains(&serde_json::json!("deny")));
    assert!(effects.contains(&serde_json::json!("escalate")));

    let trust_levels = schema["$defs"]["TrustLevel"]["enum"].as_array().unwrap();
    assert_eq!(trust_levels.len(), 4);
}

#[tokio::test]
async fn policy_schema_requires_auth() {
    let base = spawn_server().await;
    let c = client();

    let res = c.get(format!("{base}/policy/schema")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn forbidden_with_wrong_api_key() {
    let base = spawn_server().await;
    let c = client();

    let res = c
        .get(format!("{base}/agents"))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn concurrent_session_cap_enforced() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create 10 sessions (the cap configured in AppState::new).
    for i in 0..10 {
        let res = c
            .post(format!("{base}/sessions"))
            .header("x-api-key", API_KEY)
            .json(&serde_json::json!({
                "agent_id": agent_id,
                "declared_intent": format!("task {}", i),
                "authorized_tools": ["read_file"],
                "call_budget": 50,
                "time_limit_secs": 3600
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "session {} should succeed", i);
    }

    // The 11th session should be rejected with 429.
    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "one too many",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 429);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("too many concurrent sessions"),
        "expected 'too many concurrent sessions' in error, got: {error_msg}"
    );
}

#[tokio::test]
async fn session_creation_validates_parameters() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Helper: send a session creation request and return (status, error string).
    async fn create_session(
        c: &reqwest::Client,
        base: &str,
        agent_id: &str,
        overrides: serde_json::Value,
    ) -> (u16, String) {
        let mut body = serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "valid intent",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600
        });
        // Merge overrides into body.
        for (k, v) in overrides.as_object().unwrap() {
            body[k] = v.clone();
        }
        let res = c
            .post(format!("{base}/sessions"))
            .header("x-api-key", API_KEY)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        let resp: serde_json::Value = res.json().await.unwrap();
        let error = resp["error"].as_str().unwrap_or("").to_string();
        (status, error)
    }

    // time_limit_secs: 0 → 400 (must be positive)
    let (status, error) = create_session(
        &c,
        &base,
        &agent_id,
        serde_json::json!({"time_limit_secs": 0}),
    )
    .await;
    assert_eq!(status, 400, "time_limit_secs=0 should be rejected");
    assert!(
        error.contains("positive"),
        "error should mention 'positive': {error}"
    );

    // time_limit_secs: 100000 → 400 (cannot exceed 86400)
    let (status, error) = create_session(
        &c,
        &base,
        &agent_id,
        serde_json::json!({"time_limit_secs": 100000}),
    )
    .await;
    assert_eq!(status, 400, "time_limit_secs=100000 should be rejected");
    assert!(
        error.contains("86400"),
        "error should mention '86400': {error}"
    );

    // call_budget: 0 → 400 (must be positive)
    let (status, error) =
        create_session(&c, &base, &agent_id, serde_json::json!({"call_budget": 0})).await;
    assert_eq!(status, 400, "call_budget=0 should be rejected");
    assert!(
        error.contains("positive"),
        "error should mention 'positive': {error}"
    );

    // call_budget: 2000000 → 400 (cannot exceed 1000000)
    let (status, error) = create_session(
        &c,
        &base,
        &agent_id,
        serde_json::json!({"call_budget": 2000000}),
    )
    .await;
    assert_eq!(status, 400, "call_budget=2000000 should be rejected");
    assert!(
        error.contains("1000000"),
        "error should mention '1000000': {error}"
    );

    // declared_intent: "" → 400 (must not be empty)
    let (status, error) = create_session(
        &c,
        &base,
        &agent_id,
        serde_json::json!({"declared_intent": ""}),
    )
    .await;
    assert_eq!(status, 400, "empty declared_intent should be rejected");
    assert!(
        error.contains("empty"),
        "error should mention 'empty': {error}"
    );

    // declared_intent: "   " → 400 (whitespace-only, trimmed to empty)
    let (status, error) = create_session(
        &c,
        &base,
        &agent_id,
        serde_json::json!({"declared_intent": "   "}),
    )
    .await;
    assert_eq!(
        status, 400,
        "whitespace-only declared_intent should be rejected"
    );
    assert!(
        error.contains("empty"),
        "error should mention 'empty': {error}"
    );
}

#[tokio::test]
async fn deactivated_agent_token_issuance_rejected() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:bob",
            "model": "test-model",
            "capabilities": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Deactivate agent.
    let res = c
        .delete(format!("{base}/agents/{agent_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Try to issue a token for the deactivated agent.
    let res = c
        .post(format!("{base}/agents/{agent_id}/token"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("deactivated"),
        "expected 'deactivated' in error, got: {error_msg}"
    );
}

#[tokio::test]
async fn list_agents_returns_registered() {
    let base = spawn_server().await;
    let c = client();

    // Register 3 agents.
    for model in ["model-a", "model-b", "model-c"] {
        let res = c
            .post(format!("{base}/agents"))
            .header("x-api-key", API_KEY)
            .json(&serde_json::json!({
                "owner": "user:alice",
                "model": model,
                "capabilities": ["read"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }

    // List agents.
    let res = c
        .get(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let agents: serde_json::Value = res.json().await.unwrap();
    let arr = agents.as_array().expect("response should be an array");
    assert_eq!(arr.len(), 3, "should have exactly 3 registered agents");
}

#[tokio::test]
async fn list_delegations_shows_chain() {
    let base = spawn_server().await;
    let c = client();

    // Register parent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "parent-model",
            "capabilities": ["read", "write"]
        }))
        .send()
        .await
        .unwrap();
    let parent: serde_json::Value = res.json().await.unwrap();
    let parent_id = parent["agent_id"].as_str().unwrap().to_string();

    // Register child.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "child-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let child: serde_json::Value = res.json().await.unwrap();
    let child_id = child["agent_id"].as_str().unwrap().to_string();

    // Delegate parent -> child.
    let res = c
        .post(format!("{base}/agents/{parent_id}/delegate"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "to": child_id,
            "scopes": ["read"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);

    // List delegations for parent.
    let res = c
        .get(format!("{base}/agents/{parent_id}/delegations"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["agent_id"], parent_id);
    let outgoing = body["outgoing"]
        .as_array()
        .expect("outgoing should be an array");
    assert_eq!(
        outgoing.len(),
        1,
        "parent should have exactly 1 outgoing delegation"
    );
    assert_eq!(outgoing[0]["to"].as_str().unwrap(), child_id);
}

#[tokio::test]
async fn close_session_returns_summary() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Create session.
    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 100,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let session: serde_json::Value = res.json().await.unwrap();
    let session_id = session["session_id"].as_str().unwrap();

    // Close session.
    let res = c
        .post(format!("{base}/sessions/{session_id}/close"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let summary: serde_json::Value = res.json().await.unwrap();
    assert_eq!(summary["session_id"], session_id);
    assert_eq!(summary["status"], "closed");
    assert_eq!(summary["total_calls"], 0);
    assert_eq!(summary["call_budget"], 100);
    assert_eq!(summary["budget_utilization_pct"], 0.0);
}

#[tokio::test]
async fn close_nonexistent_session_returns_404() {
    let base = spawn_server().await;
    let c = client();

    let fake_id = uuid::Uuid::new_v4();
    let res = c
        .post(format!("{base}/sessions/{fake_id}/close"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

// ── RT-003 Security Fixes ──────────────────────────────────────────

/// RT-003 F-01: Ghost agent session prevention.
/// Creating a session for a non-existent agent must fail with 404.
#[tokio::test]
async fn session_creation_rejects_nonexistent_agent() {
    let base = spawn_server().await;
    let c = client();

    let fake_agent_id = uuid::Uuid::new_v4();
    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": fake_agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 404);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("not found"),
        "expected 'not found' in error, got: {error_msg}"
    );
}

/// RT-003 F-01: Creating a session for a deactivated agent must fail with 400.
#[tokio::test]
async fn session_creation_rejects_deactivated_agent() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Deactivate agent.
    let res = c
        .delete(format!("{base}/agents/{agent_id}"))
        .header("x-api-key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Try to create session for deactivated agent.
    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("deactivated"),
        "expected 'deactivated' in error, got: {error_msg}"
    );
}

/// RT-003 F-03: Rate limit window bounds validation.
/// rate_limit_window_secs: 0 must be rejected.
#[tokio::test]
async fn session_creation_rejects_zero_rate_window() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600,
            "rate_limit_window_secs": 0
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("positive"),
        "expected 'positive' in error, got: {error_msg}"
    );
}

/// RT-003 F-03: rate_limit_window_secs below minimum (10s) must be rejected.
#[tokio::test]
async fn session_creation_rejects_tiny_rate_window() {
    let base = spawn_server().await;
    let c = client();

    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600,
            "rate_limit_window_secs": 1
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("at least 10"),
        "expected 'at least 10' in error, got: {error_msg}"
    );
}

/// RT-003 F-03: rate_limit_window_secs above maximum (3600s) must be rejected.
#[tokio::test]
async fn session_creation_rejects_huge_rate_window() {
    let base = spawn_server().await;
    let c = client();

    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600,
            "rate_limit_window_secs": 99999
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("3600"),
        "expected '3600' in error, got: {error_msg}"
    );
}

/// RT-003 F-03: Valid rate_limit_window_secs (within bounds) must be accepted.
#[tokio::test]
async fn session_creation_accepts_valid_rate_window() {
    let base = spawn_server().await;
    let c = client();

    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "test-model",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    let res = c
        .post(format!("{base}/sessions"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "declared_intent": "read logs",
            "authorized_tools": ["read_file"],
            "call_budget": 50,
            "time_limit_secs": 3600,
            "rate_limit_window_secs": 60
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201, "valid rate window should be accepted");
}

/// RT-003 F-09: Negative token expiry_seconds must be rejected.
#[tokio::test]
async fn token_issuance_rejects_negative_expiry() {
    let base = spawn_server().await;
    let c = client();

    // Register agent.
    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:bob",
            "model": "test-model",
            "capabilities": []
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Issue token with negative expiry.
    let res = c
        .post(format!("{base}/agents/{agent_id}/token"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({ "expiry_seconds": -100 }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
    let err: serde_json::Value = res.json().await.unwrap();
    let error_msg = err["error"].as_str().unwrap();
    assert!(
        error_msg.contains("positive"),
        "expected 'positive' in error, got: {error_msg}"
    );
}

/// RT-003 F-09: Zero token expiry_seconds must be rejected.
#[tokio::test]
async fn token_issuance_rejects_zero_expiry() {
    let base = spawn_server().await;
    let c = client();

    let res = c
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:bob",
            "model": "test-model",
            "capabilities": []
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    let res = c
        .post(format!("{base}/agents/{agent_id}/token"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({ "expiry_seconds": 0 }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400);
}
