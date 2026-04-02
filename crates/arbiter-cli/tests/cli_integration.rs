use arbiter_lifecycle::{AppState, TokenConfig};
use tokio::net::TcpListener;
use tokio::process::Command;

const API_KEY: &str = "test-cli-key";

async fn spawn_server() -> String {
    let token_config = TokenConfig {
        signing_secret: "a]3Fz!9qL#mR&vXw2Tp7Ks@Yc0Nd8Ge$".into(),
        expiry_seconds: 3600,
        issuer: "arbiter".into(),
    };
    let state = AppState::with_token_config(API_KEY.into(), token_config);
    let app = arbiter_lifecycle::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn arbiter_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_arbiter-ctl"))
}

#[tokio::test]
async fn cli_register_and_list() {
    let base = spawn_server().await;

    // Register an agent via CLI
    let output = arbiter_cmd()
        .args([
            "--api-url",
            &base,
            "--api-key",
            API_KEY,
            "register-agent",
            "--owner",
            "user:cli-test",
            "--model",
            "test-model",
            "--capabilities",
            "read,write",
        ])
        .output()
        .await
        .expect("failed to run arbiter CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "register failed: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("Agent registered:"));
    assert!(stdout.contains("ID:"));
    assert!(stdout.contains("Token:"));

    // List agents via CLI
    let output = arbiter_cmd()
        .args(["--api-url", &base, "--api-key", API_KEY, "list-agents"])
        .output()
        .await
        .expect("failed to run arbiter CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "list failed: {stdout}");
    assert!(stdout.contains("user:cli-test"));
    assert!(stdout.contains("test-model"));
}

#[tokio::test]
async fn cli_revoke_cascading() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();

    // Register two agents via HTTP (for setup)
    let res = client
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "parent",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let parent: serde_json::Value = res.json().await.unwrap();
    let parent_id = parent["agent_id"].as_str().unwrap().to_string();

    let res = client
        .post(format!("{base}/agents"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({
            "owner": "user:alice",
            "model": "child",
            "capabilities": ["read"]
        }))
        .send()
        .await
        .unwrap();
    let child: serde_json::Value = res.json().await.unwrap();
    let child_id = child["agent_id"].as_str().unwrap().to_string();

    // Delegate parent -> child via HTTP
    client
        .post(format!("{base}/agents/{parent_id}/delegate"))
        .header("x-api-key", API_KEY)
        .json(&serde_json::json!({ "to": child_id, "scopes": ["read"] }))
        .send()
        .await
        .unwrap();

    // Revoke parent via CLI (should cascade)
    let output = arbiter_cmd()
        .args([
            "--api-url",
            &base,
            "--api-key",
            API_KEY,
            "revoke",
            "--agent",
            &parent_id,
        ])
        .output()
        .await
        .expect("failed to run arbiter CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "revoke failed: stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("Revoked 2 agent(s)"));
}
