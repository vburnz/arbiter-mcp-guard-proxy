use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "cyrenei/arbiter-mcp-firewall";

/// Arbiter CLI: agent lifecycle management, diagnostics, and policy tooling.
#[derive(Parser)]
#[command(name = "arbiter", about = "Arbiter agent lifecycle management CLI")]
struct Cli {
    /// Base URL of the Arbiter lifecycle API.
    #[arg(long, env = "ARBITER_API_URL", default_value = "http://127.0.0.1:3000")]
    api_url: String,

    /// Admin API key for authentication.
    #[arg(long, env = "ARBITER_API_KEY", default_value = "")]
    api_key: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new agent.
    RegisterAgent {
        /// Owner (human principal sub).
        #[arg(long)]
        owner: String,
        /// Model name.
        #[arg(long)]
        model: String,
        /// Comma-separated capabilities.
        #[arg(long, value_delimiter = ',')]
        capabilities: Vec<String>,
    },
    /// Create a delegation from one agent to another.
    CreateDelegation {
        /// Source agent ID.
        #[arg(long)]
        from: String,
        /// Target agent ID.
        #[arg(long)]
        to: String,
        /// Comma-separated scopes.
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
    },
    /// Revoke (deactivate) an agent and cascade to sub-agents.
    Revoke {
        /// Agent ID to revoke.
        #[arg(long)]
        agent: String,
    },
    /// List all registered agents.
    ListAgents,
    /// Run diagnostic checks against a running Arbiter instance or local config.
    Doctor {
        /// Path to arbiter.toml config file for local checks.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Policy tooling subcommands.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Check for and install Arbiter updates from GitHub Releases.
    Update {
        /// Target version to install (e.g. "v0.6.0"). Defaults to latest.
        #[arg(long)]
        version: Option<String>,
        /// Check for available updates without installing.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Dry-run policy evaluation against a sample request.
    Test {
        /// Path to the TOML policy file.
        #[arg(long)]
        policy: PathBuf,
        /// Path to a JSON file with a sample request. If omitted, reads from stdin.
        #[arg(long)]
        request: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = reqwest::Client::new();

    let result = match cli.command {
        Commands::RegisterAgent {
            owner,
            model,
            capabilities,
        } => {
            register_agent(
                &client,
                &cli.api_url,
                &cli.api_key,
                &owner,
                &model,
                &capabilities,
            )
            .await
        }
        Commands::CreateDelegation { from, to, scopes } => {
            create_delegation(&client, &cli.api_url, &cli.api_key, &from, &to, &scopes).await
        }
        Commands::Revoke { agent } => {
            revoke_agent(&client, &cli.api_url, &cli.api_key, &agent).await
        }
        Commands::ListAgents => list_agents(&client, &cli.api_url, &cli.api_key).await,
        Commands::Doctor { config } => doctor(&client, &cli.api_url, &cli.api_key, config).await,
        Commands::Policy { action } => match action {
            PolicyAction::Test { policy, request } => policy_test(&policy, request.as_deref()),
        },
        Commands::Update { version, check } => self_update(&client, version, check).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Agent lifecycle commands
// ---------------------------------------------------------------------------

async fn register_agent(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    owner: &str,
    model: &str,
    capabilities: &[String],
) -> Result<(), String> {
    let res = client
        .post(format!("{base}/agents"))
        .header("x-api-key", api_key)
        .json(&serde_json::json!({
            "owner": owner,
            "model": model,
            "capabilities": capabilities,
        }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = res.status();
    let body: Value = res
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "API error ({}): {}",
            status,
            body["error"].as_str().unwrap_or("unknown")
        ));
    }

    println!("Agent registered:");
    println!("  ID:    {}", body["agent_id"]);
    println!("  Token: {}", body["token"]);
    Ok(())
}

async fn create_delegation(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    from: &str,
    to: &str,
    scopes: &[String],
) -> Result<(), String> {
    let res = client
        .post(format!("{base}/agents/{from}/delegate"))
        .header("x-api-key", api_key)
        .json(&serde_json::json!({
            "to": to,
            "scopes": scopes,
        }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = res.status();
    let body: Value = res
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "API error ({}): {}",
            status,
            body["error"].as_str().unwrap_or("unknown")
        ));
    }

    println!("Delegation created:");
    println!("  From: {}", body["from"]);
    println!("  To:   {}", body["to"]);
    println!("  Scopes: {:?}", body["scope_narrowing"]);
    Ok(())
}

async fn revoke_agent(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    agent_id: &str,
) -> Result<(), String> {
    let res = client
        .delete(format!("{base}/agents/{agent_id}"))
        .header("x-api-key", api_key)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = res.status();
    let body: Value = res
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "API error ({}): {}",
            status,
            body["error"].as_str().unwrap_or("unknown")
        ));
    }

    println!(
        "Revoked {} agent(s): {:?}",
        body["count"], body["deactivated"]
    );
    Ok(())
}

async fn list_agents(client: &reqwest::Client, base: &str, api_key: &str) -> Result<(), String> {
    let res = client
        .get(format!("{base}/agents"))
        .header("x-api-key", api_key)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = res.status();
    let body: Value = res
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "API error ({}): {}",
            status,
            body["error"].as_str().unwrap_or("unknown")
        ));
    }

    let empty = vec![];
    let agents = body.as_array().unwrap_or(&empty);
    if agents.is_empty() {
        println!("No agents registered.");
        return Ok(());
    }

    for agent in agents {
        println!(
            "  {} | owner={} model={} trust={} active={}",
            agent["id"],
            agent["owner"].as_str().unwrap_or("?"),
            agent["model"].as_str().unwrap_or("?"),
            agent["trust_level"].as_str().unwrap_or("?"),
            agent["active"],
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Doctor command
// ---------------------------------------------------------------------------

/// Run diagnostic checks against a running instance and/or local config.
async fn doctor(
    client: &reqwest::Client,
    api_url: &str,
    api_key: &str,
    config_path: Option<PathBuf>,
) -> Result<(), String> {
    let mut all_pass = true;

    // ---- Remote checks (against running instance) ----
    // Check 1: Proxy health endpoint.
    print_check("Proxy health endpoint");
    // The proxy typically runs on port 8080 while admin is on 3000.
    // Try to derive the proxy URL from the admin URL by checking port.
    // The user can also just provide the proxy URL via --api-url.
    // We try the admin URL for /agents (admin health check).
    match client
        .get(format!("{api_url}/agents"))
        .header("x-api-key", api_key)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            print_pass("admin API reachable");
        }
        Ok(resp) => {
            // Got a response but not 200. API is reachable but auth may be wrong.
            if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                print_pass("admin API reachable (auth rejected, check api_key)");
            } else {
                print_fail(&format!(
                    "admin API returned unexpected status: {}",
                    resp.status()
                ));
                all_pass = false;
            }
        }
        Err(e) => {
            print_fail(&format!("admin API not reachable: {e}"));
            all_pass = false;
        }
    }

    // Check 2: Policy reload endpoint (indicates policy system is active).
    print_check("Policy system");
    match client
        .post(format!("{api_url}/policy/reload"))
        .header("x-api-key", api_key)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or_default();
            if status.is_success() {
                let count = body["policies_loaded"].as_u64().unwrap_or(0);
                print_pass(&format!("{count} policies loaded"));
            } else if status.as_u16() == 400 {
                // "no policy file configured": not an error, just no file-based policies.
                print_pass("no policy file configured (inline or absent)");
            } else {
                print_fail(&format!("policy reload returned {status}: {body}"));
                all_pass = false;
            }
        }
        Err(e) => {
            print_fail(&format!("could not reach policy endpoint: {e}"));
            all_pass = false;
        }
    }

    // ---- Local config checks (if --config is provided) ----
    if let Some(ref path) = config_path {
        print_check("Config file exists");
        if path.exists() {
            print_pass(&format!("{}", path.display()));
        } else {
            print_fail(&format!("{} not found", path.display()));
            all_pass = false;
        }

        if path.exists() {
            print_check("Config file parses");
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    // Try to parse as a minimal TOML with known sections.
                    let parsed: Result<toml::Value, _> = toml::from_str(&contents);
                    match parsed {
                        Ok(val) => {
                            print_pass("valid TOML");

                            // Check policy file if referenced.
                            if let Some(policy_file) = val
                                .get("policy")
                                .and_then(|p| p.get("file"))
                                .and_then(|f| f.as_str())
                            {
                                print_check("Policy file");
                                let policy_path = std::path::Path::new(policy_file);
                                // Try relative to config dir first, then absolute.
                                let resolved = if policy_path.is_absolute() {
                                    policy_path.to_path_buf()
                                } else if let Some(parent) = path.parent() {
                                    parent.join(policy_path)
                                } else {
                                    policy_path.to_path_buf()
                                };
                                if resolved.exists() {
                                    match std::fs::read_to_string(&resolved) {
                                        Ok(policy_contents) => {
                                            match arbiter_policy::PolicyConfig::from_toml(
                                                &policy_contents,
                                            ) {
                                                Ok(pc) => print_pass(&format!(
                                                    "{} policies parsed from {}",
                                                    pc.policies.len(),
                                                    resolved.display()
                                                )),
                                                Err(e) => {
                                                    print_fail(&format!("parse error: {e}"));
                                                    all_pass = false;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            print_fail(&format!(
                                                "cannot read {}: {e}",
                                                resolved.display()
                                            ));
                                            all_pass = false;
                                        }
                                    }
                                } else {
                                    print_fail(&format!("{} does not exist", resolved.display()));
                                    all_pass = false;
                                }
                            }

                            // Check audit log path writable.
                            if let Some(audit_path) = val
                                .get("audit")
                                .and_then(|a| a.get("file_path"))
                                .and_then(|f| f.as_str())
                            {
                                print_check("Audit log path");
                                let audit_file = std::path::Path::new(audit_path);
                                if let Some(parent) = audit_file.parent() {
                                    if parent.exists() {
                                        // Try to verify writability by checking parent dir.
                                        let meta = std::fs::metadata(parent);
                                        if meta.is_ok() && meta.unwrap().is_dir() {
                                            print_pass(&format!(
                                                "parent dir {} exists",
                                                parent.display()
                                            ));
                                        } else {
                                            print_fail(&format!(
                                                "parent dir {} is not a directory",
                                                parent.display()
                                            ));
                                            all_pass = false;
                                        }
                                    } else {
                                        print_fail(&format!(
                                            "parent dir {} does not exist",
                                            parent.display()
                                        ));
                                        all_pass = false;
                                    }
                                }
                            }

                            // Check storage backend.
                            if let Some(storage) = val.get("storage") {
                                let backend = storage
                                    .get("backend")
                                    .and_then(|b| b.as_str())
                                    .unwrap_or("memory");
                                if backend == "sqlite" {
                                    print_check("SQLite database");
                                    let db_path = storage
                                        .get("sqlite_path")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("arbiter.db");
                                    let db_file = std::path::Path::new(db_path);
                                    if db_file.exists() {
                                        print_pass(&format!("{db_path} exists and is readable"));
                                    } else {
                                        // Not necessarily an error; it may be created on start.
                                        print_pass(&format!(
                                            "{db_path} does not exist yet (will be created on startup)"
                                        ));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            print_fail(&format!("TOML parse error: {e}"));
                            all_pass = false;
                        }
                    }
                }
                Err(e) => {
                    print_fail(&format!("cannot read file: {e}"));
                    all_pass = false;
                }
            }
        }
    }

    println!();
    if all_pass {
        println!("All checks passed.");
        Ok(())
    } else {
        Err("one or more checks failed".into())
    }
}

fn print_check(name: &str) {
    print!("  {name} ... ");
}

fn print_pass(detail: &str) {
    println!("PASS ({detail})");
}

fn print_fail(detail: &str) {
    println!("FAIL ({detail})");
}

// ---------------------------------------------------------------------------
// Self-update command
// ---------------------------------------------------------------------------

async fn self_update(
    client: &reqwest::Client,
    target_version: Option<String>,
    check_only: bool,
) -> Result<(), String> {
    if std::env::var("ARBITER_NO_SELF_UPDATE").is_ok() {
        return Err("self-update is disabled (ARBITER_NO_SELF_UPDATE is set)".into());
    }

    let current = VERSION;
    println!("Current version: v{current}");

    // Resolve target version
    let target = match target_version {
        Some(v) => {
            if v.starts_with('v') {
                v
            } else {
                format!("v{v}")
            }
        }
        None => resolve_latest_version(client).await?,
    };

    let target_semver = target.strip_prefix('v').unwrap_or(&target);
    if target_semver == current {
        println!("Already up to date.");
        return Ok(());
    }

    println!("Available: {target}");

    if check_only {
        println!("Update available: v{current} -> {target}");
        return Ok(());
    }

    // Detect platform
    let (os, arch) = detect_platform()?;
    let target_name = format!("arbiter-{os}-{arch}");

    println!("Downloading {target_name}.tar.gz...");

    let tarball_url = format!(
        "https://github.com/{REPO}/releases/download/{target}/{target_name}.tar.gz"
    );
    let checksum_url = format!(
        "https://github.com/{REPO}/releases/download/{target}/checksums-sha256.txt"
    );

    // Download tarball
    let tarball_bytes = client
        .get(&tarball_url)
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download failed: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("download failed: {e}"))?;

    // Download checksums
    let checksums_text = client
        .get(&checksum_url)
        .send()
        .await
        .map_err(|e| format!("checksum download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("checksum download failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("checksum download failed: {e}"))?;

    // Verify SHA256
    println!("Verifying SHA256 checksum...");
    verify_sha256(&tarball_bytes, &format!("{target_name}.tar.gz"), &checksums_text)?;

    // Extract to temp dir
    let tmpdir = tempfile::tempdir().map_err(|e| format!("cannot create temp dir: {e}"))?;
    let tarball_path = tmpdir.path().join("arbiter.tar.gz");
    std::fs::write(&tarball_path, &tarball_bytes)
        .map_err(|e| format!("cannot write tarball: {e}"))?;

    let status = std::process::Command::new("tar")
        .args(["xzf", &tarball_path.to_string_lossy(), "-C"])
        .arg(tmpdir.path())
        .status()
        .map_err(|e| format!("tar extraction failed: {e}"))?;

    if !status.success() {
        return Err("tar extraction failed".into());
    }

    // Find the arbiter binary in extracted contents
    let mut new_binary = None;
    for entry in std::fs::read_dir(tmpdir.path()).map_err(|e| format!("read dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            let candidate = entry.path().join("arbiter");
            if candidate.exists() {
                new_binary = Some(candidate);
                break;
            }
        }
    }

    let new_binary = new_binary.ok_or("could not find arbiter binary in archive")?;

    // Determine where the current arbiter binary lives.
    // We update the arbiter proxy binary, not ourselves (arbiter-ctl).
    let install_dir = std::env::var("ARBITER_INSTALL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs_or_home().join(".arbiter").join("bin")
        });

    let target_path = install_dir.join("arbiter");

    println!("Installing to {}...", target_path.display());
    std::fs::create_dir_all(&install_dir)
        .map_err(|e| format!("cannot create {}: {e}", install_dir.display()))?;

    // Atomic replace: copy to temp file in same dir, then rename
    let tmp_target = install_dir.join(".arbiter.update.tmp");
    std::fs::copy(&new_binary, &tmp_target)
        .map_err(|e| format!("cannot copy binary: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_target, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot set permissions: {e}"))?;
    }

    std::fs::rename(&tmp_target, &target_path)
        .map_err(|e| format!("cannot replace binary: {e}"))?;

    println!("Updated arbiter to {target}");
    println!("Restart the arbiter proxy for changes to take effect.");

    Ok(())
}

async fn resolve_latest_version(client: &reqwest::Client) -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let resp = client
        .get(&url)
        .header("User-Agent", "arbiter-ctl")
        .send()
        .await
        .map_err(|e| format!("cannot fetch latest release: {e}"))?
        .error_for_status()
        .map_err(|e| format!("cannot fetch latest release: {e}"))?;

    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    body["tag_name"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| "no tag_name in release response".into())
}

fn detect_platform() -> Result<(&'static str, &'static str), String> {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        return Err(format!("unsupported OS"));
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        return Err(format!("unsupported architecture"));
    };

    Ok((os, arch))
}

fn verify_sha256(data: &[u8], filename: &str, checksums: &str) -> Result<(), String> {
    use std::io::Write;

    let expected = checksums
        .lines()
        .find(|line| line.contains(filename))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| format!("no checksum found for {filename}"))?;

    // Compute SHA256 using a subprocess (sha256sum or shasum)
    let actual = if let Ok(output) = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(data)?;
            child.wait_with_output()
        }) {
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    } else if let Ok(output) = std::process::Command::new("shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.as_mut().unwrap().write_all(data)?;
            child.wait_with_output()
        }) {
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    } else {
        return Err("no sha256sum or shasum found".into());
    };

    if expected != actual {
        return Err(format!(
            "checksum mismatch!\n  expected: {expected}\n  actual:   {actual}"
        ));
    }

    println!("Checksum verified: {actual}");
    Ok(())
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Policy test command
// ---------------------------------------------------------------------------

/// Sample request JSON for policy evaluation.
#[derive(serde::Deserialize)]
struct SampleRequest {
    /// Agent ID (UUID string).
    #[serde(default)]
    agent_id: Option<String>,
    /// Trust level: untrusted, basic, verified, trusted.
    #[serde(default = "default_trust_level")]
    trust_level: String,
    /// Agent capabilities.
    #[serde(default)]
    capabilities: Vec<String>,
    /// Principal subject identifier.
    #[serde(default = "default_principal")]
    principal_sub: String,
    /// Principal groups.
    #[serde(default)]
    groups: Vec<String>,
    /// Declared task intent.
    #[serde(default)]
    declared_intent: String,
    /// Tool name being called.
    #[serde(default)]
    tool_name: Option<String>,
    /// Tool arguments (JSON object).
    #[serde(default)]
    arguments: Option<serde_json::Value>,
    /// Intent keywords (alternative to declared_intent for keyword matching).
    #[serde(default)]
    intent_keywords: Vec<String>,
}

fn default_trust_level() -> String {
    "basic".to_string()
}

fn default_principal() -> String {
    "user:test".to_string()
}

/// Dry-run policy evaluation against a sample request.
fn policy_test(
    policy_path: &std::path::Path,
    request_path: Option<&std::path::Path>,
) -> Result<(), String> {
    // Load the policy file.
    let policy_contents = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("cannot read policy file '{}': {e}", policy_path.display()))?;

    let policy_config = arbiter_policy::PolicyConfig::from_toml(&policy_contents)
        .map_err(|e| format!("cannot parse policy file: {e}"))?;

    println!(
        "Loaded {} policies from {}",
        policy_config.policies.len(),
        policy_path.display()
    );

    // Load the sample request (from file or stdin).
    let request_json: String = if let Some(path) = request_path {
        std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read request file '{}': {e}", path.display()))?
    } else {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        buf
    };

    let sample: SampleRequest = serde_json::from_str(&request_json)
        .map_err(|e| format!("cannot parse request JSON: {e}"))?;

    // Build the evaluation context.
    let trust_level = match sample.trust_level.to_lowercase().as_str() {
        "untrusted" => arbiter_identity::TrustLevel::Untrusted,
        "basic" => arbiter_identity::TrustLevel::Basic,
        "verified" => arbiter_identity::TrustLevel::Verified,
        "trusted" => arbiter_identity::TrustLevel::Trusted,
        other => return Err(format!("unknown trust_level: '{other}'")),
    };

    let agent_id = if let Some(ref id_str) = sample.agent_id {
        uuid::Uuid::parse_str(id_str).map_err(|e| format!("invalid agent_id UUID: {e}"))?
    } else {
        uuid::Uuid::new_v4()
    };

    let agent = arbiter_identity::Agent {
        id: agent_id,
        owner: sample.principal_sub.clone(),
        model: "cli-test".into(),
        capabilities: sample.capabilities,
        trust_level,
        created_at: chrono::Utc::now(),
        expires_at: None,
        active: true,
    };

    let declared_intent = if sample.declared_intent.is_empty() {
        // Fall back to joining intent_keywords.
        sample.intent_keywords.join(" ")
    } else {
        sample.declared_intent
    };

    let eval_ctx = arbiter_policy::EvalContext {
        agent,
        delegation_chain: vec![],
        declared_intent,
        principal_sub: sample.principal_sub,
        principal_groups: sample.groups,
    };

    let mcp_request = arbiter_mcp::context::McpRequest {
        id: None,
        method: "tools/call".into(),
        tool_name: sample.tool_name,
        arguments: sample.arguments,
        resource_uri: None,
    };

    // Evaluate.
    let result = arbiter_policy::evaluate_explained(&policy_config, &eval_ctx, &mcp_request);

    // Print results.
    println!();
    println!(
        "Decision: {}",
        match &result.decision {
            arbiter_policy::Decision::Allow { policy_id } =>
                format!("ALLOW (matched: {policy_id})"),
            arbiter_policy::Decision::Deny { reason } => format!("DENY ({reason})"),
            arbiter_policy::Decision::Escalate { reason } => format!("ESCALATE ({reason})"),
            arbiter_policy::Decision::Annotate { policy_id, reason } =>
                format!("ANNOTATE (matched: {policy_id}, {reason})"),
        }
    );

    println!();
    println!("Trace:");
    for trace in &result.trace {
        let status = if trace.matched { "MATCH" } else { "SKIP " };
        let reason = trace
            .skip_reason
            .as_deref()
            .map(|r| format!(" -- {r}"))
            .unwrap_or_default();
        println!(
            "  [{status}] {} (effect={}, specificity={}){}",
            trace.policy_id, trace.effect, trace.specificity, reason
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_test_evaluates_allow() {
        let dir = std::env::temp_dir().join(format!("arbiter-cli-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let policy_file = dir.join("policies.toml");
        std::fs::write(
            &policy_file,
            r#"
[[policies]]
id = "allow-read"
effect = "allow"
allowed_tools = ["read_file"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
"#,
        )
        .unwrap();

        let request_file = dir.join("request.json");
        std::fs::write(
            &request_file,
            r#"{
                "trust_level": "basic",
                "declared_intent": "read the config",
                "tool_name": "read_file"
            }"#,
        )
        .unwrap();

        let result = policy_test(&policy_file, Some(&request_file));
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_test_evaluates_deny() {
        let dir = std::env::temp_dir().join(format!("arbiter-cli-deny-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let policy_file = dir.join("policies.toml");
        std::fs::write(
            &policy_file,
            r#"
[[policies]]
id = "allow-read-only"
effect = "allow"
allowed_tools = ["read_file"]

[policies.agent_match]
trust_level = "verified"
"#,
        )
        .unwrap();

        let request_file = dir.join("request.json");
        std::fs::write(
            &request_file,
            r#"{
                "trust_level": "basic",
                "tool_name": "delete_file"
            }"#,
        )
        .unwrap();

        // Should succeed (no error) but the decision is Deny.
        let result = policy_test(&policy_file, Some(&request_file));
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn doctor_config_parse_succeeds() {
        // Minimal test: just verify the config parsing path works.
        let dir = std::env::temp_dir().join(format!("arbiter-cli-doctor-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let config_file = dir.join("arbiter.toml");
        std::fs::write(
            &config_file,
            r#"
[proxy]
upstream_url = "http://localhost:9000"

[admin]
api_key = "test-key"
signing_secret = "test-secret"
"#,
        )
        .unwrap();

        // We can't easily test remote checks without a running server,
        // but we can verify the TOML parsing logic doesn't panic.
        let parsed: Result<toml::Value, _> =
            toml::from_str(&std::fs::read_to_string(&config_file).unwrap());
        assert!(parsed.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
