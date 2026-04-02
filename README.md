# Arbiter: Firewall for MCP

[![CI](https://github.com/cyrenei/arbiter-mcp-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/cyrenei/arbiter-mcp-firewall/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Donate](https://img.shields.io/badge/Sponsor-♡-ff69b4)](https://github.com/sponsors/cyrenei)

A lightweight Rust binary that sits between AI agents and MCP (Model Context Protocol) servers, enforcing
deny-by-default authorization, session budgets, drift detection, and
structured auditing on every tool call.

Arbiter governs what agents are allowed to do.
It does not govern what agents try to do. It protects the platform by
reducing the tool-call attack surface.

## Why?

AI agents act autonomously at machine speed. A single misconfigured agent
can run DDL on production databases, export customer data, or escalate
privileges, with nobody in the loop to stop it.

Traditional IAM was built for humans who log in, make decisions, and log out.
It doesn't handle agents that fire hundreds of tool calls per session and can
reason their way into destructive actions on stale data.

Arbiter sits in the request path and enforces:

- **What** an agent can do (deny-by-default tool allowlists)
- **How much** it can do (session time limits and call budgets)
- **Whether it should** (drift detection: flags when tool-call operation
  types diverge from session scope)
- **That you'll know** (structured audit trail of every decision)

See [Why MCP Tool Calls Need a Firewall](docs/sphinx/understanding/why-agent-iam.md) for the full argument, or
the [QuantumBank case study](https://cyrenei.github.io/arbiter-mcp-firewall/case-study.html) for a worked example
showing 2 allowed and 4 blocked tool categories.

## Who is Arbiter for?

Teams deploying AI agents over MCP that need per-tool-call access control
they can self-host.

Arbiter is not an identity provider. It sits downstream of your IdP (Okta,
Auth0, Keycloak) and enforces policy on what gets through. If you need
centralized NHI management across hundreds of service identities, look at
[Aembit](https://aembit.io). If you need a managed platform, this isn't
it. Arbiter is open-source infrastructure you operate yourself.

## Disclaimer

**This software is provided AS IS, with no warranty and no support.** Use it
at your own risk. There are no paid tiers, no license keys, and no gated
features. Everything in this repository is free and open source under
Apache 2.0.

## Support Arbiter

Your support makes a difference and helps us offer our products free of charge. While not required,
if you want to help, feel free throw a few dollars our way; it's deeply appreciated and we will see it makes it's way to a more secure internet.

**[Sponsor on GitHub](https://github.com/sponsors/cyrenei)**

## Features

- **Agent identity & delegation.** Register agents with trust levels and
  capabilities; delegate to sub-agents with narrowed scope; cascade
  deactivation
- **Deny-by-default authorization:** policy engine that evaluates agent
  identity, session context, tool name, and parameter constraints
- **Task sessions.** Time-limited, budget-capped, tool-whitelisted sessions
  per task
- **Drift detection:** flags or blocks when tool-call operation types
  diverge from session scope (e.g., write calls during a read-scoped session)
- **OAuth 2.1 JWT validation.** JWKS caching, multi-issuer support,
  token introspection fallback
- **MCP protocol parsing:** extracts tool names, arguments, and resource URIs
  from JSON-RPC bodies
- **Structured audit logging.** JSONL audit trail with automatic argument
  redaction for sensitive fields
- **Prometheus metrics:** request counts, tool call counts, latency
  histograms, active sessions gauge
- **Environment-based secrets.** Admin API key and token signing secret
  loaded from `ARBITER_ADMIN_API_KEY` and `ARBITER_SIGNING_SECRET` environment
  variables; startup warnings when defaults are detected; constant-time API
  key comparison to prevent timing side-channels
- **Per-agent session cap:** configurable `max_concurrent_sessions_per_agent`
  (default 10) prevents session multiplication attacks where a single agent
  opens many sessions to bypass per-session rate limits
- **Credential scrubbing.** When credential injection is active, upstream
  responses are scanned for the exact secrets Arbiter injected (in multiple
  encodings: plaintext, URL-encoded, JSON-escaped, hex, base64) and replaced
  with `[CREDENTIAL]` before the agent sees them

## Architecture

```
Agent ──▶ Arbiter Proxy (:8080) ──▶ MCP Server
              │
              ├── Middleware chain: tracing → metrics → audit → oauth
              │   → mcp-parse → session → policy → behavior → forward
              │
              └── Admin API (:3000): agent registration, delegation, tokens
```

See [Architecture](docs/sphinx/understanding/architecture.md) for the full middleware
chain, crate dependency graph, and data flow.

## Install

```bash
curl -sSf https://raw.githubusercontent.com/cyrenei/arbiter-mcp-firewall/main/install.sh | sh
```

Downloads the latest binary for your platform (Linux/macOS, amd64/arm64) with SHA256 verification. Installs both `arbiter` and `arbiter-ctl`. No sudo required.

To update an existing installation:

```bash
arbiter-ctl update
```

## Quickstart

```bash
docker compose up --build -d
curl http://localhost:8080/health           # → OK
curl -X POST http://localhost:3000/agents \
  -H "x-api-key: arbiter-quickstart-key"  \
  -H "Content-Type: application/json"       \
  -d '{"owner":"user:alice","model":"gpt-4","capabilities":["read"],"trust_level":"basic"}'
```

Full walkthrough: [Quickstart](docs/sphinx/getting-started/quickstart.md)

## Configuration

Single TOML file with sections for each subsystem:

```toml
[proxy]
listen_port = 8080
upstream_url = "http://mcp-server:8081"

[oauth]
# jwks_cache_ttl_secs = 3600
# [[oauth.issuers]]
# ...

[policy]
file = "policies.toml"

[sessions]
default_time_limit_secs = 3600
default_call_budget = 1000
max_concurrent_sessions_per_agent = 10

[audit]
enabled = true
file_path = "/var/log/arbiter/audit.jsonl"
redaction_patterns = ["password", "secret", "token"]

[admin]
listen_port = 3000
# api_key loaded from ARBITER_ADMIN_API_KEY env var (recommended)
# signing_secret loaded from ARBITER_SIGNING_SECRET env var (recommended)
```

See [arbiter.example.toml](arbiter.example.toml) for the full reference.

## Policy Language

```toml
[[policies]]
id = "allow-read-basic"
effect = "allow"
allowed_tools = ["read_file", "list_dir"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read", "analyze"]
```

Full reference: [Policy Language](docs/sphinx/guides/policy.md)

## Project Structure

```
crates/
├── arbiter/            Integration binary; wires everything together
├── arbiter-proxy/      Async HTTP reverse proxy with middleware chain
├── arbiter-oauth/      OAuth 2.1 JWT validation middleware
├── arbiter-identity/   Agent identity model and in-memory registry
├── arbiter-lifecycle/  Agent lifecycle REST API (axum)
├── arbiter-cli/        CLI for agent management
├── arbiter-mcp/        MCP JSON-RPC request parser
├── arbiter-policy/     Deny-by-default policy engine
├── arbiter-session/    Task session management
├── arbiter-behavior/   Drift detection
├── arbiter-metrics/    Prometheus-compatible metrics
└── arbiter-audit/      Structured audit logging with redaction
```

## Building from Source

```bash
cargo build --release
./target/release/arbiter --config arbiter.toml --log-level info
```

## Status

The core enforcement pipeline (policy engine, session management, drift
detection, audit logging) is complete and tested. The
[QuantumBank scenario](https://cyrenei.github.io/arbiter-mcp-firewall/case-study.html) demonstrates end-to-end
enforcement across 6 tool categories.

This project is provided as-is.

## License

[Apache License 2.0](LICENSE)

## Support

[GitHub Issues](https://github.com/cyrenei/arbiter-mcp-firewall/issues), no SLA,
no guaranteed response time.
