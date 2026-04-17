# Arbiter: Firewall for MCP

[![CI](https://github.com/cyrenei/arbiter-mcp-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/cyrenei/arbiter-mcp-firewall/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL_v3-blue.svg)](LICENSE)
[![Donate](https://img.shields.io/badge/Sponsor-♡-ff69b4)](https://github.com/sponsors/cyrenei)

A lightweight proxy that sits between AI agents and MCP (Model Context Protocol) servers, enforcing
deny-by-default authorization, session budgets, drift detection, and
structured auditing on every tool call.

## Why?

AI agents act autonomously at machine speed. A single misconfigured agent
can run DDL on production databases, export customer data, or escalate
privileges, with nobody in the loop to stop it.

Applications like Claude Code let us define permissions. But that requires us to place trust
in Claude Code, a closed source project, maintained by a corporation that operates non-transparently and is incentivized to push
for more control over your computer, not less.

Arbiter is agnostic of development tooling and enforces:

- **What** an agent can do (deny-by-default tool allowlists)
- **How much** it can do (session time limits and call budgets)
- **Whether it should** (drift detection: flags when tool-call operation
  types diverge from session scope)
- **That you'll know** (structured audit trail of every decision)

See [Why MCP Tool Calls Need a Firewall](docs/sphinx/understanding/why-agent-iam.md) for the full argument, or
the [QuantumBank case study](https://cyrenei.github.io/arbiter-mcp-firewall/case-study.html) for a worked example
showing 2 allowed and 4 blocked tool categories.

## Limitations

Arbiter governs what agents are **allowed** to do.
It does not govern what agents **might try** to do. It protects the platform by
reducing the tool-call attack surface that agentic applications typically leave open, or
require. This is valuable. But a clever-enough hacker with sinister-enough intentions
will be able to deceive a model into hacking **any** proxy. That's a far deeper problem requiring
greater compute than a proxy can performantly handle.

## Who is Arbiter for?

Teams deploying AI agents over MCP that need per-tool-call access control
they can self-host.

Arbiter is not an identity provider. It sits downstream of your IdP (Okta,
Auth0, Keycloak) and enforces policy on what gets through. If you need
centralized NHI management across hundreds of service identities, look at
[Aembit](https://aembit.io). If you need a managed platform, this isn't
it. Arbiter is open-source infrastructure you operate yourself.

### Trust model

| Actor | Trust level | Rationale |
|-------|------------|-----------|
| **Operator** | Trusted | Configures Arbiter, writes policy files, manages agent registration |
| **Policy file** | Authoritative | Defines what tools are allowed; not validated for correctness |
| **AI agent** | Untrusted | Tool calls are intercepted, evaluated, and audit-logged before forwarding |
| **Declared intent** | Advisory | Used for drift detection, not enforcement; an adversarial agent would lie |

Arbiter is designed for scenarios where the platform operator is trusted but the AI agents are not — the operator writes policy, the agents operate within it.

## Disclaimers

1. **This software is provided AS IS, with no warranty and no support.** Use it
at your own risk. There are no paid tiers, no license keys, and no gated
features. Everything in this repository is free and open source under
GPL-3.0-or-later.

2. Due to resource constraints, this project is currently managed agentically, under close human supervision. Take that as you will.

## Sponsor

This is free software with no paid tiers. If you get value from it and want to help keep it going, consider sponsoring.

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

[GNU General Public License v3.0 or later](LICENSE)

Releases `v0.0.11` and earlier were published under [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). Starting with `v0.1.0`, the project is licensed under GPL-3.0-or-later. Prior releases retain their original Apache-2.0 terms; the license change applies to the `v0.1.0` codebase and all subsequent work. Inbound contributions are accepted under the project's outbound license (GPL-3.0-or-later).

## Support

[GitHub Issues](https://github.com/cyrenei/arbiter-mcp-firewall/issues), no SLA,
no guaranteed response time.

Contact: [cyrenei@proton.me](mailto:arbitersecurity@proton.me)

## PGP Public Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=gMhW
-----END PGP PUBLIC KEY BLOCK-----
```
