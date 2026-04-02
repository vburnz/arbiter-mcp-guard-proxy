# Security Model

Arbiter's security posture starts from a simple principle: nothing is permitted unless explicitly allowed. This page describes the trust boundaries, threat actors, specific threats, and what Arbiter does (and doesn't) protect against.

## Trust Boundaries

```text
                  ┌─────────────────────────────────────────────────┐
                  │              Arbiter Gateway                    │
 ┌──────────┐    │  :8080 proxy         :3000 admin API            │    ┌────────────┐
 │  Agent    │──->│  ┌───────────────┐   ┌───────────────────┐     │──->│ Upstream   │
 │  Client   │<──│  │ 9-stage chain │   │ x-api-key gated   │     │<───│ MCP Server │
 └──────────┘    │  └───────────────┘   └───────────────────┘     │    └────────────┘
                  │         │                    │                  │
                  └─────────┼────────────────────┼──────────────────┘
                            v                    v
                  ┌──────────────┐     ┌──────────────────┐
                  │  IdP (OIDC)  │     │  Operator / CI   │
                  └──────────────┘     └──────────────────┘
```

| Boundary | Trust Level | Notes |
|----------|------------|-------|
| Agent to Proxy | **Untrusted** | Every request requires a valid JWT and session ID. The 9-stage chain is the enforcement surface. |
| Admin API to Operator | **Fully trusted** | A static `x-api-key` gates all admin endpoints. Whoever holds the key controls agent registration, token issuance, policy mutation, and session management. |
| Proxy to Upstream | **Partially trusted** | Requests are forwarded only after authorization. When credential injection is active, responses are scrubbed for injected secrets before delivery to the agent. |
| Proxy to IdP | **Trusted** | JWKS keys fetched over HTTPS and cached. A compromised IdP would issue tokens Arbiter accepts. |

## Threat Actors

| Actor | Motivation | Access |
|-------|-----------|--------|
| **Compromised Agent** | Exfiltrate data, escalate privilege, pivot through delegation | Valid JWT, potentially an active session |
| **Malicious Operator** | Weaken policies, register rogue agents, tamper with audit | Full admin API access |
| **Network Attacker** | Intercept tokens, replay requests, deny service | Network path between components |
| **Malicious Upstream** | Inject payloads in responses, manipulate agent behavior | Receives forwarded requests, returns arbitrary responses |

## Hardened Defaults

Arbiter ships with security-first defaults. You have to explicitly weaken them:

- **`require_session = true`:** MCP requests without a session header are denied outright
- **`strict_mcp = true`:** non-MCP POST requests are rejected, preventing protocol smuggling
- **`deny_non_post_methods = true`:** non-POST HTTP methods (GET, PUT, DELETE, PATCH) are rejected with 405, preventing authorization bypass via method switching
- **`require_healthy = true`:** (audit) denies all traffic when the audit sink is degraded, preventing attackers from blinding the audit trail before executing their attack
- **Deny-by-default policy engine.** No request is authorized unless an Allow policy explicitly matches. When no policies are loaded, all MCP traffic is denied.
- **Audit logging enabled.** Automatic redaction of 24 sensitive field patterns (passwords, tokens, secrets, credentials, PII)
- **Constant-time API key comparison:** uses the `subtle` crate (`ConstantTimeEq`) to prevent timing side-channel attacks on the admin API
- **Admin API rate limiting.** Sliding-window rate limiter (default 60 requests/minute) on all admin endpoints to prevent credential-stuffing and automated abuse
- **Session-agent binding:** when a session is active, the `x-agent-id` header is required and must match the session's owning agent. Omitting the header is denied.

## What Arbiter Defends Against

### Unauthorized Tool Calls
The deny-by-default policy engine rejects any tool call that doesn't match an explicit Allow policy. No matching policy means no access. Period.

### Session Hijacking
Sessions are identified by UUIDv4, scoped to a specific agent. The middleware validates that the `x-agent-id` header matches the session's agent ID on every request. The header is mandatory when a session is present, preventing bypass via header omission. Time limits and call budgets bound the exploitation window.

### Privilege Escalation Through Delegation
Delegation chains enforce scope narrowing: a sub-agent's capabilities must be a subset of its parent's. If a parent is deactivated, all delegates are cascade-deactivated. The delegation chain is snapshotted at session creation and recorded in every audit entry.

### Behavioral Drift
The anomaly detector classifies operations and compares them to the session's declared intent. An agent that declared "read configuration files" but starts calling write tools gets flagged or blocked, even if those tools appear on its whitelist.

All intent tiers are subject to anomaly detection. Admin-intent sessions still flag delete operations for forensic visibility. Repeated anomalies trigger automatic trust degradation: after 5 anomaly flags (with hourly decay), the agent's trust level is demoted one tier (e.g., Trusted to Verified). Trust demotion is automatic; recovery requires manual re-promotion by an operator.

### Audit Tampering
Audit records are append-only JSONL. When hash chaining is enabled, each record carries a BLAKE3 hash linking it to its predecessor. Insertion, deletion, and modification of records are detectable through chain verification. All admin API operations are also audit-logged with structured tracing.

Batch MCP requests (JSON-RPC arrays) record all tool calls in the audit entry, not just the first, preventing attackers from hiding operations behind a benign leading request.

### Protocol Smuggling
Strict MCP mode rejects non-JSON-RPC POST traffic. Combined with the MCP parser that validates JSON-RPC structure, this prevents attackers from smuggling non-MCP requests through the proxy.

### Credential Leakage
The credential injection system substitutes `${CRED:ref}` patterns in request bodies so agents never see raw secrets. When credentials are injected, response scrubbing checks upstream responses for the exact injected values (across multiple encodings) and replaces them with `[CREDENTIAL]` before they reach the agent.

### Session Multiplication
A per-agent concurrent session cap (default 10) prevents an agent from opening many sessions to bypass per-session rate limits. Exceeding the cap returns HTTP 429.

## What Arbiter Does NOT Defend Against

Being honest about boundaries matters more than claiming total coverage.

### Prompt injection and agent reasoning compromise

Arbiter is a syntactic enforcement layer. It sees tool names, parameters, and session metadata. It does not inspect the agent's reasoning, system prompt, or conversation history. If an adversary compromises the agent's reasoning via prompt injection and the agent uses its *legitimate, whitelisted tools* to carry out the adversary's intent, Arbiter sees valid tool calls from a valid agent within its budget. Defense against prompt injection belongs in the agent framework, model provider, and system prompt — not at the network boundary.

### Semantic attacks via legitimate tools

Arbiter enforces *what* tools an agent can call and *what parameters* it can pass (via regex constraints). It cannot evaluate whether the agent's use of a permitted tool is appropriate in context. An agent whitelisted for `write_file` that writes sensitive data to an attacker-controlled path is making a legitimate tool call with legitimate parameters. Arbiter blocks unauthorized tools; it does not judge authorized ones.

### Non-MCP traffic

Arbiter is an MCP tool-call firewall, not a general-purpose API gateway. Non-POST HTTP methods (GET, PUT, DELETE, PATCH) are **denied by default** with 405 Method Not Allowed (`deny_non_post_methods = true`). If you set `deny_non_post_methods = false` to proxy non-MCP REST traffic, those requests are forwarded without session validation, policy evaluation, or behavioral analysis. Use upstream-level access control for non-MCP endpoints.

### Drift detection via tool naming

The behavioral anomaly detector classifies operations by tool name patterns (`read_*`, `write_*`, `delete_*`, `admin_*`). A tool named `read_backup` that actually deletes data would be classified as a read operation. Drift detection catches *unintentional* scope drift where tool naming follows convention. It does not catch adversarial tool naming or tools whose names don't reflect their actual operation.

### Infrastructure-layer threats

- **Adversarial upstream MCP server.** Arbiter assumes the upstream is **semi-trusted** — cooperating with the protocol but potentially buggy or partially compromised. Credential scrubbing is defense-in-depth against accidental credential echo, not a guarantee against a fully adversarial upstream that deliberately tries to exfiltrate injected credentials. The scrubber covers plaintext, URL-encoded (upper and lowercase), JSON-escaped, hex (upper/lower), base64, base64url, double-URL-encoded, and Unicode JSON-escaped variants. Response bodies are decompressed before scrubbing. Encodings NOT covered include HTML entities, octal, and split/chunked credentials across multiple fields. If your upstream is actively hostile, the correct mitigation is to not give it credentials — use upstream-side secret management instead of Arbiter credential injection.
- **Network-layer attacks.** Arbiter doesn't terminate TLS. Put a TLS-terminating reverse proxy or load balancer in front.
- **Compromised identity provider:** if the IdP is compromised, it can issue tokens Arbiter will accept.
- **DDoS at the network layer.** Use a CDN or WAF for volumetric protection.
- **Side-channel attacks on the runtime.** Rust's memory safety helps, but this is out of scope.

## Risk Matrix

| Threat | Likelihood | Impact | Risk Level | Arbiter Coverage |
|--------|-----------|--------|------------|-----------------|
| Credential exposure | Medium | Critical | **High** | Injection + scrubbing |
| Policy bypass (silent reload) | Medium | Critical | **High** | Hash-chained audit detects |
| Agent impersonation | Medium | High | **High** | Session-agent binding |
| Prompt injection → legitimate tool misuse | Medium | High | **High** | **Out of scope** — syntactic layer, not semantic |
| Data exfiltration via tool calls | Low | High | Medium | Policy + parameter constraints |
| Audit tampering | Low | High | Medium | BLAKE3 hash chaining |
| Session hijacking | Low | High | Medium | UUIDv4 + agent binding |
| Privilege escalation via delegation | Low | High | Medium | Scope narrowing + cascade deactivation |
| Semantic attack via permitted tools | Low | High | Medium | **Out of scope** — cannot judge intent |
| Resource exhaustion / DoS | Low | Medium | **Low** | Session budgets + rate limits |

## Known Limitations

### Admin API: single shared key

The admin API is protected by a single static API key (`x-api-key`). All operators share this key. There is no per-operator scoping, key rotation without restart, or per-key audit identity. All admin actions are attributable to "whoever has the key," not to specific operators. For environments requiring individual accountability (SOC 2 CC6.1), restrict admin API access to automated systems and audit key distribution.

**Roadmap:** OAuth integration for the admin API, per-operator API keys with scoped permissions.

## Hardening Recommendations

Ordered by risk reduction per effort:

1. **Load secrets from environment variables.** Set `ARBITER_ADMIN_API_KEY` and `ARBITER_SIGNING_SECRET`. Never use the compiled defaults in production.

2. **Keep hash-chained audit enabled.** `hash_chain` defaults to `true` in `[audit]`; leave it on for tamper-detectable logs. Each record carries `chain_sequence`, `chain_prev_hash`, and `chain_record_hash`, and concurrent writes are serialized so on-disk order matches sequence order.

3. **Cap sessions per agent.** The default of 10 is reasonable. Lower it if agents don't need concurrent sessions.

4. **Enable anomaly escalation.** Set `escalate_anomalies = true` in `[sessions]` to hard-block behavioral drift instead of just logging it.

5. **Use TLS termination.** Put Arbiter behind a reverse proxy (nginx, Caddy, or a cloud load balancer) that terminates TLS.

6. **Restrict admin API access.** Bind the admin API to `127.0.0.1` or use network-level access controls to limit who can reach port 3000.

7. **Enable metrics authentication.** Set `require_auth = true` in `[metrics]` to prevent unauthenticated access to operational telemetry (tool names, allow/deny rates, active sessions).

8. **Enable storage encryption.** Set `ARBITER_STORAGE_ENCRYPTION_KEY` (64-char hex) to encrypt session data at rest in SQLite.

## Next Steps

- {doc}`../guides/audit`: configure audit logging and hash chaining
- {doc}`../guides/policy`: write authorization policies
- {doc}`../reference/attack-scenarios`: see Arbiter defend against real attacks
