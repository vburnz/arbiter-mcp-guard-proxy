# Architecture

Arbiter is an MCP tool-call firewall that sits between AI agents and MCP servers. Every request an agent makes passes through Arbiter before it reaches the upstream server. Every response passes back through on the way out.

Two processes run side by side:

- A **proxy** on port 8080 that handles MCP traffic through a 9-stage middleware chain
- An **admin API** on port 3000 that handles agent registration, delegation, token issuance, and session management

```text
┌──────────┐     ┌─────────────────────────────────────────────┐     ┌────────────┐
│  Agent   │────>│                 Arbiter                     │────>│ MCP Server │
│  Client  │<────│  (proxy :8080     admin API :3000)          │<────│ (upstream)  │
└──────────┘     └─────────────────────────────────────────────┘     └────────────┘
                           │
                           v
                   ┌───────────────┐
                   │   Keycloak /  │
                   │   IdP (OIDC)  │
                   └───────────────┘
```

## The Middleware Chain

Every proxied request passes through nine stages, in order. Every response passes back through the same stages in reverse. Any stage can reject a request. When that happens, the response goes straight back to the client and downstream stages are skipped. Audit and metrics are still recorded regardless.

```text
Request ──> Tracing ──> Metrics ──> Audit ──> OAuth ──> MCP Parse
                                                           │
            <── Forward Upstream <── Behavior <── Policy <── Session
```

Here's what each stage does:

| # | Stage | What It Does |
|---|-------|-------------|
| 1 | **Tracing** | Assigns a span and structured log entry to the request |
| 2 | **Metrics** | Records Prometheus counters and starts the latency timer |
| 3 | **Audit** | Begins capturing the audit entry (timestamp, request ID) |
| 4 | **OAuth** | Validates the JWT bearer token against cached JWKS keys, injects claims |
| 5 | **MCP Parse** | Parses the JSON-RPC body, extracts tool name, arguments, resource URI |
| 6 | **Session** | Validates the session is active, tool is whitelisted, budget isn't blown |
| 7 | **Policy** | Evaluates authorization rules; deny-by-default, specificity wins |
| 8 | **Behavior** | Flags when operation types diverge from session scope |
| 9 | **Forward** | Proxies the request upstream and inspects the response on the way back |

The ordering matters. OAuth runs before session validation because you need to know *who* is making the request before you can check *whether they're allowed*. Policy runs after session validation because the session provides the declared intent that policies match against.

## A Request's Journey

Walk through what happens when an agent calls `query_transactions`:

1. The agent sends an HTTP POST to Arbiter's proxy port (8080) with a JSON-RPC body, a JWT in the Authorization header, and a session ID in `x-arbiter-session`.

2. **Tracing** tags the request with a unique span for structured logging.

3. **Metrics** increments `requests_total` and starts a duration timer.

4. **Audit** timestamps the request and generates a UUID request ID.

5. **OAuth** validates the JWT signature against the cached JWKS for the issuer, checks expiry and audience, and injects the parsed claims (subject, groups) into the request context.

6. **MCP Parse** deserializes the JSON-RPC body. For a `tools/call` method, it extracts the tool name (`query_transactions`) and the arguments (`{"account": "ACC-2847", "period": "2025-Q4"}`).

7. **Session** looks up the session by ID, confirms it belongs to this agent, checks that `query_transactions` is on the tool whitelist, that the call budget hasn't been exceeded, and that the rate limit window hasn't been blown.

8. **Policy** evaluates loaded policies against the request context: agent identity, trust level, declared intent, tool name, and arguments. If no Allow policy matches, the request is denied.

9. **Behavior** classifies `query_transactions` as a read operation and compares it to the session's declared intent. A read intent plus a read operation, so no anomaly.

10. **Forward** proxies the request to the upstream MCP server. On the response path back through this stage:

    - **Credential scrubbing** checks whether any credentials that Arbiter injected into the outgoing request appear in the upstream response. If they do (in any encoding: plaintext, URL-encoded, JSON-escaped, hex, or base64), they're replaced with `[CREDENTIAL]` before the agent sees them.
    - **Audit** finalizes the entry with upstream status code, latency, and any credential scrubbing actions, then writes the JSONL record.
    - **Metrics** records the request duration histogram and tool call counter.

11. The response goes back to the agent.

## Crate Architecture

Arbiter is built as a Rust workspace with 14 crates. Each crate owns one domain:

| Crate | Domain |
|-------|--------|
| `arbiter` | Integration binary that wires everything together |
| `arbiter-proxy` | Async HTTP reverse proxy with middleware chain |
| `arbiter-oauth` | OAuth 2.1 JWT validation, JWKS caching |
| `arbiter-identity` | Agent model, trust levels, delegation chains |
| `arbiter-lifecycle` | Admin REST API (axum) |
| `arbiter-mcp` | MCP JSON-RPC parser |
| `arbiter-policy` | Deny-by-default policy engine |
| `arbiter-session` | Task session management |
| `arbiter-behavior` | Drift detection |
| `arbiter-audit` | Structured JSONL audit logging with redaction |
| `arbiter-metrics` | Prometheus metrics |
| `arbiter-credential` | Credential injection and response scrubbing |
| `arbiter-storage` | Storage abstraction (in-memory + SQLite) |
| `arbiter-cli` | CLI tool (`arbiter-ctl`) |

You don't need to know the crate structure to use Arbiter. It ships as a single binary. But if you're reading the source, the boundaries are clean: each crate has a focused responsibility and a well-defined interface.

## Request and Response Handling

Arbiter processes traffic in both directions:

**Inbound (requests):** The MCP parser extracts tool names and arguments. The policy engine evaluates parameter constraints. Credential references (`${CRED:ref}`) are resolved and injected. Audit redaction strips sensitive fields before logging.

**Outbound (responses):** When credential injection is active, Arbiter scrubs the response body for the exact secrets it injected. Scrubbing covers multiple encodings (plaintext, URL-encoded, JSON-escaped, hex, base64) to catch credentials even if the upstream transforms them. Matches are replaced with `[CREDENTIAL]`. This is a closed-scope defense: Arbiter scrubs what it injected, not arbitrary patterns.

## Key Design Decisions

Four architectural decisions shaped Arbiter's design. Each is documented as a formal Architecture Decision Record:

- **{doc}`../reference/decisions`**: deny-by-default authorization, Rust as the implementation language, in-memory registry as the default storage, TOML as the policy language

## Next Steps

- {doc}`security-model`: the threat model and defense philosophy
- {doc}`../getting-started/quickstart`: get it running
- {doc}`../guides/policy`: write authorization rules
