# Your First Session

Sessions are how Arbiter scopes what an agent can do during a specific task. Without a session, an agent can't make any MCP tool calls through the proxy (when `require_session = true`, which is the default).

This guide walks you through creating a session, understanding what it controls, and watching it enforce limits in practice.

## What a Session Contains

A session is a bundle of constraints:

- **Declared intent:** a free-form string describing what the agent plans to do. The policy engine and anomaly detector both use this.
- **Authorized tools.** The whitelist of tools the agent can call during this session. Anything not on the list is denied.
- **Time limit:** how long the session stays active.
- **Call budget:** maximum number of tool calls before the session is exhausted.
- **Rate limit.** Optional per-minute cap on tool calls.
- **Data sensitivity ceiling:** the maximum sensitivity tier of data this session can access.

## Creating a Session

Sessions are created through the admin API. You'll need an agent registered first (see {doc}`quickstart`).

```bash
$ curl -s -X POST http://localhost:3000/sessions \
  -H "Content-Type: application/json" \
  -H "x-api-key: arbiter-dev-key" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "declared_intent": "read and analyze customer transaction history",
    "authorized_tools": ["query_transactions", "get_account_summary"],
    "time_limit_secs": 1800,
    "call_budget": 100,
    "rate_limit_per_minute": 30,
    "data_sensitivity": "internal"
  }' | jq .
```

The response gives you a session ID:

```json
{
  "session_id": "b7d3f1a2-..."
}
```

Pass this as the `x-arbiter-session` header on every MCP request.

## How Sessions Enforce Limits

Each proxied request triggers a sequence of checks:

1. **Session exists and is active.** Expired or closed sessions are rejected immediately (408 Gone).
2. **Agent matches.** The JWT's agent ID must match the session's agent ID. No borrowing sessions between agents.
3. **Tool is whitelisted.** The requested tool must appear in `authorized_tools`. If it doesn't, 403.
4. **Budget check:** if `calls_made >= call_budget`, the session is exhausted. 429 Too Many Requests.
5. **Rate limit check:** if the call rate in the current window exceeds `rate_limit_per_minute`, 429.
6. **Call counter incremented.** The session's `calls_made` goes up by one.

When the remaining budget or time drops below the warning threshold (default 20%), Arbiter includes `X-Arbiter-Warning` headers in the response so the agent (or its orchestrator) can plan accordingly.

## Declared Intent and Drift Detection

The declared intent drives drift detection. Arbiter classifies the intent string into a tier by keyword matching:

| Intent Tier | Triggered By | Allowed Operations |
|-------------|-------------|-------------------|
| Read | Keywords: read, analyze, query, search, list, get | Read only |
| Write | Keywords: write, create, update, modify, edit | Read + Write |
| Admin | Keywords: admin, manage, configure, deploy, delete | Everything |
| Unknown | No matching keywords | No anomaly detection |

If an agent declares "read and analyze transaction history" (classified as Read intent) but calls a tool classified as a Write or Admin operation, the anomaly detector fires. Depending on configuration, it either logs a warning or blocks the request.

## Session Lifecycle

Sessions move through three states:

```text
Active ──> Expired (time limit exceeded)
  │
  └──> Closed (explicitly closed via API)
```

You can close a session manually:

```bash
$ curl -s -X DELETE http://localhost:3000/sessions/$SESSION_ID \
  -H "x-api-key: arbiter-dev-key" | jq .
```

Or check its status:

```bash
$ curl -s http://localhost:3000/sessions/$SESSION_ID \
  -H "x-api-key: arbiter-dev-key" | jq .
```

## Concurrent Session Limits

A single agent can have at most `max_concurrent_sessions_per_agent` active sessions at once (default 10). This prevents session multiplication attacks where a compromised agent opens many concurrent sessions, each with its own call budget, to bypass per-session limits.

If an agent hits the cap, session creation returns HTTP 429 with the `TooManySessions` error code. Existing sessions continue working.

## Next Steps

- {doc}`../guides/sessions`: advanced session configuration and data sensitivity ceilings
- {doc}`../guides/behavior`: how drift detection works in detail
- {doc}`../reference/api`: full session API reference
