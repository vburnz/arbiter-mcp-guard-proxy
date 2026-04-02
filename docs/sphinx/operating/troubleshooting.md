# Troubleshooting

When something goes wrong, Arbiter is usually telling you exactly what happened: in the HTTP response, the audit log, or the structured logs. This guide organizes common problems by symptom.

## "My request is getting denied"

This is the most common question, and the answer is almost always in the response body.

### Step 1: Read the Error Response

Arbiter returns JSON error bodies with specific codes:

| HTTP Status | Error Code | Meaning |
|-------------|-----------|---------|
| 403 | `PolicyDenied` | No matching Allow policy (deny-by-default) |
| 403 | `ToolNotAuthorized` | Tool isn't on the session's whitelist |
| 403 | `AnomalyDenied` | Behavioral anomaly detected, escalation is on |
| 403 | `StrictMcpViolation` | Non-JSON-RPC POST in strict MCP mode |
| 408 | `SessionExpired` | Session time limit exceeded |
| 429 | `BudgetExhausted` | Call budget exhausted |
| 429 | `RateLimited` | Per-minute rate limit exceeded |
| 429 | `TooManySessions` | Per-agent concurrent session cap hit |
| 401 | `Unauthorized` | Missing or invalid JWT |

### Step 2: Check the Audit Log

```bash
$ tail -1 /var/log/arbiter/audit.jsonl | jq .
```

The `authorization_decision`, `policy_matched`, and `anomaly_flags` fields tell you exactly what happened.

### Step 3: Use Policy Explain

Dry-run the request against your policies:

```bash
$ curl -s -X POST http://localhost:3000/policy/explain \
  -H "x-api-key: arbiter-dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "trust_level": "basic",
    "declared_intent": "read configuration files",
    "tool_name": "read_file"
  }' | jq .
```

This shows which policy matched (or that none did) and the decision trace.

## "My request doesn't reach the upstream"

### Missing Session Header

If `require_session = true` (the default), every MCP POST must include an `x-arbiter-session` header. Without it, the request is rejected before it reaches the policy engine.

### Missing Agent ID

The `x-agent-id` header must be present and match the JWT's agent claims.

### Non-MCP POST in Strict Mode

If `strict_mcp = true` (the default), POST requests with non-JSON-RPC bodies are rejected. Check that your request body is valid JSON-RPC 2.0.

## "Session creation fails"

### TooManySessions

The agent already has `max_concurrent_sessions_per_agent` active sessions. Close some before creating new ones:

```bash
$ curl -s -X DELETE http://localhost:3000/sessions/$SESSION_ID \
  -H "x-api-key: arbiter-dev-key"
```

### Invalid Agent ID

The agent must be registered and active. Check:

```bash
$ curl -s http://localhost:3000/agents/$AGENT_ID \
  -H "x-api-key: arbiter-dev-key" | jq '.active'
```

## "Startup warnings"

### Default API Key Warning

```text
WARN admin API key is the compiled default -- set ARBITER_ADMIN_API_KEY for production
```

You're using the development API key. Set a real one:

```bash
export ARBITER_ADMIN_API_KEY="$(openssl rand -base64 32)"
```

### Default Signing Secret Warning

```text
WARN signing secret is the compiled default -- set ARBITER_SIGNING_SECRET for production
```

Same thing for the JWT signing secret:

```bash
export ARBITER_SIGNING_SECRET="$(openssl rand -base64 32)"
```

## "Policy changes aren't taking effect"

### File Watching Disabled

Policy hot-reload requires `watch = true`:

```toml
[policy]
file = "policies.toml"
watch = true
```

Without it, you need to restart Arbiter or call the reload endpoint:

```bash
$ curl -s -X POST http://localhost:3000/policy/reload \
  -H "x-api-key: arbiter-dev-key"
```

### Syntax Errors in Policy File

Validate before deploying:

```bash
$ curl -s -X POST http://localhost:3000/policy/validate \
  -H "x-api-key: arbiter-dev-key" \
  -H "Content-Type: application/json" \
  -d '{"toml": "'"$(cat policies.toml)"'"}' | jq .
```

## "Arbiter-ctl doctor"

The CLI includes a diagnostic command that checks common configuration issues:

```bash
$ arbiter-ctl doctor --config arbiter.toml
```

This validates:
- Configuration file parsing
- Policy file syntax and loading
- Audit log path writability
- Storage backend connectivity

## Next Steps

- {doc}`../guides/audit`: understanding audit log entries
- {doc}`../reference/configuration`: full configuration reference
- {doc}`../reference/api`: admin API endpoints
