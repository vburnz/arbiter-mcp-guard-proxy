# Session Management

Sessions are the operational boundary around agent work. Every task an agent performs runs inside a session that declares what the agent intends to do, which tools it can use, how long it has, and how many calls it can make. Think of a session as a work order: scoped, budgeted, and auditable.

For a hands-on walkthrough, see {doc}`../getting-started/first-session`. This guide covers the full model.

## Session Anatomy

| Field | Type | Purpose |
|-------|------|---------|
| `session_id` | UUID | Unique identifier, passed as `x-arbiter-session` header |
| `agent_id` | UUID | The agent this session belongs to |
| `declared_intent` | string | Free-form description of the planned work |
| `authorized_tools` | string[] | Tools the agent can call (anything else is denied) |
| `time_limit` | duration | How long before the session expires |
| `call_budget` | integer | Maximum tool calls before exhaustion |
| `rate_limit_per_minute` | integer | Optional per-minute call cap |
| `data_sensitivity_ceiling` | enum | Maximum data sensitivity tier: public, internal, confidential, restricted |
| `status` | enum | Active, Closed, or Expired |

## Creating Sessions

```bash
$ curl -s -X POST http://localhost:3000/sessions \
  -H "x-api-key: arbiter-dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "declared_intent": "analyze Q4 transaction patterns for risk assessment",
    "authorized_tools": ["query_transactions", "get_account_summary", "generate_risk_report"],
    "time_limit_secs": 3600,
    "call_budget": 200,
    "rate_limit_per_minute": 30,
    "data_sensitivity": "internal"
  }'
```

If you omit optional fields, Arbiter uses defaults from the `[sessions]` config section:

- `time_limit_secs` defaults to `default_time_limit_secs` (3600)
- `call_budget` defaults to `default_call_budget` (1000)

## Enforcement Chain

On every proxied request, the session middleware runs five checks in order:

1. **Existence and status.** The session must exist and be Active. Expired or Closed sessions return 408.
2. **Agent binding.** The JWT's agent ID must match the session's `agent_id`. No sharing sessions between agents.
3. **Tool whitelist:** the tool being called must appear in `authorized_tools`. Missing tools get 403.
4. **Budget:** if `calls_made >= call_budget`, the session is exhausted. Returns 429.
5. **Rate limit:** if the current-window call count exceeds `rate_limit_per_minute`, returns 429.

If all checks pass, the call counter increments and the request proceeds.

## Budget Warnings

When remaining budget or time drops below the warning threshold (default 20%, configurable via `warning_threshold_pct`), Arbiter adds warning headers to the response:

```text
X-Arbiter-Warning: budget_remaining=15, budget_total=200
X-Arbiter-Warning: time_remaining_secs=180, time_limit_secs=3600
```

Agents or their orchestrators can use these to wrap up gracefully before the hard limits kick in.

## Data Sensitivity Ceilings

Sessions carry a `data_sensitivity_ceiling` that sets the maximum tier of data the session can access:

| Tier | Description |
|------|-------------|
| `public` | Open data, no restrictions |
| `internal` | Organization-internal, not for external sharing |
| `confidential` | Sensitive business data |
| `restricted` | Regulated data (PII, PHI, financial) |

Tiers are ordered. A session with an `internal` ceiling cannot access `confidential` or `restricted` data.

## Concurrent Session Limits

The `max_concurrent_sessions_per_agent` setting (default 10) caps how many active sessions one agent can hold simultaneously. This closes a specific attack vector: a compromised agent opening many sessions to multiply its effective call budget.

When an agent hits the cap, session creation returns HTTP 429:

```json
{
  "error": "TooManySessions",
  "message": "agent has 10 active sessions (max: 10)"
}
```

Existing sessions keep working. The cap is enforced at creation time only.

## Session Lifecycle

```text
              create
                │
                v
             Active ──────> Expired (time_limit exceeded)
                │
                │  DELETE /sessions/{id}
                v
              Closed
```

Active sessions transition to Expired automatically when the time limit passes. You can also close a session explicitly through the API, which is the clean way to signal that a task is done.

## Configuration Defaults

These go in the `[sessions]` section of `arbiter.toml`:

```toml
[sessions]
default_time_limit_secs = 3600
default_call_budget = 1000
warning_threshold_pct = 20.0
max_concurrent_sessions_per_agent = 10
rate_limit_window_secs = 60
cleanup_interval_secs = 60
escalate_anomalies = false
```

See {doc}`../reference/configuration` for full descriptions of each option.

## Next Steps

- {doc}`behavior`: how declared intent drives anomaly detection
- {doc}`policy`: how policies interact with session tool whitelists
- {doc}`../reference/api`: full session API reference
