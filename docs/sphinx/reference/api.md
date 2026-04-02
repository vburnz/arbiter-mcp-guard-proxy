# Admin API Reference

The admin API runs on a separate port (default 3000) from the proxy. All endpoints require the `x-api-key` header with a valid admin API key. The key comparison uses constant-time equality to prevent timing side-channel attacks.

## Authentication

Every request must include:

```text
x-api-key: <your-admin-api-key>
```

Missing or invalid keys return 401.

---

## Agents

### Register Agent

```text
POST /agents
```

**Request Body:**

```json
{
  "owner": "user:alice",
  "model": "gpt-4",
  "capabilities": ["read", "write"],
  "trust_level": "basic",
  "expires_at": "2026-04-15T00:00:00Z"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `owner` | string | yes | Human principal (OAuth subject) |
| `model` | string | yes | LLM model identifier |
| `capabilities` | string[] | yes | Agent capabilities |
| `trust_level` | string | yes | `untrusted`, `basic`, `verified`, or `trusted` |
| `expires_at` | string | no | ISO 8601 expiration timestamp |

**Response (201):**

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

The response includes a short-lived JWT for immediate use.

### List Agents

```text
GET /agents
```

**Response (200):**

```json
[
  {
    "id": "550e8400-...",
    "owner": "user:alice",
    "model": "gpt-4",
    "capabilities": ["read", "write"],
    "trust_level": "basic",
    "active": true,
    "created_at": "2026-03-15T10:00:00Z"
  }
]
```

### Get Agent

```text
GET /agents/{id}
```

**Response (200):** Same schema as list items. Returns 404 if not found.

### Deactivate Agent

```text
DELETE /agents/{id}
```

Deactivates the agent and **cascade-deactivates** all delegates in the delegation chain. This is not reversible.

**Response (200):**

```json
{
  "deactivated": ["550e8400-...", "661f9400-..."]
}
```

Returns the list of all deactivated agent IDs (the target plus its delegates).

---

## Delegation

### Create Delegation

```text
POST /agents/{id}/delegate
```

**Request Body:**

```json
{
  "to": "661f9400-e29b-41d4-a716-446655440001",
  "scopes": ["read"],
  "expires_at": "2026-04-01T00:00:00Z"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | UUID | yes | Target agent ID |
| `scopes` | string[] | yes | Capabilities to delegate (must be subset of parent's) |
| `expires_at` | string | no | Delegation expiration |

**Response (201):**

```json
{
  "delegation_id": "d1e2f3a4-..."
}
```

Scope narrowing is enforced: the delegated scopes must be a subset of the delegating agent's capabilities. Attempting to widen scope returns 400 with `ScopeNarrowingViolation`.

### List Delegations

```text
GET /agents/{id}/delegations
```

Returns incoming and outgoing delegation links for the specified agent.

---

## Tokens

### Issue Token

```text
POST /agents/{id}/token
```

**Request Body:**

```json
{
  "expiry_seconds": 300
}
```

**Response (200):**

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

Issues a short-lived JWT signed with the configured signing secret. The token contains the agent ID, owner (sub), issuer, and expiration.

---

## Sessions

### Create Session

```text
POST /sessions
```

**Request Body:**

```json
{
  "agent_id": "550e8400-...",
  "declared_intent": "analyze transactions and generate reports",
  "authorized_tools": ["query_transactions", "generate_risk_report"],
  "time_limit_secs": 1800,
  "call_budget": 100,
  "rate_limit_per_minute": 30,
  "data_sensitivity": "internal"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | UUID | yes | Agent this session belongs to |
| `declared_intent` | string | yes | Free-form intent description |
| `authorized_tools` | string[] | yes | Tool whitelist |
| `time_limit_secs` | integer | no | Session duration (default from config) |
| `call_budget` | integer | no | Max tool calls (default from config) |
| `rate_limit_per_minute` | integer | no | Per-minute rate cap |
| `data_sensitivity` | string | no | `public`, `internal`, `confidential`, `restricted` |

**Response (201):**

```json
{
  "session_id": "b7d3f1a2-..."
}
```

Returns 429 `TooManySessions` if the agent has reached `max_concurrent_sessions_per_agent`.

### Get Session Status

```text
GET /sessions/{id}
```

**Response (200):**

```json
{
  "session_id": "b7d3f1a2-...",
  "agent_id": "550e8400-...",
  "declared_intent": "analyze transactions",
  "authorized_tools": ["query_transactions", "generate_risk_report"],
  "calls_made": 23,
  "call_budget": 100,
  "status": "active",
  "created_at": "2026-03-15T14:00:00Z"
}
```

### Close Session

```text
DELETE /sessions/{id}
```

Marks the session as Closed. Subsequent requests with this session ID return 408.

**Response (200):**

```json
{
  "status": "closed"
}
```

---

## Policy Management

### Explain (Dry-Run)

```text
POST /policy/explain
```

Evaluates a hypothetical request against loaded policies without actually proxying anything.

**Request Body:**

```json
{
  "agent_id": "550e8400-...",
  "trust_level": "basic",
  "capabilities": ["read"],
  "declared_intent": "read configuration files",
  "tool_name": "read_file",
  "principal_sub": "user:alice",
  "principal_groups": ["dev-team"]
}
```

**Response (200):**

```json
{
  "decision": "allow",
  "matched_policy": "allow-read-basic",
  "trace": []
}
```

### Validate Policy TOML

```text
POST /policy/validate
```

**Request Body:**

```json
{
  "toml": "[[policies]]\nid = \"test\"\neffect = \"allow\""
}
```

**Response (200):**

```json
{
  "valid": true,
  "policies_count": 1,
  "errors": []
}
```

### Reload Policies

```text
POST /policy/reload
```

Forces an immediate reload from the configured policy file. Returns the new policy count or errors.

### Get Policy Schema

```text
GET /policy/schema
```

Returns the expected TOML schema for policy files.

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": "ErrorCode",
  "message": "Human-readable explanation"
}
```

| Status | Code | When |
|--------|------|------|
| 400 | `BadRequest` | Invalid request body |
| 400 | `ScopeNarrowingViolation` | Delegation attempts to widen scope |
| 401 | `Unauthorized` | Missing or invalid `x-api-key` |
| 404 | `NotFound` | Agent or session not found |
| 429 | `TooManySessions` | Per-agent session cap exceeded |
| 500 | `InternalError` | Server-side failure |
