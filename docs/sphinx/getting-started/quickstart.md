# Quickstart

Five minutes from install to your first proxied tool call.

## Install the Binary

```bash
$ curl -sSf https://raw.githubusercontent.com/samanthaci/arbiter-mcp-firewall/main/install.sh | sh
```

This downloads the latest Arbiter binary for your platform (Linux or macOS, amd64 or arm64), verifies its SHA256 checksum, and installs it to `~/.arbiter/bin`. To pin a version:

```bash
$ ARBITER_VERSION=v0.5.0 curl -sSf https://raw.githubusercontent.com/samanthaci/arbiter-mcp-firewall/main/install.sh | sh
```

## Or: Run with Docker Compose

If you prefer Docker, this gets a full gateway running with a mock MCP server and Keycloak as the identity provider.

### Prerequisites

- Docker and Docker Compose v2
- `curl` and optionally `jq` for readability

```bash
$ git clone https://github.com/samanthaci/arbiter-mcp-firewall.git
$ cd arbiter
$ docker compose up --build -d
```

This starts four services:

| Service | Port | Role |
|---------|------|------|
| Arbiter proxy | 8080 | Gateway; where agents send MCP traffic |
| Arbiter admin | 3000 | Lifecycle API (agent registration, sessions, tokens) |
| mcp-echo | 8081 | Mock MCP upstream that echoes requests back |
| Keycloak | 9090 | OAuth 2.0 identity provider |

Wait for everything to come up:

```bash
$ docker compose ps
```

## Verify the Proxy

```bash
$ curl http://localhost:8080/health
OK
```

If you get `OK`, the proxy is running and connected to the upstream.

## Register an Agent

Every agent needs to be registered before it can make tool calls through Arbiter. Registration happens through the admin API:

```bash
$ curl -s -X POST http://localhost:3000/agents \
  -H "Content-Type: application/json" \
  -H "x-api-key: arbiter-dev-key" \
  -d '{
    "owner": "user:alice",
    "model": "gpt-4",
    "capabilities": ["read", "write"],
    "trust_level": "basic"
  }' | jq .
```

You'll get back an agent ID and a short-lived JWT:

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

Save both. You'll need them in the next steps.

```bash
$ export AGENT_ID="550e8400-e29b-41d4-a716-446655440000"
```

## Create a Task Session

Sessions scope what an agent can do during a specific task. They carry a declared intent, a tool whitelist, a time limit, and a call budget:

```bash
$ curl -s -X POST http://localhost:3000/sessions \
  -H "Content-Type: application/json" \
  -H "x-api-key: arbiter-dev-key" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "declared_intent": "analyze transactions and generate reports",
    "authorized_tools": ["query_transactions", "generate_risk_report"],
    "time_limit_secs": 1800,
    "call_budget": 50
  }' | jq .
```

```json
{
  "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

```bash
$ export SESSION_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

## Send a Proxied MCP Request

Now send an actual MCP tool call through the proxy. The request includes the agent ID and session ID as headers:

```bash
$ curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "query_transactions",
      "arguments": { "account": "ACC-2847", "period": "2025-Q4" }
    }
  }' | jq .
```

The echo server returns the request back as a JSON-RPC response. Behind the scenes, Arbiter validated the session, checked the tool whitelist, evaluated policies, ran anomaly detection, and logged an audit entry.

## Check the Audit Log

```bash
$ docker compose exec arbiter cat /var/log/arbiter/audit.jsonl | jq .
```

Each line is a structured JSON entry with the request ID, agent ID, tool called, authorization decision, latency, and any anomaly flags.

## Check Metrics

```bash
$ curl -s http://localhost:8080/metrics
```

Prometheus-format metrics: `requests_total` (by decision), `tool_calls_total` (by tool), and request duration histograms.

## Try Getting Denied

Send a request for a tool that isn't on the session's whitelist:

```bash
$ curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "delete_account",
      "arguments": { "account": "ACC-2847" }
    }
  }' | jq .
```

You'll get a 403 with an error explaining the tool isn't authorized for this session. That's deny-by-default at work.

## Explore the Admin API

```bash
# List all registered agents
$ curl -s http://localhost:3000/agents \
  -H "x-api-key: arbiter-dev-key" | jq .

# Get details for a specific agent
$ curl -s http://localhost:3000/agents/$AGENT_ID \
  -H "x-api-key: arbiter-dev-key" | jq .

# Issue a fresh short-lived token
$ curl -s -X POST http://localhost:3000/agents/$AGENT_ID/token \
  -H "x-api-key: arbiter-dev-key" \
  -H "Content-Type: application/json" \
  -d '{"expiry_seconds": 300}' | jq .
```

## Stop the Stack

```bash
$ docker compose down -v
```

## Next Steps

You've seen Arbiter running. Now go deeper:

- {doc}`first-policy`: write your first authorization policy from scratch
- {doc}`first-session`: understand session scoping, budgets, and intent
- {doc}`../understanding/architecture`: how the middleware chain works under the hood
