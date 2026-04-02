# Configuration Reference

Arbiter is configured with a single TOML file, passed via `--config` at startup. This is the complete reference for every configuration key.

## `[proxy]`

Core reverse proxy settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_addr` | string | `"0.0.0.0"` | Address the proxy listens on |
| `listen_port` | integer | `8080` | Port the proxy listens on |
| `upstream_url` | string | **required** | URL of the upstream MCP server |
| `blocked_paths` | string[] | `[]` | Paths to block (exact match). Returns 403. |
| `require_session` | bool | `true` | Require `x-arbiter-session` header for MCP traffic |
| `strict_mcp` | bool | `true` | Reject non-JSON-RPC POST requests |
| `max_request_body_bytes` | integer | `10485760` | Maximum request body size (bytes). Returns 413 if exceeded. |
| `max_response_body_bytes` | integer | `10485760` | Maximum response body size (bytes). Oversized responses are blocked. |
| `upstream_timeout_secs` | integer | `60` | Timeout for upstream requests (seconds). Returns 504 on timeout. |

```toml
[proxy]
listen_addr = "0.0.0.0"
listen_port = 8080
upstream_url = "http://mcp-server:8081"
require_session = true
strict_mcp = true
```

`require_session` and `strict_mcp` both default to `true`. This is deliberate. Turning them off widens the attack surface. Do so only if your deployment architecture requires it.

## `[oauth]`

JWT validation against one or more identity providers. This entire section is optional; omit it to skip OAuth validation.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jwks_cache_ttl_secs` | integer | `3600` | How long to cache JWKS responses |

### `[[oauth.issuers]]`

Each issuer is a separate identity provider:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | yes | Human-readable name for this issuer |
| `issuer_url` | string | yes | The issuer URL (matched against JWT `iss` claim) |
| `jwks_uri` | string | yes | JWKS endpoint URL |
| `audiences` | string[] | no | Expected audience values |
| `introspection_url` | string | no | Token introspection endpoint (RFC 7662) |
| `client_id` | string | no | Client ID for introspection |
| `client_secret` | string | no | Client secret for introspection |

```toml
[oauth]
jwks_cache_ttl_secs = 3600

[[oauth.issuers]]
name = "keycloak"
issuer_url = "http://keycloak:8080/realms/arbiter"
jwks_uri = "http://keycloak:8080/realms/arbiter/protocol/openid-connect/certs"
audiences = ["arbiter-api"]
```

## `[policy]`

Authorization policy configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file` | string | none | Path to TOML policy file |
| `watch` | bool | `false` | Enable file-system hot-reload |
| `watch_debounce_ms` | integer | `500` | Debounce interval for the file watcher |

```toml
[policy]
file = "policies.toml"
watch = true
watch_debounce_ms = 500
```

When `watch = true`, policy file changes are detected, parsed, validated, and atomically swapped. In-flight requests complete under the old policy set.

See {doc}`../guides/policy` for the policy language itself.

## `[sessions]`

Session defaults and behavioral settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_time_limit_secs` | integer | `3600` | Default session time limit |
| `default_call_budget` | integer | `1000` | Default maximum tool calls per session |
| `escalate_anomalies` | bool | `false` | Hard-block behavioral anomalies (vs. log only) |
| `warning_threshold_pct` | float | `20.0` | Budget/time warning threshold percentage |
| `max_concurrent_sessions_per_agent` | integer | `10` | Concurrent session cap per agent |
| `rate_limit_window_secs` | integer | `60` | Duration of the sliding rate-limit window |
| `cleanup_interval_secs` | integer | `60` | Interval for expired session cleanup |

```toml
[sessions]
default_time_limit_secs = 3600
default_call_budget = 1000
escalate_anomalies = false
warning_threshold_pct = 20.0
max_concurrent_sessions_per_agent = 10
```

## `[audit]`

Audit logging configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable audit logging |
| `file_path` | string | none | Append-only JSONL log file path |
| `redaction_patterns` | string[] | see below | Field name patterns that trigger argument redaction |
| `hash_chain` | bool | `false` | Enable BLAKE3 hash-chained records |

Default redaction patterns cover 24 variants including abbreviations and PII: `password`, `passwd`, `pwd`, `token`, `access_token`, `refresh_token`, `secret`, `client_secret`, `key`, `api_key`, `apikey`, `api-key`, `authorization`, `auth`, `credential`, `cred`, `private`, `private_key`, `ssn`, `social_security`, `credit_card`, `card_number`, `cvv`, `cvc`.

```toml
[audit]
enabled = true
file_path = "/var/log/arbiter/audit.jsonl"
redaction_patterns = ["password", "secret", "token", "key", "authorization", "credential"]
hash_chain = false
```

## `[credentials]`

Credential injection configuration. Optional (omit to disable credential injection).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provider` | string | none | Provider type: `"file"` or `"env"` |
| `file_path` | string | none | Path to TOML credentials file (file provider) |
| `env_prefix` | string | none | Environment variable prefix (env provider) |

```toml
[credentials]
provider = "file"
file_path = "credentials.toml"
```

See {doc}`../guides/credentials` for usage details.

## `[storage]`

Persistence backend.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `backend` | string | `"memory"` | `"memory"` or `"sqlite"` |
| `sqlite_path` | string | none | Database file path (SQLite only) |

```toml
[storage]
backend = "memory"
```

SQLite requires the `sqlite` feature flag: `cargo build --features sqlite`.

## `[metrics]`

Prometheus metrics.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the `/metrics` endpoint |

## `[admin]`

Admin/lifecycle API settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen_addr` | string | `"0.0.0.0"` | Address the admin API listens on |
| `listen_port` | integer | `3000` | Port for the admin API |
| `api_key` | string | `"arbiter-dev-key"` | API key for admin endpoints |
| `signing_secret` | string | `"arbiter-dev-secret..."` | HMAC secret for JWT signing |
| `token_expiry_secs` | integer | `3600` | Token validity duration |

```{warning}
The `api_key` and `signing_secret` defaults are for development only. In production, set `ARBITER_ADMIN_API_KEY` and `ARBITER_SIGNING_SECRET` environment variables. **Arbiter refuses to start with default credentials.**
```

All admin API endpoints are rate-limited at 60 requests per minute (sliding window). All admin operations are audit-logged with structured tracing.

## Environment Variable Overrides

| Variable | Overrides |
|----------|-----------|
| `ARBITER_ADMIN_API_KEY` | `[admin] api_key` |
| `ARBITER_SIGNING_SECRET` | `[admin] signing_secret` |
