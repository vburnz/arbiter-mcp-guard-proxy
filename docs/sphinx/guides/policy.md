# Policy Language

Arbiter uses a TOML-based policy language for authorization rules. If you haven't written a policy yet, start with {doc}`../getting-started/first-policy`. This guide covers the full language.

## How Authorization Works

Every MCP tool call passes through the policy engine. The engine loads all policies, finds which ones match the current request context, and picks the most specific match. If no policy matches, the request is denied. That's the whole algorithm.

The request context available to policies includes:

- **Agent identity:** agent ID, trust level, capabilities
- **Principal:** OAuth subject and groups from the JWT
- **Session:** declared intent
- **Tool:** the tool name being called
- **Arguments:** the tool call arguments (for parameter constraints)

## Policy Structure

Each policy is a `[[policies]]` entry in a TOML file:

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

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier. Shows up in audit logs. |
| `effect` | string | yes | `allow`, `deny`, or `escalate` |
| `allowed_tools` | string[] | no | Tools this policy covers. Empty = all tools. |
| `priority` | integer | no | Manual specificity override (0 = auto) |

### Agent Matching

```toml
[policies.agent_match]
agent_id = "550e8400-..."          # exact agent (most specific)
trust_level = "basic"              # minimum trust: untrusted, basic, verified, trusted
capabilities = ["read", "write"]   # all must be present on the agent
```

Trust levels form an ordered hierarchy. A policy requiring `basic` trust matches agents at `basic`, `verified`, or `trusted`.

### Principal Matching

```toml
[policies.principal_match]
sub = "user:alice"                 # OAuth subject
groups = ["ops-team", "admins"]    # match any of these groups
```

### Intent Matching

```toml
[policies.intent_match]
keywords = ["read", "analyze"]     # all must appear in declared intent (case-insensitive)
regex = "^(read|analyze)\\b"       # regex the intent must match
```

Keywords and regex can be combined. When both are present, both must match.

### Parameter Constraints

```toml
[[policies.parameter_constraints]]
key = "max_tokens"
max_value = 1000.0

[[policies.parameter_constraints]]
key = "temperature"
min_value = 0.0
max_value = 1.0

[[policies.parameter_constraints]]
key = "model"
allowed_values = ["gpt-4", "claude-sonnet-4-20250514"]
```

Parameter constraints are checked against the tool call's arguments. Numeric bounds and string allowlists are both supported.

## Effects

| Effect | What Happens |
|--------|-------------|
| `allow` | Request proceeds to the upstream MCP server |
| `deny` | Request is rejected with HTTP 403 |
| `escalate` | Request is flagged for human-in-the-loop approval |

## Specificity Ordering

When multiple policies match the same request, the most specific one wins. Arbiter computes specificity automatically:

| Criterion | Score |
|-----------|-------|
| `agent_id` set | +100 |
| `trust_level` set | +50 |
| Per capability | +25 each |
| `sub` set | +40 |
| Per group | +20 each |
| `regex` set | +30 |
| Per keyword | +10 each |

The policy with the highest total score wins. You can override this with a manual `priority` field, but auto-computed specificity handles most cases well.

**Why this matters:** you can have a broad Deny policy blocking `admin_users` for everyone (score: 0) and a targeted Allow policy granting `admin_users` to a specific agent ID (score: 100). The targeted policy wins because it's more precise about *who* it applies to.

## Real-World Examples

### Read-Only Access for Low-Trust Agents

```toml
[[policies]]
id = "allow-read-basic"
effect = "allow"
allowed_tools = ["read_file", "list_dir", "search", "get_metadata"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
```

### Block Destructive Tools Globally

```toml
[[policies]]
id = "deny-destructive"
effect = "deny"
allowed_tools = ["drop_database", "delete_all", "truncate_table", "rm_rf"]
```

No match criteria, so this applies to everyone. Even if another policy allows one of these tools, you'd need a *more specific* Allow (like matching an `agent_id`) to override this.

### Escalate Write Operations for Readers

Agents that declared a read intent but try to use write tools trigger human review:

```toml
[[policies]]
id = "escalate-write-for-readers"
effect = "escalate"
allowed_tools = ["write_file", "create_file", "update_record"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
```

### Ops Team Gets Deployment Tools

```toml
[[policies]]
id = "allow-deploy-ops"
effect = "allow"
allowed_tools = ["deploy", "rollback", "scale"]

[policies.principal_match]
groups = ["ops-team"]
```

### Surgical Override for a Specific Agent

```toml
[[policies]]
id = "allow-admin-for-ops-bot"
effect = "allow"
allowed_tools = ["admin_users", "configure_system"]

[policies.agent_match]
agent_id = "550e8400-e29b-41d4-a716-446655440000"
```

With `agent_id` scoring +100, this beats any broader deny.

### Token Generation with Guardrails

```toml
[[policies]]
id = "allow-generate-limited"
effect = "allow"
allowed_tools = ["generate"]

[[policies.parameter_constraints]]
key = "max_tokens"
max_value = 1000.0

[[policies.parameter_constraints]]
key = "temperature"
min_value = 0.0
max_value = 1.0
```

## Loading and Managing Policies

### From a File

```toml
[policy]
file = "policies.toml"
```

### Hot Reload

Enable file watching to pick up changes without restarting:

```toml
[policy]
file = "policies.toml"
watch = true
watch_debounce_ms = 500
```

Changes are parsed, validated, and atomically swapped. In-flight requests finish under the old policy set.

### Runtime Management

The admin API provides three policy endpoints:

- **`POST /policy/explain`:** dry-run a request against loaded policies
- **`POST /policy/validate`:** check policy TOML for syntax errors
- **`POST /policy/reload`:** force an immediate reload from disk

See {doc}`../reference/api` for full request/response schemas.

## Best Practices

**Start with deny-all, add specific allows.** That's the default behavior. Work with it rather than against it.

**Use intent keywords.** They constrain what agents can do based on their declared purpose, not just their identity. An agent with admin capabilities but a read intent still gets limited to read tools.

**Set `escalate` for high-risk operations.** Instead of a hard deny, let a human review the request. This is especially useful during early rollout when you're still learning your agents' behavior patterns.

**Use `agent_id` for surgical overrides.** The specificity system ensures agent-specific policies always win over broad rules.

**Audit first, restrict later.** Start with broad allows and review the audit log to understand actual usage patterns. Then tighten policies based on what you see, not what you guess.

## Next Steps

- {doc}`../reference/configuration`: full `[policy]` configuration reference
- {doc}`../reference/api`: policy management API endpoints
- {doc}`sessions`: how sessions interact with policies
