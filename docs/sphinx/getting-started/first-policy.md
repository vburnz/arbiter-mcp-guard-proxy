# Your First Policy

Arbiter's policy engine is deny-by-default. Until you write a policy that explicitly allows something, every tool call gets rejected. This guide walks you through writing your first policy, understanding how matching works, and testing it.

## The Default State

With no policies loaded, every MCP tool call through Arbiter returns 403. That's not a bug; it's the point. You add access surgically, for specific agents, doing specific things, with specific tools.

## A Minimal Allow Policy

Create a file called `policies.toml`:

```toml
[[policies]]
id = "allow-read-basic"
effect = "allow"
allowed_tools = ["read_file", "list_dir", "search"]

[policies.agent_match]
trust_level = "basic"

[policies.intent_match]
keywords = ["read"]
```

This policy says: agents with at least a `basic` trust level, whose declared intent contains the word "read," can use three specific tools. Everything else is still denied.

Point Arbiter at this file in your configuration:

```toml
[policy]
file = "policies.toml"
```

## What Each Field Does

**`id`:** A unique name for this policy. Shows up in audit logs and policy traces, so make it descriptive.

**`effect`:** What happens when this policy matches. Three options:
- `allow`: request proceeds to the upstream MCP server
- `deny`: request is rejected with 403
- `escalate`: request is flagged for human-in-the-loop approval

**`allowed_tools`:** Which tools this policy applies to. An empty list means *all tools*, which is almost always a mistake for Allow policies.

**`agent_match`:** Narrows which agents this policy applies to. You can match by trust level, specific agent ID, or required capabilities.

**`intent_match`:** Matches against the session's declared intent. Keywords are case-insensitive and all must appear. You can also use regex for more complex patterns.

## Adding a Deny Policy

You don't strictly need Deny policies since everything is denied by default. But explicit Deny policies are useful for being clear about what's off-limits, even if a broader Allow policy exists:

```toml
[[policies]]
id = "deny-admin-tools"
effect = "deny"
allowed_tools = ["admin_users", "drop_database", "delete_all"]
```

No match criteria means this applies to everyone. These tools are blocked regardless of who's asking.

## Specificity: How Conflicts Are Resolved

When multiple policies match the same request, the most specific one wins. Arbiter computes a specificity score automatically:

| Criterion | Score |
|-----------|-------|
| `agent_id` match | +100 |
| `trust_level` match | +50 |
| Each capability | +25 |
| `sub` (principal) match | +40 |
| Each group | +20 |
| `regex` match | +30 |
| Each keyword | +10 |

So if you have a broad Deny for `admin_users` (score: 0, no match criteria) and a specific Allow for a particular agent to use `admin_users` (score: 100, matching `agent_id`), the specific Allow wins. The agent-specific policy is more precise, so it takes precedence.

## Testing Your Policies

Before deploying, use the policy explain endpoint to dry-run a request:

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

This returns the decision (allow/deny/escalate) and which policy matched, without actually proxying anything.

You can also validate policy syntax:

```bash
$ curl -s -X POST http://localhost:3000/policy/validate \
  -H "x-api-key: arbiter-dev-key" \
  -H "Content-Type: application/json" \
  -d '{"toml": "[[policies]]\nid = \"test\"\neffect = \"allow\""}' | jq .
```

## Hot Reload

If you want policies to update without restarting Arbiter, enable file watching:

```toml
[policy]
file = "policies.toml"
watch = true
watch_debounce_ms = 500
```

When you save changes to `policies.toml`, Arbiter re-reads, parses, validates, and atomically swaps the policy set. In-flight requests complete under the old policies; new requests get the new ones.

## Next Steps

- {doc}`first-session`: create sessions that use your policies
- {doc}`../guides/policy`: the complete policy language guide with advanced matching
- {doc}`../reference/configuration`: all policy configuration options
