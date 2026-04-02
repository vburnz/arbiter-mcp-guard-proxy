# Drift Detection

Policies control which tools an agent *can* call. Drift detection flags when tool-call operation types diverge from the session's declared scope.

This is the difference between authorization and scope enforcement. An agent might have write tools on its whitelist, but if its session is scoped for read operations and it starts writing, something has gone wrong. Either the scope was misconfigured, or the agent is drifting from its assigned task.

## How Classification Works

Every tool call is classified into one of four operation types:

| Type | Description | Example Tools |
|------|-------------|--------------|
| **Read** | Fetches or queries data | `read_file`, `query_transactions`, `list_dir` |
| **Write** | Creates or modifies data | `write_file`, `create_record`, `update_config` |
| **Delete** | Removes data | `delete_file`, `drop_table` |
| **Admin** | System-level operations | `admin_users`, `configure_system`, `deploy` |

Classification is based on tool name patterns. The detector uses pre-compiled regex sets for fast matching against configurable keyword lists.

## Intent Tiers

The session's declared intent is also classified into a tier:

| Tier | Triggered By | Allows |
|------|-------------|--------|
| **Read** | Keywords: read, analyze, query, search, list, get | Read operations only |
| **Write** | Keywords: write, create, update, modify, edit | Read + Write operations |
| **Admin** | Keywords: admin, manage, configure, deploy, delete | All operations |
| **Unknown** | No matching keywords | No anomaly detection runs |

The intent classifier uses the highest-matching tier. An intent containing "read and manage servers" matches both Read and Admin keywords. Admin wins, and the agent gets broad latitude.

## When Anomalies Fire

The detector compares the operation type against the intent tier:

| Intent Tier | Read Op | Write Op | Delete Op | Admin Op |
|-------------|---------|----------|-----------|----------|
| Read | OK | **Anomaly** | **Anomaly** | **Anomaly** |
| Write | OK | OK | **Anomaly** | **Anomaly** |
| Admin | OK | OK | OK | OK |

An anomaly doesn't necessarily mean the request is blocked. The behavior depends on configuration.

## Escalation vs. Logging

By default, anomalies are logged but requests proceed:

```toml
[sessions]
escalate_anomalies = false
```

This is observational mode, useful during initial deployment when you're learning your agents' behavior patterns and don't want false positives to break workflows.

When you're confident in your intent classifications, switch to enforcement:

```toml
[sessions]
escalate_anomalies = true
```

Now anomalies trigger a deny, and the request is blocked with a 403 that includes the anomaly reason.

## Anomaly Responses

The detector returns one of three responses:

| Response | Meaning |
|----------|---------|
| **Normal** | Operation type matches intent tier |
| **Flagged** | Mismatch detected, logged, request proceeds |
| **Denied** | Mismatch detected, request blocked (when `escalate_anomalies = true`) |

Flagged and Denied responses include a reason string that appears in the audit log. Something like: "write operation detected during read-intent session."

## Trust Degradation

Anomaly flags accumulate per agent. After 5 flags, the agent's trust level is automatically demoted one tier:

| From | To |
|------|----|
| Trusted | Verified |
| Verified | Basic |
| Basic | Untrusted |

This is asymmetric by design: trust is easy to lose, hard to regain. Demotion is automatic; recovery requires an operator to manually re-promote the agent via the admin API. The counter resets after each demotion, so continued anomalies trigger further demotions.

Trust demotion affects policy evaluation immediately; policies that require a minimum trust level will stop matching the demoted agent.

## Customizing Intent Keywords

The default keyword lists cover common patterns, but you can customize them:

```toml
[sessions]
read_intent_keywords = ["read", "analyze", "query", "search", "list", "get", "fetch", "inspect"]
write_intent_keywords = ["write", "create", "update", "modify", "edit", "insert", "set"]
admin_intent_keywords = ["admin", "manage", "configure", "deploy", "delete", "provision"]
```

Choose keywords that match your domain. If your agents use "examine" instead of "read," add it.

## How This Interacts with Policies

Anomaly detection runs *after* the policy engine. A request that passes policy evaluation can still be flagged or blocked by the behavior detector. This means:

- The policy engine answers: "Is this agent allowed to call this tool?"
- The behavior detector answers: "Is this agent behaving consistently with what it said it would do?"

Both must pass for the request to proceed to the upstream.

## Next Steps

- {doc}`sessions`: session intent and tool whitelists
- {doc}`audit`: how anomaly flags appear in audit entries
- {doc}`../reference/attack-scenarios`: see intent drift detection in Demo 08
