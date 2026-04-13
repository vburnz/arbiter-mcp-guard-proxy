# Audit & Compliance

Every request through Arbiter produces a structured audit entry: who made the call, what tool they called, what the policy engine decided, whether anomalies fired, how long it took, and what the upstream returned. This happens regardless of whether the request was allowed or denied.

## What Gets Logged

Each audit entry is a JSON object written as a single line in a JSONL file:

```json
{
  "timestamp": "2026-03-15T14:32:01.234Z",
  "request_id": "a7b3c1d2-e4f5-6789-abcd-ef0123456789",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "delegation_chain": "agent-a > agent-b",
  "task_session_id": "b7d3f1a2-...",
  "tool_called": "query_transactions",
  "arguments": {
    "account": "ACC-2847",
    "password": "[REDACTED]"
  },
  "authorization_decision": "allow",
  "policy_matched": "allow-read-basic",
  "anomaly_flags": [],
  "latency_ms": 47,
  "upstream_status": 200,
  "credentials_scrubbed": 0
}
```

Notice `"password": "[REDACTED]"`. Sensitive fields are automatically scrubbed before they reach the log.

## Configuration

```toml
[audit]
enabled = true
file_path = "/var/log/arbiter/audit.jsonl"
redaction_patterns = ["password", "secret", "token", "key", "authorization", "credential"]
hash_chain = true
```

### Redaction Patterns

The `redaction_patterns` list specifies field name patterns (case-insensitive) that trigger argument redaction. If a tool call argument's key matches any pattern, its value is replaced with `[REDACTED]` in the audit entry.

The default patterns catch the most common sensitive fields. Add domain-specific patterns if your tools use different naming conventions:

```toml
redaction_patterns = [
  "password", "secret", "token", "key", "authorization", "credential",
  "ssn", "credit_card", "api_key", "connection_string"
]
```

Redaction applies to audit output only. The actual request sent to the upstream still contains the real values.

## Hash-Chained Audit Records

Hash chaining is **on by default** for tamper detection. Each record is linked
to its predecessor via a BLAKE3 hash chain. Disable only for development or
ephemeral environments where audit integrity is not required:

```toml
[audit]
hash_chain = false
```

When enabled, each audit record includes three additional fields:

- **`chain_sequence`:** a monotonically increasing counter
- **`chain_prev_hash`:** a BLAKE3 hash of the previous record's `chain_record_hash`
- **`chain_record_hash`:** a BLAKE3 hash over the current record (including sequence and prev_hash)

This creates a chain where modifying, inserting, or deleting any record breaks
the hash link. Concurrent audit writes are serialized so on-disk order matches
sequence order; a naive top-to-bottom verifier is sufficient.

```bash
$ arbiter-ctl audit verify --file /var/log/arbiter/audit.jsonl
```

The chain resumes correctly across Arbiter restarts; the last sequence number
and hash are recovered from the existing file.

### What Hash Chaining Detects

- Record modification (changing any field breaks the hash)
- Record deletion (gap in sequence numbers, hash mismatch)
- Record insertion (hash of inserted record won't match the chain)

### What It Doesn't Prevent

An attacker with filesystem access can rewrite the entire chain from the beginning with consistent hashes. Hash chaining is a detection mechanism, not a prevention mechanism. For stronger guarantees, export audit records to an external append-only system.

## Failure Categories

When a request is denied, the audit entry includes a `failure_category` field that classifies the reason:

| Category | Meaning |
|----------|---------|
| `governance` | Policy denial, session tool whitelist violation |
| `infrastructure` | Session expired, budget exceeded, rate limited |
| `protocol` | Invalid JSON-RPC, non-MCP POST, missing headers |

This categorization is useful for building dashboards and alerts that distinguish between "the system is working as designed" (governance) and "something is broken" (protocol).

## Compliance Templates

Arbiter ships with policy starter packs for common compliance frameworks:

- **SOC 2:** controls for agent access logging and review
- **HIPAA.** PHI access restrictions and audit requirements
- **PCI-DSS:** cardholder data protection policies
- **EU AI Act.** AI system transparency and oversight controls

These templates live in the `templates/` directory and provide pre-built policies you can adapt to your environment.

## Next Steps

- {doc}`../reference/configuration`: full `[audit]` configuration reference
- {doc}`../understanding/security-model`: audit tampering in the threat model
- {doc}`metrics`: Prometheus metrics for operational monitoring
