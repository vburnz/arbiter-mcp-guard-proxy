# Credential Management

Agents that call upstream tools often need credentials: API keys for third-party services, database passwords, OAuth tokens. The question is: should the agent know the credentials?

Arbiter's answer is no. The credential injection system lets you reference secrets by name in tool call arguments without the agent ever seeing the actual values.

## How It Works

1. You configure a credential provider (file-based or environment variable-based).
2. Agents include `${CRED:reference_name}` patterns in their tool call arguments.
3. Arbiter resolves the reference, substitutes the real credential into the request body, and forwards it to the upstream MCP server.
4. On the way back, Arbiter scrubs the response body. If any resolved credential value appears in the response, it's replaced with `[CREDENTIAL]` before reaching the agent.

The agent sees the reference pattern. The upstream sees the real credential. Nobody in between can leak it.

## Configuration

### File Provider

Store credentials in a separate TOML file:

```toml
# arbiter.toml
[credentials]
provider = "file"
file_path = "credentials.toml"
```

```toml
# credentials.toml
[credentials]
stripe_key = "sk_test_abc123..."
db_password = "hunter2"
github_token = "ghp_xyz789..."
```

### Environment Variable Provider

Resolve credentials from environment variables:

```toml
# arbiter.toml
[credentials]
provider = "env"
env_prefix = "ARBITER_CRED"
```

With this configuration, `${CRED:STRIPE_KEY}` resolves to the value of the `ARBITER_CRED_STRIPE_KEY` environment variable.

## Using Credential References

An agent's tool call might look like this:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "query_database",
    "arguments": {
      "connection_string": "postgres://app:${CRED:db_password}@db:5432/prod",
      "query": "SELECT * FROM orders WHERE status = 'pending'"
    }
  }
}
```

Before forwarding to the upstream, Arbiter replaces `${CRED:db_password}` with the actual password from the configured provider. The agent never sees `hunter2`; it only knows the reference name.

## Response Scrubbing

If the upstream response happens to contain a credential value (maybe it echoes connection strings, maybe an error message leaks a key), Arbiter catches it. The response body is scanned for all resolved credential values, and any matches are replaced with `[CREDENTIAL]`.

This is a defense-in-depth measure. The upstream *shouldn't* leak credentials in responses, but if it does, the agent still doesn't see them.

## Unresolvable References

If a `${CRED:name}` pattern can't be resolved (the key doesn't exist in the provider), Arbiter rejects the request with an error rather than forwarding it with an unresolved pattern. Failing closed is the right default. You don't want `${CRED:db_password}` showing up as a literal string in a database connection attempt.

## Next Steps

- {doc}`../reference/configuration`: `[credentials]` configuration reference
- {doc}`../understanding/security-model`: credential exposure in the threat model
- {doc}`audit`: how credential references appear in audit logs (redacted)
