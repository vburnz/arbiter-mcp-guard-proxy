# Demo 10: Credential Leakage via Response

This demo shows how Arbiter's credential scrubbing prevents injected secrets from leaking back through upstream MCP server responses.

When credential injection is active, Arbiter substitutes `${CRED:ref}` patterns in outgoing requests with real secret values. If the upstream server echoes those secrets back in its response (through error messages, debug output, or data fields), the agent would see the raw credentials it was never supposed to have.

Arbiter's response scrubbing catches this. After receiving the upstream response, it scans for every credential value it injected, across multiple encodings (plaintext, URL-encoded, JSON-escaped, hex, base64). Matches are replaced with `[CREDENTIAL]` before the response reaches the agent.

## Attack scenario

1. Agent `data-reader` is registered with `read` capabilities
2. Credential injection is configured with a database password and API key
3. Agent makes a `query_records` tool call with `${CRED:db_password}` in arguments
4. Arbiter injects the real credential before forwarding to upstream
5. Upstream MCP server echoes the credential back in its response

## Defense

- `[credentials]` configured with file or env provider
- Arbiter tracks which credentials were injected per request
- Response body scanned for those exact values in multiple encodings
- Matches replaced with `[CREDENTIAL]` before the agent sees them

## Scope

This is **closed-scope scrubbing**: Arbiter catches the specific secrets it injected because it knows exactly what to look for. It does **not** perform general content inspection (arbitrary PII patterns, prompt injection detection, or pattern-based secret scanning). For general content inspection, use a dedicated tool like Nightfall or Presidio.

## Expected output

```
── Legitimate tool call (no credential echo) ──
  Call 1: 200 OK (response clean)

── Tool call where upstream echoes injected credential ──
  Call 2: 200 OK (credential scrubbed: 1 match replaced with [CREDENTIAL])
```

To run: `bash demo.sh`
