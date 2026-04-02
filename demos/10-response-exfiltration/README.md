# Demo 10: Response Exfiltration

This demo shows how Arbiter's response data classification prevents upstream MCP servers from returning sensitive data that exceeds the session's authorization level.

A compromised or misconfigured upstream server might return API keys, PII (SSNs, credit card numbers), or internal infrastructure details in its responses. Without response classification, the proxy would forward this data verbatim to the agent.

Arbiter's response classifier scans upstream response bodies for sensitive data patterns (AWS access keys, private keys, bearer tokens, API keys, SSNs, credit card numbers, email addresses, internal IP addresses). Each pattern is classified by sensitivity level: Internal, Confidential, or Restricted. The highest detected level is compared against the session's `data_sensitivity_ceiling` (default: Internal). If the response contains data above the ceiling, it is blocked.

Restricted data (API keys, AWS credentials, private keys) in a session with an Internal ceiling triggers a hard block: the response is replaced with a 502 and error code `UPSTREAM_ERROR`, and the agent never sees the leaked data.

## Attack scenario

1. Agent `data-reader` is registered with `read` capabilities
2. Agent creates a session with default `data_sensitivity_ceiling` (Internal)
3. First tool call returns clean data from upstream (no sensitive patterns)
4. Second tool call returns data containing AWS keys, SSNs, and API keys

## Defense

- Response classifier scans upstream responses using regex patterns
- Findings are classified as Internal, Confidential, or Restricted
- Restricted findings in a non-Restricted session block the response entirely
- Findings below Restricted that still exceed the ceiling are logged and audited but forwarded

## Scope

This is **pattern-based classification**: Arbiter scans for known sensitive data patterns (AWS keys, SSNs, API keys, private keys, internal IPs). It is not a general-purpose DLP solution. For credential injection scrubbing (where Arbiter redacts specific secrets it injected into requests), see the credential injection documentation.

## Expected output

```
-- Call 1: Legitimate tool call (clean upstream response) --
  Status: 200 OK (response passed inspection)

-- Call 2: Tool call with tainted upstream response --
  Status: 502 (response blocked: contained restricted data)
```

To run: `bash demo.sh`
