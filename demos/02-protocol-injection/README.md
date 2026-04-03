# Demo 02: Protocol Injection

This demo shows how Arbiter blocks non-MCP POST traffic when strict mode is enabled.

The MCP protocol uses JSON-RPC 2.0 as its wire format. Without strict mode, an attacker could send arbitrary POST bodies (SQL injection payloads, shell commands, custom JSON) through the proxy to the upstream server. The proxy would forward the traffic without inspection because it does not recognize the format as MCP and therefore skips all policy, session, and behavior checks.

When `strict_mcp = true` (the default), Arbiter parses every POST body and rejects anything that is not valid JSON-RPC 2.0 (requires both `jsonrpc` and `method` fields). The demo sends two attack variants: a plain text body containing a SQL injection payload, and a JSON body that lacks the required JSON-RPC fields. Both are rejected with a 403 and error code `NON_MCP_REJECTED`. Note that `require_session` is also active, but it only gates valid MCP traffic; non-MCP traffic is caught first by the `strict_mcp` check.

This protection closes a class of bypass vulnerabilities where attackers use the proxy as a protocol-level tunnel to reach the upstream server with un-inspected traffic.

To run: `bash demo.sh`
