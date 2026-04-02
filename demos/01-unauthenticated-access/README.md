# Demo 01: Unauthenticated Access

This demo shows how Arbiter blocks MCP tool calls that arrive without a session header.

In a typical attack scenario, a rogue agent or script attempts to call tools on the upstream MCP server by sending raw JSON-RPC requests directly to the proxy. Without Arbiter, these requests would pass straight through to the upstream server, allowing arbitrary tool execution with no identity verification, no audit trail, and no policy enforcement.

When `require_session = true` (the default), Arbiter intercepts the request at Stage 6.5 of the middleware pipeline. It checks for the `x-arbiter-session` header, and if the header is missing, returns a 403 with error code `SESSION_REQUIRED`. The request never reaches the upstream server.

This is the most basic protection Arbiter provides: no session, no access. Every subsequent demo builds on this foundation by showing what happens when an agent does have a session but attempts to exceed its authorized scope.

To run: `bash demo.sh`
