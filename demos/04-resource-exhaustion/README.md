# Demo 04: Resource Exhaustion

This demo shows how Arbiter enforces call budgets and rate limits to prevent resource exhaustion.

AI agents can enter runaway loops, be manipulated by prompt injection to make excessive API calls, or be deliberately programmed to abuse upstream resources. Without limits, a single compromised agent could overwhelm the upstream MCP server, exhaust API quotas, or rack up significant costs.

The demo creates two sessions to show both protection mechanisms. Part A creates a session with a rate limit of 3 calls per minute. The first three calls succeed, but the fourth is rejected with a 429 and error code `SESSION_INVALID`. Part B creates a session with a total call budget of 5. Calls 1 through 5 succeed, but the sixth is rejected with a 429.

Both limits are configured at session creation time and enforced at Stage 7 of Arbiter's middleware pipeline. The session store tracks call counts and fixed-window rate counters, making per-request enforcement O(1) with no external dependencies.

To run: `bash demo.sh`
