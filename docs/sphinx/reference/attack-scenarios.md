# Attack Scenario Library

Arbiter ships with 10 self-contained attack demonstrations in the `demos/` directory. Each demo runs a specific attack, shows Arbiter blocking it, and then runs a legitimate request for contrast. These are real enforcement scenarios, not mocks or simulations.

**Scope of these demos.** These scenarios test *policy enforcement* — an agent hitting boundaries that an operator configured. They demonstrate that Arbiter correctly blocks unauthorized tool calls, enforces budgets, detects drift, and scrubs credentials. They do not demonstrate defense against an adversary who controls the agent's reasoning (e.g., via prompt injection) and uses legitimate, whitelisted tools to carry out malicious intent. That threat class is outside Arbiter's enforcement surface; see {doc}`../understanding/security-model` for the full boundary analysis.

## Running the Demos

Each demo has its own directory with a script and configuration:

```bash
$ cd demos/01-unauthenticated-access
$ ./demo.sh
```

Demos start their own Arbiter instance, run the attack, show the result, and clean up.

---

## Demo 01: Unauthenticated Access

**Attack:** Send an MCP tool call without a session header.

**Defense:** `require_session = true` (default). Requests without `x-arbiter-session` are rejected with 403 before any middleware runs.

**What you see:**

```text
Attack:  POST /  (no session header)  → 403 Forbidden
Legit:   POST /  (with session header) → 200 OK
```

---

## Demo 02: Protocol Injection

**Attack:** Send a non-JSON-RPC POST body through the proxy.

**Defense:** `strict_mcp = true` (default). Non-MCP POST traffic is rejected, preventing protocol smuggling where an attacker bypasses the MCP parser entirely.

---

## Demo 03: Tool Escalation

**Attack:** Call a tool that isn't on the session's whitelist.

**Defense:** The session middleware checks every tool call against `authorized_tools`. Tools not on the list get 403 regardless of policy.

---

## Demo 04: Resource Exhaustion

**Attack:** Exceed the session's call budget, then hit the rate limit.

**Defense:** Call budget enforcement (429 when `calls_made >= call_budget`) and per-minute rate limiting. The session tracks both counters and rejects excess calls.

---

## Demo 05: Session Replay

**Attack:** Reuse an expired session ID.

**Defense:** The session middleware checks status on every request. Expired sessions return 408 Gone. Time limits aren't advisory. They're hard-enforced.

---

## Demo 06: Zero-Trust Policy

**Attack:** Make a tool call with no matching Allow policy.

**Defense:** Deny-by-default. If no policy explicitly allows the tool for this agent/intent combination, the request is denied. This demo runs with an empty policy file to show the baseline behavior.

---

## Demo 07: Parameter Tampering

**Attack:** Call a tool with argument values that violate parameter constraints.

**Defense:** Policy parameter constraints enforce numeric bounds (`max_value`, `min_value`) and string allowlists (`allowed_values`). An agent requesting `max_tokens: 10000` when the policy caps at `1000` gets denied.

---

## Demo 08: Intent Drift

**Attack:** Declare a read intent, then call write tools.

**Defense:** The behavioral anomaly detector classifies the intent as "read" and the tool call as "write." The mismatch fires an anomaly. With `escalate_anomalies = true`, the request is blocked.

---

## Demo 09: Session Multiplication

**Attack:** Open many concurrent sessions to multiply the effective call budget.

**Defense:** `max_concurrent_sessions_per_agent` (default 10) caps how many active sessions one agent can hold. Session creation beyond the cap returns 429 `TooManySessions`.

---

## Demo 10: Credential Leakage via Response

**Attack:** An upstream MCP server returns a response containing credentials that Arbiter injected into the outgoing request.

**Defense:** When credential injection is active, Arbiter scrubs responses for the exact secrets it injected, across multiple encodings (plaintext, URL-encoded, JSON-escaped, hex, base64). Matches are replaced with `[CREDENTIAL]` before the response reaches the agent.

**Scope:** This is closed-scope scrubbing: it catches secrets Arbiter knows about because it injected them. It does not perform general PII detection or prompt injection scanning on arbitrary response content.

---

## What These Demos Cover

| # | Threat | Stage That Blocks It |
|---|--------|---------------------|
| 01 | Unauthenticated access | Session middleware |
| 02 | Protocol smuggling | MCP parser (strict mode) |
| 03 | Tool escalation | Session tool whitelist |
| 04 | Resource exhaustion | Session budget + rate limiter |
| 05 | Session replay | Session expiry check |
| 06 | Missing authorization | Policy engine (deny-by-default) |
| 07 | Parameter tampering | Policy parameter constraints |
| 08 | Intent drift | Behavioral anomaly detector |
| 09 | Session multiplication | Per-agent session cap |
| 10 | Credential leakage | Credential response scrubbing |

Together, these demonstrate defense-in-depth: even if one layer is bypassed (stolen session ID, for instance), other layers catch the attack (policy evaluation, behavioral detection, credential scrubbing).
