# Architecture Decision Records

These records capture the key decisions that shaped Arbiter's design. Each explains the context, the options considered, and the rationale for the choice made.

## ADR-001: Deny-by-Default Authorization

**Status:** Accepted

**Context:** The policy engine needs a default behavior when no policy matches a request. The two options are allow-by-default (permissive) and deny-by-default (restrictive).

**Decision:** Deny-by-default. If no policy explicitly allows a request, it's denied.

**Rationale:** For a tool-call firewall protecting autonomous agents, the consequence of accidentally *allowing* an unauthorized action is far worse than accidentally *blocking* an authorized one. A false denial produces a 403 that an operator can debug. A false allow produces a data breach.

Allow-by-default works for systems where the happy path is permissive (web servers, content delivery). It's wrong for security boundaries where the safe default is closed.

**Consequences:** Operators must write explicit Allow policies for every authorized action. This creates setup overhead but eliminates the class of bugs where "we forgot to deny something."

---

## ADR-002: Rust

**Status:** Accepted

**Context:** Arbiter sits in the hot path between every agent and its upstream MCP server. Language choice affects latency, reliability, and attack surface.

**Decision:** Rust with async runtime (tokio).

**Rationale:**
- **Latency**: The middleware chain adds overhead to every request. Rust's lack of GC pauses and zero-cost abstractions keep this predictable and low (typically <5ms for the full chain).
- **Memory safety**: A security gateway that's itself vulnerable to buffer overflows or use-after-free would undermine the premise. Rust eliminates these classes at compile time.
- **Binary deployment**: Ships as a single static binary. No runtime dependencies, no interpreter versioning, no dependency conflicts on the host.
- **Concurrency**: Tokio's async runtime handles thousands of concurrent connections efficiently, which matters for high-throughput agent deployments.

**Alternatives considered:**
- Go: simpler concurrency model, but GC pauses in the hot path and weaker type safety for the policy model
- Python: poor latency characteristics for a proxy, GIL limitations for concurrent request handling
- Java/Kotlin: JVM startup time and memory footprint inappropriate for a lightweight gateway

---

## ADR-003: In-Memory Registry

**Status:** Accepted (with SQLite as opt-in alternative)

**Context:** Agents and sessions need a store. The options range from in-memory data structures to external databases.

**Decision:** In-memory by default. SQLite available as an opt-in feature for persistent storage.

**Rationale:** Most deployments are single-node, and agent/session counts are in the hundreds, not millions. In-memory storage gives microsecond access with zero operational overhead. Operators who don't need persistence shouldn't be forced to manage a database.

For deployments that need persistence across restarts, the SQLite backend provides it with minimal overhead (WAL mode, auto-migration).

**Consequences:**
- Default deployment loses state on restart. Agents must be re-registered.
- This is acceptable when an orchestration layer manages agent lifecycle externally.
- If your deployment needs persistence, add one line to the config: `backend = "sqlite"`.

---

## ADR-004: TOML Policy Language

**Status:** Accepted

**Context:** Authorization policies need a format that operators can read, write, and version-control.

**Decision:** TOML files with a structured schema.

**Rationale:**
- **Readability**: TOML is more readable than JSON for configuration. No trailing commas, no brace-matching, comments are first-class.
- **Version control**: Text-based policies are diffable and reviewable in pull requests. Policy changes are auditable in git history.
- **Validation**: Serde deserialization provides compile-time type checking on policy structure. Malformed policies are caught at load time, not at request time.
- **Hot reload**: File-watching with atomic swap means policy changes don't require restarts.

**Alternatives considered:**
- Rego (OPA): more expressive but requires learning a new language. Overkill for most agent authorization scenarios.
- JSON: valid but noisier. No comments. Harder for humans to edit without syntax errors.
- YAML: ambiguous parsing (the Norway problem, boolean coercion). TOML's explicit typing avoids these foot-guns.
- SQL-based rules: powerful querying but heavyweight runtime dependency and harder to version-control.

---

## ADR-005: Firewall-Only Mode (Proposed)

**Status:** Proposed

**Context:** Arbiter's current deployment model requires operators to use the Admin API to register agents, create sessions, and issue tokens before any enforcement happens. For teams that just need "stop my agent from calling unauthorized tools," this ceremony-to-value ratio is wrong. The most common adoption path is: operator has an incident (agent runs destructive SQL), wants enforcement immediately, and doesn't want to adopt a full identity/session model to get it.

**Problem:** The smallest useful Arbiter deployment currently requires: (1) configure TOML, (2) start the binary, (3) `POST /agents` to register the agent, (4) `POST /sessions` to create a session, (5) pass session headers from the agent. Steps 3-5 require the Admin API, token management, and agent-side integration. For a team that just wants "policy file blocks unauthorized tool calls," this is too much.

**Proposed decision:** Add a `firewall` mode alongside the current `gateway` mode.

**Firewall mode behavior:**
- Policy engine evaluates every MCP tool call against the policy file. Deny-by-default still applies.
- Agent identity extracted from request headers (`x-agent-id`) or JWT claims — no `POST /agents` registration required.
- Sessions are implicit: each request is evaluated independently against policy. No session creation, no budgets, no time limits.
- Admin API disabled. No agent registry. No session store.
- Audit logging still active — every decision is logged.
- Behavioral drift detection disabled (requires session context to compare against declared intent).

**Configuration:**

```toml
mode = "firewall"  # "gateway" (default) | "firewall"

[proxy]
listen_port = 8080
upstream_url = "http://mcp-server:8081"

[policy]
file = "policies.toml"

[audit]
enabled = true
```

That's the entire config. Three sections, enforcement active.

**Trade-offs:**
- **Gains:** Adoption ramp drops from "integrate with Admin API" to "drop in a policy file." Matches the mental model of teams coming from nginx/OPA/Envoy.
- **Loses:** No session budgets, no rate limiting, no drift detection, no delegation chains. These require the full gateway mode.
- **Risk:** Two modes means two code paths to maintain and test. Mitigation: firewall mode is a strict subset — it's the gateway pipeline with session/behavior/lifecycle stages removed, not a separate implementation.

**Rationale:** The full governance model is valuable for mature deployments. But the on-ramp should be "policy file + upstream = enforcement." Users who outgrow firewall mode graduate to gateway mode when they need budgets, sessions, and behavioral monitoring. This is the same progression as nginx (static config) to Envoy (control plane) — both are valid, serving different operational maturity levels.

**Alternatives considered:**
- Default session with permissive settings: still requires session headers from the agent, which is the integration burden we're trying to remove.
- Anonymous agent fallback: risks creating a bypass path where agents omit identity to avoid restrictions.
- Separate binary: duplicates code and confuses which binary to deploy. A mode flag is simpler.
