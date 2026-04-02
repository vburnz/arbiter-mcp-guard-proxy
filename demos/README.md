# Arbiter Attack Demos

Ten reproducible demonstrations of AI agent attacks that Arbiter blocks in real time. Each demo is self-contained: one config, one script, one explanation.

## Prerequisites

Build Arbiter from the project root:

```bash
cargo build --release
```

The binary will be at `target/release/arbiter`. Each demo script expects to find it at `../../target/release/arbiter` (relative to the demo directory).

An upstream echo server is not required for these demos. Arbiter blocks the attacks at the proxy layer before any request reaches upstream. If a legitimate call does need to reach upstream, the demo will note it.

## Running a demo

```bash
cd demos/01-unauthenticated-access
bash demo.sh
```

Each script will:
1. Start Arbiter with the demo-specific config
2. Wait for initialization
3. Run the attack (and sometimes a legitimate request for contrast)
4. Show Arbiter's structured JSON response
5. Print an explanation
6. Shut down Arbiter

## The ten attack patterns

| # | Demo | Attack | Expected |
|---|------|--------|----------|
| 01 | Unauthenticated Access | MCP call without session header | 403 SESSION_REQUIRED |
| 02 | Protocol Injection | Non-MCP POST body in strict mode | 403 NON_MCP_REJECTED |
| 03 | Tool Escalation | Call a tool not in session whitelist | 403 SESSION_INVALID |
| 04 | Resource Exhaustion | Exceed session call budget and rate limit | 429 SESSION_INVALID |
| 05 | Session Replay | Reuse an expired session | 408 SESSION_INVALID |
| 06 | Zero-Trust Policy | No matching Allow policy (deny-by-default) | 403 POLICY_DENIED |
| 07 | Parameter Tampering | Exceed parameter constraints on a tool | 403 POLICY_DENIED |
| 08 | Intent Drift | Write operation in a read-only session | 403 BEHAVIORAL_ANOMALY |
| 09 | Session Multiplication | Open sessions beyond per-agent cap | 429 TOO_MANY_SESSIONS |
| 10 | Credential Leakage | Upstream echoes injected credentials | 200 (scrubbed) |

## Color coding

- Green text = allowed (legitimate request succeeded)
- Red text = blocked (attack was stopped)
- Yellow text = informational headers or warnings

## Architecture

Each demo uses two ports:
- **8080** (proxy) for MCP traffic that Arbiter inspects
- **3000** (admin) for agent registration and session creation

All enforcement is real. No simulation, no mocks, no stubs.

**What these demos cover and don't.** These scenarios test policy enforcement: an agent hitting boundaries that an operator configured. They don't demonstrate defense against an adversary who has compromised the agent's reasoning and is using legitimate, whitelisted tools to carry out malicious intent. That threat class is outside Arbiter's enforcement surface. See `docs/sphinx/understanding/security-model.md` for the full boundary analysis.
