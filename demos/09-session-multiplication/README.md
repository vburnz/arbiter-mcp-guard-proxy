# Demo 09: Session Multiplication

This demo shows how Arbiter's per-agent session cap prevents session multiplication attacks.

A compromised or malicious agent can attempt to bypass per-session rate limits by opening many concurrent sessions. Each session has its own call budget (e.g., 1000 calls), so an agent that opens 100 sessions effectively grants itself a 100,000-call budget. Without a cap, per-session limits provide no meaningful aggregate protection.

The `max_concurrent_sessions_per_agent` setting (default: 10) closes this gap. Once an agent reaches the cap, further session creation requests are rejected with HTTP 429. Existing sessions are unaffected.

The demo registers a single agent and attempts to create 15 sessions. The first 10 succeed. Sessions 11 through 15 are rejected with HTTP 429 and a JSON body explaining the cap.

## Attack scenario

1. Agent `multiply-agent` is registered with `read` capabilities
2. Attacker script creates sessions in a loop, each with a 1000-call budget
3. Intent: accumulate 100 x 1000 = 100,000 total calls, bypassing per-session limits

## Defense

- `max_concurrent_sessions_per_agent = 10` in config
- Session creation returns 429 once the cap is reached
- Total effective budget capped at 10 x 1000 = 10,000 calls

## Expected output

```
Session  1: 200 OK (session created)
Session  2: 200 OK (session created)
...
Session 10: 200 OK (session created)
Session 11: 429 (too many concurrent sessions)
Session 12: 429 (too many concurrent sessions)
...
Session 15: 429 (too many concurrent sessions)
```

To run: `bash demo.sh`
