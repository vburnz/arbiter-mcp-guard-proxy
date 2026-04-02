# Demo 05: Session Replay

This demo shows how Arbiter prevents reuse of expired or closed sessions.

Session replay is a common attack pattern: an attacker intercepts or obtains a valid session ID (through log scraping, network sniffing, or a compromised agent) and uses it later to make unauthorized requests. If sessions lived forever, a single leaked ID would grant permanent access.

The demo creates a session with a 3-second TTL. An immediate tool call succeeds, but after waiting 4 seconds, the same session ID returns a 408 with error code `SESSION_INVALID` and a detail message explaining the session has expired. The demo also shows that sessions explicitly closed via the admin API return a 410 Gone.

Arbiter's session store checks expiry on every request at use time. A separate background cleanup task periodically removes expired sessions from memory, but expiry enforcement does not depend on it. This means even if an attacker knows a valid session UUID, it becomes useless after the TTL passes.

To run: `bash demo.sh`
