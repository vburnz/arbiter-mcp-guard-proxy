# Demo 03: Tool Escalation

This demo shows how Arbiter prevents an agent from calling tools outside its authorized set.

When a session is created, the administrator specifies exactly which tools the agent is permitted to use. In this demo, the session authorizes only `read_file` and `list_dir`. The agent first makes a legitimate `read_file` call (which passes the session check), then attempts to call `delete_file`.

Arbiter checks the tool name against the session's `authorized_tools` whitelist at Stage 7 of the middleware pipeline. Since `delete_file` is not in the set, the request is denied with a 403 and error code `SESSION_INVALID`. The session itself remains valid for future authorized calls.

This is a critical control for the principle of least privilege. Even if an agent is authenticated and has a valid session, it can only use the specific tools it was granted. A compromised or misbehaving agent cannot escalate to destructive operations.

To run: `bash demo.sh`
