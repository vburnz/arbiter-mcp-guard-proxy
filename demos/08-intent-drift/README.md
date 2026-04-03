# Demo 08: Intent Drift

This demo shows how Arbiter's behavioral anomaly detector catches operations that contradict the session's declared intent, even when both the session whitelist and policy engine would allow the call.

Intent drift is a subtle attack pattern. An agent declares a read-only intent (such as "read and analyze the source code") to obtain a session, then gradually escalates to write or delete operations. The session whitelist might include write tools for legitimate use cases, and the policy engine might have a broad Allow policy. Neither check catches the mismatch between what the agent said it would do and what it is actually doing.

The behavioral anomaly detector at Stage 9 fills this gap. It classifies the declared intent using keyword matching against configurable intent tiers (read, write, admin). Intents that match no tier are classified as Unknown and flag all operations as anomalous. The intent "read and analyze" matches the read tier. It then classifies each tool call by operation type. When the agent calls `write_file`, the detector flags this as a Write operation in a Read session -- a behavioral anomaly.

With `escalate_anomalies = true`, this flag escalates to a hard deny with a 403 and error code `BEHAVIORAL_ANOMALY`. With `escalate_anomalies = false`, the anomaly would be logged and flagged in the audit trail but the request would proceed, allowing a human reviewer to investigate.

To run: `bash demo.sh`
