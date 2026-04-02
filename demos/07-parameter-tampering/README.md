# Demo 07: Parameter Tampering

This demo shows how Arbiter enforces per-parameter constraints on tool call arguments.

Even when an agent is authorized to call a particular tool, the arguments matter. An agent allowed to call `generate_text` with a reasonable token limit could be manipulated (or deliberately programmed) to set `max_tokens` to 50,000, consuming excessive compute resources. Without parameter constraints, the tool-level authorization check would pass and the expensive request would reach the upstream server.

The demo configures an Allow policy for `generate_text` with a `parameter_constraints` entry that limits `max_tokens` to a maximum of 1000 and `temperature` to a range of 0.0 to 2.0. A legitimate call with `max_tokens = 500` passes the constraint check and the policy matches. The attack call with `max_tokens = 50000` fails the constraint check, so the Allow policy does not match. Since no other policy covers this tool, Arbiter's deny-by-default returns a 403 with error code `POLICY_DENIED`.

Parameter constraints are checked as part of policy matching at Stage 8, meaning they are evaluated alongside agent identity, principal, and intent criteria. This keeps the policy model composable: you can have different parameter limits for different trust levels or principals.

To run: `bash demo.sh`
