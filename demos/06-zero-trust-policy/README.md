# Demo 06: Zero-Trust Policy (Deny-by-Default)

This demo shows how Arbiter's deny-by-default policy engine blocks agents that have no matching Allow policy.

In a zero-trust architecture, no agent is trusted by default. Every tool call must be explicitly authorized by a policy that matches the agent's identity, principal, intent, and the specific tool being called. If no policy matches, the request is denied.

The demo configures a single Allow policy that permits `deploy_service` only when the principal is `user:trusted-team` and the intent contains the keyword "deploy". An attacker registers an agent owned by `user:rogue-contractor` and creates a session authorized for `deploy_service`. The session check passes (the tool is in the whitelist), but the policy engine at Stage 8 evaluates all policies and finds no match: the principal criterion requires `user:trusted-team`, not `user:rogue-contractor`.

The response includes a policy trace showing exactly which policies were evaluated, their specificity scores, and why each one did not match. This transparency helps operators debug policy configurations and proves the denial was intentional.

To run: `bash demo.sh`
