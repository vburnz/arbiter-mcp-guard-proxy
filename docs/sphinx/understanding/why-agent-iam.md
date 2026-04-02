# Why MCP Tool Calls Need a Firewall

## The Problem

AI agents now have direct access to enterprise tools, APIs, and data through MCP (Model Context Protocol). They fire hundreds of tool calls per session with nobody reviewing each action.

Traditional IAM was built for humans:

- **Identity** means a person with a username and password.
- **Authorization** means role-based access control.
- **Sessions** mean login and logout with inactivity timeouts.
- **Audit** means who did what, when.

None of that maps cleanly to agents.

| Human IAM | What Agents Need |
|-----------|-----------------|
| Interactive login | Agents use tokens; they never "log in" |
| Role-based access | Agents need per-tool-call, per-task access control |
| Session = login duration | Agent sessions should be scoped to a single task |
| Manual oversight | Agents act autonomously at machine speed |
| One identity per person | Agents delegate to sub-agents, forming chains |

The result: your existing identity infrastructure can tell you *who* is making a request, but it can't enforce per-tool-call authorization, session budgets, or operation-type scope at the MCP layer.

## Industry Recognition

This isn't a theoretical gap. Multiple industry bodies have flagged agent identity as a critical blind spot.

**ISACA** highlights that AI systems require identity management beyond traditional user-centric models. Autonomous agents need continuous monitoring, behavioral analysis, and real-time access revocation, capabilities absent from standard IAM deployments.

**The Cloud Security Alliance** emphasizes fine-grained access control, audit trails, and least privilege applied to AI agents. Their AI security guidance specifically calls out the risk of agents accumulating permissions beyond their intended scope.

**The OpenID Foundation** is actively working on standards for AI agent authentication and authorization. They recognize that OAuth 2.0 and OIDC need extensions for agent delegation chains, capability scoping, and short-lived task-bound credentials.

## What Arbiter Does

Arbiter fills these gaps with six capabilities.

### Agent Identity with Delegation Chains

Every agent is registered with an owner (a human principal), a trust level, and a set of capabilities. Agents can delegate to sub-agents, but only with *narrowed* capabilities. A sub-agent can never have more permissions than its parent. Deactivate a parent, and every delegate in the chain goes down with it.

### Deny-by-Default Authorization

Arbiter evaluates every tool call against deny-by-default policies that match on agent identity, trust level, session context, tool name, and parameter constraints. If no explicit Allow policy matches, the request is denied. Policies are ordered by specificity. An agent-specific rule overrides a broad default.

### Task Sessions with Budgets

Each agent task runs in a session with a time limit, a call budget (maximum tool calls), a tool whitelist, and a data sensitivity ceiling. When the budget runs out or the clock expires, the session is done.

### Drift Detection

Arbiter classifies every tool call as read, write, delete, or admin based on tool naming patterns. If a session is scoped for read operations but the agent starts making write calls, the drift detector flags or blocks the divergence. This catches unintentional scope drift, not adversarial agents deliberately circumventing detection.

### Structured Audit with Redaction

Every request produces a structured JSON audit entry: request ID, agent ID, delegation chain, tool called, arguments (with sensitive fields automatically redacted), authorization decision, matching policy, anomaly flags, latency, and upstream status. Append-only JSONL output, with optional BLAKE3 hash chaining for tamper detection.

### Deny-by-Default Policy Engine

Nothing is authorized unless an explicit policy says so. Policies are evaluated by specificity; an agent-specific Allow beats a broad Deny. You can still add surgical overrides where you need them without loosening everything else.

## The Architecture in One Sentence

Arbiter is an MCP tool-call firewall that enforces deny-by-default authorization, session budgets, drift detection, and structured auditing on every tool call between AI agents and MCP servers. It is not an identity provider or identity management platform. It sits downstream of your IdP and enforces per-tool-call policy.

## What Arbiter Is (and Isn't)

Arbiter is a **syntactic enforcement layer**. It operates at the network boundary between agents and MCP servers, enforcing access control, budgets, and operational scope on every tool call.

Arbiter does **not** perform semantic analysis of agent intent. It doesn't understand *why* an agent is making a tool call or whether the agent's reasoning is sound. That's the job of the agent framework, the model provider, and the system prompt.

A well-governed agent stack needs both. Semantic alignment inside the agent (system prompts, RLHF, framework guardrails) and syntactic enforcement at the infrastructure boundary (Arbiter).

Arbiter governs what agents are **allowed** to do. It does not govern what agents **try** to do. It protects the platform by reducing the tool-call attack surface.

## Who Needs This?

- **Enterprises deploying AI agents** that access internal tools and data
- **Platform teams** building multi-agent systems where agents delegate tasks
- **Security teams** that need audit trails and anomaly detection for AI operations
- **Compliance officers** who need to demonstrate control over AI agent access

## Who Doesn't

**MCP-only.** Arbiter enforces on MCP (JSON-RPC over HTTP) tool calls. If your agents use a different protocol — OpenAI function calling, LangChain tool use, or direct API calls — Arbiter won't help. Non-MCP traffic (GET, PUT, DELETE, PATCH) is **denied by default**. If you disable `deny_non_post_methods`, those requests pass through the proxy without session validation, policy evaluation, or behavioral analysis.

**Not an identity provider.** Arbiter doesn't replace Okta, Auth0, or Keycloak. It doesn't manage identity lifecycle, access certification, provisioning workflows, or entitlement catalogs. It enforces tool-call policy downstream of your IdP. If you need centralized non-human identity management across hundreds of service identities, look at [Aembit](https://aembit.io).

**Not adversarial AI defense.** Arbiter is a syntactic enforcement layer. It blocks unauthorized tool calls, enforces budgets, and detects operational drift. It does not analyze agent reasoning, detect prompt injection, or prevent an agent from misusing its legitimate, whitelisted tools. If your primary threat is an adversary who has compromised the agent's reasoning, you need defenses inside the agent stack (system prompts, guardrails, content filtering) in addition to infrastructure-layer enforcement.

**Not worth the overhead for simple setups.** If you're running one agent on a side project, just scope your API keys directly. Arbiter's value scales with the number of agents, the sensitivity of the tools they access, and the need for auditable governance.

## Next Steps

- {doc}`architecture`: how the middleware chain works
- {doc}`../getting-started/quickstart`: try it in 5 minutes
- {doc}`../guides/policy`: write your first authorization rules
