# Arbiter

[![Donate](https://img.shields.io/badge/Sponsor-♡-ff69b4)](https://github.com/sponsors/cyrenei)

**MCP tool-call firewall.** Arbiter governs what agents are allowed to do. It does not govern what agents try to do. It protects the platform by reducing the tool-call attack surface.

Sits between your AI agents and the MCP servers they talk to, enforcing deny-by-default authorization, session budgets, drift detection, and audit logging on every single tool call. Traditional access control was built for humans who log in and make decisions. Arbiter was built to govern MCP tool calls from agents that fire hundreds of requests per session.

---

::::{grid} 1 2 2 3
:gutter: 3

:::{grid-item-card} Why MCP Tool Calls Need a Firewall
:link: understanding/why-agent-iam
:link-type: doc

The gap between traditional access control and what MCP agents need.
:::

:::{grid-item-card} Quickstart
:link: getting-started/quickstart
:link-type: doc

Running Arbiter in 5 minutes with Docker Compose.
:::

:::{grid-item-card} Architecture
:link: understanding/architecture
:link-type: doc

How a request travels through the 9-stage middleware chain.
:::

::::

---

## What You'll Find Here

**Understanding Arbiter** covers the *why*: the problem Arbiter solves, how its architecture works, and the security model underpinning it. Start here if you're evaluating whether Arbiter fits your stack.

**Getting Started** walks you from zero to a running gateway in minutes. Register your first agent, write your first policy, create your first session.

**Guides** go deep on individual features. Each guide opens with the problem, explains the design, and walks through configuration with real examples.

**Operating Arbiter** covers deployment, monitoring, and troubleshooting for production environments.

**Reference** is the lookup section: every configuration key, every API endpoint, every CLI command. Come back here when you know what you need but forget the syntax.

## Donate

Arbiter is free and always will be. If you want to throw a few dollars our way,
it goes straight to wet food for the office kitten, who has somehow developed a
taste for the high-end stuff.

**[Sponsor on GitHub](https://github.com/sponsors/cyrenei)**

Contact: [arbitersecurity@proton.me](mailto:arbitersecurity@proton.me) ([PGP Public Key](https://cyrenei.github.io/arbiter-mcp-firewall/pub-key.asc))

```{toctree}
:maxdepth: 2
:caption: Understanding Arbiter
:hidden:

understanding/why-agent-iam
understanding/architecture
understanding/security-model
```

```{toctree}
:maxdepth: 2
:caption: Getting Started
:hidden:

getting-started/quickstart
getting-started/first-policy
getting-started/first-session
```

```{toctree}
:maxdepth: 2
:caption: Guides
:hidden:

guides/policy
guides/sessions
guides/credentials
guides/behavior
guides/audit
guides/metrics
```

```{toctree}
:maxdepth: 2
:caption: Operating Arbiter
:hidden:

operating/deployment
operating/monitoring
operating/troubleshooting
```

```{toctree}
:maxdepth: 2
:caption: Reference
:hidden:

reference/configuration
reference/api
reference/cli
reference/attack-scenarios
reference/decisions
```
