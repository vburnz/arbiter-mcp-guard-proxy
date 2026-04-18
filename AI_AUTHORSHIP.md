# Authorship

This codebase was written by **Claude Opus 4.6** (Anthropic's AI assistant) under close human supervision, as a sanitized adaptation of a private research codebase. The release omits internal naming, working-process artifacts, and operator-specific infrastructure.

## What this means

- The proxy, policy engine, and audit pipeline are real, runnable, and enforce the behaviors documented in the [README](README.md) and [docs](docs/).
- The code was authored, refactored, and documented through extensive AI assistance — Claude Opus 4.6 wrote the bulk of the source, the build configuration, and this documentation, with human review at each step.
- Names, paths, and identifiers were chosen to be generic. They do not match the original research project.
- Working-process artifacts (incident logs, design narratives, decision records, internal threat models tied to specific deployments) are not part of this release.

## What is preserved

- The enforcement model — deny-by-default tool allowlists, session time limits and call budgets, drift detection between declared intent and actual tool-call patterns, hash-chained structured audit.
- The trust model — operator trusted, policy authoritative, agent untrusted, declared intent advisory.
- The architecture decisions that survived contact with real MCP traffic.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
