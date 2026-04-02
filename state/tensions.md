# Tensions — license migration run 2026-04-17

Structural tensions surfaced during compile. Preserved as search drivers, not resolved prematurely.

## T-001 — Irreversibility vs autonomous speed
- **A:** C-009 (publish release) — autonomous mode pressures for fast, uninterrupted execution
- **B:** C-001..C-006 (pre-publish verification) — license publication is irreversible; forks can propagate
- **Disposition:** preserve. Phase boundary P2→P3 is a hard verification gate. Do NOT collapse phases. `/execute --interrogate` should apply REOPEN_SOLUTION between P2 and P3.

## T-002 — Copyleft strictness vs ecosystem breadth
- **A:** User's explicit GPL-3.0 choice (copyleft intent)
- **B:** Apache-2.0 permissiveness (broader adoption)
- **Disposition:** accept. User-driven. Compiler does not second-guess.

## T-003 — Naming drift (adjacent)
- **A:** Cargo.toml `repository = github.com/vburnz/mcp-gateway-firewall`
- **B:** Actual remote: `github.com/vburnz/mcp-gateway-firewall`
- **Disposition:** fold into C-005 (Cargo manifest update). Do NOT expand to full repo rename — out of scope.

## T-004 — Version bump semantics
- **A:** License change is breaking for downstream consumers
- **B:** semver does not define license-change semantics
- **Disposition:** resolve to 0.1.0. Document rationale in release notes.

## T-005 — Inbound contributions license
- **A:** Prior contributions (none external, but future PRs)
- **B:** Post-migration outbound license
- **Disposition:** note in release (inbound=outbound → GPL-3.0). Check CONTRIBUTING.md in P1; amend if it exists.
