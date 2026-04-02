# Attack Demo Series: Publication Schedule

All 8 demos are pre-written and ready. Publish one per week for 8 weeks.
After week 8: no ongoing content obligation. Finite series, not a treadmill.

## Schedule

| Week | Demo | Page | HN Post? |
|------|------|------|----------|
| 1 | Unauthenticated Access | `/demos/unauthenticated-access` | **Show HN**, first demo, establishes the series |
| 2 | Protocol Injection | `/demos/protocol-injection` | No, organic search only |
| 3 | Tool Escalation | `/demos/tool-escalation` | No |
| 4 | Resource Exhaustion | `/demos/resource-exhaustion` | No |
| 5 | Session Replay | `/demos/session-replay` | No |
| 6 | Zero-Trust Policy | `/demos/zero-trust-policy` | No |
| 7 | Parameter Tampering | `/demos/parameter-tampering` | No |
| 8 | Intent Drift | `/demos/intent-drift` | **Show HN**, final demo, capstone + Pro announcement |

## Publication Mechanics

1. All pages already exist in `docs/demos/`
2. Each demo has a corresponding Docker script in `demos/0N-*/`
3. To "publish": push the page live on protectedbyarbiter.dev (GitHub Pages)
4. Cross-link from index page (`docs/demos/index.html`) as each goes live
5. No social media accounts needed. HN posts are the only active distribution

## SEO Strategy

Each page targets a specific long-tail query:
- "AI agent unauthenticated access attack"
- "MCP protocol injection prevention"
- "AI agent tool escalation defense"
- "AI agent resource exhaustion rate limiting"
- "MCP session replay attack"
- "AI agent zero trust policy"
- "AI agent parameter tampering"
- "AI agent intent drift detection"

Pages are self-contained; each one converts independently via:
threat description → live demo → defense explanation → try-it-yourself → pricing CTA

## Post-Series

After week 8:
- No new demos required
- Pages continue ranking for organic search
- Blog post summarizing the series (coincides with launch)
- Quarterly: check search console, update if any demo page underperforms
