# Arbiter Compliance Policy Templates

Pre-built policy configurations for common regulatory frameworks. Each template defines a set of authorization policies that enforce framework-specific controls on AI agent tool usage.

## Available Templates

| Template | Framework | Focus |
|----------|-----------|-------|
| `soc2.toml` | SOC 2 | Audit completeness, least privilege, destructive operation controls |
| `hipaa.toml` | HIPAA | PHI access control, minimum necessary, export restrictions |
| `pci-dss.toml` | PCI DSS | Credential denial, transaction monitoring, cardholder data protection |
| `eu-ai-act.toml` | EU AI Act | Human oversight, high-risk escalation, prohibited practice denial |

## Usage

Reference a template in your Arbiter configuration file:

```toml
[proxy]
upstream_url = "http://localhost:9000"

[policy]
file = "templates/soc2.toml"

[sessions]
require_session = true

[audit]
enabled = true
```

Then start Arbiter:

```
arbiter --config config.toml
```

## Combining with Custom Policies

Templates are standalone policy files. To add organization-specific rules, copy the template and append your policies:

```
cp templates/hipaa.toml my-policies.toml
# Edit my-policies.toml to add custom [[policies]] entries
```

Policies are evaluated by specificity score (higher = more specific = wins ties). Set `priority` explicitly to control ordering when needed.

## Policy Evaluation Model

- **Deny-by-default**: if no policy matches a tool call, it is denied.
- **Most-specific-match-wins**: when multiple policies match, the one with the highest specificity score takes effect.
- **Effects**: `allow` permits the call, `deny` blocks it, `escalate` flags it for human review.

## Validation

Use the Arbiter admin API to validate a policy file before deploying:

```
POST /admin/validate-policy
Content-Type: application/toml

<contents of template file>
```

The response includes parse errors, duplicate ID warnings, and shadowed policy diagnostics.
