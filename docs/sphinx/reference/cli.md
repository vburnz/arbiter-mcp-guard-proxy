# CLI Reference

Arbiter includes a command-line tool, `arbiter-ctl`, for managing agents, delegations, policies, and audit logs without writing curl commands.

## Installation

`arbiter-ctl` is built alongside the main binary:

```bash
$ cargo build --release
$ ./target/release/arbiter-ctl --help
```

All commands require the admin API to be running and expect the API key either as a flag or the `ARBITER_ADMIN_API_KEY` environment variable.

## Commands

### register-agent

Register a new agent.

```bash
$ arbiter-ctl register-agent \
  --owner "user:alice" \
  --model "gpt-4" \
  --capabilities read,write \
  --trust-level basic \
  --api-url http://localhost:3000
```

| Flag | Required | Description |
|------|----------|-------------|
| `--owner` | yes | Human principal (OAuth subject) |
| `--model` | yes | LLM model identifier |
| `--capabilities` | yes | Comma-separated capability list |
| `--trust-level` | yes | `untrusted`, `basic`, `verified`, `trusted` |
| `--api-url` | no | Admin API URL (default: `http://localhost:3000`) |

### list-agents

List all registered agents.

```bash
$ arbiter-ctl list-agents --api-url http://localhost:3000
```

### create-delegation

Create a delegation link between agents.

```bash
$ arbiter-ctl create-delegation \
  --from $AGENT_A \
  --to $AGENT_B \
  --scopes read \
  --api-url http://localhost:3000
```

| Flag | Required | Description |
|------|----------|-------------|
| `--from` | yes | Delegating agent ID |
| `--to` | yes | Target agent ID |
| `--scopes` | yes | Comma-separated scopes (must be subset of parent's) |

### revoke

Deactivate an agent and cascade-deactivate all delegates.

```bash
$ arbiter-ctl revoke --agent-id $AGENT_ID
```

### policy test

Dry-run a tool call against loaded policies.

```bash
$ arbiter-ctl policy test \
  --agent-id $AGENT_ID \
  --trust-level basic \
  --intent "read configuration" \
  --tool read_file
```

### doctor

Run diagnostic checks on your configuration.

```bash
$ arbiter-ctl doctor --config arbiter.toml
```

Checks:
- Configuration file parses correctly
- Policy file loads and validates
- Audit log path is writable
- Storage backend is reachable

### update

Check for and install Arbiter updates from GitHub Releases.

```bash
# Check for available updates
$ arbiter-ctl update --check

# Update to latest version
$ arbiter-ctl update

# Update to a specific version
$ arbiter-ctl update --version v0.6.0
```

| Flag | Required | Description |
|------|----------|-------------|
| `--check` | no | Check for updates without installing |
| `--version` | no | Target version (default: latest) |

The update command downloads the new binary, verifies its SHA256 checksum (and minisign signature if available), and atomically replaces the installed `arbiter` binary. Disable with `ARBITER_NO_SELF_UPDATE=1`.

## Global Flags

| Flag | Description |
|------|-------------|
| `--api-url` | Admin API base URL (default: `http://localhost:3000`) |
| `--api-key` | Admin API key (or use `ARBITER_ADMIN_API_KEY` env var) |
| `--config` | Path to arbiter.toml (for `doctor` command) |
