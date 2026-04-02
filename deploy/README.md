# Deploy Arbiter

Get from zero to running proxy in under 3 minutes. Pick your platform:

| Platform | Best for | Time to deploy |
|----------|----------|----------------|
| [Binary Install](#option-0-binary-install) | Fastest, any Linux/macOS | ~30 sec |
| [Fly.io](#option-1-flyio) | Teams, production | ~2 min |
| [Railway](#option-2-railway) | Quick prototyping | ~1 min |
| [Docker Compose](#option-3-docker-compose) | Self-hosted, air-gapped | ~2 min |

---

## Deploy Buttons

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.app/template/arbiter?referralCode=arbiter)

> **Fly.io:** Run `fly launch --config deploy/fly.toml` from a clone of this repo.
> Railway template registration pending. Use the CLI workflow below in the meantime.

---

## Option 0: Binary Install

The fastest path. Downloads a pre-built binary with SHA256 verification.

```bash
curl -sSf https://raw.githubusercontent.com/cyrenei/arbiter-mcp-firewall/main/install.sh | sh
```

Then configure and run:

```bash
cp deploy/arbiter.toml ./arbiter.toml
# Edit arbiter.toml: set upstream_url, api_key, and signing_secret
arbiter --config arbiter.toml
```

Pin a specific version with `ARBITER_VERSION=v0.5.0` or change the install directory with `ARBITER_INSTALL_DIR=/usr/local/bin`.

---

## Option 1: Fly.io

Recommended for teams running production workloads. Deploys to edge infrastructure with TLS, health checks, and autoscaling.

```bash
# 1. Launch the app (builds from Dockerfile)
fly launch --config deploy/fly.toml

# 2. Set your secrets
fly secrets set ARBITER_UPSTREAM_URL=https://your-mcp-server.example.com \
               ARBITER_ADMIN_API_KEY=your-secure-admin-key

```

### Verify it works

```bash
curl https://my-arbiter-proxy.fly.dev/health
# Expected: 200 OK
```

### Notes

- Edit `deploy/fly.toml` to change the app name and region before launching.
- The admin API (port 9090) is exposed over TLS. Restrict access using `fly ips private` or Fly.io private networking for production.
- Scale with `fly scale count 2` for high availability.

---

## Option 2: Railway

Fastest path from zero to running. Railway auto-detects the Dockerfile and provisions infrastructure.

```bash
# 1. Deploy (from the repo root)
railway up

# 2. Set environment variables in the Railway dashboard:
#    ARBITER_UPSTREAM_URL = https://your-mcp-server.example.com
#    ARBITER_ADMIN_API_KEY = your-secure-admin-key
```

Or click the **Deploy on Railway** button above and configure variables in the UI.

### Verify it works

```bash
curl https://your-app.up.railway.app/health
# Expected: 200 OK
```

### Notes

- Railway reads `deploy/railway.json` for build and deploy configuration.
- Environment variables are set in the Railway dashboard under your service settings.
- Railway provides automatic TLS and a public URL.

---

## Option 3: Docker Compose

Best for self-hosted environments, local development, or air-gapped networks.

```bash
# 1. Copy the starter config and edit to taste
cp deploy/arbiter.toml ./arbiter.toml
# Edit arbiter.toml: set upstream_url, api_key, and signing_secret

# 2. Start Arbiter
docker compose -f deploy/docker-compose.quickstart.yml up -d

# 3. (Optional) Build from source instead of pulling the image
docker compose -f deploy/docker-compose.quickstart.yml up -d --build
```

### Environment variables

Set these in your shell or in a `.env` file next to `docker-compose.quickstart.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_URL` | `http://host.docker.internal:3001` | Upstream MCP server |
| `ADMIN_KEY` | `changeme` | Admin API authentication key |

### Verify it works

```bash
curl http://localhost:8080/health
# Expected: 200 OK
```

### Notes

- The quickstart compose file uses `ghcr.io/cyrenei/arbiter:latest` by default. Add `--build` to build from source instead.
- Mount your own `arbiter.toml` to `/etc/arbiter/config.toml` for custom configuration.
- For production, change the `api_key` and `signing_secret` in `arbiter.toml` and set `ADMIN_KEY` to a secure value.

---

## Configuration Reference

The starter config at `deploy/arbiter.toml` includes sensible defaults:

- **Session enforcement** enabled (`require_session = true`, `strict_mcp = true`)
- **Audit logging** to stdout with PII redaction
- **Default policy**: allow read tools, require Verified trust for writes, deny destructive operations unless Trusted
- **1-hour sessions** with 1000-call budgets
- **Metrics** endpoint at `/metrics` (Prometheus-compatible)

See `arbiter.toml` comments for full documentation of every field. For the complete config schema, see `crates/arbiter/src/config.rs`.

---

## Quick Test: End-to-End

After deploying with any option, run this sequence to verify the full pipeline:

```bash
# Set your endpoint (adjust for your platform)
ARBITER=http://localhost:8080
ADMIN=http://localhost:9090
API_KEY=arbiter-dev-key  # or your production key

# 1. Health check
curl -s $ARBITER/health

# 2. Register an agent
curl -s -X POST $ADMIN/agents \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-agent", "trust_level": "Basic"}'

# 3. Create a session (use the agent_id from step 2)
curl -s -X POST $ADMIN/sessions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "AGENT_ID_HERE", "intent": "read and analyze data"}'

# 4. Make an MCP call through the proxy (use the session_id from step 3)
curl -s -X POST $ARBITER/ \
  -H "Content-Type: application/json" \
  -H "x-arbiter-session: SESSION_ID_HERE" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "query", "arguments": {}}, "id": 1}'
```

If the proxy returns a response from your upstream MCP server, everything is wired correctly.
