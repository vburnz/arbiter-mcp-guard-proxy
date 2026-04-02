# Deployment

Arbiter ships as a single binary or a Docker image. This guide covers all paths, plus production considerations you should address before going live.

## Binary Install (Recommended)

The fastest way to get Arbiter on any Linux or macOS machine:

```bash
$ curl -sSf https://raw.githubusercontent.com/cyrenei/arbiter-mcp-firewall/main/install.sh | sh
```

The installer detects your platform, downloads the correct binary from GitHub Releases, verifies the SHA256 checksum, and installs to `~/.arbiter/bin`. Both `arbiter` (proxy) and `arbiter-ctl` (management CLI) are installed. No sudo required.

On Linux, the installer downloads the statically-linked (musl) binary by default. To force the glibc variant: `ARBITER_LIBC=gnu`.

If [minisign](https://jedisct1.github.io/minisign/) is installed, the script also verifies the release signature for provenance.

To pin a specific version:

```bash
$ ARBITER_VERSION=v0.5.0 curl -sSf https://raw.githubusercontent.com/cyrenei/arbiter-mcp-firewall/main/install.sh | sh
```

To install to a custom directory:

```bash
$ ARBITER_INSTALL_DIR=/usr/local/bin curl -sSf https://raw.githubusercontent.com/cyrenei/arbiter-mcp-firewall/main/install.sh | sh
```

Then run:

```bash
$ arbiter --config arbiter.toml --log-level info
```

## Docker Compose (Recommended for Getting Started)

The included `docker-compose.yml` runs the full stack:

```bash
$ git clone https://github.com/cyrenei/arbiter-mcp-firewall.git
$ cd arbiter
$ docker compose up --build -d
```

This gives you Arbiter (proxy on 8080, admin on 3000), a mock MCP echo server (8081), and Keycloak (9090) as the identity provider. Good for development and evaluation.

## Docker (Production)

The Dockerfile builds a multi-stage Alpine image:

```bash
$ docker build -t arbiter:latest .
$ docker run -d \
  -p 8080:8080 \
  -p 3000:3000 \
  -v /path/to/arbiter.toml:/etc/arbiter/arbiter.toml \
  -v /path/to/policies.toml:/etc/arbiter/policies.toml \
  -v /var/log/arbiter:/var/log/arbiter \
  -e ARBITER_ADMIN_API_KEY=your-production-key \
  -e ARBITER_SIGNING_SECRET=your-signing-secret \
  arbiter:latest \
  --config /etc/arbiter/arbiter.toml
```

The final image is around 8-12 MB (stripped, Alpine-based) and uses `tini` as the init process for proper signal handling.

## Building from Source

```bash
$ cargo build --release
$ ./target/release/arbiter --config arbiter.toml --log-level info
```

For persistent storage, enable the SQLite feature:

```bash
$ cargo build --release --features sqlite
```

## Production Checklist

### Secrets

Never use the default admin API key or signing secret in production.

```bash
export ARBITER_ADMIN_API_KEY="$(openssl rand -base64 32)"
export ARBITER_SIGNING_SECRET="$(openssl rand -base64 32)"
```

Arbiter emits startup warnings if it detects the compiled defaults are still in use. Take those warnings seriously.

### TLS Termination

Arbiter doesn't terminate TLS itself. Put it behind a reverse proxy that does:

- **nginx:** straightforward, well-documented
- **Caddy.** Automatic HTTPS with Let's Encrypt
- **Cloud load balancer:** AWS ALB, GCP Load Balancer, Azure Application Gateway

```text
Client ──TLS──> nginx/Caddy ──HTTP──> Arbiter :8080
                                       Arbiter :3000
```

### Admin API Access Control

The admin API on port 3000 controls agent registration, token issuance, policy management, and session creation. Restrict access:

- Bind to `127.0.0.1` if only local services need it:
  ```toml
  [admin]
  listen_addr = "127.0.0.1"
  ```
- Use network-level controls (security groups, firewall rules) to limit which hosts can reach port 3000
- The API key is the only authentication, so treat it like a root credential

### Audit Log Rotation

Audit logs grow without bound. Set up log rotation:

```text
/var/log/arbiter/audit.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

If you're using hash-chained audit, be aware that rotation breaks the chain across files. Verify each rotated file independently, or export to an external system for continuous chain verification.

### Storage Backend

The default in-memory backend loses all state on restart. For production, either:

- Accept ephemeral state (agents and sessions are re-created by your orchestration layer on restart)
- Enable SQLite for persistence:
  ```toml
  [storage]
  backend = "sqlite"
  sqlite_path = "/var/lib/arbiter/arbiter.db"
  ```
  SQLite runs in WAL mode with auto-migration. Back up the database file regularly.

### Resource Limits

Set container resource limits appropriate to your traffic:

```yaml
# docker-compose.yml
services:
  arbiter:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '2.0'
```

Arbiter's memory footprint is modest. The main concern is the audit log buffer and the in-memory store growing with agent/session count.

## Ports

| Port | Service | Protocol |
|------|---------|----------|
| 8080 | Proxy | HTTP (MCP traffic) |
| 3000 | Admin API | HTTP (management) |

Keep these on separate network segments if possible. The proxy faces agent traffic; the admin API should only be accessible to operators and CI.

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `ARBITER_ADMIN_API_KEY` | Admin API authentication | Yes (production) |
| `ARBITER_SIGNING_SECRET` | JWT signing for agent tokens | Yes (production) |
| `ARBITER_CRED_*` | Credential injection (env provider) | If using env credential provider |

## Next Steps

- {doc}`monitoring`: Prometheus, Grafana, and alerting for production
- {doc}`troubleshooting`: diagnosing common issues
- {doc}`../reference/configuration`: full configuration reference
