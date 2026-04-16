#!/bin/sh
# Arbiter configuration wizard — generates arbiter.toml interactively.
#
# Usage:
#   ./configure.sh                     # interactive mode
#   ./configure.sh --output my.toml    # write to a specific file
#   ./configure.sh --non-interactive   # use all defaults (for CI)
#
# This script asks what you know and generates what you shouldn't
# have to think about. It produces a working, secure config file.

set -eu

# ── Defaults ───────────────────────────────────────────────────────────
OUTPUT_FILE="arbiter.toml"
NON_INTERACTIVE=false
UPSTREAM_URL=""
PROXY_PORT=8080
ADMIN_PORT=3000
AUDIT_FILE=""
STORAGE_BACKEND="memory"
SQLITE_PATH="arbiter.db"
INCLUDE_OAUTH=false
INCLUDE_CREDENTIALS=false
COMPLIANCE_TEMPLATE=""
SETUP_MODE="quick"

# ── Argument parsing ───────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            shift
            OUTPUT_FILE="$1"
            ;;
        --non-interactive)
            NON_INTERACTIVE=true
            ;;
        --upstream)
            shift
            UPSTREAM_URL="$1"
            ;;
        -h|--help)
            printf "Usage: %s [--output FILE] [--non-interactive] [--upstream URL]\n" "$0"
            printf "\nGenerates an arbiter.toml configuration file.\n"
            printf "\nOptions:\n"
            printf "  --output FILE        Write config to FILE (default: arbiter.toml)\n"
            printf "  --non-interactive    Use defaults for everything (for CI/automation)\n"
            printf "  --upstream URL       Set the upstream MCP server URL\n"
            exit 0
            ;;
        *)
            printf "Unknown option: %s\n" "$1" >&2
            exit 1
            ;;
    esac
    shift
done

# ── Helpers ────────────────────────────────────────────────────────────

# Bold/color only when stdout is a terminal.
if [ -t 1 ]; then
    BOLD='\033[1m'
    DIM='\033[2m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    CYAN='\033[36m'
    RESET='\033[0m'
else
    BOLD='' DIM='' GREEN='' YELLOW='' CYAN='' RESET=''
fi

header() {
    printf "\n${BOLD}${CYAN}%s${RESET}\n" "$1"
}

info() {
    printf "${DIM}  %s${RESET}\n" "$1"
}

ask() {
    # ask "prompt" "default" -> sets REPLY
    local _prompt="$1" _default="${2:-}"
    if [ -n "$_default" ]; then
        printf "\n  %s ${DIM}[%s]${RESET}: " "$_prompt" "$_default"
    else
        printf "\n  %s: " "$_prompt"
    fi
    read -r REPLY </dev/tty || REPLY=""
    REPLY="${REPLY:-$_default}"
}

ask_yn() {
    # ask_yn "prompt" "y|n" -> sets REPLY to y or n
    local _prompt="$1" _default="${2:-n}"
    if [ "$_default" = "y" ]; then
        printf "\n  %s ${DIM}[Y/n]${RESET}: " "$_prompt"
    else
        printf "\n  %s ${DIM}[y/N]${RESET}: " "$_prompt"
    fi
    read -r REPLY </dev/tty || REPLY=""
    REPLY="${REPLY:-$_default}"
    case "$REPLY" in
        [yY]|[yY][eE][sS]) REPLY="y" ;;
        *) REPLY="n" ;;
    esac
}

generate_secret() {
    # Generate a cryptographically random secret (44 chars, base64, URL-safe).
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d '\n'
    elif [ -r /dev/urandom ]; then
        dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n/+=' | head -c 44
    else
        # Last resort: timestamp + PID. Not cryptographic, but won't
        # leave the user stuck with the default dev key.
        printf "arbiter-%s-%s-%s" "$(date +%s)" "$$" "$(id -u)" | sha256sum 2>/dev/null | awk '{print $1}' || {
            printf "arbiter-generated-%s-%s" "$(date +%s)" "$$"
        }
    fi
}

validate_url() {
    local _url="$1"
    case "$_url" in
        http://*|https://*) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Banner ─────────────────────────────────────────────────────────────
printf "\n${BOLD}Arbiter Configuration Wizard${RESET}\n"
printf "Generates a working arbiter.toml for your environment.\n"
printf "Press Enter to accept defaults shown in ${DIM}[brackets]${RESET}.\n"

# ── Non-interactive mode ───────────────────────────────────────────────
if [ "$NON_INTERACTIVE" = true ]; then
    UPSTREAM_URL="${UPSTREAM_URL:-http://127.0.0.1:8081}"
    API_KEY="$(generate_secret)"
    SIGNING_SECRET="$(generate_secret)"
    printf "\nGenerating config with defaults...\n"
    # Skip to file generation
else

# ── Step 1: The one thing you definitely know ──────────────────────────
header "1. Your MCP server"
info "This is the server Arbiter will protect. All agent traffic"
info "gets proxied through Arbiter to this URL."

if [ -z "$UPSTREAM_URL" ]; then
    while true; do
        ask "Upstream MCP server URL" "http://127.0.0.1:8081"
        UPSTREAM_URL="$REPLY"
        if validate_url "$UPSTREAM_URL"; then
            break
        fi
        printf "  ${YELLOW}URL must start with http:// or https://${RESET}\n"
    done
fi

# ── Step 2: Security secrets (generated, not typed) ───────────────────
header "2. Security"
info "Arbiter needs two secrets: an admin API key and a token signing"
info "secret. These are generated automatically. You can override them"
info "later with environment variables."

API_KEY="$(generate_secret)"
SIGNING_SECRET="$(generate_secret)"
printf "\n  ${GREEN}Admin API key:${RESET}    generated (44 chars)\n"
printf "  ${GREEN}Signing secret:${RESET}   generated (44 chars)\n"
info "These will be written to your config file."
info "For production, set ARBITER_ADMIN_API_KEY and ARBITER_SIGNING_SECRET"
info "as environment variables instead of storing them in the file."

# ── Step 3: Quick or detailed? ────────────────────────────────────────
header "3. Setup mode"
ask_yn "Use quick setup with sensible defaults?" "y"
if [ "$REPLY" = "n" ]; then
    SETUP_MODE="detailed"
fi

if [ "$SETUP_MODE" = "detailed" ]; then

    # ── Ports ──────────────────────────────────────────────────────────
    header "4. Network"
    ask "Proxy port (agents connect here)" "8080"
    PROXY_PORT="$REPLY"
    ask "Admin API port (you manage Arbiter here)" "3000"
    ADMIN_PORT="$REPLY"

    if [ "$PROXY_PORT" = "$ADMIN_PORT" ]; then
        printf "  ${YELLOW}Warning: proxy and admin ports are the same. Changing admin to %s.${RESET}\n" "$((ADMIN_PORT + 1))"
        ADMIN_PORT=$((ADMIN_PORT + 1))
    fi

    # ── Audit ──────────────────────────────────────────────────────────
    header "5. Audit logging"
    info "Arbiter logs every tool call decision. You can write these"
    info "to a file for forensic review."
    ask_yn "Write audit log to a file?" "n"
    if [ "$REPLY" = "y" ]; then
        ask "Audit log file path" "/var/log/arbiter/audit.jsonl"
        AUDIT_FILE="$REPLY"
    fi

    # ── Storage ────────────────────────────────────────────────────────
    header "6. Storage"
    info "In-memory storage is fine for development. SQLite persists"
    info "sessions across restarts (recommended for production)."
    ask_yn "Use SQLite for persistent storage?" "n"
    if [ "$REPLY" = "y" ]; then
        STORAGE_BACKEND="sqlite"
        ask "SQLite database path" "arbiter.db"
        SQLITE_PATH="$REPLY"
    fi

    # ── Compliance template ────────────────────────────────────────────
    header "7. Compliance template (optional)"
    info "Pre-built policy templates for common compliance frameworks."
    info "These add policies on top of the default read/write/admin rules."
    printf "\n  1) None (default policies only)\n"
    printf "  2) SOC 2\n"
    printf "  3) HIPAA\n"
    printf "  4) PCI-DSS\n"
    printf "  5) EU AI Act\n"
    ask "Choose a template" "1"
    case "$REPLY" in
        2) COMPLIANCE_TEMPLATE="soc2" ;;
        3) COMPLIANCE_TEMPLATE="hipaa" ;;
        4) COMPLIANCE_TEMPLATE="pci-dss" ;;
        5) COMPLIANCE_TEMPLATE="eu-ai-act" ;;
        *) COMPLIANCE_TEMPLATE="" ;;
    esac

    # ── OAuth ──────────────────────────────────────────────────────────
    header "8. OAuth / JWT validation (optional)"
    info "If your agents present JWTs from an identity provider (Keycloak,"
    info "Auth0, Okta), Arbiter can validate them."
    ask_yn "Configure OAuth now?" "n"
    INCLUDE_OAUTH="$REPLY"

    if [ "$INCLUDE_OAUTH" = "y" ]; then
        ask "OAuth issuer name (e.g., keycloak, auth0)" "keycloak"
        OAUTH_NAME="$REPLY"
        ask "Issuer URL" ""
        OAUTH_ISSUER_URL="$REPLY"
        ask "JWKS URI" ""
        OAUTH_JWKS_URI="$REPLY"
        ask "Audience (comma-separated if multiple)" "arbiter-api"
        OAUTH_AUDIENCES="$REPLY"
    fi

fi # end detailed mode

fi # end interactive check


# ── Generate config ────────────────────────────────────────────────────
printf "\n${BOLD}Generating %s...${RESET}\n" "$OUTPUT_FILE"

# Build the TOML content
cat > "$OUTPUT_FILE" << TOML_EOF
# Arbiter Configuration
# Generated by configure.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")
#
# Start Arbiter with:
#   arbiter --config ${OUTPUT_FILE}
#
# For production, set secrets as environment variables instead of
# storing them in this file:
#   export ARBITER_ADMIN_API_KEY="your-key"
#   export ARBITER_SIGNING_SECRET="your-secret"


# ── Proxy ──────────────────────────────────────────────────────────────
# The proxy sits between AI agents and your MCP server.
# All traffic flows through Arbiter's middleware chain before reaching
# the upstream.

[proxy]
listen_addr = "0.0.0.0"
listen_port = ${PROXY_PORT}
upstream_url = "${UPSTREAM_URL}"

# Require a valid session on every MCP request.
require_session = true
# Reject non-JSON-RPC POST bodies.
strict_mcp = true
# Block non-POST methods (MCP is POST-only).
deny_non_post_methods = true


# ── Admin API ──────────────────────────────────────────────────────────
# Separate port for managing agents, sessions, and tokens.
# Keep this port internal / behind a firewall in production.

[admin]
listen_addr = "0.0.0.0"
listen_port = ${ADMIN_PORT}

# API key for admin endpoints. Override with ARBITER_ADMIN_API_KEY env var.
api_key = "${API_KEY}"
# HMAC secret for signing agent JWTs. Override with ARBITER_SIGNING_SECRET env var.
signing_secret = "${SIGNING_SECRET}"
# Agent tokens expire after 1 hour.
token_expiry_secs = 3600


# ── Sessions ───────────────────────────────────────────────────────────
# Every agent works inside a time-limited, budget-capped session.

[sessions]
default_time_limit_secs = 3600
default_call_budget = 1000
# Hard-block when drift detection fires (set false for advisory-only mode).
escalate_anomalies = true


# ── Audit ──────────────────────────────────────────────────────────────
# Structured logging of every tool call decision.

[audit]
enabled = true
# Deny traffic when audit logging is broken (prevents blind-spot attacks).
require_healthy = true
# BLAKE3 hash-chained records for tamper detection.
hash_chain = true
TOML_EOF

# Audit file path (only if set)
if [ -n "$AUDIT_FILE" ]; then
    cat >> "$OUTPUT_FILE" << TOML_EOF
file_path = "${AUDIT_FILE}"
TOML_EOF
fi

# Redaction patterns
cat >> "$OUTPUT_FILE" << 'TOML_EOF'
redaction_patterns = ["password", "secret", "token", "key", "authorization", "credential", "ssn", "credit_card"]


# ── Metrics ────────────────────────────────────────────────────────────
# Prometheus-compatible /metrics endpoint on the proxy port.

[metrics]
enabled = true


TOML_EOF

# Storage section
cat >> "$OUTPUT_FILE" << TOML_EOF
# ── Storage ────────────────────────────────────────────────────────────

[storage]
backend = "${STORAGE_BACKEND}"
TOML_EOF

if [ "$STORAGE_BACKEND" = "sqlite" ]; then
    cat >> "$OUTPUT_FILE" << TOML_EOF
sqlite_path = "${SQLITE_PATH}"
TOML_EOF
fi

# OAuth section
if [ "$INCLUDE_OAUTH" = "y" ]; then
    # Format audiences as TOML array
    _audiences_toml=""
    _first=true
    IFS=',' read -r _aud_rest <<EOF
$OAUTH_AUDIENCES
EOF
    # Simple approach: split on comma, build array
    _audiences_toml="["
    _remaining="$OAUTH_AUDIENCES"
    while [ -n "$_remaining" ]; do
        _item="${_remaining%%,*}"
        _item="$(printf '%s' "$_item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ "$_audiences_toml" != "[" ]; then
            _audiences_toml="${_audiences_toml}, "
        fi
        _audiences_toml="${_audiences_toml}\"${_item}\""
        case "$_remaining" in
            *,*) _remaining="${_remaining#*,}" ;;
            *)   _remaining="" ;;
        esac
    done
    _audiences_toml="${_audiences_toml}]"

    cat >> "$OUTPUT_FILE" << TOML_EOF


# ── OAuth ──────────────────────────────────────────────────────────────

[oauth]
jwks_cache_ttl_secs = 3600

[[oauth.issuers]]
name = "${OAUTH_NAME}"
issuer_url = "${OAUTH_ISSUER_URL}"
jwks_uri = "${OAUTH_JWKS_URI}"
audiences = ${_audiences_toml}
TOML_EOF
fi

# Policy section (always include sensible defaults)
cat >> "$OUTPUT_FILE" << 'TOML_EOF'


# ── Policy Engine ──────────────────────────────────────────────────────
# Deny-by-default. If no policy matches a tool call, it's blocked.
# Rules are evaluated by specificity: most specific match wins.

# Allow common read/query tools for any agent.
[[policy.policies]]
id = "allow-read-tools"
effect = "allow"
allowed_tools = [
    "read_file",
    "list_dir",
    "search",
    "query",
    "get_status",
    "describe",
    "list_tools",
]
[policy.policies.intent_match]
keywords = ["read", "analyze", "review", "query", "search"]

# Allow write tools for Verified agents only.
[[policy.policies]]
id = "allow-write-for-verified"
effect = "allow"
allowed_tools = [
    "write_file",
    "create",
    "update",
    "modify",
    "deploy",
]
[policy.policies.agent_match]
trust_level = "verified"

# Deny destructive operations unless Trusted.
[[policy.policies]]
id = "deny-destructive-unless-trusted"
effect = "deny"
allowed_tools = [
    "delete",
    "drop",
    "truncate",
    "create_admin",
    "delete_audit_logs",
    "modify_permissions",
]

# Allow destructive operations for Trusted agents.
[[policy.policies]]
id = "allow-destructive-for-trusted"
effect = "allow"
allowed_tools = [
    "delete",
    "drop",
    "truncate",
    "create_admin",
    "delete_audit_logs",
    "modify_permissions",
]
[policy.policies.agent_match]
trust_level = "trusted"
TOML_EOF

# Compliance template hint
if [ -n "$COMPLIANCE_TEMPLATE" ]; then
    cat >> "$OUTPUT_FILE" << TOML_EOF

# ── Compliance ─────────────────────────────────────────────────────────
# You selected the ${COMPLIANCE_TEMPLATE} compliance template.
# To load it, download the template and set it as a policy file:
#
#   [policy]
#   file = "templates/${COMPLIANCE_TEMPLATE}.toml"
#   watch = true
#
# Templates are available at:
#   https://github.com/cyrenei/arbiter-mcp-firewall/tree/main/templates
TOML_EOF
fi

# ── Summary ────────────────────────────────────────────────────────────
printf "\n${GREEN}${BOLD}Done.${RESET} Config written to ${BOLD}%s${RESET}\n" "$OUTPUT_FILE"
printf "\n${BOLD}What's in it:${RESET}\n"
printf "  Proxy:     0.0.0.0:%s -> %s\n" "$PROXY_PORT" "$UPSTREAM_URL"
printf "  Admin API: 0.0.0.0:%s\n" "$ADMIN_PORT"
printf "  Audit:     enabled"
if [ -n "$AUDIT_FILE" ]; then
    printf " -> %s" "$AUDIT_FILE"
fi
printf "\n"
printf "  Storage:   %s" "$STORAGE_BACKEND"
if [ "$STORAGE_BACKEND" = "sqlite" ]; then
    printf " (%s)" "$SQLITE_PATH"
fi
printf "\n"
printf "  Policies:  4 default rules (read/write/destructive by trust level)\n"
if [ -n "$COMPLIANCE_TEMPLATE" ]; then
    printf "  Compliance: %s template (see config for setup instructions)\n" "$COMPLIANCE_TEMPLATE"
fi
if [ "$INCLUDE_OAUTH" = "y" ]; then
    printf "  OAuth:     %s\n" "$OAUTH_NAME"
fi

printf "\n${BOLD}Start Arbiter:${RESET}\n"
printf "  arbiter --config %s\n" "$OUTPUT_FILE"

printf "\n${BOLD}Quick test:${RESET}\n"
printf "  curl http://localhost:%s/health\n" "$PROXY_PORT"

printf "\n${BOLD}Register your first agent:${RESET}\n"
printf "  curl -X POST http://localhost:%s/agents \\\\\n" "$ADMIN_PORT"
printf "    -H \"x-api-key: \$ARBITER_ADMIN_API_KEY\" \\\\\n"
printf "    -H \"Content-Type: application/json\" \\\\\n"
printf "    -d '{\"owner\":\"user:you\",\"model\":\"your-model\",\"capabilities\":[\"read\"],\"trust_level\":\"basic\"}'\n"

printf "\n${DIM}Tip: for production, move secrets to environment variables:${RESET}\n"
printf "${DIM}  export ARBITER_ADMIN_API_KEY=\"%s\"${RESET}\n" "$API_KEY"
printf "${DIM}  export ARBITER_SIGNING_SECRET=\"%s\"${RESET}\n" "$SIGNING_SECRET"
printf "${DIM}  Then remove them from %s.${RESET}\n" "$OUTPUT_FILE"
printf "\n"
