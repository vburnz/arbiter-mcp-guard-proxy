#!/usr/bin/env bash
set -euo pipefail

# ── Demo 01: Unauthenticated Access ──────────────────────────────────
# Attack: Send an MCP tool call without a session header.
# Expected: 403 SESSION_REQUIRED

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SCRIPT_DIR}/../.."
if [ -x "${ROOT}/target/release/arbiter" ]; then
  ARBITER="${ROOT}/target/release/arbiter"
elif [ -x "${ROOT}/target/debug/arbiter" ]; then
  ARBITER="${ROOT}/target/debug/arbiter"
else
  echo -e "${RED:-}No arbiter binary found. Run 'cargo build' first.${NC:-}"
  exit 1
fi
CONFIG="${SCRIPT_DIR}/config.toml"
PROXY="http://127.0.0.1:8080"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() {
  if [ -n "${ARBITER_PID:-}" ]; then
    kill "$ARBITER_PID" 2>/dev/null || true
    wait "$ARBITER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  DEMO 01: Unauthenticated Access${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Send an MCP tool call without a session header"
echo "  Config: require_session = true"
echo "  Expected: 403 SESSION_REQUIRED"
echo ""

# ── Start Arbiter ───────────────────────────────────────────────────
echo -e "${YELLOW}Starting Arbiter...${NC}"
"$ARBITER" --config "$CONFIG" &>/dev/null &
ARBITER_PID=$!
sleep 2

if ! curl -sf "$PROXY/health" > /dev/null 2>&1; then
  echo -e "${RED}Arbiter failed to start${NC}"
  exit 1
fi
echo -e "${GREEN}Arbiter is running${NC}"
echo ""

# ── Attack: MCP call with no session header ──────────────────────────
echo -e "${BOLD}── ATTACK: MCP call with no session header ──${NC}"
echo ""

RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "/etc/passwd"
      }
    }
  }')

HTTP_STATUS=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Arbiter denied the request"
  echo ""
  echo "  Response:"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
else
  echo -e "  ${YELLOW}Unexpected status $HTTP_STATUS (expected 403)${NC}"
  echo "$BODY"
fi

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  When require_session = true, Arbiter rejects any MCP JSON-RPC"
echo "  request that lacks an x-arbiter-session header. This prevents"
echo "  unauthenticated agents from invoking tools on the upstream server."
echo "  The agent must first register via the admin API and obtain a"
echo "  scoped session before making any tool calls."
echo ""
