#!/usr/bin/env bash
set -euo pipefail

# ── Demo 02: Protocol Injection ──────────────────────────────────────
# Attack: Send a non-MCP POST body (plain text, raw HTTP) to bypass parsing.
# Expected: 403 NON_MCP_REJECTED

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
echo -e "${BOLD}  DEMO 02: Protocol Injection${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Send a non-MCP POST body to bypass JSON-RPC parsing"
echo "  Config: strict_mcp = true"
echo "  Expected: 403 NON_MCP_REJECTED"
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

# ── Attack 1: Plain text POST ────────────────────────────────────────
echo -e "${BOLD}── ATTACK 1: Plain text POST body ──${NC}"
echo ""

RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: text/plain" \
  -d 'DELETE FROM users WHERE 1=1;')

HTTP_STATUS=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Non-MCP POST rejected"
  echo ""
  echo "  Response:"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
else
  echo -e "  ${YELLOW}Unexpected status $HTTP_STATUS (expected 403)${NC}"
  echo "$BODY"
fi

echo ""

# ── Attack 2: Malformed JSON (not JSON-RPC) ──────────────────────────
echo -e "${BOLD}── ATTACK 2: Malformed JSON (not JSON-RPC 2.0) ──${NC}"
echo ""

RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -d '{"action": "drop_table", "target": "users"}')

HTTP_STATUS2=$(echo "$RESP2" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY2=$(echo "$RESP2" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_STATUS2"
echo ""

if [ "$HTTP_STATUS2" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Non-JSON-RPC POST rejected"
  echo ""
  echo "  Response:"
  echo "$BODY2" | python3 -m json.tool 2>/dev/null || echo "$BODY2"
else
  echo -e "  ${YELLOW}Unexpected status $HTTP_STATUS2 (expected 403)${NC}"
  echo "$BODY2"
fi

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  When strict_mcp = true, Arbiter rejects any POST request whose"
echo "  body is not a valid JSON-RPC 2.0 message. This prevents protocol"
echo "  injection attacks where an attacker sends SQL, shell commands,"
echo "  or arbitrary JSON to the upstream server through the proxy."
echo "  The MCP parser checks for the required \"jsonrpc\": \"2.0\" field."
echo ""
