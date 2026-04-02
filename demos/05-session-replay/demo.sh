#!/usr/bin/env bash
set -euo pipefail

# ── Demo 05: Session Replay ──────────────────────────────────────────
# Attack: Reuse a session after it has expired or been closed.
# Expected: 408 SESSION_INVALID (expired) / 410 (closed)

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
ADMIN="http://127.0.0.1:3000"
API_KEY="demo-key"

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
echo -e "${BOLD}  DEMO 05: Session Replay${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Reuse a session after expiry or closure"
echo "  Config: time_limit_secs = 3 (very short session)"
echo "  Expected: 408 SESSION_INVALID (expired)"
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

# ── Setup: Register agent ───────────────────────────────────────────
echo -e "${BOLD}── SETUP: Register agent ──${NC}"
echo ""

REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:demo-replay",
    "model": "test-model",
    "capabilities": ["read"],
    "trust_level": "basic"
  }')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID: $AGENT_ID"

# ── Part A: Session expiry ───────────────────────────────────────────
echo ""
echo -e "${BOLD}── PART A: Session Expiry (3-second TTL) ──${NC}"
echo ""

SESSION_A=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"read project files\",
    \"authorized_tools\": [\"read_file\"],
    \"time_limit_secs\": 3,
    \"call_budget\": 100
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

echo "  Session: $SESSION_A (expires in 3 seconds)"
echo ""

# Use session immediately (should work)
RESP1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_A" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {"path": "/readme.txt"}
    }
  }')

HTTP_1=$(echo "$RESP1" | grep "HTTP_STATUS:" | cut -d: -f2)

if [ "$HTTP_1" = "200" ] || [ "$HTTP_1" = "502" ]; then
  echo -e "  Immediate call: ${GREEN}OK${NC} (session is fresh)"
else
  echo -e "  Immediate call: $HTTP_1"
fi

# Wait for expiry
echo ""
echo -e "  ${YELLOW}Waiting 4 seconds for session to expire...${NC}"
sleep 4

# Try again (should fail)
RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_A" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {"path": "/readme.txt"}
    }
  }')

HTTP_2=$(echo "$RESP2" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_2=$(echo "$RESP2" | sed '/HTTP_STATUS:/d')

echo ""
echo "  Replay attempt: HTTP $HTTP_2"
echo ""

if [ "$HTTP_2" = "408" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Session has expired"
  echo ""
  echo "  Response:"
  echo "$BODY_2" | python3 -m json.tool 2>/dev/null || echo "$BODY_2"
else
  echo -e "  ${YELLOW}Status $HTTP_2 (expected 408)${NC}"
  echo "$BODY_2" | python3 -m json.tool 2>/dev/null || echo "$BODY_2"
fi

# ── Part B: Closed session replay ────────────────────────────────────
echo ""
echo -e "${BOLD}── PART B: Closed Session Replay ──${NC}"
echo ""

SESSION_B=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"read project files\",
    \"authorized_tools\": [\"read_file\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

echo "  Session: $SESSION_B"

# Close the session
curl -sf -X POST "$ADMIN/sessions/$SESSION_B/close" \
  -H "x-api-key: $API_KEY" > /dev/null
echo "  Status: closed via admin API"
echo ""

# Try to reuse the closed session
RESP3=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_B" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {"path": "/readme.txt"}
    }
  }')

HTTP_3=$(echo "$RESP3" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_3=$(echo "$RESP3" | sed '/HTTP_STATUS:/d')

echo "  Replay attempt: HTTP $HTTP_3"
echo ""

if [ "$HTTP_3" = "410" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Session has been closed"
  echo ""
  echo "  Response:"
  echo "$BODY_3" | python3 -m json.tool 2>/dev/null || echo "$BODY_3"
else
  echo -e "  ${YELLOW}Status $HTTP_3 (expected 410)${NC}"
  echo "$BODY_3" | python3 -m json.tool 2>/dev/null || echo "$BODY_3"
fi

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  Sessions have a time-to-live (TTL). Once expired, the session ID"
echo "  cannot be reused. Similarly, sessions closed via the admin API"
echo "  return 410 Gone. This prevents replay attacks where a stolen"
echo "  or leaked session ID is used long after the original task ended."
echo ""
