#!/usr/bin/env bash
set -euo pipefail

# ── Demo 03: Tool Escalation ─────────────────────────────────────────
# Attack: Agent has session for ["read_file", "list_dir"], tries delete_file.
# Expected: 403 SESSION_INVALID (tool not in authorized set)

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
echo -e "${BOLD}  DEMO 03: Tool Escalation${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Agent authorized for [read_file, list_dir] tries delete_file"
echo "  Config: Session with tool whitelist"
echo "  Expected: 403 SESSION_INVALID"
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

# ── Setup: Register agent and create session ─────────────────────────
echo -e "${BOLD}── SETUP: Register agent and create scoped session ──${NC}"
echo ""

REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:demo-reader",
    "model": "test-model",
    "capabilities": ["read"],
    "trust_level": "basic"
  }')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID: $AGENT_ID"

SESSION_RESP=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"read and list project files\",
    \"authorized_tools\": [\"read_file\", \"list_dir\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100
  }")

SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
echo "  Session ID: $SESSION_ID"
echo "  Authorized tools: [read_file, list_dir]"
echo ""

# ── Legitimate: read_file (should pass session check) ────────────────
echo -e "${BOLD}── LEGITIMATE: read_file (authorized tool) ──${NC}"
echo ""

RESP1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {"path": "/src/main.rs"}
    }
  }')

HTTP_1=$(echo "$RESP1" | grep "HTTP_STATUS:" | cut -d: -f2)

echo "  HTTP Status: $HTTP_1"
if [ "$HTTP_1" = "200" ] || [ "$HTTP_1" = "502" ]; then
  echo -e "  ${GREEN}PASSED${NC} - Session check passed (tool is authorized)"
  echo "  (502 is expected since no upstream server is running)"
else
  echo "  Status: $HTTP_1"
fi
echo ""

# ── Attack: delete_file (not in whitelist) ───────────────────────────
echo -e "${BOLD}── ATTACK: delete_file (not in authorized set) ──${NC}"
echo ""

RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "delete_file",
      "arguments": {"path": "/etc/passwd"}
    }
  }')

HTTP_2=$(echo "$RESP2" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_2=$(echo "$RESP2" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_2"
echo ""

if [ "$HTTP_2" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Tool not in session's authorized set"
  echo ""
  echo "  Response:"
  echo "$BODY_2" | python3 -m json.tool 2>/dev/null || echo "$BODY_2"
else
  echo -e "  ${YELLOW}Unexpected status $HTTP_2 (expected 403)${NC}"
  echo "$BODY_2"
fi

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  Sessions are created with an explicit authorized_tools whitelist."
echo "  When the agent tries to call delete_file, Arbiter checks the"
echo "  session's whitelist and finds that only [read_file, list_dir]"
echo "  are permitted. The request is denied with SESSION_INVALID before"
echo "  it ever reaches the upstream server."
echo ""
