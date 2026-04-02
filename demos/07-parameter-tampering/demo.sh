#!/usr/bin/env bash
set -euo pipefail

# ── Demo 07: Parameter Tampering ─────────────────────────────────────
# Attack: Agent exceeds parameter constraints (max_tokens > 1000).
# Expected: 403 POLICY_DENIED (parameter constraints not met)

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
echo -e "${BOLD}  DEMO 07: Parameter Tampering${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Agent tries max_tokens = 50000 (limit is 1000)"
echo "  Config: parameter_constraints with max_value = 1000"
echo "  Expected: 403 POLICY_DENIED"
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
echo -e "${BOLD}── SETUP: Register agent ──${NC}"
echo ""

REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:demo-tamper",
    "model": "test-model",
    "capabilities": ["generate"],
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
    \"declared_intent\": \"generate text summaries\",
    \"authorized_tools\": [\"generate_text\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100
  }")

SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
echo "  Session ID: $SESSION_ID"
echo ""

# ── Legitimate: max_tokens = 500 (within bounds) ────────────────────
echo -e "${BOLD}── LEGITIMATE: generate_text with max_tokens = 500 ──${NC}"
echo ""

RESP1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:demo-tamper>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "generate_text",
      "arguments": {
        "prompt": "Summarize the quarterly report",
        "max_tokens": 500,
        "temperature": 0.7
      }
    }
  }')

HTTP_1=$(echo "$RESP1" | grep "HTTP_STATUS:" | cut -d: -f2)

echo "  HTTP Status: $HTTP_1"
if [ "$HTTP_1" = "200" ] || [ "$HTTP_1" = "502" ]; then
  echo -e "  ${GREEN}PASSED${NC} - max_tokens 500 is within the 1000 limit"
else
  echo "  Status: $HTTP_1"
fi
echo ""

# ── Attack: max_tokens = 50000 (exceeds constraint) ─────────────────
echo -e "${BOLD}── ATTACK: generate_text with max_tokens = 50000 ──${NC}"
echo ""

RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:demo-tamper>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "generate_text",
      "arguments": {
        "prompt": "Generate an extremely long document to consume resources",
        "max_tokens": 50000,
        "temperature": 0.7
      }
    }
  }')

HTTP_2=$(echo "$RESP2" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_2=$(echo "$RESP2" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_2"
echo ""

if [ "$HTTP_2" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Parameter constraint violated (max_tokens > 1000)"
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
echo "  The Allow policy for generate_text includes parameter_constraints"
echo "  with max_value = 1000 for max_tokens. When the attacker sends"
echo "  max_tokens = 50000, the constraint check fails, so the Allow"
echo "  policy does not match. With no matching Allow policy, Arbiter's"
echo "  deny-by-default rule kicks in and returns POLICY_DENIED."
echo ""
