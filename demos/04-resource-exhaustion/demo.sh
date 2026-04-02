#!/usr/bin/env bash
set -euo pipefail

# ── Demo 04: Resource Exhaustion ─────────────────────────────────────
# Attack: Exhaust session call budget and rate limit.
# Expected: 429 SESSION_INVALID after budget/rate exceeded

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
echo -e "${BOLD}  DEMO 04: Resource Exhaustion${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Exhaust a session's call budget (5 calls) and rate limit"
echo "  Config: call_budget = 5, rate_limit_per_minute = 3"
echo "  Expected: 429 after limits exceeded"
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
    "owner": "user:demo-exhaust",
    "model": "test-model",
    "capabilities": ["read"],
    "trust_level": "basic"
  }')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID: $AGENT_ID"

# ── Part A: Rate limit (3 calls/min) ────────────────────────────────
echo ""
echo -e "${BOLD}── PART A: Rate Limit Exhaustion (3 calls/minute) ──${NC}"
echo ""

SESSION_A=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"read project files\",
    \"authorized_tools\": [\"read_file\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100,
    \"rate_limit_per_minute\": 3
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

echo "  Session: $SESSION_A (rate_limit_per_minute: 3, budget: 100)"
echo ""

for i in 1 2 3 4; do
  RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-agent-id: $AGENT_ID" \
    -H "x-arbiter-session: $SESSION_A" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": $i,
      \"method\": \"tools/call\",
      \"params\": {
        \"name\": \"read_file\",
        \"arguments\": {\"path\": \"/file-$i.txt\"}
      }
    }")

  HTTP=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)

  if [ "$HTTP" = "429" ]; then
    BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')
    echo -e "  Call $i: ${RED}429 RATE LIMITED${NC}"
    echo ""
    echo "  Response:"
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
  elif [ "$HTTP" = "200" ] || [ "$HTTP" = "502" ]; then
    echo -e "  Call $i: ${GREEN}OK${NC} (passed rate check)"
  else
    echo -e "  Call $i: ${YELLOW}$HTTP${NC}"
  fi
done

echo ""

# ── Part B: Budget exhaustion (5 calls total) ────────────────────────
echo -e "${BOLD}── PART B: Budget Exhaustion (5 calls total) ──${NC}"
echo ""

SESSION_B=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"read project files\",
    \"authorized_tools\": [\"read_file\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 5
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

echo "  Session: $SESSION_B (budget: 5, no rate limit)"
echo ""

for i in 1 2 3 4 5 6; do
  RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-agent-id: $AGENT_ID" \
    -H "x-arbiter-session: $SESSION_B" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": $i,
      \"method\": \"tools/call\",
      \"params\": {
        \"name\": \"read_file\",
        \"arguments\": {\"path\": \"/file-$i.txt\"}
      }
    }")

  HTTP=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)

  if [ "$HTTP" = "429" ]; then
    BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')
    echo -e "  Call $i: ${RED}429 BUDGET EXHAUSTED${NC}"
    echo ""
    echo "  Response:"
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
  elif [ "$HTTP" = "200" ] || [ "$HTTP" = "502" ]; then
    echo -e "  Call $i: ${GREEN}OK${NC} ($i/5 budget used)"
  else
    echo -e "  Call $i: ${YELLOW}$HTTP${NC}"
  fi
done

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  Sessions enforce two resource limits: call budget (total calls"
echo "  over the session lifetime) and rate limit (calls per minute)."
echo "  When either is exceeded, Arbiter returns 429. This prevents"
echo "  runaway agents from consuming unbounded upstream resources,"
echo "  whether through a loop, a prompt injection, or intentional abuse."
echo ""
