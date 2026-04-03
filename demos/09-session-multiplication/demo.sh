#!/usr/bin/env bash
set -euo pipefail

# ── Demo 09: Session Multiplication ──────────────────────────────────
# Attack: Open many concurrent sessions to bypass per-session rate limits.
# Expected: First 10 sessions succeed, 11th returns 429

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
echo -e "${BOLD}  DEMO 09: Session Multiplication${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Open 15 concurrent sessions (each with 1000-call budget)"
echo "  Config: max_concurrent_sessions_per_agent = 10"
echo "  Expected: First 10 succeed, sessions 11-15 rejected with 429"
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
    "owner": "user:demo-multiply",
    "model": "test-model",
    "capabilities": ["read"],
    "trust_level": "basic"
  }')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID: $AGENT_ID"
echo ""

# ── Attack: Create 15 sessions ──────────────────────────────────────
echo -e "${BOLD}── ATTACK: Create 15 concurrent sessions (cap = 10) ──${NC}"
echo ""

for i in $(seq 1 15); do
  RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$ADMIN/sessions" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{
      \"agent_id\": \"$AGENT_ID\",
      \"declared_intent\": \"read project files batch $i\",
      \"authorized_tools\": [\"read_file\"],
      \"time_limit_secs\": 3600,
      \"call_budget\": 1000
    }")

  HTTP=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
  BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')

  if [ "$HTTP" = "200" ] || [ "$HTTP" = "201" ]; then
    SESSION_ID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null || echo "unknown")
    printf "  Session %2d: ${GREEN}%s OK${NC} (budget: 1000)\n" "$i" "$HTTP"
  elif [ "$HTTP" = "429" ]; then
    printf "  Session %2d: ${RED}429 (too many concurrent sessions)${NC}\n" "$i"
    if [ "$i" = "11" ]; then
      echo ""
      echo "  Response:"
      echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
    fi
  else
    printf "  Session %2d: ${YELLOW}%s${NC}\n" "$i" "$HTTP"
  fi
done

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  Without the per-agent session cap, a compromised agent could open"
echo "  100 sessions with 1000-call budgets, granting itself 100,000 total"
echo "  calls -- effectively bypassing per-session rate limits."
echo ""
echo "  max_concurrent_sessions_per_agent (default: 10) caps the number of"
echo "  active sessions per agent. Once the cap is reached, new session"
echo "  creation returns 429. The agent's total effective"
echo "  budget is bounded to cap x per-session budget."
echo ""
