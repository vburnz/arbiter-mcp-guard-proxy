#!/usr/bin/env bash
set -euo pipefail

# ── Demo 08: Intent Drift ────────────────────────────────────────────
# Attack: Session declared with read-only intent, agent tries a write.
# Expected: 403 BEHAVIORAL_ANOMALY

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
echo -e "${BOLD}  DEMO 08: Intent Drift${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Session declares read-only intent, agent calls write_file"
echo "  Config: escalate_anomalies = true"
echo "  Expected: 403 BEHAVIORAL_ANOMALY"
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

# ── Setup: Register agent and create read-only session ───────────────
echo -e "${BOLD}── SETUP: Register agent with read-only intent ──${NC}"
echo ""

REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:demo-drifter",
    "model": "test-model",
    "capabilities": ["read", "write"],
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
    \"declared_intent\": \"read and analyze the source code\",
    \"authorized_tools\": [\"read_file\", \"list_dir\", \"write_file\", \"delete_file\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100
  }")

SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
echo "  Session ID: $SESSION_ID"
echo "  Intent: \"read and analyze the source code\""
echo "  Tools: [read_file, list_dir, write_file, delete_file]"
echo ""
echo -e "  ${YELLOW}Note: Policy allows all four tools. Session allows all four.${NC}"
echo -e "  ${YELLOW}But the declared intent is read-only. Behavior detection${NC}"
echo -e "  ${YELLOW}catches the mismatch at a deeper level.${NC}"
echo ""

# ── Legitimate: read_file (matches read intent) ─────────────────────
echo -e "${BOLD}── LEGITIMATE: read_file (matches read intent) ──${NC}"
echo ""

RESP1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:demo-drifter>$AGENT_ID" \
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
  echo -e "  ${GREEN}PASSED${NC} - read_file matches \"read and analyze\" intent"
else
  echo "  Status: $HTTP_1"
fi
echo ""

# ── Attack: write_file (contradicts read-only intent) ────────────────
echo -e "${BOLD}── ATTACK: write_file (contradicts read-only intent) ──${NC}"
echo ""

RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:demo-drifter>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "write_file",
      "arguments": {
        "path": "/etc/shadow",
        "content": "root::0:0:root:/root:/bin/bash"
      }
    }
  }')

HTTP_2=$(echo "$RESP2" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_2=$(echo "$RESP2" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_2"
echo ""

if [ "$HTTP_2" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - Behavioral anomaly: write in a read-only session"
  echo ""
  echo "  Response:"
  echo "$BODY_2" | python3 -m json.tool 2>/dev/null || echo "$BODY_2"
else
  echo -e "  ${YELLOW}Unexpected status $HTTP_2 (expected 403)${NC}"
  echo "$BODY_2" | python3 -m json.tool 2>/dev/null || echo "$BODY_2"
fi

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  Both the session whitelist and the policy engine allowed write_file."
echo "  But Arbiter's behavioral anomaly detector at Stage 9 classifies"
echo "  the declared intent \"read and analyze\" as read-only. It then"
echo "  classifies write_file as a Write operation. A write in a read-only"
echo "  session is flagged as anomalous. With escalate_anomalies = true,"
echo "  the flag escalates to a hard deny: 403 BEHAVIORAL_ANOMALY."
echo ""
echo "  This is defense in depth: even if policy and session checks pass,"
echo "  the behavior layer catches intent drift at runtime."
echo ""
