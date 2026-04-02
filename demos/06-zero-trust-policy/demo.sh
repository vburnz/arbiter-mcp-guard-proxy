#!/usr/bin/env bash
set -euo pipefail

# ── Demo 06: Zero-Trust Policy (Deny-by-Default) ─────────────────────
# Attack: Agent with no matching Allow policy tries to call a tool.
# Expected: 403 POLICY_DENIED

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
echo -e "${BOLD}  DEMO 06: Zero-Trust Policy (Deny-by-Default)${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Unauthorized agent tries to call deploy_service"
echo "  Config: Only user:trusted-team is allowed to deploy"
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

# ── Setup: Register the attacker agent ───────────────────────────────
echo -e "${BOLD}── SETUP: Register attacker agent (user:rogue-contractor) ──${NC}"
echo ""

REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:rogue-contractor",
    "model": "test-model",
    "capabilities": ["read", "deploy"],
    "trust_level": "basic"
  }')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID: $AGENT_ID"
echo "  Owner: user:rogue-contractor"

SESSION_RESP=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"deploy the application to production\",
    \"authorized_tools\": [\"deploy_service\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100
  }")

SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
echo "  Session ID: $SESSION_ID"
echo ""

# ── Attack: Attacker tries deploy_service ────────────────────────────
echo -e "${BOLD}── ATTACK: rogue-contractor tries deploy_service ──${NC}"
echo ""
echo "  Policy requires principal = user:trusted-team"
echo "  Attacker principal = user:rogue-contractor"
echo ""

RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:rogue-contractor>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "deploy_service",
      "arguments": {
        "service": "payment-gateway",
        "environment": "production",
        "version": "9.9.9-backdoor"
      }
    }
  }')

HTTP_STATUS=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')

echo "  HTTP Status: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "403" ]; then
  echo -e "  ${RED}BLOCKED${NC} - No matching Allow policy (deny-by-default)"
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
echo "  Arbiter uses deny-by-default policy evaluation. The only Allow"
echo "  policy for deploy_service requires principal_match.sub ="
echo "  \"user:trusted-team\". The attacker's principal is"
echo "  \"user:rogue-contractor\", so no policy matches, and the request"
echo "  is denied with POLICY_DENIED. The response includes a policy"
echo "  trace showing exactly why each policy was skipped."
echo ""
