#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Arbiter: Docker E2E Verification Suite
# ═══════════════════════════════════════════════════════════════════
#
# Runs all 10 security attack scenarios against containerized Arbiter
# instances. Each test exercises a specific enforcement mechanism
# end-to-end through real container networking.
#
# Environment:
#   ARBITER_PROXY_URL        Proxy for demos 01-09  (default: http://arbiter:8080)
#   ARBITER_ADMIN_URL        Admin for demos 01-09  (default: http://arbiter:3000)
#   ARBITER_DEMO10_PROXY_URL Proxy for demo 10      (default: http://arbiter-demo10:8080)
#   ARBITER_DEMO10_ADMIN_URL Admin for demo 10      (default: http://arbiter-demo10:3000)
#
# Exit code: number of failed assertions (0 = all pass)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────

PROXY="${ARBITER_PROXY_URL:-http://arbiter:8080}"
ADMIN="${ARBITER_ADMIN_URL:-http://arbiter:3000}"
PROXY_10="${ARBITER_DEMO10_PROXY_URL:-http://arbiter-demo10:8080}"
ADMIN_10="${ARBITER_DEMO10_ADMIN_URL:-http://arbiter-demo10:3000}"
API_KEY="demo-key"

PASS=0
FAIL=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ────────────────────────────────────────────────────────

assert_status() {
  local label="$1" expected="$2" actual="$3"
  TOTAL=$((TOTAL + 1))
  if [ "$expected" = "$actual" ]; then
    echo -e "  ${GREEN}PASS${NC}  $label  (HTTP $actual)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}FAIL${NC}  $label  (expected $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

assert_status_any() {
  local label="$1" expected="$2" actual="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$expected" | tr '|' '\n' | grep -qx "$actual"; then
    echo -e "  ${GREEN}PASS${NC}  $label  (HTTP $actual)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}FAIL${NC}  $label  (expected one of $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

http_status() {
  echo "$1" | grep "HTTP_STATUS:" | cut -d: -f2
}

json_field() {
  python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"
}

wait_for_health() {
  local url="$1" label="$2" max="${3:-30}"
  echo -e "${YELLOW}Waiting for $label at $url...${NC}"
  for i in $(seq 1 "$max"); do
    if curl -sf "$url/health" > /dev/null 2>&1; then
      echo -e "${GREEN}$label is ready${NC}"
      return 0
    fi
    sleep 1
  done
  echo -e "${RED}$label failed to respond after ${max}s${NC}"
  return 1
}

# ── Banner ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ARBITER: Docker E2E Verification Suite                     ║${NC}"
echo -e "${BOLD}║  10 attack scenarios / containerized / real enforcement     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Wait for services ──────────────────────────────────────────────
# Health endpoint is on the proxy port only; admin API has no /health.
# Compose depends_on ensures proxy is healthy before test-runner starts,
# but we verify here for safety and clearer output.

wait_for_health "$PROXY"    "Arbiter proxy (demos 01-09)"
wait_for_health "$PROXY_10" "Arbiter proxy (demo 10)"
echo ""

# ═══════════════════════════════════════════════════════════════════
# DEMO 01: Unauthenticated Access
# Attack: MCP tool call without session header
# Expected: 403 SESSION_REQUIRED
# ═══════════════════════════════════════════════════════════════════

test_demo_01() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 01: Unauthenticated Access${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -d '{
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "read_file",
        "arguments": {"path": "/etc/passwd"}
      }
    }')

  assert_status "No session header -> 403 SESSION_REQUIRED" "403" "$(http_status "$RESP")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 02: Protocol Injection
# Attack: Non-MCP POST body (plain text, malformed JSON)
# Expected: 403 NON_MCP_REJECTED
# ═══════════════════════════════════════════════════════════════════

test_demo_02() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 02: Protocol Injection${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Attack 1: Plain text POST
  RESP1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: text/plain" \
    -d 'DELETE FROM users WHERE 1=1;')

  assert_status "Plain text body -> 403 NON_MCP_REJECTED" "403" "$(http_status "$RESP1")"

  # Attack 2: Malformed JSON (not JSON-RPC 2.0)
  RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -d '{"action": "drop_table", "target": "users"}')

  assert_status "Malformed JSON (no jsonrpc field) -> 403" "403" "$(http_status "$RESP2")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 03: Tool Escalation
# Attack: Session for [read_file, list_dir], tries delete_file
# Expected: read_file -> 200, delete_file -> 403
# ═══════════════════════════════════════════════════════════════════

test_demo_03() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 03: Tool Escalation${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent + create session
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-reader",
      "model": "test-model",
      "capabilities": ["read"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  SESSION_ID=$(curl -sf -X POST "$ADMIN/sessions" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{
      \"agent_id\": \"$AGENT_ID\",
      \"declared_intent\": \"read and list project files\",
      \"authorized_tools\": [\"read_file\", \"list_dir\"],
      \"time_limit_secs\": 3600,
      \"call_budget\": 100
    }" | json_field session_id)

  echo "  Agent: $AGENT_ID"
  echo "  Session: $SESSION_ID (tools: [read_file, list_dir])"
  echo ""

  # Legitimate: read_file (authorized)
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

  assert_status "read_file (authorized) -> 200" "200" "$(http_status "$RESP1")"

  # Attack: delete_file (not in whitelist)
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

  assert_status "delete_file (not in whitelist) -> 403" "403" "$(http_status "$RESP2")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 04: Resource Exhaustion
# Attack: Exhaust rate limit (3/min) and call budget (5 total)
# Expected: 429 after limits exceeded
# ═══════════════════════════════════════════════════════════════════

test_demo_04() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 04: Resource Exhaustion${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-exhaust",
      "model": "test-model",
      "capabilities": ["read"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  # ── Part A: Rate limit (3 calls/min) ──────────────────────────────
  echo -e "  ${BOLD}Part A: Rate limit exhaustion (3 calls/minute)${NC}"
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
    }" | json_field session_id)

  for i in 1 2 3; do
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
    assert_status "Rate limit call $i/3 -> 200" "200" "$(http_status "$RESP")"
  done

  # Call 4: should be rate limited
  RESP4=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-agent-id: $AGENT_ID" \
    -H "x-arbiter-session: $SESSION_A" \
    -d '{
      "jsonrpc": "2.0",
      "id": 4,
      "method": "tools/call",
      "params": {
        "name": "read_file",
        "arguments": {"path": "/file-4.txt"}
      }
    }')

  assert_status "Rate limit call 4/3 -> 429 RATE_LIMITED" "429" "$(http_status "$RESP4")"
  echo ""

  # ── Part B: Budget exhaustion (5 calls) ───────────────────────────
  echo -e "  ${BOLD}Part B: Budget exhaustion (5 calls total)${NC}"
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
    }" | json_field session_id)

  for i in 1 2 3 4 5; do
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
    assert_status "Budget call $i/5 -> 200" "200" "$(http_status "$RESP")"
  done

  # Call 6: budget exhausted
  RESP6=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-agent-id: $AGENT_ID" \
    -H "x-arbiter-session: $SESSION_B" \
    -d '{
      "jsonrpc": "2.0",
      "id": 6,
      "method": "tools/call",
      "params": {
        "name": "read_file",
        "arguments": {"path": "/file-6.txt"}
      }
    }')

  assert_status "Budget call 6/5 -> 429 BUDGET_EXHAUSTED" "429" "$(http_status "$RESP6")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 05: Session Replay
# Attack: Reuse expired or closed session
# Expected: 408 (expired), 410 (closed)
# ═══════════════════════════════════════════════════════════════════

test_demo_05() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 05: Session Replay${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-replay",
      "model": "test-model",
      "capabilities": ["read"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  # ── Part A: Session expiry (3-second TTL) ─────────────────────────
  echo -e "  ${BOLD}Part A: Session expiry (3-second TTL)${NC}"
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
    }" | json_field session_id)

  echo "  Session: $SESSION_A (expires in 3 seconds)"

  # Use immediately (should work)
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

  assert_status "Immediate call (session fresh) -> 200" "200" "$(http_status "$RESP1")"

  # Wait for expiry
  echo -e "  ${YELLOW}Waiting 4 seconds for session to expire...${NC}"
  sleep 4

  # Replay expired session
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

  assert_status "Replay expired session -> 408 SESSION_EXPIRED" "408" "$(http_status "$RESP2")"
  echo ""

  # ── Part B: Closed session replay ─────────────────────────────────
  echo -e "  ${BOLD}Part B: Closed session replay${NC}"
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
    }" | json_field session_id)

  # Close the session
  curl -sf -X POST "$ADMIN/sessions/$SESSION_B/close" \
    -H "x-api-key: $API_KEY" > /dev/null 2>&1 || true

  # Replay closed session
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

  assert_status "Replay closed session -> 410 GONE" "410" "$(http_status "$RESP3")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 06: Zero-Trust Policy (Deny-by-Default)
# Attack: Unauthorized principal calls deploy_service
# Expected: 403 POLICY_DENIED
# ═══════════════════════════════════════════════════════════════════

test_demo_06() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 06: Zero-Trust Policy (Deny-by-Default)${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register attacker agent
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:rogue-contractor",
      "model": "test-model",
      "capabilities": ["read", "deploy"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  SESSION_ID=$(curl -sf -X POST "$ADMIN/sessions" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{
      \"agent_id\": \"$AGENT_ID\",
      \"declared_intent\": \"deploy the application to production\",
      \"authorized_tools\": [\"deploy_service\"],
      \"time_limit_secs\": 3600,
      \"call_budget\": 100
    }" | json_field session_id)

  echo "  Attacker: user:rogue-contractor ($AGENT_ID)"
  echo "  Policy requires: user:trusted-team"
  echo ""

  # Attack: unauthorized principal calls deploy_service
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

  assert_status "Unauthorized principal -> 403 POLICY_DENIED" "403" "$(http_status "$RESP")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 07: Parameter Tampering
# Attack: max_tokens = 50000 when constraint limit is 1000
# Expected: 200 within bounds, 403 outside bounds
# ═══════════════════════════════════════════════════════════════════

test_demo_07() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 07: Parameter Tampering${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-tamper",
      "model": "test-model",
      "capabilities": ["generate"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  SESSION_ID=$(curl -sf -X POST "$ADMIN/sessions" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{
      \"agent_id\": \"$AGENT_ID\",
      \"declared_intent\": \"generate text summaries\",
      \"authorized_tools\": [\"generate_text\"],
      \"time_limit_secs\": 3600,
      \"call_budget\": 100
    }" | json_field session_id)

  echo "  Constraint: max_tokens <= 1000, temperature 0-2"
  echo ""

  # Legitimate: max_tokens = 500 (within bounds)
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

  assert_status "max_tokens=500 (within bounds) -> 200" "200" "$(http_status "$RESP1")"

  # Attack: max_tokens = 50000 (exceeds constraint)
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
          "prompt": "Generate extremely long document",
          "max_tokens": 50000,
          "temperature": 0.7
        }
      }
    }')

  assert_status "max_tokens=50000 (exceeds limit) -> 403 POLICY_DENIED" "403" "$(http_status "$RESP2")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 08: Intent Drift
# Attack: Read-only session intent, agent calls write_file
# Expected: read_file -> 200, write_file -> 403 BEHAVIORAL_ANOMALY
# ═══════════════════════════════════════════════════════════════════

test_demo_08() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 08: Intent Drift${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-drifter",
      "model": "test-model",
      "capabilities": ["read", "write"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  SESSION_ID=$(curl -sf -X POST "$ADMIN/sessions" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{
      \"agent_id\": \"$AGENT_ID\",
      \"declared_intent\": \"read and analyze the source code\",
      \"authorized_tools\": [\"read_file\", \"list_dir\", \"write_file\", \"delete_file\"],
      \"time_limit_secs\": 3600,
      \"call_budget\": 100
    }" | json_field session_id)

  echo "  Intent: \"read and analyze the source code\""
  echo "  Tools:  [read_file, list_dir, write_file, delete_file] (all authorized)"
  echo "  Config: escalate_anomalies = true"
  echo ""

  # Legitimate: read_file (matches read-only intent)
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

  assert_status "read_file (matches read intent) -> 200" "200" "$(http_status "$RESP1")"

  # Attack: write_file (contradicts read-only intent)
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

  assert_status "write_file (contradicts read intent) -> 403 BEHAVIORAL_ANOMALY" "403" "$(http_status "$RESP2")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 09: Session Multiplication
# Attack: Create 15 sessions when cap is 10
# Expected: Sessions 1-10 succeed, 11-15 return 429
# ═══════════════════════════════════════════════════════════════════

test_demo_09() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 09: Session Multiplication${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent
  REGISTER=$(curl -sf -X POST "$ADMIN/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-multiply",
      "model": "test-model",
      "capabilities": ["read"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  echo "  Agent: $AGENT_ID"
  echo "  Cap: max_concurrent_sessions_per_agent = 10"
  echo ""

  # Create 15 sessions
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

    HTTP=$(http_status "$RESP")

    if [ "$i" -le 10 ]; then
      assert_status_any "Session $i/15 (within cap) -> 200|201" "200|201" "$HTTP"
    else
      assert_status "Session $i/15 (over cap) -> 429 TooManySessions" "429" "$HTTP"
    fi
  done
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# DEMO 10: Response Exfiltration
# Attack: Upstream returns leaked credentials/PII
# Expected: Clean response -> 200, tainted response -> 403
# ═══════════════════════════════════════════════════════════════════

test_demo_10() {
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  DEMO 10: Response Exfiltration${NC}"
  echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Setup: register agent on demo-10 arbiter instance
  REGISTER=$(curl -sf -X POST "$ADMIN_10/agents" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d '{
      "owner": "user:demo-exfil",
      "model": "test-model",
      "capabilities": ["read"],
      "trust_level": "basic"
    }')

  AGENT_ID=$(echo "$REGISTER" | json_field agent_id)
  TOKEN=$(echo "$REGISTER" | json_field token)

  SESSION_ID=$(curl -sf -X POST "$ADMIN_10/sessions" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $API_KEY" \
    -d "{
      \"agent_id\": \"$AGENT_ID\",
      \"declared_intent\": \"read customer records\",
      \"authorized_tools\": [\"query_records\"],
      \"time_limit_secs\": 3600,
      \"call_budget\": 100
    }" | json_field session_id)

  echo "  Target: arbiter-demo10 (response inspection enabled)"
  echo "  Upstream: tainted-echo (alternating clean/tainted)"
  echo ""

  # Call 1: Clean upstream response (odd call)
  RESP1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY_10" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-agent-id: $AGENT_ID" \
    -H "x-arbiter-session: $SESSION_ID" \
    -d '{
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "query_records",
        "arguments": {"filter": "active", "limit": 10}
      }
    }')

  assert_status "Clean upstream response -> 200" "200" "$(http_status "$RESP1")"

  # Call 2: Tainted upstream response (even call, contains AKIA, SSN, sk-)
  RESP2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY_10" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-agent-id: $AGENT_ID" \
    -H "x-arbiter-session: $SESSION_ID" \
    -d '{
      "jsonrpc": "2.0",
      "id": 2,
      "method": "tools/call",
      "params": {
        "name": "query_records",
        "arguments": {"filter": "all", "limit": 100}
      }
    }')

  assert_status "Tainted response (AWS keys, SSN) -> 403 RESPONSE_BLOCKED" "403" "$(http_status "$RESP2")"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════
# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════

test_demo_01
test_demo_02
test_demo_03
test_demo_04
test_demo_05
test_demo_06
test_demo_07
test_demo_08
test_demo_09
test_demo_10

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  E2E RESULTS                                                ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════╣${NC}"
if [ "$FAIL" -eq 0 ]; then
  echo -e "${BOLD}║                                                             ║${NC}"
  echo -e "${BOLD}║  ${GREEN}ALL $TOTAL ASSERTIONS PASSED${NC}${BOLD}                                  ║${NC}"
  echo -e "${BOLD}║                                                             ║${NC}"
else
  echo -e "${BOLD}║                                                             ║${NC}"
  echo -e "${BOLD}║  ${GREEN}Passed: $PASS${NC}${BOLD}    ${RED}Failed: $FAIL${NC}${BOLD}    Total: $TOTAL                    ║${NC}"
  echo -e "${BOLD}║                                                             ║${NC}"
fi
echo -e "${BOLD}║  Demos verified:                                            ║${NC}"
echo -e "${BOLD}║   01 Unauthenticated access    06 Zero-trust policy         ║${NC}"
echo -e "${BOLD}║   02 Protocol injection        07 Parameter tampering       ║${NC}"
echo -e "${BOLD}║   03 Tool escalation           08 Intent drift              ║${NC}"
echo -e "${BOLD}║   04 Resource exhaustion        09 Session multiplication    ║${NC}"
echo -e "${BOLD}║   05 Session replay            10 Response exfiltration     ║${NC}"
echo -e "${BOLD}║                                                             ║${NC}"
echo -e "${BOLD}║  All enforcement is REAL. No mocks, no simulation.          ║${NC}"
echo -e "${BOLD}║  Arbiter built from source, deployed in containers,         ║${NC}"
echo -e "${BOLD}║  verified over Docker networking.                           ║${NC}"
echo -e "${BOLD}║                                                             ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

exit "$FAIL"
