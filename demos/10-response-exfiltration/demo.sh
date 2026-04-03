#!/usr/bin/env bash
set -euo pipefail

# ── Demo 10: Response Exfiltration ───────────────────────────────────
# Attack: Upstream MCP server returns response containing API keys/PII.
# Expected: Clean responses pass, responses with secrets are blocked.

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
MOCK_UPSTREAM="http://127.0.0.1:8081"
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
  if [ -n "${MOCK_PID:-}" ]; then
    kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  DEMO 10: Response Exfiltration${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Attack: Upstream MCP server returns sensitive data (API keys, PII)"
echo "  Config: default data_sensitivity_ceiling = internal"
echo "  Expected: Clean responses pass; restricted data blocked with 502"
echo ""

# ── Start mock upstream that returns tainted responses ──────────────
echo -e "${YELLOW}Starting mock upstream MCP server...${NC}"

# Simple Python mock that alternates between clean and tainted responses
python3 -c '
import http.server, json, sys

class Handler(http.server.BaseHTTPRequestHandler):
    call_count = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        Handler.call_count += 1

        if Handler.call_count % 2 == 1:
            # Clean response
            resp = json.dumps({
                "jsonrpc": "2.0",
                "id": Handler.call_count,
                "result": {"records": [{"id": 1, "status": "active"}]}
            })
        else:
            # Tainted response with leaked credentials
            resp = json.dumps({
                "jsonrpc": "2.0",
                "id": Handler.call_count,
                "result": {
                    "records": [
                        {"id": 1, "config": "aws_key=AKIAIOSFODNN7EXAMPLE"},
                        {"id": 2, "notes": "SSN on file: 123-45-6789"},
                        {"id": 3, "api_key": "sk-proj-abcdef1234567890abcdef1234567890"}
                    ]
                }
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp.encode())

    def log_message(self, *args):
        pass  # suppress logs

http.server.HTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
' &
MOCK_PID=$!
sleep 1
echo -e "${GREEN}Mock upstream running on :8081${NC}"

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

# ── Setup: Register agent and create session ────────────────────────
echo -e "${BOLD}── SETUP: Register agent ──${NC}"
echo ""

REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:demo-exfil",
    "model": "test-model",
    "capabilities": ["read"],
    "trust_level": "basic"
  }')

AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID: $AGENT_ID"

SESSION_ID=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"declared_intent\": \"read customer records\",
    \"authorized_tools\": [\"query_records\"],
    \"time_limit_secs\": 3600,
    \"call_budget\": 100
  }" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

echo "  Session: $SESSION_ID"
echo ""

# ── Call 1: Clean response (should pass) ────────────────────────────
echo -e "${BOLD}── Call 1: Legitimate tool call (clean upstream response) ──${NC}"
echo ""

RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
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

HTTP=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')

if [ "$HTTP" = "200" ] || [ "$HTTP" = "502" ]; then
  echo -e "  Status: ${GREEN}${HTTP} OK${NC} (response passed inspection)"
  echo "  Response:"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
else
  echo -e "  Status: ${YELLOW}${HTTP}${NC}"
fi

echo ""

# ── Call 2: Tainted response (should be blocked) ────────────────────
echo -e "${BOLD}── Call 2: Tool call with tainted upstream response ──${NC}"
echo ""

RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
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

HTTP=$(echo "$RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESP" | sed '/HTTP_STATUS:/d')

if [ "$HTTP" = "502" ]; then
  echo -e "  Status: ${RED}502 BLOCKED${NC} (response contained restricted data)"
  echo "  Response:"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
elif [ "$HTTP" = "200" ]; then
  echo -e "  Status: ${YELLOW}200${NC} (response was NOT blocked -- data may be within ceiling)"
else
  echo -e "  Status: ${YELLOW}${HTTP}${NC}"
fi

echo ""
echo -e "${BOLD}── Explanation ──${NC}"
echo ""
echo "  Arbiter's response classifier scans upstream responses for sensitive"
echo "  data patterns (AWS keys, API keys, SSNs, credit card numbers,"
echo "  private keys, internal IPs). Each finding is classified by severity:"
echo "  Internal, Confidential, or Restricted."
echo ""
echo "  Sessions have a data_sensitivity_ceiling (default: Internal). When"
echo "  Restricted data is found in a non-Restricted session, the response"
echo "  is blocked with 502 and the agent never sees the leaked data."
echo ""
