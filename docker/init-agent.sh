#!/bin/sh
# Register a demo agent on the Arbiter admin API.
# Waits for the admin API to be ready, then creates a basic agent.

set -e

ADMIN_URL="${ADMIN_URL:-http://arbiter:3000}"
API_KEY="${API_KEY:-qb-admin-key-2026}"
MAX_RETRIES=30
RETRY_INTERVAL=2

echo "[init] waiting for arbiter admin API at ${ADMIN_URL}..."

for i in $(seq 1 $MAX_RETRIES); do
    if wget -qO- "${ADMIN_URL}/../health" 2>/dev/null || wget -qO- "http://arbiter:8080/health" 2>/dev/null; then
        echo "[init] arbiter is ready"
        break
    fi
    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "[init] timeout waiting for arbiter"
        exit 1
    fi
    echo "[init] attempt ${i}/${MAX_RETRIES}, retrying in ${RETRY_INTERVAL}s..."
    sleep $RETRY_INTERVAL
done

# Give admin API a moment to fully initialize.
sleep 1

echo "[init] registering demo agent..."
RESPONSE=$(wget -qO- \
    --header="Content-Type: application/json" \
    --header="x-api-key: ${API_KEY}" \
    --post-data='{
        "owner": "user:alice",
        "model": "gpt-4",
        "capabilities": ["read", "write"],
        "trust_level": "basic"
    }' \
    "${ADMIN_URL}/agents" 2>&1) || true

echo "[init] response: ${RESPONSE}"
echo "[init] done, demo agent registered"
