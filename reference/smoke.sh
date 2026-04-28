#!/usr/bin/env bash
# Cullis Reference Deployment — smoke test
#
# Asserts the things that make this deployment "reference":
#   1. All six LLM agents are running and healthy
#   2. Each has its agent.pem + agent-key.pem + dpop.jwk on the
#      bootstrap-state volume (ADR-014 — TLS cert + DPoP only;
#      PR-C dropped api_key entirely)
#   3. Three distinct enrollment methods were exercised
#
# Run AFTER `bash reference/demo.sh full` brings the stack up.

set -euo pipefail
cd "$(dirname "$0")"

PASS=0
FAIL=0

pass() { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "[smoke] Reference deployment health"
echo

# ── 1. Six LLM agent containers running healthy ────────────────────
ALL_AGENTS="alice-byoca alice-spiffe alice-connector bob-byoca bob-spiffe bob-connector"
for agent in $ALL_AGENTS; do
    status=$(docker compose --profile full ps --format json "$agent" 2>/dev/null \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['Health'])" 2>/dev/null \
        || echo "missing")
    if [ "$status" = "healthy" ]; then
        pass "$agent healthy"
    else
        fail "$agent: $status"
    fi
done

echo

# ── 2. Identity files written for each agent ────────────────────────
echo "[smoke] Identity files persisted on bootstrap-state volume"
echo
ID_PROBE=$(docker compose --profile full run --rm --entrypoint sh bootstrap-mastio -c '
for org in orga orgb; do
    for d in /state/$org/agents/*/; do
        name=$(basename "$d")
        if [ -f "$d/agent.pem" ] && [ -f "$d/agent-key.pem" ] && [ -f "$d/dpop.jwk" ]; then
            echo "OK $org::$name"
        else
            echo "MISSING $org::$name"
        fi
    done
done
' 2>&1 | grep -E "^(OK|MISSING)")

while IFS= read -r line; do
    if [[ "$line" == OK* ]]; then
        pass "${line#OK }: agent.pem + agent-key.pem + dpop.jwk present"
    elif [[ "$line" == MISSING* ]]; then
        fail "${line#MISSING }: identity files missing"
    fi
done <<< "$ID_PROBE"

echo

# ── 3. Three enrollment methods exercised ──────────────────────────
echo "[smoke] Three enrollment methods visible in bootstrap-mastio log"
echo
LOG=$(docker compose --profile full logs bootstrap-mastio 2>&1)
for method in BYOCA SPIFFE "Connector device-code"; do
    count=$(echo "$LOG" | grep -c "enrolled via $method" || true)
    if [ "$count" -ge 1 ]; then
        pass "$method: $count enrollment(s)"
    else
        fail "$method: no enrollment found in log"
    fi
done

echo
echo "─────────────────────────────────"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "─────────────────────────────────"

exit $FAIL
