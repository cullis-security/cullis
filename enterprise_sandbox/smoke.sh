#!/usr/bin/env bash
# Enterprise sandbox — smoke test
# Assertion list: imp/enterprise_sandbox_plan.md §smoke
set -euo pipefail

cd "$(dirname "$0")"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
skip() { echo "  ~ $1 (skipped: $2)"; SKIP=$((SKIP+1)); }

echo "[smoke] Blocco 1 — topology + cross-org reachability"

# B1.1 — all core services healthy
if docker compose ps --format json | grep -q '"Health":"healthy"'; then
    pass "B1.1 services healthy"
else
    fail "B1.1 services healthy"
fi

# B1.2 — broker-a reaches broker-b on public-wan
if docker exec enterprise_sandbox-broker-a-1 \
    python -c "import urllib.request; urllib.request.urlopen('http://broker-b:8000/health')" 2>/dev/null; then
    pass "B1.2 broker-a → broker-b via public-wan"
else
    fail "B1.2 broker-a → broker-b via public-wan"
fi

# B1.3 — broker-b reaches broker-a on public-wan
if docker exec enterprise_sandbox-broker-b-1 \
    python -c "import urllib.request; urllib.request.urlopen('http://broker-a:8000/health')" 2>/dev/null; then
    pass "B1.3 broker-b → broker-a via public-wan"
else
    fail "B1.3 broker-b → broker-a via public-wan"
fi

# B1.4 — network isolation: broker-a cannot reach postgres-b
if docker exec enterprise_sandbox-broker-a-1 python -c "
import socket; s = socket.socket(); s.settimeout(2)
try: s.connect(('postgres-b', 5432)); exit(1)
except Exception: exit(0)
" 2>/dev/null; then
    pass "B1.4 org network isolation (broker-a ⊥ postgres-b)"
else
    fail "B1.4 org network isolation"
fi

# Upcoming blocks
skip "B2 Vault + Proxy"        "Blocco 2 not yet implemented"
skip "B3 Keycloak OIDC"        "Blocco 3 not yet implemented"
skip "B4 SPIRE + SVID agent"   "Blocco 4 not yet implemented"
skip "B5 smoke 10 assertion"   "Blocco 5 not yet implemented"

echo ""
echo "[smoke] PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
