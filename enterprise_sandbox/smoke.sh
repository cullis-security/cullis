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

echo "[smoke] Blocco 1 — shared broker on public-wan"

if docker compose ps --format json | grep -q '"Health":"healthy"'; then
    pass "B1.1 services healthy"
else
    fail "B1.1 services healthy"
fi

if docker run --rm --network cullis-sandbox-wan \
    curlimages/curl:8.10.1 -sf http://broker:8000/health >/dev/null 2>&1; then
    pass "B1.2 broker reachable on public-wan"
else
    fail "B1.2 broker reachable on public-wan"
fi

echo ""
echo "[smoke] Blocco 2 — proxies + attach-ca (2 orgs)"

orgs=$(docker exec enterprise_sandbox-postgres-1 psql -U atn -d agent_trust -Atc \
    "SELECT org_id FROM organizations WHERE status='active' ORDER BY org_id;")
if [[ "$orgs" == $'orga\norgb' ]]; then
    pass "B2.1 orga + orgb active on broker"
else
    fail "B2.1 orgs active (got: $orgs)"
fi

if docker run --rm --network cullis-sandbox-orga \
    curlimages/curl:8.10.1 -sf http://proxy-a:9100/health >/dev/null 2>&1; then
    pass "B2.2 proxy-a reachable from orga-internal"
else
    fail "B2.2 proxy-a reachable from orga-internal"
fi

if docker run --rm --network cullis-sandbox-orgb \
    curlimages/curl:8.10.1 -sf http://proxy-b:9100/health >/dev/null 2>&1; then
    pass "B2.3 proxy-b reachable from orgb-internal"
else
    fail "B2.3 proxy-b reachable from orgb-internal"
fi

if docker run --rm --network cullis-sandbox-orgb \
    curlimages/curl:8.10.1 -sf --max-time 3 http://proxy-a:9100/health >/dev/null 2>&1; then
    fail "B2.4 org isolation (orgb reached proxy-a directly — LEAK)"
else
    pass "B2.4 org isolation (orgb-internal ⊥ proxy-a direct access)"
fi

echo ""
echo "[smoke] Blocco 3 — Keycloak OIDC per proxy (three-tier refactor)"

# B3.1 — Keycloak-a discovery reachable from broker network
if docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request
urllib.request.urlopen('http://keycloak-a:8180/realms/orga/.well-known/openid-configuration')
" 2>/dev/null; then
    pass "B3.1 keycloak-a realm 'orga' discovery OK (docker network)"
else
    fail "B3.1 keycloak-a discovery"
fi

# B3.2 — Keycloak-b discovery reachable from broker network
if docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request
urllib.request.urlopen('http://keycloak-b:8280/realms/orgb/.well-known/openid-configuration')
" 2>/dev/null; then
    pass "B3.2 keycloak-b realm 'orgb' discovery OK (docker network)"
else
    fail "B3.2 keycloak-b discovery"
fi

# B3.3 — OIDC config wired in proxy_config (not on broker)
q_oidc() {
    docker exec "$1" python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
r = c.execute(\"SELECT value FROM proxy_config WHERE key='oidc_issuer_url'\").fetchone()
print(r[0] if r else '')
" 2>/dev/null
}
oidc_a=$(q_oidc enterprise_sandbox-proxy-a-1)
oidc_b=$(q_oidc enterprise_sandbox-proxy-b-1)
if [[ "$oidc_a" == "http://keycloak-a:8180/realms/orga" && "$oidc_b" == "http://keycloak-b:8280/realms/orgb" ]]; then
    pass "B3.3 per-proxy OIDC config (proxy_config table)"
else
    fail "B3.3 OIDC config per proxy (a=$oidc_a b=$oidc_b)"
fi

# B3.4 — Broker DB has NO per-org OIDC (columns still exist but unused)
broker_oidc=$(docker exec enterprise_sandbox-postgres-1 psql -U atn -d agent_trust -Atc \
    "SELECT COALESCE(oidc_issuer_url, 'NULL') FROM organizations ORDER BY org_id;" | tr '\n' ',')
if [[ "$broker_oidc" == "NULL,NULL," ]]; then
    pass "B3.4 broker has no org OIDC config (network-admin-only)"
else
    fail "B3.4 broker org OIDC should be NULL (got: $broker_oidc)"
fi

# B3.5 — alice@orga Keycloak direct grant (IdP tenant works standalone)
b35=$(docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request, urllib.parse, json, base64
data = urllib.parse.urlencode({
    'grant_type':'password','client_id':'cullis-proxy-dashboard',
    'client_secret':'orga-oidc-client-secret-change-me',
    'username':'alice','password':'alice-sandbox','scope':'openid email'
}).encode()
t = json.loads(urllib.request.urlopen('http://keycloak-a:8180/realms/orga/protocol/openid-connect/token', data=data).read())
p = json.loads(base64.urlsafe_b64decode(t['id_token'].split('.')[1]+'==='))
print(p['iss']+'|'+p['email'])
" 2>/dev/null)
if [[ "$b35" == "http://keycloak-a:8180/realms/orga|alice@orga.test" ]]; then
    pass "B3.5 alice@orga OIDC token valid"
else
    fail "B3.5 alice OIDC (got: $b35)"
fi

# B3.6 — Tenant isolation: bob rejected by keycloak-a realm
if docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request, urllib.parse
data = urllib.parse.urlencode({
    'grant_type':'password','client_id':'cullis-proxy-dashboard',
    'client_secret':'orga-oidc-client-secret-change-me',
    'username':'bob','password':'bob-sandbox','scope':'openid'
}).encode()
try: urllib.request.urlopen('http://keycloak-a:8180/realms/orga/protocol/openid-connect/token', data=data); exit(1)
except Exception: exit(0)
" 2>/dev/null; then
    pass "B3.6 tenant isolation (bob rejected by keycloak-a)"
else
    fail "B3.6 tenant isolation (bob accepted by keycloak-a — LEAK)"
fi

# B3.7 — Browser OIDC login flow via PROXY dashboard (not broker)
browser_flow() {
    local proxy_port="$1" kc="$2" kc_port="$3" user="$4" pass="$5"
    local cj; cj=$(mktemp)
    local au lp fa cu rc
    au=$(curl -s -o /dev/null -w "%{redirect_url}" -c "$cj" -b "$cj" \
        "http://localhost:${proxy_port}/proxy/oidc/start") || { rm -f "$cj"; return 1; }
    [[ -n "$au" ]] || { rm -f "$cj"; return 1; }
    lp=$(curl -s --resolve "$kc:$kc_port:127.0.0.1" -c "$cj" -b "$cj" -L "$au")
    fa=$(echo "$lp" | grep -oE 'action="[^"]+"' | head -1 | sed 's/action="//;s/"$//;s/&amp;/\&/g')
    [[ -n "$fa" ]] || { rm -f "$cj"; return 1; }
    cu=$(curl -s -o /dev/null -w "%{redirect_url}" --resolve "$kc:$kc_port:127.0.0.1" -c "$cj" -b "$cj" \
        -d "username=$user&password=$pass&credentialId=" "$fa")
    rc=$(curl -s -o /dev/null -w "%{http_code}" -c "$cj" -b "$cj" "$cu")
    rm -f "$cj"
    [[ "$rc" == "303" || "$rc" == "302" || "$rc" == "200" ]]
}

if browser_flow 9100 keycloak-a 8180 alice alice-sandbox; then
    pass "B3.7 alice@orga browser OIDC → proxy-a dashboard"
else
    fail "B3.7 alice@orga browser OIDC"
fi

if browser_flow 9200 keycloak-b 8280 bob bob-sandbox; then
    pass "B3.8 bob@orgb browser OIDC → proxy-b dashboard"
else
    fail "B3.8 bob@orgb browser OIDC"
fi

# B3.9 — Unauthenticated access to proxy dashboard is blocked
anon_rc=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9100/proxy/overview)
if [[ "$anon_rc" == "303" || "$anon_rc" == "302" || "$anon_rc" == "401" || "$anon_rc" == "403" ]]; then
    pass "B3.9 anonymous GET /proxy/overview blocked (HTTP $anon_rc)"
else
    fail "B3.9 anonymous access NOT blocked (HTTP $anon_rc — LEAK)"
fi

# B3.10 — Session isolation: bob's cookie must not grant access to proxy-a
#
# Full OIDC login for bob on proxy-b captures a session cookie, then we replay
# that same cookie jar against proxy-a. Expected: 303/401/403 (bob's session
# is bound to proxy-b's signing key + org; proxy-a must reject it).
bob_login_and_try_other() {
    local cj; cj=$(mktemp)
    local au lp fa cu
    au=$(curl -s -o /dev/null -w "%{redirect_url}" -c "$cj" -b "$cj" \
        "http://localhost:9200/proxy/oidc/start") || { rm -f "$cj"; echo X; return; }
    lp=$(curl -s --resolve "keycloak-b:8280:127.0.0.1" -c "$cj" -b "$cj" -L "$au")
    fa=$(echo "$lp" | grep -oE 'action="[^"]+"' | head -1 | sed 's/action="//;s/"$//;s/&amp;/\&/g')
    cu=$(curl -s -o /dev/null -w "%{redirect_url}" --resolve "keycloak-b:8280:127.0.0.1" -c "$cj" -b "$cj" \
        -d "username=bob&password=bob-sandbox&credentialId=" "$fa")
    curl -s -o /dev/null -c "$cj" -b "$cj" "$cu" >/dev/null   # seal bob session
    # Replay bob's cookie jar against proxy-a (different port, different tenant)
    local cross
    cross=$(curl -s -o /dev/null -w "%{http_code}" -b "$cj" http://localhost:9100/proxy/overview)
    rm -f "$cj"
    echo "$cross"
}
cross_rc=$(bob_login_and_try_other)
if [[ "$cross_rc" == "303" || "$cross_rc" == "302" || "$cross_rc" == "401" || "$cross_rc" == "403" ]]; then
    pass "B3.10 bob's cookie rejected by proxy-a (HTTP $cross_rc — isolated)"
else
    fail "B3.10 bob's cookie accepted by proxy-a (HTTP $cross_rc — LEAK)"
fi

echo ""
echo "[smoke] Blocco 4 — SPIRE stack + SPIFFE agent auth"

# B4.1 — SPIRE servers up and healthy
if docker compose ps spire-server-a --format json | grep -q '"Health":"healthy"' \
   && docker compose ps spire-server-b --format json | grep -q '"Health":"healthy"'; then
    pass "B4.1 spire-server-a + spire-server-b healthy"
else
    fail "B4.1 spire-server healthy"
fi

# B4.2 — Registration entries created (one per org).
# spire-server image is distroless — no shell — but docker exec with the
# absolute binary path bypasses PATH lookup and works anyway.
entries_a=$(docker exec enterprise_sandbox-spire-server-a-1 \
    /opt/spire/bin/spire-server entry show \
    -socketPath /tmp/spire-server/private/api.sock 2>/dev/null | \
    grep -c "spiffe://orga.test/agent-a" || true)
entries_b=$(docker exec enterprise_sandbox-spire-server-b-1 \
    /opt/spire/bin/spire-server entry show \
    -socketPath /tmp/spire-server/private/api.sock 2>/dev/null | \
    grep -c "spiffe://orgb.test/agent-b" || true)
if [[ "$entries_a" -ge 1 && "$entries_b" -ge 1 ]]; then
    pass "B4.2 registration entries present (agent-a, agent-b)"
else
    fail "B4.2 registration entries (a=$entries_a b=$entries_b)"
fi

# B4.3 — SPIRE agents healthy (Workload API socket usable)
if docker compose ps spire-agent-a --format json | grep -q '"Health":"healthy"' \
   && docker compose ps spire-agent-b --format json | grep -q '"Health":"healthy"'; then
    pass "B4.3 spire-agent-a + spire-agent-b healthy (Workload API ready)"
else
    fail "B4.3 spire-agent healthy"
fi

# B4.4 + B4.5 — End-to-end SPIFFE auth to broker is BLOCKED until the broker
# learns to derive agent_id/org_id from a SPIFFE SAN URI when the cert lacks
# CN/O (SPIRE-issued SVIDs do). Tracked separately — the SPIRE half (the
# whole point of this Blocco) is verified by B4.1-3 above. Once the broker
# work lands, agent-a/agent-b containers in compose will become healthy
# without further sandbox changes.
skip "B4.4 agent broker auth via SVID"   "blocked: broker needs SPIFFE-aware x509 verifier"
skip "B4.5 cross-org session over SPIFFE" "blocked: same — see issue tracking SPIFFE-aware broker auth"

echo ""
echo "[smoke] PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
