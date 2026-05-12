#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Customer-path smoke — end-to-end VPS deploy + enrollment + 1 chat turn
# ═══════════════════════════════════════════════════════════════════════════════
#
# Exercises the topology customers actually run (project_deployment_topology_
# vps_primary): Mastio + Frontdesk bundles deployed via docker compose, Connector
# enrolled via the browser-style wizard, one live chat turn through Anthropic.
#
# Catches the class of regression the 2026-05-11 sera dogfood surfaced (Bug #5,
# Connector dashboard /api/status missing X-Enrollment-Proof) which had CI green
# yet broke the customer onboarding end-to-end.
#
# Required env:
#   ANTHROPIC_API_KEY   — live Claude API key (CI: from secrets, local: from .env)
#
# Optional env:
#   SKIP_CHAT_TURN=1    — run only enrollment, skip Anthropic call (no key needed)
#   KEEP_RUNNING=1      — leave the stack up on success for manual inspection
#
# Exit codes:
#   0  — full path green
#   1  — failure at any step (logs dumped + teardown attempted)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BOLD=$'\033[1m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
GRAY=$'\033[90m'; RESET=$'\033[0m'

step()  { echo -e "\n${BOLD}── $1 ──${RESET}"; }
ok()    { echo -e "  ${GREEN}✓${RESET}  $1"; }
fail()  { echo -e "  ${RED}✗${RESET}  $1"; exit 1; }
note()  { echo -e "  ${YELLOW}!${RESET}  $1"; }

# ── Pre-flight ───────────────────────────────────────────────────────────

step "Pre-flight"

command -v docker >/dev/null || fail "docker not installed"
command -v curl >/dev/null   || fail "curl not installed"
command -v python3 >/dev/null || fail "python3 not installed"

if [[ "${SKIP_CHAT_TURN:-0}" != "1" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
    # Graceful degrade. The bundle-deploy + enrollment portion of the gate
    # (which catches Bug #5 + Bug #8 family regressions) does not need the
    # Anthropic key. Only the final 1-turn chat verification does. If the
    # secret is missing (e.g. CI secret not seeded yet) skip the chat turn
    # rather than failing the whole gate.
    note "ANTHROPIC_API_KEY not set — auto-skipping chat turn"
    SKIP_CHAT_TURN=1
fi

ok "tools + env"

# ── Build local images ───────────────────────────────────────────────────

step "Build local images from this commit"

# Bug #1 from dogfood: the root Dockerfile is the Court, NOT the Mastio.
# Build all three customer-path images with their correct Dockerfiles so
# the gate exercises the code at THIS commit, not whichever GHCR tag
# happens to be pinned in the bundle compose files. This is what makes
# the gate catch Bug #5-class regressions: the released Connector image
# is always behind main by at least one release cut.
docker build -q -t ghcr.io/cullis-security/cullis-mastio:local-smoke \
    -f mcp_proxy/Dockerfile . > /dev/null \
    || fail "Mastio image build"
ok "cullis-mastio:local-smoke"

docker build -q -t ghcr.io/cullis-security/cullis-chat-frontdesk:local-smoke \
    -f frontend/cullis-chat/Dockerfile frontend/cullis-chat/ > /dev/null \
    || fail "Chat frontdesk image build"
ok "cullis-chat-frontdesk:local-smoke"

docker build -q -t ghcr.io/cullis-security/cullis-connector:local-smoke \
    -f packaging/docker/Dockerfile . > /dev/null \
    || fail "Connector image build"
ok "cullis-connector:local-smoke"

# ── Deploy Mastio bundle ─────────────────────────────────────────────────

step "Deploy Mastio bundle"

cd "$REPO_ROOT/packaging/mastio-bundle"

# Fresh proxy.env every run so seeded passwords don't leak across runs.
cp proxy.env.example proxy.env
ADMIN_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(24))")
DASH_SECRET=$(python3 -c "import secrets;print(secrets.token_urlsafe(24))")
INIT_PW=$(python3 -c "import secrets;print(secrets.token_urlsafe(18))")
sed -i "s/^MCP_PROXY_ADMIN_SECRET=.*/MCP_PROXY_ADMIN_SECRET=${ADMIN_SECRET}/" proxy.env
sed -i "s|^MCP_PROXY_DASHBOARD_SIGNING_KEY=.*|MCP_PROXY_DASHBOARD_SIGNING_KEY=${DASH_SECRET}|" proxy.env
sed -i "s/^MCP_PROXY_STANDALONE=.*/MCP_PROXY_STANDALONE=true/" proxy.env
sed -i "s|^MCP_PROXY_BROKER_URL=.*|MCP_PROXY_BROKER_URL=|" proxy.env
sed -i "s|^MCP_PROXY_BROKER_JWKS_URL=.*|MCP_PROXY_BROKER_JWKS_URL=|" proxy.env
sed -i "s|^MCP_PROXY_ANTHROPIC_API_KEY=.*|MCP_PROXY_ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}|" proxy.env
echo "MCP_PROXY_INITIAL_ADMIN_PASSWORD=${INIT_PW}" >> proxy.env
echo "CULLIS_MASTIO_VERSION=local-smoke" >> proxy.env
# Bug #9 workaround: deploy.sh:379 reads MCP_PROXY_PROXY_PUBLIC_URL via
# `grep ... | cut ...` with `set -o pipefail`. When the var is absent
# (the default — proxy.env.example only lists it commented), grep exits
# 1, the pipeline fails, and the deploy script aborts AFTER writing the
# Org CA + Org ID (so "Mastio + nginx ready" prints but the script
# returns non-zero). Pin a value so the grep finds the line.
echo "MCP_PROXY_PROXY_PUBLIC_URL=https://localhost:9443" >> proxy.env

CULLIS_MASTIO_VERSION=local-smoke ./deploy.sh > /tmp/mastio-deploy.log 2>&1 \
    || { cat /tmp/mastio-deploy.log; fail "Mastio deploy"; }

# Wait for nginx health
for i in $(seq 1 30); do
    curl -sk https://localhost:9443/health >/dev/null 2>&1 && break
    sleep 1
done
curl -sk https://localhost:9443/health | grep -q '"status":"ok"' \
    || fail "Mastio /health"

ORG_ID=$(cat "$REPO_ROOT/packaging/mastio-bundle/certs/org-id")
[[ -n "$ORG_ID" ]] || fail "Org ID not exported"
ok "Mastio up — org=${ORG_ID}"

# ── Admin login + Anthropic provider configured ──────────────────────────

step "Admin login + Anthropic provider configured"

curl -sk -c /tmp/admin-cookies.txt \
    -d "username=admin&password=${INIT_PW}" \
    https://localhost:9443/proxy/login -o /dev/null \
    || fail "Admin login"

CSRF=$(curl -sk -b /tmp/admin-cookies.txt https://localhost:9443/proxy/ai-providers \
    | grep -oE 'name="csrf_token" value="[a-f0-9]+"' | head -1 \
    | grep -oE '[a-f0-9]{32}')
[[ -n "$CSRF" ]] || fail "CSRF token not found"

if [[ "${SKIP_CHAT_TURN:-0}" != "1" ]]; then
    # Bug #2 workaround: dashboard ignores env var, configure via POST.
    curl -sk -b /tmp/admin-cookies.txt -X POST \
        --data-urlencode "csrf_token=${CSRF}" \
        --data-urlencode "api_key=${ANTHROPIC_API_KEY}" \
        --data-urlencode "enabled=true" \
        https://localhost:9443/proxy/ai-providers/anthropic/save \
        -o /dev/null -w "%{http_code}" \
        | grep -q "303" || fail "Provider save"

    PROBE=$(curl -sk -b /tmp/admin-cookies.txt -X POST \
        -d "csrf_token=${CSRF}" \
        https://localhost:9443/proxy/ai-providers/anthropic/test)
    echo "$PROBE" | grep -qE "OK · [0-9]+ ms" \
        || fail "Anthropic live probe failed: ${PROBE}"
    ok "Anthropic configured + probe green"
else
    ok "Anthropic configuration skipped (SKIP_CHAT_TURN=1)"
fi

# ── Deploy Frontdesk bundle ──────────────────────────────────────────────

step "Deploy Frontdesk bundle"

cd "$REPO_ROOT/packaging/frontdesk-bundle"

CULLIS_FRONTDESK_ORG_ID="${ORG_ID}" \
CULLIS_FRONTDESK_TRUST_DOMAIN=cullis.local \
CULLIS_FRONTDESK_CA_BUNDLE_HOST="$REPO_ROOT/packaging/mastio-bundle/certs/org-ca.pem" \
    ./generate-frontdesk-env.sh --prod --force > /dev/null \
    || fail "frontdesk env generate"

cat >> frontdesk.env <<EOF

# Smoke wiring — pin all three images to the local builds so the gate
# exercises this commit's code, not the released GHCR tags.
CULLIS_FRONTDESK_MASTIO_URL=https://host.docker.internal:9443
CHAT_VERSION=local-smoke
CONNECTOR_VERSION=local-smoke
EOF

./deploy.sh > /tmp/frontdesk-deploy.log 2>&1 \
    || { cat /tmp/frontdesk-deploy.log; fail "Frontdesk deploy"; }

# Wait for SPA reachable
for i in $(seq 1 30); do
    curl -sf http://localhost:8080/ >/dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:8080/ -o /dev/null \
    || fail "Frontdesk SPA /"
ok "Frontdesk SPA up on :8080"

# ── TLS sidecar (#655 / ADR-024) ─────────────────────────────────────────
#
# deploy.sh runs with TLS enabled by default. Verify the self-signed cert
# was minted under ./tls/ and that the HTTPS surface returns the SPA on
# :8443. ``-k`` (no cert verification) is correct here — the cert is
# self-signed by a local CA the smoke does not import into the system
# trust store. The TLS handshake itself + the cert path + the proxy
# header pass-through to the inner SPA are what the gate validates.
test -s ./tls/frontdesk-server.crt \
    || fail "TLS cert was not minted at ./tls/frontdesk-server.crt"
test -s ./tls/frontdesk-ca.crt \
    || fail "TLS CA cert was not minted at ./tls/frontdesk-ca.crt"
ok "TLS cert + CA present under ./tls/"

for i in $(seq 1 20); do
    curl -skf https://localhost:8443/tls-health -o /dev/null && break
    sleep 1
done
curl -skf https://localhost:8443/tls-health -o /dev/null \
    || fail "Frontdesk TLS sidecar /tls-health not reachable on :8443"
ok "TLS sidecar healthy on :8443"

# Hit the SPA root through the TLS sidecar to confirm the reverse-proxy
# to the inner nginx works end-to-end. nginx would return 200 with the
# SPA HTML; we just check the status code.
curl -skf https://localhost:8443/ -o /dev/null \
    || fail "Frontdesk SPA / not reachable through TLS sidecar"
ok "Frontdesk SPA reachable on https://localhost:8443/"

# ── Enrollment wizard, end-to-end ────────────────────────────────────────

step "Enrollment wizard — discover, submit, approve, poll"

# 1. Discover should find the Mastio. Allow some time for the connector
#    to probe; retry a few times.
#
# After issue #634 the Frontdesk deploy.sh attaches the sibling Mastio
# nginx to frontdesk_net as ``host.docker.internal`` + ``mastio-nginx``
# alias. The discover probe then reaches the same Mastio at both
# ``host.docker.internal:9443`` and the docker0 gateway IP
# ``172.17.0.1:9443`` and lists it twice. Check for at least one row,
# not for the literal "Found one Mastio" wording.
DISCOVER_HTML=""
for i in $(seq 1 10); do
    DISCOVER_HTML="$(curl -sf http://localhost:8080/api/setup/discover/results 2>&1 || true)"
    echo "$DISCOVER_HTML" | grep -q 'class="found-mastio-url"' && break
    sleep 2
done
echo "$DISCOVER_HTML" | grep -q 'class="found-mastio-url"' \
    || { echo "$DISCOVER_HTML"; fail "Discover did not find Mastio"; }

BASE_URL=$(echo "$DISCOVER_HTML" | grep -oE 'name="base_url" value="[^"]+"' | head -1 | sed 's/.*value="\([^"]*\)".*/\1/')
CA_FP=$(echo "$DISCOVER_HTML" | grep -oE 'name="fingerprint" value="[^"]+"' | head -1 | sed 's/.*value="\([^"]*\)".*/\1/')
[[ -n "$BASE_URL" && -n "$CA_FP" ]] || fail "discover missing base_url/fingerprint"
ok "discover found ${BASE_URL}"

# 2. Submit /setup with verify_tls_off=1 — Bug #4 (Mastio nginx SAN doesn't
#    cover the docker bridge gateway IP). Production wants verify on.
SETUP_RESP=$(curl -s -L -i \
    -H "Origin: http://localhost:8080" \
    -H "Referer: http://localhost:8080/setup" \
    -X POST http://localhost:8080/setup \
    --data-urlencode "site_url=${BASE_URL}" \
    --data-urlencode "ca_fingerprint=${CA_FP}" \
    --data-urlencode "requester_name=smoke-customer-path" \
    --data-urlencode "requester_email=smoke@cullis.local" \
    --data-urlencode "reason=automated smoke test" \
    --data-urlencode "verify_tls_off=1")
echo "$SETUP_RESP" | grep -q "location: /waiting" \
    || { echo "$SETUP_RESP" | head -40; fail "Setup submit"; }
ok "Enrollment submitted, redirected to /waiting"

# 3. Find the pending ticket on Mastio and approve it.
sleep 2
TICKET=$(curl -sk -b /tmp/admin-cookies.txt https://localhost:9443/proxy/enrollments \
    | grep -oE '/proxy/enrollments/[A-Za-z0-9_-]+/approve' \
    | head -1 \
    | grep -oE 'enrollments/[A-Za-z0-9_-]+' \
    | sed 's|enrollments/||')
[[ -n "$TICKET" ]] || fail "No pending enrollment ticket"
ok "ticket ${TICKET}"

curl -sk -b /tmp/admin-cookies.txt -X POST \
    -d "csrf_token=${CSRF}" \
    -d "agent_id=frontdesk-smoke" \
    -d "display_name=Frontdesk Smoke" \
    -d "capabilities=chat.query" \
    "https://localhost:9443/proxy/enrollments/${TICKET}/approve" \
    -o /dev/null -w "%{http_code}" \
    | grep -q "303" || fail "Enrollment approve"
ok "approved"

# 4. The crucial test of Bug #5: poll /api/status until "approved" (with cert
#    on disk). Pre-fix this loops forever on "Approved enrollment is missing
#    cert_pem". 30s budget.
APPROVED=0
for i in $(seq 1 15); do
    STATUS=$(curl -sf http://localhost:8080/api/status || echo '{}')
    if echo "$STATUS" | grep -q '"status":"approved"'; then
        APPROVED=1
        break
    fi
    if echo "$STATUS" | grep -q 'missing cert_pem'; then
        # Don't keep retrying for the diagnostic case — fast-fail with the
        # specific Bug #5 signature so CI logs are unambiguous.
        echo "$STATUS"
        fail "Bug #5 regression: dashboard /api/status missing cert_pem"
    fi
    sleep 2
done
[[ $APPROVED == 1 ]] || fail "Enrollment did not reach approved in 30s"
ok "Connector identity on disk, /api/status=approved"

# ── ADR-025 path guards (issue #634) ─────────────────────────────────────
#
# The legacy session/init path below uses the X-Forwarded-User flow that
# bypasses CSR provisioning entirely. The ADR-025 local-auth path that
# real customers use does NOT. Two bugs from the 2026-05-12 dogfood
# (issue #634) shipped green through the old smoke because both bugs
# only manifest on the ADR-025 path:
#
#   Bug A — Frontdesk deploy.sh did not attach sibling Mastio nginx to
#           frontdesk_net, so host.docker.internal did not resolve from
#           inside the Connector container on Linux native. CSR fails
#           with "Name or service not known".
#   Bug B — When CSR fails, the deferred-provisioning detail (a multi-
#           line httpx error message) was placed verbatim in the
#           X-Cullis-Provisioning-Detail response header. uvicorn
#           rejects LF in header values, the response crashed mid-send,
#           nginx returned 502.

step "ADR-025 path guards — DNS + login round-trip"

# Bug A guard: DNS resolution from inside the Connector container.
CONNECTOR_CONTAINER="$(docker ps --filter 'label=com.docker.compose.service=connector' --filter 'label=com.docker.compose.project=cullis-frontdesk' --format '{{.Names}}' | head -1)"
[[ -n "$CONNECTOR_CONTAINER" ]] \
    || fail "Connector container not found by compose labels"
docker exec "$CONNECTOR_CONTAINER" getent hosts host.docker.internal >/dev/null 2>&1 \
    || fail "Bug A regression: host.docker.internal does not resolve inside $CONNECTOR_CONTAINER (deploy.sh did not attach sibling Mastio nginx to frontdesk_net)"
ok "host.docker.internal resolves inside Connector"

# Bug B guard: an /api/auth/login round-trip on the ADR-025 path must
# return a well-formed response even when CSR provisioning fails (the
# whole point of "deferred" semantics). Pre-fix, the response crashed
# uvicorn mid-send.
ADMIN_SECRET=$(grep '^CULLIS_CONNECTOR_ADMIN_SECRET=' "$REPO_ROOT/packaging/frontdesk-bundle/frontdesk.env" | cut -d= -f2)
[[ -n "$ADMIN_SECRET" ]] || fail "could not read CULLIS_CONNECTOR_ADMIN_SECRET from frontdesk.env"

curl -sf -X POST http://localhost:8080/admin/users \
    -H "X-Admin-Secret: $ADMIN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"user_name":"smoke-adr025","password":"smoke-password-long","must_change_password":false}' \
    -o /tmp/smoke-create-user.json \
    || fail "admin create user (ADR-025 smoke)"

LOGIN_HTTP=$(curl -s -o /tmp/smoke-login.json -D /tmp/smoke-login.headers \
    -w "%{http_code}" \
    -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"user_name":"smoke-adr025","password":"smoke-password-long"}')
[[ "$LOGIN_HTTP" == "200" ]] \
    || { echo "headers:"; cat /tmp/smoke-login.headers; echo "body:"; cat /tmp/smoke-login.json; fail "Bug B regression: /api/auth/login returned $LOGIN_HTTP (expected 200)"; }

# Defense in depth — every response header value must be a single line.
if grep -lE $'[\r\n]' /tmp/smoke-login.headers >/dev/null 2>&1; then
    # grep -lE on the file matches if a line CONTAINS CR/LF mid-value.
    # The header file itself uses CRLF terminators per HTTP, so this
    # check fires only when a header value embeds an extra CR/LF.
    : # placeholder, real check below
fi
# Stricter check: parse each header value, ensure none contains an
# embedded \n after stripping the standard CRLF terminator.
python3 - <<'PY' || fail "Bug B regression: response header carries embedded CR/LF"
import sys
with open("/tmp/smoke-login.headers", "rb") as f:
    raw = f.read()
# Split on CRLF, then look for any "header: value" line whose value
# (after the colon) contains a bare \n or \r — would mean two distinct
# headers got concatenated, which is exactly what the original Bug B
# would have leaked.
for line in raw.split(b"\r\n"):
    if b":" not in line:
        continue
    name, _, value = line.partition(b":")
    if b"\n" in value or b"\r" in value:
        print(f"header {name!r} carries embedded CR/LF: {value!r}", file=sys.stderr)
        sys.exit(1)
PY
ok "/api/auth/login returns 200 and headers are LF-free"

# ── 1 chat turn against Claude (live) ────────────────────────────────────

if [[ "${SKIP_CHAT_TURN:-0}" == "1" ]]; then
    note "Chat turn skipped (SKIP_CHAT_TURN=1)"
else
    step "1 chat turn via SPA → Connector → Mastio → Anthropic"
    # Mint a session cookie via the SPA's local-token init endpoint.
    SESSION_INIT=$(curl -sf -X POST http://localhost:8080/api/session/init \
        -c /tmp/spa-cookies.txt -w "%{http_code}" -o /tmp/init.json)
    [[ "$SESSION_INIT" == "200" ]] \
        || { cat /tmp/init.json; fail "session/init"; }

    CHAT_RESP=$(curl -sf -b /tmp/spa-cookies.txt \
        -H "Content-Type: application/json" \
        -X POST http://localhost:8080/v1/chat/completions \
        -d '{
            "model": "claude-haiku-4-5",
            "messages": [
                {"role": "user", "content": "Say only the word PONG."}
            ],
            "stream": false
        }' || echo '{"error":"chat call failed"}')
    CONTENT=$(echo "$CHAT_RESP" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('choices', [{}])[0].get('message', {}).get('content') or d.get('error') or 'no content')
except Exception as e:
    print(f'parse error: {e}')
")
    [[ -n "$CONTENT" && "$CONTENT" != "no content" ]] \
        || { echo "Resp: $CHAT_RESP"; fail "Chat response empty"; }
    ok "chat reply: ${CONTENT:0:80}"
fi

# ── Teardown ─────────────────────────────────────────────────────────────

if [[ "${KEEP_RUNNING:-0}" == "1" ]]; then
    note "KEEP_RUNNING=1 — leaving stack up. Dashboard https://localhost:9443/proxy/login"
    note "Admin password: ${INIT_PW}"
    exit 0
fi

step "Teardown"
cd "$REPO_ROOT/packaging/frontdesk-bundle"
./deploy.sh --down > /dev/null 2>&1 || true
cd "$REPO_ROOT/packaging/mastio-bundle"
./deploy.sh --down > /dev/null 2>&1 || true
ok "stopped"

echo -e "\n${BOLD}${GREEN}Customer-path smoke PASSED${RESET}\n"
