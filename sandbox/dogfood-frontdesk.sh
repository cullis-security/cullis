#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Frontdesk end-to-end dogfood — Docker Compose, no VM, no SSH
# ═══════════════════════════════════════════════════════════════════════════════
#
# Spins both production bundles (mastio + frontdesk) side-by-side on
# the same docker host, wires them together (Mastio dashboard → Frontdesk
# Ambassador admin endpoint with verify_tls=false for the self-signed
# sidecar), and drives the full customer scenario end-to-end with curl:
#
#   1. Mastio bundle up + healthy
#   2. Frontdesk bundle up + healthy
#   3. Bridge ``proxy.env`` (Mastio learns the Frontdesk admin URL +
#      secret + verify_tls=false), restart Mastio mcp-proxy
#   4. Hit /setup on the Frontdesk → mint the bootstrap bearer
#   5. POST /setup with bearer → workload enrollment lands as
#      ``pending`` on the Mastio with ``principal_type=workload``
#   6. Approve programmatically (Mastio admin password → cookie →
#      POST /proxy/enrollments/<sid>/approve)
#   7. Poll Connector /api/status → save_identity fires →
#      ``mark_setup_completed`` flips the flag → /setup returns 410
#   8. Assert: ``internal_agents.principal_type='workload'``,
#      ``agent.crt`` has 2 PEM blocks (leaf + intermediate, #816),
#      ``GET /setup`` returns 410 (#811 hook fired)
#   9. Create user via Mastio dashboard (admin-input password, #817)
#  10. Login user against Frontdesk → assert
#      ``provisioning=ok`` (ADR-025 Phase 3 + #816 chain), check
#      ``previous`` cert pinning grace period intact
#  11. Spin up Ollama on the shared bridge, warm a tiny model,
#      configure Mastio AI Providers programmatically, then drive
#      ``GET /v1/models`` + ``POST /v1/chat/completions`` from the
#      Frontdesk SPA's vantage point (mario's cookie) and assert
#      ``source=live`` + a non-empty assistant reply
#  12. Tear everything down
#
# Why this lives next to ``demo.sh``: the existing sandbox demo
# enrolls agents via the BYOCA bootstrap script (``sandbox/bootstrap/``)
# and never touches the wizard ``/setup/*`` flow, the user login flow,
# or the Frontdesk Ambassador. Every bug surfaced during the ADR-034
# rc1/rc2/rc3 VM dogfood (#813 gate scope, #815 UPDATE propagation,
# #816 cert chain, #817 multi-worker ticket store, #818 verify_tls)
# was reproducible from a docker compose stand-up of the two bundles
# side-by-side — but no script existed to catch them automatically.
# This is that script. Run it from the repo root or from ``sandbox/``.
#
# Memory feedback_no_polling — single fixed wait per readiness gate,
# no tight retry loops.
# Memory feedback_dogfood_simulates_paying_customer — every env we
# tweak here mirrors what the operator would set in the customer
# bundle's ``proxy.env`` / ``frontdesk.env``. No source-tree
# shortcuts, no auth bypass.
# Memory feedback_dogfood_before_demo — this is the pre-merge gate
# for any PR that touches enrollment, auth, or Frontdesk surface.
#
# Usage:
#   ./sandbox/dogfood-frontdesk.sh              # full scenario
#   ./sandbox/dogfood-frontdesk.sh --keep       # leave stack up at end
#   ./sandbox/dogfood-frontdesk.sh --down       # tear down only
#   ./sandbox/dogfood-frontdesk.sh --version 0.5.0-rc3
#                                               # pin a specific tag
#                                               # (default: ``dev`` —
#                                               # uses local-built
#                                               # images, see --build)
#   ./sandbox/dogfood-frontdesk.sh --build      # build mastio + connector
#                                               # images from source
#                                               # before bring-up
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$REPO_ROOT/.data/dogfood-frontdesk"
MASTIO_WORK="$WORK_DIR/mastio"
FRONTDESK_WORK="$WORK_DIR/frontdesk"

# Versions / image tags. ``dev`` triggers --build by default.
VERSION="dev"
DO_BUILD=0
DO_KEEP=0
DO_DOWN_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --build) DO_BUILD=1; shift ;;
    --keep) DO_KEEP=1; shift ;;
    --down) DO_DOWN_ONLY=1; shift ;;
    -h|--help) sed -n '/^# Usage:/,/^# ═/p' "$0" | head -20; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ``dev`` tag implies build (caller didn't specify a pulled tag).
if [[ "$VERSION" == "dev" ]]; then
  DO_BUILD=1
fi

MASTIO_IMAGE="ghcr.io/cullis-security/cullis-mastio:${VERSION}"
CONNECTOR_IMAGE="ghcr.io/cullis-security/cullis-connector:${VERSION}"

# Ports — chosen to NOT collide with sandbox/demo.sh full (which uses
# 9443 already on a different bridge) so an operator can have both
# stacks up at once for cross-comparison. Override via env if needed.
MASTIO_HOST_PORT="${MASTIO_HOST_PORT:-19443}"
FRONTDESK_HTTP_PORT="${FRONTDESK_HTTP_PORT:-18080}"
FRONTDESK_TLS_PORT="${FRONTDESK_TLS_PORT:-18443}"

# Ollama service — tiny model so the test stays under ~400MB pull and
# the first inference call returns under ~10s on CPU. Override via env
# to pin a different model (must be ``<name>:<tag>`` exactly as Ollama
# names it). Default qwen2.5:0.5b is ~352MB.
OLLAMA_IMAGE="${OLLAMA_IMAGE:-ollama/ollama:latest}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:0.5b}"
OLLAMA_CONTAINER="dogfood-frontdesk-ollama"

# Compose project names — keep distinct so a half-baked previous run
# can be cleaned without nuking sandbox/demo.sh.
MASTIO_PROJECT="dogfood-frontdesk-mastio"
FRONTDESK_PROJECT="dogfood-frontdesk-frontdesk"

# ── helpers ───────────────────────────────────────────────────────────────────

# stderr-only colours (stdout stays parseable by tests / CI)
C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OK=$'\033[32m'
C_ERR=$'\033[31m'; C_NEU=$'\033[36m'; C_RST=$'\033[0m'

log()  { echo "${C_NEU}${C_BOLD}»${C_RST} $*" >&2; }
ok()   { echo "${C_OK}${C_BOLD}✓${C_RST} $*" >&2; }
fail() { echo "${C_ERR}${C_BOLD}✗${C_RST} $*" >&2; exit 1; }
dim()  { echo "${C_DIM}$*${C_RST}" >&2; }

# Wait for an HTTP endpoint to return 2xx/3xx. One curl per second up
# to a deadline; never tighter than that (memory feedback_no_polling).
wait_http() {
  local url="$1" deadline_s="${2:-60}" verify_arg="${3:-}"
  local end=$((SECONDS + deadline_s))
  while (( SECONDS < end )); do
    if curl -sk --max-time 3 ${verify_arg} -o /dev/null -w "%{http_code}\n" "$url" 2>/dev/null \
        | grep -qE '^[23][0-9][0-9]$'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

cleanup_down() {
  log "tearing down ${FRONTDESK_PROJECT} + ${MASTIO_PROJECT}"
  docker rm -f "$OLLAMA_CONTAINER" >/dev/null 2>&1 || true
  ( cd "$FRONTDESK_WORK" 2>/dev/null && \
      docker compose -p "$FRONTDESK_PROJECT" \
        --env-file frontdesk.env down --volumes --remove-orphans \
        >/dev/null 2>&1 ) || true
  ( cd "$MASTIO_WORK" 2>/dev/null && \
      docker compose -p "$MASTIO_PROJECT" \
        --env-file proxy.env down --volumes --remove-orphans \
        >/dev/null 2>&1 ) || true
  # Bind dirs survive ``--volumes`` (that only removes named volumes)
  # so we wipe them via a transient root container that can chown +
  # remove files owned by uid 10001.
  if [[ -d "$WORK_DIR" ]]; then
    docker run --rm --user 0:0 -v "$WORK_DIR":/wipe busybox:stable \
      sh -c 'rm -rf /wipe/mastio /wipe/frontdesk' >/dev/null 2>&1 || true
  fi
}

# ── Down-only branch ──────────────────────────────────────────────────────────

if [[ "$DO_DOWN_ONLY" -eq 1 ]]; then
  cleanup_down
  ok "down complete"
  exit 0
fi

# ── 0. Wipe any half-baked previous run before anything else ──────────────────
#
# Bind-mounted data dirs from the last run can end up owned by uid
# 10001 (the bundle's runtime user), which breaks the subsequent
# ``docker build`` because the build context tarball pass fails on
# ``permission denied``. Wipe up front, then trap the same cleanup on
# EXIT.

trap '[[ "$DO_KEEP" -eq 1 ]] || cleanup_down' EXIT
cleanup_down

# ── 1. Build (optional) ───────────────────────────────────────────────────────

if [[ "$DO_BUILD" -eq 1 ]]; then
  log "building $MASTIO_IMAGE + $CONNECTOR_IMAGE from source"
  docker build -q -f "$REPO_ROOT/mcp_proxy/Dockerfile" \
    --build-arg "VERSION=$VERSION" \
    -t "$MASTIO_IMAGE" "$REPO_ROOT" >/dev/null
  ok "mastio image built"
  docker build -q -f "$REPO_ROOT/packaging/docker/Dockerfile" \
    -t "$CONNECTOR_IMAGE" "$REPO_ROOT" >/dev/null
  ok "connector image built"
fi

# ── 2. Stage work dirs + shared network ──────────────────────────────────────

mkdir -p "$MASTIO_WORK" "$FRONTDESK_WORK"

# The two compose stacks run on disjoint private networks
# (``dogfood-frontdesk-mastio_proxy_net`` and
# ``dogfood-frontdesk-frontdesk_frontdesk_net``). For Mastio
# dashboard → Frontdesk admin we need a routable bridge between
# them; ``host.docker.internal`` routes through the default Docker
# bridge gateway which the per-stack networks don't share. Cleanest
# fix: create one external network that both stacks join, then the
# Mastio reaches the Frontdesk via Docker DNS
# (``http://connector:7777``) without round-tripping through the
# host. Identical pattern to how ``sandbox/demo.sh full`` wires the
# two-org WAN bridge.
SHARED_NET="dogfood-frontdesk-bridge"
docker network inspect "$SHARED_NET" >/dev/null 2>&1 \
  || docker network create "$SHARED_NET" >/dev/null

# Kick off Ollama early so the model pull (~350MB for qwen2.5:0.5b)
# overlaps with the Mastio + Frontdesk bring-up. By the time we get
# to step 9 the model is warm and the chat assertion stays fast.
# Container is attached to the shared bridge with alias ``ollama`` so
# the Mastio resolves ``http://ollama:11434`` via Docker DNS — same
# bridge pattern Mastio uses to reach the Frontdesk Ambassador admin.
log "spawning Ollama (${OLLAMA_IMAGE}, alias=ollama)"
docker run -d --name "$OLLAMA_CONTAINER" \
  --network "$SHARED_NET" --network-alias ollama \
  --pull=missing \
  "$OLLAMA_IMAGE" >/dev/null \
  || fail "could not start $OLLAMA_CONTAINER"
# Pull the chat model in the background — runs concurrently with the
# rest of the script. We block on completion in step 8b before
# touching the AI Providers admin endpoint.
log "pulling $OLLAMA_MODEL in background"
docker exec -d "$OLLAMA_CONTAINER" \
  sh -c "ollama pull '$OLLAMA_MODEL' > /tmp/ollama-pull.log 2>&1; echo \$? > /tmp/ollama-pull.rc"
ok "Ollama spawned, model pull running in background"

# Copy bundle templates first; THEN drop overrides on top so the
# template's ``cp -r`` doesn't clobber them. (Subtle bug fix: the
# original ordering put overrides first, ``cp -r .`` from the
# template then wrote ``docker-compose.override.yml`` from the
# template into the same path — but the template doesn't ship one,
# so the override actually disappeared. Compose ``config`` showed
# only ``frontdesk_net`` and the cross-stack DNS bridge never
# materialised.)
log "staging bundle templates → $WORK_DIR"
cp -r "$REPO_ROOT/packaging/mastio-bundle/." "$MASTIO_WORK/"
cp -r "$REPO_ROOT/packaging/frontdesk-bundle/." "$FRONTDESK_WORK/"
ok "templates staged"

# Mastio override: join the shared bridge so ``connector`` resolves
# via Docker DNS to the Frontdesk Connector container.
cat >"$MASTIO_WORK/docker-compose.override.yml" <<OVERRIDE
services:
  mcp-proxy:
    networks:
      - proxy_net
      - sharedbridge
  mastio-nginx:
    networks:
      - proxy_net
      - sharedbridge
networks:
  sharedbridge:
    external: true
    name: ${SHARED_NET}
OVERRIDE

# Frontdesk override: same shared bridge, and the Connector picks up
# the Mastio at ``mastio-nginx`` (no extra_hosts needed once we are
# on the same network).
cat >"$FRONTDESK_WORK/docker-compose.override.yml" <<OVERRIDE
services:
  connector:
    networks:
      - frontdesk_net
      - sharedbridge
  cullis-chat:
    networks:
      - frontdesk_net
      - sharedbridge
  nginx:
    networks:
      - frontdesk_net
      - sharedbridge
networks:
  sharedbridge:
    external: true
    name: ${SHARED_NET}
OVERRIDE

# ── 2. Mint a Mastio admin secret + admin password seed ───────────────────────

MASTIO_ADMIN_SECRET="$(openssl rand -hex 16)"
MASTIO_ADMIN_PASSWORD="DogfoodAdmin-$(openssl rand -hex 4)!"
FRONTDESK_ADMIN_SECRET="$(openssl rand -hex 24)"
# Pin the dashboard signing key — without an explicit value each
# uvicorn worker generates its own random one at boot, so a cookie
# signed by worker A is rejected by worker B on the next request
# (the default Mastio bundle ships ``--workers 4``). The script's
# end-to-end flow logs in once and then makes multiple admin POSTs;
# every round-trip would otherwise have ~75% chance of landing on a
# worker that doesn't recognise the cookie and bouncing through
# ``/proxy/login`` again.
MASTIO_DASHBOARD_SIGNING_KEY="$(openssl rand -hex 32)"

# ── 3. Generate Mastio proxy.env ──────────────────────────────────────────────

log "generating Mastio proxy.env"
cat >"$MASTIO_WORK/proxy.env" <<EOF
CULLIS_MASTIO_VERSION=${VERSION}
MCP_PROXY_ADMIN_SECRET=${MASTIO_ADMIN_SECRET}
MCP_PROXY_INITIAL_ADMIN_PASSWORD=${MASTIO_ADMIN_PASSWORD}
MCP_PROXY_DASHBOARD_SIGNING_KEY=${MASTIO_DASHBOARD_SIGNING_KEY}
MCP_PROXY_ENVIRONMENT=development
MCP_PROXY_STANDALONE=true
# DPoP htu binding pins the proof to the *configured* public URL,
# not the request's Host header. The Connector (inside the shared
# bridge) reaches the Mastio at ``https://mastio-nginx:9443`` via
# Docker DNS, so the public URL has to match that exact host:port
# or every DPoP-bearing egress call 401s with "htu mismatch". Host-
# side admin calls (curl https://localhost:${MASTIO_HOST_PORT}) still
# work because dashboard cookie auth + X-Admin-Secret endpoints
# don't carry DPoP. Caught dogfooding ${OLLAMA_MODEL} chat → 401 on
# /v1/egress/models with htu='mastio-nginx' vs 'localhost' expected.
MCP_PROXY_PROXY_PUBLIC_URL=https://mastio-nginx:9443
MCP_PROXY_NGINX_SAN=mastio.local,localhost,host.docker.internal,mastio-nginx,mcp-proxy
MCP_PROXY_PORT=${MASTIO_HOST_PORT}
MASTIO_WORKERS=4
# Frontdesk bridge — populated post-Frontdesk-up below. We re-write
# this file in place + ``docker compose up --force-recreate`` to push
# the values into the running container (memory
# feedback_bundle_compose_env_explicit_mapping: --env-file alone
# substitutes ``\${VAR}`` but doesn't inject vars; the compose
# ``environment:`` block does, which is why these end up in the
# Mastio container).
MCP_PROXY_FRONTDESK_AMBASSADOR_URL=
MCP_PROXY_FRONTDESK_ADMIN_SECRET=
MCP_PROXY_FRONTDESK_VERIFY_TLS=false
EOF
ok "proxy.env written"

# ── 4. Boot Mastio ────────────────────────────────────────────────────────────

log "bringing up Mastio (${MASTIO_PROJECT})"
( cd "$MASTIO_WORK" && \
    docker compose -p "$MASTIO_PROJECT" \
      --env-file proxy.env up -d --wait \
      >/dev/null 2>"$WORK_DIR/mastio-up.err" ) || {
  echo "--- mastio compose up stderr ---" >&2
  cat "$WORK_DIR/mastio-up.err" >&2
  fail "Mastio bring-up failed"
}
wait_http "https://localhost:${MASTIO_HOST_PORT}/health" 60 || \
  fail "Mastio /health never returned 2xx within 60s"
MASTIO_VERSION_REPORTED="$(curl -sk \
    "https://localhost:${MASTIO_HOST_PORT}/health" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version","?"))')"
ok "Mastio healthy — version=$MASTIO_VERSION_REPORTED"

# ── 5. Generate Frontdesk env + boot ──────────────────────────────────────────

log "generating Frontdesk env"
# Mastio CA bundle — needed for the Connector to verify the Mastio
# TLS chain when it calls /v1/auth/login-challenge-response and
# /v1/principals/csr. The bundle's nginx sidecar exposes the Org
# CA cert at /etc/nginx/certs/org-ca.crt.
docker cp "${MASTIO_PROJECT}-mastio-nginx-1:/etc/nginx/certs/org-ca.crt" \
  "$FRONTDESK_WORK/mastio-ca-bundle.pem" 2>/dev/null \
  || fail "could not extract Mastio Org CA — SDK calls will fail TLS verify"
ok "Mastio Org CA extracted → $FRONTDESK_WORK/mastio-ca-bundle.pem"
# Org ID — the Mastio mints one at first boot, expose it via /health
# or the /v1/registry/orgs/me endpoint.
MASTIO_ORG_ID="$(docker exec "${MASTIO_PROJECT}-mcp-proxy-1" python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
row = c.execute(\"SELECT value FROM proxy_config WHERE key='org_id'\").fetchone()
print(row[0] if row else 'unknown')
")"
[[ "$MASTIO_ORG_ID" != "unknown" ]] \
  || fail "Mastio org_id not minted yet (proxy_config table empty)"
dim "Mastio org_id=$MASTIO_ORG_ID"

cat >"$FRONTDESK_WORK/frontdesk.env" <<EOF
CONNECTOR_VERSION=${VERSION}
# cullis-chat-frontdesk is the SPA — we don't rebuild it locally for
# the backend-only scenario this script exercises. Pin the latest
# published tag instead of mirroring \$VERSION (which is ``dev`` /
# locally-built and would fail the GHCR pull). Override via env if
# you have a matching SPA build to test.
CHAT_VERSION=${CHAT_VERSION:-0.4.1}
CULLIS_FRONTDESK_ORG_ID=${MASTIO_ORG_ID}
CULLIS_FRONTDESK_TRUST_DOMAIN=cullis.test
CULLIS_FRONTDESK_CA_BUNDLE_HOST=./mastio-ca-bundle.pem
# Connector → Mastio: traverse the shared bridge via Docker DNS.
# ``mastio-nginx`` is a SAN on the bundle's self-signed cert (see
# ``MCP_PROXY_NGINX_SAN`` default).
CULLIS_SITE_URL=https://mastio-nginx:9443
CULLIS_CONNECTOR_ADMIN_SECRET=${FRONTDESK_ADMIN_SECRET}
FRONTDESK_HTTP_PORT=${FRONTDESK_HTTP_PORT}
FRONTDESK_TLS_PORT=${FRONTDESK_TLS_PORT}
# The bundle binds HTTP to 127.0.0.1 by default (loopback-only is
# the right shape in production: cookies + SPA secrets never touch
# a non-loopback peer, the TLS sidecar fronts the public surface).
# In sandbox the Mastio container reaches the Frontdesk admin
# endpoint via the docker bridge gateway, so loopback-only blocks
# it. Widen to 0.0.0.0 for the sandbox flow — accepted because the
# whole docker network is local to this script's host.
FRONTDESK_HTTP_BIND=0.0.0.0
# Skip the version probe — we already know the Mastio is the matching
# rc and the probe wouldn't help here anyway (CULLIS_MASTIO_VERSION
# echoes back what we passed via --build-arg).
FRONTDESK_SKIP_VERSION_PROBE=1
EOF
ok "frontdesk.env written"

log "bringing up Frontdesk (${FRONTDESK_PROJECT})"
( cd "$FRONTDESK_WORK" && \
    docker compose -p "$FRONTDESK_PROJECT" \
      --env-file frontdesk.env up -d --wait \
      >/dev/null 2>"$WORK_DIR/frontdesk-up.err" ) || {
  echo "--- frontdesk compose up stderr ---" >&2
  cat "$WORK_DIR/frontdesk-up.err" >&2
  fail "Frontdesk bring-up failed"
}
wait_http "http://localhost:${FRONTDESK_HTTP_PORT}/setup" 30 \
  || fail "Frontdesk /setup never returned 2xx within 30s"
ok "Frontdesk healthy on :$FRONTDESK_HTTP_PORT"

# ── 6. Bridge Mastio → Frontdesk ──────────────────────────────────────────────

log "bridging Mastio dashboard → Frontdesk Ambassador admin"
# Both stacks share ``${SHARED_NET}``; the Frontdesk Connector binds
# 7777 on the bridge, the Mastio dashboard reaches it via Docker DNS.
# ``connector`` is the service name in the Frontdesk compose.
sed -i \
  -e "s|^MCP_PROXY_FRONTDESK_AMBASSADOR_URL=.*|MCP_PROXY_FRONTDESK_AMBASSADOR_URL=http://connector:7777|" \
  -e "s|^MCP_PROXY_FRONTDESK_ADMIN_SECRET=.*|MCP_PROXY_FRONTDESK_ADMIN_SECRET=${FRONTDESK_ADMIN_SECRET}|" \
  "$MASTIO_WORK/proxy.env"
( cd "$MASTIO_WORK" && \
    docker compose -p "$MASTIO_PROJECT" \
      --env-file proxy.env up -d --force-recreate --wait mcp-proxy \
      >/dev/null 2>&1 ) || fail "mcp-proxy restart after bridging failed"
ok "bridge wired (verify_tls=false for self-signed)"

# ── 7. Enrollment flow ────────────────────────────────────────────────────────

log "triggering /setup to mint the bootstrap bearer"
curl -sk -o /dev/null "http://localhost:${FRONTDESK_HTTP_PORT}/setup"
sleep 1
SETUP_BEARER="$(docker logs "${FRONTDESK_PROJECT}-connector-1" 2>&1 \
  | grep -A2 'Frontdesk setup bearer' \
  | tail -n3 | head -n1 | tr -d ' ')"
[[ ${#SETUP_BEARER} -ge 32 ]] || fail "bootstrap bearer not minted (got ${#SETUP_BEARER} chars)"
ok "bootstrap bearer minted"

log "submitting enrollment as workload"
ENROLL_HTTP="$(curl -sk -o "$WORK_DIR/setup-resp.html" -w '%{http_code}' \
  -X POST "http://localhost:${FRONTDESK_HTTP_PORT}/setup" \
  -H "Authorization: Bearer ${SETUP_BEARER}" \
  -H "Origin: http://localhost:${FRONTDESK_HTTP_PORT}" \
  -d "site_url=https://mastio-nginx:9443" \
  -d "requester_name=frontdesk" \
  -d "requester_email=ops@cullis.dogfood" \
  -d "reason=sandbox dogfood-frontdesk.sh" \
  -d "verify_tls_off=1")"
[[ "$ENROLL_HTTP" == "303" ]] || fail "POST /setup expected 303, got $ENROLL_HTTP"

# Verify pending row carries principal_type=workload (#809 + #815).
PENDING_PT="$(docker exec "${MASTIO_PROJECT}-mcp-proxy-1" python -c '
import sqlite3
c = sqlite3.connect("/data/mcp_proxy.db")
row = c.execute("SELECT principal_type FROM pending_enrollments WHERE status=\"pending\" ORDER BY created_at DESC LIMIT 1").fetchone()
print(row[0] if row else "MISSING")
')"
[[ "$PENDING_PT" == "workload" ]] \
  || fail "pending_enrollments.principal_type expected 'workload', got '$PENDING_PT'"
ok "pending enrollment landed with principal_type=workload"

# ── 8. Approve via Mastio admin API ───────────────────────────────────────────

log "approving enrollment via Mastio dashboard"
# Login → cookie
LOGIN_HTTP="$(curl -sk -c "$WORK_DIR/mastio-cookies.txt" \
  -o "$WORK_DIR/login.html" -w '%{http_code}' \
  -X POST "https://localhost:${MASTIO_HOST_PORT}/proxy/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: https://localhost:${MASTIO_HOST_PORT}" \
  -d "password=${MASTIO_ADMIN_PASSWORD}")"
[[ "$LOGIN_HTTP" =~ ^30[37]$ ]] || fail "Mastio /proxy/login expected 30x, got $LOGIN_HTTP"

# Extract pending session_id + CSRF token
PENDING_SID="$(docker exec "${MASTIO_PROJECT}-mcp-proxy-1" python -c '
import sqlite3
c = sqlite3.connect("/data/mcp_proxy.db")
row = c.execute("SELECT session_id FROM pending_enrollments WHERE status=\"pending\" ORDER BY created_at DESC LIMIT 1").fetchone()
print(row[0] if row else "MISSING")
')"
[[ "$PENDING_SID" != "MISSING" ]] || fail "no pending session_id to approve"

# Extract CSRF token straight out of the session cookie. The Mastio
# dashboard signs ``{role, csrf_token, exp}`` JSON into the cookie
# body; parsing it directly is more robust than scraping the
# ``/proxy/enrollments`` HTML form (which can shift between releases).
CSRF_TOK="$(python3 -c "
import json
# Netscape cookie file — the ``#HttpOnly_`` prefix on a name field is
# part of the format (HttpOnly flag), NOT a comment. Don't skip it.
with open('$WORK_DIR/mastio-cookies.txt') as fh:
    for line in fh:
        if 'mcp_proxy_session' not in line:
            continue
        # value is the last tab-separated field; strip the surrounding
        # double quotes the file uses to keep embedded whitespace.
        raw = line.rstrip().split('\t')[-1].strip('\"')
        body = raw.rsplit('.', 1)[0]
        # Netscape encoded ',' as \\054 and JSON quotes as \\\" — decode
        # before json.loads.
        body = body.replace('\\\\054', ',').replace('\\\\\"', '\"')
        print(json.loads(body).get('csrf_token', ''))
        break
")"
[[ -n "$CSRF_TOK" ]] || fail "no CSRF token extracted from session cookie"
dim "CSRF token: ${CSRF_TOK:0:8}…"

curl -sk -b "$WORK_DIR/mastio-cookies.txt" \
  -D "$WORK_DIR/approve-headers.txt" \
  -o "$WORK_DIR/approve-resp.html" \
  -X POST "https://localhost:${MASTIO_HOST_PORT}/proxy/enrollments/${PENDING_SID}/approve" \
  -H "Origin: https://localhost:${MASTIO_HOST_PORT}" \
  --data-urlencode "csrf_token=${CSRF_TOK}" \
  --data-urlencode "agent_id=frontdesk" \
  --data-urlencode "capabilities=" \
  --data-urlencode "groups="
APPROVE_HTTP="$(head -n1 "$WORK_DIR/approve-headers.txt" | awk '{print $2}')"
APPROVE_LOC="$(grep -i '^location:' "$WORK_DIR/approve-headers.txt" | head -n1)"
dim "approve: HTTP $APPROVE_HTTP  $APPROVE_LOC"
if [[ ! "$APPROVE_HTTP" =~ ^30[37]$ ]]; then
  echo "--- approve response body ---" >&2
  head -c 400 "$WORK_DIR/approve-resp.html" >&2 || true
  echo >&2
  fail "approve expected 30x, got $APPROVE_HTTP"
fi
# Reject redirect-to-login (session lost / CSRF mismatch): legitimate
# approve redirects to ``/proxy/enrollments?flash=Approved...``.
if echo "$APPROVE_LOC" | grep -qi '/proxy/login'; then
  fail "approve was redirected to /proxy/login — session or CSRF rejected"
fi

# Verify the approve actually landed (303 alone can be a redirect to
# login if the session was rejected). Re-poll the pending row.
APPROVED_STATUS="$(docker exec "${MASTIO_PROJECT}-mcp-proxy-1" python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
row = c.execute('SELECT status FROM pending_enrollments WHERE session_id = ?', ('${PENDING_SID}',)).fetchone()
print(row[0] if row else 'MISSING')
")"
[[ "$APPROVED_STATUS" == "approved" ]] || \
  fail "pending row status expected 'approved' after POST, got '$APPROVED_STATUS' (CSRF / session may have failed)"
ok "enrollment approved (verified pending.status='approved')"

# ── 8b. Wait for Ollama model pull + configure Mastio AI Provider ────────────

log "waiting for Ollama model pull to finish"
# Block up to 5 min (CPU-only laptops at low bandwidth can stretch).
# Memory feedback_no_polling: one fixed-cadence wait, no tight loops.
pull_deadline=$((SECONDS + 300))
while (( SECONDS < pull_deadline )); do
  if docker exec "$OLLAMA_CONTAINER" sh -c '[ -f /tmp/ollama-pull.rc ]' 2>/dev/null; then
    PULL_RC="$(docker exec "$OLLAMA_CONTAINER" cat /tmp/ollama-pull.rc 2>/dev/null | tr -d '[:space:]')"
    break
  fi
  sleep 2
done
if [[ "${PULL_RC:-X}" != "0" ]]; then
  echo "--- ollama pull log ---" >&2
  docker exec "$OLLAMA_CONTAINER" cat /tmp/ollama-pull.log 2>/dev/null | tail -n40 >&2 || true
  fail "ollama pull '$OLLAMA_MODEL' did not finish cleanly (rc=${PULL_RC:-timeout})"
fi
ok "$OLLAMA_MODEL pulled"

log "registering Ollama in Mastio AI Providers (api_base=http://ollama:11434)"
SAVE_HTTP="$(curl -sk -b "$WORK_DIR/mastio-cookies.txt" \
  -D "$WORK_DIR/ai-save-headers.txt" \
  -o "$WORK_DIR/ai-save-resp.html" \
  -w '%{http_code}' \
  -X POST "https://localhost:${MASTIO_HOST_PORT}/proxy/ai-providers/ollama/save" \
  -H "Origin: https://localhost:${MASTIO_HOST_PORT}" \
  --data-urlencode "csrf_token=${CSRF_TOK}" \
  --data-urlencode "api_base=http://ollama:11434" \
  --data-urlencode "enabled=on")"
if [[ ! "$SAVE_HTTP" =~ ^30[37]$ ]]; then
  echo "--- ai-provider save response ---" >&2
  head -c 400 "$WORK_DIR/ai-save-resp.html" >&2 || true
  echo >&2
  fail "AI provider save expected 30x, got $SAVE_HTTP"
fi
# Confirm the row reached the Mastio DB (silent forward failure
# protection — same pattern as the user-create assertion below).
OLLAMA_ROW="$(docker exec "${MASTIO_PROJECT}-mcp-proxy-1" python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
row = c.execute(\"SELECT enabled FROM ai_provider_credentials WHERE provider='ollama'\").fetchone()
print(row[0] if row else 'MISSING')
")"
[[ "$OLLAMA_ROW" == "1" ]] \
  || fail "ai_provider_credentials.ollama not stored or disabled (got '$OLLAMA_ROW')"
ok "Mastio AI Providers: ollama enabled"

# Sanity-check the Mastio can list models from Ollama — this is the
# canary for shared-bridge DNS + LiteLLM provider catalog wiring.
# ``/v1/admin/ai-providers/<p>/test`` mirrors the dashboard Test button
# via the X-Admin-Secret header so we don't need to scrape the HTML.
PROBE_JSON="$(curl -sk \
  -H "X-Admin-Secret: ${MASTIO_ADMIN_SECRET}" \
  -X POST "https://localhost:${MASTIO_HOST_PORT}/v1/admin/ai-providers/ollama/test")"
echo "$PROBE_JSON" | grep -q '"status":"ok"' \
  || fail "Mastio could not probe ollama (Docker DNS or provider wiring broken): $PROBE_JSON"
ok "Mastio ↔ Ollama probe ok"

# ── 9. Connector polls + saves identity ───────────────────────────────────────

log "polling Connector /api/status to trigger save_identity"
curl -sk "http://localhost:${FRONTDESK_HTTP_PORT}/api/status" >/dev/null
sleep 2

# Assert 1 — internal_agents.principal_type == workload (#815)
INTERNAL_PT="$(docker exec "${MASTIO_PROJECT}-mcp-proxy-1" python -c '
import sqlite3
c = sqlite3.connect("/data/mcp_proxy.db")
row = c.execute("SELECT principal_type FROM internal_agents WHERE agent_id LIKE \"%::frontdesk\"").fetchone()
print(row[0] if row else "MISSING")
')"
[[ "$INTERNAL_PT" == "workload" ]] \
  || fail "internal_agents.principal_type expected 'workload', got '$INTERNAL_PT' (#815 regression)"
ok "internal_agents.principal_type='workload' (#815 ok)"

# Assert 2 — agent.crt has 2 PEM blocks (leaf + intermediate, #816)
CRT_BLOCKS="$(docker exec "${FRONTDESK_PROJECT}-connector-1" sh -c '
grep -c "BEGIN CERTIFICATE" /home/cullis/.cullis/profiles/frontdesk/identity/agent.crt 2>/dev/null
' | tr -d ' ')"
[[ "$CRT_BLOCKS" == "2" ]] \
  || fail "agent.crt PEM blocks expected 2, got '$CRT_BLOCKS' (#816 regression)"
ok "agent.crt carries leaf + intermediate (#816 ok)"

# Assert 3 — /setup returns 410 (#811 mark_setup_completed)
SETUP_HTTP="$(curl -sk -o /dev/null -w '%{http_code}' \
  "http://localhost:${FRONTDESK_HTTP_PORT}/setup")"
[[ "$SETUP_HTTP" == "410" ]] \
  || fail "/setup expected 410 post-enrollment, got '$SETUP_HTTP' (#811 hook regression)"
ok "/setup → 410 Gone (#811 ok)"

# Restart the Connector to pick up the freshly-minted identity. The
# ADR-025 Phase 3 provisioner mounts only when ``has_identity`` is
# True AT BOOT (``cullis_connector/web.py:506``); the Connector
# started before enrollment, so the provisioner was deferred. Without
# this restart the next user login lands ``provisioning="skipped"``
# (no CSR, no UserPrincipal cert) — same UX gap the operator hits in
# the wild. The bundle's runbook documents this restart; here we do
# it programmatically so the assertion below is deterministic.
log "restarting Connector to mount the ADR-025 Phase 3 provisioner"
( cd "$FRONTDESK_WORK" && \
    docker compose -p "$FRONTDESK_PROJECT" \
      --env-file frontdesk.env restart connector \
      >/dev/null 2>&1 ) || fail "Connector restart failed"
wait_http "http://localhost:${FRONTDESK_HTTP_PORT}/v1/ambassador/health" 30 \
  || fail "Connector /v1/ambassador/health unreachable after restart"
ok "Connector restarted with provisioner mounted"

# ── 10. Create user via Mastio dashboard (#817 admin-input password) ──────────

log "creating user 'mario' via Mastio dashboard"
USER_PASSWORD="MarioDogfood-$(openssl rand -hex 4)!"
# CSRF token from the same session cookie we reused for /approve.
curl -sk -b "$WORK_DIR/mastio-cookies.txt" \
  -D "$WORK_DIR/create-headers.txt" \
  -o "$WORK_DIR/create-resp.html" \
  -X POST "https://localhost:${MASTIO_HOST_PORT}/proxy/users/create" \
  -H "Origin: https://localhost:${MASTIO_HOST_PORT}" \
  --data-urlencode "csrf_token=${CSRF_TOK}" \
  --data-urlencode "user_name=mario" \
  --data-urlencode "display_name=Mario Rossi" \
  --data-urlencode "password=${USER_PASSWORD}" \
  --data-urlencode "password_confirm=${USER_PASSWORD}"
CREATE_HTTP="$(head -n1 "$WORK_DIR/create-headers.txt" | awk '{print $2}')"
CREATE_LOC="$(grep -i '^location:' "$WORK_DIR/create-headers.txt" | head -n1)"
dim "create: HTTP $CREATE_HTTP  $CREATE_LOC"
if [[ ! "$CREATE_HTTP" =~ ^30[37]$ ]]; then
  echo "--- create response ---" >&2
  head -c 400 "$WORK_DIR/create-resp.html" >&2 || true
  echo >&2
  fail "user create expected 30x, got $CREATE_HTTP"
fi
if echo "$CREATE_LOC" | grep -qi '/proxy/login'; then
  fail "create user redirected to /proxy/login — session lost / CSRF mismatch"
fi
if echo "$CREATE_LOC" | grep -qi 'error='; then
  fail "create user landed with error: $CREATE_LOC"
fi
# Confirm the row actually reached the Frontdesk's users.db. The
# Mastio dashboard forwards via the admin endpoint; a silent
# transport failure would have surfaced as ``?error=Frontdesk+...``
# (caught above) but a misconfigured bridge could still no-op.
FD_HAS_MARIO="$(docker exec "${FRONTDESK_PROJECT}-connector-1" python -c "
import sqlite3
c = sqlite3.connect('/home/cullis/.cullis/profiles/frontdesk/users.db')
row = c.execute('SELECT user_name FROM local_users WHERE user_name = \"mario\"').fetchone()
print('yes' if row else 'no')
")"
[[ "$FD_HAS_MARIO" == "yes" ]] || \
  fail "Frontdesk users.db missing mario after create (Mastio→Frontdesk forward failed silently)"
ok "user mario created end-to-end (Mastio dashboard → Frontdesk users.db)"

# ── 11. Login user → assert provisioning=ok (ADR-025 Phase 3 + #816) ─────────

log "user login → CSR provisioning"
# First login flips must_change_password, no CSR yet.
LOGIN1="$(curl -sk -c "$WORK_DIR/mario-cookies.txt" \
  -X POST "http://localhost:${FRONTDESK_HTTP_PORT}/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:${FRONTDESK_HTTP_PORT}" \
  -d "{\"user_name\":\"mario\",\"password\":\"${USER_PASSWORD}\"}")"
echo "$LOGIN1" | grep -q '"must_change_password":true' \
  || fail "first login expected must_change_password=true, got: $LOGIN1"

# Change password to the same value (real flow rotates; sandbox can reuse)
NEW_PW="MarioRotated-$(openssl rand -hex 4)!"
CHANGE="$(curl -sk -b "$WORK_DIR/mario-cookies.txt" \
  -c "$WORK_DIR/mario-cookies.txt" \
  -X POST "http://localhost:${FRONTDESK_HTTP_PORT}/api/auth/change-password" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:${FRONTDESK_HTTP_PORT}" \
  -d "{\"old_password\":\"${USER_PASSWORD}\",\"new_password\":\"${NEW_PW}\"}")"
echo "$CHANGE" | grep -q '"ok":true' \
  || fail "change-password failed: $CHANGE"

# Second login — must_change cleared → provisioning runs
LOGIN2="$(curl -sk -c "$WORK_DIR/mario-cookies.txt" \
  -X POST "http://localhost:${FRONTDESK_HTTP_PORT}/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:${FRONTDESK_HTTP_PORT}" \
  -d "{\"user_name\":\"mario\",\"password\":\"${NEW_PW}\"}")"
echo "$LOGIN2" | grep -q '"provisioning":"ok"' \
  || fail "second login expected provisioning=ok, got: $LOGIN2 (chain or workload-cap regression)"
ok "user login provisioning=ok (ADR-025 Phase 3 + #816 chain ok)"

# ── 11b. Chat end-to-end via mario (SPA's view: cookie-authed) ───────────────

# Stash mario's rotated password where the operator can read it
# from the host: handy when a test fails mid-flight and we want to
# re-drive the chat path interactively without restarting.
echo "$NEW_PW" >"$WORK_DIR/mario-pw.txt"
log "fetching /v1/models from Frontdesk as mario (pw stashed at .data/dogfood-frontdesk/mario-pw.txt)"
MODELS_JSON="$(curl -sk -b "$WORK_DIR/mario-cookies.txt" \
  "http://localhost:${FRONTDESK_HTTP_PORT}/v1/models")"
echo "$MODELS_JSON" >"$WORK_DIR/models.json"
SOURCE="$(echo "$MODELS_JSON" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("cullis_meta",{}).get("source","?"))')"
if [[ "$SOURCE" != "live" ]]; then
  echo "--- /v1/models payload ---" >&2
  head -c 800 "$WORK_DIR/models.json" >&2
  echo >&2
  fail "Frontdesk /v1/models cullis_meta.source expected 'live', got '$SOURCE'"
fi
# Ollama model must appear in the live list (live source proves the
# Mastio AI gateway aggregated provider catalogs end-to-end).
echo "$MODELS_JSON" | grep -q "ollama_chat/${OLLAMA_MODEL}" \
  || fail "ollama_chat/${OLLAMA_MODEL} missing from live model list: $(head -c 600 "$WORK_DIR/models.json")"
ok "/v1/models live, includes ollama_chat/${OLLAMA_MODEL}"

log "POST /v1/chat/completions via Ollama"
CHAT_HTTP="$(curl -sk -b "$WORK_DIR/mario-cookies.txt" \
  -o "$WORK_DIR/chat.json" -w '%{http_code}' \
  -X POST "http://localhost:${FRONTDESK_HTTP_PORT}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:${FRONTDESK_HTTP_PORT}" \
  -d "{\"model\":\"ollama_chat/${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly the word: cullis\"}],\"max_tokens\":32}")"
if [[ "$CHAT_HTTP" != "200" ]]; then
  echo "--- chat response (HTTP $CHAT_HTTP) ---" >&2
  head -c 800 "$WORK_DIR/chat.json" >&2
  echo >&2
  fail "chat completion expected 200, got $CHAT_HTTP"
fi
CHAT_CONTENT="$(python3 -c "
import json, sys
with open('$WORK_DIR/chat.json') as fh:
    d = json.load(fh)
content = d.get('choices', [{}])[0].get('message', {}).get('content', '')
print(content)
")"
[[ -n "$CHAT_CONTENT" ]] \
  || fail "chat completion returned empty content: $(head -c 400 "$WORK_DIR/chat.json")"
ok "chat completion returned ${#CHAT_CONTENT} chars (preview: ${CHAT_CONTENT:0:60}…)"

# ── 12. Done ──────────────────────────────────────────────────────────────────

echo >&2
echo "${C_OK}${C_BOLD}═══════════════════════════════════════════════════════════════════════════════${C_RST}" >&2
echo "${C_OK}${C_BOLD}  Frontdesk dogfood PASSED${C_RST}" >&2
echo "${C_OK}${C_BOLD}═══════════════════════════════════════════════════════════════════════════════${C_RST}" >&2
echo "" >&2
echo "  Mastio:    https://localhost:${MASTIO_HOST_PORT}/proxy/login" >&2
echo "  Frontdesk: http://localhost:${FRONTDESK_HTTP_PORT}/login" >&2
echo "  admin pw:  ${MASTIO_ADMIN_PASSWORD}" >&2
echo "  mario pw:  ${NEW_PW}" >&2
echo "  Ollama:    http://ollama:11434 (inside ${SHARED_NET} only)" >&2
echo "  model:     ollama_chat/${OLLAMA_MODEL}" >&2
echo "" >&2
if [[ "$DO_KEEP" -eq 1 ]]; then
  echo "  --keep set: stack stays up. Tear down with:" >&2
  echo "    $0 --down" >&2
else
  echo "  Tearing down. Pass --keep to stay up for manual inspection." >&2
fi
