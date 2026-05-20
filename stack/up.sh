#!/usr/bin/env bash
# Modern dogfood stack — bring up + post-bootstrap wiring (Ollama, users)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Config knobs (override via env) ──────────────────────────────────────────

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cullis-stack}"
OLLAMA_HOST_URL="${OLLAMA_HOST_URL:-http://host.docker.internal:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:0.5b}"
MASTIO_A_ADMIN_SECRET="stack-mastio-a-admin"
MASTIO_B_ADMIN_SECRET="stack-mastio-b-admin"
MASTIO_A_DASHBOARD_PW="stack-mastio-a-dashboard"
FRONTDESK_ADMIN_SECRET="stack-frontdesk-admin-secret"
MARIO_INITIAL_PW="MarioStack-$(openssl rand -hex 4)!"
MARIO_NEW_PW="MarioRotated-$(openssl rand -hex 4)!"
ALICE_INITIAL_PW="AliceStack-$(openssl rand -hex 4)!"
ALICE_NEW_PW="AliceRotated-$(openssl rand -hex 4)!"
WORK_DIR="/tmp/cullis-stack"
mkdir -p "$WORK_DIR"

# ── Colours ──────────────────────────────────────────────────────────────────

C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OK=$'\033[32m'
C_ERR=$'\033[31m'; C_NEU=$'\033[36m'; C_RST=$'\033[0m'
log()  { echo "${C_NEU}${C_BOLD}»${C_RST} $*" >&2; }
ok()   { echo "${C_OK}${C_BOLD}✓${C_RST} $*" >&2; }
fail() { echo "${C_ERR}${C_BOLD}✗${C_RST} $*" >&2; exit 1; }
dim()  { echo "${C_DIM}$*${C_RST}" >&2; }

# ── 0. Prerequisites ─────────────────────────────────────────────────────────

log "checking prerequisites"
command -v docker >/dev/null || fail "docker not installed"
docker compose version >/dev/null 2>&1 || fail "docker compose v2 not available"

# Ollama on host — warning only. Smoke B1 (chat) will fail if absent,
# but the rest of the stack (federation, A2A, MCP+DB) works fine.
OLLAMA_PROBE="${OLLAMA_HOST_URL/host.docker.internal/127.0.0.1}"
if curl -fsS --max-time 3 "${OLLAMA_PROBE}/api/tags" >/dev/null 2>&1; then
  OLLAMA_HAS_MODEL="$(curl -fsS "${OLLAMA_PROBE}/api/tags" \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
names = [m.get('name','') for m in d.get('models',[])]
print('yes' if any(n.startswith('${OLLAMA_MODEL}') or n == '${OLLAMA_MODEL}' for n in names) else 'no')
")"
  if [[ "$OLLAMA_HAS_MODEL" == "yes" ]]; then
    ok "Ollama healthy at ${OLLAMA_PROBE} (${OLLAMA_MODEL} pulled)"
  else
    dim "warning: Ollama running but model ${OLLAMA_MODEL} not pulled. Run: ollama pull ${OLLAMA_MODEL}"
  fi
else
  dim "warning: Ollama not reachable at ${OLLAMA_PROBE} — chat scenario (B1) will fail. Start Ollama with: ollama serve"
fi

# ── 1. Bring base stack up ───────────────────────────────────────────────────

log "bringing up stack (project=${COMPOSE_PROJECT_NAME})"
docker compose up -d --wait 2>/tmp/stack-up.err || {
  echo "--- compose up stderr ---" >&2
  cat /tmp/stack-up.err >&2
  fail "compose up failed"
}
ok "base stack healthy"

# ── 2. Verify bootstrap completed ────────────────────────────────────────────

BOOT_STATUS="$(docker compose ps -a bootstrap --format json 2>/dev/null \
  | python3 -c 'import json,sys; rows=[json.loads(l) for l in sys.stdin if l.strip()]; print(rows[0]["State"] if rows else "missing")')"
BOOT_MASTIO_STATUS="$(docker compose ps -a bootstrap-mastio --format json 2>/dev/null \
  | python3 -c 'import json,sys; rows=[json.loads(l) for l in sys.stdin if l.strip()]; print(rows[0]["State"] if rows else "missing")')"
[[ "$BOOT_STATUS" == "exited" ]] || fail "bootstrap not exited cleanly (state=$BOOT_STATUS)"
[[ "$BOOT_MASTIO_STATUS" == "exited" ]] || fail "bootstrap-mastio not exited cleanly (state=$BOOT_MASTIO_STATUS)"
ok "bootstrap + bootstrap-mastio exited cleanly"

# ── 3. Configure Ollama AI provider on Mastio A ──────────────────────────────

log "registering Ollama provider on Mastio A (api_base=${OLLAMA_HOST_URL})"
# PUT /v1/admin/ai-providers/{provider} — admin-secret authed.
SAVE_RESP="$(curl -sk -w '\nHTTP_CODE:%{http_code}' \
  -X PUT "http://localhost:9100/v1/admin/ai-providers/ollama" \
  -H "X-Admin-Secret: ${MASTIO_A_ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d "{\"creds\":{\"api_base\":\"${OLLAMA_HOST_URL}\"},\"enabled\":true,\"updated_by\":\"stack-up\"}")"
SAVE_CODE="$(echo "$SAVE_RESP" | tail -n1 | sed 's/HTTP_CODE://')"
if [[ ! "$SAVE_CODE" =~ ^2 ]]; then
  echo "--- ai-provider save body ---" >&2
  echo "$SAVE_RESP" | sed '$d' >&2
  fail "ai-providers/ollama save failed (HTTP $SAVE_CODE) — endpoint may have moved"
fi
ok "Mastio A: ollama provider registered"

# Probe upstream — confirms shared bridge + LiteLLM wiring
PROBE_JSON="$(curl -sk -X POST \
  -H "X-Admin-Secret: ${MASTIO_A_ADMIN_SECRET}" \
  "http://localhost:9100/v1/admin/ai-providers/ollama/test" 2>/dev/null || echo '{}')"
if echo "$PROBE_JSON" | grep -q '"status":"ok"'; then
  ok "Mastio A ↔ Ollama probe ok"
else
  dim "Mastio A ↔ Ollama probe non-ok: $PROBE_JSON"
fi

# ── 4. Create local users on Mastios (ADR-025) ───────────────────────────────

# ── 4a. Frontdesk Connector enrollment (workload) ───────────────────────────

log "triggering /setup to mint Frontdesk bootstrap bearer"
curl -sk -o /dev/null "http://localhost:7777/setup"
sleep 1
SETUP_BEARER="$(docker compose logs frontdesk-connector 2>&1 \
  | grep -A2 'Frontdesk setup bearer' \
  | tail -n3 | head -n1 | tr -d ' ')"
[[ "${#SETUP_BEARER}" -ge 32 ]] || fail "setup bearer not minted (got ${#SETUP_BEARER} chars). Connector log:
$(docker compose logs --tail=20 frontdesk-connector)"
ok "setup bearer minted (${#SETUP_BEARER} chars)"

log "submitting Frontdesk enrollment (workload, site=mastio-a-nginx:9443)"
ENROLL_HTTP="$(curl -sk -o "$WORK_DIR/setup-resp.html" -w '%{http_code}' \
  -X POST "http://localhost:7777/setup" \
  -H "Authorization: Bearer ${SETUP_BEARER}" \
  -H "Origin: http://localhost:7777" \
  -d "site_url=https://mastio-a-nginx:9443" \
  -d "requester_name=stack" \
  -d "requester_email=stack@cullis.local" \
  -d "reason=modern stack dogfood" \
  -d "verify_tls_off=1")"
[[ "$ENROLL_HTTP" == "303" ]] || fail "POST /setup expected 303, got $ENROLL_HTTP — body: $(head -c 300 "$WORK_DIR/setup-resp.html")"
ok "Frontdesk enrollment posted to Mastio A"

# Verify pending row exists with principal_type=workload
PENDING_PT="$(docker compose exec -T mastio-a python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
row = c.execute(\"SELECT principal_type FROM pending_enrollments WHERE status='pending' ORDER BY created_at DESC LIMIT 1\").fetchone()
print(row[0] if row else 'MISSING')
" 2>/dev/null)"
[[ "$PENDING_PT" == "workload" ]] || fail "pending_enrollments.principal_type expected 'workload', got '$PENDING_PT'"
ok "pending enrollment landed with principal_type=workload"

# Mastio admin login (cookie + CSRF) + approve
log "approving enrollment via Mastio A dashboard"
LOGIN_HTTP="$(curl -sk -c "$WORK_DIR/mastio-cookies.txt" \
  -o "$WORK_DIR/login.html" -w '%{http_code}' \
  -X POST "http://localhost:9100/proxy/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://localhost:9100" \
  -d "password=${MASTIO_A_DASHBOARD_PW}")"
[[ "$LOGIN_HTTP" =~ ^30[37]$ ]] || fail "Mastio /proxy/login expected 30x, got $LOGIN_HTTP"

PENDING_SID="$(docker compose exec -T mastio-a python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
row = c.execute(\"SELECT session_id FROM pending_enrollments WHERE status='pending' ORDER BY created_at DESC LIMIT 1\").fetchone()
print(row[0] if row else 'MISSING')
" 2>/dev/null)"
[[ "$PENDING_SID" != "MISSING" ]] || fail "no pending session_id to approve"

CSRF_TOK="$(python3 -c "
import json
with open('$WORK_DIR/mastio-cookies.txt') as fh:
    for line in fh:
        if 'mcp_proxy_session' not in line:
            continue
        raw = line.rstrip().split('\t')[-1].strip('\"')
        body = raw.rsplit('.', 1)[0]
        body = body.replace('\\\\054', ',').replace('\\\\\"', '\"')
        print(json.loads(body).get('csrf_token', ''))
        break
")"
[[ -n "$CSRF_TOK" ]] || fail "no CSRF token extracted from session cookie"

APPROVE_HTTP="$(curl -sk -b "$WORK_DIR/mastio-cookies.txt" \
  -o "$WORK_DIR/approve-resp.html" -w '%{http_code}' \
  -X POST "http://localhost:9100/proxy/enrollments/${PENDING_SID}/approve" \
  -H "Origin: http://localhost:9100" \
  --data-urlencode "csrf_token=${CSRF_TOK}" \
  --data-urlencode "agent_id=frontdesk" \
  --data-urlencode "capabilities=" \
  --data-urlencode "groups=")"
[[ "$APPROVE_HTTP" =~ ^30[37]$ ]] || fail "approve expected 30x, got $APPROVE_HTTP — body: $(head -c 300 "$WORK_DIR/approve-resp.html")"

APPROVED_STATUS="$(docker compose exec -T mastio-a python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
row = c.execute('SELECT status FROM pending_enrollments WHERE session_id = ?', ('${PENDING_SID}',)).fetchone()
print(row[0] if row else 'MISSING')
" 2>/dev/null)"
[[ "$APPROVED_STATUS" == "approved" ]] || fail "pending row status expected 'approved', got '$APPROVED_STATUS'"
ok "Frontdesk enrollment approved (workload cert minted)"

log "triggering Connector save_identity"
curl -sk "http://localhost:7777/api/status" >/dev/null
sleep 2

# Verify the Connector has the workload cert (2 PEM blocks = leaf + intermediate, #816)
CRT_BLOCKS="$(docker compose exec -T frontdesk-connector sh -c 'grep -c "BEGIN CERTIFICATE" /home/cullis/.cullis/profiles/frontdesk/identity/agent.crt 2>/dev/null' | tr -d ' ')"
[[ "$CRT_BLOCKS" == "2" ]] || dim "warning: agent.crt PEM blocks=$CRT_BLOCKS (expected 2)"
ok "Connector identity saved (PEM blocks=$CRT_BLOCKS)"

log "restarting Connector to mount the ADR-025 Phase 3 provisioner"
docker compose restart frontdesk-connector >/dev/null 2>&1
# Wait /api/status comes back (no proxy enforce yet, just liveness)
deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
  if curl -fsS --max-time 2 "http://localhost:7777/api/status" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
ok "Connector restarted with provisioner mounted"

# ── 4b. Create user mario via Mastio dashboard (forwarded to Frontdesk) ─────

log "creating user mario@orga via Mastio A dashboard (forwarded to Frontdesk users.db)"
echo "$MARIO_INITIAL_PW" >"$WORK_DIR/mario-initial-pw"
echo "$MARIO_NEW_PW" >"$WORK_DIR/mario-pw"
CREATE_HTTP="$(curl -sk -b "$WORK_DIR/mastio-cookies.txt" \
  -D "$WORK_DIR/create-headers.txt" \
  -o "$WORK_DIR/create-resp.html" \
  -w '%{http_code}' \
  -X POST "http://localhost:9100/proxy/users/create" \
  -H "Origin: http://localhost:9100" \
  --data-urlencode "csrf_token=${CSRF_TOK}" \
  --data-urlencode "user_name=mario" \
  --data-urlencode "display_name=Mario Rossi" \
  --data-urlencode "password=${MARIO_INITIAL_PW}" \
  --data-urlencode "password_confirm=${MARIO_INITIAL_PW}")"
if [[ ! "$CREATE_HTTP" =~ ^30[37]$ ]]; then
  echo "--- create response ---" >&2
  head -c 400 "$WORK_DIR/create-resp.html" >&2
  echo >&2
  fail "user create expected 30x, got $CREATE_HTTP"
fi
CREATE_LOC="$(grep -i '^location:' "$WORK_DIR/create-headers.txt" | head -n1)"
if echo "$CREATE_LOC" | grep -qi 'error='; then
  fail "user create landed with error: $CREATE_LOC"
fi
# Confirm row reached Frontdesk users.db
FD_HAS_MARIO="$(docker compose exec -T frontdesk-connector python -c "
import sqlite3
c = sqlite3.connect('/home/cullis/.cullis/profiles/frontdesk/users.db')
row = c.execute('SELECT user_name FROM local_users WHERE user_name = \"mario\"').fetchone()
print('yes' if row else 'no')
" 2>/dev/null)"
[[ "$FD_HAS_MARIO" == "yes" ]] || fail "Frontdesk users.db missing mario (Mastio→Frontdesk forward failed silently)"
ok "user mario created end-to-end (Mastio dashboard → Frontdesk users.db)"

# ── 4c. mario first-login → change-password → second-login (CSR provisioning) ─

log "user mario first login (must_change_password=true expected)"
LOGIN1="$(curl -sk -c "$WORK_DIR/mario-cookies.txt" \
  -X POST "http://localhost:7777/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:7777" \
  -d "{\"user_name\":\"mario\",\"password\":\"${MARIO_INITIAL_PW}\"}")"
echo "$LOGIN1" | grep -q '"must_change_password":true' \
  || fail "first login expected must_change_password=true, got: $LOGIN1"
ok "first login: must_change_password=true"

log "user mario change-password"
CHANGE="$(curl -sk -b "$WORK_DIR/mario-cookies.txt" -c "$WORK_DIR/mario-cookies.txt" \
  -X POST "http://localhost:7777/api/auth/change-password" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:7777" \
  -d "{\"old_password\":\"${MARIO_INITIAL_PW}\",\"new_password\":\"${MARIO_NEW_PW}\"}")"
echo "$CHANGE" | grep -q '"ok":true' \
  || fail "change-password failed: $CHANGE"
ok "password rotated"

log "user mario second login (provisioning=ok expected → CSR minted)"
LOGIN2="$(curl -sk -c "$WORK_DIR/mario-cookies.txt" \
  -X POST "http://localhost:7777/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:7777" \
  -d "{\"user_name\":\"mario\",\"password\":\"${MARIO_NEW_PW}\"}")"
echo "$LOGIN2" | grep -q '"provisioning":"ok"' \
  || fail "second login expected provisioning=ok, got: $LOGIN2"
ok "mario UserPrincipal cert minted, login session active"

# ── 4c-bis. Second Frontdesk user alice (multi-user isolation regression) ────

log "creating user alice@orga via Mastio A dashboard (forwarded to Frontdesk)"
echo "$ALICE_NEW_PW" >"$WORK_DIR/alice-pw"
CREATE_HTTP="$(curl -sk -b "$WORK_DIR/mastio-cookies.txt" \
  -D "$WORK_DIR/create-alice-headers.txt" \
  -o "$WORK_DIR/create-alice-resp.html" \
  -w '%{http_code}' \
  -X POST "http://localhost:9100/proxy/users/create" \
  -H "Origin: http://localhost:9100" \
  --data-urlencode "csrf_token=${CSRF_TOK}" \
  --data-urlencode "user_name=alice" \
  --data-urlencode "display_name=Alice Bianchi" \
  --data-urlencode "password=${ALICE_INITIAL_PW}" \
  --data-urlencode "password_confirm=${ALICE_INITIAL_PW}")"
[[ "$CREATE_HTTP" =~ ^30[37]$ ]] || fail "alice create expected 30x, got $CREATE_HTTP"
CREATE_LOC="$(grep -i '^location:' "$WORK_DIR/create-alice-headers.txt" | head -n1)"
echo "$CREATE_LOC" | grep -qi 'error=' && fail "alice create landed with error: $CREATE_LOC"
ok "user alice created (Mastio dashboard → Frontdesk users.db)"

log "alice first login + change-password + second login"
LOGIN1="$(curl -sk -c "$WORK_DIR/alice-cookies.txt" \
  -X POST "http://localhost:7777/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:7777" \
  -d "{\"user_name\":\"alice\",\"password\":\"${ALICE_INITIAL_PW}\"}")"
echo "$LOGIN1" | grep -q '"must_change_password":true' \
  || fail "alice first login expected must_change_password=true, got: $LOGIN1"
CHANGE="$(curl -sk -b "$WORK_DIR/alice-cookies.txt" -c "$WORK_DIR/alice-cookies.txt" \
  -X POST "http://localhost:7777/api/auth/change-password" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:7777" \
  -d "{\"old_password\":\"${ALICE_INITIAL_PW}\",\"new_password\":\"${ALICE_NEW_PW}\"}")"
echo "$CHANGE" | grep -q '"ok":true' || fail "alice change-password failed: $CHANGE"
LOGIN2="$(curl -sk -c "$WORK_DIR/alice-cookies.txt" \
  -X POST "http://localhost:7777/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:7777" \
  -d "{\"user_name\":\"alice\",\"password\":\"${ALICE_NEW_PW}\"}")"
echo "$LOGIN2" | grep -q '"provisioning":"ok"' \
  || fail "alice second login expected provisioning=ok, got: $LOGIN2"
ok "alice UserPrincipal cert minted, login session active"

# ── 4d. Luigi on Mastio B (no Frontdesk, direct admin) ───────────────────────

log "creating user luigi@orgb on Mastio B (UserPrincipal row, no password)"
LUIGI_RESP="$(curl -sk -w '\nHTTP_CODE:%{http_code}' \
  -X POST "http://localhost:9200/v1/admin/users" \
  -H "X-Admin-Secret: ${MASTIO_B_ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d "{\"user_name\":\"luigi\",\"display_name\":\"Luigi Verdi\",\"reach\":\"both\"}")"
LUIGI_CODE="$(echo "$LUIGI_RESP" | tail -n1 | sed 's/HTTP_CODE://')"
if [[ ! "$LUIGI_CODE" =~ ^(200|201|409)$ ]]; then
  echo "--- user create body ---" >&2
  echo "$LUIGI_RESP" | sed '$d' >&2
  dim "luigi create non-2xx (HTTP $LUIGI_CODE) — skipping"
else
  ok "user luigi@orgb ready (Mastio B)"
fi

# ── 5. Summary ───────────────────────────────────────────────────────────────

echo >&2
echo "${C_OK}${C_BOLD}═══════════════════════════════════════════════════════════════════════════════${C_RST}" >&2
echo "${C_OK}${C_BOLD}  Stack ready${C_RST}" >&2
echo "${C_OK}${C_BOLD}═══════════════════════════════════════════════════════════════════════════════${C_RST}" >&2
echo "" >&2
echo "  Court:        http://localhost:8000/health" >&2
echo "  Mastio A:     http://localhost:9100  (TLS: https://localhost:9443)" >&2
echo "  Mastio B:     http://localhost:9200  (TLS: https://localhost:9543)" >&2
echo "  Frontdesk:      http://localhost:7777" >&2
echo "  Admin secret A: ${MASTIO_A_ADMIN_SECRET}" >&2
echo "  Admin pw A:     ${MASTIO_A_DASHBOARD_PW}" >&2
echo "  Admin secret B: ${MASTIO_B_ADMIN_SECRET}" >&2
echo "  Ollama:         ${OLLAMA_HOST_URL} (model: ${OLLAMA_MODEL})" >&2
echo "  mario pw:       ${MARIO_NEW_PW}  (stashed at ${WORK_DIR}/mario-pw)" >&2
echo "  alice pw:       ${ALICE_NEW_PW}  (stashed at ${WORK_DIR}/alice-pw)" >&2
echo "" >&2
echo "  Next: ./stack/smoke.sh" >&2
