#!/usr/bin/env bash
# Modern dogfood stack — 4 end-to-end scenario assertions.
#
# Scenarios:
#   B1. Ollama chat completion via Mastio A AI gateway (admin endpoint)
#   B2. A2A cross-org oneshot (agent-a → orgb::agent-b via Court federation)
#   B3. MCP tool call: send_message (DB write)
#   B4. MCP tool call: list_messages (DB read)
#   B5. mario (user) → Frontdesk → Mastio AI gateway → Ollama qwen2.5:0.5b
#   B6. cross-user isolation: alice chat ≠ mario chat (Finding #16 regression
#       — single-router fork on _per_user_credentials, no workload-cred leak)
#
# Target wall: <60s on a warm stack.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cullis-stack}"
MASTIO_A_ADMIN_SECRET="stack-mastio-a-admin"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:0.5b}"

C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OK=$'\033[32m'
C_ERR=$'\033[31m'; C_NEU=$'\033[36m'; C_RST=$'\033[0m'

PASS=0
FAIL=0
SKIP=0

run() {
  local name="$1"; shift
  echo "" >&2
  echo "${C_NEU}${C_BOLD}»${C_RST} ${name}" >&2
  if "$@"; then
    echo "  ${C_OK}${C_BOLD}PASS${C_RST}  ${name}" >&2
    PASS=$((PASS + 1))
  else
    echo "  ${C_ERR}${C_BOLD}FAIL${C_RST}  ${name}" >&2
    FAIL=$((FAIL + 1))
  fi
}

# ── B1. Ollama chat completion via Mastio A AI gateway ───────────────────────

scenario_ollama_chat() {
  # /v1/admin/ai-providers/ollama/test drives a real chat completion
  # round-trip through LiteLLM → Ollama and returns {status, latency_ms, detail}.
  # No DPoP / user identity required — admin secret only.
  local http_code body status
  http_code="$(curl -sk -o /tmp/stack-chat.json -w '%{http_code}' \
    -X POST "http://localhost:9100/v1/admin/ai-providers/ollama/test" \
    -H "X-Admin-Secret: ${MASTIO_A_ADMIN_SECRET}")"
  if [[ "$http_code" != "200" ]]; then
    echo "${C_DIM}    http=${http_code} body=$(head -c 200 /tmp/stack-chat.json)${C_RST}" >&2
    return 1
  fi
  body="$(cat /tmp/stack-chat.json)"
  status="$(echo "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null)"
  if [[ "$status" != "ok" ]]; then
    echo "${C_DIM}    test non-ok: $(echo "$body" | head -c 300)${C_RST}" >&2
    return 1
  fi
  echo "${C_DIM}    ollama test ok: $(echo "$body" | head -c 200)${C_RST}" >&2
  return 0
}

# ── B2. A2A cross-org oneshot (agent-a → agent-b) ───────────────────────────

scenario_a2a_cross_org() {
  local out
  out="$(docker compose exec -T \
    -e TARGET_AGENT_ID=orgb::agent-b \
    agent-a python /app/scenarios/oneshot_cross_org.py 2>&1)"
  if echo "$out" | grep -qE '(✓|done|enqueued|delivered|^OK)'; then
    echo "${C_DIM}    $(echo "$out" | tail -n5 | tr '\n' ' ' | head -c 300)${C_RST}" >&2
    return 0
  fi
  echo "${C_DIM}    $(echo "$out" | tail -n10)${C_RST}" >&2
  return 1
}

# ── B3. MCP tool call: send_message (DB write) ──────────────────────────────

scenario_mcp_send_message() {
  local out
  out="$(docker compose exec -T \
    -e MCP_TOOL_NAME=send_message \
    -e "MCP_TOOL_ARGS={\"to\":\"orgb::agent-b\",\"body\":\"hello via mcp $(date +%s)\"}" \
    agent-a python /app/scenarios/mcp_call_local.py 2>&1)"
  # Fail on any ✗ marker; require an explicit success token.
  if echo "$out" | grep -q '✗'; then
    echo "${C_DIM}    $(echo "$out" | tail -n8 | tr -d '\n' | head -c 400)${C_RST}" >&2
    return 1
  fi
  if echo "$out" | grep -qE '(MCP aggregator exercised end-to-end|\\"ok\\":\s*true|\\"id\\":\s*[0-9]+)'; then
    echo "${C_DIM}    $(echo "$out" | tail -n5 | tr '\n' ' ' | head -c 300)${C_RST}" >&2
    return 0
  fi
  echo "${C_DIM}    $(echo "$out" | tail -n10)${C_RST}" >&2
  return 1
}

# ── B4. MCP tool call: list_messages (DB read) ──────────────────────────────

scenario_mcp_list_messages() {
  local out
  out="$(docker compose exec -T \
    -e MCP_TOOL_NAME=list_messages \
    -e "MCP_TOOL_ARGS={\"for_agent\":\"orgb::agent-b\"}" \
    agent-a python /app/scenarios/mcp_call_local.py 2>&1)"
  if echo "$out" | grep -q '✗'; then
    echo "${C_DIM}    $(echo "$out" | tail -n8 | tr -d '\n' | head -c 400)${C_RST}" >&2
    return 1
  fi
  if echo "$out" | grep -qE '("messages":|"for_agent":|tool returned)'; then
    echo "${C_DIM}    $(echo "$out" | tail -n5 | tr '\n' ' ' | head -c 400)${C_RST}" >&2
    return 0
  fi
  echo "${C_DIM}    $(echo "$out" | tail -n10)${C_RST}" >&2
  return 1
}

# ── Run ──────────────────────────────────────────────────────────────────────

# ── B5. mario (Frontdesk user) → chat completion via Ollama qwen2.5:0.5b ────

scenario_mario_chat_via_frontdesk() {
  local cookies="/tmp/cullis-stack/mario-cookies.txt"
  local mario_pw_file="/tmp/cullis-stack/mario-pw"
  if [[ ! -s "$cookies" || ! -s "$mario_pw_file" ]]; then
    echo "${C_DIM}    mario cookies or pw missing (up.sh did not provision Frontdesk)${C_RST}" >&2
    return 1
  fi
  # Re-auth (cookie may be stale from up.sh's restart)
  local mario_pw http_code
  mario_pw="$(cat "$mario_pw_file")"
  curl -sk -c "$cookies" \
    -X POST "http://localhost:7777/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost:7777" \
    -d "{\"user_name\":\"mario\",\"password\":\"${mario_pw}\"}" >/dev/null

  # Optional sanity: /v1/models should be live with ollama_chat/qwen2.5:0.5b
  curl -sk -b "$cookies" \
    "http://localhost:7777/v1/models" >/tmp/cullis-stack/models.json
  if ! grep -q "ollama_chat/${OLLAMA_MODEL}" /tmp/cullis-stack/models.json 2>/dev/null; then
    echo "${C_DIM}    /v1/models missing ${OLLAMA_MODEL}: $(head -c 300 /tmp/cullis-stack/models.json)${C_RST}" >&2
    return 1
  fi

  # Actual chat completion
  http_code="$(curl -sk -b "$cookies" \
    -o /tmp/cullis-stack/mario-chat.json -w '%{http_code}' \
    -X POST "http://localhost:7777/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost:7777" \
    -d "{\"model\":\"ollama_chat/${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply in one short sentence: what is Cullis?\"}],\"max_tokens\":48}")"
  if [[ "$http_code" != "200" ]]; then
    echo "${C_DIM}    http=${http_code} body=$(head -c 300 /tmp/cullis-stack/mario-chat.json)${C_RST}" >&2
    return 1
  fi
  local content
  content="$(python3 -c "
import json
d = json.load(open('/tmp/cullis-stack/mario-chat.json'))
print(d.get('choices',[{}])[0].get('message',{}).get('content',''))
" 2>/dev/null)"
  if [[ -z "$content" ]]; then
    echo "${C_DIM}    empty content: $(head -c 300 /tmp/cullis-stack/mario-chat.json)${C_RST}" >&2
    return 1
  fi
  echo "${C_DIM}    qwen2.5:0.5b → mario: ${content:0:120}${C_RST}" >&2
  return 0
}

# ── B6. Cross-user isolation (alice ≠ mario, Finding #16 regression) ────────

scenario_cross_user_isolation() {
  local alice_cookies="/tmp/cullis-stack/alice-cookies.txt"
  local alice_pw_file="/tmp/cullis-stack/alice-pw"
  local mario_cookies="/tmp/cullis-stack/mario-cookies.txt"
  local mario_pw_file="/tmp/cullis-stack/mario-pw"
  if [[ ! -s "$alice_cookies" || ! -s "$alice_pw_file" ]]; then
    echo "${C_DIM}    alice cookies/pw missing (up.sh did not provision alice)${C_RST}" >&2
    return 1
  fi

  # Re-auth both users (cookies may have rotated since up.sh)
  local alice_pw mario_pw
  alice_pw="$(cat "$alice_pw_file")"
  mario_pw="$(cat "$mario_pw_file")"
  curl -sk -c "$alice_cookies" \
    -X POST "http://localhost:7777/api/auth/login" \
    -H "Content-Type: application/json" -H "Origin: http://localhost:7777" \
    -d "{\"user_name\":\"alice\",\"password\":\"${alice_pw}\"}" >/dev/null
  curl -sk -c "$mario_cookies" \
    -X POST "http://localhost:7777/api/auth/login" \
    -H "Content-Type: application/json" -H "Origin: http://localhost:7777" \
    -d "{\"user_name\":\"mario\",\"password\":\"${mario_pw}\"}" >/dev/null

  # Both users do a chat
  local alice_http mario_http
  alice_http="$(curl -sk -b "$alice_cookies" \
    -o /tmp/cullis-stack/alice-chat.json -w '%{http_code}' \
    -X POST "http://localhost:7777/v1/chat/completions" \
    -H "Content-Type: application/json" -H "Origin: http://localhost:7777" \
    -d "{\"model\":\"ollama_chat/${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"say one word\"}],\"max_tokens\":16}")"
  mario_http="$(curl -sk -b "$mario_cookies" \
    -o /tmp/cullis-stack/mario-chat2.json -w '%{http_code}' \
    -X POST "http://localhost:7777/v1/chat/completions" \
    -H "Content-Type: application/json" -H "Origin: http://localhost:7777" \
    -d "{\"model\":\"ollama_chat/${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"say one word\"}],\"max_tokens\":16}")"
  if [[ "$alice_http" != "200" || "$mario_http" != "200" ]]; then
    echo "${C_DIM}    chat http: alice=$alice_http mario=$mario_http${C_RST}" >&2
    return 1
  fi

  # ASSERT 1: local_user_principals has 2 distinct rows with distinct cert_thumbprints
  local assert_out
  assert_out="$(docker compose exec -T mastio-a python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
rows = c.execute(\"SELECT user_name, principal_id, cert_thumbprint FROM local_user_principals WHERE user_name IN ('alice','mario') ORDER BY user_name\").fetchall()
if len(rows) != 2:
    print('FAIL rows=', rows); raise SystemExit(1)
alice, mario = rows
if alice[1] == mario[1]:
    print('FAIL same principal_id', alice, mario); raise SystemExit(2)
if not alice[2] or not mario[2]:
    print('FAIL missing cert_thumbprint', alice, mario); raise SystemExit(3)
if alice[2] == mario[2]:
    print('FAIL same cert_thumbprint — workload-cred leak!', alice, mario); raise SystemExit(4)
print('OK', alice[1], mario[1], alice[2][:12], mario[2][:12])
" 2>&1)"
  if ! echo "$assert_out" | grep -q '^OK '; then
    echo "${C_DIM}    principal isolation failed: ${assert_out}${C_RST}" >&2
    return 1
  fi
  echo "${C_DIM}    principals: ${assert_out#OK }${C_RST}" >&2

  # ASSERT 2: chat audit rows carry the UserPrincipal as agent_id (NOT the
  # workload Frontdesk Connector identity — that would be the Finding #16
  # leak). For egress_llm_chat, agent_id must be ``orga::user::<name>``.
  assert_out="$(docker compose exec -T mastio-a python -c "
import sqlite3
c = sqlite3.connect('/data/mcp_proxy.db')
rows = c.execute(\"\"\"
    SELECT agent_id, COUNT(*)
    FROM audit_log
    WHERE action = 'egress_llm_chat'
    GROUP BY agent_id
    ORDER BY agent_id
\"\"\").fetchall()
users = {r[0] for r in rows}
if 'orga::user::alice' not in users:
    print('FAIL no alice chat audit', rows); raise SystemExit(1)
if 'orga::user::mario' not in users:
    print('FAIL no mario chat audit', rows); raise SystemExit(2)
# Finding #16 regression: must NOT find the Frontdesk workload identity
# (orga::frontdesk) attributed to chat calls — that would mean the chat
# routed under workload creds instead of forking on the user.
leak = [a for a in users if 'user::' not in a and a not in ('admin',)]
if leak:
    print('FAIL chat under non-user principal', leak); raise SystemExit(3)
print('OK chat-audit per-user', rows)
" 2>&1)"
  if ! echo "$assert_out" | grep -q '^OK '; then
    echo "${C_DIM}    audit isolation failed: ${assert_out}${C_RST}" >&2
    return 1
  fi
  echo "${C_DIM}    ${assert_out}${C_RST}" >&2

  return 0
}

run "B1. Ollama chat completion via Mastio A AI gateway" scenario_ollama_chat
run "B2. A2A cross-org oneshot (agent-a → orgb::agent-b)" scenario_a2a_cross_org
run "B3. MCP send_message (DB write)" scenario_mcp_send_message
run "B4. MCP list_messages (DB read)" scenario_mcp_list_messages
run "B5. mario → Frontdesk → Ollama qwen2.5:0.5b" scenario_mario_chat_via_frontdesk
run "B6. Cross-user isolation (alice ≠ mario, Finding #16)" scenario_cross_user_isolation

# ── Summary ──────────────────────────────────────────────────────────────────

echo "" >&2
echo "${C_BOLD}════════════════════════════════════════════════════════════════════════${C_RST}" >&2
if [[ "$FAIL" -eq 0 ]]; then
  echo "  ${C_OK}${C_BOLD}[smoke] PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP}${C_RST}" >&2
else
  echo "  ${C_ERR}${C_BOLD}[smoke] PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP}${C_RST}" >&2
fi
echo "${C_BOLD}════════════════════════════════════════════════════════════════════════${C_RST}" >&2

exit $((FAIL > 0 ? 1 : 0))
