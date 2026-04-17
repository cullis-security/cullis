#!/usr/bin/env bash
# Cullis standalone proxy — smoke test (ADR-006 Fase 1 / PR #4).
#
#   ./standalone_smoke.sh up    # build image, start proxy, seed agents
#   ./standalone_smoke.sh check # full lifecycle: discover → session → send → ack → close
#   ./standalone_smoke.sh down  # stop + volumes gone
#   ./standalone_smoke.sh full  # down + up + check + down
#
# The test proves the "Trojan Horse" claim: a single proxy container
# running in standalone mode (no broker) handles the whole intra-org
# message lifecycle for two locally-enrolled agents, and the audit
# chain is intact at the end.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

COMPOSE="docker compose -p cullis-standalone -f standalone.compose.yml"
PROXY_URL="http://localhost:9110"

# ANSI colors (no-op if not TTY)
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; RESET=$'\033[0m'
else
    BOLD=""; RED=""; GREEN=""; RESET=""
fi

say() { printf "${BOLD}%s${RESET}\n" "$*" >&2; }
ok()  { printf "${GREEN}✓${RESET} %s\n" "$*" >&2; }
die() { printf "${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }


# ── Helpers ────────────────────────────────────────────────────────────────

# Generate an API key for an agent and bcrypt-hash it *inside* the proxy
# container (same hasher the proxy uses at verify time).
seed_agent() {
    local agent_id="$1"

    # generate_api_key returns "sk_local_<agent>_<32hex>" — the only
    # format get_agent_from_api_key accepts. ADR-010 Phase 6b: the
    # Mastio's sole agent registry is ``internal_agents`` — auth
    # (X-API-Key) and discovery (/v1/agents/search) both read from it.
    $COMPOSE exec -T proxy python -c "
import asyncio, os
from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
from mcp_proxy.db import create_agent, init_db
async def main():
    raw = generate_api_key('$agent_id')
    await init_db(os.environ['MCP_PROXY_DATABASE_URL'])
    await create_agent(
        agent_id='$agent_id',
        display_name='$agent_id',
        capabilities=['cap.read','cap.write'],
        api_key_hash=hash_api_key(raw),
    )
    print(raw, end='')
asyncio.run(main())
"
}


# httpie-style: call the proxy with a given key, require 200, return body.
call() {
    local method="$1" path="$2" key="$3" body="${4:-}"
    local args=(-sS -X "$method" "${PROXY_URL}${path}" -H "X-API-Key: $key")
    if [[ -n "$body" ]]; then
        args+=(-H "content-type: application/json" -d "$body")
    fi
    local resp http_code
    resp="$(curl "${args[@]}" -w "\n__HTTP_CODE__%{http_code}")"
    http_code="${resp##*__HTTP_CODE__}"
    resp="${resp%__HTTP_CODE__*}"
    resp="${resp%$'\n'}"
    if [[ "$http_code" != 2* ]]; then
        printf "[%s %s] %s → %s\n" "$method" "$path" "$http_code" "$resp" >&2
        return 1
    fi
    printf "%s" "$resp"
}


# ── Commands ───────────────────────────────────────────────────────────────

cmd_up() {
    say "standalone_smoke: building + starting proxy container"
    $COMPOSE up -d --build --wait
    ok "proxy healthy at $PROXY_URL"
}


cmd_check() {
    say "standalone_smoke: running intra-org lifecycle"

    # 1. Seed two agents with API keys.
    local alice_key bob_key
    alice_key="$(seed_agent alice-bot)"
    bob_key="$(seed_agent bob-bot)"
    ok "seeded alice-bot + bob-bot"

    # 2. Alice discovers bob via /v1/agents/search (proxy-native endpoint).
    local search
    search="$(call GET "/v1/agents/search" "$alice_key")"
    if ! grep -q "alice-bot" <<< "$search"; then
        die "discovery did not return alice-bot (got: $search)"
    fi
    if ! grep -q "bob-bot" <<< "$search"; then
        die "discovery did not return bob-bot (got: $search)"
    fi
    ok "discovery sees both agents with scope=local"

    # 3. Alice opens a session to bob.
    local open_resp session_id
    open_resp="$(call POST "/v1/egress/sessions" "$alice_key" \
        '{"target_agent_id":"bob-bot","target_org_id":"acme","capabilities":["cap.read"]}')"
    session_id="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['session_id'])" "$open_resp")"
    ok "session opened: $session_id"

    # 4. Bob accepts.
    call POST "/v1/egress/sessions/$session_id/accept" "$bob_key" >/dev/null
    ok "session accepted by bob"

    # 5. Alice sends a message (envelope mode — opaque ciphertext).
    local send_resp msg_id
    send_resp="$(call POST "/v1/egress/send" "$alice_key" \
        '{"session_id":"'"$session_id"'","payload":{"hello":"bob","nonce":"smoke42"},"recipient_agent_id":"bob-bot","mode":"envelope"}')"
    msg_id="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['msg_id'])" "$send_resp")"
    ok "message sent: $msg_id"

    # 6. Bob polls and sees exactly one message with smoke42 nonce.
    local poll
    poll="$(call GET "/v1/egress/messages/$session_id" "$bob_key")"
    if ! grep -q "smoke42" <<< "$poll"; then
        die "bob's poll didn't surface the sender's nonce (got: $poll)"
    fi
    ok "bob polled smoke42 payload"

    # 7. Bob acks — row flips to delivered, next poll is empty.
    call POST "/v1/egress/sessions/$session_id/messages/$msg_id/ack" "$bob_key" >/dev/null
    poll="$(call GET "/v1/egress/messages/$session_id" "$bob_key")"
    local count
    count="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['count'])" "$poll")"
    [[ "$count" == "0" ]] || die "post-ack poll still returns count=$count"
    ok "ack recorded, queue empty"

    # 8. Alice closes.
    call POST "/v1/egress/sessions/$session_id/close" "$alice_key" >/dev/null
    ok "session closed"

    # 9. Verify the local audit chain is intact for org=acme.
    local ok_chain
    ok_chain="$($COMPOSE exec -T proxy python -c "
import asyncio, os, sys
from mcp_proxy.db import init_db, dispose_db
from mcp_proxy.local.audit import verify_local_chain
async def main():
    await init_db(os.environ['MCP_PROXY_DATABASE_URL'])
    ok, reason = await verify_local_chain('acme')
    await dispose_db()
    if not ok:
        print('CHAIN_BROKEN:', reason)
        sys.exit(1)
    print('ok')
asyncio.run(main())
")"
    if [[ "$ok_chain" != "ok" ]]; then
        die "audit chain broken: $ok_chain"
    fi
    ok "audit chain intact"

    say "standalone_smoke: PASS — proxy served the full intra-org lifecycle with zero broker."
}


cmd_down() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    ok "teardown done"
}


cmd_full() {
    cmd_down
    cmd_up
    local rc=0
    cmd_check || rc=$?
    if [[ $rc -ne 0 ]]; then
        say "standalone_smoke: FAIL — dumping proxy logs"
        $COMPOSE logs --tail=200 proxy >&2 || true
    fi
    cmd_down
    return $rc
}


case "${1:-}" in
    up)    cmd_up ;;
    check) cmd_check ;;
    down)  cmd_down ;;
    full)  cmd_full ;;
    logs)  $COMPOSE logs --tail=200 "${2:-proxy}" ;;
    *) echo "usage: $0 {up|check|down|full|logs}" >&2; exit 2 ;;
esac
