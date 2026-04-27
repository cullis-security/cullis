#!/usr/bin/env bash
# Cullis standalone proxy — smoke test (ADR-006 Fase 1, ADR-014 PR-B).
#
#   ./standalone_smoke.sh up    # build + start proxy + nginx + seed agents
#   ./standalone_smoke.sh check # full lifecycle: discover → session → send → ack → close
#   ./standalone_smoke.sh down  # stop + volumes gone
#   ./standalone_smoke.sh full  # down + up + check + down
#
# The test proves the "Trojan Horse" claim: a single proxy container
# (plus the nginx sidecar that terminates mTLS) running in standalone
# mode handles the whole intra-org message lifecycle for two locally-
# enrolled agents over the production wire (https://localhost:9443 with
# client cert), and the audit chain is intact at the end.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

COMPOSE="docker compose -p cullis-standalone -f standalone.compose.yml"
PROXY_URL="https://localhost:9443"
CERTS_DIR="$HERE/.smoke-certs"

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

# Pull the Org CA (public cert) out of the nginx_certs volume so curl
# can verify the TLS server cert. Idempotent — short-circuits if
# ``$CERTS_DIR/org-ca.crt`` already exists.
fetch_org_ca() {
    if [[ -f "$CERTS_DIR/org-ca.crt" ]]; then
        return 0
    fi
    mkdir -p "$CERTS_DIR"
    chmod 700 "$CERTS_DIR"
    $COMPOSE exec -T proxy cat /var/lib/mastio/nginx-certs/org-ca.crt \
        > "$CERTS_DIR/org-ca.crt"
    ok "fetched Org CA from proxy first-boot"
}

# Mint a Connector-shaped cert+key for ``$1`` agent_id by calling into
# the proxy's own cert factory inside the container, then pull the
# bytes out to the host so curl can present them at the TLS handshake.
# Also writes the row into ``internal_agents`` with the matching
# ``cert_pem`` so the dep's leaf-DER pin succeeds.
seed_agent() {
    local agent_id="$1"
    local org_id="acme"
    local canonical_id="${org_id}::${agent_id}"

    # Mint inside the container, drop cert+key under /tmp/<agent>.{crt,key}
    # so we can pull them out via ``compose cp`` without inventing a
    # stdout splitter on the host.
    $COMPOSE exec -T proxy python -c "
import asyncio, os, sys
from mcp_proxy.db import init_db, create_agent
from mcp_proxy.egress.agent_manager import AgentManager
async def main():
    await init_db(os.environ['MCP_PROXY_DATABASE_URL'])
    mgr = AgentManager(org_id='${org_id}', trust_domain='cullis.local')
    if not await mgr.load_org_ca_from_config():
        sys.exit('Org CA missing from proxy_config — first-boot likely failed')
    cert_pem, key_pem = mgr._generate_agent_cert('${agent_id}')
    await create_agent(
        agent_id='${canonical_id}',
        display_name='${agent_id}',
        capabilities=['cap.read', 'cap.write'],
        api_key_hash='\$2b\$12\$placeholder',
        cert_pem=cert_pem,
    )
    with open('/tmp/${agent_id}.crt', 'w') as f:
        f.write(cert_pem)
    with open('/tmp/${agent_id}.key', 'w') as f:
        f.write(key_pem)
    os.chmod('/tmp/${agent_id}.key', 0o600)
asyncio.run(main())
"

    # Pull cert + key out to the host so curl can read them. ``compose
    # cp`` resolves the service name to its container, no need to look
    # up the container id by hand.
    $COMPOSE cp "proxy:/tmp/${agent_id}.crt" "$CERTS_DIR/${agent_id}.crt"
    $COMPOSE cp "proxy:/tmp/${agent_id}.key" "$CERTS_DIR/${agent_id}.key"
    chmod 600 "$CERTS_DIR/${agent_id}.key"
}


# httpie-style: call the proxy with a given agent's cert+key, require
# 200, return body. nginx terminates TLS on 9443, validates the client
# cert against the Org CA, forwards to mcp-proxy with X-SSL-Client-Cert
# set — same wire production uses.
call() {
    local method="$1" path="$2" agent="$3" body="${4:-}"
    local args=(
        -sS
        --cacert "$CERTS_DIR/org-ca.crt"
        --cert   "$CERTS_DIR/$agent.crt"
        --key    "$CERTS_DIR/$agent.key"
        --resolve "mastio.local:9443:127.0.0.1"
        -X "$method"
        "${PROXY_URL/localhost/mastio.local}${path}"
    )
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
    say "standalone_smoke: building + starting proxy + nginx sidecar"
    if ! $COMPOSE up -d --build --wait; then
        say "standalone_smoke: bring-up failed — dumping proxy + nginx logs"
        $COMPOSE logs --tail=200 proxy >&2 || true
        $COMPOSE logs --tail=200 mastio-nginx >&2 || true
        return 1
    fi
    ok "stack healthy at $PROXY_URL"
}


cmd_check() {
    say "standalone_smoke: running intra-org lifecycle"

    # 0. Pull Org CA the proxy minted at first-boot so curl can verify
    #    the server cert nginx is presenting.
    fetch_org_ca

    # 1. Seed two agents — DB row + Org-CA-signed cert+key on host.
    seed_agent alice-bot
    seed_agent bob-bot
    ok "seeded alice-bot + bob-bot with Org-CA-signed certs"

    # 2. Alice discovers bob via /v1/agents/search (proxy-native endpoint).
    local search
    search="$(call GET "/v1/agents/search" alice-bot)"
    if ! grep -q "alice-bot" <<< "$search"; then
        die "discovery did not return alice-bot (got: $search)"
    fi
    if ! grep -q "bob-bot" <<< "$search"; then
        die "discovery did not return bob-bot (got: $search)"
    fi
    ok "discovery sees both agents with scope=local"

    # 3. Alice opens a session to bob.
    local open_resp session_id
    open_resp="$(call POST "/v1/egress/sessions" alice-bot \
        '{"target_agent_id":"acme::bob-bot","target_org_id":"acme","capabilities":["cap.read"]}')"
    session_id="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['session_id'])" "$open_resp")"
    ok "session opened: $session_id"

    # 4. Bob accepts.
    call POST "/v1/egress/sessions/$session_id/accept" bob-bot >/dev/null
    ok "session accepted by bob"

    # 5. Alice sends a message (envelope mode — opaque ciphertext).
    local send_resp msg_id
    send_resp="$(call POST "/v1/egress/send" alice-bot \
        '{"session_id":"'"$session_id"'","payload":{"hello":"bob","nonce":"smoke42"},"recipient_agent_id":"acme::bob-bot","mode":"envelope"}')"
    msg_id="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['msg_id'])" "$send_resp")"
    ok "message sent: $msg_id"

    # 6. Bob polls and sees exactly one message with smoke42 nonce.
    local poll
    poll="$(call GET "/v1/egress/messages/$session_id" bob-bot)"
    if ! grep -q "smoke42" <<< "$poll"; then
        die "bob's poll didn't surface the sender's nonce (got: $poll)"
    fi
    ok "bob polled smoke42 payload"

    # 7. Bob acks — row flips to delivered, next poll is empty.
    call POST "/v1/egress/sessions/$session_id/messages/$msg_id/ack" bob-bot >/dev/null
    poll="$(call GET "/v1/egress/messages/$session_id" bob-bot)"
    local count
    count="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['count'])" "$poll")"
    [[ "$count" == "0" ]] || die "post-ack poll still returns count=$count"
    ok "ack recorded, queue empty"

    # 8. Alice closes.
    call POST "/v1/egress/sessions/$session_id/close" alice-bot >/dev/null
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

    say "standalone_smoke: PASS — proxy + mastio-nginx served the full intra-org lifecycle over mTLS with zero broker."
}


cmd_down() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$CERTS_DIR"
    ok "teardown done"
}


cmd_full() {
    cmd_down
    cmd_up
    local rc=0
    cmd_check || rc=$?
    if [[ $rc -ne 0 ]]; then
        say "standalone_smoke: FAIL — dumping proxy + nginx logs"
        $COMPOSE logs --tail=200 proxy >&2 || true
        $COMPOSE logs --tail=200 mastio-nginx >&2 || true
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
