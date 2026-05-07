#!/usr/bin/env bash
# Insurance demo orchestration.
#
#   run.sh seed                      provision the cast on top of reference
#   run.sh frontdesk                 bring up Asia-Pacific Frontdesk container overlay
#   run.sh trigger-night-reporter    one-tick A2U from the overnight bot
#   run.sh start-ticket-bot          background daemon for U2A request/response
#   run.sh stop-ticket-bot           kill the daemon
#   run.sh urls                      print recording-ready URLs
#   run.sh down                      tear down frontdesk overlay
#   run.sh status                    diagnostic — show component health
#   run.sh prep-ca                   copy Mediterranean Org CA out of reference state
#                                    volume to local disk (one-shot)
#
# Prerequisites:
#   1. ``cd reference && ./demo.sh full`` already ran successfully
#   2. ``imp/official_sandbox/.env`` has ANTHROPIC_API_KEY (gitignored)
#   3. ``cullis-connector`` SDK installed in the active venv
#
# Memory:
#   - feedback_dogfood_before_demo.md — always end-to-end smoke before
#     declaring a demo "ready"
#   - feedback_internal_docs_local.md — the bots, seed, and overlay live
#     here in scenarios/insurance-demo/, not in scripts/ (public)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFERENCE_DIR="$(cd "$HERE/../.." && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
STATE_DIR="$REPO_ROOT/state/insurance-demo"
ANTHROPIC_ENV_FILE="$REPO_ROOT/imp/official_sandbox/.env"
PIDS_DIR="$STATE_DIR/pids"

mkdir -p "$STATE_DIR" "$PIDS_DIR"

BOLD='\033[1m'; CYAN='\033[36m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'

_h()    { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"; }
_ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
_warn() { echo -e "  ${YELLOW}⚠${RESET} $1"; }
_fail() { echo -e "  ${RED}✗${RESET} $1"; }

_load_env() {
    if [ -f "$ANTHROPIC_ENV_FILE" ]; then
        export ANTHROPIC_API_KEY="$(grep '^ANTHROPIC_API_KEY=' "$ANTHROPIC_ENV_FILE" | cut -d= -f2- | tr -d '"')"
    fi
}

# ── Subcommands ─────────────────────────────────────────────────────────

cmd_prep_ca() {
    _h "Copying Mediterranean Org CA from reference state volume"
    # The reference compose's bootstrap container persists Org CAs into
    # the bootstrap-state volume. Copy them out for our seed.py to mint
    # agent certs against.
    local container
    container=$(docker compose -f "$REFERENCE_DIR/docker-compose.yml" ps -q bootstrap | head -1)
    if [ -z "$container" ]; then
        _warn "bootstrap container not running — starting transiently"
        docker compose -f "$REFERENCE_DIR/docker-compose.yml" up -d bootstrap || true
        container=$(docker compose -f "$REFERENCE_DIR/docker-compose.yml" ps -q bootstrap | head -1)
    fi
    if [ -z "$container" ]; then
        _fail "no bootstrap container available; cannot extract CA"
        exit 1
    fi
    docker cp "$container:/state/mediterranean/ca-cert.pem" "$STATE_DIR/mediterranean-ca.pem"
    docker cp "$container:/state/mediterranean/ca-key.pem"  "$STATE_DIR/mediterranean-ca.key"
    chmod 600 "$STATE_DIR/mediterranean-ca.key"
    _ok "Mediterranean Org CA at $STATE_DIR/mediterranean-ca.{pem,key}"
}

cmd_seed() {
    _load_env
    _h "Seeding insurance-demo cast"
    if [ ! -f "$STATE_DIR/mediterranean-ca.pem" ]; then
        _warn "Mediterranean Org CA missing — running prep-ca first"
        cmd_prep_ca
    fi
    python3 "$HERE/seed/seed.py"
}

cmd_frontdesk() {
    _h "Bringing up Asia-Pacific Frontdesk container"
    if [ ! -f "$HERE/compose.frontdesk.yml" ]; then
        _warn "compose.frontdesk.yml not present yet — manual scaffold pending"
        _warn "use ../packaging/frontdesk-bundle/ as the source for now:"
        _warn "  cd $REPO_ROOT/packaging/frontdesk-bundle"
        _warn "  cp frontdesk.env.example frontdesk.env"
        _warn "  edit frontdesk.env: set CULLIS_FRONTDESK_ORG_ID=asia-pacific"
        _warn "  docker compose --env-file frontdesk.env up -d"
        return 0
    fi
    docker compose -f "$REFERENCE_DIR/docker-compose.yml" \
                   -f "$HERE/compose.frontdesk.yml" up -d frontdesk-asia-pacific
    _ok "frontdesk-asia-pacific up — http://localhost:8090"
}

cmd_trigger_night_reporter() {
    _load_env
    _h "Triggering night-reporter one tick"
    python3 "$HERE/bots/night_reporter.py" --demo
}

cmd_start_ticket_bot() {
    _load_env
    _h "Starting ticket-bot daemon"
    if [ -f "$PIDS_DIR/ticket-bot.pid" ] && \
       kill -0 "$(cat "$PIDS_DIR/ticket-bot.pid")" 2>/dev/null; then
        _warn "ticket-bot already running (pid $(cat "$PIDS_DIR/ticket-bot.pid"))"
        return 0
    fi
    nohup python3 "$HERE/bots/ticket_bot.py" --watch \
        > "$STATE_DIR/ticket-bot.log" 2>&1 &
    echo $! > "$PIDS_DIR/ticket-bot.pid"
    _ok "ticket-bot pid $(cat "$PIDS_DIR/ticket-bot.pid") — log $STATE_DIR/ticket-bot.log"
}

cmd_stop_ticket_bot() {
    _h "Stopping ticket-bot daemon"
    if [ ! -f "$PIDS_DIR/ticket-bot.pid" ]; then
        _warn "no pid file — was it ever started?"
        return 0
    fi
    local pid
    pid=$(cat "$PIDS_DIR/ticket-bot.pid")
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid"
        sleep 0.5
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" || true
        _ok "ticket-bot pid $pid stopped"
    else
        _warn "ticket-bot pid $pid no longer running"
    fi
    rm -f "$PIDS_DIR/ticket-bot.pid"
}

cmd_urls() {
    _h "Recording-ready URLs"
    cat <<EOF
  ${GREEN}Cullis Chat (claim-officer)${RESET}    http://localhost:9100/chat?user=officer
  ${GREEN}Cullis Chat (claim-manager)${RESET}    http://localhost:9100/chat?user=manager
  ${GREEN}Asia-Pacific Frontdesk (liaison)${RESET}      http://localhost:8090?user=liaison
  ${GREEN}Mediterranean Mastio admin${RESET}              http://localhost:9100/admin
  ${GREEN}Asia-Pacific Mastio admin${RESET}             http://localhost:9200/admin
  ${GREEN}Court federation dashboard${RESET}     http://localhost:8000/dashboard
  ${GREEN}Grafana audit + traffic${RESET}        http://localhost:3000  (admin/admin)
  ${GREEN}MCP claims-db (intra-org)${RESET}      mediterranean::resource::mcp::claims-db

  Recording sequence (60-90s):
    1. Open Mediterranean Mastio admin — show Users + Agents + Workloads + Resources
    2. ./run.sh trigger-night-reporter  (verbose output for the recording)
    3. Open Cullis Chat as claim-officer — see the night-reporter's report
    4. Switch to claim-manager — receive operatore's escalation
    5. claim-manager sends @ticket-bot a request — see ticket id come back
    6. claim-manager sends cross-org to counterparty-liaison
    7. Switch to Asia-Pacific Frontdesk — Kenji Watanabe sees the cross-org request

  Each step has visible audit chain entries on Mediterranean Mastio + Asia-Pacific Mastio + Court.
EOF
}

cmd_down() {
    _h "Tearing down Frontdesk overlay"
    if [ -f "$HERE/compose.frontdesk.yml" ]; then
        docker compose -f "$REFERENCE_DIR/docker-compose.yml" \
                       -f "$HERE/compose.frontdesk.yml" down frontdesk-asia-pacific || true
    fi
    cmd_stop_ticket_bot || true
    _ok "frontdesk overlay down (reference stack untouched)"
}

cmd_status() {
    _h "Insurance demo status"
    for svc in broker proxy-a proxy-b mcp-catalog mcp-inventory; do
        if docker compose -f "$REFERENCE_DIR/docker-compose.yml" ps "$svc" 2>/dev/null | grep -q "Up"; then
            _ok "$svc — running"
        else
            _warn "$svc — not running (run reference/demo.sh full)"
        fi
    done
    if [ -f "$PIDS_DIR/ticket-bot.pid" ] && \
       kill -0 "$(cat "$PIDS_DIR/ticket-bot.pid")" 2>/dev/null; then
        _ok "ticket-bot daemon — pid $(cat "$PIDS_DIR/ticket-bot.pid")"
    else
        _warn "ticket-bot daemon — not running"
    fi
    if [ -f "$STATE_DIR/agents/night-reporter/agent.pem" ]; then
        _ok "night-reporter identity — provisioned"
    else
        _warn "night-reporter identity — missing (run ./run.sh seed)"
    fi
}

# ── Dispatcher ──────────────────────────────────────────────────────────

case "${1:-help}" in
    seed)                     cmd_seed ;;
    frontdesk)                cmd_frontdesk ;;
    trigger-night-reporter)   cmd_trigger_night_reporter ;;
    start-ticket-bot)         cmd_start_ticket_bot ;;
    stop-ticket-bot)          cmd_stop_ticket_bot ;;
    urls)                     cmd_urls ;;
    down)                     cmd_down ;;
    status)                   cmd_status ;;
    prep-ca)                  cmd_prep_ca ;;
    help|--help|-h|*)
        sed -n '3,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# //;s/^#//' ;;
esac
