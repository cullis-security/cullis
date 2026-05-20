#!/usr/bin/env bash
# Modern dogfood stack — single-entry wrapper.
#
# Usage:
#   ./stack/demo.sh              full cycle: up + smoke (default)
#   ./stack/demo.sh up           full cycle (alias)
#   ./stack/demo.sh smoke        run smoke against an already-up stack
#   ./stack/demo.sh down         teardown + drop volumes
#   ./stack/demo.sh restart      down + up + smoke
#   ./stack/demo.sh status       docker compose ps + healthcheck summary
#   ./stack/demo.sh logs [svc]   tail logs (all services or one)
#
# Exit code: 0 if up.sh + smoke both pass, non-zero otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cullis-stack}"

C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OK=$'\033[32m'
C_ERR=$'\033[31m'; C_NEU=$'\033[36m'; C_RST=$'\033[0m'

banner() {
  echo "" >&2
  echo "${C_NEU}${C_BOLD}═══════════════════════════════════════════════════════════════════════════════${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}  $*${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}═══════════════════════════════════════════════════════════════════════════════${C_RST}" >&2
}

cmd_up_and_smoke() {
  banner "[1/2] Bring up stack"
  if ! "$SCRIPT_DIR/up.sh"; then
    echo "${C_ERR}${C_BOLD}up.sh failed — aborting${C_RST}" >&2
    return 1
  fi

  banner "[2/2] Run smoke (5 E2E scenarios)"
  if ! "$SCRIPT_DIR/smoke.sh"; then
    echo "${C_ERR}${C_BOLD}smoke failed${C_RST}" >&2
    return 1
  fi

  banner "${C_OK}DEMO READY"
  echo "  Stack up + all scenarios PASS. Inspect: ./demo.sh status" >&2
  echo "  Stop: ./demo.sh down" >&2
  return 0
}

cmd_smoke_only() {
  exec "$SCRIPT_DIR/smoke.sh"
}

cmd_down() {
  exec "$SCRIPT_DIR/down.sh" "$@"
}

cmd_restart() {
  "$SCRIPT_DIR/down.sh" || true
  cmd_up_and_smoke
}

cmd_status() {
  banner "Service state"
  docker compose ps -a --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' 2>&1
  echo "" >&2
  banner "Endpoints"
  echo "  Court:        http://localhost:8000/health"
  echo "  Mastio A:     http://localhost:9100/health   (TLS https://localhost:9443/health)"
  echo "  Mastio B:     http://localhost:9200/health   (TLS https://localhost:9543/health)"
  echo "  Frontdesk:    http://localhost:7777/api/status"
  echo "  MCP messages: docker compose exec mcp-messages curl -s http://localhost:9500/healthz"
  echo "  Ollama:       http://172.17.0.1:11434/api/tags  (host bind)"
  echo ""
  echo "  Stashed:"
  echo "    /tmp/cullis-stack/mario-pw"
  echo "    /tmp/cullis-stack/mastio-cookies.txt"
  echo "    /tmp/cullis-stack/mario-cookies.txt"
}

cmd_logs() {
  if [[ $# -gt 0 ]]; then
    exec docker compose logs --tail=200 -f "$@"
  fi
  exec docker compose logs --tail=200 -f
}

case "${1:-up}" in
  up|"")        shift 2>/dev/null || true; cmd_up_and_smoke ;;
  smoke|test)   cmd_smoke_only ;;
  down|teardown) shift; cmd_down "$@" ;;
  restart)      cmd_restart ;;
  status|ps)    cmd_status ;;
  logs)         shift; cmd_logs "$@" ;;
  -h|--help|help)
    sed -n '/^# Usage:/,/^# Exit code/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  *)
    echo "unknown subcommand: $1" >&2
    echo "Try: $0 --help" >&2
    exit 2 ;;
esac
