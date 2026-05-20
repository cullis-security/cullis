#!/usr/bin/env bash
# Modern dogfood stack — teardown
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cullis-stack}"

KEEP_VOLUMES=0
if [[ "${1:-}" == "--keep-volumes" ]]; then
  KEEP_VOLUMES=1
fi

C_NEU=$'\033[36m'; C_BOLD=$'\033[1m'; C_OK=$'\033[32m'; C_RST=$'\033[0m'
log() { echo "${C_NEU}${C_BOLD}»${C_RST} $*" >&2; }
ok()  { echo "${C_OK}${C_BOLD}✓${C_RST} $*" >&2; }

log "tearing down ${COMPOSE_PROJECT_NAME}"
if [[ "$KEEP_VOLUMES" -eq 1 ]]; then
  docker compose down --remove-orphans >/dev/null 2>&1 || true
else
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
fi
rm -f /tmp/stack-mario-pw /tmp/stack-luigi-pw /tmp/stack-up.err 2>/dev/null || true
ok "down complete"
