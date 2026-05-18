#!/usr/bin/env bash
# Sandbox quick-try: full-stack sandbox with Postgres as the Mastio
# persistence layer. Companion to docs/runbooks/postgres-pilot.md.
#
# Equivalent to:
#   docker compose \
#       -f sandbox/docker-compose.yml \
#       -f sandbox/overlays/postgres.yml \
#       --profile full <up|down|status|logs>
#
# Existed because docker-compose.yml hardcodes MCP_PROXY_DATABASE_URL
# at SQLite (proxy-a line 290, proxy-b line 618), so the swap needs
# an overlay file rather than an env-only flip. NOT for production:
# pilot guidance lives in docs/runbooks/postgres-pilot.md.
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=(docker compose -f docker-compose.yml -f overlays/postgres.yml --profile full)

_header() { printf '\n\033[1;36m=== %s ===\033[0m\n\n' "$1"; }

case "${1:-help}" in
    up)
        _header "Sandbox + Postgres overlay, bringing stack up"
        "${COMPOSE[@]}" build --quiet
        "${COMPOSE[@]}" up -d --wait --quiet-pull
        "${COMPOSE[@]}" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
        _header "Verify Mastio dialect"
        echo "Run:  docker compose -f docker-compose.yml -f overlays/postgres.yml logs proxy-a | grep 'Database initialized'"
        echo "Expected: postgresql+asyncpg://...mastio_a"
        ;;
    down)
        _header "Sandbox + Postgres overlay, tearing down"
        "${COMPOSE[@]}" down -v --remove-orphans
        ;;
    status)
        "${COMPOSE[@]}" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
        ;;
    logs)
        shift || true
        "${COMPOSE[@]}" logs "${@:---tail=50}"
        ;;
    psql)
        # Convenience: open psql against the sandbox Postgres.
        docker compose -f docker-compose.yml -f overlays/postgres.yml \
            exec -it postgres psql -U cullis -d "${2:-mastio_a}"
        ;;
    help|*)
        cat <<'EOF'
Usage: sandbox/demo-postgres.sh <command>

Commands:
  up            Build + start sandbox + Postgres overlay (full profile)
  down          Stop and remove containers + volumes
  status        List running services
  logs [svc]    Tail compose logs (default: --tail=50)
  psql [db]     Open psql against the sandbox Postgres (default: mastio_a)
  help          This message

Reference: docs/runbooks/postgres-pilot.md
EOF
        ;;
esac
