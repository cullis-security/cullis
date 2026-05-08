#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — MCP Proxy deployment (org-level gateway + built-in PDP)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Deploys the MCP Proxy for one organization.
#
# Default = standalone Mastio on its own private docker network. The
# Mastio derives its Org CA at first boot and works zero-config; allaccio
# al Court is post-setup via the dashboard. The --shared-broker override
# is only for bringing up the Mastio alongside a Court already running
# on the same docker host (CI fixtures, single-host dev).
#
# Modes (combinable):
#   (default)         standalone Mastio, private docker network
#   --shared-broker   join the broker's docker network (Court must be up)
#   --prod            fail-fast on insecure defaults + prod overlay
#   --down            stop + remove containers
#   --rebuild         rebuild images and restart
#
# Examples:
#   ./deploy_proxy.sh                       # standalone (default)
#   ./deploy_proxy.sh --shared-broker       # join Court on same host
#   ./deploy_proxy.sh --prod                # standalone, prod safety
#   ./deploy_proxy.sh --prod --shared-broker
#   ./deploy_proxy.sh --down
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Distinct compose project name isolates the proxy stack from the broker
# (deploy_broker.sh → cullis-broker). Otherwise fresh clones named `cullis`
# would share docker volumes across stacks and a fresh user would hit
# opaque volume/password collisions (shake-out P0-03).
export COMPOSE_PROJECT_NAME="cullis-proxy"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

# ── docker compose binary ───────────────────────────────────────────────────
# --project-directory keeps relative paths in the compose files (./nginx,
# ./certs, build: .) resolving against the repo root even though the compose
# files themselves now live under deploy/compose/. The base compose file is
# baked into $COMPOSE so callers without an explicit -f keep working.
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose --project-directory $SCRIPT_DIR -f deploy/compose/docker-compose.proxy.yml"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose --project-directory $SCRIPT_DIR -f deploy/compose/docker-compose.proxy.yml"
else
    die "docker compose is not installed"
fi

# ── Parse args ──────────────────────────────────────────────────────────────
print_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Deploys the MCP Proxy for one organization. Default = standalone Mastio
(zero broker dependency). Combine with --down / --rebuild for lifecycle
management, --shared-broker only when a Court is up on the same host.

Options:
  (no flags)                  Standalone Mastio, private docker network
                              (default — no broker required at boot)
  --shared-broker             Join the broker's docker network. Requires
                              the Court compose project to be up.
  --prod                      Production: fail-fast on insecure defaults,
                              requires proxy.env pre-provisioned.
  --down                      Stop and remove containers.
  --rebuild                   Rebuild images and restart.
  --help, -h                  Show this help and exit.

Examples:
  ./deploy_proxy.sh                              # standalone (default)
  ./deploy_proxy.sh --shared-broker              # join Court on same host
  ./deploy_proxy.sh --prod                       # standalone, prod safety
  ./deploy_proxy.sh --prod --shared-broker       # federated prod
  ./deploy_proxy.sh --down                       # stop + remove containers

Legacy --standalone (no-op) is accepted with a deprecation warning so
older runbooks keep running.
EOF
}

ACTION="up"
MODE="development"
SHARED_BROKER=0
for arg in "$@"; do
    case "$arg" in
        --down)          ACTION="down" ;;
        --rebuild)       ACTION="rebuild" ;;
        --prod)          MODE="production" ;;
        --shared-broker) SHARED_BROKER=1 ;;
        --standalone)
            warn "--standalone is the new default — flag is a no-op. Drop it from your scripts."
            ;;
        --help|-h)       print_help; exit 0 ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

# ── Compose file stacking ───────────────────────────────────────────────────
# Default = standalone (private proxy_net + MCP_PROXY_STANDALONE=true
# in the base compose). The shared-broker override layers on broker_net
# + MCP_PROXY_STANDALONE=false.
# Base compose is already in $COMPOSE; here we add only the overlays.
COMPOSE_FILES=""
[[ $SHARED_BROKER -eq 1 ]]   && COMPOSE_FILES="$COMPOSE_FILES -f deploy/compose/docker-compose.proxy.shared-broker.yml"
[[ "$MODE" == "production" ]] && COMPOSE_FILES="$COMPOSE_FILES -f deploy/compose/docker-compose.proxy.prod.yml"

# ── Down early-exit ─────────────────────────────────────────────────────────
if [[ "$ACTION" == "down" ]]; then
    step "Stopping MCP Proxy"
    $COMPOSE $COMPOSE_FILES --env-file deploy/proxy/proxy.env down 2>/dev/null \
        || $COMPOSE $COMPOSE_FILES down
    ok "Proxy stopped"
    exit 0
fi

# ── proxy.env — create if missing, validate in prod ─────────────────────────
step "Environment configuration (proxy.env)"

if [[ ! -f "$SCRIPT_DIR/deploy/proxy/proxy.env" ]]; then
    warn "proxy.env not found — generating one"
    if [[ "$MODE" == "production" ]]; then
        die "--prod requires proxy.env to exist with real values. Run: BROKER_URL=https://broker.example.com PROXY_PUBLIC_URL=https://proxy.myorg.example.com ./scripts/generate-proxy-env.sh --prod"
    fi
    bash "$SCRIPT_DIR/scripts/generate-proxy-env.sh" --defaults
fi

# ── Pre-flight validation for --prod ────────────────────────────────────────
if [[ "$MODE" == "production" ]]; then
    _errors=()
    _load_env() { grep -E "^$1=" "$SCRIPT_DIR/deploy/proxy/proxy.env" 2>/dev/null | head -1 | cut -d= -f2- || true; }

    _admin="$(_load_env MCP_PROXY_ADMIN_SECRET)"
    if [[ -z "$_admin" || "$_admin" == "change-me-in-production" ]]; then
        _errors+=("MCP_PROXY_ADMIN_SECRET is empty or still the dev default — regenerate proxy.env")
    fi

    _signing="$(_load_env MCP_PROXY_DASHBOARD_SIGNING_KEY)"
    if [[ -z "$_signing" ]]; then
        _errors+=("MCP_PROXY_DASHBOARD_SIGNING_KEY is empty — admin sessions will break on every restart")
    fi

    _broker="$(_load_env MCP_PROXY_BROKER_URL)"
    if [[ -z "$_broker" || "$_broker" == "http://broker:8000" ]]; then
        _errors+=("MCP_PROXY_BROKER_URL still points at the dev docker-compose name — set the public broker URL")
    fi
    if [[ "$_broker" == http://* ]]; then
        warn "MCP_PROXY_BROKER_URL uses plain HTTP — production brokers should be HTTPS"
    fi

    _public="$(_load_env MCP_PROXY_PROXY_PUBLIC_URL)"
    if [[ -z "$_public" || "$_public" == "http://localhost:9100" || "$_public" == "https://localhost:9443" ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL still localhost — set the public URL where internal agents reach this proxy")
    fi
    # ADR-014 — production must use HTTPS through the mastio-nginx sidecar.
    if [[ "$_public" == http://* ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL uses plain HTTP — ADR-014 requires HTTPS via the mastio-nginx sidecar (default port 9443)")
    fi

    if [[ ${#_errors[@]} -gt 0 ]]; then
        echo ""
        err "Production proxy.env is not safe to deploy:"
        for e in "${_errors[@]}"; do echo -e "    ${RED}✗${RESET} $e"; done
        echo ""
        die "Fix the issues above and rerun. Aborting before compose up."
    fi
    ok "proxy.env validated for production"
fi

# ── Build + Start ───────────────────────────────────────────────────────────
step "Deploying Cullis MCP Proxy (${MODE}, $([ $SHARED_BROKER -eq 1 ] && echo shared-broker || echo standalone))"

if [[ "$ACTION" == "rebuild" ]]; then
    echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILES --env-file deploy/proxy/proxy.env build --no-cache${RESET}"
    $COMPOSE $COMPOSE_FILES --env-file deploy/proxy/proxy.env build --no-cache
    ok "Images rebuilt"
fi

# --shared-broker assumes the broker compose project is up so its docker
# network is reachable. Bail with a useful error if it isn't, instead of
# letting compose emit "network cullis-broker_default not found".
if [[ $SHARED_BROKER -eq 1 ]]; then
    if ! docker network inspect cullis-broker_default >/dev/null 2>&1; then
        die "--shared-broker requires the broker compose to be up. Either run ./deploy_broker.sh --dev first, or drop --shared-broker for the standalone default."
    fi
fi

echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILES --env-file deploy/proxy/proxy.env up --build -d${RESET}"
$COMPOSE $COMPOSE_FILES --env-file deploy/proxy/proxy.env up --build -d
ok "Containers started"

# ── Wait for health ─────────────────────────────────────────────────────────
step "Waiting for services"

# ADR-014 — the Mastio listens behind the mastio-nginx sidecar on
# 9443 TLS. The sidecar healthcheck (in compose) waits for cert
# material to land on the shared volume, so by the time it's healthy
# the Mastio already booted, ran first-boot cert provisioning, and
# nginx is serving. We poll TLS here with -k because the cert is
# self-signed off the Org CA — operators who care about strict
# verification can extract /var/lib/mastio/nginx-certs/org-ca.crt
# from the mcp-proxy container and pass --cacert.
PROXY_PORT="$(grep -E '^MCP_PROXY_PORT=' "$SCRIPT_DIR/deploy/proxy/proxy.env" 2>/dev/null | cut -d= -f2-)"
PROXY_PORT="${PROXY_PORT:-9443}"

echo -n "  Proxy + nginx "
for i in $(seq 1 60); do
    if curl -skf "https://localhost:${PROXY_PORT}/health" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 60 ]]; then
        echo -e " ${RED}timeout${RESET}"
        warn "Proxy did not become healthy — check logs: $COMPOSE $COMPOSE_FILES logs mcp-proxy mastio-nginx"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────────────
BROKER_URL="$(grep -E '^MCP_PROXY_BROKER_URL=' "$SCRIPT_DIR/deploy/proxy/proxy.env" | cut -d= -f2-)"
PUBLIC_URL="$(grep -E '^MCP_PROXY_PROXY_PUBLIC_URL=' "$SCRIPT_DIR/deploy/proxy/proxy.env" | cut -d= -f2-)"

echo ""
echo -e "${GREEN}${BOLD}MCP Proxy deployed (${MODE}).${RESET}"
echo ""
echo -e "  ${BOLD}Proxy dashboard${RESET}  ${GRAY}${PUBLIC_URL}/proxy/login${RESET}"
echo -e "  ${BOLD}Health${RESET}           ${GRAY}${PUBLIC_URL}/health${RESET}"
echo -e "  ${BOLD}Broker uplink${RESET}    ${GRAY}${BROKER_URL}${RESET}"
echo -e "  ${BOLD}PDP webhook${RESET}      ${GRAY}${PUBLIC_URL}/pdp/policy  (broker reaches this)${RESET}"
echo ""
if [[ "$MODE" == "development" ]]; then
    echo "  Next steps (development):"
    echo "    1. Open ${PUBLIC_URL}/proxy/login"
    echo "       (browser will warn — the TLS cert is signed by your local"
    echo "        Org CA, not a public CA. Accept the self-signed warning.)"
    echo "    2. Paste broker URL + invite token from the broker admin"
    echo "    3. Register your organization (certs auto-generated)"
    echo "    4. Wait for approval, then create agents"
else
    echo "  Next steps (production):"
    echo "    1. ADR-014 — the mastio-nginx sidecar terminates TLS on :${PROXY_PORT}"
    echo "       with a server cert signed by your Org CA. Front-door TLS for the"
    echo "       public hostname is up to your edge load-balancer (LB → sidecar :${PROXY_PORT})."
    echo "    2. DNS: ${PUBLIC_URL}  →  this host"
    echo "    3. Share the dashboard URL with your org admin (credentials in proxy.env)"
    echo "    4. Broker admin generates an attach-ca or join invite for you"
fi
echo ""
echo "  Useful commands:"
echo "    $COMPOSE $COMPOSE_FILES logs -f                # tail logs"
echo "    $COMPOSE $COMPOSE_FILES ps                     # container status"
echo "    $0 --down                                      # stop"
echo ""
