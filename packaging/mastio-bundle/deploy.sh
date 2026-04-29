#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Mastio — image-based deploy (no source tree required)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Pulls the published Mastio image from GHCR and brings up the Mastio +
# nginx sidecar via docker-compose. The Mastio derives its Org CA at
# first boot and runs as a self-contained mini-broker (ADR-006). The
# --shared-broker overlay opts into federation when a Court is up on
# the same docker host.
#
# Pin a release with CULLIS_MASTIO_VERSION=0.3.0 ./deploy.sh
# (defaults to "latest" — fine for dev, pin in production).
#
# Modes (combinable):
#   (default)         standalone Mastio, private docker network
#   --shared-broker   join the broker's docker network (Court must be up)
#   --prod            fail-fast on insecure defaults + prod overlay
#   --down            stop + remove containers
#   --pull            re-pull image (otherwise pulled on first up)
#
# Examples:
#   ./deploy.sh                                # standalone (default)
#   CULLIS_MASTIO_VERSION=0.3.0 ./deploy.sh    # pinned version
#   ./deploy.sh --shared-broker                # join Court on same host
#   ./deploy.sh --prod                         # standalone, prod safety
#   ./deploy.sh --down                         # stop + remove
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export COMPOSE_PROJECT_NAME="cullis-mastio"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    die "docker compose is not installed"
fi

print_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Deploys the Cullis Mastio from the published image (no source tree
required). Default = standalone, zero broker dependency at boot.

Options:
  (no flags)                  Standalone Mastio, private docker network
  --shared-broker             Join the broker's docker network. Requires
                              the Court compose project to be up.
  --prod                      Production: fail-fast on insecure defaults,
                              requires proxy.env pre-provisioned.
  --down                      Stop and remove containers.
  --pull                      Force-pull the image before starting.
  --upgrade <version>         Pin CULLIS_MASTIO_VERSION in proxy.env to
                              <version>, pull the new image, and recreate
                              containers in-place. Volumes (DB, certs)
                              are preserved. Equivalent to:
                                  ./deploy.sh --down
                                  edit proxy.env: CULLIS_MASTIO_VERSION=…
                                  ./deploy.sh --pull
                              packaged as one command so a non-tech
                              operator never has to edit env by hand.
  --help, -h                  Show this help and exit.

Environment:
  CULLIS_MASTIO_VERSION       Image tag to pull (default: "latest").
                              Pin to a specific release in production.

Examples:
  ./deploy.sh                                    # standalone (default)
  CULLIS_MASTIO_VERSION=0.3.0 ./deploy.sh        # pinned version
  ./deploy.sh --shared-broker                    # join Court on same host
  ./deploy.sh --prod                             # standalone, prod safety
  ./deploy.sh --upgrade 0.3.0-rc3                # bump image + restart
  ./deploy.sh --down                             # stop + remove
EOF
}

ACTION="up"
MODE="development"
SHARED_BROKER=0
FORCE_PULL=0
UPGRADE_TO=""
# Manual loop because ``--upgrade <version>`` needs to consume the
# next positional arg. Keeps the existing single-token flags working
# without pulling in getopt.
while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
        --down)          ACTION="down"; shift ;;
        --pull)          FORCE_PULL=1; shift ;;
        --prod)          MODE="production"; shift ;;
        --shared-broker) SHARED_BROKER=1; shift ;;
        --upgrade)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--upgrade requires a version (e.g. --upgrade 0.3.0-rc3)"
            UPGRADE_TO="$1"
            FORCE_PULL=1
            shift
            ;;
        --upgrade=*)
            UPGRADE_TO="${arg#--upgrade=}"
            [[ -n "$UPGRADE_TO" ]] || die "--upgrade= requires a value"
            FORCE_PULL=1
            shift
            ;;
        --help|-h)       print_help; exit 0 ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

COMPOSE_FILES="-f docker-compose.yml"
[[ $SHARED_BROKER -eq 1 ]]    && COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.shared-broker.yml"
[[ "$MODE" == "production" ]] && COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.prod.yml"

if [[ "$ACTION" == "down" ]]; then
    step "Stopping Cullis Mastio"
    $COMPOSE $COMPOSE_FILES --env-file proxy.env down 2>/dev/null \
        || $COMPOSE $COMPOSE_FILES down
    ok "Mastio stopped"
    exit 0
fi

# ── proxy.env — create if missing, validate in prod ─────────────────────────
step "Environment configuration (proxy.env)"

if [[ ! -f "$SCRIPT_DIR/proxy.env" ]]; then
    warn "proxy.env not found — generating one"
    if [[ "$MODE" == "production" ]]; then
        die "--prod requires proxy.env to exist with real values. Run: BROKER_URL=https://broker.example.com PROXY_PUBLIC_URL=https://mastio.myorg.example.com ./generate-proxy-env.sh --prod"
    fi
    bash "$SCRIPT_DIR/generate-proxy-env.sh" --defaults

    # Critical: agents validate DPoP htu against MCP_PROXY_PROXY_PUBLIC_URL.
    # Without an explicit public URL the laptop default (localhost:9443) is
    # baked in, and any agent reaching the Mastio over a non-localhost
    # hostname (Docker host on a LAN, internal DNS, public hostname) hits
    # 401 ``Invalid DPoP proof: htu mismatch`` on every egress. Ask up
    # front so the operator never finds out post-deploy.
    echo ""
    echo "  ${BOLD}Where will agents reach this Mastio?${RESET}"
    echo "    ${GRAY}- Laptop quick-try: just press Enter (uses https://localhost:9443)${RESET}"
    echo "    ${GRAY}- Internal server / VM: enter the public URL agents resolve at${RESET}"
    echo "    ${GRAY}  e.g. https://mastio.acme.local  or  https://192.168.10.42:9443${RESET}"
    echo "    ${GRAY}- Internet-facing: the LB/ingress hostname${RESET}"
    echo "    ${GRAY}  e.g. https://mastio.myorg.example.com${RESET}"
    echo ""
    read -rp "  Public URL [https://localhost:9443]: " _public_url
    _public_url="${_public_url:-https://localhost:9443}"

    # Strip any pre-existing line and re-add (proxy.env from the
    # generator may already carry an empty one).
    sed -i.bak '/^#*[[:space:]]*MCP_PROXY_PROXY_PUBLIC_URL=/d' "$SCRIPT_DIR/proxy.env"
    rm -f "$SCRIPT_DIR/proxy.env.bak"
    echo "MCP_PROXY_PROXY_PUBLIC_URL=$_public_url" >> "$SCRIPT_DIR/proxy.env"
    ok "proxy.env: MCP_PROXY_PROXY_PUBLIC_URL=$_public_url"

    # Extract the hostname (no scheme, no port) and bake it into the
    # nginx server cert SAN list. Without this, an agent that connects
    # to ``https://mastio.acme.local:9443`` with verify_tls=True fails
    # the TLS handshake — the cert only carries the default
    # ``mastio.local,localhost`` SANs and the hostname doesn't match.
    # ``sed`` strips the scheme and port; the result is empty for the
    # localhost default, in which case we keep the SAN at its default.
    _public_host="$(echo "$_public_url" | sed -E 's|^https?://||; s|:[0-9]+$||; s|/.*$||')"
    if [[ -n "$_public_host" && "$_public_host" != "localhost" ]]; then
        sed -i.bak '/^#*[[:space:]]*MCP_PROXY_NGINX_SAN=/d' "$SCRIPT_DIR/proxy.env"
        rm -f "$SCRIPT_DIR/proxy.env.bak"
        echo "MCP_PROXY_NGINX_SAN=${_public_host},mastio.local,localhost" >> "$SCRIPT_DIR/proxy.env"
        ok "proxy.env: MCP_PROXY_NGINX_SAN=${_public_host},mastio.local,localhost"
    fi
fi

if [[ "$MODE" == "production" ]]; then
    _errors=()
    _load_env() { grep -E "^$1=" "$SCRIPT_DIR/proxy.env" 2>/dev/null | head -1 | cut -d= -f2- || true; }

    _admin="$(_load_env MCP_PROXY_ADMIN_SECRET)"
    if [[ -z "$_admin" || "$_admin" == "change-me-in-production" ]]; then
        _errors+=("MCP_PROXY_ADMIN_SECRET is empty or still the dev default — regenerate proxy.env")
    fi

    _signing="$(_load_env MCP_PROXY_DASHBOARD_SIGNING_KEY)"
    if [[ -z "$_signing" ]]; then
        _errors+=("MCP_PROXY_DASHBOARD_SIGNING_KEY is empty — admin sessions will break on every restart")
    fi

    _public="$(_load_env MCP_PROXY_PROXY_PUBLIC_URL)"
    if [[ -z "$_public" ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL is empty in production — set the public URL where internal agents reach this Mastio (e.g. https://mastio.myorg.example.com)")
    elif [[ "$_public" == "https://localhost:9443" || "$_public" == "http://localhost:9100" ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL still localhost — set the public URL where internal agents reach this Mastio")
    elif [[ "$_public" == http://* ]]; then
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

# ── --upgrade: pin the requested version into proxy.env ────────────────────
# We rewrite ``CULLIS_MASTIO_VERSION`` BEFORE the pull/up so the compose
# expansion uses the new tag in this run AND the next plain ``./deploy.sh``
# does too — operators don't expect the version to silently revert if they
# forget the env var on a later restart.
if [[ -n "$UPGRADE_TO" ]]; then
    step "Upgrading Cullis Mastio to ${UPGRADE_TO}"
    if [[ ! -f "$SCRIPT_DIR/proxy.env" ]]; then
        die "proxy.env not found — run ./deploy.sh once before --upgrade"
    fi
    sed -i.bak '/^#*[[:space:]]*CULLIS_MASTIO_VERSION=/d' "$SCRIPT_DIR/proxy.env"
    rm -f "$SCRIPT_DIR/proxy.env.bak"
    echo "CULLIS_MASTIO_VERSION=${UPGRADE_TO}" >> "$SCRIPT_DIR/proxy.env"
    ok "proxy.env: CULLIS_MASTIO_VERSION=${UPGRADE_TO}"
    # Export so this very run sees the new pin without a re-source.
    export CULLIS_MASTIO_VERSION="$UPGRADE_TO"
    # Stop the running stack BEFORE the port pre-flight below — without
    # this, the port-9443 check sees our own existing nginx sidecar
    # bound to it and refuses to continue. Volumes (DB + mastio-nginx
    # certs) are preserved by ``compose down``, so the upgrade comes
    # back up with the same Org CA + admin secret + enrolled agents.
    $COMPOSE $COMPOSE_FILES --env-file proxy.env down 2>/dev/null \
        || $COMPOSE $COMPOSE_FILES down
    ok "Stopped existing stack — preparing rc${UPGRADE_TO} bring-up"
fi

# ── Pre-flight: host port not already in use ───────────────────────────────
_host_port="$(grep -E '^MCP_PROXY_PORT=' "$SCRIPT_DIR/proxy.env" 2>/dev/null | cut -d= -f2-)"
_host_port="${_host_port:-9443}"
if command -v ss >/dev/null 2>&1 && ss -tlnH "sport = :${_host_port}" 2>/dev/null | grep -q .; then
    err "Host port ${_host_port} is already in use — another service is bound there."
    err "Override with MCP_PROXY_PORT=<free-port> in proxy.env, and update"
    err "MCP_PROXY_PROXY_PUBLIC_URL to use the same port (otherwise agents 401)."
    die "Refusing to start — fix the port conflict first."
fi

# ── Pull + Start ────────────────────────────────────────────────────────────
step "Deploying Cullis Mastio (${MODE}, $([ $SHARED_BROKER -eq 1 ] && echo shared-broker || echo standalone))"

VERSION="${CULLIS_MASTIO_VERSION:-latest}"
echo -e "  Image: ${GRAY}ghcr.io/cullis-security/cullis-mastio:${VERSION}${RESET}"

if [[ $FORCE_PULL -eq 1 ]]; then
    echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILES --env-file proxy.env pull${RESET}"
    $COMPOSE $COMPOSE_FILES --env-file proxy.env pull
    ok "Image pulled"
fi

if [[ $SHARED_BROKER -eq 1 ]]; then
    if ! docker network inspect cullis-broker_default >/dev/null 2>&1; then
        die "--shared-broker requires the Court compose to be up. Either bring the Court online first, or drop --shared-broker for the standalone default."
    fi
fi

echo -e "  ${GRAY}$COMPOSE $COMPOSE_FILES --env-file proxy.env up -d${RESET}"
$COMPOSE $COMPOSE_FILES --env-file proxy.env up -d
ok "Containers started"

# ── Wait for health ─────────────────────────────────────────────────────────
step "Waiting for services"

PROXY_PORT="$(grep -E '^MCP_PROXY_PORT=' "$SCRIPT_DIR/proxy.env" 2>/dev/null | cut -d= -f2-)"
PROXY_PORT="${PROXY_PORT:-9443}"

echo -n "  Mastio + nginx "
for i in $(seq 1 60); do
    if curl -skf "https://localhost:${PROXY_PORT}/health" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 60 ]]; then
        echo -e " ${RED}timeout${RESET}"
        warn "Mastio did not become healthy — check logs: $COMPOSE $COMPOSE_FILES logs mcp-proxy mastio-nginx"
    fi
done

PUBLIC_URL="$(grep -E '^MCP_PROXY_PROXY_PUBLIC_URL=' "$SCRIPT_DIR/proxy.env" 2>/dev/null | cut -d= -f2-)"
PUBLIC_URL="${PUBLIC_URL:-https://localhost:${PROXY_PORT}}"

echo ""
echo -e "${GREEN}${BOLD}Cullis Mastio deployed (${MODE}).${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard${RESET}        ${GRAY}${PUBLIC_URL}/proxy/login${RESET}"
echo -e "  ${BOLD}Health${RESET}           ${GRAY}${PUBLIC_URL}/health${RESET}"
echo ""
if [[ "$MODE" == "development" ]]; then
    echo "  Next steps (development):"
    echo "    1. Open ${PUBLIC_URL}/proxy/login"
    echo "       (browser will warn — TLS is signed by your local Org CA,"
    echo "        not a public CA. Accept the self-signed warning.)"
    echo "    2. Complete the first-boot setup wizard"
    echo "    3. Enroll agents via the Connector or paste an invite token"
else
    echo "  Next steps (production):"
    echo "    1. Front-door TLS at your edge LB → mastio-nginx :${PROXY_PORT}"
    echo "    2. DNS: ${PUBLIC_URL}  →  this host"
    echo "    3. Share the dashboard URL with your org admin"
fi
echo ""
echo "  Useful commands:"
echo "    $COMPOSE $COMPOSE_FILES logs -f                # tail logs"
echo "    $COMPOSE $COMPOSE_FILES ps                     # container status"
echo "    $0 --down                                      # stop"
echo ""
