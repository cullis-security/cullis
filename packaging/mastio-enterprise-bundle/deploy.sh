#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Mastio Enterprise — image-based deploy
# ═══════════════════════════════════════════════════════════════════════════════
#
# Pulls the private ghcr.io/cullis-security/cullis-mastio-enterprise
# image and brings up the same Mastio + nginx-sidecar topology as the
# open-core bundle, with two additions:
#
#   - Pre-flight validates the license JWT is present and parses (no
#     signature verification client-side; the container does that on
#     boot against the baked pubkey).
#   - Pre-flight tests ``docker pull`` against the private registry.
#     Operator must have run ``docker login ghcr.io`` first with the
#     PAT issued at deal close.
#
# Modes:
#   (default)         standalone enterprise Mastio
#   --down            stop + remove containers
#   --pull            re-pull image
#
# Usage:
#   ./deploy.sh
#   CULLIS_MASTIO_VERSION=0.4.2 ./deploy.sh
#   ./deploy.sh --down
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Pin compose project name so we never collide with a sibling
# open-core ``cullis-mastio`` stack on the same docker host.
export COMPOSE_PROJECT_NAME="cullis-mastio-enterprise"

# ── colour helpers ──────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD="\033[1m"; RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; RESET="\033[0m"
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

MODE="up"
PULL=0
for arg in "$@"; do
    case "$arg" in
        --down)  MODE="down" ;;
        --pull)  PULL=1 ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) die "unknown arg: $arg (use --help)" ;;
    esac
done

# ── ensure proxy.env exists ─────────────────────────────────────────────────
if [[ ! -f proxy.env ]]; then
    if [[ -f proxy.env.example ]]; then
        die "proxy.env missing. Copy 'proxy.env.example' to 'proxy.env', edit, then re-run."
    else
        die "proxy.env missing and proxy.env.example not found — bundle looks corrupted."
    fi
fi

# Load env so the pre-flights can inspect CULLIS_LICENSE_KEY etc.
# shellcheck disable=SC1091,SC2046
set -a
. ./proxy.env
set +a

# ── down ────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "down" ]]; then
    step "stopping cullis-mastio-enterprise stack"
    docker compose --env-file proxy.env down
    ok "stack stopped"
    exit 0
fi

# ── pre-flight: license JWT ─────────────────────────────────────────────────
step "license pre-flight"

_license_jwt=""
if [[ -n "${CULLIS_LICENSE_KEY:-}" ]]; then
    _license_jwt="$CULLIS_LICENSE_KEY"
elif [[ -n "${CULLIS_LICENSE_PATH:-}" && -f "${CULLIS_LICENSE_PATH}" ]]; then
    _license_jwt="$(cat "${CULLIS_LICENSE_PATH}")"
fi

if [[ -z "$_license_jwt" ]]; then
    warn "no license configured (CULLIS_LICENSE_KEY / CULLIS_LICENSE_PATH)"
    warn "the proxy will boot in community mode — no paid plugins will activate"
else
    # Shape check only. The container verifies signature + exp on boot.
    if [[ "$_license_jwt" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
        ok "license JWT shape valid"
    else
        die "license value is not a JWT (need 'header.payload.signature' base64url)"
    fi
fi

# ── pre-flight: registry auth ───────────────────────────────────────────────
step "registry auth pre-flight"
IMG_BASE="ghcr.io/cullis-security/cullis-mastio-enterprise"
VERSION_TAG="${CULLIS_MASTIO_VERSION:-latest}"
IMG="${IMG_BASE}:${VERSION_TAG}"

# ``docker pull --quiet`` against the private repo. If the operator has
# not authenticated this fails fast with a clear message.
if ! docker pull --quiet "$IMG" >/dev/null 2>&1; then
    err "pull of ${IMG} failed"
    err "have you run 'docker login ghcr.io' with your Cullis PAT?"
    err "ask hello@cullis.io if your PAT has expired"
    exit 1
fi
ok "${IMG} pull OK"

# ── bring up ────────────────────────────────────────────────────────────────
step "bringing up cullis-mastio-enterprise"
if [[ "$PULL" == "1" ]]; then
    docker compose --env-file proxy.env pull
fi
docker compose --env-file proxy.env up -d --wait
ok "stack up"

# ── post-up: plugin discovery report ────────────────────────────────────────
step "plugin discovery"
sleep 2
loaded_count="$(docker compose --env-file proxy.env logs --no-color mcp-proxy 2>&1 | grep -c 'plugin loaded:' || true)"
ok "${loaded_count} plugins loaded (expected up to 9 depending on license features)"

license_line="$(docker compose --env-file proxy.env logs --no-color mcp-proxy 2>&1 | grep -m1 'license:' || true)"
if [[ -n "$license_line" ]]; then
    echo "  $license_line"
else
    warn "no license log line — proxy may still be starting"
fi

echo
echo -e "${BOLD}Mastio Enterprise ready at: ${MCP_PROXY_PROXY_PUBLIC_URL:-https://localhost:${MCP_PROXY_PORT:-9443}}${RESET}"
echo -e "  Logs:  docker compose -p ${COMPOSE_PROJECT_NAME} logs -f mcp-proxy"
echo -e "  Stop:  ./deploy.sh --down"
