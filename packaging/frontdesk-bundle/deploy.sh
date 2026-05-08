#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Frontdesk — image-based deploy (no source tree required)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Pulls the published Connector + Frontdesk Chat images from GHCR and
# brings up nginx + chat + connector via docker-compose. The Connector
# is enrolled against an existing Mastio (separate bundle, see
# packaging/mastio-bundle/) using an invite code minted on the Mastio
# dashboard. ADR-019 Phase 7.
#
# Modes (combinable):
#   (default)         dev: generate frontdesk.env from --defaults if missing
#   --prod            fail-fast on insecure defaults, requires frontdesk.env
#   --down            stop + remove containers
#   --pull            re-pull images (otherwise pulled on first up)
#
# Enrollment:
#   --code <invite>   skip the invite-code prompt
#   --site <url>      override CULLIS_SITE_URL for the enroll step
#   --skip-enroll     bring the bundle up assuming connector_data is already
#                     enrolled out-of-band
#
# Examples:
#   ./deploy.sh                                      # interactive
#   ./deploy.sh --code abc123 --site https://mastio.acme.local:9443
#   ./deploy.sh --skip-enroll                        # second run, identity exists
#   ./deploy.sh --down                               # stop + remove
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export COMPOSE_PROJECT_NAME="cullis-frontdesk"

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

Deploys the Cullis Frontdesk bundle from the published images (no source
tree required). Default = dev mode, prompts for missing values.

Options:
  (no flags)                  Dev mode: generate frontdesk.env if missing,
                              prompt for invite code at enrollment time
  --prod                      Production: fail-fast on insecure defaults,
                              frontdesk.env must exist with real values
  --down                      Stop and remove containers
  --pull                      Force-pull the images before starting
  --code <invite>             Pre-supply the invite code (skip prompt)
  --site <url>                Mastio URL the Connector enrolls against,
                              defaults to https://host.docker.internal:9443
                              for the same-host topology
  --skip-enroll               Skip the enrollment one-shot (use when the
                              connector_data volume is already populated)
  --help, -h                  Show this help and exit

Environment variables (loaded from frontdesk.env, set by
generate-frontdesk-env.sh):
  CULLIS_FRONTDESK_ORG_ID            Org slug, must match Mastio
  CULLIS_FRONTDESK_TRUST_DOMAIN      SPIFFE trust domain, e.g. acme.test
  CULLIS_FRONTDESK_CA_BUNDLE_HOST    Host path to the Mastio CA chain PEM
  CONNECTOR_VERSION                  cullis-connector image tag (default: 0.4.0-rc1)
  CHAT_VERSION                       cullis-chat-frontdesk image tag (default: 0.1.0-rc1)
  CONNECTOR_PROFILE                  Connector profile name (default: frontdesk)
  CONNECTOR_DATA_DIR                 Local dir for enrolled identity (default: ./connector_data)
  FRONTDESK_HTTP_PORT                Host port to bind nginx (default: 8080)
EOF
}

ACTION="up"
MODE="development"
FORCE_PULL=0
INVITE_CODE=""
CLI_SITE_URL=""
SKIP_ENROLL=0

while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
        --down)         ACTION="down"; shift ;;
        --pull)         FORCE_PULL=1; shift ;;
        --prod)         MODE="production"; shift ;;
        --skip-enroll)  SKIP_ENROLL=1; shift ;;
        --code)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--code requires an invite code"
            INVITE_CODE="$1"; shift ;;
        --code=*)       INVITE_CODE="${arg#--code=}"; shift ;;
        --site)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--site requires a URL"
            CLI_SITE_URL="$1"; shift ;;
        --site=*)       CLI_SITE_URL="${arg#--site=}"; shift ;;
        --help|-h)      print_help; exit 0 ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

if [[ "$ACTION" == "down" ]]; then
    step "Stopping Cullis Frontdesk"
    $COMPOSE --env-file frontdesk.env down 2>/dev/null \
        || $COMPOSE down
    ok "Frontdesk stopped"
    exit 0
fi

# ── frontdesk.env — create if missing, validate in prod ─────────────────────
step "Environment configuration (frontdesk.env)"

if [[ ! -f "$SCRIPT_DIR/frontdesk.env" ]]; then
    warn "frontdesk.env not found — generating one"
    if [[ "$MODE" == "production" ]]; then
        die "--prod requires frontdesk.env to exist. Run: CULLIS_FRONTDESK_ORG_ID=acme CULLIS_FRONTDESK_TRUST_DOMAIN=acme.prod CULLIS_FRONTDESK_CA_BUNDLE_HOST=/path/to/ca.pem ./generate-frontdesk-env.sh --prod"
    fi
    bash "$SCRIPT_DIR/generate-frontdesk-env.sh" --defaults
fi

# Load env with grep (sourcing is fragile because the file is also a
# docker-compose env file with shell-incompatible substitutions).
_load_env() { grep -E "^$1=" "$SCRIPT_DIR/frontdesk.env" 2>/dev/null | head -1 | cut -d= -f2- || true; }

ORG_ID="$(_load_env CULLIS_FRONTDESK_ORG_ID)"
TRUST_DOMAIN="$(_load_env CULLIS_FRONTDESK_TRUST_DOMAIN)"
CA_BUNDLE="$(_load_env CULLIS_FRONTDESK_CA_BUNDLE_HOST)"
CONNECTOR_VERSION="$(_load_env CONNECTOR_VERSION)";   CONNECTOR_VERSION="${CONNECTOR_VERSION:-0.4.0-rc1}"
CHAT_VERSION="$(_load_env CHAT_VERSION)";             CHAT_VERSION="${CHAT_VERSION:-0.1.0-rc1}"
CONNECTOR_PROFILE="$(_load_env CONNECTOR_PROFILE)";   CONNECTOR_PROFILE="${CONNECTOR_PROFILE:-frontdesk}"
DATA_DIR="$(_load_env CONNECTOR_DATA_DIR)";           DATA_DIR="${DATA_DIR:-./connector_data}"
HTTP_PORT="$(_load_env FRONTDESK_HTTP_PORT)";         HTTP_PORT="${HTTP_PORT:-8080}"
ENV_SITE_URL="$(_load_env CULLIS_SITE_URL)"

if [[ "$MODE" == "production" ]]; then
    _errors=()
    [[ -n "$ORG_ID" ]]       || _errors+=("CULLIS_FRONTDESK_ORG_ID is empty")
    [[ -n "$TRUST_DOMAIN" ]] || _errors+=("CULLIS_FRONTDESK_TRUST_DOMAIN is empty")
    [[ -n "$CA_BUNDLE" ]]    || _errors+=("CULLIS_FRONTDESK_CA_BUNDLE_HOST is empty")
    [[ -z "$CA_BUNDLE" || -f "$CA_BUNDLE" ]] || _errors+=("CA bundle not found at: $CA_BUNDLE")
    if [[ ${#_errors[@]} -gt 0 ]]; then
        echo ""
        err "Production frontdesk.env is not safe to deploy:"
        for e in "${_errors[@]}"; do echo -e "    ${RED}✗${RESET} $e"; done
        echo ""
        die "Fix the issues above and rerun. Aborting before compose up."
    fi
    ok "frontdesk.env validated for production"
fi

# ── Pre-flight: CA bundle readable ──────────────────────────────────────────
if [[ -z "$CA_BUNDLE" || ! -f "$CA_BUNDLE" ]]; then
    err "Mastio CA bundle not found at: ${CA_BUNDLE:-<unset>}"
    err "Edit frontdesk.env: set CULLIS_FRONTDESK_CA_BUNDLE_HOST to the path"
    err "of your Mastio's Org CA. The sibling Mastio bundle exports it to"
    err "../cullis-mastio-bundle/certs/org-ca.pem (release tarball) or"
    err "../mastio-bundle/certs/org-ca.pem (repo layout) when its"
    err "./deploy.sh runs."
    exit 1
fi
ok "CA bundle: $CA_BUNDLE"

# ── Pre-flight: host port not already in use ────────────────────────────────
if command -v ss >/dev/null 2>&1 && ss -tlnH "sport = :${HTTP_PORT}" 2>/dev/null | grep -q .; then
    err "Host port ${HTTP_PORT} is already in use — another service is bound there."
    err "Override FRONTDESK_HTTP_PORT in frontdesk.env to a free port."
    die "Refusing to start — fix the port conflict first."
fi

# ── Enrollment one-shot ─────────────────────────────────────────────────────
mkdir -p "$DATA_DIR"
DATA_DIR_ABS="$(cd "$DATA_DIR" && pwd)"
ENROLLMENT_METADATA="$DATA_DIR_ABS/profiles/${CONNECTOR_PROFILE}/identity/metadata.json"

# Ensure the bind target is owned by uid 10001 (the cullis user inside
# the connector image), otherwise the enrollment one-shot below + the
# connector container at runtime fail to write identity material with
# ``Permission denied`` on Linux where the host uid is typically 1000.
# The compose-up path has the same fix via an ``init-permissions``
# service (PR #524); this handles the enroll-time path that runs first.
_data_uid="$(stat -c '%u' "$DATA_DIR_ABS" 2>/dev/null || echo 0)"
if [[ "$_data_uid" != "10001" ]]; then
    if docker run --rm --user 0:0 \
            -v "${DATA_DIR_ABS}:/data" \
            busybox:stable chown -R 10001:10001 /data >/dev/null 2>&1; then
        ok "connector_data ownership normalized to uid 10001"
    else
        warn "Could not chown ${DATA_DIR_ABS} via docker"
        warn "Run manually if enrollment fails: sudo chown -R 10001:10001 ${DATA_DIR_ABS}"
    fi
fi

if [[ -f "$ENROLLMENT_METADATA" ]]; then
    ok "Connector profile '${CONNECTOR_PROFILE}' already enrolled"
elif [[ $SKIP_ENROLL -eq 1 ]]; then
    warn "--skip-enroll: assuming Connector profile is enrolled out-of-band"
else
    step "Enrolling Connector profile '${CONNECTOR_PROFILE}'"

    # Site URL precedence: CLI flag > frontdesk.env CULLIS_SITE_URL > prompt.
    SITE_URL="${CLI_SITE_URL:-${ENV_SITE_URL}}"
    if [[ -z "$SITE_URL" ]]; then
        echo ""
        echo "  ${BOLD}Where does the Connector reach the Mastio?${RESET}"
        echo "    ${GRAY}- Same host (laptop / single VM): just press Enter${RESET}"
        echo "    ${GRAY}- Different host: enter the public URL Mastio is bound at${RESET}"
        echo ""
        read -rp "  Site URL [https://host.docker.internal:9443]: " SITE_URL
        SITE_URL="${SITE_URL:-https://host.docker.internal:9443}"
    fi
    ok "Site URL: $SITE_URL"

    if [[ -z "$INVITE_CODE" ]]; then
        echo ""
        echo "  ${BOLD}Get an invite code from the Mastio dashboard:${RESET}"
        # Translate host.docker.internal back to localhost for the browser
        # hint, since the operator opens the dashboard from the host.
        _dashboard_url="${SITE_URL/host.docker.internal/localhost}"
        echo "    1. Open ${_dashboard_url}/proxy/login"
        echo "    2. Go to Enrollments → Create invite (target name: ${CONNECTOR_PROFILE})"
        echo "    3. Paste the generated code below"
        echo ""
        read -rp "  Invite code: " INVITE_CODE
        [[ -n "$INVITE_CODE" ]] || die "Invite code is required to enroll"
    fi

    # Resolve to absolute path so docker volume mount works regardless of
    # where the operator invokes the script from. ``DATA_DIR_ABS`` was
    # already resolved above for the chown step.
    CA_BUNDLE_ABS="$(cd "$(dirname "$CA_BUNDLE")" && pwd)/$(basename "$CA_BUNDLE")"

    # Use a bridge network with host-gateway so the URL the Connector
    # uses to reach Mastio at enroll-time matches what it will use at
    # runtime (compose attaches the same host-gateway extra_hosts to the
    # connector service). Without this, ``--network host`` would let the
    # enroll succeed via localhost but the saved site_url in
    # metadata.json would not resolve from the bridge network at runtime.
    echo ""
    docker run --rm \
        --add-host "host.docker.internal:host-gateway" \
        -v "${DATA_DIR_ABS}:/home/cullis/.cullis" \
        -v "${CA_BUNDLE_ABS}:/etc/cullis/ca-bundle.pem:ro" \
        -e SSL_CERT_FILE=/etc/cullis/ca-bundle.pem \
        -e REQUESTS_CA_BUNDLE=/etc/cullis/ca-bundle.pem \
        "ghcr.io/cullis-security/cullis-connector:${CONNECTOR_VERSION}" \
        enroll \
            --site "$SITE_URL" \
            --code "$INVITE_CODE" \
            --profile "$CONNECTOR_PROFILE" \
        || die "Enrollment failed — verify the Mastio is reachable at $SITE_URL and the invite code is valid"

    if [[ ! -f "$ENROLLMENT_METADATA" ]]; then
        die "Enrollment finished without writing metadata to $ENROLLMENT_METADATA — check container logs above"
    fi
    ok "Connector enrolled: ${CONNECTOR_PROFILE}"
fi

# ── Pull + Start ────────────────────────────────────────────────────────────
step "Deploying Cullis Frontdesk (${MODE})"
echo -e "  Connector image: ${GRAY}ghcr.io/cullis-security/cullis-connector:${CONNECTOR_VERSION}${RESET}"
echo -e "  Chat image:      ${GRAY}ghcr.io/cullis-security/cullis-chat-frontdesk:${CHAT_VERSION}${RESET}"

if [[ $FORCE_PULL -eq 1 ]]; then
    echo -e "  ${GRAY}$COMPOSE --env-file frontdesk.env pull${RESET}"
    $COMPOSE --env-file frontdesk.env pull
    ok "Images pulled"
fi

echo -e "  ${GRAY}$COMPOSE --env-file frontdesk.env up -d${RESET}"
$COMPOSE --env-file frontdesk.env up -d
ok "Containers started"

# ── Wait for health ─────────────────────────────────────────────────────────
step "Waiting for services"

echo -n "  nginx + chat + connector "
for i in $(seq 1 60); do
    if curl -sf "http://localhost:${HTTP_PORT}/" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 60 ]]; then
        echo -e " ${RED}timeout${RESET}"
        warn "Frontdesk did not become healthy — check logs:"
        warn "  $COMPOSE --env-file frontdesk.env logs"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────────────
SITE_URL_DISPLAY="${CLI_SITE_URL:-${ENV_SITE_URL:-(see frontdesk.env CULLIS_SITE_URL)}}"

echo ""
echo -e "${GREEN}${BOLD}Cullis Frontdesk deployed (${MODE}).${RESET}"
echo ""
echo -e "  ${BOLD}SPA URL${RESET}          ${GRAY}http://localhost:${HTTP_PORT}${RESET}"
echo -e "  ${BOLD}Mastio target${RESET}    ${GRAY}${SITE_URL_DISPLAY}${RESET}"
echo -e "  ${BOLD}Org${RESET}              ${GRAY}${ORG_ID} (${TRUST_DOMAIN})${RESET}"
echo -e "  ${BOLD}Profile${RESET}          ${GRAY}${CONNECTOR_PROFILE} (data: ${DATA_DIR})${RESET}"
echo ""
echo "  Smoke test (dev fake-SSO injects X-Forwarded-User from ?user=):"
echo "    open http://localhost:${HTTP_PORT}?user=mario"
echo "    open http://localhost:${HTTP_PORT}?user=anna   # incognito tab"
echo ""
echo "  Useful commands:"
echo "    $COMPOSE --env-file frontdesk.env logs -f connector"
echo "    $COMPOSE --env-file frontdesk.env ps"
echo "    $0 --down"
echo ""
