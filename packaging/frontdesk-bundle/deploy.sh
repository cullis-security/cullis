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
# Enrollment (device-code flow — there is no pre-minted invite token in
# the Mastio architecture; the Connector posts its public key + identity
# claim to /v1/enrollment/start and the admin approves the pending row in
# /proxy/enrollments. The docker run below blocks until that happens.):
#   --requester-email <addr>   email the Mastio admin sees in the pending
#                              row (default: frontdesk@<trust-domain>)
#   --requester-name <name>    display name in the pending row
#                              (default: "Frontdesk Bundle (<profile>)")
#   --site <url>               override CULLIS_SITE_URL for the enroll step
#   --skip-enroll              bring the bundle up assuming connector_data
#                              is already enrolled out-of-band
#   --no-wizard                refuse to fall back to the in-browser setup
#                              wizard when no Mastio URL is configured —
#                              fail fast instead. Use in CI / scripted
#                              deploys where prompting a human is wrong.
#
# First-boot wizard:
#   When no CULLIS_SITE_URL is set (env or --site) and no enrollment
#   metadata yet exists in connector_data/, the script skips the CLI
#   one-shot and brings the bundle up directly. The Connector serves a
#   discovery wizard at /setup/discover that probes nearby Mastios and
#   pre-populates the enrollment form. Pass --no-wizard to opt out.
#
# Examples:
#   ./deploy.sh                                      # interactive (or wizard)
#   ./deploy.sh --requester-email ops@acme.local
#   ./deploy.sh --site https://mastio.acme.local:9443
#   ./deploy.sh --skip-enroll                        # second run, identity exists
#   ./deploy.sh --no-wizard --site …                 # CI: fail-fast, no wizard
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
                              run the device-code enrollment one-shot
  --prod                      Production: fail-fast on insecure defaults,
                              frontdesk.env must exist with real values
  --down                      Stop and remove containers
  --pull                      Force-pull the images before starting
  --requester-email <addr>    Email the Mastio admin sees in the pending
                              enrollment row. Default: frontdesk@<trust-domain>
  --requester-name <name>     Display name in the pending row.
                              Default: "Frontdesk Bundle (<profile>)"
  --site <url>                Mastio URL the Connector enrolls against,
                              defaults to https://host.docker.internal:9443
                              for the same-host topology
  --skip-enroll               Skip the enrollment one-shot (use when the
                              connector_data volume is already populated)
  --no-wizard                 Refuse to fall back to the in-browser setup
                              wizard when no Mastio URL is configured.
                              Fail fast instead — use in CI / scripted
                              deploys where prompting a human is wrong
  --help, -h                  Show this help and exit

Environment variables (loaded from frontdesk.env, set by
generate-frontdesk-env.sh):
  CULLIS_FRONTDESK_ORG_ID            Org slug, must match Mastio
  CULLIS_FRONTDESK_TRUST_DOMAIN      SPIFFE trust domain, e.g. acme.test
  CULLIS_FRONTDESK_CA_BUNDLE_HOST    Host path to the Mastio CA chain PEM
  CONNECTOR_VERSION                  cullis-connector image tag (default: 0.4.0-rc2)
  CHAT_VERSION                       cullis-chat-frontdesk image tag (default: 0.2.0-rc1)
  CHAT_VERSION                       cullis-chat-frontdesk image tag (default: 0.1.0-rc1)
  CONNECTOR_PROFILE                  Connector profile name (default: frontdesk)
  CONNECTOR_DATA_DIR                 Local dir for enrolled identity (default: ./connector_data)
  FRONTDESK_HTTP_PORT                Host port to bind nginx (default: 8080)
EOF
}

ACTION="up"
MODE="development"
FORCE_PULL=0
CLI_REQUESTER_EMAIL=""
CLI_REQUESTER_NAME=""
CLI_SITE_URL=""
SKIP_ENROLL=0
NO_WIZARD=0

while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
        --down)             ACTION="down"; shift ;;
        --pull)             FORCE_PULL=1; shift ;;
        --prod)             MODE="production"; shift ;;
        --skip-enroll)      SKIP_ENROLL=1; shift ;;
        --no-wizard)        NO_WIZARD=1; shift ;;
        --requester-email)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--requester-email requires a value"
            CLI_REQUESTER_EMAIL="$1"; shift ;;
        --requester-email=*) CLI_REQUESTER_EMAIL="${arg#--requester-email=}"; shift ;;
        --requester-name)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--requester-name requires a value"
            CLI_REQUESTER_NAME="$1"; shift ;;
        --requester-name=*) CLI_REQUESTER_NAME="${arg#--requester-name=}"; shift ;;
        --site)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--site requires a URL"
            CLI_SITE_URL="$1"; shift ;;
        --site=*)           CLI_SITE_URL="${arg#--site=}"; shift ;;
        --help|-h)          print_help; exit 0 ;;
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

# Magic placeholder that ``generate-frontdesk-env.sh --defaults`` writes
# when it cannot auto-detect the sibling Mastio CA path. If the user
# re-runs deploy.sh after a sibling-bundle bring-up that exported the
# CA, we should regenerate the env so auto-detect picks up the new
# state. Otherwise the placeholder leaks all the way to the docker
# compose layer which fails with a confusing "CA bundle not found".
_PLACEHOLDER_CA_PATH="./MUST_SET_TO_MASTIO_CA_BUNDLE_PATH"

_env_has_placeholder_ca() {
    [[ -f "$SCRIPT_DIR/frontdesk.env" ]] || return 1
    grep -qE "^CULLIS_FRONTDESK_CA_BUNDLE_HOST=${_PLACEHOLDER_CA_PATH}\$" \
        "$SCRIPT_DIR/frontdesk.env"
}

if [[ ! -f "$SCRIPT_DIR/frontdesk.env" ]]; then
    warn "frontdesk.env not found — generating one"
    if [[ "$MODE" == "production" ]]; then
        die "--prod requires frontdesk.env to exist. Run: CULLIS_FRONTDESK_ORG_ID=acme CULLIS_FRONTDESK_TRUST_DOMAIN=acme.prod CULLIS_FRONTDESK_CA_BUNDLE_HOST=/path/to/ca.pem ./generate-frontdesk-env.sh --prod"
    fi
    bash "$SCRIPT_DIR/generate-frontdesk-env.sh" --defaults
elif _env_has_placeholder_ca; then
    # Pre-existing frontdesk.env still pinning the unconfigured magic
    # placeholder (e.g. the sibling Mastio bundle was not yet up at the
    # time of the previous run). Regenerate so the freshly-exported CA
    # gets picked up by the auto-detect block in
    # generate-frontdesk-env.sh.
    if [[ "$MODE" == "production" ]]; then
        die "frontdesk.env still has the placeholder CA path (${_PLACEHOLDER_CA_PATH}). Set CULLIS_FRONTDESK_CA_BUNDLE_HOST to a real PEM path and rerun --prod."
    fi
    warn "frontdesk.env has the placeholder CA path — regenerating to pick up the sibling Mastio bundle"
    rm -f "$SCRIPT_DIR/frontdesk.env"
    bash "$SCRIPT_DIR/generate-frontdesk-env.sh" --defaults
fi

# Load env with grep (sourcing is fragile because the file is also a
# docker-compose env file with shell-incompatible substitutions).
_load_env() { grep -E "^$1=" "$SCRIPT_DIR/frontdesk.env" 2>/dev/null | head -1 | cut -d= -f2- || true; }

ORG_ID="$(_load_env CULLIS_FRONTDESK_ORG_ID)"
TRUST_DOMAIN="$(_load_env CULLIS_FRONTDESK_TRUST_DOMAIN)"
CA_BUNDLE="$(_load_env CULLIS_FRONTDESK_CA_BUNDLE_HOST)"
CONNECTOR_VERSION="$(_load_env CONNECTOR_VERSION)";   CONNECTOR_VERSION="${CONNECTOR_VERSION:-0.4.0-rc2}"
CHAT_VERSION="$(_load_env CHAT_VERSION)";             CHAT_VERSION="${CHAT_VERSION:-0.2.0-rc1}"
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

WIZARD_MODE=0
if [[ -f "$ENROLLMENT_METADATA" ]]; then
    ok "Connector profile '${CONNECTOR_PROFILE}' already enrolled"
elif [[ $SKIP_ENROLL -eq 1 ]]; then
    warn "--skip-enroll: assuming Connector profile is enrolled out-of-band"
elif [[ -z "${CLI_SITE_URL}${ENV_SITE_URL}" && $NO_WIZARD -eq 0 ]]; then
    # No Mastio URL configured anywhere and the operator hasn't opted out
    # of the in-browser wizard. Skip the CLI device-code one-shot and let
    # the Connector's auto-discovery wizard at /setup/discover handle
    # enrollment after compose up. The wizard probes nearby Mastios,
    # pins the CA from /pki/ca.crt, and walks the operator through the
    # same device-code flow the CLI one-shot would have driven —
    # only it does it from the browser instead of an interactive prompt.
    WIZARD_MODE=1
    warn "No CULLIS_SITE_URL configured — bringing up in browser-wizard mode"
    warn "After compose up, finish enrollment at http://localhost:${HTTP_PORT}/setup/discover"
else
    step "Enrolling Connector profile '${CONNECTOR_PROFILE}'"

    # Site URL precedence: CLI flag > frontdesk.env CULLIS_SITE_URL > prompt.
    # ``--no-wizard`` skipped the wizard branch above; if we still have
    # no URL here, fail fast rather than fall through to a prompt that
    # would just confuse a CI runner.
    SITE_URL="${CLI_SITE_URL:-${ENV_SITE_URL}}"
    if [[ -z "$SITE_URL" ]]; then
        if [[ $NO_WIZARD -eq 1 ]]; then
            die "--no-wizard requires --site or CULLIS_SITE_URL to be set"
        fi
        echo ""
        echo "  ${BOLD}Where does the Connector reach the Mastio?${RESET}"
        echo "    ${GRAY}- Same host (laptop / single VM): just press Enter${RESET}"
        echo "    ${GRAY}- Different host: enter the public URL Mastio is bound at${RESET}"
        echo ""
        read -rp "  Site URL [https://host.docker.internal:9443]: " SITE_URL
        SITE_URL="${SITE_URL:-https://host.docker.internal:9443}"
    fi
    ok "Site URL: $SITE_URL"

    # Default identity for the pending enrollment row. The admin sees
    # ``REQUESTER_NAME <REQUESTER_EMAIL>`` in /proxy/enrollments and
    # decides whether to approve. There is no ``invite code`` in the
    # Mastio architecture — this is a device-code flow (Connector posts
    # its public key + identity claim, admin approves out-of-band).
    REQUESTER_EMAIL="${CLI_REQUESTER_EMAIL:-frontdesk@${TRUST_DOMAIN:-localhost}}"
    REQUESTER_NAME="${CLI_REQUESTER_NAME:-Frontdesk Bundle (${CONNECTOR_PROFILE})}"

    # Translate host.docker.internal back to localhost for the browser
    # hint, since the operator opens the dashboard from the host.
    _dashboard_url="${SITE_URL/host.docker.internal/localhost}"

    echo ""
    echo "  ${BOLD}Approval workflow${RESET}"
    echo "    ${GRAY}1. The next docker run posts a pending enrollment to Mastio.${RESET}"
    echo "    ${GRAY}2. Open ${_dashboard_url}/proxy/enrollments in your browser.${RESET}"
    echo "    ${GRAY}3. You should see a row for: ${REQUESTER_NAME} <${REQUESTER_EMAIL}>${RESET}"
    echo "    ${GRAY}4. Click Approve, set agent_id = ${CONNECTOR_PROFILE} (or your choice).${RESET}"
    echo "    ${GRAY}5. The connector container below polls until the cert lands.${RESET}"
    echo ""

    # Resolve CA bundle to absolute path so the docker volume mount works
    # regardless of where the operator invokes the script from.
    # ``DATA_DIR_ABS`` was already resolved above for the chown step.
    CA_BUNDLE_ABS="$(cd "$(dirname "$CA_BUNDLE")" && pwd)/$(basename "$CA_BUNDLE")"

    # Use a bridge network with host-gateway so the URL the Connector
    # uses to reach Mastio at enroll-time matches what it will use at
    # runtime (compose attaches the same host-gateway extra_hosts to the
    # connector service). The container exits 0 once Mastio approves;
    # the script unblocks and continues to ``compose up``.
    #
    # ``-it`` was unconditional in rc1/rc2 — that fails outright in any
    # non-TTY context (CI runner, ssh pipe, ``echo "" | ./deploy.sh``,
    # IDE-integrated terminals without tty allocation) with
    # ``the input device is not a TTY``. Detect ``[ -t 0 ]`` and only
    # request ``-t`` when stdin is actually a tty. The polling output
    # streams either way; in non-TTY mode it just lacks the carriage
    # returns that re-paint the spinner line.
    DOCKER_TTY_FLAGS=""
    if [[ -t 0 && -t 1 ]]; then
        DOCKER_TTY_FLAGS="-it"
    fi

    # Pin the enroll docker run to the frontdesk_net bridge that the
    # compose stack will use. Without this, the container lands on the
    # default bridge, where ``host.docker.internal:host-gateway``
    # resolves to a gateway IP that on Linux-native Docker is NOT
    # forwarded to the host's published ports (Docker Desktop on
    # macOS/Windows fakes the resolution via NAT magic, masking the
    # bug). Symptom on Linux: ``Could not reach Site at
    # https://host.docker.internal:9443: timed out`` after 10s. Pre-
    # creating the user-defined bridge gives the same gateway routing
    # behaviour the compose-managed Connector container will see.
    ENROLL_NET="${COMPOSE_PROJECT_NAME}_frontdesk_net"
    if ! docker network inspect "$ENROLL_NET" >/dev/null 2>&1; then
        docker network create "$ENROLL_NET" >/dev/null \
            || die "Could not create docker network ${ENROLL_NET} for the enroll one-shot"
    fi

    docker run --rm $DOCKER_TTY_FLAGS \
        --network "$ENROLL_NET" \
        --add-host "host.docker.internal:host-gateway" \
        -v "${DATA_DIR_ABS}:/home/cullis/.cullis" \
        -v "${CA_BUNDLE_ABS}:/etc/cullis/ca-bundle.pem:ro" \
        -e SSL_CERT_FILE=/etc/cullis/ca-bundle.pem \
        -e REQUESTS_CA_BUNDLE=/etc/cullis/ca-bundle.pem \
        "ghcr.io/cullis-security/cullis-connector:${CONNECTOR_VERSION}" \
        enroll \
            --site-url "$SITE_URL" \
            --profile "$CONNECTOR_PROFILE" \
            --requester-name "$REQUESTER_NAME" \
            --requester-email "$REQUESTER_EMAIL" \
            --reason "Frontdesk container bundle deploy.sh" \
        || die "Enrollment failed — verify the Mastio is reachable at $SITE_URL and that you approved the pending row at ${_dashboard_url}/proxy/enrollments"

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
if [[ $WIZARD_MODE -eq 1 ]]; then
    echo "  ${BOLD}${YELLOW}First-boot wizard active${RESET}"
    echo ""
    echo "  No Mastio URL was configured, so enrollment hasn't run yet."
    echo "  Open the wizard in your browser to finish:"
    echo ""
    echo "      ${BOLD}http://localhost:${HTTP_PORT}/setup/discover${RESET}"
    echo ""
    echo "  The wizard will probe nearby Mastios, show the CA fingerprint"
    echo "  for visual confirmation, and walk you through enrollment."
    echo "  After approval lands, refresh the SPA URL above and log in."
    echo ""
elif [[ "${AMBASSADOR_MODE:-}" == "shared" ]]; then
    echo "  ${YELLOW}Legacy shared mode active${RESET} (AMBASSADOR_MODE=shared)."
    echo "    open http://localhost:${HTTP_PORT}?user=mario   # X-Forwarded-User dev only"
    echo "    open http://localhost:${HTTP_PORT}?user=anna    # incognito tab"
else
    # The Connector's admin endpoints validate ``X-Admin-Secret`` against
    # ``CULLIS_CONNECTOR_ADMIN_SECRET`` (cullis_connector/admin/auth.py),
    # which lives in *this* bundle's frontdesk.env. The Mastio's
    # ``MCP_PROXY_ADMIN_SECRET`` is a different secret on a different
    # component and cannot authenticate this admin API — pre-v0.2.0-rc4
    # the summary mistakenly told operators to use it and they hit 403
    # on every provisioning call. Surface our secret instead.
    ADMIN_SECRET="$(_load_env CULLIS_CONNECTOR_ADMIN_SECRET)"
    echo "  Next steps (ADR-025 local-auth):"
    echo "    1. Pre-create users via the admin API (X-Admin-Secret guarded):"
    echo ""
    if [[ -n "$ADMIN_SECRET" ]]; then
        echo "       ADMIN=\"$ADMIN_SECRET\""
    else
        echo "       ADMIN=\"\$(grep '^CULLIS_CONNECTOR_ADMIN_SECRET' frontdesk.env | cut -d= -f2-)\""
        echo "       # Empty above? generate-frontdesk-env.sh mints one on first run;"
        echo "       # rerun ./deploy.sh after deleting frontdesk.env to regenerate."
    fi
    echo "       curl -X POST http://localhost:${HTTP_PORT}/admin/users \\"
    echo "         -H \"X-Admin-Secret: \$ADMIN\" -H 'Content-Type: application/json' \\"
    echo "         -d '{\"user_name\":\"mario\",\"password\":\"temp123!\",\"display_name\":\"Mario Rossi\"}'"
    echo ""
    echo "    2. Open the SPA in a browser and sign in:"
    echo "       open http://localhost:${HTTP_PORT}/login"
fi
echo ""
echo "  Useful commands:"
echo "    $COMPOSE --env-file frontdesk.env logs -f connector"
echo "    $COMPOSE --env-file frontdesk.env ps"
echo "    $0 --down"
echo ""
