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
#   (default)                   standalone enterprise Mastio
#   --down                      stop + remove containers (keeps bind dirs)
#   --down -v                   stop + wipe bind dirs (data/, nginx-certs/)
#   --pull                      re-pull image
#   --upgrade-bundle <version>  snapshot user state to ./backups/, bump
#                               CULLIS_MASTIO_VERSION in proxy.env, pull
#                               the new image, restart with --wait
#
# Usage:
#   ./deploy.sh
#   CULLIS_MASTIO_VERSION=0.4.2 ./deploy.sh
#   ./deploy.sh --down
#   ./deploy.sh --upgrade-bundle 0.4.5
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

# Source shared backup helpers (same file the open-core mastio-bundle
# uses, so the two bundles cannot drift on backup semantics). MAJOR-5
# of imp/p3-operability-audit.md.
#
# Layout: source tree has the helper at ``packaging/_common-deploy-
# helpers.sh`` (parent of this bundle dir). Release workflow cp's it
# as a sibling so the customer tarball can be extracted standalone.
# Prefer the sibling copy; fall back to the source-tree relative path.
# shellcheck source=../_common-deploy-helpers.sh
if [ -f "$SCRIPT_DIR/_common-deploy-helpers.sh" ]; then
    source "$SCRIPT_DIR/_common-deploy-helpers.sh"
else
    source "$SCRIPT_DIR/../_common-deploy-helpers.sh"
fi

MODE="up"
PULL=0
UPGRADE_BUNDLE_TO=""
# ``--down -v`` (alias ``--volumes`` / ``--wipe-data``) mirrors
# ``docker compose down --volumes`` semantics for bind dirs: after
# stopping containers, wipe ./data and ./nginx-certs via a transient
# root busybox. Default ``--down`` preserves state (P3 MINOR-H).
WIPE_VOLUMES=0
# Manual loop because --upgrade-bundle consumes the next positional
# arg; the original ``for arg in "$@"`` cannot shift mid-iteration.
while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
        --down)  MODE="down"; shift ;;
        -v|--volumes|--wipe-data) WIPE_VOLUMES=1; shift ;;
        --pull)  PULL=1; shift ;;
        --upgrade-bundle)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--upgrade-bundle requires a version (e.g. --upgrade-bundle 0.4.5)"
            UPGRADE_BUNDLE_TO="$1"
            MODE="upgrade_bundle"
            shift
            ;;
        --upgrade-bundle=*)
            UPGRADE_BUNDLE_TO="${arg#--upgrade-bundle=}"
            [[ -n "$UPGRADE_BUNDLE_TO" ]] || die "--upgrade-bundle= requires a value"
            MODE="upgrade_bundle"
            shift
            ;;
        -h|--help)
            sed -n '2,35p' "$SCRIPT_DIR/deploy.sh" | sed 's/^# \?//'
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
    if [[ $WIPE_VOLUMES -eq 1 ]]; then
        step "wiping bind dirs (data/, nginx-certs/)"
        warn "Destructive: every Connector enrolled against the current Org CA"
        warn "will fail TLS verify on /v1/principals/csr after the next bring-up."
        _data_dir="$(_data_dir_host)"
        _nginx_certs_dir="$(_nginx_certs_dir_host)"
        _wipe_bind_dirs "$_data_dir" "$_nginx_certs_dir"
    fi
    exit 0
fi

# ── upgrade-bundle (image-only, pre-upgrade backup) ─────────────────────────
# Customer-facing recovery target: every Mastio Enterprise upgrade lands
# a timestamped snapshot of proxy.env + ./data + ./nginx-certs under
# ./backups/pre-upgrade-<version>-<ts>/ BEFORE the new image is pulled.
# Operator can ``cp -a`` it back on the spot if the new release misbehaves
# (or use ./restore.sh for a full GPG-encrypted off-host copy, see
# backup.sh — that path is for compliance archives, not in-place
# rollbacks).
#
# Mirrors the open-core ``--upgrade-bundle`` pattern but stops short of
# downloading a tarball — the enterprise bundle's scripts ship with the
# private image release, not a public GitHub tarball, so an image-only
# bump is the right operation. memoria
# feedback_bundle_upgrade_must_use_deploy_sh.md: never invoke compose
# plain, always --wait and route through deploy.sh so
# COMPOSE_PROJECT_NAME and env-file stay aligned.
if [[ "$MODE" == "upgrade_bundle" ]]; then
    step "upgrading cullis-mastio-enterprise bundle to ${UPGRADE_BUNDLE_TO}"

    # Version safety: same regex as mcp_proxy.dashboard.update_check
    # _TAG_SAFE_RE (PR #668). Refuses anything that could land as a
    # shell metacharacter in the compose / pull argv.
    if [[ ! "$UPGRADE_BUNDLE_TO" =~ ^[A-Za-z0-9.\-]+$ ]]; then
        die "refusing version with unsafe characters: ${UPGRADE_BUNDLE_TO} (allowed: A-Z a-z 0-9 . -)"
    fi

    # 1. Snapshot user state. Helper writes to ./backups/<label>-<ts>/
    # and chowns the copy back to the invoking user (busybox-root
    # pattern preserves 0600 mcp_proxy.db + mastio-server.key reads).
    _backup_user_state "pre-upgrade-${UPGRADE_BUNDLE_TO}"

    # 2. Pin the new version in proxy.env so this run AND every future
    # ./deploy.sh see the new tag without re-sourcing. Idempotent: any
    # pre-existing CULLIS_MASTIO_VERSION line is dropped first.
    sed -i.bak "/^#*[[:space:]]*CULLIS_MASTIO_VERSION=/d" "$SCRIPT_DIR/proxy.env"
    rm -f "$SCRIPT_DIR/proxy.env.bak"
    echo "CULLIS_MASTIO_VERSION=${UPGRADE_BUNDLE_TO}" >> "$SCRIPT_DIR/proxy.env"
    export CULLIS_MASTIO_VERSION="$UPGRADE_BUNDLE_TO"
    ok "proxy.env: CULLIS_MASTIO_VERSION=${UPGRADE_BUNDLE_TO}"

    # 3. Down the stack BEFORE pulling — running containers do not pick
    # up a new image and force-recreating live would leave an open
    # SQLite WAL on /data mid-restart. Use the env-file flag so
    # COMPOSE_PROJECT_NAME inherits correctly even if a stale shell
    # forgot the export.
    step "stopping current stack"
    docker compose --env-file proxy.env down || warn "down returned non-zero — continuing (may already be stopped)"

    # 4. Pull the new image. Fails fast if the PAT is unauthorized
    # for the new tag.
    step "pulling ${UPGRADE_BUNDLE_TO}"
    if ! docker compose --env-file proxy.env pull; then
        err "pull failed — restore proxy.env from backup: ${BACKUP_DIR}/proxy.env"
        die "aborting upgrade"
    fi

    # 5. Up with --wait so we block until the healthcheck passes (memoria
    # feedback_frontdesk_deploy_force_recreate_mcp_proxy_race).
    # Sweep orphan shims first (P3 MINOR-I) so a previously crashed
    # container does not drift bind-mount dst paths into dirs.
    step "starting ${UPGRADE_BUNDLE_TO}"
    _cleanup_orphan_shims "$COMPOSE_PROJECT_NAME"
    # Capture exit BEFORE the if: bash rewrites $? to 0 inside the
    # success branch of `!`, which would dead-code the hint. MINOR-I
    # review.
    docker compose --env-file proxy.env up -d --wait
    _rc=$?
    if [[ $_rc -ne 0 ]]; then
        _hint_on_bind_mount_failure "$_rc" "$COMPOSE_PROJECT_NAME"
        exit 1
    fi

    echo
    echo -e "${GREEN}${BOLD}Cullis Mastio Enterprise upgraded to ${UPGRADE_BUNDLE_TO}.${RESET}"
    echo
    echo -e "  Pre-upgrade backup: ${BACKUP_DIR#$SCRIPT_DIR/}/"
    echo -e "  Restore in case of regression:"
    echo -e "    ./deploy.sh --down"
    echo -e "    cp -a ${BACKUP_DIR#$SCRIPT_DIR/}/proxy.env ./proxy.env"
    echo -e "    cp -a ${BACKUP_DIR#$SCRIPT_DIR/}/data/.        ./data/"
    echo -e "    cp -a ${BACKUP_DIR#$SCRIPT_DIR/}/nginx-certs/. ./nginx-certs/"
    echo -e "    CULLIS_MASTIO_VERSION=<previous-tag> ./deploy.sh"
    echo
    echo -e "  Or the GPG-encrypted off-host copy from ./backup.sh + ./restore.sh"
    echo -e "  if you need a compliance-grade archive (different flow, slower)."
    echo
    echo -e "  Pre-upgrade snapshots are NOT auto-pruned. Remove confirmed-good"
    echo -e "  ones with:  rm -rf backups/pre-upgrade-*"
    echo
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
# Sweep orphan shims left over from any previous failed ``compose up``
# (P3 MINOR-I) before the primary up. Scoped to COMPOSE_PROJECT_NAME so
# sibling open-core stacks are untouched.
_cleanup_orphan_shims "$COMPOSE_PROJECT_NAME"
# Capture exit BEFORE the if: bash rewrites $? to 0 inside the success
# branch of `!`, which would dead-code the hint. MINOR-I review.
docker compose --env-file proxy.env up -d --wait
_rc=$?
if [[ $_rc -ne 0 ]]; then
    _hint_on_bind_mount_failure "$_rc" "$COMPOSE_PROJECT_NAME"
    exit 1
fi
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
