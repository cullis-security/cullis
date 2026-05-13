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

# ═══════════════════════════════════════════════════════════════════════════
# ADR-030 helpers — bundle-level upgrade + bind-mount data layout
# ═══════════════════════════════════════════════════════════════════════════

# Strict version validation. Mirror of ``_TAG_SAFE_RE`` in
# mcp_proxy/dashboard/update_check.py (PR #668): only letters, digits,
# dots, and hyphens. Refuses any shell metacharacter that could land in
# a curl/tar argv. ``mastio-v`` prefix is added by the URL builder, not
# the operator-supplied string.
_validate_version() {
    local v="$1"
    [[ -n "$v" ]] || die "version is required"
    if [[ ! "$v" =~ ^[A-Za-z0-9.\-]+$ ]]; then
        die "refusing version with unsafe characters: ${v} (allowed: A-Z a-z 0-9 . -)"
    fi
}

# Bundle dir sanity. ``_cmd_upgrade_bundle`` rewrites scripts in place; if
# we're not actually in a bundle directory the tarball extract would
# scatter unrelated files. Cheap pre-flight.
_assert_bundle_pwd() {
    [[ -f "$SCRIPT_DIR/docker-compose.yml" ]] \
        || die "not a Mastio bundle directory (no docker-compose.yml at $SCRIPT_DIR)"
    [[ -f "$SCRIPT_DIR/deploy.sh" ]] \
        || die "not a Mastio bundle directory (no deploy.sh at $SCRIPT_DIR)"
}

# Does a named volume still exist? Used to decide whether a v0.3.x
# customer needs the bind-mount migration before --upgrade-bundle.
_named_volume_exists() {
    docker volume inspect "$1" >/dev/null 2>&1
}

# Compose-aware named-volume name. docker-compose prefixes volume names
# with ${COMPOSE_PROJECT_NAME}_ so the actual identifier on the host is
# ``cullis-mastio_mcp_proxy_data``, not the bare ``mcp_proxy_data`` from
# the compose stanza. We always export COMPOSE_PROJECT_NAME=cullis-mastio
# above, so this is deterministic — but spell it out so the helper stays
# correct if the project name ever changes.
_volume_full_name() {
    echo "${COMPOSE_PROJECT_NAME}_$1"
}

# Bind-mount targets resolved from proxy.env (with the compose-level
# defaults baked in). Echoed as absolute paths so the rest of the script
# does not have to care about relative-to-bundle semantics.
_data_dir_host() {
    local p
    p="$(_load_env MASTIO_DATA_DIR 2>/dev/null || true)"
    p="${p:-./data}"
    [[ "$p" = /* ]] || p="$SCRIPT_DIR/${p#./}"
    echo "$p"
}
_nginx_certs_dir_host() {
    local p
    p="$(_load_env MASTIO_NGINX_CERTS_DIR 2>/dev/null || true)"
    p="${p:-./nginx-certs}"
    [[ "$p" = /* ]] || p="$SCRIPT_DIR/${p#./}"
    echo "$p"
}

# proxy.env value lookup. Mirrors the inline lambda used in the prod
# validation block, hoisted here so the ADR-030 helpers can share it
# without forward-references.
_load_env() {
    grep -E "^$1=" "$SCRIPT_DIR/proxy.env" 2>/dev/null | head -1 | cut -d= -f2- || true
}

# mkdir + chown the host bind targets. The chown is the same operation
# the init-permissions compose service runs at boot, just earlier so a
# fresh install does not have to wait for the first ``compose up`` for
# the directories to exist with the right owner. Idempotent.
_ensure_data_dirs() {
    local data_dir nginx_certs_dir
    data_dir="$(_data_dir_host)"
    nginx_certs_dir="$(_nginx_certs_dir_host)"
    mkdir -p "$data_dir" "$nginx_certs_dir"
    # busybox chown matches the in-compose init-permissions service. We
    # don't strictly need this on a fresh install (compose will do it)
    # but it makes the --migrate-volumes audit trail honest: the host
    # dir is correctly owned before the copy starts. Silently ignore
    # failures — the compose init-permissions service is the backstop.
    if command -v docker >/dev/null 2>&1; then
        docker run --rm \
            -v "$data_dir:/data" \
            -v "$nginx_certs_dir:/nginx-certs" \
            --user 0:0 \
            busybox:stable sh -c "chown -R 10001:10001 /data /nginx-certs && chmod 0750 /data /nginx-certs" \
            >/dev/null 2>&1 || true
    fi
}

# Rewrite (or append) a single VAR=value line in proxy.env. Same sed
# pattern as the legacy --upgrade flow, extracted so --upgrade-bundle
# and any future caller share the same trailing-newline-safe behaviour.
_rewrite_env_pin() {
    local var="$1" value="$2" envfile="$SCRIPT_DIR/proxy.env"
    [[ -f "$envfile" ]] || die "proxy.env not found — run ./deploy.sh once before pinning ${var}"
    sed -i.bak "/^#*[[:space:]]*${var}=/d" "$envfile"
    rm -f "${envfile}.bak"
    echo "${var}=${value}" >> "$envfile"
}

# Tar-aware backup. Snapshots proxy.env + data dir + nginx-certs dir into
# ./backups/<label>-<ts>/ so an operator who hits a regression mid-upgrade
# has an obvious restore target. Cheap (rsync-style copy, not tar) so the
# operator can ``cp -a`` it back without untar tooling.
_backup_user_state() {
    local label="$1" ts backup_dir data_dir nginx_certs_dir
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_dir="$SCRIPT_DIR/backups/${label}-${ts}"
    data_dir="$(_data_dir_host)"
    nginx_certs_dir="$(_nginx_certs_dir_host)"
    mkdir -p "$backup_dir"
    if [[ -f "$SCRIPT_DIR/proxy.env" ]]; then
        cp -a "$SCRIPT_DIR/proxy.env" "$backup_dir/proxy.env"
    fi
    if [[ -d "$data_dir" ]] && compgen -G "$data_dir/*" >/dev/null; then
        cp -a "$data_dir" "$backup_dir/data"
    fi
    if [[ -d "$nginx_certs_dir" ]] && compgen -G "$nginx_certs_dir/*" >/dev/null; then
        cp -a "$nginx_certs_dir" "$backup_dir/nginx-certs"
    fi
    ok "Backup written to ${backup_dir#$SCRIPT_DIR/}"
    BACKUP_DIR="$backup_dir"
}

# Move a single legacy named volume's contents into a host bind dir.
# Safety: refuses if the destination bind dir already has files in it
# (that would suggest a partial migration the operator should resolve by
# hand). The named volume is left in place — the operator decides when
# to ``docker volume rm`` after verifying the new layout boots clean.
_migrate_single_volume() {
    local volume_short="$1" volume_full bind_target log_line size_before size_after files_after
    volume_full="$(_volume_full_name "$volume_short")"
    bind_target="$2"

    if ! _named_volume_exists "$volume_full"; then
        ok "${volume_full} — no legacy named volume, skipping"
        return 0
    fi

    if [[ -d "$bind_target" ]] && compgen -G "$bind_target/*" >/dev/null 2>&1; then
        warn "${bind_target} already has content; skipping ${volume_full} migration"
        warn "  resolve manually: inspect both, ``docker volume rm ${volume_full}`` only after confirming"
        return 0
    fi

    mkdir -p "$bind_target"
    size_before="$(docker run --rm -v "$volume_full:/src:ro" busybox:stable sh -c 'du -sk /src 2>/dev/null | cut -f1' || echo 0)"
    docker run --rm \
        -v "$volume_full:/src:ro" \
        -v "$bind_target:/dst" \
        --user 0:0 \
        busybox:stable sh -c "cp -a /src/. /dst/ && chown -R 10001:10001 /dst" \
        >/dev/null
    size_after="$(du -sk "$bind_target" 2>/dev/null | cut -f1 || echo 0)"
    files_after="$(find "$bind_target" -mindepth 1 | wc -l)"
    log_line="${volume_full} → ${bind_target}  size_before=${size_before}K size_after=${size_after}K files=${files_after}"
    echo "$log_line" >> "${BACKUP_DIR:-$SCRIPT_DIR/backups/last-migration}/migration.log"
    ok "Migrated ${volume_full} → ${bind_target#$SCRIPT_DIR/} (${files_after} files, ${size_after}K)"
    MIGRATED_VOLUMES+=("$volume_full")
}

# Idempotent: re-running after a successful migration is a no-op (bind
# dirs are populated, every _migrate_single_volume hits the "destination
# already has content" guard).
_cmd_migrate_volumes() {
    _assert_bundle_pwd
    step "Migrating Cullis Mastio data to bind mounts (ADR-030)"

    local data_dir nginx_certs_dir mcp_full nginx_full any=0
    data_dir="$(_data_dir_host)"
    nginx_certs_dir="$(_nginx_certs_dir_host)"
    mcp_full="$(_volume_full_name mcp_proxy_data)"
    nginx_full="$(_volume_full_name mastio_nginx_certs)"

    if ! _named_volume_exists "$mcp_full" && ! _named_volume_exists "$nginx_full"; then
        ok "No legacy named volumes found — bundle is already on the bind-mount layout"
        return 0
    fi

    # Stop the running stack before copying — a running mcp-proxy can hold
    # an open SQLite WAL on /data and a half-copied DB is the worst kind
    # of corruption to debug after the fact.
    if docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" --format '{{.Names}}' 2>/dev/null | grep -q .; then
        warn "Stopping running stack before migration (open WALs would corrupt the copy)"
        $COMPOSE $COMPOSE_FILES --env-file proxy.env down 2>/dev/null \
            || $COMPOSE $COMPOSE_FILES down 2>/dev/null \
            || true
    fi

    _backup_user_state "pre-bind-migration"
    mkdir -p "$BACKUP_DIR"
    : > "$BACKUP_DIR/migration.log"

    MIGRATED_VOLUMES=()
    _migrate_single_volume mcp_proxy_data "$data_dir" && any=1
    _migrate_single_volume mastio_nginx_certs "$nginx_certs_dir" && any=1

    if [[ ${#MIGRATED_VOLUMES[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${BOLD}Migration complete.${RESET} The named volumes are left in place so you can"
        echo -e "  verify the new layout boots cleanly before deleting them."
        echo ""
        echo -e "  Once the next ``./deploy.sh`` (or ``--upgrade-bundle``) brings the stack up"
        echo -e "  and the dashboard answers, remove the obsolete volumes with:"
        echo ""
        for v in "${MIGRATED_VOLUMES[@]}"; do
            echo -e "    ${GRAY}docker volume rm ${v}${RESET}"
        done
        echo ""
        echo -e "  Backup of pre-migration state: ${GRAY}${BACKUP_DIR#$SCRIPT_DIR/}/${RESET}"
    else
        ok "Nothing to migrate (named volumes were empty or destinations already populated)"
    fi
}

# Full bundle refresh: download the released tarball, extract over the
# current bundle, bump CULLIS_MASTIO_VERSION, pull the matching image,
# restart with healthcheck wait. ``--from-banner`` skips the migration
# prompt for the banner-driven one-liner.
_cmd_upgrade_bundle() {
    local version="$1" tarball_url tarball_local backup_dir
    _validate_version "$version"
    _assert_bundle_pwd

    step "Upgrading Cullis Mastio bundle to ${version}"

    # 1. Decide whether the migration is needed first. Doing it before the
    # tarball download keeps the failure surface predictable: if the
    # operator says no to the migration we have not yet touched anything.
    local mcp_full nginx_full needs_migration=0
    mcp_full="$(_volume_full_name mcp_proxy_data)"
    nginx_full="$(_volume_full_name mastio_nginx_certs)"
    if _named_volume_exists "$mcp_full" || _named_volume_exists "$nginx_full"; then
        needs_migration=1
        if [[ $FROM_BANNER -eq 1 ]]; then
            warn "Legacy named volumes detected — auto-migrating (--from-banner)"
        else
            echo ""
            warn "Legacy named volumes detected (${mcp_full}, ${nginx_full})."
            warn "ADR-030 moves data to host bind dirs (./data, ./nginx-certs)."
            warn "This is automatic, idempotent, and leaves the named volumes intact"
            warn "until you remove them manually after a clean boot."
            read -rp "  Migrate now? [Y/n]: " _reply
            if [[ "$_reply" =~ ^[Nn] ]]; then
                die "Aborted by operator — re-run with --from-banner to skip this prompt or run ./deploy.sh --migrate-volumes separately"
            fi
        fi
        _cmd_migrate_volumes
    fi

    # 2. Backup current scripts + user state so a regression mid-extract
    # has a clear restore target. _backup_user_state already grabs
    # proxy.env + data + nginx-certs; here we also snapshot the bundle
    # scripts the extract is about to overwrite.
    _backup_user_state "pre-upgrade-${version}"
    mkdir -p "$BACKUP_DIR/scripts"
    for f in docker-compose.yml docker-compose.prod.yml docker-compose.shared-broker.yml \
             deploy.sh generate-proxy-env.sh README.md; do
        if [[ -f "$SCRIPT_DIR/$f" ]]; then
            cp -a "$SCRIPT_DIR/$f" "$BACKUP_DIR/scripts/$f"
        fi
    done
    if [[ -d "$SCRIPT_DIR/nginx" ]]; then
        cp -a "$SCRIPT_DIR/nginx" "$BACKUP_DIR/scripts/nginx"
    fi

    # 3. Download tarball. URL host is hardcoded — version is the only
    # variable input and is regex-validated above so it cannot smuggle a
    # path traversal or shell metacharacter.
    tarball_url="https://github.com/cullis-security/cullis/releases/download/mastio-v${version}/cullis-mastio-bundle-${version}.tar.gz"
    tarball_local="$(mktemp -t cullis-mastio-bundle-XXXXXX.tar.gz)"
    step "Downloading ${tarball_url}"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --proto '=https' --tlsv1.2 -o "$tarball_local" "$tarball_url" \
            || die "Download failed: ${tarball_url}"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -qO "$tarball_local" "$tarball_url" \
            || die "Download failed: ${tarball_url}"
    else
        die "Need curl or wget to download the bundle tarball"
    fi
    if [[ ! -s "$tarball_local" ]]; then
        die "Downloaded tarball is empty: ${tarball_local}"
    fi
    ok "Downloaded $(du -h "$tarball_local" | cut -f1) to ${tarball_local}"

    # 4. Extract over the current bundle. --strip-components=1 drops the
    # top-level ``cullis-mastio-bundle-<version>/`` directory the release
    # workflow stages with. --exclude protects proxy.env in the unlikely
    # event a future release accidentally ships one; the bind-mount dirs
    # (./data, ./nginx-certs) live OUTSIDE the tarball staging so they
    # are not at risk regardless.
    step "Extracting bundle"
    tar xzf "$tarball_local" \
        --strip-components=1 \
        --overwrite \
        --exclude='proxy.env' \
        --exclude='backups' \
        --exclude='data' \
        --exclude='nginx-certs' \
        -C "$SCRIPT_DIR"
    chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true
    ok "Bundle scripts updated"

    # 5. Pin the new version in proxy.env so this run and every future
    # ./deploy.sh sees the new tag without a re-source.
    _rewrite_env_pin CULLIS_MASTIO_VERSION "$version"
    export CULLIS_MASTIO_VERSION="$version"
    ok "proxy.env: CULLIS_MASTIO_VERSION=${version}"

    # 6. Pull + restart. ``--wait`` blocks until healthcheck passes,
    # avoiding the race PR #663 fixed for the Frontdesk bundle (force-
    # recreate returns when the container is spawned, NOT when uvicorn
    # is bound).
    step "Pulling image + restarting"
    $COMPOSE $COMPOSE_FILES --env-file proxy.env pull
    $COMPOSE $COMPOSE_FILES --env-file proxy.env up -d --wait \
        || $COMPOSE $COMPOSE_FILES --env-file proxy.env up -d
    ok "Stack restarted on ${version}"

    rm -f "$tarball_local"

    echo ""
    echo -e "${GREEN}${BOLD}Cullis Mastio upgraded to ${version}.${RESET}"
    echo ""
    echo -e "  Backup: ${GRAY}${BACKUP_DIR#$SCRIPT_DIR/}/${RESET}"
    if [[ $needs_migration -eq 1 ]]; then
        echo -e "  Legacy named volumes are still around — delete them after verifying"
        echo -e "  the dashboard answers normally."
    fi
    local proxy_port public_url
    proxy_port="$(_load_env MCP_PROXY_PORT)"
    proxy_port="${proxy_port:-9443}"
    public_url="$(_load_env MCP_PROXY_PROXY_PUBLIC_URL)"
    public_url="${public_url:-https://localhost:${proxy_port}}"
    echo -e "  Dashboard: ${GRAY}${public_url}/proxy/login${RESET}"
    echo ""
}

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
  --upgrade <version>         Image-only bump: pin CULLIS_MASTIO_VERSION
                              in proxy.env to <version>, pull the new
                              image, recreate containers in-place. Bind-
                              mount data is preserved. Scripts stay at
                              the bundle's original version — use
                              --upgrade-bundle for a full bundle refresh.
  --upgrade-bundle <version>  Full bundle refresh: download the released
                              tarball, extract over the current bundle
                              (preserving proxy.env, ./data, ./nginx-
                              certs), bump CULLIS_MASTIO_VERSION, pull
                              the matching image, and restart with
                              ``compose up -d --wait``. Auto-runs
                              --migrate-volumes when legacy named volumes
                              are detected. Backup of proxy.env + bind
                              dirs goes under ./backups/pre-upgrade-<ts>.
  --migrate-volumes           Move legacy named volumes (mcp_proxy_data,
                              mastio_nginx_certs) to host bind dirs
                              (./data, ./nginx-certs). Idempotent: safe
                              to re-run, never deletes the named volumes
                              automatically — operator decides when.
  --from-banner               Internal: skip the interactive prompt on
                              named-volume migration during --upgrade-
                              bundle. Used by the dashboard's update
                              banner one-liner.
  --help, -h                  Show this help and exit.

Environment:
  CULLIS_MASTIO_VERSION       Image tag to pull (default: "latest").
                              Pin to a specific release in production.

Examples:
  ./deploy.sh                                    # standalone (default)
  CULLIS_MASTIO_VERSION=0.3.0 ./deploy.sh        # pinned version
  ./deploy.sh --shared-broker                    # join Court on same host
  ./deploy.sh --prod                             # standalone, prod safety
  ./deploy.sh --upgrade 0.3.0-rc3                # image-only bump
  ./deploy.sh --upgrade-bundle 0.4.0             # full bundle refresh
  ./deploy.sh --migrate-volumes                  # one-shot bind migration
  ./deploy.sh --down                             # stop + remove
EOF
}

ACTION="up"
MODE="development"
SHARED_BROKER=0
FORCE_PULL=0
UPGRADE_TO=""
UPGRADE_BUNDLE_TO=""
FROM_BANNER=0
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
        --upgrade-bundle)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--upgrade-bundle requires a version (e.g. --upgrade-bundle 0.4.0)"
            UPGRADE_BUNDLE_TO="$1"
            ACTION="upgrade_bundle"
            shift
            ;;
        --upgrade-bundle=*)
            UPGRADE_BUNDLE_TO="${arg#--upgrade-bundle=}"
            [[ -n "$UPGRADE_BUNDLE_TO" ]] || die "--upgrade-bundle= requires a value"
            ACTION="upgrade_bundle"
            shift
            ;;
        --migrate-volumes) ACTION="migrate_volumes"; shift ;;
        --from-banner)     FROM_BANNER=1; shift ;;
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

# ── ADR-030 — bundle-level upgrade + bind-mount migration dispatch ─────────
# Dispatched here, before the long ``up`` body, so a customer running
# --upgrade-bundle or --migrate-volumes doesn't pay for the env validation /
# port preflight before the migration starts.
if [[ "$ACTION" == "migrate_volumes" ]]; then
    _cmd_migrate_volumes
    exit 0
fi
if [[ "$ACTION" == "upgrade_bundle" ]]; then
    _cmd_upgrade_bundle "$UPGRADE_BUNDLE_TO"
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
    # Without an explicit public URL the laptop default is baked in, and
    # any agent reaching the Mastio over a different hostname hits 401
    # ``Invalid DPoP proof: htu mismatch`` on every egress. Ask up front
    # so the operator never finds out post-deploy.
    #
    # The default ``host.docker.internal:9443`` covers BOTH the browser
    # on the host (resolves to 127.0.0.1 via the host's hosts file or
    # docker desktop's automatic mapping) AND a sibling docker container
    # such as the Frontdesk Connector reaching the Mastio across docker
    # networks. ``localhost:9443`` only works for the host browser case
    # and silently breaks the moment a second component (Frontdesk,
    # second Mastio, agent on a different docker network) is introduced.
    echo ""
    echo "  ${BOLD}Where will agents reach this Mastio?${RESET}"
    echo "    ${GRAY}- Laptop / single VM: just press Enter (uses https://host.docker.internal:9443)${RESET}"
    echo "      ${GRAY}covers host browser AND sibling containers (Frontdesk bundle, etc.)${RESET}"
    echo "    ${GRAY}- Internal server with stable DNS: enter the public URL agents resolve at${RESET}"
    echo "    ${GRAY}  e.g. https://mastio.acme.local  or  https://192.168.10.42:9443${RESET}"
    echo "    ${GRAY}- Internet-facing: the LB/ingress hostname${RESET}"
    echo "    ${GRAY}  e.g. https://mastio.myorg.example.com${RESET}"
    echo ""
    read -rp "  Public URL [https://host.docker.internal:9443]: " _public_url
    _public_url="${_public_url:-https://host.docker.internal:9443}"

    # Strip any pre-existing line and re-add (proxy.env from the
    # generator may already carry an empty one).
    sed -i.bak '/^#*[[:space:]]*MCP_PROXY_PROXY_PUBLIC_URL=/d' "$SCRIPT_DIR/proxy.env"
    rm -f "$SCRIPT_DIR/proxy.env.bak"
    echo "MCP_PROXY_PROXY_PUBLIC_URL=$_public_url" >> "$SCRIPT_DIR/proxy.env"
    ok "proxy.env: MCP_PROXY_PROXY_PUBLIC_URL=$_public_url"

    # Extract the hostname (no scheme, no port) and bake it into the
    # nginx server cert SAN list. Without this, an agent that connects
    # to ``https://mastio.acme.local:9443`` with verify_tls=True fails
    # the TLS handshake — the cert only carries the default SANs and
    # the hostname doesn't match. ``sed`` strips the scheme and port.
    # We always include host.docker.internal alongside so a sibling
    # container (Frontdesk Connector) reaching the Mastio across docker
    # networks completes the handshake whether the operator picked the
    # default or a custom public URL.
    _public_host="$(echo "$_public_url" | sed -E 's|^https?://||; s|:[0-9]+$||; s|/.*$||')"
    _san="mastio.local,localhost,host.docker.internal"
    if [[ -n "$_public_host" && "$_public_host" != "localhost" && "$_public_host" != "host.docker.internal" ]]; then
        _san="${_public_host},${_san}"
    fi
    sed -i.bak '/^#*[[:space:]]*MCP_PROXY_NGINX_SAN=/d' "$SCRIPT_DIR/proxy.env"
    rm -f "$SCRIPT_DIR/proxy.env.bak"
    echo "MCP_PROXY_NGINX_SAN=${_san}" >> "$SCRIPT_DIR/proxy.env"
    ok "proxy.env: MCP_PROXY_NGINX_SAN=${_san}"
fi

if [[ "$MODE" == "production" ]]; then
    _errors=()
    # _load_env is hoisted to the top of the script (ADR-030 helpers).

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
    elif [[ "$_public" == "https://localhost:9443" \
         || "$_public" == "http://localhost:9100" \
         || "$_public" == "https://host.docker.internal:9443" ]]; then
        _errors+=("MCP_PROXY_PROXY_PUBLIC_URL still a dev default ($_public) — set the public URL where internal agents reach this Mastio")
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

# Pre-create the bind-mount target for the optional corporate CA bundle.
# docker-compose.yml mounts ``${CULLIS_CERTS_DIR:-./certs}:/certs:ro``;
# if the directory does not exist when ``compose up`` runs, Docker
# auto-creates it as ``root:root`` and the post-up ``docker cp org-ca``
# step further down (run as the host user) cannot write into it. Creating
# it here as the invoking user keeps ownership host-side and the export
# works without sudo.
CERT_DIR="${CULLIS_CERTS_DIR:-$SCRIPT_DIR/certs}"
mkdir -p "$CERT_DIR"

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

# ── Export Org CA to host filesystem ───────────────────────────────────────
# The Org CA is generated at first boot inside the mcp-proxy container's
# named volume. Downstream consumers (Frontdesk Connector enroll, mTLS
# verify, manual curl smoke) need it as a trust anchor on the host. Copy
# it out so operators don't have to docker cp by hand.
PROXY_CID="$($COMPOSE $COMPOSE_FILES ps -q mcp-proxy 2>/dev/null || true)"
ORG_CA_HOST="$CERT_DIR/org-ca.pem"
# If a previous ``compose up`` (e.g. before the pre-mkdir fix landed)
# created ``./certs`` as root, reclaim ownership before docker cp so the
# host user can write into it without sudo. Cheap no-op when ownership is
# already correct.
if [[ ! -w "$CERT_DIR" ]]; then
    docker run --rm -v "$CERT_DIR:/target" --entrypoint /bin/sh \
        alpine -c "chown -R $(id -u):$(id -g) /target" >/dev/null 2>&1 || true
fi
if [[ -n "$PROXY_CID" ]] && docker cp "$PROXY_CID:/var/lib/mastio/nginx-certs/org-ca.crt" "$ORG_CA_HOST" 2>/dev/null; then
    chmod 644 "$ORG_CA_HOST"
    ok "Org CA exported to ./certs/org-ca.pem"
else
    warn "Could not export Org CA — retrieve manually:"
    warn "  docker cp ${COMPOSE_PROJECT_NAME}-mcp-proxy-1:/var/lib/mastio/nginx-certs/org-ca.crt ./certs/org-ca.pem"
    rm -f "$ORG_CA_HOST" 2>/dev/null
fi

# Export Org ID alongside the Org CA. Standalone Mastios derive a
# 16-char hex id from the Org CA at first boot (proxy_config.org_id);
# downstream bundles (Frontdesk in particular) need it to set
# CULLIS_FRONTDESK_ORG_ID. Without this, generate-frontdesk-env.sh
# defaults to ``acme`` / ``acme.test`` which doesn't match the Mastio,
# and a SPIFFE id mismatch surfaces only at runtime when the audit
# chain attribution starts looking wrong. Read the value out of the
# health endpoint via curl + jq is fragile (jq may be missing, the
# endpoint shape evolves); read it directly from the sqlite DB the
# Mastio writes at first boot.
ORG_ID_HOST="$CERT_DIR/org-id"
if [[ -n "$PROXY_CID" ]]; then
    ORG_ID_VAL="$(docker exec "$PROXY_CID" python3 -c "
import sqlite3
try:
    c = sqlite3.connect('/data/mcp_proxy.db')
    row = c.execute(\"SELECT value FROM proxy_config WHERE key='org_id'\").fetchone()
    print(row[0] if row else '')
except Exception:
    print('')
" 2>/dev/null)"
    ORG_ID_VAL="${ORG_ID_VAL//[$'\t\r\n ']}"
    if [[ -n "$ORG_ID_VAL" ]]; then
        echo "$ORG_ID_VAL" > "$ORG_ID_HOST"
        chmod 644 "$ORG_ID_HOST"
        ok "Org ID exported to ./certs/org-id (${ORG_ID_VAL})"
    else
        warn "Could not read org_id from proxy_config — Frontdesk bundle"
        warn "will fall back to its default org slug. Set"
        warn "CULLIS_FRONTDESK_ORG_ID manually in frontdesk.env."
    fi
fi

PUBLIC_URL="$(grep -E '^MCP_PROXY_PROXY_PUBLIC_URL=' "$SCRIPT_DIR/proxy.env" 2>/dev/null | cut -d= -f2-)"
PUBLIC_URL="${PUBLIC_URL:-https://localhost:${PROXY_PORT}}"

echo ""
echo -e "${GREEN}${BOLD}Cullis Mastio deployed (${MODE}).${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard${RESET}        ${GRAY}${PUBLIC_URL}/proxy/login${RESET}"
echo -e "  ${BOLD}Health${RESET}           ${GRAY}${PUBLIC_URL}/health${RESET}"
if [[ -f "$ORG_CA_HOST" ]]; then
    echo -e "  ${BOLD}Org CA${RESET}           ${GRAY}./certs/org-ca.pem${RESET}"
    echo -e "                   ${GRAY}use as CULLIS_FRONTDESK_CA_BUNDLE_HOST when bringing up the Frontdesk bundle${RESET}"
fi
echo ""
SEED_PWD="$(grep -E '^MCP_PROXY_INITIAL_ADMIN_PASSWORD=' "$SCRIPT_DIR/proxy.env" 2>/dev/null | cut -d= -f2-)"

if [[ "$MODE" == "development" ]]; then
    echo "  Next steps (development):"
    echo "    1. Open ${PUBLIC_URL}/proxy/login"
    echo "       (browser will warn — TLS is signed by your local Org CA,"
    echo "        not a public CA. Accept the self-signed warning.)"
    if [[ -n "$SEED_PWD" ]]; then
        echo "    2. Sign in as ``admin`` with this password:"
        echo "         ${SEED_PWD}"
        echo "       (rotate via /proxy/settings on first sign-in. The seed"
        echo "        env is ignored on subsequent boots; the persisted hash wins.)"
        echo "    3. Enroll agents via the Connector or paste an invite token"
    else
        echo "    2. First-boot setup: the dashboard will redirect to"
        echo "         ${PUBLIC_URL}/proxy/register"
        echo "       Pick the admin password there (typed once, never stored"
        echo "        on disk in plaintext or surfaced on stdout)."
        echo "    3. Enroll agents via the Connector or paste an invite token"
    fi
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
