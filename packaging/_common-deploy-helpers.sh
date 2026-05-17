#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Mastio bundles — shared deploy helpers (backup + bind-mount paths)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Sourced by:
#   - packaging/mastio-bundle/deploy.sh             (open-core)
#   - packaging/mastio-enterprise-bundle/deploy.sh  (private)
#
# Single source of truth for pre-upgrade snapshot logic so the two
# bundles do not drift (MAJOR-5 of imp/p3-operability-audit.md).
#
# Contract the caller must provide before sourcing:
#   - SCRIPT_DIR  absolute path to the bundle dir (so proxy.env can be
#                 read and ./backups/ lands inside the bundle)
#   - ok / warn / err / die / step  the colour-aware log helpers used
#                 by every bundle deploy.sh
#
# These helpers were the inline definitions in
# packaging/mastio-bundle/deploy.sh:90-189 before this extraction.
# Mechanical extraction only: no logic changes, no perf tweaks, no
# parameter renames. The busybox-root pattern
# (feedback_busybox_root_for_bind_dir_post_init_perms.md) is preserved
# bit-for-bit so 0600 files (mcp_proxy.db, mastio-server.key) survive
# the backup read.

# proxy.env value lookup. Mirrors the inline lambda used in the prod
# validation block, hoisted here so the ADR-030 helpers can share it
# without forward-references.
_load_env() {
    grep -E "^$1=" "$SCRIPT_DIR/proxy.env" 2>/dev/null | head -1 | cut -d= -f2- || true
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

# Copy a bind dir into the backup target. Must run as root through a
# busybox sidecar because post-init-permissions the dir + sensitive
# files (mastio-server.key 0600, mcp_proxy.db 0600) are owned by uid
# 10001 and unreadable by the invoking ``cullis``/operator user. The
# in-container cp also handles ownership preservation cleanly. Chown
# the *backup copy* back to the invoking user so the operator can read
# / restore it without sudo.
_copy_bind_dir_for_backup() {
    local src_dir="$1" dst_dir="$2"
    [[ -d "$src_dir" ]] || return 0
    compgen -G "$src_dir/*" >/dev/null 2>&1 || return 0
    mkdir -p "$(dirname "$dst_dir")"
    docker run --rm \
        -v "$src_dir:/src:ro" \
        -v "$(dirname "$dst_dir"):/dst-parent" \
        --user 0:0 \
        busybox:stable sh -c "
            cp -a /src /dst-parent/$(basename "$dst_dir")
            chown -R $(id -u):$(id -g) /dst-parent/$(basename "$dst_dir")
        " >/dev/null
}

# Tar-aware backup. Snapshots proxy.env + data dir + nginx-certs dir into
# ./backups/<label>-<ts>/ so an operator who hits a regression mid-upgrade
# has an obvious restore target. Cheap (rsync-style copy, not tar) so the
# operator can ``cp -a`` it back without untar tooling. The bind-dir
# copies route through a root busybox so 0600 files (mastio-server.key,
# mcp_proxy.db) survive the read.
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
    _copy_bind_dir_for_backup "$data_dir"         "$backup_dir/data"
    _copy_bind_dir_for_backup "$nginx_certs_dir"  "$backup_dir/nginx-certs"
    ok "Backup written to ${backup_dir#$SCRIPT_DIR/}"
    BACKUP_DIR="$backup_dir"
}

# Wipe contents of bind-mount dirs after ``compose down``. Mirror of
# ``docker compose down --volumes`` semantics for the named volumes,
# extended to the host bind dirs the bundles use after ADR-030. Each
# arg is an absolute host path; the dir itself is kept (the operator
# expects ``./data/`` to still exist as a placeholder, just empty),
# only its contents are removed.
#
# Runs as root inside a transient busybox so 0600 files owned by uid
# 10001 (mcp_proxy.db, mastio-server.key, connector identity material)
# are actually removable. The invoking host user can't ``rm -rf`` them
# directly after the init-permissions service has chown'd everything
# to the runtime uid (feedback_busybox_root_for_bind_dir_post_init_perms).
#
# Idempotent: missing or empty dirs are a no-op. Never touches files
# outside the supplied paths (proxy.env, frontdesk.env,
# docker-compose.yml are explicitly NOT in scope). The caller is responsible
# for confirming ``compose down`` ran first; wiping an active bind
# mount under a running container is a recipe for sqlite WAL corruption.
_wipe_bind_dirs() {
    local any_wiped=0 dir mount_args=() rm_paths=()
    if ! command -v docker >/dev/null 2>&1; then
        warn "docker not available, cannot wipe bind dirs"
        return 1
    fi
    # Build the docker mount list + the in-container paths to wipe.
    # Each host dir is mounted at /wipe<N>; we only wipe contents
    # (``/wipe<N>/.`` glob) so the dir itself survives.
    local idx=0
    for dir in "$@"; do
        [[ -n "$dir" ]] || continue
        [[ -d "$dir" ]] || continue
        # Empty dir → skip both the mount and the rm to keep the
        # docker argv short on a fresh-install down.
        if ! compgen -G "$dir/*" >/dev/null 2>&1 \
                && ! compgen -G "$dir/.[!.]*" >/dev/null 2>&1 \
                && ! compgen -G "$dir/..?*" >/dev/null 2>&1; then
            continue
        fi
        mount_args+=( -v "$dir:/wipe$idx" )
        rm_paths+=( "/wipe$idx" )
        any_wiped=1
        idx=$((idx + 1))
    done
    if [[ $any_wiped -eq 0 ]]; then
        ok "Bind dirs already empty, nothing to wipe"
        return 0
    fi
    # Use ``find -mindepth 1 -delete`` instead of ``rm -rf /wipe*/*``
    # so dotfiles (e.g. SQLite WAL/SHM ``-journal``, ``.cullis``
    # identity stash) are caught too. ``-mindepth 1`` protects the
    # mount root itself, matching the "keep the dir, wipe contents"
    # contract above.
    local find_cmd=""
    for p in "${rm_paths[@]}"; do
        find_cmd+="find $p -mindepth 1 -delete 2>/dev/null; "
    done
    docker run --rm --user 0:0 "${mount_args[@]}" busybox:stable \
        sh -c "$find_cmd true" >/dev/null
    for dir in "$@"; do
        [[ -n "$dir" && -d "$dir" ]] || continue
        ok "Wiped ${dir#$SCRIPT_DIR/}/"
    done
}

# Surgical wipe of orphan SQLite files inside a bind-mount data dir.
# Used by ``--accept-data-loss`` (P3 MINOR-E) after the MAJOR-A guard
# has been bypassed: the operator has confirmed they accept losing
# every enrolled Connector, so the 281 MB orphan ``mcp_proxy.db`` plus
# the WAL / SHM sidecars are dead weight on disk and confuse later
# ``du -sh ./data`` audits.
#
# Strict allowlist by exact filename — no glob, no recursion, no
# ``rm -rf data/*``. We refuse to touch anything that isn't one of
# the three SQLite artefacts the Mastio writes:
#
#   - mcp_proxy.db        the database file proper
#   - mcp_proxy.db-wal    write-ahead log (present while WAL mode is
#                         active, usually a few MB)
#   - mcp_proxy.db-shm    shared memory file (small, ~32K, sometimes
#                         left dangling after an unclean shutdown)
#
# Anything else in ``./data`` (operator-dropped notes, a future
# ``connector_data.db`` from the Connector bundle, etc.) is preserved.
# Idempotent: missing files are no-ops. Runs as root via busybox so
# 0600 files owned by uid 10001 are actually removable, mirror of the
# pattern documented at feedback_busybox_root_for_bind_dir_post_init_perms.
_wipe_orphan_sqlite() {
    local data_dir="$1"
    [[ -n "$data_dir" ]] || return 0
    [[ -d "$data_dir" ]] || return 0
    if ! command -v docker >/dev/null 2>&1; then
        warn "docker not available, cannot wipe orphan SQLite files"
        return 1
    fi
    # Build a human-readable inventory before the wipe so the log line
    # makes the blast radius obvious: ``data/mcp_proxy.db (281M)``.
    local name path size_h inventory=()
    local found=()
    for name in mcp_proxy.db mcp_proxy.db-wal mcp_proxy.db-shm; do
        path="$data_dir/$name"
        [[ -f "$path" ]] || continue
        size_h="$(du -h "$path" 2>/dev/null | cut -f1)"
        size_h="${size_h:-?}"
        inventory+=("${path#$SCRIPT_DIR/} (${size_h})")
        found+=("$name")
    done
    if [[ ${#found[@]} -eq 0 ]]; then
        ok "No orphan SQLite files in ${data_dir#$SCRIPT_DIR/}/ (already clean)"
        return 0
    fi
    warn "Wiping orphan SQLite files: ${inventory[*]}"
    # Allowlist applied inside the container too: build the explicit
    # ``rm`` argv from the same names we inventoried above so a wider
    # mount cannot smuggle extra deletions. ``-f`` swallows the
    # already-missing case (idempotent re-run).
    local rm_args=""
    for name in "${found[@]}"; do
        rm_args+=" /data/${name}"
    done
    docker run --rm \
        -v "$data_dir:/data" \
        --user 0:0 \
        busybox:stable sh -c "rm -f${rm_args}" >/dev/null
    ok "Orphan SQLite files removed from ${data_dir#$SCRIPT_DIR/}/"
}
