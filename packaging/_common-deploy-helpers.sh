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
