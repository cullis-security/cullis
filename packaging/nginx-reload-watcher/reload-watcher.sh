#!/bin/sh
# =============================================================================
# nginx-reload-watcher — polls a TLS cert file mtime and reloads nginx on
# change. Pairs with the Mastio-side lifespan watcher
# (`mcp_proxy/lifespan/nginx_cert_watcher.py`) that rewrites the cert via
# `ensure_nginx_server_cert` when expiry approaches.
#
# Why polling vs inotify: the sidecar runs stock `nginx:1.27-alpine`,
# which does not ship `inotify-tools`. Polling with `stat -c %Y` is POSIX
# busybox-compatible, needs no package install, no docker socket mount,
# and adds at most one poll interval of latency. For a cert that rotates
# at most every 60-90 days, 60-second polling latency is comfortably
# below any SLA concern.
#
# Trigger: mtime change on the cert file. `ensure_nginx_server_cert`
# writes via tmpfile + rename so mtime updates atomically.
#
# Env:
#   NGINX_RELOAD_WATCH_FILE   path to the cert file to poll
#                             (default: /etc/nginx/certs/mastio-server.crt)
#   NGINX_RELOAD_POLL_SECONDS poll interval (default: 60)
# =============================================================================
set -eu
CERT_FILE="${NGINX_RELOAD_WATCH_FILE:-/etc/nginx/certs/mastio-server.crt}"
INTERVAL="${NGINX_RELOAD_POLL_SECONDS:-60}"
last_mtime=""
if [ -f "$CERT_FILE" ]; then
    last_mtime=$(stat -c %Y "$CERT_FILE" 2>/dev/null || echo "")
fi
echo "[nginx-reload-watcher] start watch=$CERT_FILE interval=${INTERVAL}s initial_mtime=${last_mtime:-none}"
while sleep "$INTERVAL"; do
    if [ ! -f "$CERT_FILE" ]; then
        continue
    fi
    cur_mtime=$(stat -c %Y "$CERT_FILE" 2>/dev/null || echo "")
    if [ -z "$cur_mtime" ]; then
        continue
    fi
    if [ -z "$last_mtime" ]; then
        last_mtime="$cur_mtime"
        echo "[nginx-reload-watcher] cert appeared, baseline mtime=$cur_mtime"
        continue
    fi
    if [ "$cur_mtime" != "$last_mtime" ]; then
        echo "[nginx-reload-watcher] cert mtime changed ($last_mtime -> $cur_mtime), reloading nginx"
        if nginx -s reload 2>&1; then
            echo "[nginx-reload-watcher] reload OK"
        else
            rc=$?
            echo "[nginx-reload-watcher] reload FAILED (rc=$rc), will retry on next change" >&2
        fi
        last_mtime="$cur_mtime"
    fi
done
