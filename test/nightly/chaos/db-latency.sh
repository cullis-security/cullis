#!/usr/bin/env bash
# Disk I/O saturation on a Mastio container's SQLite volume — ADR-013
# Phase 3 (circuit breaker) end-to-end chaos scenario.
#
# Why: the Phase 3 breaker protects the Mastio from its OWN DB latency
# (pool-acquire + query wall time, read via both the active probe and
# SQLAlchemy event-listener passive sampler). The Phase 2 / Phase 6
# defences need their own chaos signal, and this is the one for Phase
# 3. A kill of the Court/broker does not exercise this path because
# the Mastio's SQLite stays fast throughout.
#
# What: writes a large random file into the ``/data`` volume that
# houses ``mcp_proxy.db``, contending with sqlite's fsync writes on
# the same device. The passive sampler then records rising query p99,
# max(probe, passive) crosses the activation threshold, and the
# middleware sheds until the noise file is removed.
#
# Usage: db-latency.sh <service> [--duration N] [--size-mb N]
# Example: chaos/db-latency.sh proxy-a --duration 30 --size-mb 400
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

if [[ $# -lt 1 ]]; then
    echo "usage: db-latency.sh <service> [--duration N] [--size-mb N]" >&2
    exit 1
fi

service="$1"; shift || true
duration=30
size_mb=400
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) duration="$2"; shift 2 ;;
        --size-mb)  size_mb="$2";  shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

container="$(compose ps -q "$service" | head -n1)"
if [[ -z "$container" ]]; then
    echo "[chaos] service '$service' has no running container" >&2
    exit 1
fi

# Path inside the container: the Mastio's SQLite lives under /data
# (see mcp_proxy/Dockerfile). Put the noise next to it so they fight
# for the same volume bandwidth.
noise_path="/data/cullis-chaos-noise"
bs="4M"
count="$(( size_mb / 4 ))"

chaos_log "db_latency_start" \
    service="$service" duration_seconds="$duration" \
    size_mb="$size_mb" noise_path="$noise_path"

# Fire-and-forget: dd runs detached so we can time the window. Use sh -c
# so the redirection applies inside the container. /dev/urandom keeps
# the kernel + device busy (not just the filesystem cache).
docker exec -d "$container" sh -c \
    "dd if=/dev/urandom of=${noise_path} bs=${bs} count=${count} 2>/dev/null; true"

sleep "$duration"

# Remove the noise file to restore normal sqlite write throughput.
# ``rm -f`` never errors; if dd already finished the file is still
# there (it gets cleaned up), and if dd is mid-write the kernel's
# pending writes are dropped with the unlink.
docker exec "$container" sh -c "rm -f ${noise_path}" || true

chaos_log "db_latency_end" service="$service"
