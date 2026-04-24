#!/usr/bin/env bash
# Scripted chaos timeline. Runs while the workload (nightly.sh go) is
# active in another terminal. Each fault is timed so post-run analysis
# can correlate workload latency/failure with the fault window.
#
# Profiles:
#   light  — 1 Mastio kill + 1 partition, ~2 minutes total
#   heavy  — both Mastio killed + court partition + court kill + DB
#            latency injection on both proxies, ~6-7 minutes total. The
#            DB latency step is the one that exercises ADR-013 Phase 3
#            (circuit breaker); without it, heavy only validates the
#            proxy's resilience to Court/broker faults, not to its
#            OWN DB saturation.
#
# Usage: sequence.sh [--profile light|heavy]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

profile="light"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) profile="$2"; shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

chaos_log "sequence_start" profile="$profile"

case "$profile" in
    light)
        # Warm up: 20s of clean traffic before the first fault.
        sleep 20
        "$SCRIPT_DIR/kill.sh" proxy-a --down-seconds 15
        # Recovery window: let the workload reconnect + flush.
        sleep 30
        "$SCRIPT_DIR/partition.sh" broker --duration 20
        sleep 20
        ;;
    heavy)
        sleep 20
        "$SCRIPT_DIR/kill.sh" proxy-a --down-seconds 20
        sleep 30
        "$SCRIPT_DIR/kill.sh" proxy-b --down-seconds 20
        sleep 30
        "$SCRIPT_DIR/partition.sh" broker --duration 30
        sleep 30
        "$SCRIPT_DIR/kill.sh" broker --down-seconds 15
        sleep 30
        # ADR-013 Phase 3 end-to-end: saturate the proxy's SQLite volume
        # so the passive sampler sees real query p99 rise. Tune the
        # breaker thresholds in .env.chaos (see .env.chaos.example) so
        # the modest latency injected here actually crosses activation
        # — default 500 ms is usually above the spike this produces.
        "$SCRIPT_DIR/db-latency.sh" proxy-a --duration 30
        sleep 15
        "$SCRIPT_DIR/db-latency.sh" proxy-b --duration 30
        sleep 30
        ;;
    *)
        echo "unknown profile: $profile" >&2
        exit 1
        ;;
esac

chaos_log "sequence_end" profile="$profile"
