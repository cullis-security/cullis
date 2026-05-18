#!/usr/bin/env bash
# _run-k6.sh: k6 wrapper with post-run NDJSON cleanup.
#
# Why: `k6 --out json=` writes one NDJSON line per HTTP sample. At 2k req/s
# this is ~30 MiB/min. A 1h soak is ~1.8 GiB, a 30min 5k-VU burst is ~18 GiB,
# a 3h partial soak is ~89 GiB. The 2026-05-18 incident saturated 107 GiB of
# /tmp + 18 GiB in repo path, killed k6 mid-soak with ENOSPC, and lost the
# tail of the telemetry. See memory feedback_k6_ndjson_saturates_tmp.
#
# What it does: invokes k6 with --out json=<ndjson> + --summary-export=<json>,
# then on exit (success OR failure) drops the ndjson if it exceeded the size
# threshold. The summary always survives. Override behaviour via env:
#
#   K6_SKIP_NDJSON=1                  Do not write the ndjson at all. Use this for
#                                     high-RPS scenarios against fast targets where
#                                     post-run cleanup is too late (file grows faster
#                                     than disk can hold it — observed 110 GiB/h on a
#                                     local Mastio bundle 2026-05-18). Wins over
#                                     K6_KEEP_NDJSON.
#   K6_KEEP_NDJSON=1                  Never drop ndjson (forensic / _analyze_burst.py).
#                                     Ignored when K6_SKIP_NDJSON=1.
#   K6_NDJSON_KEEP_THRESHOLD_MB=<N>   Drop only if ndjson > N MiB. Default 1024.
#   K6_RESULTS_DIR=<path>             Where to write ndjson + summary. Default
#                                     /tmp/k6-run-<scenario>-<epoch>.
#   K6_EXTRA_ARGS="..."               Extra args appended to the k6 invocation.
#
# Usage:
#   bash scripts/stress/_run-k6.sh soak-stability.js
#   bash scripts/stress/_run-k6.sh intra-org-mastio-burst.js
#   K6_KEEP_NDJSON=1 bash scripts/stress/_run-k6.sh intra-org-mastio-burst.js
#
# Requires: k6 on PATH (use `nix-shell -p k6 --run "bash scripts/stress/_run-k6.sh ..."`
# on NixOS).

set -euo pipefail

SCRIPT="${1:-}"
if [[ -z "${SCRIPT}" ]]; then
    echo "usage: $0 <scenario.js> [extra k6 args...]" >&2
    exit 2
fi
shift

STRESS_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_PATH="${STRESS_DIR}/${SCRIPT}"
if [[ ! -f "${SCENARIO_PATH}" ]]; then
    echo "scenario not found: ${SCENARIO_PATH}" >&2
    exit 2
fi

SCENARIO_NAME="$(basename "${SCRIPT}" .js)"
EPOCH="$(date +%s)"
RESULTS_DIR="${K6_RESULTS_DIR:-/tmp/k6-run-${SCENARIO_NAME}-${EPOCH}}"
mkdir -p "${RESULTS_DIR}"

NDJSON="${RESULTS_DIR}/results.ndjson"
SUMMARY="${RESULTS_DIR}/summary.json"

KEEP_NDJSON="${K6_KEEP_NDJSON:-0}"
KEEP_THRESHOLD_MB="${K6_NDJSON_KEEP_THRESHOLD_MB:-1024}"
SKIP_NDJSON="${K6_SKIP_NDJSON:-0}"

# K6_SKIP_NDJSON=1 wins over K6_KEEP_NDJSON. Skipping means we never
# pass --out json= to k6, so no NDJSON file exists at all. Use this
# for high-RPS scenarios against fast targets where the file would
# grow faster than disk can hold it (~110 GiB/h soak on a local
# bundle observed 2026-05-18).
if [[ "${SKIP_NDJSON}" == "1" && "${KEEP_NDJSON}" == "1" ]]; then
    echo "[_run-k6] WARNING: K6_SKIP_NDJSON=1 overrides K6_KEEP_NDJSON=1 (no ndjson will be written)." >&2
fi

cleanup() {
    local rc=$?
    if [[ "${SKIP_NDJSON}" == "1" ]]; then
        echo "[_run-k6] K6_SKIP_NDJSON=1, no ndjson was written" >&2
    elif [[ -f "${NDJSON}" ]]; then
        local size_bytes
        size_bytes=$(stat -c '%s' "${NDJSON}" 2>/dev/null || echo 0)
        local size_mb=$((size_bytes / 1024 / 1024))
        if [[ "${KEEP_NDJSON}" == "1" ]]; then
            echo "[_run-k6] K6_KEEP_NDJSON=1, kept ${NDJSON} (${size_mb} MiB)" >&2
        elif (( size_mb > KEEP_THRESHOLD_MB )); then
            rm -f "${NDJSON}"
            echo "[_run-k6] dropped ndjson (${size_mb} MiB > ${KEEP_THRESHOLD_MB} MiB threshold). summary at ${SUMMARY}" >&2
        else
            echo "[_run-k6] kept ndjson (${size_mb} MiB <= ${KEEP_THRESHOLD_MB} MiB threshold) at ${NDJSON}" >&2
        fi
    fi
    if [[ -f "${SUMMARY}" ]]; then
        echo "[_run-k6] summary preserved: ${SUMMARY}" >&2
    fi
    exit "${rc}"
}
trap cleanup EXIT

# Pre-flight: warn if the output dir has less than 5 GiB free, only
# when we are about to write the NDJSON (skipping = no growth on disk).
TMP_FREE_MB=$(df -BM --output=avail "${RESULTS_DIR}" | tail -1 | tr -dc '0-9')
if [[ "${SKIP_NDJSON}" != "1" ]] && (( TMP_FREE_MB < 5120 )); then
    echo "[_run-k6] WARNING: only ${TMP_FREE_MB} MiB free at ${RESULTS_DIR}. ndjson at 2k req/s grows ~30 MiB/min and can hit 100+ GiB/h against fast targets. Consider K6_SKIP_NDJSON=1." >&2
fi

echo "[_run-k6] scenario=${SCENARIO_NAME} results_dir=${RESULTS_DIR}" >&2
echo "[_run-k6] skip_ndjson=${SKIP_NDJSON} keep_ndjson=${KEEP_NDJSON} threshold_mb=${KEEP_THRESHOLD_MB} tmp_free_mb=${TMP_FREE_MB}" >&2

# Build the k6 argv. When K6_SKIP_NDJSON=1 we omit --out json= so k6
# never opens the NDJSON file in the first place. The summary export
# is always on.
K6_OUTPUT_ARGS=()
if [[ "${SKIP_NDJSON}" != "1" ]]; then
    K6_OUTPUT_ARGS+=(--out "json=${NDJSON}")
fi

# Run k6 inline (not via exec) so the EXIT trap above can fire and
# clean up the ndjson. With `exec` the bash process is replaced by
# k6 and the trap is lost.
# shellcheck disable=SC2086
k6 run \
    --insecure-skip-tls-verify \
    "${K6_OUTPUT_ARGS[@]}" \
    --summary-export="${SUMMARY}" \
    ${K6_EXTRA_ARGS:-} \
    "${SCENARIO_PATH}" \
    "$@"
