#!/usr/bin/env bash
# =============================================================================
# 91_merkle_anchor — Merkle batch anchor + inclusion proof end-to-end
# =============================================================================
#
# env.smoke configures the Merkle watcher with an aggressive cadence
# so the scenario hits an anchored batch within the test budget:
#   MCP_PROXY_AUDIT_MERKLE_BATCH_SIZE=8
#   MCP_PROXY_AUDIT_MERKLE_MIN_BATCH=2
#   MCP_PROXY_AUDIT_MERKLE_INTERVAL_SECONDS=15
#
# This scenario:
#   * Waits up to 60s for the first anchor row to land
#   * Fetches /v1/admin/audit/merkle/anchors and asserts shape
#   * Picks a chain_seq inside the anchored range, fetches the
#     inclusion proof via /v1/admin/audit/merkle/proof/{chain_seq}
#   * Replays the Phase 0 verify_inclusion math in-container — the
#     proof must verify against the returned root
#   * Negative: chain_seq outside the anchored range → 404
#   * Negative: wrong admin secret → 403
#
# JSON parsing uses python via docker exec (smoke framework guarantee
# is "no host jq, no host python", everything runs in the Mastio
# container).
# =============================================================================
set -euo pipefail

SCENARIO_TAG="91_merkle_anchor"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"


# ── Step 1: wait for the first Merkle anchor row ───────────────────
deadline=$(( $(date +%s) + 60 ))
anchors=0
while (( $(date +%s) < deadline )); do
    anchors="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os, re
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    print(query('SELECT COUNT(*) FROM audit_merkle_anchors')[0][0])
except Exception:
    print(0)
" 2>/dev/null | tr -d '\r' || echo 0)"
    [[ "$anchors" =~ ^[0-9]+$ ]] || anchors=0
    if (( anchors >= 1 )); then
        break
    fi
    sleep 2
done

(( anchors >= 1 )) \
    || die "no Merkle anchor written within 60s — watcher silent"
log_pass "merkle watcher emitted ${anchors} anchor(s) within 60s"


# ── Step 2: GET /v1/admin/audit/merkle/anchors ────────────────────
ADMIN_SECRET="$(smoke_admin_secret)"
NGINX_URL="$(smoke_mastio_url)"

response="$(curl -sk -X GET \
    -H "X-Admin-Secret: ${ADMIN_SECRET}" \
    "${NGINX_URL}/v1/admin/audit/merkle/anchors?limit=5")"

# Parse the JSON inside the Mastio container — no host jq needed.
parsed="$(printf '%s' "$response" | smoke_compose exec -T mcp-proxy \
    python3 -c "
import json, sys
body = json.loads(sys.stdin.read())
count = body.get('count', 0)
if not body.get('anchors'):
    print(f'|||{count}')
else:
    a = body['anchors'][0]
    print(f\"{a['chain_seq_start']}|{a['chain_seq_end']}|{a['merkle_root']}|{count}\")
" 2>&1 | tr -d '\r')"

IFS='|' read -r start end root_hex count <<<"$parsed"
[[ "$count" =~ ^[0-9]+$ ]] && (( count >= 1 )) \
    || die "admin endpoint returned count=${count:-empty}, response=$response"
log_pass "GET /v1/admin/audit/merkle/anchors returned ${count} anchor(s)"

[[ "$start" =~ ^[0-9]+$ ]] || die "chain_seq_start malformed: $start"
[[ "$end" =~ ^[0-9]+$ ]] || die "chain_seq_end malformed: $end"
[[ ${#root_hex} -eq 64 ]] || die "merkle_root not 64 hex chars: ${root_hex}"
log_pass "anchor metadata sane (range=[${start}, ${end}], root=${root_hex:0:12}...)"


# ── Step 3: GET /v1/admin/audit/merkle/proof/{chain_seq} ──────────
target_seq="$start"
if (( end > start )); then
    target_seq=$(( start + 1 ))
fi

proof_response="$(curl -sk -X GET \
    -H "X-Admin-Secret: ${ADMIN_SECRET}" \
    "${NGINX_URL}/v1/admin/audit/merkle/proof/${target_seq}")"

proof_parse="$(printf '%s' "$proof_response" | smoke_compose exec -T mcp-proxy \
    python3 -c "
import json, sys
body = json.loads(sys.stdin.read())
print(f\"{body.get('chain_seq', '')}|{body.get('merkle_root', '')}|{body.get('leaf_hex', '')}\")
" 2>&1 | tr -d '\r')"
IFS='|' read -r proof_seq proof_root proof_leaf <<<"$proof_parse"
[[ "$proof_seq" == "$target_seq" ]] \
    || die "proof.chain_seq mismatch: got '$proof_seq', expected $target_seq"
[[ "$proof_root" == "$root_hex" ]] \
    || die "proof.merkle_root disagrees with anchor list root"
[[ ${#proof_leaf} -eq 64 ]] \
    || die "proof.leaf_hex not 64 hex chars: '$proof_leaf'"
log_pass "GET /v1/admin/audit/merkle/proof/${target_seq} returned proof"


# ── Step 4: replay verify_inclusion offline ───────────────────────
verify_result="$(printf '%s' "$proof_response" | smoke_compose exec -T mcp-proxy \
    python3 -c "
import json, sys
from mcp_proxy.audit.merkle import verify_inclusion

body = json.loads(sys.stdin.read())
leaf = bytes.fromhex(body['leaf_hex'])
root = bytes.fromhex(body['merkle_root'])
proof = [
    (bytes.fromhex(step['sibling_hex']), step['position'])
    for step in body['proof']
]
ok = verify_inclusion(leaf, proof, root)
print('OK' if ok else 'FAIL')
" 2>&1 | tr -d '\r')"

[[ "$verify_result" == "OK" ]] \
    || die "verify_inclusion replay failed: $verify_result"
log_pass "verify_inclusion replay PASSED — Phase 0 math agrees with persisted root"


# ── Step 5: negative — chain_seq outside anchored range → 404 ─────
unanchored_seq=$(( end + 10000 ))
http_status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -H "X-Admin-Secret: ${ADMIN_SECRET}" \
    "${NGINX_URL}/v1/admin/audit/merkle/proof/${unanchored_seq}")"
[[ "$http_status" == "404" ]] \
    || die "unanchored chain_seq=${unanchored_seq} returned ${http_status}, expected 404"
log_pass "unanchored chain_seq correctly returned 404"


# ── Step 6: negative — wrong admin secret → 403 ──────────────────
http_status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -H "X-Admin-Secret: wrong-secret" \
    "${NGINX_URL}/v1/admin/audit/merkle/anchors")"
[[ "$http_status" == "403" ]] \
    || die "wrong admin secret returned ${http_status}, expected 403"
log_pass "wrong admin secret correctly returned 403"
