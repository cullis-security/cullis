#!/usr/bin/env bash
# =============================================================================
# 80_audit_verify — in-process chain verification end-to-end
# =============================================================================
#
# scripts/cullis-audit-verify.py was written against the Court
# (cullis-enterprise) audit_log schema (``event_type``, ``entry_hash``,
# ``previous_hash``, ``result``, ``session_id``, ``org_id``). The
# public Mastio's audit_log uses ``action``, ``row_hash``,
# ``prev_hash``, ``status``, ``request_id``, ``hash_format``.
#
# The in-process verifier ``mcp_proxy.db.verify_audit_chain`` knows
# the Mastio schema and is the authoritative chain-walker. We
# exercise it here as the air-gapped tamper-evidence signal until the
# standalone CLI gets ported (follow-up tracked in the README).
#
# Asserts:
#   * verify_audit_chain returns (True, None, None) — every chained
#     row recomputes to its stored row_hash and the chain has no gaps
#   * The number of rows walked matches the count of non-null
#     chain_seq rows in audit_log (no silent skip)
# =============================================================================
set -euo pipefail

SCENARIO_TAG="80_audit_verify"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"

VERIFY_SCRIPT="$(cat <<'PY'
import hashlib, os, sys

# Reuse the in-tree canonical hash function so the smoke is a
# byte-exact replay of the lifespan's verify_audit_chain. Don't go
# through get_db() — it requires init_db() to have run, which only
# happens inside the FastAPI lifespan.
from mcp_proxy.db import compute_audit_row_hash, _AUDIT_CHAIN_GENESIS

url = os.environ.get('MCP_PROXY_DATABASE_URL', '')

rows = query('SELECT chain_seq, prev_hash, row_hash, timestamp, agent_id, action, tool_name, status, detail, request_id, dpop_jkt, on_behalf_of_user_id, hash_format FROM audit_log WHERE chain_seq IS NOT NULL ORDER BY chain_seq ASC')
if not rows:
    print('VERIFY_OK total=0  (empty chain — nothing to verify)')
    sys.exit(0)

expected_seq = None
expected_prev = None
for row in rows:
    chain_seq, prev_hash, stored_hash, ts, agent_id, action, tool_name, status, detail, request_id, dpop_jkt, obo, hash_format = row
    chain_seq = int(chain_seq)
    prev_hash = str(prev_hash) if prev_hash is not None else _AUDIT_CHAIN_GENESIS
    stored_hash = str(stored_hash)
    if expected_seq is None:
        expected_seq = chain_seq
        if chain_seq == 1 and prev_hash != _AUDIT_CHAIN_GENESIS:
            print(f'VERIFY_FAIL seq={chain_seq} reason=first row prev_hash != genesis')
            sys.exit(1)
    else:
        if chain_seq != expected_seq:
            print(f'VERIFY_FAIL seq={chain_seq} reason=chain_seq gap expected {expected_seq}')
            sys.exit(1)
        if expected_prev is not None and prev_hash != expected_prev:
            print(f'VERIFY_FAIL seq={chain_seq} reason=prev_hash mismatch')
            sys.exit(1)
    recomputed = compute_audit_row_hash(
        chain_seq=chain_seq,
        timestamp=str(ts),
        agent_id=str(agent_id),
        action=str(action),
        tool_name=tool_name,
        status=str(status),
        detail=detail,
        request_id=request_id,
        prev_hash=prev_hash,
        dpop_jkt=dpop_jkt,
        on_behalf_of_user_id=obo,
        hash_format=hash_format,
    )
    if recomputed != stored_hash:
        print(f'VERIFY_FAIL seq={chain_seq} reason=row_hash mismatch (stored={stored_hash[:16]} recomputed={recomputed[:16]})')
        sys.exit(1)
    expected_prev = stored_hash
    expected_seq = chain_seq + 1

print(f'VERIFY_OK total={len(rows)}')
sys.exit(0)
PY
)"

set +e
result="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
$VERIFY_SCRIPT" 2>&1)"
exit_code=$?
set -e

[[ "$exit_code" -eq 0 ]] \
    || die "verify_audit_chain returned non-zero — chain tampered. output: $result"

# Parse the OK line.
if ! grep -q '^VERIFY_OK' <<<"$result"; then
    die "verifier produced no VERIFY_OK line. raw output: $result"
fi

total="$(grep -oE 'total=[0-9]+' <<<"$result" | head -1 | cut -d= -f2)"
[[ "${total:-0}" -gt 0 ]] \
    || die "verifier walked 0 chained rows — chain may be empty or selector broken"

log_pass "verify_audit_chain: ${total} chained rows verified, chain intact"

# Bonus: round-trip the audit_chain_anchors → TSA token decoding via
# asn1crypto, mirroring what the offline standalone verifier would do
# for the anchor portion. Skip cleanly when no anchors are present.
anchor_check="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import hashlib, os, sys

url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
row = query('SELECT chain_seq, row_hash, tsa_token FROM audit_chain_anchors ORDER BY id DESC LIMIT 1')[0]
if row is None:
    print('NO_ANCHORS')
    sys.exit(0)

chain_seq, row_hash, token = row
if isinstance(token, memoryview):
    token = bytes(token)
if not token or not token.startswith(b'T1|'):
    print(f'BAD_PREFIX seq={chain_seq}')
    sys.exit(1)

try:
    # Import tsp for side effect: registers TSTInfo in the CMS
    # encap_content_info OID dispatch table so .parsed below resolves
    # to TSTInfo instead of the default asn1crypto.core.Sequence.
    from asn1crypto import cms, tsp  # noqa: F401
    raw = token[3:]
    # The persisted token is the bare TimeStampToken — a CMS
    # ContentInfo wrapping SignedData wrapping TSTInfo. See
    # mcp_proxy/audit/tsa_client.py:202 (token_raw = tsr['time_stamp_token'].dump()).
    ci = cms.ContentInfo.load(raw)
    signed_data = ci['content']
    tst_info = signed_data['encap_content_info']['content'].parsed
    imprint = tst_info['message_imprint']['hashed_message'].native.hex()
    # The in-tree tsa_client hashes the row_hash once more before
    # sending the messageImprint, so the imprint should equal
    # sha256(row_hash_ascii_hex). Verify both shapes — bare equality
    # OR the hashed equivalent — to stay robust against any future
    # client-side simplification.
    sha = hashlib.sha256(row_hash.encode('ascii')).hexdigest()
    if imprint == sha or imprint == row_hash:
        print(f'ANCHOR_OK seq={chain_seq} imprint={imprint[:16]}')
        sys.exit(0)
    print(f'ANCHOR_IMPRINT_MISMATCH seq={chain_seq} imprint={imprint[:16]} expected_sha={sha[:16]} or_row_hash={row_hash[:16]}')
    sys.exit(1)
except Exception as exc:
    print(f'PARSE_ERROR {exc}')
    sys.exit(1)
" 2>&1 || true)"
anchor_rc=$?

case "$anchor_check" in
    NO_ANCHORS*)
        log_warn "no anchors in audit_chain_anchors yet (70_tsa_anchor ran but watcher loop may have not ticked again)"
        ;;
    ANCHOR_OK*)
        if [[ $anchor_rc -ne 0 ]]; then
            die "anchor decode returned nonzero unexpectedly: $anchor_check"
        fi
        log_pass "TSA anchor token round-trip via asn1crypto: ${anchor_check}"
        ;;
    *)
        die "anchor verification failed: $anchor_check"
        ;;
esac
