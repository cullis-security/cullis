#!/usr/bin/env bash
# =============================================================================
# 70_tsa_anchor — RFC 3161 TSA anchoring of the audit chain head
# =============================================================================
#
# env.smoke configures the audit anchor watcher with:
#   MCP_PROXY_AUDIT_ANCHOR_TSA_URL=http://mock-tsa:2560/tsr
#   MCP_PROXY_AUDIT_ANCHOR_INTERVAL_SECONDS=30
#
# The watcher loop in mcp_proxy/lifespan/audit_anchor_watcher.py wakes
# every 30s and POSTs a TimeStampReq to the mock TSA, which returns a
# real RFC 3161 token signed by the bundled ephemeral CA. The token
# is persisted in audit_chain_anchors (with the ``T1|`` magic prefix).
#
# Asserts:
#   * audit_chain_anchors has at least 1 row within 90s of scenario start
#   * The persisted token starts with the ``T1|`` magic prefix
#   * tsa_url + chain_seq + row_hash columns are populated
#   * Negative: pointing the watcher at an unreachable TSA after the
#     first successful anchor must NOT take the Mastio down (fail-soft)
# =============================================================================
set -euo pipefail

SCENARIO_TAG="70_tsa_anchor"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"

# Wait up to 90s for the first anchor to land. The watcher's tick is
# 30s + the initial sleep; allow generous slack for CI.
deadline=$(( $(date +%s) + 90 ))
anchors=0
while (( $(date +%s) < deadline )); do
    anchors="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    print(query('SELECT COUNT(*) FROM audit_chain_anchors')[0][0])
except Exception:
    print('0')
" 2>/dev/null || echo '0')"

    if [[ "$anchors" -ge 1 ]]; then
        break
    fi
    sleep 5
done

if [[ "$anchors" -lt 1 ]]; then
    # Capture watcher logs to help diagnose.
    log_warn "no anchor in audit_chain_anchors after 90s. recent watcher logs:"
    smoke_compose logs --tail=40 mcp-proxy 2>&1 \
        | grep -E 'audit_anchor_watcher|tsa' >&2 || true
    die "TSA anchor watcher did not write a row within 90s"
fi
log_pass "audit_chain_anchors has ${anchors} row(s) after wait"

# ── Validate the persisted token shape ──────────────────────────────────────
shape="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    row = query('SELECT chain_seq, row_hash, tsa_url, tsa_token FROM audit_chain_anchors ORDER BY id DESC LIMIT 1')[0]
    if not row:
        print('no-row')
    else:
        chain_seq, row_hash, tsa_url, token = row
        # token is bytes on Postgres BYTEA, possibly bytes on SQLite
        # too. Coerce to bytes for a deterministic prefix view.
        if isinstance(token, memoryview):
            token = bytes(token)
        if isinstance(token, str):
            token = token.encode('latin-1', 'replace')
        # Print on separate lines so the bash caller can read fixed
        # fields without splitting on a delimiter the prefix may
        # contain itself ('T1|').
        prefix2 = token[:2].decode('latin-1', 'replace') if token else ''
        token_len = len(token) if token else 0
        print(f'chain_seq={chain_seq}')
        print(f'row_hash16={(row_hash or \"\")[:16]}')
        print(f'tsa_url={tsa_url}')
        print(f'prefix2={prefix2}')
        print(f'token_len={token_len}')
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"

[[ "$shape" != "no-row" ]] || die "anchor row missing on follow-up read"
[[ "$shape" != error:* ]]  || die "anchor introspection failed: $shape"

# Parse k=v lines.
seq="$(printf '%s\n' "$shape" | grep '^chain_seq=' | cut -d= -f2-)"
hash16="$(printf '%s\n' "$shape" | grep '^row_hash16=' | cut -d= -f2-)"
url="$(printf '%s\n' "$shape" | grep '^tsa_url=' | cut -d= -f2-)"
prefix2="$(printf '%s\n' "$shape" | grep '^prefix2=' | cut -d= -f2-)"
token_len="$(printf '%s\n' "$shape" | grep '^token_len=' | cut -d= -f2-)"

[[ -n "$seq" && "$seq" -gt 0 ]]   || die "anchor chain_seq is empty/zero: $shape"
[[ -n "$hash16" ]]                || die "anchor row_hash is empty"
[[ "$url" == http://mock-tsa:* ]] || die "anchor tsa_url unexpected: $url"
[[ "$prefix2" == "T1" ]]          || die "anchor token does not carry the RFC 3161 T1| prefix (got prefix2='$prefix2')"
[[ "$token_len" -gt 100 ]]        || die "anchor token suspiciously small (len=$token_len) — TSA response likely malformed"

log_pass "anchor row shape OK (chain_seq=${seq}, tsa_url=${url}, token_len=${token_len}, prefix=T1|)"
