#!/usr/bin/env bash
# =============================================================================
# 90_multiworker — restart Mastio with 4 uvicorn workers, verify leadership
# =============================================================================
#
# Memory: feedback_mastio_multiworker_audit_chain_retry_ship_safe.md +
# feedback_multiworker_uvicorn_systemic_gaps.md. Multi-worker uvicorn
# is the default in packaging/mastio-bundle/ (4 workers), and the
# audit chain retry path + leader-election (lifespan/get_leader) is
# the contract that keeps F0.1 ship-safe.
#
# Asserts:
#   * After restart with MASTIO_WORKERS=4, the stack stays healthy
#   * No IntegrityError on the audit chain when ~50 audit-emitting
#     calls fire concurrently against the 4-worker stack
#   * The audit chain remains internally consistent (no gaps in
#     chain_seq, every row_hash populated)
# =============================================================================
set -euo pipefail

SCENARIO_TAG="90_multiworker"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_agent.sh
source "$SMOKE_LIB_DIR/_agent.sh"

audit_agent="$(agent_enroll auditburst 'Audit burst fixture' '[]')"

# Snapshot the row count pre-restart so we can compute the delta after
# the burst.
pre_count="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    print(query('SELECT COUNT(*) FROM audit_log')[0][0])
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"
[[ "$pre_count" =~ ^[0-9]+$ ]] || die "pre_count unreadable"

log_info "restarting Mastio with MASTIO_WORKERS=4"
# Restart only the mcp-proxy + nginx so redis + mock-tsa + the state
# bind dirs survive. ``up -d --wait`` blocks until healthcheck passes.
MASTIO_WORKERS=4 smoke_compose up -d --wait --force-recreate mcp-proxy mastio-nginx \
    || die "stack failed to come back up with 4 workers"

if ! wait_http_ok "$(smoke_mastio_url)/health" 60; then
    die "Mastio did not become healthy after multi-worker restart"
fi
log_pass "stack healthy with MASTIO_WORKERS=4"

# Use an audited mutation on a dedicated fixture. Public-key GETs do not
# emit audit records and cannot exercise concurrent chain writers.
base="$(smoke_mastio_url)"
secret="$(smoke_admin_secret)"
log_info "firing 50 concurrent capability updates on the audit fixture"

burst_pids=()
fail_log="$(mktemp)"
for i in $(seq 1 50); do
    (
        if ! curl -sk -f -o /dev/null \
            -X PATCH -H "X-Admin-Secret: $secret" \
            -H "Content-Type: application/json" -d '{"capabilities":[]}' \
            "$base/v1/admin/agents/$audit_agent/capabilities"; then
            echo "call $i failed" >> "$fail_log"
        fi
    ) &
    burst_pids+=($!)
done

# Wait for every child.
for pid in "${burst_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
done

if [[ -s "$fail_log" ]]; then
    fails="$(wc -l <"$fail_log")"
    die "multi-worker burst failed ${fails}/50 calls"

fi
rm -f "$fail_log"

# Batched audit is asynchronous (one-second flush). Require all 50 fixture
# events within a bounded deadline; unrelated audit activity cannot satisfy it.
smoke_compose exec -T -e "AUDIT_BURST_AGENT=$audit_agent" mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
$(cat <<'PYCODE'
import time
sql = "SELECT COUNT(*) FROM audit_log WHERE action = 'agent.capabilities_patched' AND detail = ?"
detail = "agent_id=" + os.environ["AUDIT_BURST_AGENT"] + " capabilities=[]"
deadline = time.monotonic() + 10
while True:
    count = query(sql, (detail,))[0][0]
    if count == 50:
        print("50/50 fixture mutations persisted in audit")
        break
    if count > 50 or time.monotonic() >= deadline:
        raise SystemExit(f"Expected exactly 50 fixture audit rows, found {count}")
    time.sleep(0.2)
PYCODE
)"

# ── Verify the chain is intact ──────────────────────────────────────────────
result="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    total = query('SELECT COUNT(*) FROM audit_log')[0][0]
    nulls = query('SELECT COUNT(*) FROM audit_log WHERE chain_seq IS NULL OR row_hash IS NULL')[0][0]
    max_seq = query('SELECT MAX(chain_seq) FROM audit_log WHERE chain_seq IS NOT NULL')[0][0] or 0
    distinct = query('SELECT COUNT(DISTINCT chain_seq) FROM audit_log WHERE chain_seq IS NOT NULL')[0][0] or 0
    print(f'{total}|{nulls}|{max_seq}|{distinct}')
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"

[[ "$result" != error:* ]] || die "post-burst chain query failed: $result"
IFS='|' read -r total nulls max_seq distinct_seq <<<"$result"
delta=$(( total - pre_count ))

# Fresh smoke state has no legacy rows; every audit event must be chained.
if [[ "$nulls" -ne 0 ]]; then
    die "post-burst: ${nulls} rows have NULL chain_seq/row_hash — multi-worker writer broke chain"
fi

# Burst should have added at LEAST as many rows as there were
# successful calls (some calls may write multiple rows: auth check +
# the actual admin call). Don't assert exact count.
if [[ "$delta" -lt 50 ]]; then
    die "burst delta=${delta}: missing audit rows from 50 successful writes"
fi

# distinct_seq must == count of non-null chain_seq rows (no duplicate
# sequence numbers — that would mean two workers raced past the retry).
non_null=$(( total - nulls ))
if [[ "$distinct_seq" -ne "$non_null" ]]; then
    die "chain_seq collision detected: distinct=${distinct_seq} vs non_null=${non_null}"
fi

log_pass "multi-worker chain integrity OK (delta=${delta}, max_seq=${max_seq}, distinct=${distinct_seq})"

# Recompute hashes after the concurrent writes, not only uniqueness/count.
bash "$SMOKE_ROOT/scenarios/80_audit_verify.sh"
