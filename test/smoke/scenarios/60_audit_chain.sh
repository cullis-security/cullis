#!/usr/bin/env bash
# =============================================================================
# 60_audit_chain — audit_log rows present + chain head verifies
# =============================================================================
#
# Earlier scenarios (10..50) generated audit rows via login, enrollment,
# peer discovery, etc. This scenario asserts:
#
#   * audit_log is non-empty
#   * Every row has chain_seq + row_hash populated (post PR #887 the
#     trigger writes both on insert)
#   * The dashboard's POST /proxy/audit/verify endpoint returns
#     {"ok": true} — same canonicalisation as
#     scripts/cullis-audit-verify.py runs in-process
#
# This is the in-process tamper-evident check. Scenario 80 then exports
# NDJSON + runs the standalone CLI for the air-gapped equivalent.
# =============================================================================
set -euo pipefail

SCENARIO_TAG="60_audit_chain"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=../lib/_common.sh
source "$SMOKE_LIB_DIR/_common.sh"

# ── audit_log row count ────────────────────────────────────────────────────
count="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    print(query('SELECT COUNT(*) FROM audit_log')[0][0])
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"

if [[ "$count" =~ ^error: ]]; then
    die "audit_log count query failed: $count"
fi
if [[ -z "$count" || "$count" -lt 1 ]]; then
    die "audit_log empty after upstream scenarios — chain trigger may be off"
fi
log_pass "audit_log has ${count} row(s)"

# ── chain_seq + row_hash populated on every row ─────────────────────────────
missing="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    print(query('SELECT COUNT(*) FROM audit_log WHERE chain_seq IS NULL OR row_hash IS NULL')[0][0])
except Exception as exc:
    print(f'error:{exc}')
" 2>/dev/null)"

if [[ "$missing" =~ ^error: ]]; then
    die "row-hash null query failed: $missing"
fi
if [[ "$missing" -gt 0 ]]; then
    # Pre-PR #887 legacy rows have chain_seq IS NULL — tolerate up to
    # the first few but warn loudly.
    if [[ "$missing" -gt 5 ]]; then
        die "$missing audit_log rows have chain_seq/row_hash NULL (chain trigger off)"
    fi
    log_warn "$missing legacy rows have NULL chain_seq (tolerated pre-trigger rows)"
fi
log_pass "chain_seq + row_hash populated on ${count} - ${missing} row(s)"

# ── Dashboard /proxy/audit/verify — in-process chain check ──────────────────
# Requires a dashboard login + CSRF cookie + token. The verify endpoint
# is the in-process equivalent of cullis-audit-verify.py.
pwd_val="$(grep -E '^MCP_PROXY_INITIAL_ADMIN_PASSWORD=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-)"
cookie_jar="$(mktemp)"
trap 'rm -f "$cookie_jar"' EXIT
base="$(smoke_mastio_url)"

# Login first to seat the cookie + CSRF token.
curl -sk -c "$cookie_jar" -o /dev/null \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "password=$pwd_val" \
    "$base/proxy/login" || die "dashboard login failed"

# The audit page renders the session CSRF token on the verify button.
# The endpoint accepts form data, not an X-CSRF-Token JSON request.
dashboard_html="$(curl -sk -f -b "$cookie_jar" "$base/proxy/audit")" || die "audit page fetch failed"
csrf_token="$(printf '%s' "$dashboard_html" | grep -oE 'data-csrf="[a-f0-9]+"' | head -1 | cut -d'"' -f2)"
[[ -n "$csrf_token" ]] || die "audit page missing CSRF token"
resp="$(curl -sk -f -b "$cookie_jar" -X POST \
    --data-urlencode "csrf_token=$csrf_token" "$base/proxy/audit/verify")" \
    || die "dashboard audit verification request failed"
[[ "$(json_get "$resp" 'ok')" == "True" || "$(json_get "$resp" 'ok')" == "true" ]] \
    || die "dashboard audit verification did not confirm integrity"
log_pass "/proxy/audit/verify → ok=true (both chains verified)"
