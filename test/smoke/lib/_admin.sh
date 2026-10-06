#!/usr/bin/env bash
# =============================================================================
# Cullis smoke — admin bootstrap helpers
# =============================================================================
#
# First-boot admin password is seeded via MCP_PROXY_INITIAL_ADMIN_PASSWORD
# (env.smoke) so /proxy/register doesn't have to be driven by a browser.
# These helpers exist for:
#   * verify the seed actually landed (curl /proxy/login + expect 200)
#   * fetch the Org CA from the running Mastio for host-side trust
#   * read org_id out of the running container
#
# Auth model used by every /v1/admin/* call: X-Admin-Secret header,
# pinned to MCP_PROXY_ADMIN_SECRET. The dashboard cookie session is NOT
# used here — scenarios that need dashboard semantics would have to
# layer a separate login helper.
# =============================================================================

# Source guard — only source _common.sh once even if multiple scenarios
# pull both _admin.sh and _agent.sh.
if [[ -z "${_SMOKE_COMMON_SOURCED:-}" ]]; then
    # shellcheck source=./_common.sh
    source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"
    _SMOKE_COMMON_SOURCED=1
fi

# Fetch the Org CA the Mastio minted at first boot. The host bind dir
# state/nginx-certs/ is owned by uid 10001 (the container user) and
# mode 0750, so the host invoker cannot read it directly. Use ``docker
# cp`` from inside the running mcp-proxy container — same pattern as
# packaging/mastio-bundle/deploy.sh:961.
admin_export_org_ca() {
    local dst="$(smoke_org_ca_path)"
    local cid
    cid="$(smoke_compose ps -q mcp-proxy 2>/dev/null | head -1)"
    if [[ -z "$cid" ]]; then
        log_warn "mcp-proxy container id not found — stack may not be up"
        return 1
    fi
    if docker cp "$cid:/var/lib/mastio/nginx-certs/org-ca.crt" "$dst" 2>/dev/null; then
        chmod 0644 "$dst"
        log_info "org CA exported to ${dst#$SMOKE_ROOT/}"
        return 0
    fi
    log_warn "docker cp org-ca.crt failed — mastio may not have first-booted yet"
    return 1
}

# Read org_id from the running Mastio's SQLite (or Postgres). Returns
# 16-char hex on stdout. Used by 10_admin_bootstrap to assert the
# Mastio actually completed first-boot.
admin_read_org_id() {
    local val=""
    val="$(smoke_compose exec -T mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import os
import sys
url = os.environ.get('MCP_PROXY_DATABASE_URL', '')
try:
    row = query(\"SELECT value FROM proxy_config WHERE key='org_id'\")[0]
    print(row[0] if row else '')
except Exception as exc:
    print('', end='')
    print(f'org-id-read-error: {exc}', file=sys.stderr)
" 2>/dev/null)"
    printf '%s' "$val"
}

# Seed an AI provider credentials row so the cullis_native backend
# dispatches to a deterministic, offline upstream instead of the real
# provider API. ``api_base`` points the native SDK (AsyncAnthropic /
# AsyncOpenAI) at the in-stack mock-tsa:2561 endpoint.
#
# Why in-container Python instead of the dashboard form: the dispatcher
# reads ``ai_provider_credentials`` directly, and the creds_json is
# Fernet-wrapped at rest with the per-install master key the running
# Mastio minted into proxy_config at first boot. Writing through the
# app's own ``upsert_ai_provider_creds`` (which calls encrypt_at_rest)
# guarantees the row round-trips with that exact key — same pattern as
# admin_read_org_id running python in-container. PROXY_SKIP_MIGRATIONS=1
# keeps this a metadata.create_all no-op (the DB is already migrated by
# the running app) so the seed never contends on the alembic lock.
admin_seed_ai_provider_creds() {
    local provider="$1" api_base="$2" api_key="${3:-smoke-fake-anthropic-key}"
    smoke_compose exec -T \
        -e SEED_PROVIDER="$provider" \
        -e SEED_API_BASE="$api_base" \
        -e SEED_API_KEY="$api_key" \
        -e PROXY_SKIP_MIGRATIONS=1 \
        mcp-proxy python3 -c "$(cat "$SMOKE_ROOT/probes/read_db.py")
import asyncio, os, sys
from mcp_proxy.db import init_db, upsert_ai_provider_creds
async def _seed():
    await init_db(os.environ['MCP_PROXY_DATABASE_URL'])
    await upsert_ai_provider_creds(
        os.environ['SEED_PROVIDER'],
        {'api_key': os.environ['SEED_API_KEY'],
         'api_base': os.environ['SEED_API_BASE']},
        updated_by='smoke',
    )
try:
    asyncio.run(_seed())
    print('ok')
except Exception as exc:  # noqa: BLE001
    print(f'seed-error: {exc}', file=sys.stderr)
    sys.exit(1)
" 2>&1
}

# Verify the admin password seed was honoured. The Mastio writes the
# bcrypt hash on first boot if MCP_PROXY_INITIAL_ADMIN_PASSWORD is
# set; we hit /proxy/login with the seeded password and expect a 303
# redirect to the post-login page.
admin_verify_seed_password() {
    local pwd
    pwd="$(grep -E '^MCP_PROXY_INITIAL_ADMIN_PASSWORD=' "$SMOKE_ROOT/env.smoke" | head -1 | cut -d= -f2-)"
    [[ -n "$pwd" ]] || die "MCP_PROXY_INITIAL_ADMIN_PASSWORD not set in env.smoke"

    local url status
    url="$(smoke_mastio_url)/proxy/login"
    # POST the form, do NOT follow redirects (we want to see the 303).
    # Login form expects ``password`` field; CSRF is form-token enforced
    # only when a session cookie is present, which we don't have yet.
    status="$(curl -sk -o /dev/null -w '%{http_code}' \
        -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "password=$pwd" \
        "$url" || echo 000)"
    _set_smoke_status "$status"
    case "$status" in
        303|302) return 0 ;;  # success → redirect
        *)
            log_warn "expected 303 on login submit, got HTTP $status"
            return 1
            ;;
    esac
}
