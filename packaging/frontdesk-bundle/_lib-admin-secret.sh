#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Frontdesk — shared helper: mint a Connector admin secret
# ═══════════════════════════════════════════════════════════════════════════════
#
# Sourced by:
#   - generate-frontdesk-env.sh   (first-run env mint)
#   - deploy.sh                   (--rotate-admin-secret subcommand)
#
# The Connector validates ``X-Admin-Secret`` against
# ``CULLIS_CONNECTOR_ADMIN_SECRET`` (cullis_connector/admin/auth.py) on
# every admin API call. Keep the generator centralized so both first-mint
# and rotation paths produce wire-compatible secrets.
#
# Output: 48 lowercase hex chars (matching ``openssl rand -hex 24``),
# with a /dev/urandom + coreutils fallback for hosts without openssl
# (minimal NixOS, Alpine, distroless, trimmed WSL2 Ubuntu). Issue #638.

gen_admin_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    else
        head -c 24 /dev/urandom | od -An -vtx1 | tr -d ' \n'
    fi
}
