#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Frontdesk — Generate frontdesk.env (no secrets, just wiring)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Frontdesk inherits identity from the Connector profile (cert + key minted
# by Mastio during enrollment). There are no secrets to generate here —
# this script only fills in the wiring vars: org slug, trust domain, CA
# bundle path, image versions.
#
# Usage:
#   ./generate-frontdesk-env.sh              # Interactive
#   ./generate-frontdesk-env.sh --defaults   # Sensible same-host defaults
#   ./generate-frontdesk-env.sh --prod       # Needs ORG_ID + TRUST_DOMAIN +
#                                            # CA_BUNDLE_HOST env vars
#   ./generate-frontdesk-env.sh --force      # Overwrite existing frontdesk.env
#
# Environment variables (used by --prod, optional elsewhere):
#   CULLIS_FRONTDESK_ORG_ID           — org slug, e.g. ``acme``
#   CULLIS_FRONTDESK_TRUST_DOMAIN     — SPIFFE TD, e.g. ``acme.prod``
#   CULLIS_FRONTDESK_CA_BUNDLE_HOST   — host path to Mastio CA chain PEM
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }

MODE="interactive"
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --defaults)    MODE="defaults" ;;
        --prod)        MODE="prod" ;;
        # ``--interactive`` is the implicit default — accept it as an
        # explicit alias so operators who type it (or scripts that
        # always pass an explicit mode) don't get a die.
        --interactive) MODE="interactive" ;;
        --force)       FORCE=1 ;;
        --help|-h)
            echo "Usage: $0 [--defaults|--interactive|--prod] [--force]"
            exit 0
            ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

OUT="$SCRIPT_DIR/frontdesk.env"
if [[ -f "$OUT" && "$FORCE" -eq 0 ]]; then
    if [[ "$MODE" != "interactive" ]]; then
        ok "Keeping existing frontdesk.env (use --force to overwrite)"
        exit 0
    fi
    warn "frontdesk.env already exists"
    read -rp "  Overwrite with fresh values? [y/N]: " reply
    [[ "$reply" =~ ^[Yy] ]] || { ok "Keeping existing frontdesk.env"; exit 0; }
fi

[[ -f "$SCRIPT_DIR/frontdesk.env.example" ]] || die "frontdesk.env.example not found"

# Default Mastio CA path: the sibling Mastio bundle exports its Org CA to
# ./certs/org-ca.pem when ./deploy.sh runs (PR #520). The release tarball
# extracts as ``cullis-mastio-bundle/`` (release-mastio.yml) but the repo
# layout is ``packaging/mastio-bundle/``; check both so this works whether
# the operator extracted the tarball next to ours or is running out of a
# repo checkout.
default_ca_bundle() {
    local candidates=(
        "$SCRIPT_DIR/../cullis-mastio-bundle/certs/org-ca.pem"
        "$SCRIPT_DIR/../mastio-bundle/certs/org-ca.pem"
    )
    local sibling
    for sibling in "${candidates[@]}"; do
        if [[ -f "$sibling" ]]; then
            # Use absolute path so docker compose substitution works
            # regardless of where the operator invokes ./deploy.sh from.
            local abs_dir
            abs_dir="$(cd "$(dirname "$sibling")" && pwd)"
            echo "${abs_dir}/$(basename "$sibling")"
            return
        fi
    done
    echo ""
}

# Sibling Mastio bundle exports the auto-derived org_id to
# ./certs/org-id alongside the CA. Without picking it up, the
# Frontdesk default ``acme`` is wrong against a standalone Mastio's
# 16-char hex id, the SPIFFE attribution silently mismatches, and the
# operator only finds out when audit rows show the wrong principal.
default_org_id() {
    local candidates=(
        "$SCRIPT_DIR/../cullis-mastio-bundle/certs/org-id"
        "$SCRIPT_DIR/../mastio-bundle/certs/org-id"
    )
    local sibling
    for sibling in "${candidates[@]}"; do
        if [[ -f "$sibling" ]]; then
            tr -d '[:space:]' < "$sibling"
            return
        fi
    done
    echo ""
}

case "$MODE" in
    prod)
        [[ -n "${CULLIS_FRONTDESK_ORG_ID:-}" ]]         || die "--prod requires CULLIS_FRONTDESK_ORG_ID env var"
        [[ -n "${CULLIS_FRONTDESK_TRUST_DOMAIN:-}" ]]   || die "--prod requires CULLIS_FRONTDESK_TRUST_DOMAIN env var"
        [[ -n "${CULLIS_FRONTDESK_CA_BUNDLE_HOST:-}" ]] || die "--prod requires CULLIS_FRONTDESK_CA_BUNDLE_HOST env var (path to Mastio CA chain PEM)"
        [[ -f "${CULLIS_FRONTDESK_CA_BUNDLE_HOST}" ]]   || die "CA bundle not found at: ${CULLIS_FRONTDESK_CA_BUNDLE_HOST}"
        ORG_ID="${CULLIS_FRONTDESK_ORG_ID}"
        TRUST_DOMAIN="${CULLIS_FRONTDESK_TRUST_DOMAIN}"
        CA_BUNDLE="${CULLIS_FRONTDESK_CA_BUNDLE_HOST}"
        ;;
    defaults)
        # ORG_ID precedence: explicit env > sibling Mastio export
        # (./certs/org-id, written by mastio-bundle deploy.sh) > legacy
        # ``acme`` placeholder. The sibling lookup matches the same
        # tarball-vs-repo dance default_ca_bundle does, so the two
        # auto-detects move together: if the operator ran the Mastio
        # bundle, both org_id and the CA come from there.
        ORG_ID="${CULLIS_FRONTDESK_ORG_ID:-$(default_org_id)}"
        ORG_ID="${ORG_ID:-acme}"
        TRUST_DOMAIN="${CULLIS_FRONTDESK_TRUST_DOMAIN:-${ORG_ID}.test}"
        CA_BUNDLE="${CULLIS_FRONTDESK_CA_BUNDLE_HOST:-$(default_ca_bundle)}"
        if [[ -z "$CA_BUNDLE" ]]; then
            warn "No Mastio CA bundle found next to this bundle."
            warn "Looked at ../cullis-mastio-bundle/certs/org-ca.pem and"
            warn "../mastio-bundle/certs/org-ca.pem (depending on whether"
            warn "you extracted the release tarball or run from a repo)."
            warn "Set CULLIS_FRONTDESK_CA_BUNDLE_HOST in frontdesk.env to a"
            warn "valid path before running ./deploy.sh, otherwise compose"
            warn "will fail at ``up`` time with a clear error."
            CA_BUNDLE="./MUST_SET_TO_MASTIO_CA_BUNDLE_PATH"
        fi
        ;;
    interactive)
        echo ""
        _default_ca="$(default_ca_bundle)"
        ca_prompt_default="${_default_ca:-./mastio-org-ca.pem}"
        # Sibling Mastio bundle (if present) wins the org_id default
        # over the legacy ``acme``. Operator can still override at the
        # prompt, but the offered default is the right one.
        _default_org_id="$(default_org_id)"
        org_prompt_default="${_default_org_id:-acme}"

        read -rp "  Org ID [${org_prompt_default}]: " ORG_ID
        ORG_ID="${ORG_ID:-${org_prompt_default}}"

        read -rp "  SPIFFE trust domain [${ORG_ID}.test]: " TRUST_DOMAIN
        TRUST_DOMAIN="${TRUST_DOMAIN:-${ORG_ID}.test}"

        read -rp "  Mastio CA bundle path [${ca_prompt_default}]: " CA_BUNDLE
        CA_BUNDLE="${CA_BUNDLE:-${ca_prompt_default}}"
        if [[ ! -f "$CA_BUNDLE" ]]; then
            warn "CA bundle path '$CA_BUNDLE' does not exist on disk."
            warn "Run the sibling Mastio bundle's deploy.sh first to"
            warn "generate it, or"
            warn "edit frontdesk.env later before ./deploy.sh."
        fi
        ;;
esac

# Mint a Connector admin secret. The Connector validates ``X-Admin-Secret``
# against ``CULLIS_CONNECTOR_ADMIN_SECRET`` (cullis_connector/admin/auth.py)
# on POST /admin/users — without this, every provisioning call returns
# 403 ``admin secret not configured on this Connector`` and the operator
# is dead-locked at user provisioning. Pre-v0.2.0-rc4 the bundle silently
# left this empty and the deploy.sh summary pointed at the Mastio's
# MCP_PROXY_ADMIN_SECRET, which is a different secret on a different
# component (the Mastio dashboard) and cannot authenticate the Connector
# admin API. See bug 1 in the v0.2.0 dogfood notes.
ADMIN_SECRET="${CULLIS_CONNECTOR_ADMIN_SECRET:-$(openssl rand -hex 24)}"

cp "$SCRIPT_DIR/frontdesk.env.example" "$OUT"
sed -i "s|^CULLIS_FRONTDESK_ORG_ID=.*|CULLIS_FRONTDESK_ORG_ID=${ORG_ID}|"               "$OUT"
sed -i "s|^CULLIS_FRONTDESK_TRUST_DOMAIN=.*|CULLIS_FRONTDESK_TRUST_DOMAIN=${TRUST_DOMAIN}|" "$OUT"
sed -i "s|^CULLIS_FRONTDESK_CA_BUNDLE_HOST=.*|CULLIS_FRONTDESK_CA_BUNDLE_HOST=${CA_BUNDLE}|" "$OUT"
# The example file does not ship the secret line (we mint per-deploy); append.
echo "CULLIS_CONNECTOR_ADMIN_SECRET=${ADMIN_SECRET}" >> "$OUT"

ok "Wrote ${OUT}"
echo ""
echo -e "  ${BOLD}CULLIS_FRONTDESK_ORG_ID${RESET}          ${GRAY}${ORG_ID}${RESET}"
echo -e "  ${BOLD}CULLIS_FRONTDESK_TRUST_DOMAIN${RESET}    ${GRAY}${TRUST_DOMAIN}${RESET}"
echo -e "  ${BOLD}CULLIS_FRONTDESK_CA_BUNDLE_HOST${RESET}  ${GRAY}${CA_BUNDLE}${RESET}"
echo -e "  ${BOLD}CULLIS_CONNECTOR_ADMIN_SECRET${RESET}    ${GRAY}${ADMIN_SECRET:0:8}…${RESET} (provision users via X-Admin-Secret)"
echo ""
