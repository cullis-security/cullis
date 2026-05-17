#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Frontdesk — smoke test for --rotate-admin-secret
# ═══════════════════════════════════════════════════════════════════════════════
#
# Verifies the wiring of the rotation flow without bringing up Docker:
#   1. ``_lib-admin-secret.sh`` is sourceable and ``gen_admin_secret``
#      emits a 48-char lowercase hex string (matching openssl rand -hex 24).
#   2. ``generate-frontdesk-env.sh`` references the shared helper (the
#      old inline definition is gone).
#   3. ``deploy.sh`` exposes the ``--rotate-admin-secret`` flag in both
#      the argument parser and ``--help`` output.
#   4. The anchored sed substitution rewrites only the
#      ``CULLIS_CONNECTOR_ADMIN_SECRET=`` line and leaves comments /
#      sibling vars containing the substring intact.
#
# Run:
#   ./test-rotate-admin-secret.sh

set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
fail() { echo -e "${RED}FAIL${RESET}: $1" >&2; exit 1; }
pass() { echo -e "${GREEN}PASS${RESET}: $1"; }

# ── 1. Helper sources cleanly and produces a 48-hex secret ──────────────────
[[ -f "$BUNDLE_DIR/_lib-admin-secret.sh" ]] \
    || fail "_lib-admin-secret.sh not found at $BUNDLE_DIR/_lib-admin-secret.sh"

# shellcheck source=_lib-admin-secret.sh
source "$BUNDLE_DIR/_lib-admin-secret.sh"

declare -F gen_admin_secret >/dev/null \
    || fail "gen_admin_secret function not defined after sourcing the helper"

NEW="$(gen_admin_secret)"
[[ -n "$NEW" ]] || fail "gen_admin_secret returned empty string"
[[ ${#NEW} -eq 48 ]] \
    || fail "gen_admin_secret length is ${#NEW}, expected 48 (openssl rand -hex 24 shape)"
[[ "$NEW" =~ ^[0-9a-f]{48}$ ]] \
    || fail "gen_admin_secret output is not lowercase hex: $NEW"

# Two consecutive calls must not collide (sanity check on randomness).
NEW2="$(gen_admin_secret)"
[[ "$NEW" != "$NEW2" ]] || fail "gen_admin_secret returned the same value twice"
pass "_lib-admin-secret.sh emits 48-char lowercase hex secrets"

# ── 2. generate-frontdesk-env.sh sources the shared helper ──────────────────
GEN_SH="$BUNDLE_DIR/generate-frontdesk-env.sh"
[[ -f "$GEN_SH" ]] || fail "generate-frontdesk-env.sh not found"
grep -q 'source.*_lib-admin-secret.sh' "$GEN_SH" \
    || fail "generate-frontdesk-env.sh does not source _lib-admin-secret.sh"
# The inline definition (``openssl rand -hex 24`` body) must be gone so
# the helper is the single source of truth.
if grep -q 'gen_admin_secret()' "$GEN_SH"; then
    fail "generate-frontdesk-env.sh still defines gen_admin_secret() inline — remove the duplicate"
fi
pass "generate-frontdesk-env.sh sources the shared helper, no inline duplicate"

# ── 3. deploy.sh wires the --rotate-admin-secret flag + help text ───────────
DEPLOY_SH="$BUNDLE_DIR/deploy.sh"
[[ -f "$DEPLOY_SH" ]] || fail "deploy.sh not found"
grep -q -- '--rotate-admin-secret) ACTION="rotate-admin-secret"' "$DEPLOY_SH" \
    || fail "deploy.sh does not wire --rotate-admin-secret in the arg parser"
grep -q -- '--rotate-admin-secret' "$DEPLOY_SH" \
    || fail "deploy.sh does not mention --rotate-admin-secret at all"
grep -qE '\$ACTION" == "rotate-admin-secret"' "$DEPLOY_SH" \
    || fail "deploy.sh has no handler block for rotate-admin-secret"
# Help text must surface the flag for operators.
"$DEPLOY_SH" --help 2>&1 | grep -q -- '--rotate-admin-secret' \
    || fail "deploy.sh --help does not document --rotate-admin-secret"
pass "deploy.sh exposes --rotate-admin-secret in parser, handler, and --help"

# ── 4. Anchored sed substitution scope is correct ───────────────────────────
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/frontdesk.env" <<EOF
# This comment mentions CULLIS_CONNECTOR_ADMIN_SECRET on purpose
CULLIS_FRONTDESK_ORG_ID=acme
CULLIS_CONNECTOR_ADMIN_SECRET=old-secret-placeholder
OTHER_VAR_REFERENCING_CULLIS_CONNECTOR_ADMIN_SECRET=untouched
EOF

FAKE_NEW="abcdef0123456789abcdef0123456789abcdef0123456789"
sed -i "s|^CULLIS_CONNECTOR_ADMIN_SECRET=.*|CULLIS_CONNECTOR_ADMIN_SECRET=${FAKE_NEW}|" \
    "$WORK/frontdesk.env"

grep -qE "^CULLIS_CONNECTOR_ADMIN_SECRET=${FAKE_NEW}\$" "$WORK/frontdesk.env" \
    || fail "anchored sed did not rewrite the target line"
grep -q "old-secret-placeholder" "$WORK/frontdesk.env" \
    && fail "old secret value still present in frontdesk.env after rotation"
grep -q "^# This comment mentions CULLIS_CONNECTOR_ADMIN_SECRET on purpose\$" \
    "$WORK/frontdesk.env" \
    || fail "comment line was modified (anchored regex regression)"
grep -q "^OTHER_VAR_REFERENCING_CULLIS_CONNECTOR_ADMIN_SECRET=untouched\$" \
    "$WORK/frontdesk.env" \
    || fail "sibling var line was modified (anchored regex regression)"
pass "anchored sed rewrites only the target line"

echo ""
echo -e "${GREEN}All checks passed.${RESET}"
