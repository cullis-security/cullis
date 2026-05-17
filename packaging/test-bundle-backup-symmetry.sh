#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Mastio bundles — backup symmetry smoke test
# ═══════════════════════════════════════════════════════════════════════════════
#
# Verifies that mastio-bundle (open-core) and mastio-enterprise-bundle
# share the same backup helpers and both expose ``--upgrade-bundle``.
# MAJOR-5 of imp/p3-operability-audit.md — without this gate the two
# bundles silently drift on backup semantics every time someone touches
# only one of the two deploy.sh files.
#
# No Docker required. Live upgrade verification is deferred to the
# dogfood VM (out of scope for the pre-merge smoke).
#
# Run:
#   ./packaging/test-bundle-backup-symmetry.sh

set -euo pipefail

PACKAGING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
fail() { echo -e "${RED}FAIL${RESET}: $1" >&2; exit 1; }
pass() { echo -e "${GREEN}PASS${RESET}: $1"; }

HELPER="$PACKAGING_DIR/_common-deploy-helpers.sh"
OC_DEPLOY="$PACKAGING_DIR/mastio-bundle/deploy.sh"
ENT_DEPLOY="$PACKAGING_DIR/mastio-enterprise-bundle/deploy.sh"

# ── 1. Shared helper is present and exports the expected functions ──────────
[[ -f "$HELPER" ]] || fail "$HELPER missing"

# Source under a minimal harness — the helper needs SCRIPT_DIR + an
# ``ok`` log helper from the caller (contract documented in the file
# header). We pass a throwaway SCRIPT_DIR and a no-op ``ok``.
HELPER_FNS="$(
    SCRIPT_DIR="/tmp" bash -c '
        SCRIPT_DIR="/tmp"
        ok() { :; }
        # shellcheck source=_common-deploy-helpers.sh
        source "'"$HELPER"'"
        # ``declare -F <fn1> <fn2> ...`` prints one name per line on
        # match, exits non-zero if any function is missing.
        declare -F _backup_user_state _copy_bind_dir_for_backup \
                   _load_env _data_dir_host _nginx_certs_dir_host
    '
)" || fail "sourcing $HELPER raised an error or a function is missing"

for fn in _backup_user_state _copy_bind_dir_for_backup _load_env \
          _data_dir_host _nginx_certs_dir_host; do
    grep -qx "$fn" <<<"$HELPER_FNS" \
        || fail "shared helper does not export $fn"
done
pass "_common-deploy-helpers.sh exports the 5 backup functions"

# ── 2. Both deploy.sh files SOURCE the shared helper ────────────────────────
for path in "$OC_DEPLOY" "$ENT_DEPLOY"; do
    grep -q '_common-deploy-helpers.sh' "$path" \
        || fail "$(basename "$(dirname "$path")")/deploy.sh does not source the shared helper"
done
pass "both deploy.sh files source the shared helper (no drift)"

# ── 3. The open-core deploy.sh no longer defines the helpers inline ─────────
# Pre-extraction the open-core deploy.sh had inline copies. After the
# refactor those must be GONE — otherwise the inline copy can drift
# from the shared helper while the source line below makes the file
# *look* correct.
for fn in _copy_bind_dir_for_backup _backup_user_state _data_dir_host \
          _nginx_certs_dir_host _load_env; do
    if grep -qE "^${fn}\(\)" "$OC_DEPLOY"; then
        fail "$(basename "$(dirname "$OC_DEPLOY")")/deploy.sh still defines ${fn} inline — remove the duplicate"
    fi
done
pass "open-core deploy.sh has no inline copies of the extracted helpers"

# ── 4. --upgrade-bundle is wired on BOTH bundles ────────────────────────────
for path in "$OC_DEPLOY" "$ENT_DEPLOY"; do
    grep -q -- '--upgrade-bundle' "$path" \
        || fail "$(basename "$(dirname "$path")")/deploy.sh does not mention --upgrade-bundle"
    grep -qE 'UPGRADE_BUNDLE_TO=' "$path" \
        || fail "$(basename "$(dirname "$path")")/deploy.sh has no UPGRADE_BUNDLE_TO assignment"
done
pass "--upgrade-bundle wired on both bundles"

# ── 5. --help on both bundles documents --upgrade-bundle ────────────────────
for path in "$OC_DEPLOY" "$ENT_DEPLOY"; do
    "$path" --help 2>&1 | grep -q -- '--upgrade-bundle' \
        || fail "$(basename "$(dirname "$path")")/deploy.sh --help does not document --upgrade-bundle"
done
pass "both --help outputs document --upgrade-bundle"

# ── 6. Bash -n syntax check on all three files ──────────────────────────────
for path in "$HELPER" "$OC_DEPLOY" "$ENT_DEPLOY"; do
    bash -n "$path" || fail "bash -n failed on $path"
done
pass "bash -n clean on helper + both deploy.sh files"

# ── 7. Both bundles export the right COMPOSE_PROJECT_NAME ───────────────────
# memoria feedback_bundle_upgrade_must_use_deploy_sh: invoking compose
# from the wrong project name spawns an orphan parallel stack with empty
# volumes. The export must live in deploy.sh, not in a one-shot env.
grep -q 'COMPOSE_PROJECT_NAME="cullis-mastio"' "$OC_DEPLOY" \
    || fail "open-core deploy.sh does not export COMPOSE_PROJECT_NAME=cullis-mastio"
grep -q 'COMPOSE_PROJECT_NAME="cullis-mastio-enterprise"' "$ENT_DEPLOY" \
    || fail "enterprise deploy.sh does not export COMPOSE_PROJECT_NAME=cullis-mastio-enterprise"
pass "both bundles export their project-scoped COMPOSE_PROJECT_NAME"

echo ""
echo -e "${GREEN}All symmetry checks passed.${RESET}"
