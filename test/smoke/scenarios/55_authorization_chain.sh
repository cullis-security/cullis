#!/usr/bin/env bash
# Real agent identities and operator policies; only business actions are fixtures.
set -euo pipefail
SCENARIO_TAG="55_authorization_chain"
SMOKE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "$SMOKE_LIB_DIR/_common.sh"
smoke_compose exec -T mcp-proxy python3 - < "$SMOKE_ROOT/probes/authorization_chain.py" \
    || die "real-identity authorization chain failed"
log_pass "authorization, delegation, DPoP impersonation and binding revocation verified"
