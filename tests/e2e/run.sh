#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════════════
# Cullis E2E test runner — one-shot wrapper.
#
# Boots the full Cullis stack via docker compose, runs the e2e test suite,
# and tears everything down. Designed for both local dev and CI.
#
# Usage:
#   tests/e2e/run.sh                  # default: full suite
#   tests/e2e/run.sh -k test_full     # filter by name
#   KEEP_E2E_STACK=1 tests/e2e/run.sh # leave the stack up for inspection
#
# Exit codes:
#   0  all tests passed
#   1  test failure (stack already torn down)
#   2  prerequisite missing (docker, pytest, ...)
# ═════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ── Prerequisites ────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "FAIL: docker not installed"; exit 2; }
docker info >/dev/null 2>&1 || { echo "FAIL: docker daemon not reachable"; exit 2; }

if ! docker compose version >/dev/null 2>&1; then
    if ! command -v docker-compose >/dev/null 2>&1; then
        echo "FAIL: neither 'docker compose' (plugin) nor 'docker-compose' is installed"
        exit 2
    fi
fi

PYTHON="${PYTHON:-python}"
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
fi

$PYTHON -c "import pytest" 2>/dev/null || { echo "FAIL: pytest not installed in $PYTHON"; exit 2; }

# ── Run ─────────────────────────────────────────────────────────────────────
echo "── Cullis E2E test suite ──"
echo "  Repo:    $REPO_ROOT"
echo "  Python:  $PYTHON"
echo "  Compose: tests/e2e/docker-compose.e2e.yml"
echo "  Project: cullis-e2e"
if [[ "${KEEP_E2E_STACK:-0}" == "1" ]]; then
    echo "  KEEP_E2E_STACK=1 → stack will be left running after the suite"
fi
echo ""

# Override pytest's default `-m "not e2e"` so the e2e tests actually run.
# Pass `-s` so the conftest prints (`[e2e] Booting stack...`,
# `[e2e] Stack is healthy`) are visible live during the slow boot phase —
# without this the user stares at "tests/e2e/test_full_flow.py " for 3-5
# minutes wondering if it is stuck.
# Pass through any extra arguments (e.g. -k test_name, -x, -v).
$PYTHON -m pytest -m e2e -o addopts="" -s -v tests/e2e/ "$@"
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    echo ""
    echo "── All e2e tests passed ──"
fi
exit $exit_code
