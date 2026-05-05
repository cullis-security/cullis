#!/usr/bin/env bash
# scripts/build-spa.sh — build the Cullis Chat SPA and stage it for
# packaging. ADR-019 Phase 8c.
#
# After this script:
#   - frontend/cullis-chat/dist/         contains the prerendered SPA
#                                        (used by the Frontdesk container's
#                                        cullis-chat Dockerfile)
#   - cullis_connector/static/cullis-chat/  contains the same dist
#                                        (used by the Connector wheel; the
#                                        FastAPI app mounts it at /chat)
#
# Run before:
#   - publishing the Connector wheel (so pip-installed users get /chat)
#   - building the PyInstaller bundle for the desktop installer
#   - dogfooding /chat from a source checkout
#
# Idempotent: re-runs replace the staged copy.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPA_DIR="${REPO_ROOT}/frontend/cullis-chat"
DIST_DIR="${SPA_DIR}/dist"
STAGE_DIR="${REPO_ROOT}/cullis_connector/static/cullis-chat"

if [[ ! -f "${SPA_DIR}/package.json" ]]; then
    echo "ERROR: SPA package.json not found at ${SPA_DIR}" >&2
    exit 1
fi

echo "==> npm ci (deterministic install) in ${SPA_DIR}"
( cd "${SPA_DIR}" && npm ci --include=dev )

# ASTRO_BASE=/chat/: the Connector mounts the SPA at /chat (web.py),
# Astro must emit asset URLs under that prefix or the browser 404s the
# entire CSS/JS payload. Trailing slash matters because we concatenate
# ``${BASE_URL}cullis-mark.svg`` in the templates — Astro exposes
# ``import.meta.env.BASE_URL`` exactly as configured, no normalisation.
# The Frontdesk container Dockerfile leaves ASTRO_BASE unset so its
# default-/-rooted nginx serve still works.
echo "==> npm run build (ASTRO_BASE=/chat/)"
( cd "${SPA_DIR}" && ASTRO_BASE=/chat/ npm run build )

if [[ ! -f "${DIST_DIR}/index.html" ]]; then
    echo "ERROR: build did not produce index.html in ${DIST_DIR}" >&2
    exit 1
fi

echo "==> staging dist into ${STAGE_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "$(dirname "${STAGE_DIR}")"
cp -R "${DIST_DIR}" "${STAGE_DIR}"

echo "==> done. Connector now mounts /chat from ${STAGE_DIR}"
