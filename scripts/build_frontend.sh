#!/usr/bin/env bash
# Build the Tailwind stylesheets for the broker + proxy dashboards.
#
# Uses the Tailwind standalone CLI (no Node/npm required). Downloads the
# binary into ./node_modules/.bin/tailwindcss on first run; reuses it after.
#
# Usage:
#   scripts/build_frontend.sh          # minified, one-shot
#   scripts/build_frontend.sh --watch  # rebuild on template changes (broker only)
#
# Called automatically by the Dockerfile multi-stage build; run manually when
# iterating on the dashboard outside Docker.
set -euo pipefail

TAILWIND_VERSION="${TAILWIND_VERSION:-v3.4.10}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/node_modules/.bin"
BIN="${BIN_DIR}/tailwindcss"

detect_asset() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
  esac
  case "${os}" in
    linux) echo "tailwindcss-linux-${arch}" ;;
    darwin) echo "tailwindcss-macos-${arch}" ;;
    *) echo "unsupported OS ${os}" >&2; exit 1 ;;
  esac
}

if [[ ! -x "${BIN}" ]]; then
  mkdir -p "${BIN_DIR}"
  ASSET="$(detect_asset)"
  URL="https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/${ASSET}"
  echo ">>> downloading Tailwind CLI ${TAILWIND_VERSION} from ${URL}"
  curl -sSLf "${URL}" -o "${BIN}"
  chmod +x "${BIN}"
fi

WATCH=""
if [[ "${1:-}" == "--watch" ]]; then
  WATCH="--watch"
fi

echo ">>> building broker tailwind.css"
"${BIN}" ${WATCH} \
  -c "${ROOT_DIR}/tailwind.config.js" \
  -i "${ROOT_DIR}/app/dashboard/static_src/input.css" \
  -o "${ROOT_DIR}/app/static/css/tailwind.css" \
  --minify

if [[ -z "${WATCH}" ]]; then
  echo ">>> building proxy tailwind.css"
  "${BIN}" \
    -c "${ROOT_DIR}/tailwind.config.js" \
    -i "${ROOT_DIR}/mcp_proxy/dashboard/static_src/input.css" \
    -o "${ROOT_DIR}/mcp_proxy/dashboard/static/css/tailwind.css" \
    --minify
  echo ">>> done"
fi
