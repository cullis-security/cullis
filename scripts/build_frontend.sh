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
  SHA_FILE="${ROOT_DIR}/scripts/tailwind-sha256.txt"
  echo ">>> downloading Tailwind CLI ${TAILWIND_VERSION} from ${URL}"
  TMP_BIN="$(mktemp)"
  curl -sSLf "${URL}" -o "${TMP_BIN}"
  # Wave B F1 (audit 2026-05-11) — verify against the pinned SHA-256
  # before trusting the binary. Extract the host expected sha and
  # compare with the downloaded blob; abort on mismatch.
  EXPECTED_SHA="$(awk -v a="${ASSET}" '$2 == a {print $1}' "${SHA_FILE}")"
  if [[ -z "${EXPECTED_SHA}" ]]; then
    echo "FATAL: no SHA-256 entry for ${ASSET} in ${SHA_FILE}" >&2
    rm -f "${TMP_BIN}"
    exit 1
  fi
  ACTUAL_SHA="$(sha256sum "${TMP_BIN}" | awk '{print $1}')"
  if [[ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]]; then
    echo "FATAL: Tailwind binary SHA mismatch for ${ASSET}" >&2
    echo "  expected: ${EXPECTED_SHA}" >&2
    echo "  actual:   ${ACTUAL_SHA}" >&2
    rm -f "${TMP_BIN}"
    exit 1
  fi
  mv "${TMP_BIN}" "${BIN}"
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
