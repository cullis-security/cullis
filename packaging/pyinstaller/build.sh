#!/usr/bin/env bash
# Build a standalone PyInstaller binary for `cullis-connector`.
#
# Produces a single-file executable under `dist/` that bundles the Python
# runtime and all dependencies. Target platform is whatever the host
# machine is — PyInstaller does NOT cross-compile, so Linux amd64 binaries
# must be built on Linux amd64 (CI uses `ubuntu-latest`), macOS binaries
# on macOS runners, Windows binaries on Windows runners.
#
# Usage:
#     ./packaging/pyinstaller/build.sh              # auto-detect platform
#     ./packaging/pyinstaller/build.sh --name foo   # override binary name
#
# Environment:
#     CULLIS_PYINSTALLER_OUT   override `dist/` output directory
#     CULLIS_PYINSTALLER_SPEC  use a custom .spec file instead of CLI args
#
# Notes:
#   • We deliberately avoid `--onedir` because single-file is simpler to
#     ship via GitHub Releases; startup cost is ~200ms extra from the
#     bootloader extracting to a temp dir, which is fine for an MCP
#     stdio server that runs for the duration of the client session.
#   • `--strip` reduces size ~30% but breaks on macOS code-signing;
#     we enable it only on Linux.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

BIN_NAME="cullis-connector"
OUT_DIR="${CULLIS_PYINSTALLER_OUT:-dist}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)   BIN_NAME="$2"; shift 2 ;;
    --out)    OUT_DIR="$2";  shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown flag: $1" >&2
      exit 64
      ;;
  esac
done

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
case "${UNAME_S}" in
  Linux)    PLATFORM="linux" ;;
  Darwin)   PLATFORM="macos" ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
  *)        PLATFORM="unknown-${UNAME_S,,}" ;;
esac
ARCH="${UNAME_M}"

echo "==> Building ${BIN_NAME} on ${PLATFORM}/${ARCH}"

# Install build deps into the active environment. Callers are expected
# to run this inside a venv or CI; we don't create one to avoid
# surprising contributors who already manage their own.
python -m pip install --upgrade pip pyinstaller >&2
python -m pip install --upgrade \
    "mcp[cli]>=1.0" "httpx>=0.24.0" "cryptography>=41.0.0" "PyYAML>=6.0" \
    "bcrypt>=4.0" \
    "fastapi>=0.110" "uvicorn[standard]>=0.27" "jinja2>=3.1" "python-multipart>=0.0.9" >&2
# mcp[cli] pulls in typer — required by `--collect-submodules mcp` below
# because mcp.cli raises ImportError at module-load time when typer is
# absent, which aborts PyInstaller's submodule scan.

STRIP_FLAG=""
if [[ "${PLATFORM}" == "linux" ]]; then
  STRIP_FLAG="--strip"
fi

# PyInstaller's --add-data wants different separators per OS. The modern
# release accepts both but we hedge anyway: ':' on POSIX, ';' on Windows.
DATA_SEP=":"
if [[ "${PLATFORM}" == "windows" ]]; then
  DATA_SEP=";"
fi

# `cullis_connector.__main__` is the documented module entry point;
# PyInstaller hooks the package correctly when given the module path.
# We build from the source tree rather than an installed wheel so the
# binary reflects the current repo state (important for the release
# workflow, which checks out the tagged commit).
#
# The --add-data flags ship the dashboard's templates + static assets as
# runtime data files — Jinja2 and FastAPI StaticFiles read them off disk
# next to __file__, and PyInstaller's bootloader extracts them into the
# _MEIPASS temp dir on launch.
pyinstaller \
  --name "${BIN_NAME}" \
  --onefile \
  --clean \
  --noconfirm \
  --distpath "${OUT_DIR}" \
  --workpath "build/pyinstaller" \
  --specpath "build/pyinstaller" \
  ${STRIP_FLAG} \
  --add-data "cullis_connector/templates${DATA_SEP}cullis_connector/templates" \
  --add-data "cullis_connector/static${DATA_SEP}cullis_connector/static" \
  --collect-submodules cullis_connector \
  --collect-submodules mcp \
  --collect-submodules fastapi \
  --collect-submodules starlette \
  --hidden-import "uvicorn.loops.auto" \
  --hidden-import "uvicorn.loops.asyncio" \
  --hidden-import "uvicorn.lifespan.on" \
  --hidden-import "uvicorn.protocols.http.auto" \
  --hidden-import "uvicorn.protocols.http.h11_impl" \
  --hidden-import "uvicorn.protocols.websockets.auto" \
  --hidden-import "uvicorn.logging" \
  cullis_connector/__main__.py

FINAL_NAME="${BIN_NAME}-${PLATFORM}-${ARCH}"
if [[ "${PLATFORM}" == "windows" ]]; then
  mv "${OUT_DIR}/${BIN_NAME}.exe" "${OUT_DIR}/${FINAL_NAME}.exe"
  FINAL_PATH="${OUT_DIR}/${FINAL_NAME}.exe"
else
  mv "${OUT_DIR}/${BIN_NAME}" "${OUT_DIR}/${FINAL_NAME}"
  FINAL_PATH="${OUT_DIR}/${FINAL_NAME}"
fi

echo "==> Built: ${FINAL_PATH}"
echo "==> Size:  $(du -h "${FINAL_PATH}" | cut -f1)"

# Quick smoke test — binary must at least answer --version without
# blowing up. This catches missing hidden imports early.
"${FINAL_PATH}" --version

echo "==> OK"
