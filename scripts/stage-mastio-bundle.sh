#!/usr/bin/env bash
# Stage cullis-mastio-bundle.tar.gz for release with strict allowlist.
#
# Why this exists: the manual `tar czf ... mastio-bundle/` we used for
# v0.5.2 (2026-05-22) skipped the sibling _common-deploy-helpers.sh
# (it lives in packaging/, one level above mastio-bundle/), shipping a
# tarball that crashes at deploy.sh line 106 on cold install. v0.5.1
# happened to include it because the dir was named with the version
# and staged differently. This script removes the foot-gun by codifying
# the allowlist and running a post-stage cold-reader sanity check.
#
# Usage:
#   ./scripts/stage-mastio-bundle.sh <version> [out-dir]
#
# Example:
#   ./scripts/stage-mastio-bundle.sh 0.5.2 ./dist/
#
# Produces:
#   <out-dir>/cullis-mastio-bundle.tar.gz             (unversioned, for README quickstart curl)
#   <out-dir>/cullis-mastio-bundle-<version>.tar.gz   (versioned, for archive)
#
# Both tarballs have identical content; only the asset name differs so
# the GitHub release can publish both URLs without sha mismatch.
#
# Exit code: 0 on success, non-zero if any allowlist file is missing
# or the post-stage cold-reader check fails.

set -euo pipefail

VERSION="${1:?usage: $0 <version> [out-dir]}"
OUT_DIR="${2:-./dist}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_BUNDLE="$REPO_ROOT/packaging/mastio-bundle"
SRC_HELPER="$REPO_ROOT/packaging/_common-deploy-helpers.sh"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_NEU=$'\033[36m'
C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'

err()  { echo "${C_ERR}${C_BOLD}error:${C_RST} $*" >&2; }
ok()   { echo "${C_OK}$*${C_RST}" >&2; }
info() { echo "${C_NEU}$*${C_RST}" >&2; }

banner() {
  echo "" >&2
  echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}  $*${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
}

# Allowlist: files copied INTO the tarball's cullis-mastio-bundle/ dir.
# Order: matches v0.5.1 layout + post-v0.5.1 additions (postgres compose).
# Runtime artifacts (data/, nginx-certs/, certs/ with operator org id,
# proxy.env without .example) are intentionally excluded.
BUNDLE_ALLOWLIST=(
  "deploy.sh"
  "generate-proxy-env.sh"
  "docker-compose.yml"
  "docker-compose.prod.yml"
  "docker-compose.shared-broker.yml"
  "docker-compose.postgres.yml"
  "proxy.env.example"
  "README.md"
  "FIRST_AGENT.md"
  "first-agent.py"
  "LOCAL_DEMO.md"
  "local-demo.py"
  "local-demo-bootstrap.py"
  "docker-compose.local-demo.yml"
  "local-demo-nginx"
  "nginx"
)

banner "Stage cullis-mastio-bundle $VERSION"

# Preflight: source-of-truth files all present.
for f in "${BUNDLE_ALLOWLIST[@]}"; do
  if [[ ! -e "$SRC_BUNDLE/$f" ]]; then
    err "missing source: packaging/mastio-bundle/$f"
    exit 1
  fi
done
if [[ ! -e "$SRC_HELPER" ]]; then
  err "missing source: packaging/_common-deploy-helpers.sh"
  exit 1
fi
ok "  preflight: all ${#BUNDLE_ALLOWLIST[@]} bundle files + sibling helper present"

# Stage in a temp dir so the tar metadata is clean (no .gitignored
# runtime crud, no operator-specific certs/).
STAGE_DIR="$(mktemp -d /tmp/cullis-mastio-stage-XXXXXX)"
trap 'rm -rf "$STAGE_DIR"' EXIT
TAR_ROOT="$STAGE_DIR/cullis-mastio-bundle"
mkdir -p "$TAR_ROOT"

for f in "${BUNDLE_ALLOWLIST[@]}"; do
  cp -r "$SRC_BUNDLE/$f" "$TAR_ROOT/$f"
done
cp "$SRC_HELPER" "$TAR_ROOT/_common-deploy-helpers.sh"

# Stamp the bundle with its version. ``generate-proxy-env.sh`` reads
# this on first run and writes ``CULLIS_MASTIO_VERSION=<v>`` into
# proxy.env, so the container ENV (``MCP_PROXY_VERSION``) carries a
# real version instead of falling back to the compose ``unknown``
# placeholder. Without this stamp, the dashboard update banner of a
# freshly installed v0.5.5 bundle reads "Update available: 0.5.5"
# because version_check.py compares ``unknown`` against the GitHub
# releases API latest. Cold-reader-confidence-killer; see also
# ``packaging/mastio-bundle/generate-proxy-env.sh`` which reads it.
echo "$VERSION" > "$TAR_ROOT/VERSION"

ok "  staged $(find "$TAR_ROOT" -mindepth 1 -maxdepth 1 | wc -l) entries in $TAR_ROOT (incl. VERSION=$VERSION)"

# Tar.
mkdir -p "$OUT_DIR"
OUT_DIR_ABS="$(cd "$OUT_DIR" && pwd)"

TAR_UNVER="$OUT_DIR_ABS/cullis-mastio-bundle.tar.gz"
TAR_VER="$OUT_DIR_ABS/cullis-mastio-bundle-$VERSION.tar.gz"

(cd "$STAGE_DIR" && tar czf "$TAR_UNVER" cullis-mastio-bundle/)
cp "$TAR_UNVER" "$TAR_VER"
ok "  $TAR_UNVER ($(stat -c%s "$TAR_UNVER") bytes)"
ok "  $TAR_VER  (identical sha)"

# Sanity check post-stage: extract elsewhere, replay cold reader.
banner "Cold-reader sanity check"

CHECK_DIR="$(mktemp -d /tmp/cullis-mastio-check-XXXXXX)"
trap 'rm -rf "$STAGE_DIR" "$CHECK_DIR"' EXIT

(cd "$CHECK_DIR" && tar xzf "$TAR_UNVER")
cd "$CHECK_DIR/cullis-mastio-bundle"

# 1. deploy.sh syntactically valid.
if ! bash -n deploy.sh; then
  err "deploy.sh has bash syntax errors"
  exit 1
fi
ok "  bash -n deploy.sh"

# 2. helper sibling present (the v0.5.2 regression).
if [[ ! -f _common-deploy-helpers.sh ]]; then
  err "_common-deploy-helpers.sh missing from tarball (the v0.5.2 bug)"
  exit 1
fi
ok "  _common-deploy-helpers.sh present"

# 3. helper source line resolves: dry-run the if/else in deploy.sh.
if ! grep -q '_common-deploy-helpers.sh' deploy.sh; then
  err "deploy.sh no longer references _common-deploy-helpers.sh"
  exit 1
fi
ok "  deploy.sh sources the helper"

# 4. no runtime crud leaked.
for forbidden in data nginx-certs certs proxy.env local-demo-state; do
  if [[ -e "$forbidden" ]]; then
    err "forbidden runtime artifact in tarball: $forbidden"
    exit 1
  fi
done
ok "  no runtime artifacts (data/, nginx-certs/, certs/, proxy.env)"

# 5. helper is sourceable in isolation (catches future helper bugs early).
if ! ( source _common-deploy-helpers.sh 2>/dev/null ); then
  err "_common-deploy-helpers.sh cannot be sourced standalone"
  exit 1
fi
ok "  _common-deploy-helpers.sh sources cleanly"

cd "$REPO_ROOT"

SHA="$(sha256sum "$TAR_UNVER" | awk '{print $1}')"

banner "${C_OK}Stage OK"
echo "  Version:     $VERSION" >&2
echo "  Output:      $TAR_UNVER" >&2
echo "               $TAR_VER" >&2
echo "  SHA-256:     $SHA" >&2
echo "" >&2
echo "  Next:        gh release upload mastio-v$VERSION \\" >&2
echo "                 $TAR_UNVER \\" >&2
echo "                 $TAR_VER \\" >&2
echo "                 --clobber" >&2
