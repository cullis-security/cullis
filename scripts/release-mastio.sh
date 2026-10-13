#!/usr/bin/env bash
# Release a new Mastio version end-to-end.
#
# Why this exists: the manual release dance (tag git, build image, push
# :X.Y.Z, push :latest, stage tarball, extract CHANGELOG notes, gh
# release create + upload) was a 7-step muscle-memory recipe with two
# papered-over gotchas — the asymmetric tag convention (git tag
# ``mastio-vX.Y.Z`` vs GHCR tag bare ``X.Y.Z``) and the cold-reader
# stage that needs a VERSION file inside the tarball so the running
# container can self-report. Codifying it removes both papers, plus
# the post-tag VM cold-reader regression test.
#
# Usage:
#   ./scripts/release-mastio.sh <version>
#
# Example:
#   ./scripts/release-mastio.sh 0.5.5
#
# Preconditions:
#   - Working tree clean, on ``main``, in sync with origin/main.
#   - CHANGELOG.md has a ``## [v<version>]`` section ready (the
#     ``release-*.yml`` extraction format).
#   - README + site quickstart curls already point at mastio-v<version>
#     (the release-bump PR landed on main).
#   - ``gh`` authenticated, ``docker`` logged in to ghcr.io.
#
# Exit code: 0 on success, non-zero on any preflight or sub-step fail.

set -euo pipefail

VERSION="${1:?usage: $0 <version>}"
SKIP_DOGFOOD="${SKIP_DOGFOOD:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_NEU=$'\033[36m'; C_WARN=$'\033[33m'
C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'

err()  { echo "${C_ERR}${C_BOLD}error:${C_RST} $*" >&2; }
ok()   { echo "${C_OK}$*${C_RST}" >&2; }
info() { echo "${C_NEU}$*${C_RST}" >&2; }
warn() { echo "${C_WARN}$*${C_RST}" >&2; }

banner() {
  echo "" >&2
  echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}  $*${C_RST}" >&2
  echo "${C_NEU}${C_BOLD}═════════════════════════════════════════════════════════════════════${C_RST}" >&2
}

# Strict version validation. Mirror of stage-mastio-bundle.sh.
if [[ ! "$VERSION" =~ ^[A-Za-z0-9.-]+$ ]]; then
  err "refusing version with unsafe characters: ${VERSION}"
  exit 1
fi

GIT_TAG="mastio-v${VERSION}"
IMAGE_REPO="ghcr.io/cullis-security/cullis-mastio"

banner "Preflight"

# 1. Working tree clean.
if [[ -n "$(git status --porcelain)" ]]; then
  err "working tree has uncommitted changes"
  git status --short >&2
  exit 1
fi
ok "  working tree clean"

# 2. On main, synced with origin/main.
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" ]]; then
  err "not on main (currently on ${BRANCH})"
  exit 1
fi
ok "  on main"

git fetch origin --quiet
LOCAL_HEAD="$(git rev-parse HEAD)"
REMOTE_HEAD="$(git rev-parse origin/main)"
if [[ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]]; then
  err "local main (${LOCAL_HEAD:0:7}) is not in sync with origin/main (${REMOTE_HEAD:0:7})"
  err "run 'git pull origin main' (or push pending work) and re-run"
  exit 1
fi
ok "  in sync with origin/main"

# 3. Tag does not already exist.
if git rev-parse "refs/tags/${GIT_TAG}" >/dev/null 2>&1; then
  err "git tag ${GIT_TAG} already exists locally"
  err "delete with: git tag -d ${GIT_TAG} && git push origin :refs/tags/${GIT_TAG}"
  exit 1
fi
if git ls-remote --tags origin "refs/tags/${GIT_TAG}" | grep -q "${GIT_TAG}"; then
  err "git tag ${GIT_TAG} already exists on origin"
  exit 1
fi
ok "  tag ${GIT_TAG} is unused"

# 4. CHANGELOG has a section for the version.
if ! grep -q "^## \[v${VERSION}\]" CHANGELOG.md; then
  err "CHANGELOG.md has no '## [v${VERSION}]' section"
  err "add the release notes there (matching the release-*.yml extractor format)"
  exit 1
fi
ok "  CHANGELOG.md has [v${VERSION}] section"

# 5. README + site point at the new tag.
PINS_OK=1
if ! grep -q "mastio-v${VERSION}" README.md; then
  warn "README.md does not mention mastio-v${VERSION} — quickstart curl + status table may be stale"
  PINS_OK=0
fi
for f in site/src/pages/index.astro site/src/pages/index-dark.astro; do
  if [[ -f "$f" ]] && ! grep -q "mastio-v${VERSION}" "$f"; then
    warn "${f} does not mention mastio-v${VERSION} — quickstart curl may be stale"
    PINS_OK=0
  fi
done
if [[ $PINS_OK -eq 0 ]]; then
  err "bump README/site references to mastio-v${VERSION} before releasing"
  err "(the release-bump PR usually does this — was it merged?)"
  exit 1
fi
ok "  README + site reference mastio-v${VERSION}"

# 6. gh + docker tooling reachable.
if ! command -v gh >/dev/null 2>&1; then
  err "gh CLI not found in PATH"; exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  err "docker CLI not found in PATH"; exit 1
fi
ok "  gh + docker available"

banner "Stage bundle tarball"
./scripts/stage-mastio-bundle.sh "$VERSION" ./dist/

banner "Tag git"
# Try a signed tag first (matches recent convention); fall back to
# unsigned if gpg is not available so the release does not get stuck on
# a missing keyring. The fallback emits a warning so the operator can
# rotate to a signed retag later if they want.
if git tag -s -a "$GIT_TAG" -m "Mastio v${VERSION}" 2>/dev/null; then
  ok "  signed tag ${GIT_TAG}"
else
  warn "  gpg signing unavailable — falling back to unsigned annotated tag"
  git tag -a "$GIT_TAG" -m "Mastio v${VERSION}"
  ok "  unsigned tag ${GIT_TAG}"
fi

git push origin "$GIT_TAG"
ok "  pushed ${GIT_TAG} to origin"

banner "Build + push Docker image"
# IMAGE convention: GHCR tag is the bare version (no ``v`` prefix).
# Git tag is ``mastio-v${VERSION}``. See feedback/memory note
# ``mastio-release-tag-convention``.
docker build --build-arg VERSION="$VERSION" -t "${IMAGE_REPO}:${VERSION}" -f mcp_proxy/Dockerfile .
ok "  built ${IMAGE_REPO}:${VERSION}"

docker tag "${IMAGE_REPO}:${VERSION}" "${IMAGE_REPO}:latest"
ok "  tagged ${IMAGE_REPO}:latest"

docker push "${IMAGE_REPO}:${VERSION}"
docker push "${IMAGE_REPO}:latest"
ok "  pushed both image tags to GHCR"

banner "Create GitHub release"
NOTES_FILE="$(mktemp /tmp/cullis-release-notes-XXXXXX.md)"
trap 'rm -f "$NOTES_FILE"' EXIT
# POSIX character class ``[[]`` / ``[]]`` portably matches literal
# ``[`` / ``]`` across awk implementations. The previous ``\[`` /
# ``\]`` form raised "escape sequence treated as plain" warnings in
# GNU awk's strict mode and the pattern then failed to match, leaving
# the extracted notes file empty and blocking gh release create.
awk -v v="^## [[]v${VERSION}[]]" '
  $0 ~ v { p = 1 }
  /^## / && p && $0 !~ v { exit }
  p { print }
' CHANGELOG.md > "$NOTES_FILE"

if [[ ! -s "$NOTES_FILE" ]]; then
  err "extracted release notes from CHANGELOG are empty — preflight check missed something"
  exit 1
fi

gh release create "$GIT_TAG" \
  --title "Mastio v${VERSION}" \
  --notes-file "$NOTES_FILE" \
  "./dist/cullis-mastio-bundle.tar.gz" \
  "./dist/cullis-mastio-bundle-${VERSION}.tar.gz"
ok "  release published"

banner "${C_OK}Mastio v${VERSION} released${C_RST}"
echo "  Tag:          https://github.com/cullis-security/cullis/releases/tag/${GIT_TAG}" >&2
echo "  Image:        ${IMAGE_REPO}:${VERSION}" >&2
echo "                ${IMAGE_REPO}:latest" >&2
echo "  Tarball:      ./dist/cullis-mastio-bundle.tar.gz" >&2
echo "                ./dist/cullis-mastio-bundle-${VERSION}.tar.gz" >&2
echo "" >&2

if [[ "$SKIP_DOGFOOD" == "1" ]]; then
  warn "  Skipped post-release cold-reader dogfood (SKIP_DOGFOOD=1)"
  exit 0
fi

cat >&2 <<HINT
  ${C_BOLD}Next:${C_RST} cold-reader dogfood
  Either:
    - On a fresh VM: curl the tarball, run deploy.sh, register admin,
      enroll an agent, run a chat reply end-to-end.
    - On your existing dogfood VM, remove the cached :latest image
      first so docker compose pull picks up the new digest:
        docker image rm ${IMAGE_REPO}:latest
        curl -L https://github.com/cullis-security/cullis/releases/download/${GIT_TAG}/cullis-mastio-bundle.tar.gz | tar xz
        cd cullis-mastio-bundle && ./deploy.sh
HINT
