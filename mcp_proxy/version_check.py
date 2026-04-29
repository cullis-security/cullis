"""Self-update advisory — compare the running image tag against GHCR releases.

Loaded by the dashboard so the operator-facing banner can say "a new
Mastio is out, run ``./deploy.sh --upgrade X.Y.Z``" without us
silently auto-pulling. The container CANNOT auto-replace itself
(it'd need ``/var/run/docker.sock`` mounted, which is a privilege
escalation antipattern) — so the design is "advise + give the
operator the exact one-liner".

Pieces:

  - ``get_current_version()`` — reads ``MCP_PROXY_VERSION`` env, set
    by ``packaging/mastio-bundle/docker-compose.yml`` to whatever
    ``CULLIS_MASTIO_VERSION`` was at deploy time. Falls back to
    ``"unknown"`` for dev runs that didn't pin a tag.
  - ``get_latest_version()`` — async fetch of GitHub's releases API,
    filters for ``mastio-v*`` tags, returns the highest semver. No
    auth needed (public repo); uses a 5s timeout so a flaky GitHub
    doesn't stall the dashboard.
  - ``check_for_updates()`` — orchestrates both, caches the result
    in module memory for ``_CACHE_TTL_S`` (default 1h) so a busy
    dashboard doesn't hammer the GitHub API. Returns the dict the
    banner consumes verbatim.

Cache is module-level intentionally — ``settings`` is a singleton,
the dashboard runs in one process per Mastio, and a stale entry
older than the TTL is recomputed on the next request. Killing the
container drops the cache, which is the right behaviour for an
advisory that's only as accurate as the most recent comparison.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import asdict, dataclass
from typing import Any

import httpx

_log = logging.getLogger("mcp_proxy.version_check")


_GITHUB_RELEASES_URL = "https://api.github.com/repos/cullis-security/cullis/releases"
_TAG_PREFIX = "mastio-v"
_CACHE_TTL_S = 3600  # 1 hour — the GitHub Releases API allows 60 anon req/h
_FETCH_TIMEOUT_S = 5.0

# Module-level cache. Populated lazily by ``check_for_updates``.
_cache: dict[str, Any] | None = None
_cache_at: float = 0.0
_cache_lock = asyncio.Lock()


# Loose semver: ``MAJOR.MINOR.PATCH`` plus an optional ``-PRERELEASE``
# (rc1, rc2, beta, …). Captures pieces so ``_version_key`` can build a
# sortable tuple. Anything more exotic falls through and gets sorted
# lexically — fine for our naming convention.
_SEMVER_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z]+)(\d+)?)?$"
)


def _version_key(v: str) -> tuple:
    """Return a sortable tuple for a version string.

    Final releases (``0.3.0``) sort AFTER any of their prereleases
    (``0.3.0-rc1``, ``0.3.0-beta3``) — same convention as PEP 440 and
    npm/cargo. ``rc2`` sorts after ``rc1`` even when the major.minor
    part is the same. Unparseable strings sort last.
    """
    m = _SEMVER_RE.match(v)
    if not m:
        return (1, v)  # garbage versions sort after everything parseable
    major, minor, patch = int(m[1]), int(m[2]), int(m[3])
    pre_tag = m[4] or ""
    pre_num = int(m[5]) if m[5] else 0
    # ``is_release = 1`` for full releases, ``0`` for prereleases —
    # so the same major.minor.patch sorts ``rc1 < rc2 < (release)``.
    is_release = 1 if not pre_tag else 0
    # Pre-release tag ordering: alpha < beta < rc < anything-else.
    pre_rank = {"alpha": 0, "beta": 1, "rc": 2}.get(pre_tag, 3) if pre_tag else 0
    return (0, major, minor, patch, is_release, pre_rank, pre_num)


def get_current_version() -> str:
    """Image tag this container was started with, or ``"unknown"``.

    Set by ``packaging/mastio-bundle/docker-compose.yml`` from the
    operator-side ``CULLIS_MASTIO_VERSION``. Trimmed of an accidental
    ``mastio-v`` prefix so ``"unknown"`` and ``"0.3.0-rc2"`` are the
    only shapes the rest of the code has to handle.
    """
    raw = (os.environ.get("MCP_PROXY_VERSION") or "").strip()
    if not raw or raw in {"latest", "unknown"}:
        return "unknown"
    if raw.startswith(_TAG_PREFIX):
        raw = raw[len(_TAG_PREFIX):]
    return raw


async def get_latest_version() -> str | None:
    """Highest ``mastio-v*`` release tag on the public repo, or None.

    Returns the bare version (no ``mastio-v`` prefix). On any
    transport / parse failure we return None — the banner then
    silently stays hidden, which is the right outcome for an
    advisory feature.
    """
    try:
        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT_S) as client:
            resp = await client.get(_GITHUB_RELEASES_URL, params={"per_page": 50})
            resp.raise_for_status()
            releases = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        _log.info("version_check: GitHub releases fetch failed (%s)", exc)
        return None

    candidates: list[str] = []
    for r in releases:
        if not isinstance(r, dict):
            continue
        if r.get("draft") or r.get("prerelease") is None:
            # ``prerelease=None`` would mean malformed payload — skip.
            continue
        tag = r.get("tag_name") or ""
        if not tag.startswith(_TAG_PREFIX):
            continue
        version = tag[len(_TAG_PREFIX):]
        candidates.append(version)

    if not candidates:
        return None
    return max(candidates, key=_version_key)


@dataclass(frozen=True)
class UpdateStatus:
    """Banner-shaped payload the dashboard renders verbatim."""

    current: str  # ``"0.3.0-rc2"`` or ``"unknown"``
    latest: str | None  # ``"0.3.0-rc3"`` or None when GitHub is unreachable
    update_available: bool
    install_command: str | None  # the one-liner to copy
    release_url: str  # GitHub releases page — always safe to link


def _make_status(current: str, latest: str | None) -> UpdateStatus:
    update_available = (
        current != "unknown"
        and latest is not None
        and _version_key(latest) > _version_key(current)
    )
    install_command = (
        f"./deploy.sh --upgrade {latest}" if (update_available and latest) else None
    )
    return UpdateStatus(
        current=current,
        latest=latest,
        update_available=update_available,
        install_command=install_command,
        release_url="https://github.com/cullis-security/cullis/releases",
    )


async def check_for_updates(*, force: bool = False) -> UpdateStatus:
    """Cached comparison of running tag vs GHCR's latest. The
    dashboard endpoint calls this on every banner poll; the cache
    keeps the GitHub API call rare (~1/h)."""
    global _cache, _cache_at

    now = time.monotonic()
    async with _cache_lock:
        if (
            not force
            and _cache is not None
            and (now - _cache_at) < _CACHE_TTL_S
        ):
            return UpdateStatus(**_cache)

        current = get_current_version()
        latest = await get_latest_version()
        status = _make_status(current, latest)
        _cache = asdict(status)
        _cache_at = now
        return status


def reset_cache() -> None:
    """Test hook — clears the module cache so each test starts cold."""
    global _cache, _cache_at
    _cache = None
    _cache_at = 0.0
