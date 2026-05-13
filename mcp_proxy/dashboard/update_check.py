"""Mastio self-update check: poll GitHub releases for the latest
``mastio-vX.Y.Z`` tag, cache the result in ``proxy_config``, surface
a dismissible banner on the dashboard.

This is operational, not federation: the Mastio polls GitHub directly,
NOT through the Court ([[court-is-federation-broker-not-management-hub]]).
Each org is sovereign on its own update lifecycle. The Court does not
need to know which version each federated Mastio runs.

The check is informational only — the Mastio does NOT auto-apply the
upgrade. The banner shows the operator that a new release exists and
hands over a copy-pasteable command to run on the host. Self-execution
would require Docker socket access from inside the container, which
crosses a privilege boundary the threat model refuses ([[update-button-inside-mastio-is-anti-pattern]]).
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from pydantic import BaseModel

from mcp_proxy.db import get_config, set_config

_log = logging.getLogger("mcp_proxy.dashboard.update_check")


# GitHub repo + endpoint. Hardcoded — the bundle is one product, not
# a generic update framework. If we ever ship a private fork that needs
# a different repo, this becomes an env knob; for now keep it static
# so an attacker who can flip an env can't redirect the check.
_GITHUB_REPO = "cullis-security/cullis"
_RELEASES_URL = f"https://api.github.com/repos/{_GITHUB_REPO}/releases"

# Stay well below GitHub's 60 req/hour unauthenticated quota.
_POLL_INTERVAL = timedelta(hours=24)

# How long the in-process cache is fresh. We hold the value in DB
# config but also short-circuit via this window so concurrent requests
# don't all hit GitHub on startup.
_HTTP_TIMEOUT = 5.0

# Tag prefix we care about. Other tags (connector-vX.Y.Z, chat-vX.Y.Z,
# frontdesk-bundle-vX.Y.Z) live in the same repo but address other
# components — ignore them.
_TAG_PREFIX = "mastio-v"

# Config keys.
_KEY_LAST_POLL = "update_check_last_poll_at"
_KEY_LATEST_TAG = "update_check_latest_tag"
_KEY_LATEST_URL = "update_check_latest_url"
_KEY_DISMISSED_TAG = "update_check_dismissed_tag"


class ReleaseInfo(BaseModel):
    """The fields we extract from a GitHub release entry."""
    tag: str
    html_url: str


class UpdateStatus(BaseModel):
    """What the dashboard renders.

    ``available`` is the only field the template cares about for the
    "show banner / hide banner" decision. ``latest_url`` lets the modal
    link to the release notes. ``current`` is informational.
    """
    current: str
    latest: Optional[str] = None
    latest_url: Optional[str] = None
    available: bool = False
    last_polled_at: Optional[str] = None


def _current_version() -> str:
    """Resolve the running Mastio version.

    Matches the env that ``mcp_proxy/main.py`` already reads at lifespan
    start. ``dev`` when running from source.
    """
    return os.environ.get("CULLIS_MASTIO_VERSION", "dev")


def _parse_semver(tag: str) -> Optional[tuple[int, int, int, str]]:
    """``mastio-v0.3.8`` → ``(0, 3, 8, "")``. ``mastio-v0.3.8-rc2`` →
    ``(0, 3, 8, "rc2")``. ``None`` if the tag is not a recognisable
    semver under our prefix.

    The pre-release suffix sorts AFTER the bare version so an rc never
    triumphs over a final release with the same x.y.z (matches the
    semver spec: 1.0.0-rc1 < 1.0.0). We model this by treating an
    empty suffix as the highest possible string for the sort key.
    """
    if not tag.startswith(_TAG_PREFIX):
        return None
    rest = tag[len(_TAG_PREFIX):]
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$", rest)
    if not m:
        return None
    major, minor, patch, suffix = m.groups()
    return int(major), int(minor), int(patch), suffix or ""


def _is_newer(candidate_tag: str, current_version: str) -> bool:
    """Return True iff ``candidate_tag`` is a newer semver than the
    bare ``current_version`` (no ``mastio-v`` prefix on current — it's
    the env value like ``0.3.8``).

    Defensive: any parse failure on either side returns False so the
    banner never fires from garbled data. ``dev`` current always
    triggers the banner because any tagged release is "newer than dev".
    """
    if current_version == "dev":
        return True
    c = _parse_semver(candidate_tag)
    if c is None:
        return False
    cur = _parse_semver(f"{_TAG_PREFIX}{current_version}")
    if cur is None:
        return False
    # Compare (M, m, p) first, then suffix. Empty suffix > non-empty
    # so a final release beats an rc with the same x.y.z.
    c_key = (c[0], c[1], c[2], 1 if c[3] == "" else 0, c[3])
    cur_key = (cur[0], cur[1], cur[2], 1 if cur[3] == "" else 0, cur[3])
    return c_key > cur_key


async def _fetch_latest_from_github() -> Optional[ReleaseInfo]:
    """One-shot GET to GitHub releases API.

    Returns the highest semver ``mastio-v*`` release (by parsed x.y.z,
    final > rc) or ``None`` on any transport / parse error. The caller
    decides what to do with ``None`` (typically: keep the cached value,
    don't crash the dashboard).

    ``/releases`` returns up to 30 entries by default and includes
    pre-releases. Filter + sort client-side so the choice is in our
    hands, not GitHub's "latest" heuristic (which picks the most
    recently published non-prerelease across ALL tag prefixes,
    including connector / chat / frontdesk-bundle — wrong for us).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"cullis-mastio/{_current_version()}",
        # GitHub recommends pinning the API version; v2022-11-28 is the
        # stable line at the time of writing.
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(_RELEASES_URL, headers=headers)
        if resp.status_code != 200:
            _log.warning(
                "update_check: GitHub responded HTTP %s", resp.status_code,
            )
            return None
        entries = resp.json()
    except (httpx.HTTPError, ValueError) as exc:  # ValueError covers JSON decode
        _log.warning("update_check: GitHub fetch failed: %s", exc)
        return None

    candidates: list[tuple[tuple, str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        tag = entry.get("tag_name") or ""
        if not tag.startswith(_TAG_PREFIX):
            continue
        parsed = _parse_semver(tag)
        if parsed is None:
            continue
        key = (parsed[0], parsed[1], parsed[2], 1 if parsed[3] == "" else 0, parsed[3])
        html_url = entry.get("html_url") or ""
        if not html_url.startswith("https://github.com/"):
            # Defensive: refuse anything not on github.com so a poisoned
            # response can't redirect the operator to a phishing link.
            continue
        candidates.append((key, tag, html_url))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    _, tag, html_url = candidates[0]
    return ReleaseInfo(tag=tag, html_url=html_url)


async def _refresh_cache_if_stale() -> None:
    """If the cache is older than ``_POLL_INTERVAL``, poll GitHub once
    and persist. Swallows errors — the dashboard must never block on
    GitHub being reachable.

    Called lazily from the status endpoint, NOT from the lifespan, so
    a Mastio behind a strict outbound firewall doesn't pay startup
    latency on every boot. First dashboard hit triggers the first
    poll.
    """
    now = datetime.now(timezone.utc)
    last_raw = await get_config(_KEY_LAST_POLL)
    if last_raw:
        try:
            last = datetime.fromisoformat(last_raw)
            if now - last < _POLL_INTERVAL:
                return  # cache still fresh
        except ValueError:
            pass  # garbled timestamp, treat as never polled

    info = await _fetch_latest_from_github()
    # Always update the timestamp so a transient GitHub outage doesn't
    # cause us to hammer the API. On success we also refresh the tag.
    await set_config(_KEY_LAST_POLL, now.isoformat())
    if info is not None:
        await set_config(_KEY_LATEST_TAG, info.tag)
        await set_config(_KEY_LATEST_URL, info.html_url)


async def get_update_status() -> UpdateStatus:
    """Return what the dashboard banner should render.

    Lazy-polls GitHub if the cache is stale. Honors the operator's
    dismiss: if ``update_check_dismissed_tag`` equals the cached
    ``update_check_latest_tag``, ``available`` is False and the
    banner is suppressed until a newer release shows up.
    """
    await _refresh_cache_if_stale()

    current = _current_version()
    latest_tag = await get_config(_KEY_LATEST_TAG)
    latest_url = await get_config(_KEY_LATEST_URL)
    dismissed = await get_config(_KEY_DISMISSED_TAG)
    last_poll = await get_config(_KEY_LAST_POLL)

    available = False
    if latest_tag and _is_newer(latest_tag, current):
        if dismissed != latest_tag:
            available = True

    return UpdateStatus(
        current=current,
        latest=latest_tag,
        latest_url=latest_url,
        available=available,
        last_polled_at=last_poll,
    )


async def dismiss_current_latest() -> Optional[str]:
    """Operator clicked dismiss on the banner. Pin the dismissed tag
    to whatever is currently cached as ``latest``. Banner stays hidden
    until a newer release arrives.

    Returns the tag that was dismissed (for the audit row), or None
    if there was nothing cached to dismiss.
    """
    latest = await get_config(_KEY_LATEST_TAG)
    if not latest:
        return None
    await set_config(_KEY_DISMISSED_TAG, latest)
    return latest


__all__ = [
    "ReleaseInfo",
    "UpdateStatus",
    "dismiss_current_latest",
    "get_update_status",
]
