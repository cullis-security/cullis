"""ADR-029 Phase G — dynamic peer-Mastio URL discovery via Court.

Phase D-2 wired cross-org tool-call PDP federation by having each
originator Mastio read a static JSON env map
``MCP_PROXY_TOOL_PDP_FEDERATION_URLS`` (``{org_id: url}``). That works
for two-org demos but does not scale: every operator has to update
every peer's env file when a new org joins the network or moves its
Mastio behind a new URL.

Phase G moves the source of truth into the Court registry. The org
admin sets the URL once (``PATCH /v1/registry/orgs/{id}/mastio-url``)
and every other Mastio resolves it at PDP evaluation time via
``GET /v1/federation/orgs/{id}/mastio-url``. Lookups are cached for
:data:`_TTL_SECONDS` to bound the hot-path latency cost.

Operator override remains: the env map is consulted **first** and the
Court lookup only fires when the local config has no entry. This lets
operators pin a URL temporarily (e.g. during a peer's blue/green
rollout) without changing Court state.

Failure mode is conservative. If the Court is unreachable, the entry
is unknown, or the response is malformed, :meth:`resolve` returns
``None`` and the caller treats it as default-deny — same posture as
the pre-Phase-G "missing env entry" branch.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

_log = logging.getLogger("mcp_proxy.policy.federation_catalog")

# Cache TTL. Short enough that a freshly published URL is picked up
# within minutes without a Mastio restart; long enough that PDP
# evaluation stays cheap under load. The same value is used for
# negative caching ("Court said 404") so a peer that has not yet
# published a URL does not flood Court with repeated lookups while
# its admin is mid-onboarding.
_TTL_SECONDS = 300.0
_LOOKUP_TIMEOUT = 3.0  # seconds
_MAX_URL_LENGTH = 512


@dataclass
class _CacheEntry:
    """Memoised result of a peer URL resolution.

    ``url`` is ``None`` for negative cache hits (org unknown to Court
    or no URL published). ``expires_at`` is an absolute monotonic
    timestamp; entries older than this are refreshed on next access.
    """
    url: str | None
    expires_at: float


class FederationCatalog:
    """Thread-safe peer-URL resolver with TTL cache + env fallback.

    Instances are intended to be long-lived; one per Mastio process
    suffices. The cache is in-memory only (no Redis, no disk) so a
    restart drops the cache, which is fine — the first PDP call for
    each peer pays the Court round-trip once.
    """

    def __init__(
        self,
        *,
        court_base_url: str | None,
        env_map: dict[str, str] | None = None,
        ttl_seconds: float = _TTL_SECONDS,
    ) -> None:
        self._court_base_url = (court_base_url or "").rstrip("/") or None
        self._env_map = dict(env_map or {})
        self._ttl = ttl_seconds
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def resolve(self, target_org: str) -> str | None:
        """Return the URL where ``target_org``'s Mastio answers tool-call
        federation, or ``None`` if it cannot be determined.

        Lookup order:

        1. Env override (``MCP_PROXY_TOOL_PDP_FEDERATION_URLS``).
        2. Memoised positive or negative cache entry (within TTL).
        3. Live ``GET /v1/federation/orgs/{org}/mastio-url`` against Court.

        Cache rules: definitive answers from Court (200 with a valid URL,
        or 404) are cached for ``ttl_seconds``. Transport errors are
        **not** cached — a flaky Court should not lock out cross-org
        invocations for the whole TTL, the next PDP call retries.
        """
        if not target_org:
            return None

        env_url = self._env_map.get(target_org)
        if env_url:
            return env_url

        if self._court_base_url is None:
            # No Court uplink configured — cannot resolve dynamically.
            return None

        now = time.monotonic()
        async with self._lock:
            entry = self._cache.get(target_org)
            if entry is not None and entry.expires_at > now:
                return entry.url

            url, definitive = await self._fetch_from_court(target_org)
            if definitive:
                self._cache[target_org] = _CacheEntry(
                    url=url, expires_at=now + self._ttl,
                )
            return url

    async def _fetch_from_court(
        self, target_org: str,
    ) -> tuple[str | None, bool]:
        """Lookup ``target_org`` at Court.

        Returns ``(url, definitive)``. ``definitive=True`` means the
        Court answered (200 with a valid URL, or 404) and the result
        is cacheable. ``definitive=False`` means the lookup failed in
        a non-deterministic way (timeout, transport error, non-200,
        malformed body) and the caller should not cache.
        """
        endpoint = (
            f"{self._court_base_url}/v1/federation/orgs/{target_org}/mastio-url"
        )
        try:
            async with httpx.AsyncClient(
                timeout=_LOOKUP_TIMEOUT, follow_redirects=False,
            ) as client:
                resp = await client.get(endpoint)
        except httpx.TimeoutException:
            _log.warning(
                "federation catalog lookup timeout target=%s url=%s",
                target_org, endpoint,
            )
            return None, False
        except Exception as exc:
            _log.warning(
                "federation catalog lookup transport error target=%s url=%s err=%s",
                target_org, endpoint, exc,
            )
            return None, False

        if resp.status_code == 404:
            # Org unknown or has not published a URL. Negative cache.
            return None, True
        if resp.status_code != 200:
            _log.warning(
                "federation catalog lookup non-200 target=%s status=%s",
                target_org, resp.status_code,
            )
            return None, False

        try:
            data = resp.json()
        except Exception:
            return None, False

        url = data.get("mastio_url") if isinstance(data, dict) else None
        if not isinstance(url, str):
            return None, False
        url = url.strip()
        if not url or len(url) > _MAX_URL_LENGTH:
            return None, False
        if not (url.startswith("http://") or url.startswith("https://")):
            # Defensive: should never happen because the admin PATCH
            # validates the protocol, but the catalog is a security
            # boundary and a malformed URL would propagate to httpx.
            _log.warning(
                "federation catalog rejected non-HTTP URL target=%s url=%s",
                target_org, url,
            )
            return None, False
        return url.rstrip("/"), True

    def invalidate(self, target_org: str | None = None) -> None:
        """Drop cache entries.

        Called on admin-triggered events (e.g. an explicit refresh) or
        by tests. Without an argument, drops the whole cache.
        """
        if target_org is None:
            self._cache.clear()
        else:
            self._cache.pop(target_org, None)
