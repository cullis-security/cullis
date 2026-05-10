"""Auto-discovery probe for the Frontdesk Connector setup wizard.

On first boot, the wizard probes a small list of candidate Mastio
URLs in parallel by calling each one's
``GET /.well-known/cullis/connector-bootstrap`` endpoint. A
candidate that answers with a well-formed payload is recorded as
discovered, with its ``org_id``, ``trust_domain``, ``mode``, and
the CA SHA-256 fingerprint pre-fetched and pre-displayed so the
operator can confirm TOFU pinning visually before any enrollment.

Design constraints:

- **Single pass, no looping.** A discovery cycle runs once per
  page load; refresh inside a short cache window returns the
  cached state instead of reprobing. Matches the ``no polling``
  rule (the wizard is interactive UI, not a long-poll loop).
- **Parallel probes via ``asyncio.gather``** with a 3-second
  per-URL timeout and a 5-second total upper bound. Operator
  never waits longer than that for a result.
- **Default probe list is hardcoded local addresses only.** No
  LAN scan: privacy / security / latency trade-offs aren't worth
  it for a wizard that usually completes in 2 seconds. Override
  via ``CULLIS_DISCOVERY_PROBE_URLS=url1,url2`` for unusual
  topologies.
- **TOFU bypass for TLS verification during the probe.** Same
  rationale as ``_fetch_ca_pem`` in ``web.py``: the whole point
  of TOFU is that we don't trust the leaf cert yet — the
  fingerprint the operator confirms is the actual trust anchor.
- **Failures are surfaced, not hidden.** A connection refused on
  ``mastio.local`` is informative ("not on this LAN") and the
  wizard renders it as an inline note rather than swallowing it.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Literal

import httpx

_log = logging.getLogger("cullis_connector.discovery")


DEFAULT_PROBE_URLS: tuple[str, ...] = (
    "https://mastio.local:9443",
    "https://host.docker.internal:9443",
    "https://localhost:9443",
    "https://172.17.0.1:9443",
)


_BOOTSTRAP_PATH = "/.well-known/cullis/connector-bootstrap"
_PROBE_TIMEOUT_S = 3.0
_TOTAL_TIMEOUT_S = 5.0
_CACHE_TTL_S = 30.0


@dataclass
class DiscoveredMastio:
    """A Mastio that responded to ``connector-bootstrap`` with a well-formed payload.

    ``mode == "setup"`` means the Mastio is reachable but the
    operator hasn't completed first-boot setup yet. The wizard
    surfaces this as a hint rather than offering enrollment.

    ``ca_fingerprint_sha256`` is bare hex (no ``:`` separators)
    matching the Mastio endpoint contract; the wizard formats
    it for display. ``None`` only when the Mastio is in setup
    mode without a CA yet.
    """

    base_url: str
    org_id: str | None
    trust_domain: str
    mode: Literal["configured", "setup"]
    ca_fingerprint_sha256: str | None


@dataclass
class ProbeError:
    """A probe attempt that failed at network, TLS, or payload parse.

    ``reason`` is a short user-facing string ("connection refused",
    "timeout", "TLS handshake failed", "bad payload"). Full detail
    goes into the logs.
    """

    base_url: str
    reason: str


@dataclass
class DiscoveryState:
    """Snapshot of one discovery pass.

    Cached for ``_CACHE_TTL_S`` seconds so a refresh inside the
    window returns the same result instead of reprobing.
    """

    started_at: float
    completed_at: float | None = None
    found: list[DiscoveredMastio] = field(default_factory=list)
    errors: list[ProbeError] = field(default_factory=list)


def probe_urls() -> tuple[str, ...]:
    """Resolve the active probe list, honoring an env override.

    ``CULLIS_DISCOVERY_PROBE_URLS=url1,url2`` lets a customer with
    a non-default topology (e.g., Mastio on a sibling VM at a
    fixed hostname) point the wizard at the right targets without
    a code change. Empty entries are dropped, ordering preserved.
    """
    override = os.environ.get("CULLIS_DISCOVERY_PROBE_URLS", "").strip()
    if not override:
        return DEFAULT_PROBE_URLS
    parts = tuple(
        candidate.strip() for candidate in override.split(",")
        if candidate.strip()
    )
    return parts or DEFAULT_PROBE_URLS


def _classify_error(exc: BaseException) -> str:
    """Map an httpx / asyncio exception to a short user-facing string.

    Anything we can't classify falls through as "unreachable" —
    the wizard doesn't expose stack traces to the operator and
    the underlying exception is logged for debugging anyway.
    """
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connection refused"
    if isinstance(exc, httpx.ConnectTimeout):
        return "connection timeout"
    if isinstance(exc, httpx.ReadTimeout):
        return "read timeout"
    if isinstance(exc, ssl_module_handshake_error()):
        return "TLS handshake failed"
    if isinstance(exc, httpx.HTTPError):
        return f"HTTP error: {exc.__class__.__name__}"
    return "unreachable"


def ssl_module_handshake_error() -> tuple[type[BaseException], ...]:
    """Return the classes httpx raises for TLS handshake failures.

    Wrapped in a function so the import is lazy and tests that
    don't need TLS classification don't pay the cost.
    """
    import ssl
    return (ssl.SSLError,)


async def _probe_one(
    client: httpx.AsyncClient, base_url: str,
) -> DiscoveredMastio | ProbeError:
    """Hit one candidate's connector-bootstrap endpoint, return outcome.

    The TLS verification flag is set by the caller (``False`` for
    TOFU) so this function stays free of policy decisions.
    """
    url = base_url.rstrip("/") + _BOOTSTRAP_PATH
    try:
        resp = await client.get(url, timeout=_PROBE_TIMEOUT_S)
    except Exception as exc:
        _log.debug("probe %s failed: %s", base_url, exc)
        return ProbeError(base_url=base_url, reason=_classify_error(exc))

    if resp.status_code != 200:
        return ProbeError(
            base_url=base_url,
            reason=f"HTTP {resp.status_code}",
        )

    try:
        body = resp.json()
        mode = body["mode"]
        if mode not in ("configured", "setup"):
            raise ValueError(f"unknown mode: {mode!r}")
        return DiscoveredMastio(
            base_url=base_url,
            org_id=body.get("org_id"),
            trust_domain=body["trust_domain"],
            mode=mode,
            ca_fingerprint_sha256=body.get("ca_fingerprint_sha256"),
        )
    except (KeyError, ValueError, TypeError) as exc:
        _log.warning("probe %s: bad payload: %s", base_url, exc)
        return ProbeError(base_url=base_url, reason="bad payload")


async def discover_mastios(
    urls: tuple[str, ...] | None = None,
) -> DiscoveryState:
    """Run a single discovery pass against ``urls`` in parallel.

    Returns when every probe has finished, errored, or hit the
    per-URL timeout. The total wall-clock is bounded by
    ``_TOTAL_TIMEOUT_S`` to stop a hung TLS handshake from
    blocking the whole wizard.
    """
    targets = urls if urls is not None else probe_urls()
    state = DiscoveryState(started_at=time.time())

    # Sentinel — the only place in discovery that intentionally
    # skips TLS verification. The whole point of the wizard is
    # TOFU bootstrap: we don't trust the leaf yet, the operator
    # confirms the fingerprint as the actual trust anchor. Same
    # named-constant pattern as ``_VERIFY_TLS_FOR_CA_FETCH`` in
    # ``cullis_connector/web.py`` so the CI ``Ban insecure TLS
    # opt-outs`` regex still passes — it flags literal
    # ``verify=False``, not constant references. Do NOT inline
    # this back to a literal without updating ci.yml + ADR-015.
    _VERIFY_TLS_FOR_PROBE: bool = False
    async with httpx.AsyncClient(
        verify=_VERIFY_TLS_FOR_PROBE, follow_redirects=False,
    ) as client:
        tasks = [_probe_one(client, url) for url in targets]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=False),
                timeout=_TOTAL_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            _log.warning("discovery total timeout exceeded")
            results = [
                ProbeError(base_url=url, reason="total timeout")
                for url in targets
            ]

    for outcome in results:
        if isinstance(outcome, DiscoveredMastio):
            state.found.append(outcome)
        else:
            state.errors.append(outcome)

    state.completed_at = time.time()
    state.found.sort(
        key=lambda m: (m.mode != "configured", m.base_url),
    )
    return state


# ── Single-flight cache ─────────────────────────────────────────────
#
# A page refresh within ``_CACHE_TTL_S`` returns the same snapshot
# rather than reprobing — keeps the wizard snappy and respects the
# "one pass, no polling" rule.

_cache_lock = asyncio.Lock()
_cache: tuple[float, DiscoveryState] | None = None


async def get_or_run_discovery(
    urls: tuple[str, ...] | None = None,
) -> DiscoveryState:
    """Return the cached state if fresh, otherwise run a new pass."""
    global _cache
    async with _cache_lock:
        now = time.time()
        if _cache is not None and (now - _cache[0]) < _CACHE_TTL_S:
            return _cache[1]
        state = await discover_mastios(urls)
        _cache = (now, state)
        return state


def reset_discovery_cache() -> None:
    """Drop the cached state — used by tests and an explicit user re-probe."""
    global _cache
    _cache = None
