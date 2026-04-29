"""Tests for the dashboard's update advisory.

The container can't auto-replace itself (would need
``/var/run/docker.sock`` mounted, which is a privilege escalation
antipattern). Instead, the dashboard polls GHCR for newer
``mastio-v*`` releases and surfaces the exact ``./deploy.sh
--upgrade <ver>`` the operator should run on the host.

These tests pin the comparator + the cache + the install_command
shape so a regression silently swapping in the wrong tag (or worse,
auto-pulling) shows up at unit-test time.
"""
from __future__ import annotations

import asyncio

import pytest

from mcp_proxy import version_check
from mcp_proxy.version_check import (
    UpdateStatus,
    _make_status,
    _version_key,
    check_for_updates,
    get_current_version,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _isolate_module_state(monkeypatch):
    """Reset cache + scrub MCP_PROXY_VERSION env between tests so each
    case starts cold. The cache is module-level by design (one
    Mastio process, one cache) and would leak across tests otherwise."""
    reset_cache()
    monkeypatch.delenv("MCP_PROXY_VERSION", raising=False)
    yield
    reset_cache()


# ── _version_key — comparator pin ───────────────────────────────────


def test_release_sorts_after_its_prereleases():
    """Final ``0.3.0`` must beat any of its rcs — same convention as
    PEP 440. Otherwise we'd nag the operator to "upgrade" from a
    final release back to an rc."""
    assert _version_key("0.3.0") > _version_key("0.3.0-rc1")
    assert _version_key("0.3.0") > _version_key("0.3.0-rc99")
    assert _version_key("0.3.0") > _version_key("0.3.0-beta3")


def test_rc_numbers_sort_by_int_not_string():
    """``rc10`` must beat ``rc2`` numerically — string sort would
    flip them and a banner would lie to the operator."""
    assert _version_key("0.3.0-rc10") > _version_key("0.3.0-rc2")


def test_alpha_beta_rc_ordering():
    """alpha < beta < rc — anyone running an rc must not be told
    a newer beta is "available"."""
    assert _version_key("0.3.0-alpha1") < _version_key("0.3.0-beta1")
    assert _version_key("0.3.0-beta1") < _version_key("0.3.0-rc1")


def test_unparseable_versions_sort_last():
    """Garbage tag (``"latest"``, ``"main"``, manual experiments) must
    not silently win the comparison and trigger a "downgrade"
    suggestion."""
    assert _version_key("0.3.0-rc1") < _version_key("garbage-tag")
    # …and ``unknown`` is treated like garbage too.
    assert _version_key("0.3.0") < _version_key("unknown")


# ── get_current_version — env wiring ────────────────────────────────


def test_current_version_from_env(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_VERSION", "0.3.0-rc2")
    assert get_current_version() == "0.3.0-rc2"


def test_current_version_strips_mastio_v_prefix(monkeypatch):
    """The compose env normally passes the bare version, but a careless
    operator may paste the full tag (``mastio-v0.3.0-rc2``). Strip it
    so the comparator doesn't see two different shapes."""
    monkeypatch.setenv("MCP_PROXY_VERSION", "mastio-v0.3.0-rc2")
    assert get_current_version() == "0.3.0-rc2"


@pytest.mark.parametrize("val", ["", "latest", "unknown", "   "])
def test_current_version_returns_unknown_for_dev_runs(monkeypatch, val):
    """Dev compose / image rebuilt locally without a tag → ``"unknown"``
    so the banner stays silent (we can't compare against GitHub)."""
    monkeypatch.setenv("MCP_PROXY_VERSION", val)
    assert get_current_version() == "unknown"


# ── _make_status — banner shape ─────────────────────────────────────


def test_make_status_update_available_when_latest_is_newer():
    s = _make_status("0.3.0-rc2", "0.3.0-rc3")
    assert s.update_available is True
    assert s.install_command == "./deploy.sh --upgrade 0.3.0-rc3"
    assert s.release_url.endswith("/releases")


def test_make_status_no_update_when_versions_equal():
    s = _make_status("0.3.0-rc3", "0.3.0-rc3")
    assert s.update_available is False
    assert s.install_command is None


def test_make_status_no_update_when_running_ahead_of_published():
    """Operator running a custom build of main (newer than any
    tagged release) — banner must stay silent so we don't suggest
    a "downgrade" install command."""
    s = _make_status("0.4.0", "0.3.0-rc3")
    assert s.update_available is False


def test_make_status_silent_on_unknown_current():
    """Dev runs (``MCP_PROXY_VERSION=unknown``) must produce no
    banner — we have nothing to compare against, and the operator
    on a bespoke build doesn't want noise."""
    s = _make_status("unknown", "0.3.0-rc3")
    assert s.update_available is False
    assert s.install_command is None


def test_make_status_silent_when_github_unreachable():
    """Latest=None is the documented signal for transport failure;
    must not flip update_available."""
    s = _make_status("0.3.0-rc2", None)
    assert s.update_available is False
    assert s.install_command is None


# ── check_for_updates — cache + GitHub stub ─────────────────────────


@pytest.mark.asyncio
async def test_check_for_updates_round_trip(monkeypatch):
    """Happy path: env says rc2, GitHub says rc3, banner gets
    upgrade=True + the right one-liner."""
    monkeypatch.setenv("MCP_PROXY_VERSION", "0.3.0-rc2")

    async def _fake_latest():
        return "0.3.0-rc3"

    monkeypatch.setattr(version_check, "get_latest_version", _fake_latest)
    status = await check_for_updates(force=True)
    assert isinstance(status, UpdateStatus)
    assert status.current == "0.3.0-rc2"
    assert status.latest == "0.3.0-rc3"
    assert status.update_available is True
    assert status.install_command == "./deploy.sh --upgrade 0.3.0-rc3"


@pytest.mark.asyncio
async def test_check_for_updates_caches_result(monkeypatch):
    """Second call within TTL must NOT re-hit GitHub — the API has a
    60 anon req/h limit per IP and a busy dashboard with multiple
    admins would burn through it fast."""
    monkeypatch.setenv("MCP_PROXY_VERSION", "0.3.0-rc2")
    calls = 0

    async def _fake_latest():
        nonlocal calls
        calls += 1
        return "0.3.0-rc3"

    monkeypatch.setattr(version_check, "get_latest_version", _fake_latest)
    await check_for_updates(force=True)
    await check_for_updates()  # warm cache
    await check_for_updates()  # warm cache
    assert calls == 1, f"GitHub API called {calls} times — cache bypassed"


@pytest.mark.asyncio
async def test_check_for_updates_concurrent_fetches_dont_thunder(monkeypatch):
    """Two concurrent first-call awaits must serialise on the lock
    so we don't race two GitHub requests in the cold path."""
    monkeypatch.setenv("MCP_PROXY_VERSION", "0.3.0-rc2")
    calls = 0

    async def _fake_latest():
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return "0.3.0-rc3"

    monkeypatch.setattr(version_check, "get_latest_version", _fake_latest)
    results = await asyncio.gather(
        check_for_updates(force=True),
        check_for_updates(),
        check_for_updates(),
    )
    assert all(r.latest == "0.3.0-rc3" for r in results)
    assert calls == 1


# ── get_latest_version — GitHub API stub ────────────────────────────


@pytest.mark.asyncio
async def test_get_latest_version_picks_highest_mastio_release(monkeypatch):
    """Releases API returns a mixed bag (drafts, connector tags, the
    mastio chain). Filter must keep only ``mastio-v*`` non-draft
    non-prerelease, then return the highest by semver."""
    fake_releases = [
        {"tag_name": "connector-v0.3.4", "draft": False, "prerelease": False},
        {"tag_name": "mastio-v0.3.0-rc1", "draft": False, "prerelease": False},
        {"tag_name": "mastio-v0.3.0-rc3", "draft": False, "prerelease": False},
        {"tag_name": "mastio-v0.3.0-rc2", "draft": False, "prerelease": False},
        {"tag_name": "mastio-v0.4.0-alpha1", "draft": True, "prerelease": False},
        {"tag_name": "sdk-v0.1.0", "draft": False, "prerelease": False},
    ]

    class _StubResp:
        def raise_for_status(self): pass
        def json(self): return fake_releases

    class _StubClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, **kw): return _StubResp()

    monkeypatch.setattr(version_check.httpx, "AsyncClient", _StubClient)
    latest = await version_check.get_latest_version()
    assert latest == "0.3.0-rc3"


@pytest.mark.asyncio
async def test_get_latest_version_returns_none_on_transport_error(monkeypatch):
    import httpx as _httpx

    class _StubClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, **kw):
            raise _httpx.ConnectError(
                "github unreachable",
                request=_httpx.Request("GET", "https://api.github.com"),
            )

    monkeypatch.setattr(version_check.httpx, "AsyncClient", _StubClient)
    assert await version_check.get_latest_version() is None
