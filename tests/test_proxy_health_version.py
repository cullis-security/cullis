"""Tests for the Mastio (mcp_proxy) ``/health`` version surface.

Bug #8 from the 2026-05-09 AI-as-customer dogfood: a customer that
runs ``cullis-mastio:0.3.1`` and curls ``/health`` sees
``{"status":"ok","version":"0.1.0"}``. ``0.1.0`` was a literal in
``mcp_proxy/main.py`` that nobody bumped after mastio-v0.3.0 cut.
The fix routes ``/health`` through ``_mastio_version()`` which reads
``CULLIS_MASTIO_VERSION`` at call time (was an import-time constant,
caused 6+ flake reruns due to cross-file env mutation), falling
back to ``dev`` for source-checkout runs.
``release-mastio.yml`` passes ``--build-arg VERSION=<tag>`` so the
running image labels and ``/health`` agree.
"""
from __future__ import annotations

import pytest


def test_mastio_version_defaults_to_dev_in_source_checkout(monkeypatch):
    """Without CULLIS_MASTIO_VERSION env (the default for a source
    checkout / pytest run), ``_mastio_version()`` returns ``dev`` so
    ops cannot confuse a dev process with a tagged release.

    The function reads env at call time, so this assertion is
    deterministic regardless of what other tests in the suite set on
    ``CULLIS_MASTIO_VERSION`` before importing ``mcp_proxy.main``.
    The explicit ``delenv`` guards against an operator-set value
    leaking into the test process (CI runners, dev shells with the
    var exported)."""
    import mcp_proxy.main as _m
    monkeypatch.delenv("CULLIS_MASTIO_VERSION", raising=False)
    assert _m._mastio_version() == "dev"


@pytest.mark.asyncio
async def test_mastio_health_surfaces_module_version(monkeypatch):
    """The ``/health`` handler calls ``_mastio_version()`` so a release
    image with VERSION=1.2.3 baked in (and thus
    ``CULLIS_MASTIO_VERSION=1.2.3``) surfaces that exact value."""
    import mcp_proxy.main as _m
    monkeypatch.setenv("CULLIS_MASTIO_VERSION", "1.2.3")

    class _Req:
        class _App:
            class _State:
                pass
            state = _State()
        app = _App()

    body = await _m.health(_Req())
    assert body == {"status": "ok", "version": "1.2.3"}
