"""Tests for the Mastio (mcp_proxy) ``/health`` version surface.

Bug #8 from the 2026-05-09 AI-as-customer dogfood: a customer that
runs ``cullis-mastio:0.3.1`` and curls ``/health`` sees
``{"status":"ok","version":"0.1.0"}``. ``0.1.0`` was a literal in
``mcp_proxy/main.py`` that nobody bumped after mastio-v0.3.0 cut.
The fix swaps the literal for ``_MASTIO_VERSION``, which is read
from ``CULLIS_MASTIO_VERSION`` and falls back to ``dev``.
``release-mastio.yml`` passes ``--build-arg VERSION=<tag>`` so the
running image labels and ``/health`` agree.
"""
from __future__ import annotations

import pytest


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
def test_mastio_version_defaults_to_dev_in_source_checkout():
    """Without CULLIS_MASTIO_VERSION env (the default for a source
    checkout / pytest run), ``_MASTIO_VERSION`` is ``dev`` so ops cannot
    confuse a dev process with a tagged release.

    Marked serial: ``mcp_proxy.main._MASTIO_VERSION`` is a module-level
    constant resolved at first import. Any test in another file that
    sets ``CULLIS_MASTIO_VERSION`` env + re-imports the module
    (intentionally or by side-effect) parks a non-``dev`` value that
    this test then sees. 6 reruns across PRs #720 / #722 / #723 / #727
    / #728 / #730 traced to this pattern. The xdist_group marker is a
    forward-looking pin for when the suite migrates to
    ``--dist=loadgroup``; today it still lets ``pytest -m serial`` run
    this test in isolation.
    """
    import mcp_proxy.main as _m
    assert _m._MASTIO_VERSION == "dev"


@pytest.mark.asyncio
async def test_mastio_health_surfaces_module_version(monkeypatch):
    """The ``/health`` handler reads ``_MASTIO_VERSION`` at call time
    (not a baked literal), so a release image with VERSION=1.2.3 baked
    in surfaces that exact value."""
    import mcp_proxy.main as _m
    monkeypatch.setattr(_m, "_MASTIO_VERSION", "1.2.3")

    class _Req:
        class _App:
            class _State:
                pass
            state = _State()
        app = _App()

    body = await _m.health(_Req())
    assert body == {"status": "ok", "version": "1.2.3"}
