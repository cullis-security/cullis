"""
Unit tests for ``mcp_proxy/auth/dpop.py`` htu-mismatch operability
(P3 MAJOR-2 of imp/p3-operability-audit.md).

Coverage:
  - htu mismatch always emits ``X-Cullis-Hint: htu_mismatch_check_proxy_public_url``
  - in non-production environments the body includes expected+got for dev UX
  - in production the body is generic (no internal URL leak)

These tests call ``mcp_proxy.auth.dpop.verify_dpop_proof`` directly with
``require_nonce=False`` so we exercise the htu branch without involving the
nonce machinery.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from mcp_proxy.auth.dpop import verify_dpop_proof
from mcp_proxy.auth.dpop_jti_store import reset_dpop_jti_store
from mcp_proxy.config import get_settings
from tests.cert_factory import make_dpop_key_pair, make_dpop_proof

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _reset_jti_store():
    reset_dpop_jti_store()
    yield
    reset_dpop_jti_store()


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _build_proof(claimed_htu: str) -> str:
    priv, jwk = make_dpop_key_pair()
    return make_dpop_proof(priv, jwk, "POST", claimed_htu)


async def test_htu_mismatch_includes_hint_header(monkeypatch):
    """htu mismatch must always carry X-Cullis-Hint, in any environment."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    get_settings.cache_clear()

    proof = _build_proof("http://wrong-host.example/v1/mcp")
    with pytest.raises(HTTPException) as exc_info:
        await verify_dpop_proof(
            proof,
            htm="POST",
            htu="http://right-host.example/v1/mcp",
            require_nonce=False,
        )
    err = exc_info.value
    assert err.status_code == 401
    assert err.headers is not None
    assert err.headers.get("X-Cullis-Hint") == "htu_mismatch_check_proxy_public_url"


async def test_htu_mismatch_dev_body_includes_expected_got(monkeypatch):
    """Non-production: expected+got included in body for fast diagnosis."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    get_settings.cache_clear()

    expected_url = "http://right-host.example/v1/mcp"
    wrong_url = "http://wrong-host.example/v1/mcp"
    proof = _build_proof(wrong_url)

    with pytest.raises(HTTPException) as exc_info:
        await verify_dpop_proof(
            proof, htm="POST", htu=expected_url, require_nonce=False
        )
    detail = exc_info.value.detail
    assert "htu mismatch" in detail
    assert "expected=" in detail
    assert "got=" in detail
    # Both normalized URLs surface in the message
    assert "right-host.example" in detail
    assert "wrong-host.example" in detail
    # Hint header still present
    assert (
        exc_info.value.headers.get("X-Cullis-Hint")
        == "htu_mismatch_check_proxy_public_url"
    )


async def test_htu_mismatch_prod_body_generic(monkeypatch):
    """Production: body is exactly generic, no internal URL leak."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    get_settings.cache_clear()

    expected_url = "https://mastio.internal.corp/v1/mcp"
    wrong_url = "https://mastio-leaked.example/v1/mcp"
    proof = _build_proof(wrong_url)

    with pytest.raises(HTTPException) as exc_info:
        await verify_dpop_proof(
            proof, htm="POST", htu=expected_url, require_nonce=False
        )
    err = exc_info.value
    assert err.status_code == 401
    assert err.detail == "Invalid DPoP proof: htu mismatch"
    # Header present in prod too (machine-readable, does not leak URL)
    assert (
        err.headers.get("X-Cullis-Hint") == "htu_mismatch_check_proxy_public_url"
    )
    # Defense in depth: the internal URL must not appear anywhere in detail
    assert "mastio.internal.corp" not in err.detail
    assert "mastio-leaked" not in err.detail
