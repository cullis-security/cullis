"""Wave 2 fix 7+8 — DPoP jkt pinning grace fallback tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from mcp_proxy.models import InternalAgent


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")
    monkeypatch.setenv("MCP_PROXY_AGENT_CERT_GRACE_CLEANUP_ENABLED", "false")
    monkeypatch.delenv("PROXY_TRANSPORT_INTRA_ORG", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as _client:
        async with app.router.lifespan_context(app):
            yield app
    get_settings.cache_clear()


def _build_agent(*, dpop_jkt: str, previous_jkt: str | None, grace_expiry: str | None) -> InternalAgent:
    return InternalAgent(
        agent_id="acme::rotor-bot",
        display_name="rotor-bot",
        capabilities=[],
        created_at="2026-05-15T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt=dpop_jkt,
        reach="both",
        previous_dpop_jkt=previous_jkt,
        previous_grace_period_expires_at=grace_expiry,
    )


def _patch_dpop_chain(monkeypatch, *, fake_agent: InternalAgent, proof_jkt: str) -> None:
    from mcp_proxy.auth import dpop_client_cert
    import mcp_proxy.auth.api_token as _api_token_mod
    import mcp_proxy.auth.local_agent_dep as _lad
    import mcp_proxy.auth.dpop as _dpop_mod

    async def _noop_api_token(_req):
        return None

    async def _noop_local_agent(_req):
        return None

    async def _fake_cert(_req):
        return fake_agent

    async def _fake_verify(*_a, **_kw):
        return proof_jkt

    monkeypatch.setattr(_api_token_mod, "_maybe_api_token_principal", _noop_api_token)
    monkeypatch.setattr(_lad, "_maybe_local_internal_agent", _noop_local_agent)
    monkeypatch.setattr(dpop_client_cert, "get_agent_from_client_cert", _fake_cert)
    monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "optional")
    monkeypatch.setattr(_dpop_mod, "verify_dpop_proof", _fake_verify)


def _stub_request() -> MagicMock:
    req = MagicMock()
    req.method = "POST"
    req.headers = {"DPoP": "proof.proof.proof"}
    req.url = MagicMock()
    req.url.path = "/v1/llm/chat"
    return req


@pytest.mark.asyncio
async def test_dpop_grace_accepts_previous_jkt_during_window(monkeypatch, proxy_app):
    from mcp_proxy.auth import dpop_client_cert

    future = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    fake_agent = _build_agent(
        dpop_jkt="NEW" + "0" * 60,
        previous_jkt="OLD" + "0" * 60,
        grace_expiry=future,
    )
    _patch_dpop_chain(monkeypatch, fake_agent=fake_agent, proof_jkt="OLD" + "0" * 60)

    agent = await dpop_client_cert.get_agent_from_dpop_client_cert(_stub_request())
    assert agent.agent_id == "acme::rotor-bot"


@pytest.mark.asyncio
async def test_dpop_grace_rejects_after_expiry(monkeypatch, proxy_app):
    from mcp_proxy.auth import dpop_client_cert

    expired = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    fake_agent = _build_agent(
        dpop_jkt="NEW" + "0" * 60,
        previous_jkt="OLD" + "0" * 60,
        grace_expiry=expired,
    )
    _patch_dpop_chain(monkeypatch, fake_agent=fake_agent, proof_jkt="OLD" + "0" * 60)

    with pytest.raises(HTTPException) as excinfo:
        await dpop_client_cert.get_agent_from_dpop_client_cert(_stub_request())
    assert excinfo.value.status_code == 401
    assert "not registered" in str(excinfo.value.detail)


@pytest.mark.asyncio
async def test_dpop_grace_rejects_third_party_jkt(monkeypatch, proxy_app):
    from mcp_proxy.auth import dpop_client_cert

    future = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    fake_agent = _build_agent(
        dpop_jkt="NEW" + "0" * 60,
        previous_jkt="OLD" + "0" * 60,
        grace_expiry=future,
    )
    _patch_dpop_chain(monkeypatch, fake_agent=fake_agent, proof_jkt="FORGED" + "0" * 57)

    with pytest.raises(HTTPException) as excinfo:
        await dpop_client_cert.get_agent_from_dpop_client_cert(_stub_request())
    assert excinfo.value.status_code == 401


@pytest.mark.asyncio
async def test_dpop_no_previous_means_strict_mismatch(monkeypatch, proxy_app):
    from mcp_proxy.auth import dpop_client_cert

    fake_agent = _build_agent(
        dpop_jkt="NEW" + "0" * 60,
        previous_jkt=None,
        grace_expiry=None,
    )
    _patch_dpop_chain(monkeypatch, fake_agent=fake_agent, proof_jkt="OTHER" + "0" * 58)

    with pytest.raises(HTTPException) as excinfo:
        await dpop_client_cert.get_agent_from_dpop_client_cert(_stub_request())
    assert excinfo.value.status_code == 401
    assert "not registered" in str(excinfo.value.detail)


@pytest.mark.asyncio
async def test_dpop_current_jkt_match_is_unchanged(monkeypatch, proxy_app):
    from mcp_proxy.auth import dpop_client_cert

    future = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    fake_agent = _build_agent(
        dpop_jkt="NEW" + "0" * 60,
        previous_jkt="OLD" + "0" * 60,
        grace_expiry=future,
    )
    _patch_dpop_chain(monkeypatch, fake_agent=fake_agent, proof_jkt="NEW" + "0" * 60)

    agent = await dpop_client_cert.get_agent_from_dpop_client_cert(_stub_request())
    assert agent.agent_id == "acme::rotor-bot"
