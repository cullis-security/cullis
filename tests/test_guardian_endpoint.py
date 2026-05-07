"""ADR-016 Phase 1 — POST /v1/guardian/inspect contract.

The endpoint is exercised in isolation with the mTLS+DPoP dependency
overridden, the proxy DB initialized in a temp sqlite (so audit rows
land in ``local_audit``), and ``MCP_PROXY_GUARDIAN_TICKET_KEY`` set in
env. We assert the wire shape, the audit row, the failure modes (no
key configured, malformed payload), and that the issued ticket is
verifiable by the same key.
"""
from __future__ import annotations

import base64
import json

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.guardian.endpoint import router as guardian_router
from mcp_proxy.guardian.ticket import verify_ticket
from mcp_proxy.models import InternalAgent


_KEY_HEX = "00112233445566778899aabbccddeeff" * 2


def _agent() -> InternalAgent:
    return InternalAgent(
        agent_id="orga::alice",
        display_name="alice",
        capabilities=["a2a.send"],
        created_at="2026-05-07T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt="jkt-test",
        reach="both",
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _body(direction: str = "out") -> dict:
    return {
        "direction": direction,
        "peer_agent_id": "orgb::bob",
        "msg_id": "msg-test-1",
        "content_type": "application/json+a2a-payload",
        "payload_b64": _b64url(b'{"hello":"world"}'),
    }


@pytest_asyncio.fixture
async def app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.setenv("MCP_PROXY_GUARDIAN_TICKET_KEY", _KEY_HEX)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "orga")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    test_app = FastAPI()
    test_app.include_router(guardian_router)
    test_app.dependency_overrides[get_agent_from_dpop_client_cert] = _agent

    yield test_app

    test_app.dependency_overrides.clear()
    get_settings.cache_clear()
    await dispose_db()


@pytest.mark.asyncio
async def test_inspect_returns_pass_with_signed_ticket(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=_body())

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "pass"
    assert body["audit_id"]
    assert body["ticket"]
    assert body["ticket_exp"]
    assert body["redacted_payload_b64"] is None
    assert body["reasons"] == []

    claims = verify_ticket(key=_KEY_HEX, token=body["ticket"])
    assert claims["agent_id"] == "orga::alice"
    assert claims["peer_agent_id"] == "orgb::bob"
    assert claims["msg_id"] == "msg-test-1"
    assert claims["direction"] == "out"
    assert claims["decision"] == "pass"
    assert claims["audit_id"] == body["audit_id"]


@pytest.mark.asyncio
async def test_inspect_writes_audit_row(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=_body())

    body = r.json()
    async with get_db() as conn:
        rows = (await conn.execute(text(
            "SELECT agent_id, event_type, result, details FROM local_audit "
            "WHERE event_type = 'guardian.inspect'"
        ))).fetchall()
    assert len(rows) == 1
    row = dict(rows[0]._mapping)
    assert row["agent_id"] == "orga::alice"
    detail = json.loads(row["details"])
    assert detail["audit_id"] == body["audit_id"]
    assert detail["decision"] == "pass"
    assert detail["direction"] == "out"
    assert detail["peer_agent_id"] == "orgb::bob"
    assert detail["msg_id"] == "msg-test-1"
    assert detail["content_type"] == "application/json+a2a-payload"
    assert detail["phase"] == "fast_path"
    assert detail["tools_run"] == []


@pytest.mark.asyncio
async def test_inspect_rejects_missing_ticket_key(app, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_GUARDIAN_TICKET_KEY", "")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=_body())

    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "guardian_ticket_key_not_configured"


@pytest.mark.asyncio
async def test_inspect_rejects_malformed_payload_b64(app):
    body = _body()
    body["payload_b64"] = "###not-base64###"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=body)

    assert r.status_code == 422
    assert r.json()["detail"]["reason"] == "malformed_payload_b64"


@pytest.mark.asyncio
async def test_inspect_rejects_unknown_direction(app):
    body = _body()
    body["direction"] = "sideways"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=body)
    # FastAPI/pydantic Literal validator returns 422 with an error detail.
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_inspect_records_direction_in_audit(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r1 = await c.post("/v1/guardian/inspect", json=_body("out"))
        r2 = await c.post("/v1/guardian/inspect", json=_body("in"))
    assert r1.status_code == 200 and r2.status_code == 200

    async with get_db() as conn:
        rows = (await conn.execute(text(
            "SELECT details FROM local_audit "
            "WHERE event_type = 'guardian.inspect' "
            "ORDER BY chain_seq ASC"
        ))).fetchall()
    assert len(rows) == 2
    directions = [json.loads(r._mapping["details"])["direction"] for r in rows]
    assert directions == ["out", "in"]
