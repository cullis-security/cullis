"""ADR-016 Phase 2 — fast-path tool dispatch + slow-path hook.

Phase 1 tests cover the empty-registry path (endpoint returns pass).
This file covers the case the registry has tools and the endpoint
runs them. Tools are registered locally per test via ``register_tool``
+ a fixture that clears the registry on teardown so tests don't leak
state into each other.
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
from mcp_proxy.guardian import (
    SlowPathPayload,
    Tool,
    ToolResult,
    register_tool,
    set_slow_path_hook,
)
from mcp_proxy.guardian.endpoint import router as guardian_router
from mcp_proxy.guardian.registry import clear_registry
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


def _body(direction: str = "out", payload: bytes = b'{"hello":"world"}') -> dict:
    return {
        "direction": direction,
        "peer_agent_id": "orgb::bob",
        "msg_id": "msg-fastpath-1",
        "content_type": "application/json+a2a-payload",
        "payload_b64": _b64url(payload),
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
    clear_registry()
    set_slow_path_hook(None)
    await dispose_db()


# ── Stub tools ─────────────────────────────────────────────────────


class _BlockOnSubstr(Tool):
    name = "block_on_substr"
    direction = "out"

    def __init__(self, substr: str):
        self._substr = substr

    async def evaluate(self, payload: bytes, ctx) -> ToolResult:
        if self._substr.encode() in payload:
            return ToolResult(
                decision="block",
                reasons=[{"tool": self.name, "match": self._substr}],
            )
        return ToolResult(decision="pass")


class _RedactSubstr(Tool):
    name = "redact_substr"
    direction = "out"

    def __init__(self, substr: str):
        self._substr = substr

    async def evaluate(self, payload: bytes, ctx) -> ToolResult:
        if self._substr.encode() not in payload:
            return ToolResult(decision="pass")
        redacted = payload.replace(
            self._substr.encode(), b"[REDACTED]",
        )
        return ToolResult(
            decision="redact",
            redacted_payload=redacted,
            reasons=[{"tool": self.name, "match": self._substr}],
        )


class _AlwaysRaise(Tool):
    name = "always_raise"
    direction = "out"

    async def evaluate(self, payload: bytes, ctx) -> ToolResult:
        raise RuntimeError("synthetic tool failure")


# ── Tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_tool_short_circuits_decision(app):
    register_tool(_BlockOnSubstr("AKIA"))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/guardian/inspect",
            json=_body(payload=b"please leak AKIAEXAMPLE now"),
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "block"
    assert body["redacted_payload_b64"] is None
    # reasons surfaced from the firing tool
    assert any(r["tool"] == "block_on_substr" for r in body["reasons"])


@pytest.mark.asyncio
async def test_redact_tool_returns_redacted_payload(app):
    register_tool(_RedactSubstr("4242"))

    payload = b'{"card":"4242 4242 4242 4242"}'
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=_body(payload=payload))

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "redact"
    assert body["redacted_payload_b64"]
    decoded = base64.urlsafe_b64decode(
        body["redacted_payload_b64"]
        + "=" * (-len(body["redacted_payload_b64"]) % 4),
    )
    # 4 occurrences of "4242" each replaced with [REDACTED]
    assert decoded.count(b"[REDACTED]") == 4
    assert b"4242" not in decoded


@pytest.mark.asyncio
async def test_block_wins_over_redact_when_both_fire(app):
    """Worst-decision-wins: block strictness > redact > pass. The
    redaction is also dropped from the response so a block result
    never carries 'almost OK' bytes downstream."""
    register_tool(_RedactSubstr("4242"))
    # Block must register AFTER redact so we test ordering invariance.
    register_tool(_BlockOnSubstr("AKIA"))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/guardian/inspect",
            json=_body(payload=b"4242 4242 / AKIAEXAMPLE"),
        )

    body = r.json()
    assert body["decision"] == "block"
    assert body["redacted_payload_b64"] is None


@pytest.mark.asyncio
async def test_tool_exception_recorded_not_propagated(app):
    """A broken tool must not break the endpoint. The exception is
    surfaced as a reason so operators see the gap in the audit row,
    but the response is otherwise computed from the surviving tools."""
    register_tool(_AlwaysRaise())
    register_tool(_BlockOnSubstr("AKIA"))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/guardian/inspect",
            json=_body(payload=b"AKIAEXAMPLE"),
        )

    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "block"
    reason_tools = [r["tool"] for r in body["reasons"]]
    assert "always_raise" in reason_tools
    assert "block_on_substr" in reason_tools


@pytest.mark.asyncio
async def test_slow_path_hook_called_with_inspect_payload(app):
    """When set_slow_path_hook is registered, the endpoint enqueues
    after the fast-path response is computed. The hook receives the
    audit_id + direction + payload."""
    captured: list[SlowPathPayload] = []

    def hook(task: SlowPathPayload) -> bool:
        captured.append(task)
        return True

    set_slow_path_hook(hook)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=_body())

    assert r.status_code == 200
    assert len(captured) == 1
    assert captured[0].audit_id == r.json()["audit_id"]
    assert captured[0].direction == "out"
    assert captured[0].peer_agent_id == "orgb::bob"
    assert captured[0].payload == b'{"hello":"world"}'


@pytest.mark.asyncio
async def test_slow_path_hook_returning_false_does_not_break_response(app):
    """Queue full / dropped task is best-effort: response still 200."""
    set_slow_path_hook(lambda task: False)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        r = await c.post("/v1/guardian/inspect", json=_body())

    assert r.status_code == 200
    assert r.json()["decision"] == "pass"


@pytest.mark.asyncio
async def test_slow_path_receives_redacted_payload_when_redact(app):
    """When fast-path redacted the payload, the slow-path sees the
    sanitized form. Slow-path judges should never see raw PII when
    the synchronous tools already redacted it."""
    register_tool(_RedactSubstr("4242"))
    captured: list[SlowPathPayload] = []
    set_slow_path_hook(lambda task: (captured.append(task) or True))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        await c.post(
            "/v1/guardian/inspect",
            json=_body(payload=b"see 4242 here"),
        )

    assert len(captured) == 1
    assert b"4242" not in captured[0].payload
    assert b"[REDACTED]" in captured[0].payload


@pytest.mark.asyncio
async def test_audit_row_carries_tools_run_list(app):
    register_tool(_BlockOnSubstr("AKIA"))
    register_tool(_RedactSubstr("4242"))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        await c.post(
            "/v1/guardian/inspect",
            json=_body(payload=b"clean payload"),
        )

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT details FROM local_audit WHERE event_type = 'guardian.inspect'"
        ))).fetchone()
    detail = json.loads(row._mapping["details"])
    assert detail["phase"] == "fast_path"
    assert sorted(detail["tools_run"]) == ["block_on_substr", "redact_substr"]
