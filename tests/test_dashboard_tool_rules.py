"""ADR-029 Phase E, dashboard authoring for tool-level PDP rules.

Covers the structured form-based UI that supersedes hand-editing the
``policy_rules.tool_rules`` subtree in the JSON editor. The router
sits at ``/proxy/policies/tool-rules`` and persists into the same
``policy_rules`` config row that the Phase C ``/v1/policy/tool-call``
endpoint reads, so a rule added here is enforced immediately by the
existing gate.
"""
from __future__ import annotations

import json
import re

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_logged_in(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-password-1234")
            await client.post(
                "/proxy/login",
                data={"password": "test-password-1234"},
                follow_redirects=False,
            )
            yield client
    get_settings.cache_clear()


async def _csrf(client) -> str:
    page = await client.get("/proxy/policies/tool-rules")
    assert page.status_code == 200, page.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token not found on page"
    return m.group(1)


@pytest.mark.asyncio
async def test_list_renders_empty_state(proxy_logged_in):
    page = await proxy_logged_in.get("/proxy/policies/tool-rules")
    assert page.status_code == 200
    assert "ADR-029 tool-level PDP" in page.text
    assert "No tool rules configured" in page.text


@pytest.mark.asyncio
async def test_save_upserts_and_lists_rule(proxy_logged_in):
    csrf = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={
            "csrf_token": csrf,
            "tool_name": "acme.catalog.search",
            "allowed_principals":
                "acme::user::mario@acme.local, acme::user::anna@acme.local",
            "allowed_models": "claude-haiku-4-5",
            "allowed_mcp_servers": "acme-catalog-prod",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    # The same /v1/policy/tool-call gate will read this back; verify the
    # JSON document was merged correctly.
    from mcp_proxy.db import get_config
    raw = await get_config("policy_rules")
    doc = json.loads(raw)
    assert "tool_rules" in doc
    rule = doc["tool_rules"]["acme.catalog.search"]
    assert rule["allowed_principals"] == [
        "acme::user::mario@acme.local",
        "acme::user::anna@acme.local",
    ]
    assert rule["allowed_models"] == ["claude-haiku-4-5"]
    assert rule["allowed_mcp_servers"] == ["acme-catalog-prod"]

    page = await proxy_logged_in.get("/proxy/policies/tool-rules")
    assert "acme.catalog.search" in page.text
    assert "mario@acme.local" in page.text


@pytest.mark.asyncio
async def test_save_overwrites_existing_rule(proxy_logged_in):
    csrf = await _csrf(proxy_logged_in)
    # First write
    await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={
            "csrf_token": csrf,
            "tool_name": "acme.catalog.search",
            "allowed_principals": "acme::user::mario@acme.local",
        },
        follow_redirects=False,
    )
    # Overwrite with denied_principals only
    csrf2 = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={
            "csrf_token": csrf2,
            "tool_name": "acme.catalog.search",
            "denied_principals": "acme::user::contractor@acme.local",
        },
        follow_redirects=False,
    )

    from mcp_proxy.db import get_config
    doc = json.loads(await get_config("policy_rules"))
    rule = doc["tool_rules"]["acme.catalog.search"]
    assert "allowed_principals" not in rule
    assert rule["denied_principals"] == ["acme::user::contractor@acme.local"]


@pytest.mark.asyncio
async def test_delete_removes_rule(proxy_logged_in):
    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={
            "csrf_token": csrf,
            "tool_name": "acme.catalog.search",
            "allowed_principals": "acme::user::mario@acme.local",
        },
        follow_redirects=False,
    )

    csrf2 = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        "/proxy/policies/tool-rules/acme.catalog.search/delete",
        data={"csrf_token": csrf2},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_config
    doc = json.loads(await get_config("policy_rules"))
    assert "acme.catalog.search" not in doc.get("tool_rules", {})


@pytest.mark.asyncio
async def test_csrf_required_on_save(proxy_logged_in):
    resp = await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={
            "csrf_token": "wrong-token",
            "tool_name": "acme.catalog.search",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_save_rejects_empty_tool_name(proxy_logged_in):
    csrf = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={"csrf_token": csrf, "tool_name": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_round_trip_via_phase_c_endpoint(proxy_logged_in, monkeypatch):
    """End-to-end: dashboard saves a rule, /v1/policy/tool-call enforces
    it on the next call. Bridges Phase E (authoring) and Phase C
    (enforcement) in a single test."""
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_ENABLED", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/policies/tool-rules/save",
        data={
            "csrf_token": csrf,
            "tool_name": "acme.catalog.search",
            "allowed_principals": "acme::user::mario@acme.local",
        },
        follow_redirects=False,
    )

    # Mario gets allow.
    r_allow = await proxy_logged_in.post("/v1/policy/tool-call", json={
        "principal": {"id": "acme::user::mario@acme.local", "type": "user"},
        "model": {"id": "claude-haiku-4-5"},
        "target": {"id": "acme::workload::catalog", "type": "workload", "org": "acme"},
        "invocation": {"kind": "session_tool_call", "tool_name": "acme.catalog.search"},
    })
    assert r_allow.status_code == 200
    assert r_allow.json()["decision"] == "allow"

    # Anna gets deny (not in allowed_principals).
    r_deny = await proxy_logged_in.post("/v1/policy/tool-call", json={
        "principal": {"id": "acme::user::anna@acme.local", "type": "user"},
        "model": {"id": "claude-haiku-4-5"},
        "target": {"id": "acme::workload::catalog", "type": "workload", "org": "acme"},
        "invocation": {"kind": "session_tool_call", "tool_name": "acme.catalog.search"},
    })
    assert r_deny.status_code == 200
    assert r_deny.json()["decision"] == "deny"
