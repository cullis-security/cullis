"""ADR-029 Phase C, tool-level PDP gate endpoint tests.

Endpoint: ``POST /v1/policy/tool-call``

Pins the contract:

- The endpoint is gated by ``MCP_PROXY_TOOL_PDP_ENABLED``: 404 when
  off, 200 with a decision when on.
- Legacy default-allow mode: no ``policy_rules.tool_rules`` configured
  means every tool call is allowed (existing Mastios keep working).
- Explicit-allow mode: as soon as ``tool_rules`` is non-empty, a tool
  that is not listed in tool_rules is denied.
- Per-tool principal allowlist / denylist works, denylist wins.
- Per-tool model allowlist works.
- Optional scope / rate_limit / obligations on the rule are echoed
  through the decision response.
- Every call (allow + deny) writes an ``policy.tool_call`` audit row
  in the hash-chained audit_log.
- HMAC signature enforced when ``MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET``
  is set, same shape as ``/pdp/policy``.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "tool_pdp.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "")  # off by default
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def proxy_app_pdp_off(tmp_path, monkeypatch):
    """Same proxy fixture but with the feature flag OFF, to verify
    the 404 behaviour."""
    db_file = tmp_path / "tool_pdp_off.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_ENABLED", "false")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


def _payload(
    *,
    principal_id: str = "acme::user::mario@acme.local",
    tool_name: str = "acme.catalog.search",
    model_id: str = "claude-haiku-4-5",
    server_id: str = "acme-catalog-prod",
):
    return {
        "principal": {
            "id": principal_id,
            "type": "user",
            "org": "acme",
        },
        "model": {"id": model_id, "provider": "anthropic"},
        "target": {"id": "acme::workload::catalog-mcp", "type": "workload", "org": "acme"},
        "invocation": {
            "kind": "session_tool_call",
            "tool_name": tool_name,
            "mcp_server_id": server_id,
        },
        "context": {"session_id": "s_test"},
    }


async def _set_tool_rules(rules: dict) -> None:
    from mcp_proxy.db import set_config
    await set_config("policy_rules", json.dumps({"tool_rules": rules}))


# ── Feature flag gate ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_returns_404_when_feature_flag_off(proxy_app_pdp_off):
    _, client = proxy_app_pdp_off
    resp = await client.post("/v1/policy/tool-call", json=_payload())
    assert resp.status_code == 404


# ── Legacy default-allow ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_allow_when_tool_rules_empty(proxy_app):
    _, client = proxy_app
    # No policy_rules in DB at all.
    resp = await client.post("/v1/policy/tool-call", json=_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert "legacy" in body["reason"].lower()


# ── Explicit-allow mode ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deny_when_tool_not_in_tool_rules(proxy_app):
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })
    p = _payload(tool_name="acme.catalog.update")
    resp = await client.post("/v1/policy/tool-call", json=p)
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "acme.catalog.update" in body["reason"]


@pytest.mark.asyncio
async def test_allow_when_principal_in_allowlist(proxy_app):
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
            "allowed_models": ["claude-haiku-4-5"],
        }
    })
    resp = await client.post("/v1/policy/tool-call", json=_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"


@pytest.mark.asyncio
async def test_deny_when_principal_in_denylist(proxy_app):
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": [
                "acme::user::mario@acme.local",
                "acme::user::anna@acme.local",
            ],
            "denied_principals": ["acme::user::anna@acme.local"],
        }
    })
    p = _payload(principal_id="acme::user::anna@acme.local")
    resp = await client.post("/v1/policy/tool-call", json=p)
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "denied_principals" in body["reason"]


@pytest.mark.asyncio
async def test_deny_when_model_not_in_allowed_models(proxy_app):
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
            "allowed_models": ["qwen-72b-chat"],
        }
    })
    resp = await client.post("/v1/policy/tool-call", json=_payload(model_id="claude-haiku-4-5"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "allowed_models" in body["reason"]


@pytest.mark.asyncio
async def test_deny_when_mcp_server_not_in_allowed(proxy_app):
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
            "allowed_mcp_servers": ["other-postgres"],
        }
    })
    resp = await client.post("/v1/policy/tool-call", json=_payload(server_id="acme-catalog-prod"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "allowed_mcp_servers" in body["reason"]


@pytest.mark.asyncio
async def test_scope_rate_limit_obligations_echoed_on_allow(proxy_app):
    """When a tool_rule carries scope/rate_limit/obligations the
    decision response carries them through to the caller."""
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
            "scope": {
                "tools_allowed": ["acme.catalog.search", "acme.catalog.list"],
                "max_session_duration_s": 1800,
            },
            "rate_limit": {"per_minute": 60},
            "obligations": {"trace_visibility": "redacted"},
        }
    })
    resp = await client.post("/v1/policy/tool-call", json=_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["scope"]["tools_allowed"] == ["acme.catalog.search", "acme.catalog.list"]
    assert body["scope"]["max_session_duration_s"] == 1800
    assert body["rate_limit"]["per_minute"] == 60
    assert body["obligations"]["trace_visibility"] == "redacted"


# ── Audit row ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_row_written_on_allow_and_deny(proxy_app):
    """Every decision lands in audit_log with action=policy.tool_call,
    status=allow|deny, tool_name set, principal id in agent_id."""
    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
            "denied_principals": ["acme::user::anna@acme.local"],
        }
    })

    # 1) allow
    await client.post("/v1/policy/tool-call", json=_payload(
        principal_id="acme::user::mario@acme.local",
    ))
    # 2) deny
    await client.post("/v1/policy/tool-call", json=_payload(
        principal_id="acme::user::anna@acme.local",
    ))

    # Read audit_log rows back.
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        result = await conn.execute(text(
            "SELECT agent_id, action, status, tool_name "
            "FROM audit_log WHERE action = 'policy.tool_call' "
            "ORDER BY chain_seq ASC"
        ))
        rows = result.fetchall()

    statuses = {r.agent_id: r.status for r in rows}
    assert statuses.get("acme::user::mario@acme.local") == "allow"
    assert statuses.get("acme::user::anna@acme.local") == "deny"
    for r in rows:
        assert r.tool_name == "acme.catalog.search"


# ── HMAC signature gate ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hmac_required_when_secret_set(tmp_path, monkeypatch):
    """When the proxy has MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET set, the
    tool-call endpoint mirrors /pdp/policy: 401 without a valid
    X-ATN-Signature, 200 with one."""
    db_file = tmp_path / "tool_pdp_hmac.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "shared-secret-xyz")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            body = json.dumps(_payload()).encode()

            # No signature: 401.
            r1 = await client.post(
                "/v1/policy/tool-call",
                content=body,
                headers={"content-type": "application/json"},
            )
            assert r1.status_code == 401

            # Wrong signature: 401.
            r2 = await client.post(
                "/v1/policy/tool-call",
                content=body,
                headers={"content-type": "application/json", "x-atn-signature": "00" * 32},
            )
            assert r2.status_code == 401

            # Valid signature: 200.
            sig = hmac.new(b"shared-secret-xyz", body, hashlib.sha256).hexdigest()
            r3 = await client.post(
                "/v1/policy/tool-call",
                content=body,
                headers={"content-type": "application/json", "x-atn-signature": sig},
            )
            assert r3.status_code == 200
    get_settings.cache_clear()
