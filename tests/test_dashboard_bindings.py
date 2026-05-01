"""Tests for the network-admin /dashboard/bindings page (Court).

Covers list rendering + filters, approve, revoke, and scope edit (with
the subset-of-capabilities guard). Auth uses the same admin password
helper the rest of the dashboard suite uses.

The session-scope ``setup_db`` fixture never tears the schema down
between tests, so every test in this module uses a uuid suffix on
agent_ids to avoid UNIQUE(agent_id) collisions with the shared DB.
"""
from __future__ import annotations

import json
import uuid

import pytest
from httpx import AsyncClient

from app.config import get_settings
from tests.conftest import seed_court_agent


def _uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

pytestmark = pytest.mark.asyncio


def _extract_csrf(cookies: dict) -> str:
    cookie = cookies.get("cullis_session", "")
    if not cookie:
        return ""
    if cookie.startswith('"') and cookie.endswith('"'):
        cookie = cookie[1:-1]
    import codecs
    try:
        cookie = codecs.decode(cookie, "unicode_escape")
    except Exception:
        pass
    if "." not in cookie:
        return ""
    payload_str = cookie.rsplit(".", 1)[0]
    try:
        return json.loads(payload_str).get("csrf_token", "")
    except (json.JSONDecodeError, TypeError):
        return ""


async def _admin_ctx(client: AsyncClient) -> tuple[dict, str]:
    resp = await client.post(
        "/dashboard/login",
        data={"user_id": "admin", "password": get_settings().admin_secret},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    cookies = dict(resp.cookies)
    return cookies, _extract_csrf(cookies)


async def _make_binding(
    org_id: str,
    agent_id: str,
    scope: list[str],
    status: str = "pending",
) -> int:
    """Insert a binding directly via the store. Returns the new id."""
    from tests.conftest import TestSessionLocal
    from app.registry.binding_store import create_binding, approve_binding, revoke_binding

    async with TestSessionLocal() as session:
        b = await create_binding(session, org_id, agent_id, scope)
        if status == "approved":
            await approve_binding(session, b.id, approved_by="seed-helper")
        elif status == "revoked":
            await revoke_binding(session, b.id)
        return b.id


# ── list page ──────────────────────────────────────────────────────


async def test_bindings_page_renders_empty(client: AsyncClient):
    """Render check on a freshly-cleared bindings table.

    The session-scope ``setup_db`` fixture means earlier shards may have
    seeded rows that survive into this test. Truncate first so the
    'no bindings registered' empty state is what we actually render.
    """
    from sqlalchemy import delete
    from app.registry.binding_store import BindingRecord
    from tests.conftest import TestSessionLocal
    async with TestSessionLocal() as s:
        await s.execute(delete(BindingRecord))
        await s.commit()

    cookies, _ = await _admin_ctx(client)
    resp = await client.get("/dashboard/bindings", cookies=cookies)
    assert resp.status_code == 200
    assert "Bindings" in resp.text
    assert "No bindings registered" in resp.text


async def test_bindings_page_lists_seeded_rows(client: AsyncClient):
    aid = _uniq("orga::agent")
    await seed_court_agent(aid, "orga", capabilities=["order.read", "order.write"])
    bid = await _make_binding(
        org_id="orgb", agent_id=aid,
        scope=["order.read"], status="approved",
    )
    cookies, _ = await _admin_ctx(client)
    resp = await client.get("/dashboard/bindings", cookies=cookies)
    assert resp.status_code == 200
    assert aid in resp.text
    assert "order.read" in resp.text
    assert "Approved" in resp.text
    assert f"#{bid}" in resp.text


async def test_bindings_filter_by_status(client: AsyncClient):
    approved_aid = _uniq("orga::agent-app")
    pending_aid = _uniq("orga::agent-pen")
    await seed_court_agent(approved_aid, "orga", capabilities=["x.y"])
    await _make_binding("orgb", approved_aid, ["x.y"], status="approved")
    await seed_court_agent(pending_aid, "orga", capabilities=["x.y"])
    await _make_binding("orgb", pending_aid, ["x.y"], status="pending")

    cookies, _ = await _admin_ctx(client)
    resp = await client.get(
        "/dashboard/bindings?status_filter=pending", cookies=cookies,
    )
    assert resp.status_code == 200
    assert pending_aid in resp.text
    assert approved_aid not in resp.text


# ── approve ────────────────────────────────────────────────────────


async def test_approve_pending_binding(client: AsyncClient):
    aid = _uniq("orga::agent")
    await seed_court_agent(aid, "orga", capabilities=["x.y"])
    bid = await _make_binding("orgb", aid, ["x.y"], status="pending")

    cookies, csrf = await _admin_ctx(client)
    resp = await client.post(
        f"/dashboard/bindings/{bid}/approve",
        data={"csrf_token": csrf},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from tests.conftest import TestSessionLocal
    from app.registry.binding_store import get_binding
    async with TestSessionLocal() as s:
        b = await get_binding(s, bid)
        assert b.status == "approved"
        assert b.approved_by == "dashboard-network-admin"


async def test_approve_requires_csrf(client: AsyncClient):
    aid = _uniq("orga::agent")
    await seed_court_agent(aid, "orga", capabilities=["x.y"])
    bid = await _make_binding("orgb", aid, ["x.y"], status="pending")

    cookies, _ = await _admin_ctx(client)
    resp = await client.post(
        f"/dashboard/bindings/{bid}/approve",
        data={"csrf_token": "wrong"},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_approve_unknown_binding_404(client: AsyncClient):
    cookies, csrf = await _admin_ctx(client)
    resp = await client.post(
        "/dashboard/bindings/99999/approve",
        data={"csrf_token": csrf},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 404


# ── revoke ─────────────────────────────────────────────────────────


async def test_revoke_approved_binding(client: AsyncClient):
    aid = _uniq("orga::agent")
    await seed_court_agent(aid, "orga", capabilities=["x.y"])
    bid = await _make_binding("orgb", aid, ["x.y"], status="approved")

    cookies, csrf = await _admin_ctx(client)
    resp = await client.post(
        f"/dashboard/bindings/{bid}/revoke",
        data={"csrf_token": csrf},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from tests.conftest import TestSessionLocal
    from app.registry.binding_store import get_binding
    async with TestSessionLocal() as s:
        b = await get_binding(s, bid)
        assert b.status == "revoked"


# ── scope edit ─────────────────────────────────────────────────────


async def test_scope_edit_subset_succeeds(client: AsyncClient):
    aid = _uniq("orga::agent")
    await seed_court_agent(
        aid, "orga",
        capabilities=["order.read", "order.write", "order.delete"],
    )
    bid = await _make_binding(
        "orgb", aid,
        scope=["order.read", "order.write"], status="approved",
    )

    cookies, csrf = await _admin_ctx(client)
    resp = await client.post(
        f"/dashboard/bindings/{bid}/scope",
        data={"csrf_token": csrf, "scope": ["order.read"]},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from tests.conftest import TestSessionLocal
    from app.registry.binding_store import get_binding
    async with TestSessionLocal() as s:
        b = await get_binding(s, bid)
        assert b.scope == ["order.read"]


async def test_scope_edit_rejects_non_subset(client: AsyncClient):
    """Trying to grant a capability the agent never declared is 400."""
    aid = _uniq("orga::agent")
    await seed_court_agent(aid, "orga", capabilities=["order.read"])
    bid = await _make_binding(
        "orgb", aid, scope=["order.read"], status="approved",
    )

    cookies, csrf = await _admin_ctx(client)
    resp = await client.post(
        f"/dashboard/bindings/{bid}/scope",
        data={"csrf_token": csrf, "scope": ["order.read", "order.delete"]},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "order.delete" in resp.json()["detail"]


async def test_scope_edit_to_empty(client: AsyncClient):
    """An empty scope is legal — the binding stays but the agent loses
    every concession until the operator re-approves a real scope."""
    aid = _uniq("orga::agent")
    await seed_court_agent(aid, "orga", capabilities=["order.read"])
    bid = await _make_binding(
        "orgb", aid, scope=["order.read"], status="approved",
    )
    cookies, csrf = await _admin_ctx(client)
    resp = await client.post(
        f"/dashboard/bindings/{bid}/scope",
        data={"csrf_token": csrf},
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from tests.conftest import TestSessionLocal
    from app.registry.binding_store import get_binding
    async with TestSessionLocal() as s:
        b = await get_binding(s, bid)
        assert b.scope == []


# ── auth gate ─────────────────────────────────────────────────────


async def test_unauthenticated_redirects_to_login(client: AsyncClient):
    resp = await client.get("/dashboard/bindings", follow_redirects=False)
    assert resp.status_code == 303
    assert "/dashboard/login" in resp.headers.get("location", "")
