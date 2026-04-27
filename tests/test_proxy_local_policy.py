"""ADR-006 Fase 1 / PR #2 — intra-org policy evaluation at the proxy.

Covers the policy engine in isolation plus its wiring into
POST /v1/egress/send when a local session matches the message.
Rule format mirrors the broker's message-policy schema so a JSON rule
authored once can be re-used on either side.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.policy.local_eval import evaluate_local_message

from tests._mtls_helpers import provision_internal_agent


@pytest_asyncio.fixture
async def fresh_db(tmp_path):
    db_file = tmp_path / "policy.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    yield
    await dispose_db()


async def _insert_policy(
    policy_id: str,
    org_id: str,
    rules: dict,
    *,
    policy_type: str = "message",
    enabled: int = 1,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_policies (
                    policy_id, org_id, policy_type, name, scope,
                    rules_json, enabled, created_at, updated_at
                ) VALUES (
                    :pid, :org, :ptype, :name, 'intra',
                    :rules, :enabled, '2026-04-16T00:00:00Z', '2026-04-16T00:00:00Z'
                )
                """
            ),
            {
                "pid": policy_id,
                "org": org_id,
                "ptype": policy_type,
                "name": policy_id,
                "rules": json.dumps(rules),
                "enabled": enabled,
            },
        )


# ── unit: evaluate_local_message ────────────────────────────────────

@pytest.mark.asyncio
async def test_no_policies_defaults_to_allow(fresh_db):
    verdict = await evaluate_local_message(org_id="acme", payload={"x": 1})
    assert verdict.allowed is True
    assert "default allow" in verdict.reason


@pytest.mark.asyncio
async def test_max_payload_size_denies(fresh_db):
    await _insert_policy(
        "p1", "acme",
        {"effect": "allow", "conditions": {"max_payload_size_bytes": 5}},
    )
    verdict = await evaluate_local_message(org_id="acme", payload={"very": "long"})
    assert verdict.allowed is False
    assert "too large" in verdict.reason
    assert verdict.policy_id == "p1"


@pytest.mark.asyncio
async def test_required_fields_denies_when_missing(fresh_db):
    await _insert_policy(
        "p_req", "acme",
        {"effect": "allow", "conditions": {"required_fields": ["user_id"]}},
    )
    verdict = await evaluate_local_message(org_id="acme", payload={"x": 1})
    assert verdict.allowed is False
    assert "required fields missing" in verdict.reason


@pytest.mark.asyncio
async def test_blocked_fields_denies(fresh_db):
    await _insert_policy(
        "p_blk", "acme",
        {"effect": "allow", "conditions": {"blocked_fields": ["admin_override"]}},
    )
    verdict = await evaluate_local_message(
        org_id="acme", payload={"user_id": "u1", "admin_override": True},
    )
    assert verdict.allowed is False
    assert "blocked fields" in verdict.reason


@pytest.mark.asyncio
async def test_disabled_policies_skipped(fresh_db):
    await _insert_policy(
        "p_off", "acme",
        {"effect": "deny", "conditions": {}},
        enabled=0,
    )
    verdict = await evaluate_local_message(org_id="acme", payload={})
    assert verdict.allowed is True


@pytest.mark.asyncio
async def test_other_org_policies_ignored(fresh_db):
    await _insert_policy(
        "p_other", "contoso",
        {"effect": "deny", "conditions": {}},
    )
    verdict = await evaluate_local_message(org_id="acme", payload={})
    assert verdict.allowed is True


@pytest.mark.asyncio
async def test_org_null_policy_applies_to_any_org(fresh_db):
    """NULL org_id acts as a global default rule — useful for baseline
    guardrails that should bite regardless of org_id config."""
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_policies (
                    policy_id, org_id, policy_type, name, scope,
                    rules_json, enabled, created_at, updated_at
                ) VALUES (
                    'global', NULL, 'message', 'global', 'intra',
                    :rules, 1, '2026-04-16T00:00:00Z', '2026-04-16T00:00:00Z'
                )
                """
            ),
            {"rules": json.dumps(
                {"effect": "deny", "conditions": {"blocked_fields": ["secret"]}}
            )},
        )
    verdict = await evaluate_local_message(org_id="acme", payload={"secret": "x"})
    assert verdict.allowed is False


# ── integration: wired into /v1/egress/send ─────────────────────────

@pytest_asyncio.fixture
async def standalone_proxy(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("PROXY_INTRA_ORG", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_JWKS_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield app, client
    get_settings.cache_clear()


async def _provision_agent(agent_id: str) -> dict[str, str]:
    """Provision via the mTLS helper and return nginx-shaped headers."""
    return await provision_internal_agent(agent_id, capabilities=["cap.read"])


@pytest.mark.asyncio
async def test_send_blocked_by_policy_returns_403_and_logs_denial(standalone_proxy):
    app, client = standalone_proxy
    alice_headers = await _provision_agent("alice-bot")
    bob_headers = await _provision_agent("bob-bot")

    # Install a policy that blocks payloads carrying "admin_override".
    await _insert_policy(
        "p_guardrail", "acme",
        {"effect": "allow", "conditions": {"blocked_fields": ["admin_override"]}},
    )

    # Open + accept a session so send reaches the local path.
    open_resp = await client.post(
        "/v1/egress/sessions",
        headers=alice_headers,
        json={"target_agent_id": "acme::bob-bot", "target_org_id": "acme", "capabilities": []},
    )
    session_id = open_resp.json()["session_id"]
    await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers=bob_headers,
    )

    # Forbidden payload
    send = await client.post(
        "/v1/egress/send",
        headers=alice_headers,
        json={
            "session_id": session_id,
            "payload": {"hello": "bob", "admin_override": True},
            "recipient_agent_id": "acme::bob-bot",
            "mode": "envelope",
        },
    )
    assert send.status_code == 403, send.text
    body = send.json()["detail"]
    assert body["error"] == "policy_denied"
    assert body["policy_id"] == "p_guardrail"

    # Allowed payload goes through.
    allowed = await client.post(
        "/v1/egress/send",
        headers=alice_headers,
        json={
            "session_id": session_id,
            "payload": {"hello": "bob"},
            "recipient_agent_id": "acme::bob-bot",
            "mode": "envelope",
        },
    )
    assert allowed.status_code == 200, allowed.text

    # The denial and the successful send both show up in local_audit.
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT event_type FROM local_audit "
                "WHERE org_id = 'acme' ORDER BY chain_seq ASC"
            )
        )).all()
    kinds = [r[0] for r in rows]
    assert "message_denied" in kinds
    assert "message_sent" in kinds
    assert kinds.count("session_opened") == 1
    assert kinds.count("session_accepted") == 1


@pytest.mark.asyncio
async def test_local_audit_chain_integrity_after_full_roundtrip(standalone_proxy):
    _, client = standalone_proxy
    alice_headers = await _provision_agent("alice-bot")
    bob_headers = await _provision_agent("bob-bot")

    open_resp = await client.post(
        "/v1/egress/sessions",
        headers=alice_headers,
        json={"target_agent_id": "acme::bob-bot", "target_org_id": "acme", "capabilities": []},
    )
    session_id = open_resp.json()["session_id"]
    await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers=bob_headers,
    )
    send = await client.post(
        "/v1/egress/send",
        headers=alice_headers,
        json={
            "session_id": session_id,
            "payload": {"hi": 1},
            "recipient_agent_id": "acme::bob-bot",
            "mode": "envelope",
        },
    )
    msg_id = send.json()["msg_id"]
    await client.post(
        f"/v1/egress/sessions/{session_id}/messages/{msg_id}/ack",
        headers=bob_headers,
    )
    await client.post(
        f"/v1/egress/sessions/{session_id}/close",
        headers=alice_headers,
    )

    from mcp_proxy.local.audit import verify_local_chain
    ok, reason = await verify_local_chain("acme")
    assert ok is True, reason


@pytest.mark.asyncio
async def test_default_allow_when_no_policies(standalone_proxy):
    _, client = standalone_proxy
    alice_headers = await _provision_agent("alice-bot")
    bob_headers = await _provision_agent("bob-bot")

    # No policies inserted — send must succeed.
    open_resp = await client.post(
        "/v1/egress/sessions",
        headers=alice_headers,
        json={"target_agent_id": "acme::bob-bot", "target_org_id": "acme", "capabilities": []},
    )
    session_id = open_resp.json()["session_id"]
    await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers=bob_headers,
    )
    send = await client.post(
        "/v1/egress/send",
        headers=alice_headers,
        json={
            "session_id": session_id,
            "payload": {"x": "y"},
            "recipient_agent_id": "acme::bob-bot",
            "mode": "envelope",
        },
    )
    assert send.status_code == 200, send.text
