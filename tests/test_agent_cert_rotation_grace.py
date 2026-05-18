"""Wave 2 fix 7+8 — agent leaf cert rotation grace period tests.

Validates the four phases end-to-end:

1. Schema: new ``previous_*`` columns are nullable + indexable.
2. Pinning fallback: ``get_agent_from_client_cert`` accepts the
   previous cert during an active grace window, rejects after expiry,
   rejects when the cert matches neither.
3. Cleanup sweep: ``agent_cert_grace_cleanup._sweep_once`` clears
   expired rows back to NULL and emits one audit row per agent.
4. Helper coverage: ``cert_grace.is_grace_active`` /
   ``compute_grace_expiry`` / ``cert_thumbprint_hex`` edge cases.

Tests hit the FastAPI ASGI app directly via ``ASGITransport`` (same
pattern as ``test_client_cert_auth.py``); nginx is synthesized by
``tests._mtls_helpers.mtls_headers``.
"""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from tests._mtls_helpers import (
    mint_agent_cert,
    mtls_headers,
    provision_internal_agent,
)


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
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _set_grace_columns(
    *,
    agent_id: str,
    previous_cert_pem: str | None,
    previous_dpop_jkt: str | None,
    grace_expiry_iso: str | None,
) -> None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE internal_agents "
                "  SET previous_cert_pem = :pcp, "
                "      previous_dpop_jkt = :pjk, "
                "      previous_grace_period_expires_at = :pge "
                "WHERE agent_id = :aid"
            ),
            {
                "pcp": previous_cert_pem,
                "pjk": previous_dpop_jkt,
                "pge": grace_expiry_iso,
                "aid": agent_id,
            },
        )


async def _swap_current_cert(*, agent_id: str, cert_pem: str) -> None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE internal_agents SET cert_pem = :cert WHERE agent_id = :aid"
            ),
            {"cert": cert_pem, "aid": agent_id},
        )


async def _read_audit_rows(*, action: str, agent_id: str) -> list[dict]:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT timestamp, action, status, detail FROM audit_log "
                " WHERE action = :action AND agent_id = :aid "
                " ORDER BY id DESC"
            ),
            {"action": action, "aid": agent_id},
        )).mappings().all()
    return [dict(r) for r in rows]


@pytest.mark.asyncio
async def test_cert_pin_falls_back_to_previous_during_grace(proxy_app):
    _, client = proxy_app
    old_headers = await provision_internal_agent("rotor-bot")
    new_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="rotor-bot")
    old_cert_pem = urllib.parse.unquote(old_headers["X-SSL-Client-Cert"])

    await _swap_current_cert(agent_id="acme::rotor-bot", cert_pem=new_cert_pem)
    grace_expiry = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    await _set_grace_columns(
        agent_id="acme::rotor-bot",
        previous_cert_pem=old_cert_pem,
        previous_dpop_jkt=None,
        grace_expiry_iso=grace_expiry,
    )

    resp = await client.get("/v1/egress/peers", headers=old_headers)
    assert resp.status_code == 200, resp.text

    audit = await _read_audit_rows(
        action="agent.cert_pinning_grace_match",
        agent_id="acme::rotor-bot",
    )
    assert audit, "grace match audit row should be present"
    assert grace_expiry in audit[0]["detail"]


@pytest.mark.asyncio
async def test_cert_pin_rejects_after_grace_expiry(proxy_app):
    _, client = proxy_app
    old_headers = await provision_internal_agent("ex-rotor")
    new_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="ex-rotor")
    old_cert_pem = urllib.parse.unquote(old_headers["X-SSL-Client-Cert"])

    await _swap_current_cert(agent_id="acme::ex-rotor", cert_pem=new_cert_pem)
    expired = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    await _set_grace_columns(
        agent_id="acme::ex-rotor",
        previous_cert_pem=old_cert_pem,
        previous_dpop_jkt=None,
        grace_expiry_iso=expired,
    )

    resp = await client.get("/v1/egress/peers", headers=old_headers)
    assert resp.status_code == 401
    body = resp.json()["detail"]
    assert body["reason"] == "client_cert_pin_mismatch"


@pytest.mark.asyncio
async def test_cert_pin_rejects_third_party_cert_during_grace(proxy_app):
    _, client = proxy_app
    await provision_internal_agent("strict-rotor")
    new_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="strict-rotor")
    await _swap_current_cert(agent_id="acme::strict-rotor", cert_pem=new_cert_pem)
    other_pem, _ = mint_agent_cert(org_id="acme", agent_name="strict-rotor")
    forged_pem, _ = mint_agent_cert(org_id="acme", agent_name="strict-rotor")
    grace_expiry = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    await _set_grace_columns(
        agent_id="acme::strict-rotor",
        previous_cert_pem=other_pem,
        previous_dpop_jkt=None,
        grace_expiry_iso=grace_expiry,
    )

    resp = await client.get(
        "/v1/egress/peers", headers=mtls_headers(forged_pem),
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "client_cert_pin_mismatch"


@pytest.mark.asyncio
async def test_cleanup_sweep_clears_expired_grace_rows(proxy_app):
    from mcp_proxy.db import get_db
    from mcp_proxy.lifespan.agent_cert_grace_cleanup import _sweep_once

    _, _client = proxy_app
    await provision_internal_agent("expired-bot")
    await provision_internal_agent("active-bot")

    expired = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    future = (
        datetime.now(timezone.utc) + timedelta(hours=24)
    ).isoformat()
    await _set_grace_columns(
        agent_id="acme::expired-bot",
        previous_cert_pem="-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----",
        previous_dpop_jkt="old-jkt",
        grace_expiry_iso=expired,
    )
    await _set_grace_columns(
        agent_id="acme::active-bot",
        previous_cert_pem="-----BEGIN CERTIFICATE-----\nactive\n-----END CERTIFICATE-----",
        previous_dpop_jkt="active-jkt",
        grace_expiry_iso=future,
    )

    cleared = await _sweep_once()
    assert cleared == 1

    async with get_db() as conn:
        expired_row = (await conn.execute(
            text(
                "SELECT previous_cert_pem, previous_dpop_jkt, "
                "       previous_grace_period_expires_at "
                "  FROM internal_agents WHERE agent_id = :aid"
            ),
            {"aid": "acme::expired-bot"},
        )).mappings().first()
        active_row = (await conn.execute(
            text(
                "SELECT previous_cert_pem, previous_dpop_jkt, "
                "       previous_grace_period_expires_at "
                "  FROM internal_agents WHERE agent_id = :aid"
            ),
            {"aid": "acme::active-bot"},
        )).mappings().first()

    assert expired_row["previous_cert_pem"] is None
    assert expired_row["previous_dpop_jkt"] is None
    assert expired_row["previous_grace_period_expires_at"] is None
    assert active_row["previous_cert_pem"] is not None
    assert active_row["previous_dpop_jkt"] == "active-jkt"
    assert active_row["previous_grace_period_expires_at"] == future

    audit = await _read_audit_rows(
        action="agent.cert_grace_period_expired",
        agent_id="acme::expired-bot",
    )
    assert audit, "cleanup must audit each cleared row"


@pytest.mark.asyncio
async def test_cleanup_sweep_empty_case_is_noop(proxy_app):
    from mcp_proxy.lifespan.agent_cert_grace_cleanup import _sweep_once

    _, _client = proxy_app
    await provision_internal_agent("nogrease-bot")
    cleared = await _sweep_once()
    assert cleared == 0

    audit = await _read_audit_rows(
        action="agent.cert_grace_period_expired",
        agent_id="acme::nogrease-bot",
    )
    assert audit == []


@pytest.mark.asyncio
async def test_cert_grace_helper_now_and_active():
    from mcp_proxy.auth.cert_grace import (
        compute_grace_expiry,
        is_grace_active,
        cert_thumbprint_hex,
    )

    assert is_grace_active(None) is False
    assert is_grace_active("") is False
    assert is_grace_active("not-a-date") is False

    future = (
        datetime.now(timezone.utc) + timedelta(hours=1)
    ).isoformat()
    past = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    assert is_grace_active(future) is True
    assert is_grace_active(past) is False

    naive_future = (
        datetime.utcnow() + timedelta(hours=1)
    ).isoformat()
    assert is_grace_active(naive_future) is True

    expiry = compute_grace_expiry(24)
    assert is_grace_active(expiry) is True

    instant = compute_grace_expiry(0)
    parsed = datetime.fromisoformat(instant)
    assert parsed <= datetime.now(timezone.utc)

    assert cert_thumbprint_hex(None) is None
    assert cert_thumbprint_hex("") is None
    assert cert_thumbprint_hex("not-a-pem") is None
    real_pem, _ = mint_agent_cert(org_id="acme", agent_name="thumb-test")
    thumb = cert_thumbprint_hex(real_pem)
    assert thumb is not None
    assert len(thumb) == 64
