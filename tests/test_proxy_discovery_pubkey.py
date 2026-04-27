"""ADR-006 Fase 1 / PR #3 — proxy serves agent discovery + public-key itself.

Before this PR the /v1/agents/search and /v1/federation/agents/*/public-key
calls were forwarded to the broker. Now the proxy answers from its own
tables (internal_agents + cached_federated_agents after ADR-010 Phase 6b),
with broker fallback for public-key lookups only when the agent is
unknown locally AND the proxy is running federated.
"""
from __future__ import annotations

import datetime
import json

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.db import get_db

from tests._mtls_helpers import provision_internal_agent


def _real_cert_pem(cn: str = "test-agent") -> str:
    """Build a minimal but syntactically valid X.509 cert PEM.

    The standalone public-key endpoint parses ``cert_pem`` with
    ``load_pem_x509_certificate`` and extracts SPKI, so the seed rows
    must carry real certs. Self-signed EC keeps the helper fast.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


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


async def _provision_agent(agent_id: str, **extra) -> dict[str, str]:
    """Provision an agent via mTLS helper and return the nginx-shaped headers.

    ADR-010 Phase 6b: caller-bot now surfaces in discovery results
    (single ``internal_agents`` registry). Default to an empty
    capability set so capability-filtered searches exclude it.
    """
    return await provision_internal_agent(
        agent_id,
        display_name=extra.get("display_name", agent_id),
        capabilities=extra.get("capabilities", []),
    )


async def _insert_local_agent(
    agent_id: str,
    *,
    display_name: str = "",
    capabilities: list[str] | None = None,
    cert_pem: str | None = None,
    active: int = 1,
    **_ignored,  # accepts legacy ``cert_thumbprint``/``org_id`` call-sites
) -> None:
    """Seed a row into ``internal_agents`` — the sole Mastio registry
    after ADR-010 Phase 6b. Discovery + public-key lookups now read from
    here; any ``cert_thumbprint`` is computed on-the-fly from ``cert_pem``."""
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO internal_agents (
                    agent_id, display_name, capabilities, cert_pem,
                    api_key_hash, created_at, is_active
                ) VALUES (
                    :aid, :dn, :caps, :cert,
                    '$2b$12$placeholder', '2026-04-16T00:00:00Z', :active
                )
                """
            ),
            {
                "aid": agent_id,
                "dn": display_name or agent_id,
                "caps": json.dumps(capabilities or []),
                "cert": cert_pem,
                "active": active,
            },
        )


async def _insert_cached_federated_agent(
    agent_id: str,
    *,
    org_id: str,
    display_name: str = "",
    capabilities: list[str] | None = None,
    thumbprint: str | None = None,
    revoked: int = 0,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO cached_federated_agents (
                    agent_id, org_id, display_name, capabilities,
                    thumbprint, revoked, updated_at
                ) VALUES (
                    :aid, :org, :dn, :caps, :tp, :rev, '2026-04-16T00:00:00Z'
                )
                """
            ),
            {
                "aid": agent_id,
                "org": org_id,
                "dn": display_name or agent_id,
                "caps": json.dumps(capabilities or []),
                "tp": thumbprint,
                "rev": revoked,
            },
        )


# ── /v1/agents/search ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_returns_local_agents_only_in_standalone(standalone_proxy):
    _, client = standalone_proxy
    caller_headers = await _provision_agent("caller-bot")
    await _insert_local_agent("alice-bot", capabilities=["cap.read"])
    await _insert_local_agent("bob-bot", capabilities=["cap.write"])

    resp = await client.get(
        "/v1/agents/search",
        headers=caller_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = sorted(a["agent_id"] for a in body["agents"])
    # ADR-010 Phase 6b: discovery now reads the single ``internal_agents``
    # table. The mTLS-provisioned caller surfaces under its canonical
    # ``<org>::<name>`` id alongside the explicitly-inserted test rows.
    assert "acme::caller-bot" in ids
    assert "alice-bot" in ids
    assert "bob-bot" in ids
    for entry in body["agents"]:
        assert entry["scope"] == "local"


@pytest.mark.asyncio
async def test_search_filters_by_capability(standalone_proxy):
    _, client = standalone_proxy
    caller_headers = await _provision_agent("caller-bot")
    await _insert_local_agent("reader", capabilities=["cap.read"])
    await _insert_local_agent("writer", capabilities=["cap.write"])
    await _insert_local_agent("both", capabilities=["cap.read", "cap.write"])

    resp = await client.get(
        "/v1/agents/search?capability=cap.read",
        headers=caller_headers,
    )
    assert resp.status_code == 200
    ids = sorted(a["agent_id"] for a in resp.json()["agents"])
    assert ids == ["both", "reader"]


@pytest.mark.asyncio
async def test_search_q_substring_match(standalone_proxy):
    _, client = standalone_proxy
    caller_headers = await _provision_agent("caller-bot")
    await _insert_local_agent("acme-kyc-1", display_name="KYC Service 1")
    await _insert_local_agent("acme-audit-1", display_name="Audit Service")

    resp = await client.get(
        "/v1/agents/search?q=kyc",
        headers=caller_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["agents"][0]["agent_id"] == "acme-kyc-1"


@pytest.mark.asyncio
async def test_search_local_and_federated_union_with_local_priority(standalone_proxy):
    """When an agent_id appears in both local_agents and
    cached_federated_agents, the local row must win (ADR-006 §2.4)."""
    _, client = standalone_proxy
    caller_headers = await _provision_agent("caller-bot")
    await _insert_local_agent("shared-bot", display_name="Local Version")
    await _insert_cached_federated_agent(
        "shared-bot", org_id="other", display_name="Federated Version",
    )
    await _insert_cached_federated_agent(
        "partner-bot", org_id="other", display_name="Partner Bot",
    )

    resp = await client.get(
        "/v1/agents/search",
        headers=caller_headers,
    )
    assert resp.status_code == 200
    by_id = {a["agent_id"]: a for a in resp.json()["agents"]}
    assert by_id["shared-bot"]["scope"] == "local"
    assert by_id["shared-bot"]["display_name"] == "Local Version"
    assert by_id["partner-bot"]["scope"] == "federated"


@pytest.mark.asyncio
async def test_search_inactive_agents_skipped_by_default(standalone_proxy):
    _, client = standalone_proxy
    caller_headers = await _provision_agent("caller-bot")
    await _insert_local_agent("live", active=1)
    await _insert_local_agent("retired", active=0)

    resp = await client.get(
        "/v1/agents/search",
        headers=caller_headers,
    )
    assert resp.status_code == 200
    ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "live" in ids
    assert "retired" not in ids

    resp_all = await client.get(
        "/v1/agents/search?active=false",
        headers=caller_headers,
    )
    ids_all = [a["agent_id"] for a in resp_all.json()["agents"]]
    assert "retired" in ids_all


@pytest.mark.asyncio
async def test_search_requires_api_key(standalone_proxy):
    _, client = standalone_proxy
    resp = await client.get("/v1/agents/search")
    assert resp.status_code == 401


# ── /v1/federation/agents/{id}/public-key ─────────────────────────────

@pytest.mark.asyncio
async def test_public_key_served_from_local_agents(standalone_proxy):
    _, client = standalone_proxy
    cert_pem = _real_cert_pem("alice-bot")
    await _insert_local_agent("alice-bot", cert_pem=cert_pem)

    resp = await client.get("/v1/federation/agents/alice-bot/public-key")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "alice-bot"
    assert body["scope"] == "local"
    # Endpoint extracts SPKI from ``cert_pem``; SDK feeds this straight
    # into ``load_pem_public_key`` which only accepts ``BEGIN PUBLIC KEY``.
    assert "BEGIN PUBLIC KEY" in body["public_key_pem"]
    assert "BEGIN CERTIFICATE" not in body["public_key_pem"]
    # ADR-010 Phase 6b: thumbprint is SHA-256 of the DER the PEM wraps.
    import base64
    import hashlib
    import re as _re
    der = base64.b64decode(_re.sub(r"-----.*?-----|\s", "", cert_pem))
    assert body["cert_thumbprint"] == hashlib.sha256(der).hexdigest()


@pytest.mark.asyncio
async def test_public_key_404_in_standalone_when_not_local(standalone_proxy):
    """Standalone has no broker to forward to — unknown agent → 404."""
    _, client = standalone_proxy
    resp = await client.get("/v1/federation/agents/missing-bot/public-key")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_public_key_skips_inactive_local_rows(standalone_proxy):
    """Revoked / disabled local agents look "not local" to the lookup —
    they must NOT be served, otherwise a revoked cert stays fetchable."""
    _, client = standalone_proxy
    await _insert_local_agent(
        "retired-bot",
        cert_pem="-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n",
        active=0,
    )
    resp = await client.get("/v1/federation/agents/retired-bot/public-key")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_public_key_endpoint_wins_over_reverse_proxy(standalone_proxy):
    """/v1/registry/* is a reverse-proxy prefix — verify our proxy-native
    public-key route wins the route match, even when no broker is wired
    in. Without the explicit include_router ordering in main.py this
    would hit the reverse-proxy handler and 503 for "broker not
    configured"."""
    _, client = standalone_proxy
    await _insert_local_agent(
        "ordering-check",
        cert_pem=_real_cert_pem("ordering-check"),
    )
    resp = await client.get("/v1/federation/agents/ordering-check/public-key")
    # 200 = proxy-native route wins. 503 = reverse-proxy caught it first
    # (would be a regression).
    assert resp.status_code == 200, resp.text
