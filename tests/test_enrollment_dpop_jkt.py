"""F-B-11 Phase 3b — enrollment flow auto-populates ``dpop_jkt``.

Covers the service layer and the HTTP path:
  - ``start_enrollment`` accepts an optional ``dpop_jwk`` and stores
    the RFC 7638 thumbprint on ``pending_enrollments.dpop_jkt``.
  - ``approve`` copies that thumbprint to ``internal_agents.dpop_jkt``.
  - Backwards compat: omitting ``dpop_jwk`` leaves the column NULL
    throughout (pre-Phase-3c SDKs keep working).
  - Malformed JWKs (private key material, bad ``kty``, missing
    coords, empty object) are rejected at start time — they never
    touch the DB.
"""
from __future__ import annotations

import base64

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.enrollment import service
from mcp_proxy.enrollment.service import EnrollmentError


# ── Helpers ────────────────────────────────────────────────────────

def _ec_pubkey_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _ec_public_jwk() -> dict:
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y}


def _rsa_public_jwk() -> dict:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    n = base64.urlsafe_b64encode(
        nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()
    e = base64.urlsafe_b64encode(
        nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()
    return {"kty": "RSA", "n": n, "e": e}


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "enrollment.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


# ── start_enrollment: JWK → thumbprint ──────────────────────────────

@pytest.mark.asyncio
async def test_start_with_valid_ec_jwk_stores_thumbprint(db_engine):
    from mcp_proxy.auth.dpop import compute_jkt
    jwk = _ec_public_jwk()
    expected_jkt = compute_jkt(jwk)

    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=_ec_pubkey_pem(),
            requester_name="Alice",
            requester_email="alice@example.com",
            reason="test",
            device_info=None,
            dpop_jwk=jwk,
        )
        row = (await conn.execute(
            text("SELECT dpop_jkt FROM pending_enrollments WHERE session_id = :sid"),
            {"sid": started.session_id},
        )).first()

    assert row is not None
    assert row[0] == expected_jkt


@pytest.mark.asyncio
async def test_start_with_valid_rsa_jwk_stores_thumbprint(db_engine):
    from mcp_proxy.auth.dpop import compute_jkt
    jwk = _rsa_public_jwk()
    expected_jkt = compute_jkt(jwk)

    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=_ec_pubkey_pem(),
            requester_name="Bob",
            requester_email="bob@example.com",
            reason=None,
            device_info=None,
            dpop_jwk=jwk,
        )
        row = (await conn.execute(
            text("SELECT dpop_jkt FROM pending_enrollments WHERE session_id = :sid"),
            {"sid": started.session_id},
        )).first()

    assert row[0] == expected_jkt


@pytest.mark.asyncio
async def test_start_without_jwk_keeps_dpop_jkt_null(db_engine):
    """Backwards compat: a pre-Phase-3c SDK that omits ``dpop_jwk`` still
    produces a valid enrollment — the column stays NULL and the egress
    dep falls back to the mode=optional grace path."""
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=_ec_pubkey_pem(),
            requester_name="Carol",
            requester_email="carol@example.com",
            reason=None,
            device_info=None,
        )
        row = (await conn.execute(
            text("SELECT dpop_jkt FROM pending_enrollments WHERE session_id = :sid"),
            {"sid": started.session_id},
        )).first()

    assert row[0] is None


# ── Validation refusals ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_rejects_jwk_with_private_material(db_engine):
    bad = _ec_public_jwk()
    bad["d"] = "private-key-scalar-must-never-reach-the-server"
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=_ec_pubkey_pem(),
                requester_name="Dave",
                requester_email="dave@example.com",
                reason=None,
                device_info=None,
                dpop_jwk=bad,
            )
    assert exc.value.http_status == 400
    assert "private" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_start_rejects_unsupported_kty(db_engine):
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=_ec_pubkey_pem(),
                requester_name="Erin",
                requester_email="erin@example.com",
                reason=None,
                device_info=None,
                dpop_jwk={"kty": "oct", "k": "symmetric-not-allowed"},
            )
    assert exc.value.http_status == 400
    assert "kty" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_start_rejects_malformed_jwk(db_engine):
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=_ec_pubkey_pem(),
                requester_name="Fred",
                requester_email="fred@example.com",
                reason=None,
                device_info=None,
                dpop_jwk={"kty": "EC", "crv": "P-256"},  # missing x/y
            )
    assert exc.value.http_status == 400


@pytest.mark.asyncio
async def test_start_rejects_empty_jwk(db_engine):
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=_ec_pubkey_pem(),
                requester_name="Gina",
                requester_email="gina@example.com",
                reason=None,
                device_info=None,
                dpop_jwk={},
            )
    assert exc.value.http_status == 400


# ── approve propagates dpop_jkt ─────────────────────────────────────

@pytest_asyncio.fixture
async def agent_manager(db_engine):
    from mcp_proxy.egress.agent_manager import AgentManager
    mgr = AgentManager(org_id="acme", trust_domain="test.local")
    await mgr.generate_org_ca()
    return mgr


@pytest.mark.asyncio
async def test_approve_copies_jkt_to_internal_agents(agent_manager):
    from mcp_proxy.auth.dpop import compute_jkt
    jwk = _ec_public_jwk()
    expected_jkt = compute_jkt(jwk)

    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=_ec_pubkey_pem(),
            requester_name="Helen",
            requester_email="helen@example.com",
            reason=None,
            device_info=None,
            dpop_jwk=jwk,
        )

    async with get_db() as conn:
        await service.approve(
            conn,
            session_id=started.session_id,
            agent_id="acme::helen",
            capabilities=["order.read"],
            groups=[],
            admin_name="ops",
            agent_manager=agent_manager,
        )
        row = (await conn.execute(
            text("SELECT dpop_jkt FROM internal_agents WHERE agent_id = :aid"),
            {"aid": "acme::helen"},
        )).first()

    assert row is not None
    assert row[0] == expected_jkt


@pytest.mark.asyncio
async def test_approve_without_jwk_leaves_agent_dpop_jkt_null(agent_manager):
    """Pre-Phase-3c enrollment (no dpop_jwk) → internal_agents.dpop_jkt
    is NULL and the agent rides the mode=optional grace path."""
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=_ec_pubkey_pem(),
            requester_name="Iris",
            requester_email="iris@example.com",
            reason=None,
            device_info=None,
        )

    async with get_db() as conn:
        await service.approve(
            conn,
            session_id=started.session_id,
            agent_id="acme::iris",
            capabilities=[],
            groups=[],
            admin_name="ops",
            agent_manager=agent_manager,
        )
        row = (await conn.execute(
            text("SELECT dpop_jkt FROM internal_agents WHERE agent_id = :aid"),
            {"aid": "acme::iris"},
        )).first()

    assert row[0] is None


# ── HTTP path: POST /v1/enrollment/start ────────────────────────────

@pytest_asyncio.fixture
async def http_app(tmp_path, monkeypatch):
    """Standalone Mastio app with a fresh SQLite for HTTP-layer tests."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "fb11-p3b")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    reset_agent_rate_limiter()
    from mcp_proxy.main import app
    yield app
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_http_start_with_dpop_jwk_returns_201(http_app):
    from httpx import ASGITransport, AsyncClient
    transport = ASGITransport(app=http_app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with http_app.router.lifespan_context(http_app):
            body = {
                "pubkey_pem": _ec_pubkey_pem(),
                "requester_name": "Jack",
                "requester_email": "jack@example.com",
                "dpop_jwk": _ec_public_jwk(),
            }
            r = await cli.post("/v1/enrollment/start", json=body)
            assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_http_start_rejects_malformed_dpop_jwk(http_app):
    from httpx import ASGITransport, AsyncClient
    transport = ASGITransport(app=http_app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with http_app.router.lifespan_context(http_app):
            body = {
                "pubkey_pem": _ec_pubkey_pem(),
                "requester_name": "Kate",
                "requester_email": "kate@example.com",
                "dpop_jwk": {"kty": "oct", "k": "bad"},
            }
            r = await cli.post("/v1/enrollment/start", json=body)
            assert r.status_code == 400
            assert "kty" in r.json()["detail"].lower()
