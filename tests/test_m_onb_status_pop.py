"""
M-onb-1 regression: ``GET /v1/enrollment/{session_id}/status`` now
gates ``cert_pem`` / ``agent_id`` / ``capabilities`` behind a proof
of possession of the keypair the Connector registered at
``POST /v1/enrollment/start``.

Before the fix, the endpoint was unauthenticated — anyone holding
the session_id (guessed, leaked from logs, intercepted on HTTP)
could pull the issued cert and learn the assigned agent_id +
capabilities of an approved enrolment. The session_id functioned
as a bearer token. Now an attacker with just the session_id sees
``status`` and nothing else.
"""
from __future__ import annotations

import base64

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "m_onb.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


def _ec_keypair() -> tuple:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def _sign_proof(priv, session_id: str) -> str:
    canonical = f"enrollment-status:v1|{session_id}".encode("utf-8")
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        sig = priv.sign(canonical, ec.ECDSA(hashes.SHA256()))
    else:
        sig = priv.sign(
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


async def _start_enrollment(client: AsyncClient, pub_pem: str) -> str:
    resp = await client.post(
        "/v1/enrollment/start",
        json={
            "pubkey_pem": pub_pem,
            "requester_name": "M Rossi",
            "requester_email": "m@acme.test",
            "reason": "test",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["session_id"]


async def _approve(client: AsyncClient, session_id: str) -> None:
    """Push the row to ``approved`` directly via the agent_manager
    (skip the dashboard CSRF dance — not the surface under test)."""
    from mcp_proxy.db import get_db
    from mcp_proxy.enrollment import service

    async with get_db() as conn:
        from mcp_proxy.main import app as _app
        agent_manager = _app.state.agent_manager
        await service.approve(
            conn,
            session_id=session_id,
            agent_id="alice",
            capabilities=["read"],
            groups=[],
            admin_name="test-admin",
            agent_manager=agent_manager,
        )


# ── Status without proof: only `status` field comes back ─────────────


@pytest.mark.asyncio
async def test_status_without_proof_hides_cert_and_caps(proxy_app) -> None:
    _, client = proxy_app
    priv, pub_pem = _ec_keypair()
    session_id = await _start_enrollment(client, pub_pem)
    await _approve(client, session_id)

    resp = await client.get(f"/v1/enrollment/{session_id}/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    # The whole point of the fix:
    assert body.get("cert_pem") is None, "cert_pem leaked without PoP"
    assert body.get("agent_id") is None, "agent_id leaked without PoP"
    assert (body.get("capabilities") or []) == [], (
        "capabilities leaked without PoP"
    )


# ── Wrong / forged proof: same restricted shape ──────────────────────


@pytest.mark.asyncio
async def test_status_with_wrong_key_proof_hides_cert(proxy_app) -> None:
    """An attacker with the session_id but a different keypair can
    forge a syntactically-valid proof. The server rejects it because
    the signature won't verify against the enroller's public key."""
    _, client = proxy_app
    priv, pub_pem = _ec_keypair()
    session_id = await _start_enrollment(client, pub_pem)
    await _approve(client, session_id)

    attacker_priv, _ = _ec_keypair()
    forged_proof = _sign_proof(attacker_priv, session_id)

    resp = await client.get(
        f"/v1/enrollment/{session_id}/status",
        headers={"X-Enrollment-Proof": forged_proof},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body.get("cert_pem") is None
    assert body.get("agent_id") is None


# ── Valid proof: full payload is returned ────────────────────────────


@pytest.mark.asyncio
async def test_status_with_valid_proof_returns_full_payload(proxy_app) -> None:
    _, client = proxy_app
    priv, pub_pem = _ec_keypair()
    session_id = await _start_enrollment(client, pub_pem)
    await _approve(client, session_id)

    proof = _sign_proof(priv, session_id)
    resp = await client.get(
        f"/v1/enrollment/{session_id}/status",
        headers={"X-Enrollment-Proof": proof},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["agent_id"] == "acme::alice"
    assert body["cert_pem"] and "BEGIN CERTIFICATE" in body["cert_pem"]
    assert body["capabilities"] == ["read"]


# ── Status field still leaks pending/approved (acceptable trade-off) ─


@pytest.mark.asyncio
async def test_status_field_alone_still_observable_without_proof(proxy_app) -> None:
    """The fix does NOT hide the bare ``status`` field — the Connector
    UI needs to show ``pending → approved`` to the operator without
    bringing the private key online for every poll. Document the
    accepted residual."""
    _, client = proxy_app
    priv, pub_pem = _ec_keypair()
    session_id = await _start_enrollment(client, pub_pem)

    resp = await client.get(f"/v1/enrollment/{session_id}/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"
