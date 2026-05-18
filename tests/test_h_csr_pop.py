"""
H-csr-pop regression: ``POST /v1/enrollment/start`` verifies a proof
of possession over the submitted ``pubkey_pem``.

Pre-fix, the start endpoint accepted any public key with no proof
the caller controlled the matching private key. An attacker who
observed someone else's public key (logs, public artifacts, leaked
backups) could submit it under a different requester identity and
have the admin issue a cert tied to it. The cert would be unusable
to the attacker (they have no private key), but it gave a griefing
/ impersonation surface against the real owner of the keypair.

The fix: the Connector signs ``"enrollment-pop:v1|<sha256-fp>"``
with the enrollment private key and submits the signature in
``pop_signature``. The server verifies before persisting.
"""
from __future__ import annotations

import base64
import hashlib

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "h_csr_pop.sqlite"
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


def _fingerprint(pub_pem: str) -> str:
    pub = serialization.load_pem_public_key(pub_pem.encode())
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _sign_pop(priv, pub_pem: str) -> str:
    fp = _fingerprint(pub_pem)
    canonical = f"enrollment-pop:v1|{fp}".encode("utf-8")
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


# ── Valid PoP: enrollment created ────────────────────────────────────


@pytest.mark.asyncio
async def test_start_with_valid_pop_creates_pending(proxy_app) -> None:
    _, client = proxy_app
    priv, pub_pem = _ec_keypair()
    proof = _sign_pop(priv, pub_pem)

    resp = await client.post(
        "/v1/enrollment/start",
        json={
            "pubkey_pem": pub_pem,
            "requester_name": "Alice",
            "requester_email": "a@acme.test",
            "pop_signature": proof,
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "pending"


# ── Wrong key signed PoP: 400 ────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_with_wrong_key_pop_rejected(proxy_app) -> None:
    """An attacker submits Alice's public key with a PoP signed by
    a different private key. The server's verify must reject."""
    _, client = proxy_app
    _, alice_pub = _ec_keypair()
    bob_priv, _ = _ec_keypair()
    forged_proof = _sign_pop(bob_priv, alice_pub)

    resp = await client.post(
        "/v1/enrollment/start",
        json={
            "pubkey_pem": alice_pub,
            "requester_name": "Eve (impersonating)",
            "requester_email": "eve@evil.test",
            "pop_signature": forged_proof,
        },
    )
    assert resp.status_code == 400, resp.text
    assert "pop_signature" in resp.text


# ── Garbage PoP: 400 ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_with_garbage_pop_rejected(proxy_app) -> None:
    _, client = proxy_app
    _, pub_pem = _ec_keypair()

    resp = await client.post(
        "/v1/enrollment/start",
        json={
            "pubkey_pem": pub_pem,
            "requester_name": "Alice",
            "requester_email": "a@acme.test",
            "pop_signature": "not-a-real-signature-just-noise",
        },
    )
    assert resp.status_code == 400


# ── Missing PoP: rejected (transition window closed) ─────────────────


@pytest.mark.asyncio
async def test_start_without_pop_now_rejected(proxy_app) -> None:
    """The transition window is closed. A Connector that does not ship
    ``pop_signature`` is refused with 422 (Pydantic schema requires the
    field) so an attacker cannot enroll by replaying a stolen public
    key."""
    _, client = proxy_app
    _, pub_pem = _ec_keypair()

    resp = await client.post(
        "/v1/enrollment/start",
        json={
            "pubkey_pem": pub_pem,
            "requester_name": "LegacyConnector",
            "requester_email": "legacy@acme.test",
        },
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    # Pydantic surfaces the missing required field in ``detail``.
    assert any(
        "pop_signature" in (str(err.get("loc")) + str(err.get("msg")))
        for err in body.get("detail", [])
    ), body
