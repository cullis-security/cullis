"""ADR-009 Phase 1 PR 1b — Court enforces mastio counter-signature
on /v1/auth/token when the org has pinned a mastio_pubkey.

Covers:
  - Valid counter-sig + pinned mastio_pubkey → 200
  - Missing counter-sig header + pinned mastio_pubkey → 403
  - Invalid counter-sig + pinned mastio_pubkey → 403
  - Malformed base64 counter-sig → 403
  - Legacy org (mastio_pubkey NULL) ignores any counter-sig → 200
  - SDK client.login_from_pem wires the countersign_fn callback into
    the X-Cullis-Mastio-Signature header end-to-end.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient

from tests.cert_factory import make_assertion, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio


# ── helpers ────────────────────────────────────────────────────────────

def _gen_mastio_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def _sign_countersig(priv: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    resp = await client.get("/health")
    dpop._update_nonce(resp)


async def _register_agent_with_mastio(
    client: AsyncClient,
    agent_id: str,
    org_id: str,
    mastio_pubkey_pem: str | None,
) -> None:
    """Mirror tests/test_auth.py::_register_agent and pin the mastio pubkey
    directly on the org row if supplied."""
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)

    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id,
        "org_id": org_id,
        "display_name": f"Test Agent {agent_id}",
        "capabilities": ["test.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})

    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    if mastio_pubkey_pem is not None:
        from app.db.database import AsyncSessionLocal
        from app.registry.org_store import update_org_mastio_pubkey

        async with AsyncSessionLocal() as db:
            await update_org_mastio_pubkey(db, org_id, mastio_pubkey_pem)


# ── enforcement tests ──────────────────────────────────────────────────

async def test_token_ok_with_valid_countersig(client: AsyncClient, dpop):
    await _prime_nonce(client, dpop)
    priv, pub_pem = _gen_mastio_keypair()
    org_id = "cs-ok"
    await _register_agent_with_mastio(client, f"{org_id}::alice", org_id, pub_pem)

    assertion = make_assertion(f"{org_id}::alice", org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    sig = _sign_countersig(priv, assertion.encode())

    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={
            "DPoP": dpop_proof,
            "X-Cullis-Mastio-Signature": sig,
        },
    )
    assert resp.status_code == 200, resp.text
    assert "access_token" in resp.json()


async def test_token_denied_missing_countersig(client: AsyncClient, dpop):
    await _prime_nonce(client, dpop)
    _, pub_pem = _gen_mastio_keypair()
    org_id = "cs-missing"
    await _register_agent_with_mastio(client, f"{org_id}::bob", org_id, pub_pem)

    assertion = make_assertion(f"{org_id}::bob", org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")

    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 403
    assert "mastio counter-signature" in resp.text or "X-Cullis-Mastio-Signature" in resp.text


async def test_token_denied_wrong_countersig_key(client: AsyncClient, dpop):
    """Signature with an unrelated EC key → 403."""
    await _prime_nonce(client, dpop)
    _, pinned_pub = _gen_mastio_keypair()
    attacker_priv, _ = _gen_mastio_keypair()
    org_id = "cs-wrong-key"
    await _register_agent_with_mastio(
        client, f"{org_id}::eve", org_id, pinned_pub,
    )

    assertion = make_assertion(f"{org_id}::eve", org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    sig = _sign_countersig(attacker_priv, assertion.encode())

    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof, "X-Cullis-Mastio-Signature": sig},
    )
    assert resp.status_code == 403
    assert "verification failed" in resp.text


async def test_token_denied_malformed_countersig(client: AsyncClient, dpop):
    await _prime_nonce(client, dpop)
    _, pub_pem = _gen_mastio_keypair()
    org_id = "cs-malformed"
    await _register_agent_with_mastio(
        client, f"{org_id}::mallory", org_id, pub_pem,
    )

    assertion = make_assertion(f"{org_id}::mallory", org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")

    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={
            "DPoP": dpop_proof,
            "X-Cullis-Mastio-Signature": "!!!not-base64!!!",
        },
    )
    assert resp.status_code == 403
    assert "base64url" in resp.text or "verification" in resp.text


async def test_token_legacy_org_ignores_countersig(client: AsyncClient, dpop):
    """Org with mastio_pubkey NULL accepts login without any header."""
    await _prime_nonce(client, dpop)
    org_id = "cs-legacy"
    await _register_agent_with_mastio(
        client, f"{org_id}::charlie", org_id, mastio_pubkey_pem=None,
    )

    assertion = make_assertion(f"{org_id}::charlie", org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")

    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 200, resp.text


# ── SDK callback unit test ─────────────────────────────────────────────

def test_sdk_login_calls_countersign_fn_with_assertion():
    """CullisClient.login_from_pem invokes ``countersign_fn(assertion)``
    and attaches the result as X-Cullis-Mastio-Signature on the POST.

    Drives CullisClient against a mocked httpx transport so we don't need
    a running broker — the broker-side enforcement is covered by the
    tests above.
    """
    import httpx as _httpx
    from cullis_sdk.client import CullisClient
    from tests.cert_factory import make_agent_cert, _key_pem

    captured_headers: dict[str, str] = {}

    def _handler(request: _httpx.Request) -> _httpx.Response:
        captured_headers.update(request.headers)
        # Fake server nonce on the first round-trip.
        return _httpx.Response(
            200,
            json={
                "access_token": "fake-token",
                "token_type": "DPoP",
                "expires_in": 900,
            },
            headers={"DPoP-Nonce": "test-nonce"},
        )

    transport = _httpx.MockTransport(_handler)
    client = CullisClient("http://test", verify_tls=False)
    client._http = _httpx.Client(transport=transport)

    key, cert = make_agent_cert("mock-org::sdk-bot", "mock-org")
    from cryptography.hazmat.primitives import serialization as _ser
    cert_pem = cert.public_bytes(_ser.Encoding.PEM).decode()
    key_pem = _key_pem(key)

    invocations: list[str] = []

    def _sign(assertion_str: str) -> str:
        invocations.append(assertion_str)
        return "FAKE-SIG-BASE64URL"

    client.login_from_pem(
        "mock-org::sdk-bot", "mock-org", cert_pem, key_pem,
        countersign_fn=_sign,
    )

    assert len(invocations) == 1
    assert captured_headers.get("x-cullis-mastio-signature") == "FAKE-SIG-BASE64URL"
