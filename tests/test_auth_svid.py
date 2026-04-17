"""
SVID-only authentication — client_assertion JWT signed by a certificate
whose identity lives ONLY in a SPIFFE URI SAN (empty subject, no CN/O).

Verifies the broker derives (org_id, agent_id) by matching the SVID's
trust_domain against OrganizationRecord.trust_domain, without breaking
the classic CN/O-based auth path.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.cert_factory import (
    get_org_ca_pem,
    make_assertion,
    make_svid_assertion,
)
from tests.conftest import ADMIN_HEADERS, TestSessionLocal, seed_court_agent
from app.registry.org_store import update_org_trust_domain

pytestmark = pytest.mark.asyncio


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    resp = await client.get("/health")
    dpop._update_nonce(resp)


async def _register_agent(
    client: AsyncClient, agent_id: str, org_id: str,
    trust_domain: str | None = None,
) -> None:
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    if trust_domain is not None:
        async with TestSessionLocal() as db:
            await update_org_trust_domain(db, org_id, trust_domain)
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['test.read'],
    )
    resp = await client.post(
        "/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )


async def test_svid_only_assertion_accepted(client: AsyncClient, dpop):
    """SVID cert (no CN/O, SPIFFE SAN only) → 200 when org.trust_domain matches."""
    await _prime_nonce(client, dpop)
    org_id = "svid-orga"
    trust_domain = "svid-orga.test"
    # agent_id derived by broker = "{org_id}::{last-path-segment}"
    agent_id = f"{org_id}::agent-a"
    await _register_agent(client, agent_id, org_id, trust_domain=trust_domain)

    assertion, _spiffe = make_svid_assertion(
        agent_name="agent-a",
        ca_org_id=org_id,
        trust_domain=trust_domain,
        spiffe_path="workload/agent-a",
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200, resp.text


async def test_svid_trust_domain_unknown_rejected(client: AsyncClient, dpop):
    """SVID with a trust_domain that no registered org claims → 403."""
    await _prime_nonce(client, dpop)
    org_id = "svid-orgb"
    await _register_agent(client, f"{org_id}::agent-a", org_id)  # no trust_domain set

    assertion, _ = make_svid_assertion(
        agent_name="agent-a",
        ca_org_id=org_id,
        trust_domain="nobody.test",
        spiffe_path="workload/agent-a",
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 403
    assert "trust domain" in resp.text.lower()


async def test_classic_cn_o_still_works(client: AsyncClient, dpop):
    """Backward compat: agent cert with CN/O subject continues to authenticate."""
    await _prime_nonce(client, dpop)
    org_id = "svid-classic"
    agent_id = f"{org_id}::agent-1"
    await _register_agent(client, agent_id, org_id)

    assertion = make_assertion(agent_id, org_id)
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200, resp.text


async def test_svid_no_san_rejected(client: AsyncClient, dpop):
    """Cert without CN/O AND without SPIFFE SAN → 401."""
    await _prime_nonce(client, dpop)
    org_id = "svid-nosan"
    await _register_agent(client, f"{org_id}::agent-a", org_id,
                          trust_domain="svid-nosan.test")

    # Forge a bogus assertion whose cert is a valid SVID but we strip the
    # SAN by constructing with a trust_domain no org claims. This path is
    # already covered by test_svid_trust_domain_unknown_rejected. Here we
    # exercise the "no SPIFFE SAN and no CN/O" branch by using an empty
    # path, which make_svid_assertion rejects at the x509 level via
    # validate_spiffe_id — so use a garbage cert constructed manually.
    import base64
    import datetime
    import uuid
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt

    from tests.cert_factory import _get_org_ca, _key_pem

    org_ca_key, org_ca_cert = _get_org_ca(org_id)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))  # empty subject
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # deliberately no SubjectAlternativeName
        .sign(org_ca_key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]
    payload = {
        "sub": "anyone", "iss": "anyone", "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    assertion = jwt.encode(
        payload, _key_pem(key), algorithm="RS256", headers={"x5c": x5c},
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 401
