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


# ── ADR-020 — 3-component principal SPIFFE format ──────────────────────────


async def test_user_principal_svid_token_endpoint_issues_token(
    client: AsyncClient, dpop,
):
    """User principal cert (``spiffe://td/org/user/<name>``) round-trips
    through ``/v1/auth/token`` and gets a DPoP-bound JWT with
    ``principal_type=user``.

    Pre-fix this 500'd because the verifier collapsed the 3-component
    path into a fake agent_id. PR #443 + the typed-token flow added
    the user-principal lookup that issues an empty-scope token (the
    proxy's ``local_agent_resource_bindings`` is the authz source for
    user MCP access — see ADR-020). Workload principals stay rejected
    on this endpoint by design (separate test below).
    """
    await _prime_nonce(client, dpop)
    org_id = "userp-orga"
    trust_domain = "userp-orga.test"
    await _register_agent(
        client, f"{org_id}::placeholder", org_id, trust_domain=trust_domain,
    )

    assertion, spiffe = make_svid_assertion(
        agent_name="daniele",
        ca_org_id=org_id,
        trust_domain=trust_domain,
        spiffe_path=f"{org_id}/user/daniele",
    )
    assert spiffe == f"spiffe://{trust_domain}/{org_id}/user/daniele"
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    token = body["access_token"]

    # Decode without verification to check the typed claims survived.
    import jwt as _jwt
    payload = _jwt.decode(token, options={"verify_signature": False})
    assert payload["principal_type"] == "user"
    assert payload["agent_id"] == f"{org_id}::user::daniele"
    assert payload["sub"] == spiffe
    assert payload["scope"] == []  # binding-driven authz; no broker scope


async def test_workload_principal_svid_token_endpoint_returns_400(
    client: AsyncClient, dpop,
):
    """Same fast-fail for ``workload`` principals."""
    await _prime_nonce(client, dpop)
    org_id = "wlp-orga"
    trust_domain = "wlp-orga.test"
    await _register_agent(
        client, f"{org_id}::placeholder", org_id, trust_domain=trust_domain,
    )

    assertion, _ = make_svid_assertion(
        agent_name="frontdesk",
        ca_org_id=org_id,
        trust_domain=trust_domain,
        spiffe_path=f"{org_id}/workload/frontdesk",
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 400, resp.text


async def test_3component_agent_principal_accepted(
    client: AsyncClient, dpop,
):
    """3-component path with ``principal_type=agent`` resolves identically
    to the legacy 2-component agent SVID — same agent_id shape, same
    behaviour at ``/v1/auth/token``."""
    await _prime_nonce(client, dpop)
    org_id = "ag3-orga"
    trust_domain = "ag3-orga.test"
    agent_id = f"{org_id}::sales-agent"
    await _register_agent(client, agent_id, org_id, trust_domain=trust_domain)

    assertion, _ = make_svid_assertion(
        agent_name="sales-agent",
        ca_org_id=org_id,
        trust_domain=trust_domain,
        spiffe_path=f"{org_id}/agent/sales-agent",
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200, resp.text


async def test_3component_org_segment_mismatch_rejected(
    client: AsyncClient, dpop,
):
    """SPIFFE SAN's org segment does not match the trust-domain-resolved
    org → 403. Closes the SAN-smuggling gap that 2-component legacy SVIDs
    intentionally allowed for SPIRE-shape paths."""
    await _prime_nonce(client, dpop)
    org_id = "real-orga"
    trust_domain = "real-orga.test"
    await _register_agent(
        client, f"{org_id}::placeholder", org_id, trust_domain=trust_domain,
    )

    assertion, _ = make_svid_assertion(
        agent_name="bob",
        ca_org_id=org_id,  # signed by THIS org's CA
        trust_domain=trust_domain,
        spiffe_path="other-org/user/bob",  # SAN claims a DIFFERENT org
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 403, resp.text
    assert "does not match" in resp.text.lower()


async def test_3component_unknown_principal_type_rejected(
    client: AsyncClient, dpop,
):
    """Made-up principal type (e.g. ``service``) → 401 with parse error."""
    await _prime_nonce(client, dpop)
    org_id = "ut-orga"
    trust_domain = "ut-orga.test"
    await _register_agent(
        client, f"{org_id}::placeholder", org_id, trust_domain=trust_domain,
    )

    assertion, _ = make_svid_assertion(
        agent_name="x",
        ca_org_id=org_id,
        trust_domain=trust_domain,
        spiffe_path=f"{org_id}/service/x",  # 'service' not in whitelist
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 401, resp.text
