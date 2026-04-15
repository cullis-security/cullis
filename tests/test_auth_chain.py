"""
Broker x509 chain walk — 3-level PKI for SPIFFE/SPIRE agents.

Covers ADR-003 §2.1 (broker walks x5c) and §2.3 (thumbprint pinning
skipped in SPIFFE mode). All tests register the Org CA with
pathLenConstraint=1 so the CA is legally allowed to sign a single
intermediate below it (the SPIRE signing intermediate).
"""
from __future__ import annotations

import base64
import datetime
import uuid

import jwt as jose_jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient

from tests.cert_factory import (
    get_org_ca_pem_for_chain,
    make_intermediate_ca,
    make_svid_chain_assertion,
    make_svid_with_chain,
    _get_org_ca,
    _key_pem,
    _now,
)
from tests.conftest import ADMIN_HEADERS, TestSessionLocal
from app.registry.org_store import update_org_trust_domain

pytestmark = pytest.mark.asyncio


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    resp = await client.get("/health")
    dpop._update_nonce(resp)


async def _register_agent_with_chain_ca(
    client: AsyncClient, agent_id: str, org_id: str, trust_domain: str,
) -> None:
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    # Upload the pathLen=1 CA — the classic helper uses pathLen=0
    # which would refuse any intermediate below it.
    ca_pem = get_org_ca_pem_for_chain(org_id)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    async with TestSessionLocal() as db:
        await update_org_trust_domain(db, org_id, trust_domain)
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["test.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
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


# ─────────────────────────────────────────────────────────────────────────────
# Happy paths
# ─────────────────────────────────────────────────────────────────────────────

async def test_three_level_chain_accepted(client: AsyncClient, dpop):
    """SVID signed by intermediate signed by Org CA → broker walks chain → 200."""
    await _prime_nonce(client, dpop)
    org_id = "chain-orga"
    td = "chain-orga.test"
    agent_id = f"{org_id}::workload-a"
    await _register_agent_with_chain_ca(client, agent_id, org_id, td)

    assertion, _ = make_svid_chain_assertion(
        agent_name="workload-a",
        ca_org_id=org_id,
        trust_domain=td,
        spiffe_path="workload/workload-a",
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200, resp.text


async def test_chain_with_orgca_appended_still_accepted(client: AsyncClient, dpop):
    """If the client erroneously includes the Org CA in x5c, broker strips
    it and still validates the chain."""
    await _prime_nonce(client, dpop)
    org_id = "chain-orgb"
    td = "chain-orgb.test"
    agent_id = f"{org_id}::workload-b"
    await _register_agent_with_chain_ca(client, agent_id, org_id, td)

    # Build chain + append the Org CA cert as last element.
    _, org_ca_cert = _get_org_ca(org_id, path_length=1)
    svid_key, svid_cert, int_cert, spiffe_id = make_svid_with_chain(
        "workload-b", org_id, td, spiffe_path="workload/workload-b",
    )
    chain = [svid_cert, int_cert, org_ca_cert]
    x5c = [
        base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
        for c in chain
    ]
    now = _now()
    payload = {
        "sub": spiffe_id, "iss": spiffe_id, "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    assertion = jose_jwt.encode(
        payload, _key_pem(svid_key), algorithm="RS256", headers={"x5c": x5c},
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200, resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Rejection paths
# ─────────────────────────────────────────────────────────────────────────────

async def test_chain_broken_at_intermediate(client: AsyncClient, dpop):
    """Intermediate from a DIFFERENT Org CA is spliced into the chain → 401."""
    await _prime_nonce(client, dpop)
    org_id = "chain-orgc"
    td = "chain-orgc.test"
    agent_id = f"{org_id}::workload-c"
    await _register_agent_with_chain_ca(client, agent_id, org_id, td)

    # Make a legitimate intermediate for org_id, but SIGN the SVID with
    # an intermediate whose parent is a different org (unregistered).
    _, rogue_int_cert = make_intermediate_ca("unregistered-org", name="rogue")
    rogue_int_key, _ = make_intermediate_ca("unregistered-org", name="rogue2")
    # Actually use a fresh unrelated intermediate for signing:
    rogue_key, rogue_cert = make_intermediate_ca("unregistered-org", name="rogue3")

    # Build SVID signed by rogue intermediate but place legitimate
    # intermediate in x5c to try to fool the verifier.
    _, int_ca_cert_ok = make_intermediate_ca(org_id)
    svid_key, svid_cert, _, spiffe_id = make_svid_with_chain(
        "workload-c", org_id, td,
        int_ca_key=rogue_key, int_ca_cert=rogue_cert,
        spiffe_path="workload/workload-c",
    )
    # x5c claims svid is under the legit intermediate — but signature
    # was actually produced by the rogue key. Chain walk will catch it.
    chain = [svid_cert, int_ca_cert_ok]
    x5c = [
        base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
        for c in chain
    ]
    now = _now()
    payload = {
        "sub": spiffe_id, "iss": spiffe_id, "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    assertion = jose_jwt.encode(
        payload, _key_pem(svid_key), algorithm="RS256", headers={"x5c": x5c},
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 401
    assert "chain" in resp.text.lower()


async def test_chain_with_duplicate_intermediate(client: AsyncClient, dpop):
    """Same intermediate cert appears twice in x5c → 401 duplicate."""
    await _prime_nonce(client, dpop)
    org_id = "chain-orgd"
    td = "chain-orgd.test"
    agent_id = f"{org_id}::workload-d"
    await _register_agent_with_chain_ca(client, agent_id, org_id, td)

    int_key, int_cert = make_intermediate_ca(org_id)
    assertion, _ = make_svid_chain_assertion(
        agent_name="workload-d",
        ca_org_id=org_id,
        trust_domain=td,
        int_ca_key=int_key,
        int_ca_cert=int_cert,
        spiffe_path="workload/workload-d",
        extra_intermediates=[int_cert],  # duplicate the intermediate
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 401
    assert "duplicate" in resp.text.lower()


async def test_chain_too_long(client: AsyncClient, dpop):
    """More than _MAX_CHAIN_LENGTH intermediates → 401."""
    await _prime_nonce(client, dpop)
    org_id = "chain-orge"
    td = "chain-orge.test"
    agent_id = f"{org_id}::workload-e"
    await _register_agent_with_chain_ca(client, agent_id, org_id, td)

    # 7 certs in intermediates — exceeds _MAX_CHAIN_LENGTH=6.
    bogus_intermediates = [
        make_intermediate_ca("unregistered", name=f"bogus-{i}")[1]
        for i in range(7)
    ]
    assertion, _ = make_svid_chain_assertion(
        agent_name="workload-e",
        ca_org_id=org_id,
        trust_domain=td,
        spiffe_path="workload/workload-e",
        extra_intermediates=bogus_intermediates,
    )
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 401
    assert "too long" in resp.text.lower() or "chain" in resp.text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Pinning behavior
# ─────────────────────────────────────────────────────────────────────────────

async def test_pinning_skipped_in_spiffe_mode(client: AsyncClient, dpop):
    """Two consecutive logins with DIFFERENT SVIDs (rotation) both succeed,
    because SPIFFE mode skips thumbprint pinning."""
    await _prime_nonce(client, dpop)
    org_id = "chain-rot"
    td = "chain-rot.test"
    agent_id = f"{org_id}::rotator"
    await _register_agent_with_chain_ca(client, agent_id, org_id, td)

    # Shared intermediate so the chain walks consistently.
    int_key, int_cert = make_intermediate_ca(org_id)

    # First login with one SVID
    a1, _ = make_svid_chain_assertion(
        agent_name="rotator", ca_org_id=org_id, trust_domain=td,
        int_ca_key=int_key, int_ca_cert=int_cert,
        spiffe_path="workload/rotator",
    )
    r1 = await client.post(
        "/v1/auth/token",
        json={"client_assertion": a1},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert r1.status_code == 200, r1.text

    # Second login with a FRESH SVID (new key → new thumbprint). If pinning
    # were active this would 401 with cert_thumbprint_mismatch.
    a2, _ = make_svid_chain_assertion(
        agent_name="rotator", ca_org_id=org_id, trust_domain=td,
        int_ca_key=int_key, int_ca_cert=int_cert,
        spiffe_path="workload/rotator",
    )
    r2 = await client.post(
        "/v1/auth/token",
        json={"client_assertion": a2},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert r2.status_code == 200, r2.text


# ─────────────────────────────────────────────────────────────────────────────
# Onboarding pathLen validation
# ─────────────────────────────────────────────────────────────────────────────

async def test_onboarding_rejects_too_permissive_ca_in_spiffe_mode(client: AsyncClient):
    """Submitting a CA with pathLenConstraint=2 together with a trust_domain
    must be rejected with 400."""
    # Build a self-signed CA with path_length=2 for the test.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "TooDeep CA"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "toodeep"),
    ])
    now = _now()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # First create an invite
    invite_resp = await client.post(
        "/v1/admin/invites", json={"label": "t", "ttl_hours": 1},
        headers=ADMIN_HEADERS,
    )
    token = invite_resp.json()["token"]

    resp = await client.post("/v1/onboarding/join", json={
        "org_id": "toodeep",
        "display_name": "TooDeep",
        "secret": "toodeep-secret",
        "ca_certificate": ca_pem,
        "invite_token": token,
        "contact_email": "a@b.c",
        "trust_domain": "toodeep.test",
    })
    assert resp.status_code == 400
    assert "pathlen" in resp.text.lower()
