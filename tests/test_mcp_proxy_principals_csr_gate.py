"""F-001 regression for the proxy-side CSR signing endpoint.

The broker-side gate (``app/registry/user_principals_router.py``) lands
the security review F-001 check that requires a ``principal_type=workload``
caller for any CSR whose ``principal_id`` targets a ``user`` principal.
The proxy hosts a sister copy at
``mcp_proxy/registry/user_principals_router.py`` that was missing the
same gate, leaving the Frontdesk Mastio path open to escalation by any
DPoP-authenticated agent in the org.

This module mirrors the relevant cases from ``tests/test_principals_csr.py``
against the proxy app:

  * a regular ``principal_type=agent`` caller is refused (403),
  * a ``principal_type=user`` caller is refused (403),
  * a ``principal_type=workload`` caller is accepted (would proceed
    past the gate; we stop at the agent_manager 503 fallback because
    booting the full proxy stack would require a live Org CA),
  * a regular agent caller may still sign a CSR for an ``agent``
    principal (gate scoped to ``user`` segment only).
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.models import TokenPayload
from mcp_proxy.registry.user_principals_router import router as principals_router

pytestmark = pytest.mark.asyncio


def _make_csr(spiffe_uri: str) -> str:
    """Build a CSR with a single SPIFFE SAN and return its PEM."""
    priv = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "principal")]),
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(spiffe_uri)],
        ),
        critical=False,
    )
    csr = builder.sign(priv, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _override_token(
    *, agent_id: str, org: str, principal_type: str,
) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{org}/{principal_type}/"
        f"{agent_id.split('::', 1)[-1]}",
        agent_id=agent_id,
        org=org,
        exp=2_000_000_000,
        iat=1_700_000_000,
        jti="test-jti",
        scope=[],
        cnf={"jkt": "x" * 43},
        principal_type=principal_type,
    )


@pytest_asyncio.fixture
async def proxy_app():
    """Minimal FastAPI app exposing only the CSR router.

    The full proxy boot requires a live DB, agent_manager, Org CA, etc.
    The F-001 gate fires BEFORE those touchpoints, so we can exercise
    the check against a stripped-down app. The workload happy path
    stops at the 503 agent_manager fallback (we don't actually want a
    cert minted in a unit test).
    """
    app = FastAPI()
    app.include_router(principals_router)
    yield app
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(proxy_app):
    transport = ASGITransport(app=proxy_app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver",
    ) as ac:
        yield ac


async def test_proxy_csr_403_regular_agent_cannot_mint_user_cert(
    proxy_app, client,
):
    """A ``principal_type=agent`` caller in the same org may NOT mint
    a user-principal cert. Without the gate, this would proceed past
    the org check and end up signing an attacker-controlled
    ``user/admin`` cert.
    """
    proxy_app.dependency_overrides[get_authenticated_agent] = (
        lambda: _override_token(
            agent_id="acme::sales-bot",
            org="acme",
            principal_type="agent",
        )
    )
    csr_pem = _make_csr("spiffe://acme.test/acme/user/admin")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/admin",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 403, r.text
    detail = r.json()["detail"].lower()
    assert "workload" in detail or "ambassador" in detail


async def test_proxy_csr_403_user_principal_cannot_mint_user_cert(
    proxy_app, client,
):
    """A ``principal_type=user`` caller (e.g. a Frontdesk end-user
    presenting their own user cert) is also refused. The gate is
    strictly ``workload``, never ``user``.
    """
    proxy_app.dependency_overrides[get_authenticated_agent] = (
        lambda: _override_token(
            agent_id="acme::mario",
            org="acme",
            principal_type="user",
        )
    )
    csr_pem = _make_csr("spiffe://acme.test/acme/user/admin")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/admin",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 403, r.text


async def test_proxy_csr_workload_caller_passes_gate(proxy_app, client):
    """The legitimate Ambassador / Frontdesk workload caller passes
    the gate. Past the gate we hit the agent_manager 503 fallback
    because this minimal app doesn't carry a live Org CA. Anything
    other than 403 from the gate is what this test asserts; the 503
    is the expected next stop and confirms the gate let us through.
    """
    proxy_app.dependency_overrides[get_authenticated_agent] = (
        lambda: _override_token(
            agent_id="acme::frontdesk",
            org="acme",
            principal_type="workload",
        )
    )
    csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/mario",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code != 403, r.text
    # agent_manager is not wired in the minimal app → 503 is expected.
    assert r.status_code == 503, r.text


async def test_proxy_csr_agent_caller_for_agent_principal_passes_gate(
    proxy_app, client,
):
    """The gate keys on the principal-type segment of the requested
    ``principal_id``, not on the caller type globally. A regular agent
    caller can still submit a CSR for an ``agent`` principal — the
    legacy admin path stays open. Same agent_manager 503 confirms we
    moved past the gate.
    """
    proxy_app.dependency_overrides[get_authenticated_agent] = (
        lambda: _override_token(
            agent_id="acme::admin-cli",
            org="acme",
            principal_type="agent",
        )
    )
    csr_pem = _make_csr("spiffe://acme.test/acme/agent/sales-bot")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/agent/sales-bot",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code != 403, r.text
    assert r.status_code == 503, r.text


async def test_proxy_csr_403_cross_org_still_enforced(proxy_app, client):
    """The pre-existing org boundary check stays in place ahead of the
    F-001 gate. A workload caller in ``globex`` cannot mint a cert for
    an ``acme`` user, even though it is a workload.
    """
    proxy_app.dependency_overrides[get_authenticated_agent] = (
        lambda: _override_token(
            agent_id="globex::frontdesk",
            org="globex",
            principal_type="workload",
        )
    )
    csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/mario",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 403, r.text
    detail = r.json()["detail"].lower()
    assert "different org" in detail
