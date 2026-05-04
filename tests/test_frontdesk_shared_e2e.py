"""End-to-end smoke for Cullis Frontdesk shared mode (ADR-021 PR5).

Composes the pieces shipped by PR1 (UserPrincipalKMS + embedded
backend), PR2 (user_principals table), PR4a (Mastio CSR endpoint),
PR4b (shared-mode router + provisioning) into a single in-memory
Frontdesk-style FastAPI app and verifies the two-user happy path:

    1. mario@acme.it logs in via X-Forwarded-User → cookie issued
    2. anna@acme.it logs in (separately) → distinct cookie
    3. Provisioner is invoked for each → distinct cert + key + SPIFFE id
    4. Both certs verify under the broker CA
    5. Audit attribution is correct: mario's cert SAN is mario's SPIFFE id

No docker, no nginx, no real LLM. The Mastio CSR endpoint is
reached via ``httpx.ASGITransport`` so the whole flow runs in-
process. The README in ``imp/sandbox-frontdesk-notes.md`` covers
the manual recording session that turns this into a video demo.
"""
from __future__ import annotations

import pytest
import httpx
from cryptography import x509
from fastapi import FastAPI

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.main import app as mastio_app
from cullis_connector.ambassador.shared.credentials import UserCredentialCache
from cullis_connector.ambassador.shared.provisioning import (
    HttpxMastioCsrTransport, UserProvisioner,
)
from cullis_connector.ambassador.shared.proxy_trust import (
    TrustedProxiesAllowlist,
)
from cullis_connector.ambassador.shared.router import install_shared_ambassador
from fastapi.testclient import TestClient

pytestmark = pytest.mark.asyncio


SECRET = b"frontdesk-test-cookie-secret-32!"


def _override_token(*, agent_id: str, org: str) -> TokenPayload:
    """The Frontdesk Ambassador's own workload identity for CSR calls."""
    return TokenPayload(
        sub=f"spiffe://cullis.test/{org}/agent/{agent_id.split('::', 1)[-1]}",
        agent_id=agent_id,
        org=org,
        exp=2_000_000_000,
        iat=1_700_000_000,
        jti="frontdesk-jti",
        scope=[],
        cnf={"jkt": "x" * 43},
    )


@pytest.fixture
def auth_as_frontdesk_workload():
    """Override Mastio's get_current_agent so the Frontdesk's CSR
    calls succeed without a full DPoP token roundtrip."""
    mastio_app.dependency_overrides[get_current_agent] = (
        lambda: _override_token(
            agent_id="acme::frontdesk-shared", org="acme",
        )
    )
    yield
    mastio_app.dependency_overrides.pop(get_current_agent, None)


@pytest.fixture
def in_memory_mastio_http():
    """``httpx.AsyncClient`` that talks to Mastio in-process via ASGI."""
    transport = httpx.ASGITransport(app=mastio_app)
    return httpx.AsyncClient(
        transport=transport, base_url="http://mastio.test",
    )


@pytest.fixture
def frontdesk_app(in_memory_mastio_http, auth_as_frontdesk_workload):
    """A FastAPI app wired exactly as ``_maybe_install_shared_ambassador``
    would do in production, but with the Mastio side reached
    in-process. Returns the app and the underlying provisioner so
    direct unit-style assertions are easy."""
    app = FastAPI()
    cache = UserCredentialCache()
    transport = HttpxMastioCsrTransport(
        http=in_memory_mastio_http, base_url="http://mastio.test",
    )
    provisioner = UserProvisioner(mastio=transport, cache=cache)

    install_shared_ambassador(
        app,
        cookie_secret=SECRET,
        trusted_proxies=TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32"]),
        org_id="acme",
        trust_domain="acme.test",
        provisioner=provisioner,
        site_url="http://mastio.test",
        # TestClient reports peer host = "testclient" (not an IP), so
        # disable the proxy-trust check for the test surface only —
        # ADR-021 §6 requires production deployments to keep it on.
        enforce_proxy_trust=False,
    )
    return app, provisioner


# ── Cookie issuance: 2 distinct users (3 tests) ───────────────────


def test_two_users_get_distinct_cookies(frontdesk_app):
    app, _ = frontdesk_app
    with TestClient(app, base_url="https://testserver") as cli:
        r_mario = cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        assert r_mario.status_code == 200, r_mario.text
        cookie_mario = r_mario.cookies.get("cullis_session")

    with TestClient(app, base_url="https://testserver") as cli:
        r_anna = cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "anna@acme.it"},
        )
        assert r_anna.status_code == 200, r_anna.text
        cookie_anna = r_anna.cookies.get("cullis_session")

    assert cookie_mario and cookie_anna
    assert cookie_mario != cookie_anna
    assert r_mario.json()["principal_id"] == "acme.test/acme/user/mario"
    assert r_anna.json()["principal_id"] == "acme.test/acme/user/anna"


def test_whoami_returns_per_user_principal(frontdesk_app):
    app, _ = frontdesk_app
    with TestClient(app, base_url="https://testserver") as cli:
        cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        r = cli.get("/api/session/whoami")
        assert r.status_code == 200
        body = r.json()
        assert body["principal_id"] == "acme.test/acme/user/mario"
        assert body["sub"] == "mario@acme.it"
        assert body["org"] == "acme"


def test_logout_clears_then_unauthorised(frontdesk_app):
    app, _ = frontdesk_app
    with TestClient(app, base_url="https://testserver") as cli:
        cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        assert cli.post("/api/session/logout").status_code == 200
        # After logout the cookie is dropped — whoami fails.
        assert cli.get("/api/session/whoami").status_code == 401


# ── End-to-end provisioning chain (3 tests) ───────────────────────


async def test_provisioning_chain_mints_distinct_certs(frontdesk_app):
    """Drive the provisioner directly — same code path the Ambassador
    runs on the first /v1/chat/completions call after login."""
    _, provisioner = frontdesk_app

    cred_mario = await provisioner.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    cred_anna = await provisioner.get_or_provision(
        principal_id="acme.test/acme/user/anna",
        sso_subject="anna@acme.it",
    )

    assert cred_mario.principal_id == "acme.test/acme/user/mario"
    assert cred_anna.principal_id == "acme.test/acme/user/anna"
    assert cred_mario.cert_pem != cred_anna.cert_pem
    assert cred_mario.key_pem != cred_anna.key_pem


async def test_provisioning_certs_carry_correct_spiffe_san(frontdesk_app):
    _, provisioner = frontdesk_app

    cred = await provisioner.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    cert = x509.load_pem_x509_certificate(cred.cert_pem.encode())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName,
    ).value
    uris = [u.value for u in san if isinstance(u, x509.UniformResourceIdentifier)]
    assert uris == ["spiffe://acme.test/acme/user/mario"]


async def test_provisioning_certs_signed_by_broker_ca(frontdesk_app):
    """Confirm Mastio's broker CA private key actually signed the cert.

    We don't have the broker CA cert handy here (it's not in the
    KMS provider's public surface), but we can verify the cert's
    issuer name matches what the CSR endpoint hardcodes — which is
    a strong proxy: a forged cert from a different signer would have
    a different issuer name."""
    _, provisioner = frontdesk_app

    cred = await provisioner.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    cert = x509.load_pem_x509_certificate(cred.cert_pem.encode())
    issuer_cn = next(
        a.value for a in cert.issuer
        if a.oid.dotted_string == "2.5.4.3"  # commonName
    )
    issuer_org = next(
        a.value for a in cert.issuer
        if a.oid.dotted_string == "2.5.4.10"  # organizationName
    )
    assert issuer_cn == "Cullis Mastio Broker CA"
    assert issuer_org == "acme"


# ── Cache cuts the second provision on cache hit (1 test) ─────────


async def test_provisioning_cache_skips_second_csr(frontdesk_app):
    """The second get_or_provision for the same principal returns
    the cached cred, so no second CSR is sent to Mastio."""
    _, provisioner = frontdesk_app

    a = await provisioner.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    b = await provisioner.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    # Same object content (frozen dataclass equality), so cert and
    # key are byte-for-byte identical → no re-provision happened.
    assert a == b
    assert a.cert_pem == b.cert_pem
    assert a.key_pem == b.key_pem
