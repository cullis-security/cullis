"""Integration tests for ADR-025 Phase 3 post-login CSR flow.

Covers:

  - PrincipalCoordinates env resolution (default + override)
  - LocalUserProvisioner cache-miss + cache-hit + Mastio failure
  - End-to-end ``/api/auth/login`` with stubbed Mastio:
      * cert minted + cached + bound to session row
      * second /v1/* request reuses the in-process cache
      * Mastio failure returns ``provisioning="deferred"`` + header
  - ``/api/auth/reprovision`` endpoint
  - Persisted binding row visible across login + lookup
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.xdist_group(name="serial_csr_flow")

from cullis_connector.ambassador.shared.credentials import (
    UserCredentialCache,
)
from cullis_connector.ambassador.shared.provisioning import MastioCsrError
from cullis_connector.config import ConnectorConfig
from cullis_connector.identity.cert_session_map import (
    derive_session_id,
    lookup_binding,
)
from cullis_connector.identity.csr_flow import (
    DEFAULT_ORG_ID,
    DEFAULT_TRUST_DOMAIN,
    ENV_ORG_ID,
    ENV_TRUST_DOMAIN,
    LocalProvisioningError,
    LocalUserProvisioner,
    resolve_principal_coordinates,
)
from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    parse_local_cookie,
)
from cullis_connector.identity.users_db import dispose_users_engines
from cullis_connector.web import build_app


ADMIN_SECRET = "test-admin-secret-not-default"


def _self_signed_cert_pem() -> str:
    """Build a self-signed P-256 cert PEM for thumbprint computations."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    priv = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-cert"),
    ])
    not_before = datetime.now(timezone.utc) - timedelta(minutes=1)
    not_after = datetime.now(timezone.utc) + timedelta(hours=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(priv, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


FAKE_CERT_PEM = _self_signed_cert_pem()


# ── stub transport ───────────────────────────────────────────────────────


class _StubMastio:
    """Records calls + returns canned cert. Compatible with MastioCsrTransport."""

    def __init__(
        self,
        *,
        cert_pem: str | None = None,
        not_after: datetime | None = None,
        fail_with: Exception | None = None,
    ) -> None:
        self.cert_pem = cert_pem if cert_pem is not None else FAKE_CERT_PEM
        self.not_after = (
            not_after
            if not_after is not None
            else datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.fail_with = fail_with
        self.calls: list[tuple[str, str]] = []

    async def sign_csr(self, *, principal_id: str, csr_pem: str):
        self.calls.append((principal_id, csr_pem))
        if self.fail_with is not None:
            raise self.fail_with
        return self.cert_pem, self.not_after


# ── fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def _cleanup_engines():
    yield
    await dispose_users_engines()


@pytest.fixture
def connector_config(tmp_path):
    cfg = ConnectorConfig(
        config_dir=tmp_path / "connector",
        site_url="http://mastio.test",
        verify_tls=False,
    )
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    return cfg


@pytest.fixture
def stub_mastio():
    return _StubMastio()


@pytest.fixture
def client(connector_config, stub_mastio, monkeypatch):
    """Build the connector app + inject a stubbed LocalUserProvisioner.

    The boot-time wiring in ``web.py`` only mounts the real
    ``SdkMastioCsrTransport`` when an agent identity exists on disk.
    These tests focus on the post-login CSR flow itself, so we
    sidestep the agent-identity prerequisite by stubbing the
    provisioner directly on ``app.state``.
    """
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("CULLIS_CONNECTOR_DEV", "1")
    monkeypatch.setenv("CULLIS_FRONTDESK_TRUST_DOMAIN", "td.test")
    monkeypatch.setenv("CULLIS_FRONTDESK_ORG_ID", "acme")
    app = build_app(connector_config)
    cache = UserCredentialCache()
    provisioner = LocalUserProvisioner(mastio=stub_mastio, cache=cache)
    app.state.local_user_cache = cache
    app.state.local_provisioner = provisioner
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"
    return tc


def _admin_headers() -> dict[str, str]:
    return {"X-Admin-Secret": ADMIN_SECRET}


def _create_user(
    client: TestClient,
    *,
    user_name: str,
    password: str,
    must_change: bool = False,
) -> None:
    r = client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": user_name,
            "password": password,
            "must_change_password": must_change,
        },
    )
    assert r.status_code == 201, r.text


# ── PrincipalCoordinates ────────────────────────────────────────────────


def test_resolve_principal_coordinates_uses_env():
    coords = resolve_principal_coordinates(
        "mario",
        env={ENV_TRUST_DOMAIN: "acme.test", ENV_ORG_ID: "acme"},
    )
    assert coords.principal_id == "acme.test/acme/user/mario"
    assert coords.spiffe_uri == "spiffe://acme.test/acme/user/mario"


def test_resolve_principal_coordinates_defaults_on_missing_env():
    coords = resolve_principal_coordinates("mario", env={})
    assert coords.trust_domain == DEFAULT_TRUST_DOMAIN
    assert coords.org_id == DEFAULT_ORG_ID
    assert coords.principal_id == f"{DEFAULT_TRUST_DOMAIN}/{DEFAULT_ORG_ID}/user/mario"


def test_resolve_principal_coordinates_rejects_empty_user_name():
    with pytest.raises(ValueError):
        resolve_principal_coordinates("", env={})
    with pytest.raises(ValueError):
        resolve_principal_coordinates("   ", env={})


# ── LocalUserProvisioner unit tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_local_provisioner_cache_miss_then_hit(stub_mastio):
    cache = UserCredentialCache()
    p = LocalUserProvisioner(
        mastio=stub_mastio,
        cache=cache,
        env={ENV_TRUST_DOMAIN: "td.test", ENV_ORG_ID: "acme"},
    )

    cred = await p.provision_for_user("mario")
    assert cred.principal_id == "td.test/acme/user/mario"
    assert cred.cert_pem == stub_mastio.cert_pem
    assert len(stub_mastio.calls) == 1

    # Second call hits the cache → no extra Mastio roundtrip.
    cred2 = await p.provision_for_user("mario")
    assert cred2 == cred
    assert len(stub_mastio.calls) == 1


@pytest.mark.asyncio
async def test_local_provisioner_wraps_mastio_error():
    stub = _StubMastio(fail_with=MastioCsrError("Mastio said no"))
    cache = UserCredentialCache()
    p = LocalUserProvisioner(
        mastio=stub,
        cache=cache,
        env={ENV_TRUST_DOMAIN: "td.test", ENV_ORG_ID: "acme"},
    )
    with pytest.raises(LocalProvisioningError, match="Mastio said no"):
        await p.provision_for_user("mario")
    # Cache stays empty so a retry triggers a fresh attempt.
    assert await cache.size() == 0


@pytest.mark.asyncio
async def test_local_provisioner_invalidate_drops_entry(stub_mastio):
    cache = UserCredentialCache()
    p = LocalUserProvisioner(
        mastio=stub_mastio,
        cache=cache,
        env={ENV_TRUST_DOMAIN: "td.test", ENV_ORG_ID: "acme"},
    )
    await p.provision_for_user("mario")
    assert await cache.size() == 1
    assert await p.invalidate("mario") is True
    assert await cache.size() == 0


# ── /api/auth/login → CSR happy path ────────────────────────────────────


def test_login_mints_cert_and_binds_session(
    client, stub_mastio, connector_config,
):
    _create_user(
        client, user_name="mario", password="longpassword", must_change=False,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["provisioning"] == "ok"
    assert "X-Cullis-Provisioning-Failed" not in r.headers

    # Mastio was called exactly once with the right principal_id.
    assert len(stub_mastio.calls) == 1
    assert stub_mastio.calls[0][0] == "td.test/acme/user/mario"
    assert "BEGIN CERTIFICATE REQUEST" in stub_mastio.calls[0][1]

    # Cookie carries the session iat — derive the same session_id and
    # confirm the binding row landed in users.db.
    raw = r.cookies.get(LOCAL_SESSION_COOKIE_NAME)
    assert raw
    secret = (connector_config.config_dir / "cookie.secret").read_bytes()
    payload = parse_local_cookie(raw, secret)
    assert payload is not None
    session_id = derive_session_id(
        iat=payload.iat, user_name=payload.user_name,
    )

    import asyncio

    async def _read():
        return await lookup_binding(connector_config.config_dir, session_id)

    binding = asyncio.get_event_loop().run_until_complete(_read())
    assert binding is not None
    assert binding.principal_id == "td.test/acme/user/mario"
    assert binding.user_name == "mario"
    assert binding.cert_thumbprint  # may be empty string only if cert pem invalid


def test_login_must_change_skips_provisioning(client, stub_mastio):
    _create_user(
        client, user_name="mario", password="oldpassword", must_change=True,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "oldpassword"},
    )
    assert r.status_code == 200
    assert r.json()["provisioning"] == "skipped"
    assert len(stub_mastio.calls) == 0


def test_change_password_provisions_after_change(client, stub_mastio):
    _create_user(
        client, user_name="mario", password="oldpassword", must_change=True,
    )
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "oldpassword"},
    )
    # No CSR call yet (must_change skipped it).
    assert len(stub_mastio.calls) == 0
    r = client.post(
        "/api/auth/change-password",
        json={
            "old_password": "oldpassword",
            "new_password": "fresh-and-long-enough",
        },
    )
    assert r.status_code == 200
    # Cert minted now that the post-change session is the active one.
    assert len(stub_mastio.calls) == 1


# ── Mastio failure → deferred ───────────────────────────────────────────


def test_login_mastio_failure_returns_deferred(connector_config, monkeypatch):
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("CULLIS_CONNECTOR_DEV", "1")
    monkeypatch.setenv("CULLIS_FRONTDESK_TRUST_DOMAIN", "td.test")
    monkeypatch.setenv("CULLIS_FRONTDESK_ORG_ID", "acme")

    failing_mastio = _StubMastio(
        fail_with=MastioCsrError("Mastio /v1/principals/csr returned 503"),
    )
    app = build_app(connector_config)
    cache = UserCredentialCache()
    app.state.local_user_cache = cache
    app.state.local_provisioner = LocalUserProvisioner(
        mastio=failing_mastio, cache=cache,
    )
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"

    tc.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario",
            "password": "longpassword",
            "must_change_password": False,
        },
    )
    r = tc.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Login succeeded so the cookie is set + the user is allowed in.
    assert body["ok"] is True
    assert body["must_change_password"] is False
    # But the SPA is told to render a banner.
    assert body["provisioning"] == "deferred"
    assert r.headers.get("X-Cullis-Provisioning-Failed") == "true"
    assert "503" in r.headers.get("X-Cullis-Provisioning-Detail", "")
    assert LOCAL_SESSION_COOKIE_NAME in r.cookies


# ── /api/auth/reprovision ───────────────────────────────────────────────


def test_reprovision_requires_session(client):
    r = client.post("/api/auth/reprovision")
    assert r.status_code == 401


def test_reprovision_returns_cached_when_recent_login(client, stub_mastio):
    _create_user(
        client, user_name="mario", password="longpassword", must_change=False,
    )
    client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert len(stub_mastio.calls) == 1
    r = client.post("/api/auth/reprovision")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["cached"] is True
    assert body["principal_id"] == "td.test/acme/user/mario"
    # No extra Mastio roundtrip — the cache was warm.
    assert len(stub_mastio.calls) == 1


def test_reprovision_after_failure_succeeds_when_mastio_recovers(
    connector_config, monkeypatch,
):
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("CULLIS_CONNECTOR_DEV", "1")
    monkeypatch.setenv("CULLIS_FRONTDESK_TRUST_DOMAIN", "td.test")
    monkeypatch.setenv("CULLIS_FRONTDESK_ORG_ID", "acme")

    flaky = _StubMastio(
        fail_with=MastioCsrError("Mastio /v1/principals/csr returned 503"),
    )
    app = build_app(connector_config)
    cache = UserCredentialCache()
    provisioner = LocalUserProvisioner(mastio=flaky, cache=cache)
    app.state.local_user_cache = cache
    app.state.local_provisioner = provisioner
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"

    tc.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario",
            "password": "longpassword",
            "must_change_password": False,
        },
    )
    r1 = tc.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r1.json()["provisioning"] == "deferred"

    # Manual retry while Mastio is still down — returns 502.
    r2 = tc.post("/api/auth/reprovision")
    assert r2.status_code == 502
    assert r2.headers.get("X-Cullis-Provisioning-Failed") == "true"
    assert r2.json()["ok"] is False

    # Mastio recovers — next retry mints + caches.
    flaky.fail_with = None
    r3 = tc.post("/api/auth/reprovision")
    assert r3.status_code == 200, r3.text
    body = r3.json()
    assert body["ok"] is True
    assert body["cached"] is False
    assert body["principal_id"] == "td.test/acme/user/mario"


# ── logout drops binding ────────────────────────────────────────────────


def test_logout_drops_persisted_binding(
    client, stub_mastio, connector_config,
):
    _create_user(
        client, user_name="mario", password="longpassword", must_change=False,
    )
    r = client.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    raw = r.cookies.get(LOCAL_SESSION_COOKIE_NAME)
    secret = (connector_config.config_dir / "cookie.secret").read_bytes()
    payload = parse_local_cookie(raw, secret)
    session_id = derive_session_id(
        iat=payload.iat, user_name=payload.user_name,
    )

    import asyncio
    async def _read():
        return await lookup_binding(connector_config.config_dir, session_id)
    assert asyncio.get_event_loop().run_until_complete(_read()) is not None

    r2 = client.post("/api/auth/logout")
    assert r2.status_code == 200

    assert asyncio.get_event_loop().run_until_complete(_read()) is None


# ── No provisioner wired (skipped path) ─────────────────────────────────


def test_login_returns_skipped_when_no_provisioner(connector_config, monkeypatch):
    """Pre-enrollment / unwired: login still works, no CSR attempted."""
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("CULLIS_CONNECTOR_DEV", "1")
    app = build_app(connector_config)
    # Deliberately leave app.state.local_provisioner unset.
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"

    tc.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario",
            "password": "longpassword",
            "must_change_password": False,
        },
    )
    r = tc.post(
        "/api/auth/login",
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["provisioning"] == "skipped"
    assert "X-Cullis-Provisioning-Failed" not in r.headers
