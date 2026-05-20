"""Tests for ADR-025 Phase 3 per-request cert middleware.

The middleware reads ``cullis_local_session`` from /v1/* requests,
resolves the user's :class:`UserCredentials` (cache-first, re-mint on
miss) and stashes the result on ``request.state.user_credentials``.

These tests exercise the middleware in isolation: a tiny FastAPI app
mounts the middleware + a probe endpoint that echoes
``request.state.user_credentials`` back so we can assert what the
middleware bound. The real Connector ``build_app`` integration is
covered by ``test_csr_flow.py``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from cullis_connector.ambassador.shared.credentials import (
    UserCredentialCache,
)
from cullis_connector.ambassador.shared.provisioning import MastioCsrError
from cullis_connector.auth.cert_middleware import install_cert_middleware
from cullis_connector.identity.csr_flow import (
    ENV_ORG_ID,
    ENV_TRUST_DOMAIN,
    LocalUserProvisioner,
)
from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    build_payload,
    issue_local_cookie,
)
from cullis_connector.identity.users_db import dispose_users_engines


COOKIE_SECRET = b"x" * 32


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


def _build_app(tmp_path, *, mastio: _StubMastio, env_overrides=None):
    """Compose a FastAPI app with the cert middleware + a probe route."""
    config_dir = tmp_path / "connector"
    config_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI()
    cache = UserCredentialCache()
    env = {
        ENV_TRUST_DOMAIN: "td.test",
        ENV_ORG_ID: "acme",
    }
    if env_overrides:
        env.update(env_overrides)
    provisioner = LocalUserProvisioner(mastio=mastio, cache=cache, env=env)
    app.state.local_provisioner = provisioner
    app.state.local_user_cache = cache
    app.state.local_cookie_secret = COOKIE_SECRET
    install_cert_middleware(app, config_dir=config_dir)

    @app.get("/v1/chat/completions")
    async def probe(request: Request):
        cred = getattr(request.state, "user_credentials", None)
        return JSONResponse({
            "principal_id": cred.principal_id if cred else None,
            "cert_pem_len": len(cred.cert_pem) if cred else 0,
        })

    @app.get("/healthz")
    async def healthz(request: Request):
        # Out-of-scope endpoint — middleware should not touch it.
        cred = getattr(request.state, "user_credentials", None)
        return JSONResponse({"bound": cred is not None})

    return app, config_dir, cache, provisioner


def _login_cookie(user_name: str = "mario", *, must_change: bool = False) -> str:
    payload = build_payload(
        user_name=user_name,
        must_change_password=must_change,
    )
    return issue_local_cookie(payload, COOKIE_SECRET)


# ── tests ────────────────────────────────────────────────────────────────


def test_install_twice_raises(tmp_path):
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    with pytest.raises(RuntimeError, match="already installed"):
        install_cert_middleware(app, config_dir=tmp_path)


def test_unguarded_route_passes_through(tmp_path):
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    r = tc.get("/healthz")
    assert r.status_code == 200
    assert r.json()["bound"] is False
    assert mastio.calls == []


def test_guarded_route_without_cookie_does_not_bind(tmp_path):
    """Missing cookie → middleware passes through without binding.

    The middleware itself never raises 401 — that decision belongs to
    the route's auth dependency. Here the probe endpoint just echoes
    ``user_credentials = None``.
    """
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    r = tc.get("/v1/chat/completions")
    assert r.status_code == 200
    assert r.json()["principal_id"] is None
    assert mastio.calls == []


def test_guarded_route_with_invalid_cookie_does_not_bind(tmp_path):
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, "garbage.value")
    r = tc.get("/v1/chat/completions")
    assert r.status_code == 200
    assert r.json()["principal_id"] is None
    assert mastio.calls == []


def test_guarded_route_with_valid_cookie_provisions_and_binds(tmp_path):
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("mario"))
    r = tc.get("/v1/chat/completions")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["principal_id"] == "td.test/acme/user/mario"
    assert body["cert_pem_len"] > 0
    assert len(mastio.calls) == 1


def test_guarded_route_cache_hit_skips_mastio(tmp_path):
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    cookie = _login_cookie("mario")
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, cookie)
    tc.get("/v1/chat/completions")
    tc.get("/v1/chat/completions")
    tc.get("/v1/chat/completions")
    # First call mints, the next two are pure cache hits.
    assert len(mastio.calls) == 1


def test_guarded_route_with_unwired_app_passes_through(tmp_path):
    """Without ``app.state.local_provisioner`` the middleware is a no-op.

    Lets a single-mode (Bearer) ambassador share the same dashboard
    process without having a local provisioner forced on it.
    """
    config_dir = tmp_path / "connector"
    config_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI()
    install_cert_middleware(app, config_dir=config_dir)

    @app.get("/v1/chat/completions")
    async def probe(request: Request):
        cred = getattr(request.state, "user_credentials", None)
        return JSONResponse({"bound": cred is not None})

    tc = TestClient(app)
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("mario"))
    r = tc.get("/v1/chat/completions")
    assert r.status_code == 200
    assert r.json()["bound"] is False


def test_provisioning_failure_returns_none_credentials(tmp_path):
    failing = _StubMastio(
        fail_with=MastioCsrError("Mastio /v1/principals/csr returned 503"),
    )
    app, *_ = _build_app(tmp_path, mastio=failing)
    tc = TestClient(app)
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("mario"))
    r = tc.get("/v1/chat/completions")
    # Middleware swallows the error and returns request.state.user_credentials = None
    # so the route can decide what to do (the probe shows None).
    assert r.status_code == 200
    assert r.json()["principal_id"] is None
    # Mastio was hit (and failed). Future requests will keep retrying
    # (cache stays empty).
    assert len(failing.calls) == 1
    r2 = tc.get("/v1/chat/completions")
    assert r2.json()["principal_id"] is None
    assert len(failing.calls) == 2


def test_expired_cert_in_cache_triggers_remint(tmp_path):
    """LRU cache lazy-expires past ``not_after`` → middleware re-mints."""
    mastio = _StubMastio(
        # Cert that's already expired; cache.get will see it stale.
        not_after=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    app, _config_dir, cache, _provisioner = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("mario"))
    tc.get("/v1/chat/completions")
    tc.get("/v1/chat/completions")
    # Each request observes a stale cache entry and re-mints; the
    # cache never holds a fresh entry because the stub returns a
    # past not_after.
    assert len(mastio.calls) == 2


def test_persisted_binding_survives_provisioner_swap(tmp_path):
    """A new provisioner sharing the same users.db re-resolves the binding."""
    mastio = _StubMastio()
    app, config_dir, cache, _ = _build_app(tmp_path, mastio=mastio)
    tc = TestClient(app)
    cookie = _login_cookie("mario")
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, cookie)
    r = tc.get("/v1/chat/completions")
    assert r.status_code == 200
    assert len(mastio.calls) == 1

    # Simulate a process restart: drop the in-memory cache so the
    # next request falls through to re-provisioning.
    import asyncio
    asyncio.get_event_loop().run_until_complete(
        cache.invalidate("td.test/acme/user/mario")
    )

    # Same cookie still works — middleware re-mints transparently.
    r2 = tc.get("/v1/chat/completions")
    assert r2.status_code == 200
    assert r2.json()["principal_id"] == "td.test/acme/user/mario"
    assert len(mastio.calls) == 2


def test_distinct_users_get_distinct_principals(tmp_path):
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)
    tc1 = TestClient(app)
    tc1.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("mario"))
    tc2 = TestClient(app)
    tc2.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("anna"))

    r1 = tc1.get("/v1/chat/completions")
    r2 = tc2.get("/v1/chat/completions")
    assert r1.json()["principal_id"] == "td.test/acme/user/mario"
    assert r2.json()["principal_id"] == "td.test/acme/user/anna"
    # Each user triggers exactly one CSR call.
    seen = sorted(p for p, _ in mastio.calls)
    assert seen == ["td.test/acme/user/anna", "td.test/acme/user/mario"]


# ── 2026-05-20 CRITICAL regression: /v1/conversations cross-user leak ──


def test_guarded_prefixes_includes_v1_conversations():
    """Sentinel: ``/v1/conversations`` MUST stay in ``_GUARDED_PREFIXES``.

    Before 2026-05-20 the prefix was missing. Effect: the middleware
    skipped binding ``request.state.user_credentials`` on
    ``/v1/conversations*`` requests, so
    ``conversations_router._authenticate`` fell back to the Connector
    agent_id (one shared identity for the whole process) for every
    enrolled Frontdesk user. All chat history collapsed onto the same
    ``principal_id``, leaking READ + WRITE across users.

    Removing this prefix again would silently re-introduce the leak.
    """
    from cullis_connector.auth.cert_middleware import _GUARDED_PREFIXES

    assert "/v1/conversations" in _GUARDED_PREFIXES, (
        "CRITICAL regression — /v1/conversations dropped from "
        "_GUARDED_PREFIXES; cross-user chat history leak resurfaces"
    )


def test_v1_conversations_binds_per_user_principal(tmp_path):
    """End-to-end: with the guard in place, two distinct cookies on
    ``/v1/conversations`` must resolve to two distinct
    ``request.state.user_credentials.principal_id``s.

    Pre-fix this test would PASS the gate (no 401 — middleware is
    silent) but FAIL the assertion because both users got
    ``principal_id=None`` (middleware skipped the path) and the
    downstream router's fallback to ``state.agent_id`` would collapse
    them. Post-fix both users get their own principal_id.
    """
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)

    @app.get("/v1/conversations")
    async def probe_conv(request: Request):
        cred = getattr(request.state, "user_credentials", None)
        return JSONResponse({
            "principal_id": cred.principal_id if cred else None,
        })

    tc_alice = TestClient(app)
    tc_alice.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("alice"))
    tc_bob = TestClient(app)
    tc_bob.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("bob"))

    r_alice = tc_alice.get("/v1/conversations")
    r_bob = tc_bob.get("/v1/conversations")

    assert r_alice.status_code == 200
    assert r_bob.status_code == 200
    pid_alice = r_alice.json()["principal_id"]
    pid_bob = r_bob.json()["principal_id"]
    assert pid_alice is not None, (
        "/v1/conversations not guarded by cert middleware — "
        "user_credentials not bound"
    )
    assert pid_bob is not None
    assert pid_alice != pid_bob, (
        "CRITICAL — distinct users got SAME principal_id on "
        "/v1/conversations (cross-user leak)"
    )
    assert pid_alice == "td.test/acme/user/alice"
    assert pid_bob == "td.test/acme/user/bob"


def test_v1_conversations_subpaths_also_guarded(tmp_path):
    """``/v1/conversations/{id}`` and ``/v1/conversations/{id}/messages``
    must also be guarded (prefix match)."""
    mastio = _StubMastio()
    app, *_ = _build_app(tmp_path, mastio=mastio)

    @app.get("/v1/conversations/{conv_id}")
    async def probe_conv_id(conv_id: str, request: Request):
        cred = getattr(request.state, "user_credentials", None)
        return JSONResponse({
            "principal_id": cred.principal_id if cred else None,
        })

    @app.post("/v1/conversations/{conv_id}/messages")
    async def probe_conv_messages(conv_id: str, request: Request):
        cred = getattr(request.state, "user_credentials", None)
        return JSONResponse({
            "principal_id": cred.principal_id if cred else None,
        })

    tc = TestClient(app)
    tc.cookies.set(LOCAL_SESSION_COOKIE_NAME, _login_cookie("carol"))

    r_get = tc.get("/v1/conversations/abc123")
    r_post = tc.post("/v1/conversations/abc123/messages")
    assert r_get.json()["principal_id"] == "td.test/acme/user/carol"
    assert r_post.json()["principal_id"] == "td.test/acme/user/carol"
