"""Regression tests for the Ambassador post-enrollment install hook.

Architectural bug discovered 2026-05-17 during a demo smoke run:

  * In the Frontdesk bundle the Connector container starts BEFORE
    the operator drives the enrollment wizard (the wizard *is*
    served by the Connector dashboard). At that boot,
    ``_dashboard_lifespan`` calls ``_maybe_install_ambassador``,
    sees ``has_identity()=False`` on the still-empty profile, and
    returns early. The router is never mounted.

  * After the admin approves the enrollment ticket, the on-disk
    identity lands but the Ambassador stays unmounted, so every
    ``/v1/chat/completions``, ``/v1/models``, ``/api/session/*`` 404s.

  * Pre-fix the only way out was a manual ``docker compose restart
    cullis-frontdesk-connector-1``. No customer admin will do that.

The fix in ``cullis_connector/web.py``:

  1. ``_maybe_install_ambassador`` and ``_maybe_install_shared_ambassador``
     gained an early-return idempotency guard so they can be called more
     than once on the same FastAPI app without tripping the loud
     ``RuntimeError`` raised by ``install_ambassador`` on double-mount.

  2. A new helper ``_ensure_ambassador_installed`` dispatches to the
     single or shared variant based on ``AMBASSADOR_MODE`` and swallows
     install errors (logs + returns False) so an Ambassador wiring
     failure never blocks the enrollment "approved" response.

  3. ``/api/status`` calls the helper both in the ``has_identity``
     early-return branch (covers polling on an already-enrolled
     profile after a pre-enrollment dashboard boot) and right after
     ``save_identity`` succeeds on the approved-polling path.

These tests pin all four legs of the contract so a future refactor that
drops the hook is caught immediately by ``pytest``.
"""
from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cullis_connector import web as connector_web
from cullis_connector.config import ConnectorConfig
from cullis_connector.identity import generate_keypair, save_identity
from cullis_connector.identity.store import IdentityMetadata
from cullis_connector.web import (
    RequesterInfo,
    _ensure_ambassador_installed,
    _maybe_install_ambassador,
    build_app,
)


# ── helpers ─────────────────────────────────────────────────────────


def _self_signed_cert_pem(private_key, *, common_name: str) -> str:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, common_name.split("::", 1)[0],
        ),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _seed_identity(
    config_dir: Path, *, agent_id: str = "acme::frontdesk",
) -> None:
    key = generate_keypair()
    cert_pem = _self_signed_cert_pem(key, common_name=agent_id)
    metadata = IdentityMetadata(
        agent_id=agent_id,
        capabilities=[],
        site_url="https://mastio.test",
        issued_at="2026-05-17T10:00:00+00:00",
    )
    save_identity(
        config_dir=config_dir,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem=None,
        metadata=metadata,
    )


class _FakeCullisClient:
    """No-op stand-in for ``cullis_sdk.CullisClient``.

    The Ambassador's ``install_ambassador`` only constructs the holder
    (``AmbassadorClient``); the actual SDK login is lazy on first
    ``/v1/chat/completions`` so a no-op fake is enough for the install
    path. Inbox poller bootstrap also calls ``from_connector`` which
    we cover with the no-arg classmethod below.
    """

    @classmethod
    def from_connector(cls, *args, **kwargs):
        return cls()

    def __init__(self, *args, **kwargs) -> None:
        self.identity = None
        self.agent_id = ""

    def close(self) -> None:
        pass

    def list_inbox(self, *args, **kwargs):
        return []

    def discover(self, *args, **kwargs):
        return []

    def login_from_pem(self, *args, **kwargs) -> None:
        pass


@pytest.fixture(autouse=True)
def _patch_sdk(monkeypatch):
    monkeypatch.setattr("cullis_sdk.CullisClient", _FakeCullisClient)
    # Make sure the test isn't running in shared-mode by accident
    # (env may have AMBASSADOR_MODE set from a sibling test).
    monkeypatch.delenv("AMBASSADOR_MODE", raising=False)
    yield


@pytest.fixture
def cfg(tmp_path: Path) -> ConnectorConfig:
    cfg = ConnectorConfig(
        site_url="https://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    # TestClient sends client.host=testclient, which is rejected by
    # the loopback gate. Disable for unit tests; production keeps it on.
    cfg.ambassador.require_local_only = False
    return cfg


@pytest.fixture
def fresh_app_pre_enrollment(cfg):
    """App built with NO identity on disk yet.

    Mirrors the Frontdesk bundle's boot: the Connector container starts
    before the operator runs the enrollment wizard. The lifespan will
    skip the Ambassador mount because ``has_identity()`` is False.
    """
    return build_app(cfg)


@pytest.fixture
def enrolled_app(cfg):
    """App built with an identity already on disk before lifespan runs.

    Mirrors a normal restart after a successful enrollment — the
    lifespan should mount the Ambassador on its own.
    """
    _seed_identity(cfg.config_dir)
    return build_app(cfg)


# ── tests ───────────────────────────────────────────────────────────


def test_ambassador_unmounted_when_app_boots_pre_enrollment(
    fresh_app_pre_enrollment,
):
    """Bug repro: Connector booted before enrollment → no Ambassador.

    This is the pre-fix state we are explicitly NOT trying to remove —
    boot-time mount is still gated on identity presence. What we ARE
    fixing is the absence of a recovery path when identity lands later;
    the other tests in this file exercise that.
    """
    with TestClient(fresh_app_pre_enrollment) as client:
        resp = client.get("/v1/ambassador/health")
    # FastAPI returns 404 for routes that were never mounted.
    assert resp.status_code == 404
    assert (
        getattr(fresh_app_pre_enrollment.state, "ambassador", None) is None
    )


def test_ambassador_mounts_lazily_when_identity_appears_then_status_polls(
    fresh_app_pre_enrollment, cfg,
):
    """The Frontdesk bundle's primary recovery path.

    The Connector boots empty, the operator completes the wizard via
    a different code path (CLI ``cullis users add`` or the shared-mode
    SSO subject populates the identity directly), and the dashboard's
    ``/api/status`` poller hits the ``has_identity`` early-return branch.
    That branch must trigger the lazy Ambassador install so the SPA's
    next request to ``/v1/chat/completions`` actually reaches the router.
    """
    with TestClient(fresh_app_pre_enrollment) as client:
        # 1. Pre-enrollment: router not mounted.
        assert client.get("/v1/ambassador/health").status_code == 404

        # 2. Identity lands on disk (simulates the side-channel that
        #    can write identity without going through /api/status,
        #    e.g. CLI enrollment or shared-mode bootstrap).
        _seed_identity(cfg.config_dir)

        # 3. The next ``/api/status`` poll hits the ``has_identity``
        #    branch and must lazily mount the Ambassador.
        status = client.get("/api/status")
        assert status.status_code == 200
        assert status.json()["status"] == "approved"

        # 4. Router is now live and unauth health surfaces agent_id.
        health = client.get("/v1/ambassador/health")
        assert health.status_code == 200
        body = health.json()
        assert body["status"] == "ok"
        assert body["agent_id"] == "acme::frontdesk"

    assert (
        getattr(fresh_app_pre_enrollment.state, "ambassador", None)
        is not None
    )


def test_ambassador_mounts_after_admin_approved_polling_flow(
    fresh_app_pre_enrollment, cfg, monkeypatch,
):
    """The HTMX wizard path: ``/api/status`` polls the proxy, gets the
    approved record (cert_pem + agent_id), persists the identity, and
    must mount the Ambassador BEFORE returning ``{"status": "approved"}``
    so the SPA's first chat request lands on a live router."""
    cert_pem = _self_signed_cert_pem(
        generate_keypair(), common_name="acme::wizard-agent",
    )

    # Install a pending session as if the wizard had just submitted
    # the enrollment request.
    pending_key = ec.generate_private_key(ec.SECP256R1())
    prev = connector_web._pending
    connector_web._pending = connector_web._Pending(
        session_id="ticket-xyz-001",
        enroll_url="https://mastio.test/v1/enrollment/ticket-xyz-001",
        site_url="https://mastio.test",
        verify_tls=False,
        private_key=pending_key,
        requester=RequesterInfo(
            name="demo", email="demo@cullis.local", reason="t",
        ),
        started_at=time.time(),
    )

    def _fake_get(url, *, headers=None, verify=None, timeout=None, **kwargs):
        return httpx.Response(
            200,
            json={
                "session_id": "ticket-xyz-001",
                "status": "approved",
                "agent_id": "acme::wizard-agent",
                "cert_pem": cert_pem,
                "capabilities": ["chat.query"],
            },
            request=httpx.Request("GET", url),
        )
    monkeypatch.setattr(connector_web.httpx, "get", _fake_get)

    try:
        with TestClient(fresh_app_pre_enrollment) as client:
            # Pre-poll: router not mounted (boot was pre-enrollment).
            assert (
                client.get("/v1/ambassador/health").status_code == 404
            )

            status = client.get("/api/status")
            assert status.status_code == 200
            body = status.json()
            assert body["status"] == "approved", body
            assert body["agent_id"] == "acme::wizard-agent"

            # Post-poll: Ambassador is live without any restart.
            health = client.get("/v1/ambassador/health")
            assert health.status_code == 200
            assert (
                health.json()["agent_id"] == "acme::wizard-agent"
            )
    finally:
        connector_web._pending = prev


def test_maybe_install_ambassador_is_idempotent(enrolled_app, cfg):
    """The boot path and the post-enrollment hook share the same helper.

    Calling it twice MUST be safe — the second call short-circuits on
    the idempotency guard instead of bubbling the ``RuntimeError``
    raised by ``install_ambassador`` on double-mount.
    """
    with TestClient(enrolled_app) as _client:
        first = enrolled_app.state.ambassador
        assert first is not None, (
            "lifespan should have mounted on boot when identity exists"
        )

        # Second call: no-op, no error, same state object.
        _maybe_install_ambassador(enrolled_app, cfg)
        assert enrolled_app.state.ambassador is first


def test_ensure_ambassador_installed_helper_is_idempotent(
    enrolled_app, cfg,
):
    """Public helper returns True on every call once mounted."""
    with TestClient(enrolled_app) as _client:
        assert _ensure_ambassador_installed(enrolled_app) is True
        assert _ensure_ambassador_installed(enrolled_app) is True
        assert _ensure_ambassador_installed(enrolled_app) is True


def test_ensure_ambassador_installed_swallows_install_errors(
    fresh_app_pre_enrollment, cfg, monkeypatch,
):
    """Best-effort contract: an install failure (e.g. Mastio unreachable
    during ``ensure_local_token``) must NOT propagate. The enrollment
    polling response stays ``approved`` and the operator retries on the
    next poll. We force a failure by monkeypatching ``install_ambassador``
    to raise and assert the helper logs + returns False without bubbling.
    """
    _seed_identity(cfg.config_dir)

    def _raise(*args, **kwargs):
        raise RuntimeError("simulated Mastio reachability failure")

    # Patch the single-mode installer at its call site
    # (``_ensure_ambassador_installed`` dispatches to it when shared
    # mode is off). Patching at the module the helper actually reads
    # is more robust against test pollution than reaching for
    # ``cullis_connector.ambassador.router`` — that package re-exports
    # ``router`` as an APIRouter object so dotted-path lookups confuse
    # the resolver.
    monkeypatch.setattr(
        connector_web, "_maybe_install_ambassador", _raise,
    )

    # ``cullis_connector`` sets ``propagate=False`` (see
    # ``cullis_connector/_logging.py:50``) so caplog — which attaches
    # to the root logger by default — never sees these warnings. Patch
    # the module-level logger's ``warning`` directly; same pattern as
    # ``feedback_mcp_proxy_logger_caplog`` (mcp_proxy has the identical
    # propagate=False contract).
    captured: list[str] = []

    def _capture(msg, *args, **kwargs):
        captured.append(msg % args if args else msg)

    monkeypatch.setattr(connector_web._log, "warning", _capture)

    result = _ensure_ambassador_installed(fresh_app_pre_enrollment)

    assert result is False
    assert (
        getattr(fresh_app_pre_enrollment.state, "ambassador", None)
        is None
    )
    assert any(
        "post-enrollment Ambassador install failed" in line
        for line in captured
    ), captured
