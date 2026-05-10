"""Connector SPA bundle dogfood fixes — three independent surfaces.

These cover the three bugs the Frontdesk SPA dogfood surfaced when the
Connector ran behind nginx inside a Frontdesk bundle:

  1. ``/api/session/init`` returned 403 because the loopback guard
     rejected the nginx sidecar IP. The env override
     ``CULLIS_AMBASSADOR_LOOPBACK_ONLY=false`` lets the bundle opt out
     of the IP check (the cookie / Bearer gate is the actual auth
     boundary inside a private docker network).

  2. ``/api/session/whoami`` returned the container's own ``::frontdesk``
     bearer identity instead of the user who signed in. The route now
     short-circuits to ``_whoami_from_local_cookie`` whenever the
     request carries a valid HMAC-signed ``cullis_local_session`` cookie
     (ADR-025 local-auth path); the legacy Bearer / cookie-bearer path
     stays untouched for laptop callers (Cursor, OpenWebUI on loopback).

  3. ``/v1/chat/completions`` 502'd after ~12 s because the per-user
     and singleton ``CullisClient`` instances defaulted to ``timeout=10``.
     ``CULLIS_REQUEST_TIMEOUT_S`` now flows into the SDK constructor on
     every build, so chain-of-thought local models (qwen3.5, deepseek-r1)
     can finish.

Plus a config-loader test for ``CULLIS_ADVERTISED_MODELS`` (operator
override for the SPA dropdown when the live /v1/models fetch path
degrades).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ── shared fixtures (mirror tests/connector/test_ambassador_session_routes) ──


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


def _seed_identity(config_dir: Path, *, agent_id: str = "acme::frontdesk") -> None:
    from cullis_connector.identity import generate_keypair, save_identity
    from cullis_connector.identity.store import IdentityMetadata

    key = generate_keypair()
    cert_pem = _self_signed_cert_pem(key, common_name=agent_id)
    metadata = IdentityMetadata(
        agent_id=agent_id,
        capabilities=[],
        site_url="https://mastio.test",
        issued_at="2026-05-04T10:00:00+00:00",
    )
    save_identity(
        config_dir=config_dir,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem=None,
        metadata=metadata,
    )


class _FakeCullisClient:
    """SDK stub — these tests do not exercise broker round-trips."""

    last_init_kwargs: dict | None = None

    def __init__(self, *args, **kwargs) -> None:
        type(self).last_init_kwargs = kwargs

    @classmethod
    def from_connector(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    @classmethod
    def from_user_principal_pem(cls, *args, **kwargs):
        type(cls).last_init_kwargs = kwargs
        return cls()

    def close(self) -> None:
        pass

    def list_inbox(self, *args, **kwargs):
        return []

    def discover(self, *args, **kwargs):
        return []

    def login_from_pem(self, *args, **kwargs) -> None:
        pass

    def login_via_proxy_with_local_key(self, *args, **kwargs) -> None:
        pass

    def list_mcp_tools(self) -> list[dict]:
        return []


@pytest.fixture(autouse=True)
def _patch_sdk(monkeypatch):
    monkeypatch.setattr("cullis_sdk.CullisClient", _FakeCullisClient)
    _FakeCullisClient.last_init_kwargs = None


# ── (1) Loopback override ─────────────────────────────────────────────


def _build_app_with_env(tmp_path: Path, monkeypatch, **env: str):
    """Build the Connector FastAPI app + trigger lifespan so the
    Ambassador mounts (``_maybe_install_ambassador`` runs inside the
    lifespan, not at construction). The caller can then inspect the
    captured kwargs."""
    _seed_identity(tmp_path)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from cullis_connector.config import ConnectorConfig
    from cullis_connector.web import build_app

    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = True
    app = build_app(cfg)
    # Entering the TestClient context fires the lifespan startup hooks,
    # which call ``_maybe_install_ambassador``.
    with TestClient(app):
        pass
    return app


def _capture_install_ambassador(monkeypatch) -> list[dict]:
    """Patch install_ambassador to record its kwargs without actually mounting.

    ``cullis_connector.web._maybe_install_ambassador`` performs a local
    ``from cullis_connector.ambassador.router import install_ambassador``
    inside the function body, so the patch has to land on the source
    module rather than on ``web``.
    """
    captured: list[dict] = []

    # The submodule is named ``router`` and also defines a top-level
    # ``router`` APIRouter; ``from X import router`` re-binds to the
    # router object, not the module. Import via ``sys.modules`` to keep
    # hold of the module proper. Same gotcha noted in
    # memory feedback_monkeypatch_plugin_name_collision.md.
    import sys

    import cullis_connector.ambassador.router  # noqa: F401 — populate sys.modules

    amb_router_mod = sys.modules["cullis_connector.ambassador.router"]
    real = amb_router_mod.install_ambassador

    def spy(app, **kwargs):
        captured.append(kwargs)
        return real(app, **kwargs)

    monkeypatch.setattr(amb_router_mod, "install_ambassador", spy)
    return captured


def test_loopback_env_false_disables_check(tmp_path: Path, monkeypatch):
    """Setting the env to ``false`` must override the config default
    (``require_local_only=True``) so the SPA bundle inside docker can
    reach ``/api/session/init`` from the nginx sidecar IP."""
    captured = _capture_install_ambassador(monkeypatch)
    _build_app_with_env(
        tmp_path, monkeypatch,
        CULLIS_AMBASSADOR_LOOPBACK_ONLY="false",
    )
    assert captured, "install_ambassador was not called"
    assert captured[-1]["require_local_only"] is False


@pytest.mark.parametrize("falsey", ["false", "FALSE", "False", "0", "no", "off"])
def test_loopback_env_all_falsey_aliases_disable(
    tmp_path: Path, monkeypatch, falsey: str,
):
    captured = _capture_install_ambassador(monkeypatch)
    _build_app_with_env(
        tmp_path, monkeypatch,
        CULLIS_AMBASSADOR_LOOPBACK_ONLY=falsey,
    )
    assert captured[-1]["require_local_only"] is False, (
        f"env {falsey!r} should have disabled the loopback check"
    )


def test_loopback_env_missing_keeps_config_default(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CULLIS_AMBASSADOR_LOOPBACK_ONLY", raising=False)
    captured = _capture_install_ambassador(monkeypatch)
    _build_app_with_env(tmp_path, monkeypatch)
    # ConnectorConfig default is True; env missing → fall back to it.
    assert captured[-1]["require_local_only"] is True


@pytest.mark.parametrize("truthy", ["true", "True", "yes", "1", "on", "anything"])
def test_loopback_env_non_falsey_keeps_config_default(
    tmp_path: Path, monkeypatch, truthy: str,
):
    """Any non-false-y value falls through to the config default rather
    than enabling the check unconditionally — that way a typo in the
    env doesn't silently flip the topology."""
    captured = _capture_install_ambassador(monkeypatch)
    _build_app_with_env(
        tmp_path, monkeypatch,
        CULLIS_AMBASSADOR_LOOPBACK_ONLY=truthy,
    )
    assert captured[-1]["require_local_only"] is True


# ── (2) whoami local cookie override ──────────────────────────────────


@pytest.fixture
def cookie_secret() -> bytes:
    return b"\x00" * 32


@pytest.fixture
def shared_mode_app(tmp_path: Path, cookie_secret: bytes):
    """Build an app with the loopback check off + local_cookie_secret
    stamped on app.state — the same wiring ADR-019 shared mode applies."""
    _seed_identity(tmp_path)
    from cullis_connector.config import ConnectorConfig
    from cullis_connector.web import build_app

    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    app = build_app(cfg)
    app.state.local_cookie_secret = cookie_secret
    return app


def _mint_local_cookie(secret: bytes, *, user_name: str, principal: str) -> str:
    from cullis_connector.identity.local_session import (
        build_payload, issue_local_cookie,
    )

    payload = build_payload(
        user_name=user_name,
        must_change_password=False,
        principal_name=principal,
    )
    return issue_local_cookie(payload, secret)


def test_whoami_returns_local_user_when_cookie_valid(
    shared_mode_app, cookie_secret: bytes,
):
    cookie = _mint_local_cookie(
        cookie_secret, user_name="alice", principal="alice",
    )
    with TestClient(shared_mode_app) as client:
        r = client.get(
            "/api/session/whoami",
            cookies={"cullis_local_session": cookie},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["principal"]["name"] == "alice"
    assert body["principal"]["principal_type"] == "user"
    assert body["principal"]["source"] == "local-cookie"
    # spiffe path is 4-segment ``<td>/<org>/user/<name>`` shape.
    assert body["principal"]["spiffe_id"].startswith("spiffe://")
    assert "/user/alice" in body["principal"]["spiffe_id"]


def test_whoami_falls_back_when_no_cookie(shared_mode_app, tmp_path: Path):
    """No cookie + no Authorization header should not crash — the
    bearer-path branch handles it (whoami returns ok=False or 401 by
    design; here we assert we don't accidentally surface a fake
    local-user principal)."""
    with TestClient(shared_mode_app) as client:
        r = client.get("/api/session/whoami")
    # Either 401 or 200-with-no-principal; the invariant is no local-cookie
    # source slipped through.
    if r.status_code == 200:
        body = r.json()
        principal = body.get("principal") or {}
        assert principal.get("source") != "local-cookie", body


def test_whoami_falls_back_when_cookie_hmac_invalid(shared_mode_app):
    # Cookie HMAC over a different secret — parse must fail and the
    # bearer path takes over.
    bad_cookie = _mint_local_cookie(
        b"\xff" * 32, user_name="impersonator", principal="impersonator",
    )
    with TestClient(shared_mode_app) as client:
        r = client.get(
            "/api/session/whoami",
            cookies={"cullis_local_session": bad_cookie},
        )
    if r.status_code == 200:
        body = r.json()
        principal = body.get("principal") or {}
        assert principal.get("source") != "local-cookie", (
            "tampered cookie must NOT yield a local-cookie whoami"
        )


def test_whoami_falls_back_when_no_cookie_secret_on_app_state(
    tmp_path: Path, cookie_secret: bytes,
):
    """If app.state.local_cookie_secret is unset (single-mode topology),
    we must skip the local-cookie path even if a cookie is present —
    otherwise the assertion that the bearer path is the only auth
    surface in single mode would be silently violated."""
    _seed_identity(tmp_path)
    from cullis_connector.config import ConnectorConfig
    from cullis_connector.web import build_app

    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    app = build_app(cfg)
    # Explicitly clear: no local-auth wiring in this app.
    app.state.local_cookie_secret = None

    cookie = _mint_local_cookie(
        cookie_secret, user_name="ghost", principal="ghost",
    )
    with TestClient(app) as client:
        r = client.get(
            "/api/session/whoami",
            cookies={"cullis_local_session": cookie},
        )
    if r.status_code == 200:
        body = r.json()
        principal = body.get("principal") or {}
        assert principal.get("source") != "local-cookie"


# ── (3) Request-timeout env propagation ──────────────────────────────


def test_ambassador_client_passes_env_timeout_to_sdk(
    tmp_path: Path, monkeypatch,
):
    """Building the singleton ``AmbassadorClient`` must forward
    ``CULLIS_REQUEST_TIMEOUT_S`` to the SDK constructor."""
    monkeypatch.setenv("CULLIS_REQUEST_TIMEOUT_S", "120")
    from cullis_connector.ambassador.client import AmbassadorClient

    holder = AmbassadorClient(
        agent_id="acme::frontdesk",
        org_id="acme",
        site_url="https://mastio.test",
        cert_pem="-----BEGIN CERT-----\n-----END CERT-----\n",
        key_pem="-----BEGIN KEY-----\n-----END KEY-----\n",
        verify_tls=False,
    )
    holder._build()
    kwargs = _FakeCullisClient.last_init_kwargs or {}
    assert kwargs.get("timeout") == 120.0


def test_ambassador_client_falls_back_to_10s_when_env_invalid(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setenv("CULLIS_REQUEST_TIMEOUT_S", "not-a-number")
    from cullis_connector.ambassador.client import AmbassadorClient

    holder = AmbassadorClient(
        agent_id="acme::frontdesk",
        org_id="acme",
        site_url="https://mastio.test",
        cert_pem="-----BEGIN CERT-----\n-----END CERT-----\n",
        key_pem="-----BEGIN KEY-----\n-----END KEY-----\n",
        verify_tls=False,
    )
    holder._build()
    kwargs = _FakeCullisClient.last_init_kwargs or {}
    assert kwargs.get("timeout") == 10.0


def test_ambassador_client_defaults_to_10s_when_env_missing(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.delenv("CULLIS_REQUEST_TIMEOUT_S", raising=False)
    from cullis_connector.ambassador.client import AmbassadorClient

    holder = AmbassadorClient(
        agent_id="acme::frontdesk",
        org_id="acme",
        site_url="https://mastio.test",
        cert_pem="-----BEGIN CERT-----\n-----END CERT-----\n",
        key_pem="-----BEGIN KEY-----\n-----END KEY-----\n",
        verify_tls=False,
    )
    holder._build()
    kwargs = _FakeCullisClient.last_init_kwargs or {}
    assert kwargs.get("timeout") == 10.0


# ── (4) CULLIS_ADVERTISED_MODELS env override ──────────────────────────


def test_advertised_models_env_overrides_default(tmp_path: Path, monkeypatch):
    """``CULLIS_ADVERTISED_MODELS`` must populate the Ambassador's
    advertised list so the SPA dropdown reflects the Mastio's actual
    providers when the live /v1/models fetch path is unavailable."""
    from cullis_connector.config import load_config

    env = {
        "CULLIS_CONFIG_DIR": str(tmp_path),
        "CULLIS_LOG_LEVEL": "warning",
        "CULLIS_ADVERTISED_MODELS": (
            "claude-haiku-4-5, ollama_chat/gemma3:1b, "
            "ollama_chat/qwen3.5:8b"
        ),
    }
    cfg = load_config(env=env)
    # Whitespace and empty tokens are stripped.
    assert cfg.ambassador.advertised_models == [
        "claude-haiku-4-5",
        "ollama_chat/gemma3:1b",
        "ollama_chat/qwen3.5:8b",
    ]


def test_advertised_models_empty_env_keeps_default(tmp_path: Path, monkeypatch):
    from cullis_connector.config import AmbassadorConfig, load_config

    env = {
        "CULLIS_CONFIG_DIR": str(tmp_path),
        "CULLIS_ADVERTISED_MODELS": "",
    }
    cfg = load_config(env=env)
    assert "" not in cfg.ambassador.advertised_models
    default = AmbassadorConfig().advertised_models
    assert cfg.ambassador.advertised_models == default
