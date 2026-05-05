"""ADR-019 Phase 8c — Cullis Chat SPA mount in the Connector.

The Connector FastAPI mounts the prerendered SPA at /chat when a built
dist/ is reachable. Resolution order:

  1. CULLIS_CHAT_DIST env var
  2. cullis_connector/static/cullis-chat/  (production wheel layout)
  3. <repo>/frontend/cullis-chat/dist/      (dev source layout)

Tests cover:

  * No dist anywhere → /chat is not mounted, ``/`` falls back to
    /connected when identity exists, /setup otherwise.
  * dist via env var → /chat serves index.html, ``/`` redirects to /chat.
  * Templates global ``cullis_chat_mounted`` reflects the mount state
    so connected.html can conditionally render the "Open Cullis Chat"
    button.

The dist used here is a tiny fixture (one index.html, one CSS, one JS
chunk). It does not exercise the real SPA — that is the job of the
Playwright suite under ``frontend/cullis-chat/tests/e2e/``.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.identity import generate_keypair, save_identity
from cullis_connector.identity.store import IdentityMetadata
from cullis_connector.web import build_app


def _self_signed_cert_pem(private_key, *, common_name: str) -> str:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, common_name.split("::", 1)[0]),
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
    key = generate_keypair()
    cert_pem = _self_signed_cert_pem(key, common_name=agent_id)
    save_identity(
        config_dir=config_dir,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem=None,
        metadata=IdentityMetadata(
            agent_id=agent_id,
            capabilities=[],
            site_url="https://mastio.test",
            issued_at="2026-05-04T10:00:00+00:00",
        ),
    )


def _make_fake_dist(target: Path) -> None:
    """Create a minimal SPA-like dist tree: index.html + one asset."""
    target.mkdir(parents=True, exist_ok=True)
    (target / "index.html").write_text(
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>Cullis Chat</title></head><body>"
        '<div id="root">cullis-chat fixture</div></body></html>',
        encoding="utf-8",
    )
    assets = target / "_astro"
    assets.mkdir(exist_ok=True)
    (assets / "app.js").write_text("/* fixture */", encoding="utf-8")


class _NoChatDistEnv:
    """Force the SPA resolver to find nothing.

    Repository-relative dev fallback can survive monkeypatching of
    ``CULLIS_CHAT_DIST`` (it does not look at env vars). We point the
    env var at a guaranteed-empty directory under tmp_path AND null
    the bundled / repo-dev candidates by monkeypatching the module
    constants. Both must be set or one of them resolves the path
    despite our intent.
    """


@pytest.fixture
def app_no_chat(tmp_path: Path, monkeypatch):
    _seed_identity(tmp_path)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    # Point to an empty dir (no index.html) so the resolver rejects it.
    empty = tmp_path / "no-spa-here"
    empty.mkdir()
    monkeypatch.setenv("CULLIS_CHAT_DIST", str(empty))
    # Null the other candidates by pointing them at non-existent paths.
    monkeypatch.setattr(
        "cullis_connector.web._CHAT_BUNDLED_DIR", tmp_path / "no-bundled"
    )
    monkeypatch.setattr(
        "cullis_connector.web._CHAT_REPO_DEV_DIR", tmp_path / "no-repo-dev"
    )
    return build_app(cfg)


@pytest.fixture
def app_with_chat(tmp_path: Path, monkeypatch):
    _seed_identity(tmp_path)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    # Build a fake dist and point CULLIS_CHAT_DIST at it.
    dist = tmp_path / "fake-spa-dist"
    _make_fake_dist(dist)
    monkeypatch.setenv("CULLIS_CHAT_DIST", str(dist))
    return build_app(cfg)


@pytest.fixture
def app_with_chat_no_identity(tmp_path: Path, monkeypatch):
    """SPA dist exists but no enrollment yet — the gate should redirect
    /chat traffic to /setup so the user does not see the SPA's
    session_init 404 banner before completing enrollment."""
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    dist = tmp_path / "fake-spa-dist"
    _make_fake_dist(dist)
    monkeypatch.setenv("CULLIS_CHAT_DIST", str(dist))
    return build_app(cfg)


def test_chat_not_mounted_when_no_dist(app_no_chat):
    with TestClient(app_no_chat, follow_redirects=False) as cli:
        # /chat is not mounted at all — 404 from the dashboard router.
        resp = cli.get("/chat/")
        assert resp.status_code == 404

        # Without the mount, /  falls back to the dashboard /connected
        # (identity is seeded by the fixture).
        root = cli.get("/")
        assert root.status_code == 303
        assert root.headers["location"] == "/connected"


def test_chat_mounted_serves_index(app_with_chat):
    with TestClient(app_with_chat, follow_redirects=False) as cli:
        # /chat/ serves the SPA's index.html.
        resp = cli.get("/chat/")
        assert resp.status_code == 200
        assert "cullis-chat fixture" in resp.text
        assert resp.headers["content-type"].startswith("text/html")


def test_chat_assets_resolve(app_with_chat):
    with TestClient(app_with_chat, follow_redirects=False) as cli:
        resp = cli.get("/chat/_astro/app.js")
        assert resp.status_code == 200
        assert "fixture" in resp.text


def test_root_redirects_to_chat_when_mounted_and_identity(app_with_chat):
    with TestClient(app_with_chat, follow_redirects=False) as cli:
        root = cli.get("/")
        assert root.status_code == 303
        assert root.headers["location"] == "/chat/"


def test_connected_template_shows_chat_button_when_mounted(app_with_chat):
    with TestClient(app_with_chat) as cli:
        resp = cli.get("/connected")
        assert resp.status_code == 200
        assert "Open Cullis Chat" in resp.text


def test_connected_template_hides_chat_button_when_not_mounted(app_no_chat):
    with TestClient(app_no_chat) as cli:
        resp = cli.get("/connected")
        assert resp.status_code == 200
        assert "Open Cullis Chat" not in resp.text


def test_chat_gate_redirects_to_setup_when_no_identity(app_with_chat_no_identity):
    """SPA mounted but no enrollment: /chat and /chat/ both redirect
    to /setup so the user lands on the wizard instead of seeing the
    SPA's ``session_init: HTTP 404`` banner before there is anything
    for the cookie to authenticate against."""
    with TestClient(app_with_chat_no_identity, follow_redirects=False) as cli:
        for path in ("/chat", "/chat/"):
            resp = cli.get(path)
            assert resp.status_code == 303, f"{path}: {resp.status_code}"
            assert resp.headers["location"] == "/setup"


def test_chat_gate_does_not_block_static_assets_when_no_identity(
    app_with_chat_no_identity,
):
    """Asset paths under /chat/_astro/ stay reachable so an already-
    loaded SPA tab (rare but possible during enrollment if the user
    keeps the chat tab open) can still pull JS/CSS chunks without a
    redirect ping-pong."""
    with TestClient(app_with_chat_no_identity, follow_redirects=False) as cli:
        # The fake dist fixture writes _astro/app.js under the dist root.
        resp = cli.get("/chat/_astro/app.js")
        assert resp.status_code == 200
        assert "fixture" in resp.text


def test_chat_gate_passes_through_when_identity_exists(app_with_chat):
    """The original mount-on path still works once enrollment is done."""
    with TestClient(app_with_chat, follow_redirects=False) as cli:
        resp = cli.get("/chat/")
        assert resp.status_code == 200
        assert "cullis-chat fixture" in resp.text
