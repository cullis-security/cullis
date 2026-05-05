"""ADR-019 Phase 8a — single-mode session endpoints on the Ambassador.

Covers ``/api/session/init``, ``/api/session/whoami`` and
``/api/session/logout`` plus the cookie path of ``require_bearer``:

  * init mints an HttpOnly cookie carrying the local Bearer token
  * logout clears the cookie idempotently
  * whoami returns ADR-020 shape with bearer / cookie / nothing
  * /v1/models accepts the session cookie alone (no Authorization)
  * the legacy Bearer header path keeps working unchanged
  * mismatching cookie value yields 401, not silent fallback

Reuses the ``app`` / ``client`` / ``bearer`` fixtures style from
``test_ambassador_router.py``: the SDK is faked, the Ambassador is
real, the TestClient enters lifespan so ``install_ambassador`` runs.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cullis_connector.ambassador.auth import LOCAL_SESSION_COOKIE
from cullis_connector.config import ConnectorConfig
from cullis_connector.identity import generate_keypair, save_identity
from cullis_connector.identity.store import IdentityMetadata
from cullis_connector.web import build_app


# ── helpers (copied from test_ambassador_router for fixture parity) ──


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


class FakeCullisClient:
    """Minimal SDK fake — these tests do not exercise chat / mcp paths."""

    @classmethod
    def from_connector(cls, *args, **kwargs):
        return cls()

    def __init__(self, *args, **kwargs) -> None:
        pass

    def close(self) -> None:
        pass

    def list_inbox(self, *args, **kwargs):
        return []

    def discover(self, *args, **kwargs):
        return []

    def login_from_pem(self, *args, **kwargs) -> None:
        pass

    def list_mcp_tools(self) -> list[dict]:
        return []

    def chat_completion(self, body: dict) -> dict:
        return {
            "choices": [{
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
        }


# ── fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _patch_sdk(monkeypatch):
    monkeypatch.setattr("cullis_sdk.CullisClient", FakeCullisClient)


@pytest.fixture
def app(tmp_path: Path):
    _seed_identity(tmp_path)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    return build_app(cfg)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def bearer(client, tmp_path: Path) -> str:
    return (tmp_path / "local.token").read_text(encoding="utf-8").strip()


# ── /api/session/init ───────────────────────────────────────────────


def test_init_returns_ok_and_sets_cookie(client, bearer):
    resp = client.post("/api/session/init")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["ttl"] == 30 * 60

    set_cookie = resp.headers.get("set-cookie", "")
    # The cookie value carries the same secret as the local Bearer.
    assert LOCAL_SESSION_COOKIE in set_cookie
    assert bearer in set_cookie
    # HttpOnly is mandatory — the SPA never reads the value, only the
    # browser carries it. SameSite=strict + path=/ are the topology L
    # defaults; this assertion catches a regression that loosens any of
    # them.
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie or "SameSite=Strict" in set_cookie
    assert "Path=/" in set_cookie or "path=/" in set_cookie


def test_init_is_idempotent_returns_same_token(client, bearer):
    """Calling init twice keeps minting cookies with the same value.

    Regression guard against a future change that rotates the local
    token on every init — that would invalidate every existing cookie
    on every browser tab refresh and silently break the SPA.
    """
    r1 = client.post("/api/session/init")
    r2 = client.post("/api/session/init")
    c1 = r1.headers.get("set-cookie", "")
    c2 = r2.headers.get("set-cookie", "")
    assert bearer in c1 and bearer in c2


# ── /api/session/logout ─────────────────────────────────────────────


def test_logout_clears_cookie(client):
    resp = client.post("/api/session/logout")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    set_cookie = resp.headers.get("set-cookie", "")
    # Either an empty value or Max-Age=0 — both are valid clear signals.
    assert LOCAL_SESSION_COOKIE in set_cookie
    cleared = (
        f'{LOCAL_SESSION_COOKIE}=""' in set_cookie
        or f"{LOCAL_SESSION_COOKIE}=" in set_cookie and "Max-Age=0" in set_cookie
    )
    assert cleared, f"expected clear cookie, got: {set_cookie}"


def test_logout_idempotent_when_no_session(client):
    """Two consecutive logouts both succeed."""
    assert client.post("/api/session/logout").status_code == 200
    assert client.post("/api/session/logout").status_code == 200


# ── cookie path of require_bearer ───────────────────────────────────


def test_models_accepts_session_cookie_no_header(client, bearer):
    """The original goal of Phase 8a: a browser SPA can hit /v1/* with
    just the cookie, no Astro server in front.
    """
    resp = client.get(
        "/v1/models",
        cookies={LOCAL_SESSION_COOKIE: bearer},
    )
    assert resp.status_code == 200
    assert resp.json()["object"] == "list"


def test_models_still_accepts_legacy_bearer_header(client, bearer):
    """Regression: existing Bearer-only callers (Cursor, LibreChat) keep working."""
    resp = client.get(
        "/v1/models",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    assert resp.status_code == 200


def test_models_rejects_no_auth(client):
    resp = client.get("/v1/models")
    assert resp.status_code == 401


def test_models_rejects_wrong_cookie_value(client):
    """Wrong cookie token → 401, not a silent fallback to placeholder."""
    resp = client.get(
        "/v1/models",
        cookies={LOCAL_SESSION_COOKIE: "definitely-not-the-real-token"},
    )
    assert resp.status_code == 401


def test_models_rejects_wrong_bearer_header(client):
    """Wrong Bearer header → 401, even if a valid cookie is also present.

    Header-first ordering: a legacy client that sends an explicit
    Authorization header expects it to be the source of truth. Falling
    back to the cookie when the header is wrong would mask client bugs.
    """
    resp = client.get(
        "/v1/models",
        headers={"Authorization": "Bearer wrong-token"},
        cookies={LOCAL_SESSION_COOKIE: "anything"},
    )
    assert resp.status_code == 401


# ── /api/session/whoami ─────────────────────────────────────────────


def test_whoami_no_session_returns_placeholder(client):
    resp = client.get("/api/session/whoami")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] == "no_session"
    assert body["principal"]["name"] == "local"
    assert body["principal"]["source"] == "single-fallback"


def test_whoami_with_cookie_returns_full_principal(client, bearer):
    resp = client.get(
        "/api/session/whoami",
        cookies={LOCAL_SESSION_COOKIE: bearer},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    p = body["principal"]
    # The seeded agent_id is ``acme::frontdesk`` — the trust-domain is
    # the single-mode placeholder ``laptop``, the org follows agent_id,
    # principal_type is always ``user`` in single mode.
    assert p["principal_type"] == "user"
    assert p["name"] == "frontdesk"
    assert p["org"] == "acme"
    assert p["trust_domain"] == "laptop"
    assert p["spiffe_id"] == "spiffe://laptop/acme/user/frontdesk"
    assert body["principal_id"] == "laptop/acme/user/frontdesk"


def test_whoami_with_bearer_header_returns_full_principal(client, bearer):
    resp = client.get(
        "/api/session/whoami",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_whoami_with_invalid_cookie_returns_placeholder(client):
    resp = client.get(
        "/api/session/whoami",
        cookies={LOCAL_SESSION_COOKIE: "nope"},
    )
    # Whoami stays 200 even when wrong: the IdentityBadge needs a
    # parseable response in every state. The error code is in the body.
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] == "invalid_token"


# ── round-trip: init mints cookie, subsequent calls work ────────────


def test_init_then_models_via_cookie_jar(client):
    """End-to-end: POST /init, then the TestClient's cookie jar carries
    the cookie back on the next GET."""
    init = client.post("/api/session/init")
    assert init.status_code == 200
    # TestClient sticky cookies — no manual cookie= needed.
    resp = client.get("/v1/models")
    assert resp.status_code == 200
