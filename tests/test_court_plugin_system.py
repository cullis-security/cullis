"""Contract tests for the Court plugin + license skeleton.

Mirrors :mod:`tests.test_mastio_plugin_system` against the Court
(``app/``) side. The PR is enterprise-shaped but ships in the public
repo: every test here asserts that the core boots identically when no
plugin is installed.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
import jwt as jose_jwt

from app import license as ap_license
from app import plugins as ap_plugins


# ── helpers ────────────────────────────────────────────────────────────────


def _gen_keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def _mint_license(
    priv_pem: bytes,
    *,
    features: list[str],
    tier: str = "enterprise",
    org: str = "test-org",
    exp_offset: int = 3600,
) -> str:
    now = int(time.time())
    return jose_jwt.encode(
        {"tier": tier, "org": org, "features": features, "exp": now + exp_offset},
        priv_pem,
        algorithm="RS256",
    )


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch):
    """Each test starts with a fresh license cache and plugin registry."""
    ap_license.reset_cache()
    ap_plugins.reset_registry()
    monkeypatch.delenv("CULLIS_LICENSE_KEY", raising=False)
    monkeypatch.delenv("CULLIS_LICENSE_PATH", raising=False)
    monkeypatch.delenv("CULLIS_LICENSE_PUBKEY_PATH", raising=False)
    yield
    ap_license.reset_cache()
    ap_plugins.reset_registry()


# ── license: community fallback ────────────────────────────────────────────


def test_no_token_returns_community():
    claims = ap_license.load_license()
    assert claims.is_community
    assert claims.features == frozenset()
    assert ap_license.has_feature("anything") is False


def test_invalid_token_falls_back_to_community(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    _, pub = _gen_keypair()
    pub_path = tmp_path / "license.pub"
    pub_path.write_bytes(pub)

    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))
    monkeypatch.setenv("CULLIS_LICENSE_KEY", "not.a.valid.jwt")

    claims = ap_license.load_license()
    assert claims.is_community


def test_expired_token_falls_back_to_community(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "license.pub"
    pub_path.write_bytes(pub)
    token = _mint_license(priv, features=["tsa_anchoring"], exp_offset=-60)

    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))
    monkeypatch.setenv("CULLIS_LICENSE_KEY", token)

    claims = ap_license.load_license()
    assert claims.is_community


def test_token_present_but_no_real_pubkey_falls_back_to_community(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CULLIS_LICENSE_KEY", "anything")
    claims = ap_license.load_license()
    assert claims.is_community


# ── license: valid token ───────────────────────────────────────────────────


def test_valid_token_grants_listed_features(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "license.pub"
    pub_path.write_bytes(pub)
    token = _mint_license(
        priv, features=["tsa_anchoring", "cross_org_guardian"],
    )

    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))
    monkeypatch.setenv("CULLIS_LICENSE_KEY", token)

    claims = ap_license.load_license()
    assert claims.is_community is False
    assert claims.tier == "enterprise"
    assert claims.org == "test-org"
    assert ap_license.has_feature("tsa_anchoring") is True
    assert ap_license.has_feature("cross_org_guardian") is True
    assert ap_license.has_feature("multi_tenant_isolation") is False


def test_token_loaded_from_path(tmp_path, monkeypatch: pytest.MonkeyPatch):
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "license.pub"
    pub_path.write_bytes(pub)
    token = _mint_license(priv, features=["sla_federation_monitor"])
    token_path = tmp_path / "license.jwt"
    token_path.write_text(token)

    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))
    monkeypatch.setenv("CULLIS_LICENSE_PATH", str(token_path))

    assert ap_license.has_feature("sla_federation_monitor") is True


def test_require_feature_returns_402_without_license():
    app = FastAPI()

    @app.get(
        "/protected",
        dependencies=[Depends(ap_license.require_feature("tsa_anchoring"))],
    )
    def protected():
        return {"ok": True}

    with TestClient(app) as client:
        resp = client.get("/protected")
        assert resp.status_code == 402
        body = resp.json()
        assert body["detail"]["error"] == "license_required"
        assert body["detail"]["feature"] == "tsa_anchoring"
        assert body["detail"]["tier"] == "community"


def test_require_feature_passes_with_valid_license(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "license.pub"
    pub_path.write_bytes(pub)
    token = _mint_license(priv, features=["tsa_anchoring"])
    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))
    monkeypatch.setenv("CULLIS_LICENSE_KEY", token)

    app = FastAPI()

    @app.get(
        "/protected",
        dependencies=[Depends(ap_license.require_feature("tsa_anchoring"))],
    )
    def protected():
        return {"ok": True}

    with TestClient(app) as client:
        resp = client.get("/protected")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


# ── plugin registry ────────────────────────────────────────────────────────


def test_empty_registry_is_a_noop():
    reg = ap_plugins.PluginRegistry()
    app = FastAPI()
    initial_routes = len(app.routes)
    reg.mount_routers(app)
    reg.add_middlewares(app)
    assert reg.kms_factory("aws") is None
    assert len(app.routes) == initial_routes


def test_plugin_routers_mount_in_order():
    class _R1(ap_plugins.Plugin):
        name = "r1"

        def routers(self):
            r = APIRouter()
            r.add_api_route("/_test/court_r1", lambda: {"ok": "r1"})
            return [r]

    class _R2(ap_plugins.Plugin):
        name = "r2"

        def routers(self):
            r = APIRouter()
            r.add_api_route("/_test/court_r2", lambda: {"ok": "r2"})
            return [r]

    reg = ap_plugins.PluginRegistry(plugins=[_R1(), _R2()])
    app = FastAPI()
    reg.mount_routers(app)
    paths = [r.path for r in app.routes if hasattr(r, "path")]
    assert "/_test/court_r1" in paths
    assert "/_test/court_r2" in paths


def test_filter_by_license_drops_ungated_plugins():
    class _Free(ap_plugins.Plugin):
        name = "free"

    class _Paid(ap_plugins.Plugin):
        name = "paid"
        requires_feature = "tsa_anchoring"

    reg = ap_plugins.PluginRegistry(plugins=[_Free(), _Paid()])
    filtered = reg.filter_by_license(lambda f: False)
    assert [p.name for p in filtered.plugins] == ["free"]

    filtered_paid = reg.filter_by_license(lambda f: f == "tsa_anchoring")
    assert {p.name for p in filtered_paid.plugins} == {"free", "paid"}


def test_kms_factory_first_hit_wins():
    class _A(ap_plugins.Plugin):
        name = "a"

        def kms_factory(self, provider):
            return ("a", provider) if provider == "aws" else None

    class _B(ap_plugins.Plugin):
        name = "b"

        def kms_factory(self, provider):
            return ("b", provider)

    reg = ap_plugins.PluginRegistry(plugins=[_A(), _B()])
    assert reg.kms_factory("aws") == ("a", "aws")
    assert reg.kms_factory("azure") == ("b", "azure")


@pytest.mark.asyncio
async def test_startup_failure_does_not_break_other_plugins():
    calls: list[str] = []

    class _OK(ap_plugins.Plugin):
        name = "ok"

        async def startup(self, app):
            calls.append("ok-start")

        async def shutdown(self, app):
            calls.append("ok-stop")

    class _Boom(ap_plugins.Plugin):
        name = "boom"

        async def startup(self, app):
            raise RuntimeError("nope")

    reg = ap_plugins.PluginRegistry(plugins=[_Boom(), _OK()])
    app = FastAPI()
    await reg.run_startup(app)
    await reg.run_shutdown(app)
    assert "ok-start" in calls
    assert "ok-stop" in calls


def test_discovery_skips_non_plugin_entrypoint(monkeypatch: pytest.MonkeyPatch):
    """A misregistered entry point must not crash discovery."""

    class _NotAPlugin:
        pass

    class _FakeEntryPoint:
        name = "bogus"

        def load(self):
            return _NotAPlugin

    class _FakeEntryPoints:
        def select(self, group: str):
            return [_FakeEntryPoint()] if group == ap_plugins.ENTRY_POINT_GROUP else []

    monkeypatch.setattr(ap_plugins, "entry_points", lambda: _FakeEntryPoints())
    reg = ap_plugins.PluginRegistry.discover()
    assert reg.plugins == []


# ── core app boots identically without plugins ─────────────────────────────


def test_core_app_imports_without_plugins():
    """No entry points installed = main.py imports clean and registry is empty."""
    from app.plugins import get_registry

    ap_plugins.reset_registry()
    reg = get_registry()
    assert reg.plugins == []


def test_court_uses_distinct_entry_point_group():
    """Court's group must NOT collide with Mastio's — they are vended separately."""
    from mcp_proxy.plugins import ENTRY_POINT_GROUP as MASTIO_GROUP

    assert ap_plugins.ENTRY_POINT_GROUP == "cullis.court_plugins"
    assert MASTIO_GROUP == "cullis.mastio_plugins"
    assert ap_plugins.ENTRY_POINT_GROUP != MASTIO_GROUP
