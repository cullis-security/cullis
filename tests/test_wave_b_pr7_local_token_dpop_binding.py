"""Wave B PR7 — C1 LOCAL_TOKEN cnf.jkt + DPoP binding.

Audit ref: imp/audits/2026-05-11-track-2-auth.md H3.

Pre-fix vector:
  * SDK called ``POST /v1/auth/token`` with x509 client_assertion +
    a DPoP proof header (the wire format is identical to the Court's
    flow). The Mastio mint handler ignored the DPoP proof entirely
    and issued a plain Bearer LOCAL_TOKEN (no ``cnf.jkt``).
  * Subsequent requests carried ``Authorization: Bearer <token>``
    (or ``Authorization: DPoP <token>`` with an SDK proof). The dep
    validated the JWT signature + claims but never verified the
    proof: any holder of the token bytes (e.g. an attacker who
    exfiltrated ``~/.cullis/local.token``) could replay until the
    token expired.

Post-fix:
  1. ``POST /v1/auth/token`` reads the inbound ``DPoP`` header,
     verifies the proof against ``htm=POST`` + ``htu=<request URL>``,
     extracts the JWK thumbprint (jkt) and stamps it into the issued
     token's ``cnf.jkt`` claim.
  2. The ingress dep (``_maybe_local_token``) and egress dep
     (``_maybe_local_internal_agent``) require, when the token has
     ``cnf.jkt``:
       * a fresh DPoP proof header on the inbound request
       * proof's jkt matches the token's ``cnf.jkt``
       * proof's ``ath`` hashes the LOCAL_TOKEN
     Mismatch / missing → 401.
  3. Backward compat: tokens minted before this fix carry no
     ``cnf.jkt``. They validate as Bearer with a WARN log, until
     ``MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP=true`` flips them to 401.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import importlib
import time
import uuid

import jwt as jose_jwt
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient


# ── Cert + assertion + DPoP helpers (mirror tests/test_proxy_local_token.py) ──


def _gen_ca() -> tuple[bytes, str, str]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject).issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    return ca_key, key_pem, cert_pem


def _issue_leaf(ca_key, ca_cert_pem: str, agent_id: str):
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject).issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    x5c = [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()]
    return key_pem, cert_pem, x5c


def _build_assertion(agent_id: str, leaf_key_pem: str, x5c: list[str]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": agent_id,
        "iss": agent_id,
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jose_jwt.encode(
        payload, leaf_key_pem, algorithm="RS256", headers={"x5c": x5c}
    )


def _make_dpop_keypair():
    """Generate an EC P-256 keypair + JWK suitable for DPoP proofs."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return priv, jwk


def _build_dpop_proof(
    priv, jwk: dict, method: str, url: str, *,
    access_token: str | None = None, jti: str | None = None,
) -> str:
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    claims: dict = {
        "jti": jti or uuid.uuid4().hex,
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }
    if access_token:
        claims["ath"] = base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode()).digest()
        ).rstrip(b"=").decode()
    return jose_jwt.encode(
        claims, priv_pem, algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


def _compute_jkt(jwk: dict) -> str:
    """RFC 7638 thumbprint matching ``mcp_proxy.auth.dpop.compute_jkt``."""
    import json
    raw = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(
        hashlib.sha256(canonical).digest()
    ).rstrip(b"=").decode()


# ── Fixture (lifted from tests/test_proxy_local_token.py with require_dpop knob) ──


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.invalid")
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "1")
    # Disable DPoP iat freshness window pressure for deterministic tests.
    monkeypatch.setenv("MCP_PROXY_DPOP_IAT_WINDOW", "120")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import mcp_proxy.main as main_mod
    importlib.reload(main_mod)
    app = main_mod.app

    async with app.router.lifespan_context(app):
        from mcp_proxy.db import set_config
        ca_key, ca_key_pem, ca_cert_pem = _gen_ca()
        await set_config("org_ca_key", ca_key_pem)
        await set_config("org_ca_cert", ca_cert_pem)

        mgr = app.state.agent_manager
        await mgr.load_org_ca(ca_key_pem, ca_cert_pem)
        await mgr.ensure_mastio_identity()
        from mcp_proxy.auth.local_issuer import build_from_keystore
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        app.state.local_keystore = LocalKeyStore()
        app.state.local_issuer = await build_from_keystore(
            "acme", app.state.local_keystore,
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield {
                "app": app, "client": client,
                "ca_key": ca_key, "ca_cert_pem": ca_cert_pem,
            }

    get_settings.cache_clear()


# ── Mint-side tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mint_with_dpop_header_stamps_cnf_jkt(proxy_app):
    """Happy path — SDK sends DPoP proof on /v1/auth/token, the issued
    LOCAL_TOKEN carries cnf.jkt = thumbprint of that DPoP key."""
    ctx = proxy_app
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion("acme::alice", leaf_key_pem, x5c)

    priv, jwk = _make_dpop_keypair()
    proof = _build_dpop_proof(
        priv, jwk, "POST", "http://test/v1/auth/token",
    )

    resp = await ctx["client"].post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]

    issuer = ctx["app"].state.local_issuer
    pub_pem = issuer.active_key.pubkey_pem
    claims = jose_jwt.decode(
        token, pub_pem, algorithms=["ES256"],
        audience="cullis-local",
        issuer="cullis-mastio:acme",
    )
    expected_jkt = _compute_jkt(jwk)
    assert claims.get("cnf") == {"jkt": expected_jkt}


@pytest.mark.asyncio
async def test_mint_without_dpop_header_falls_back_to_unbound(proxy_app):
    """Back-compat — when SDK omits DPoP header (legacy clients still
    in flight), the mint succeeds but the token has no cnf.jkt and a
    WARN is logged. Caller behaviour preserved until the flag flips."""
    ctx = proxy_app
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion("acme::alice", leaf_key_pem, x5c)

    resp = await ctx["client"].post(
        "/v1/auth/token", json={"client_assertion": assertion},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]

    issuer = ctx["app"].state.local_issuer
    pub_pem = issuer.active_key.pubkey_pem
    claims = jose_jwt.decode(
        token, pub_pem, algorithms=["ES256"],
        audience="cullis-local",
        issuer="cullis-mastio:acme",
    )
    assert "cnf" not in claims


@pytest.mark.asyncio
async def test_mint_without_dpop_rejected_when_require_flag(proxy_app, monkeypatch):
    """Strict mode — once the SDK has rolled out and the operator flips
    MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP=true, mint without a DPoP proof
    is 401 instead of falling back."""
    ctx = proxy_app
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "local_token_require_dpop", True,
    )
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion("acme::alice", leaf_key_pem, x5c)

    resp = await ctx["client"].post(
        "/v1/auth/token", json={"client_assertion": assertion},
    )
    assert resp.status_code == 401
    assert "DPoP proof required" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_mint_with_invalid_dpop_falls_back(proxy_app):
    """Tampered / wrong-method DPoP proof → mint falls back to unbound
    (the caller may have opted out of DPoP). The require-flag closes
    this gap when needed."""
    ctx = proxy_app
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], "acme::alice")
    assertion = _build_assertion("acme::alice", leaf_key_pem, x5c)

    priv, jwk = _make_dpop_keypair()
    # Sign for the wrong method — htm=GET ≠ POST
    proof = _build_dpop_proof(
        priv, jwk, "GET", "http://test/v1/auth/token",
    )

    resp = await ctx["client"].post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200
    issuer = ctx["app"].state.local_issuer
    claims = jose_jwt.decode(
        resp.json()["access_token"], issuer.active_key.pubkey_pem,
        algorithms=["ES256"],
        audience="cullis-local",
        issuer="cullis-mastio:acme",
    )
    assert "cnf" not in claims


# ── Validate-side helpers ──────────────────────────────────────────


async def _mint_bound_token(ctx, agent_id="acme::user::alice"):
    """Mint a fresh LOCAL_TOKEN bound to a new DPoP keypair. Returns
    ``(token, priv, jwk, jkt)`` for the validation tests."""
    leaf_key_pem, _, x5c = _issue_leaf(ctx["ca_key"], ctx["ca_cert_pem"], agent_id)
    assertion = _build_assertion(agent_id, leaf_key_pem, x5c)
    priv, jwk = _make_dpop_keypair()
    proof = _build_dpop_proof(
        priv, jwk, "POST", "http://test/v1/auth/token",
    )
    resp = await ctx["client"].post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return token, priv, jwk, _compute_jkt(jwk)


# ── Validate-side tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_validation_accepts_correct_dpop_proof(proxy_app):
    """Happy path — token bound to jkt_X, request carries fresh DPoP
    proof signed by jkt_X. Dep accepts."""
    from mcp_proxy.auth.local_agent_dep import _maybe_local_token

    ctx = proxy_app
    token, priv, jwk, _jkt = await _mint_bound_token(ctx)
    proof = _build_dpop_proof(
        priv, jwk, "GET", "http://test/v1/proxy/agents/list",
        access_token=token,
    )

    # Build a minimal Request stub via Starlette.
    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"dpop", proof.encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    payload = await _maybe_local_token(req)
    assert payload is not None
    assert payload.agent_id == "acme::user::alice"


@pytest.mark.asyncio
async def test_validation_rejects_missing_dpop_when_token_bound(proxy_app):
    """Token has cnf.jkt; request omits DPoP header → 401."""
    from fastapi import HTTPException

    from mcp_proxy.auth.local_agent_dep import _maybe_local_token

    ctx = proxy_app
    token, _priv, _jwk, _jkt = await _mint_bound_token(ctx)

    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    with pytest.raises(HTTPException) as exc:
        await _maybe_local_token(req)
    assert exc.value.status_code == 401
    assert "DPoP-bound" in exc.value.detail


@pytest.mark.asyncio
async def test_validation_rejects_dpop_signed_by_different_key(proxy_app):
    """Token bound to jkt_X; request brings DPoP proof signed by jkt_Y
    (attacker exfiltrated the LOCAL_TOKEN bytes but not the private
    key) → 401. This is the headline replay-window closure."""
    from fastapi import HTTPException

    from mcp_proxy.auth.local_agent_dep import _maybe_local_token

    ctx = proxy_app
    token, _orig_priv, _orig_jwk, _ = await _mint_bound_token(ctx)

    # Attacker generates their own DPoP key.
    attacker_priv, attacker_jwk = _make_dpop_keypair()
    attacker_proof = _build_dpop_proof(
        attacker_priv, attacker_jwk, "GET",
        "http://test/v1/proxy/agents/list",
        access_token=token,
    )

    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"dpop", attacker_proof.encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    with pytest.raises(HTTPException) as exc:
        await _maybe_local_token(req)
    assert exc.value.status_code == 401
    assert "cnf.jkt" in exc.value.detail


@pytest.mark.asyncio
async def test_validation_rejects_dpop_with_wrong_ath(proxy_app):
    """Token bound to jkt_X; request brings DPoP proof signed by jkt_X
    but with the wrong access-token hash (proof recycled from a prior
    different-token request) → 401."""
    from fastapi import HTTPException

    from mcp_proxy.auth.local_agent_dep import _maybe_local_token

    ctx = proxy_app
    token, priv, jwk, _ = await _mint_bound_token(ctx)
    other_token = "this-is-some-other-token"
    bad_ath_proof = _build_dpop_proof(
        priv, jwk, "GET", "http://test/v1/proxy/agents/list",
        access_token=other_token,
    )

    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {token}".encode()),
            (b"dpop", bad_ath_proof.encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    with pytest.raises(HTTPException) as exc:
        await _maybe_local_token(req)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_validation_legacy_unbound_token_accepted_by_default(proxy_app):
    """Token minted before this fix has no cnf.jkt. With the require
    flag off (default) the dep accepts it as plain Bearer + warns —
    so in-flight tokens within the existing TTL window aren't bricked
    by the upgrade."""
    from mcp_proxy.auth.local_agent_dep import _maybe_local_token

    ctx = proxy_app
    issuer = ctx["app"].state.local_issuer
    legacy_token = issuer.issue(agent_id="acme::user::alice", ttl_seconds=300)

    from starlette.requests import Request as StarletteRequest
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {legacy_token.token}".encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    payload = await _maybe_local_token(req)
    assert payload is not None
    assert payload.agent_id == "acme::user::alice"


@pytest.mark.asyncio
async def test_validation_legacy_unbound_token_rejected_when_strict(
    proxy_app, monkeypatch,
):
    """Strict mode — once operator flips local_token_require_dpop=true,
    legacy unbound tokens are rejected so the migration is finite."""
    from fastapi import HTTPException

    from mcp_proxy.auth.local_agent_dep import _maybe_local_token
    from mcp_proxy.config import get_settings

    monkeypatch.setattr(
        get_settings(), "local_token_require_dpop", True,
    )

    ctx = proxy_app
    issuer = ctx["app"].state.local_issuer
    legacy_token = issuer.issue(agent_id="acme::user::alice", ttl_seconds=300)

    from starlette.requests import Request as StarletteRequest
    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "path": "/v1/proxy/agents/list",
        "query_string": b"",
        "headers": [
            (b"authorization", f"Bearer {legacy_token.token}".encode()),
        ],
        "app": ctx["app"],
    }
    req = StarletteRequest(scope)
    with pytest.raises(HTTPException) as exc:
        await _maybe_local_token(req)
    assert exc.value.status_code == 401
    assert "re-login required" in exc.value.detail
