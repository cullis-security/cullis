"""Tests for Cullis Frontdesk shared mode (ADR-021 PR4b).

Five layers, all in this file for now:

  1. ``shared/cookie.py``          HMAC-signed session cookies
  2. ``shared/proxy_trust.py``     X-Forwarded-User trust + allowlist
  3. ``shared/credentials.py``     LRU + TTL credential cache
  4. ``shared/provisioning.py``    KMS-less keypair → CSR → Mastio sign
  5. ``shared/router.py``          FastAPI surface end-to-end
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cullis_connector.ambassador.shared.cookie import (
    SessionPayload, issue, make_cookie, parse_cookie,
)
from cullis_connector.ambassador.shared.credentials import (
    UserCredentialCache, UserCredentials,
)
from cullis_connector.ambassador.shared.provisioning import (
    HttpxMastioCsrTransport, MastioCsrError, UserProvisioner,
)
from cullis_connector.ambassador.shared.proxy_trust import (
    TrustedProxiesAllowlist, extract_sso_subject,
)
from cullis_connector.ambassador.shared.router import (
    COOKIE_NAME, install_shared_ambassador,
)


SECRET = b"x" * 32


# ─────────────────────────────────────────────────────────────────
# 1) cookie.py
# ─────────────────────────────────────────────────────────────────


def test_cookie_roundtrip_happy():
    cookie, payload = issue(
        sub="mario@acme.it", org="acme",
        principal_id="acme.test/acme/user/mario",
        secret=SECRET, ttl_seconds=3600,
    )
    parsed = parse_cookie(cookie, SECRET)
    assert parsed == payload


def test_cookie_tampered_payload_fails():
    cookie, _ = issue(
        sub="mario@acme.it", org="acme",
        principal_id="acme.test/acme/user/mario",
        secret=SECRET, ttl_seconds=3600,
    )
    payload_b64, sig = cookie.split(".", 1)
    raw = base64.urlsafe_b64decode(payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4))
    obj = json.loads(raw)
    obj["sub"] = "anna@acme.it"
    new_payload = base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":"), sort_keys=True).encode(),
    ).rstrip(b"=").decode()
    tampered = f"{new_payload}.{sig}"
    assert parse_cookie(tampered, SECRET) is None


def test_cookie_wrong_secret_fails():
    cookie, _ = issue(
        sub="mario@acme.it", org="acme",
        principal_id="acme.test/acme/user/mario",
        secret=SECRET, ttl_seconds=3600,
    )
    assert parse_cookie(cookie, b"y" * 32) is None


def test_cookie_expired_fails():
    payload = SessionPayload(
        sub="mario@acme.it", org="acme",
        principal_id="acme.test/acme/user/mario",
        iat=1000, exp=2000,
    )
    cookie = make_cookie(payload, SECRET)
    assert parse_cookie(cookie, SECRET, now=2001) is None
    assert parse_cookie(cookie, SECRET, now=1500) == payload


def test_cookie_issued_in_future_fails():
    cookie, _ = issue(
        sub="mario@acme.it", org="acme",
        principal_id="acme.test/acme/user/mario",
        secret=SECRET, ttl_seconds=3600, now=10_000,
    )
    assert parse_cookie(cookie, SECRET, now=5_000) is None


def test_cookie_malformed_returns_none():
    assert parse_cookie("not-a-cookie", SECRET) is None
    assert parse_cookie("", SECRET) is None
    assert parse_cookie(".", SECRET) is None
    assert parse_cookie("a.b", SECRET) is None


def test_cookie_secret_too_short_raises():
    with pytest.raises(ValueError, match="16 bytes"):
        issue(
            sub="x", org="a", principal_id="td/a/user/x",
            secret=b"short", ttl_seconds=60,
        )


def test_cookie_ttl_bounds():
    with pytest.raises(ValueError, match="ttl_seconds"):
        issue(sub="x", org="a", principal_id="td/a/user/x",
              secret=SECRET, ttl_seconds=0)
    with pytest.raises(ValueError, match="ttl_seconds"):
        issue(sub="x", org="a", principal_id="td/a/user/x",
              secret=SECRET, ttl_seconds=24 * 3600 + 1)


def test_cookie_size_cap():
    # Very long principal_id should bust the soft cap.
    with pytest.raises(ValueError, match="payload too large"):
        issue(
            sub="x" * 1024, org="a",
            principal_id="td/a/user/" + "x" * 1024,
            secret=SECRET, ttl_seconds=60,
        )


# ─────────────────────────────────────────────────────────────────
# 2) proxy_trust.py
# ─────────────────────────────────────────────────────────────────


def test_allowlist_loopback_default():
    al = TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32", "::1/128"])
    assert al.contains("127.0.0.1") is True
    assert al.contains("::1") is True
    assert al.contains("10.0.0.5") is False


def test_allowlist_cidr_range():
    al = TrustedProxiesAllowlist.from_cidrs(["10.0.0.0/8"])
    assert al.contains("10.5.6.7") is True
    assert al.contains("11.0.0.1") is False


def test_allowlist_empty_raises():
    with pytest.raises(ValueError, match="cannot be empty"):
        TrustedProxiesAllowlist.from_cidrs([])


def test_allowlist_invalid_cidr_raises():
    with pytest.raises(ValueError, match="invalid CIDR"):
        TrustedProxiesAllowlist.from_cidrs(["not-a-cidr"])


def test_allowlist_invalid_peer_returns_false():
    al = TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32"])
    assert al.contains("not-an-ip") is False


def test_extract_sso_subject_happy():
    assert extract_sso_subject({"x-forwarded-user": "mario@acme.it"}) == "mario@acme.it"


def test_extract_sso_subject_missing():
    assert extract_sso_subject({}) is None
    assert extract_sso_subject({"x-forwarded-user": ""}) is None


def test_extract_sso_subject_rejects_control_chars():
    assert extract_sso_subject({"x-forwarded-user": "mario\nanna@acme.it"}) is None
    assert extract_sso_subject({"x-forwarded-user": "x" * 500}) is None


# ─────────────────────────────────────────────────────────────────
# 3) credentials.py
# ─────────────────────────────────────────────────────────────────


def _make_cred(principal_id="acme.test/acme/user/mario", *, ttl_s=3600):
    return UserCredentials(
        principal_id=principal_id,
        cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        key_pem="-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        cert_not_after=datetime.now(timezone.utc) + timedelta(seconds=ttl_s),
    )


@pytest.mark.asyncio
async def test_cache_get_miss():
    cache = UserCredentialCache()
    assert await cache.get("acme.test/acme/user/ghost") is None


@pytest.mark.asyncio
async def test_cache_put_then_get():
    cache = UserCredentialCache()
    cred = _make_cred()
    await cache.put(cred)
    assert await cache.get(cred.principal_id) == cred


@pytest.mark.asyncio
async def test_cache_lazy_expiry_evicts():
    cache = UserCredentialCache()
    cred = UserCredentials(
        principal_id="acme.test/acme/user/mario",
        cert_pem="", key_pem="",
        cert_not_after=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    await cache.put(cred)
    assert await cache.get(cred.principal_id) is None
    assert await cache.size() == 0


@pytest.mark.asyncio
async def test_cache_lru_eviction():
    cache = UserCredentialCache(max_size=2)
    a = _make_cred("td/o/user/a")
    b = _make_cred("td/o/user/b")
    c = _make_cred("td/o/user/c")
    await cache.put(a)
    await cache.put(b)
    await cache.put(c)  # evicts a
    assert await cache.get("td/o/user/a") is None
    assert await cache.get("td/o/user/b") == b
    assert await cache.get("td/o/user/c") == c


@pytest.mark.asyncio
async def test_cache_invalidate():
    cache = UserCredentialCache()
    cred = _make_cred()
    await cache.put(cred)
    assert await cache.invalidate(cred.principal_id) is True
    assert await cache.invalidate(cred.principal_id) is False
    assert await cache.get(cred.principal_id) is None


def test_cache_max_size_validation():
    with pytest.raises(ValueError, match="max_size"):
        UserCredentialCache(max_size=0)


# ─────────────────────────────────────────────────────────────────
# 4) provisioning.py
# ─────────────────────────────────────────────────────────────────


@dataclass
class _StubMastio:
    """Records calls + returns canned cert."""

    cert_pem: str = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
    not_after_iso: str = "2099-12-31T23:59:59+00:00"
    fail_with: Exception | None = None
    calls: list[tuple[str, str]] = None  # type: ignore[assignment]

    def __post_init__(self):
        self.calls = []

    async def sign_csr(self, *, principal_id: str, csr_pem: str):
        self.calls.append((principal_id, csr_pem))
        if self.fail_with is not None:
            raise self.fail_with
        return self.cert_pem, datetime.fromisoformat(self.not_after_iso)


@pytest.mark.asyncio
async def test_provisioner_cache_miss_then_provision():
    cache = UserCredentialCache()
    mastio = _StubMastio()
    p = UserProvisioner(mastio=mastio, cache=cache)

    cred = await p.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    assert cred.cert_pem == mastio.cert_pem
    assert cred.principal_id == "acme.test/acme/user/mario"
    assert "BEGIN PRIVATE KEY" in cred.key_pem
    # CSR was sent to Mastio with the right principal_id.
    assert len(mastio.calls) == 1
    assert mastio.calls[0][0] == "acme.test/acme/user/mario"
    assert "BEGIN CERTIFICATE REQUEST" in mastio.calls[0][1]
    # Cached for the next call.
    assert await cache.get("acme.test/acme/user/mario") == cred


@pytest.mark.asyncio
async def test_provisioner_cache_hit_skips_mastio():
    cache = UserCredentialCache()
    mastio = _StubMastio()
    p = UserProvisioner(mastio=mastio, cache=cache)

    await p.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    await p.get_or_provision(
        principal_id="acme.test/acme/user/mario",
        sso_subject="mario@acme.it",
    )
    assert len(mastio.calls) == 1


@pytest.mark.asyncio
async def test_provisioner_propagates_mastio_failure():
    cache = UserCredentialCache()
    mastio = _StubMastio(fail_with=MastioCsrError("Mastio said no"))
    p = UserProvisioner(mastio=mastio, cache=cache)
    with pytest.raises(MastioCsrError, match="Mastio said no"):
        await p.get_or_provision(
            principal_id="acme.test/acme/user/mario",
            sso_subject="mario@acme.it",
        )
    # Cache stays empty so a retry triggers a fresh attempt.
    assert await cache.size() == 0


@pytest.mark.asyncio
async def test_httpx_transport_201():
    async def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["principal_id"] == "acme.test/acme/user/mario"
        assert "BEGIN CERTIFICATE REQUEST" in body["csr_pem"]
        return httpx.Response(
            201,
            json={
                "cert_pem": "PEM",
                "cert_thumbprint": "x" * 64,
                "cert_not_after": "2099-12-31T23:59:59+00:00",
            },
        )

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as http:
        t = HttpxMastioCsrTransport(http=http, base_url="http://mastio.test")
        cert, not_after = await t.sign_csr(
            principal_id="acme.test/acme/user/mario",
            csr_pem=(
                "-----BEGIN CERTIFICATE REQUEST-----\n"
                + ("AAAA" * 32) + "\n"
                + "-----END CERTIFICATE REQUEST-----\n"
            ),
        )
        assert cert == "PEM"
        assert not_after.year == 2099


@pytest.mark.asyncio
async def test_httpx_transport_non_201_raises():
    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad CSR")

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as http:
        t = HttpxMastioCsrTransport(http=http, base_url="http://mastio.test")
        with pytest.raises(MastioCsrError, match="returned 400"):
            await t.sign_csr(principal_id="x/x/user/x", csr_pem="abc")


@pytest.mark.asyncio
async def test_httpx_transport_missing_fields_raises():
    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"cert_pem": "PEM"})  # no not_after

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as http:
        t = HttpxMastioCsrTransport(http=http, base_url="http://mastio.test")
        with pytest.raises(MastioCsrError, match="missing required fields"):
            await t.sign_csr(principal_id="x/x/user/x", csr_pem="abc")


# ─────────────────────────────────────────────────────────────────
# 5) router.py — endpoint integration
# ─────────────────────────────────────────────────────────────────


@dataclass
class _StubProvisioner:
    """Returns a canned UserCredentials, no Mastio calls."""

    cred: UserCredentials

    async def get_or_provision(self, *, principal_id: str, sso_subject: str):
        return self.cred


def _build_shared_app(
    *,
    trusted_cidrs=("127.0.0.1/32",),
    provisioner=None,
    enforce_proxy_trust: bool = False,
) -> FastAPI:
    app = FastAPI()
    if provisioner is None:
        provisioner = _StubProvisioner(_make_cred())
    install_shared_ambassador(
        app,
        cookie_secret=SECRET * 1,  # 32 bytes
        trusted_proxies=TrustedProxiesAllowlist.from_cidrs(trusted_cidrs),
        org_id="acme",
        trust_domain="acme.test",
        provisioner=provisioner,  # type: ignore[arg-type]
        site_url="https://mastio.test",
        enforce_proxy_trust=enforce_proxy_trust,
    )
    return app


def test_session_init_issues_cookie():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        r = cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["principal_id"] == "acme.test/acme/user/mario"
        assert COOKIE_NAME in r.cookies


def test_session_init_missing_xfu_401():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        r = cli.post("/api/session/init")
        assert r.status_code == 401


def test_session_init_untrusted_proxy_401():
    # Enable the proxy check; TestClient reports "testclient" as host
    # which is not in any CIDR, so enforcement gives 401.
    app = _build_shared_app(
        trusted_cidrs=("10.0.0.0/8",),
        enforce_proxy_trust=True,
    )
    with TestClient(app, base_url="https://testserver") as cli:
        r = cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        assert r.status_code == 401


def test_session_whoami_requires_cookie():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        r = cli.get("/api/session/whoami")
        assert r.status_code == 401


def test_session_whoami_after_init():
    app = _build_shared_app()
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


def test_session_logout_clears_cookie():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        r = cli.post("/api/session/logout")
        assert r.status_code == 200
        # whoami after logout → 401
        # TestClient persists cookies across calls; logout sets Max-Age=0
        # which TestClient honours by removing the cookie.
        r2 = cli.get("/api/session/whoami")
        assert r2.status_code == 401


def test_session_logout_requires_cookie():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        r = cli.post("/api/session/logout")
        assert r.status_code == 401


def test_v1_models_requires_cookie():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        assert cli.get("/v1/models").status_code == 401


def test_v1_models_after_init():
    app = _build_shared_app()
    with TestClient(app, base_url="https://testserver") as cli:
        cli.post(
            "/api/session/init",
            headers={"X-Forwarded-User": "mario@acme.it"},
        )
        r = cli.get("/v1/models")
        assert r.status_code == 200
        assert r.json()["data"][0]["id"] == "claude-haiku-4-5"


def test_install_twice_raises():
    app = _build_shared_app()
    provisioner = _StubProvisioner(_make_cred())
    with pytest.raises(RuntimeError, match="already installed"):
        install_shared_ambassador(
            app,
            cookie_secret=SECRET,
            trusted_proxies=TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32"]),
            org_id="acme",
            trust_domain="acme.test",
            provisioner=provisioner,  # type: ignore[arg-type]
        )


def test_install_short_secret_raises():
    app = FastAPI()
    provisioner = _StubProvisioner(_make_cred())
    with pytest.raises(ValueError, match="32 bytes"):
        install_shared_ambassador(
            app,
            cookie_secret=b"short",
            trusted_proxies=TrustedProxiesAllowlist.from_cidrs(["127.0.0.1/32"]),
            org_id="acme",
            trust_domain="acme.test",
            provisioner=provisioner,  # type: ignore[arg-type]
        )
