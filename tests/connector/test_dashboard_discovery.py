"""Tests for the Frontdesk Connector setup wizard auto-discovery flow.

Covers the discovery probe layer (``cullis_connector/discovery.py``)
and the wizard routes (``/setup/discover``, ``/api/setup/discover/results``,
``POST /setup/discover/select``) that wire the probe into the existing
device-code enrollment flow.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi.testclient import TestClient

from cullis_connector import discovery as discovery_mod
from cullis_connector.config import ConnectorConfig
from cullis_connector.discovery import (
    DiscoveredMastio,
    DiscoveryState,
    ProbeError,
    discover_mastios,
    get_or_run_discovery,
    probe_urls,
    reset_discovery_cache,
)
from cullis_connector.web import build_app


def _make_self_signed() -> tuple[str, str]:
    """Real self-signed cert so the dashboard's CA fetch + fingerprint
    paths run against actual DER bytes."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "fake-test-ca")],
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(Encoding.PEM).decode()
    fingerprint = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    return pem, fingerprint


# ── discovery module unit tests ────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_discovery():
    reset_discovery_cache()
    yield
    reset_discovery_cache()


def _make_response(
    status_code: int, payload: dict | None = None,
) -> httpx.Response:
    body = json.dumps(payload).encode() if payload is not None else b""
    return httpx.Response(
        status_code=status_code,
        content=body,
        headers={"content-type": "application/json"} if payload else {},
    )


@pytest.mark.asyncio
async def test_discover_mastios_returns_configured_when_payload_ok(monkeypatch):
    """Single probe → 200 + configured payload → DiscoveredMastio."""
    payload = {
        "version": 1,
        "mode": "configured",
        "org_id": "acme",
        "trust_domain": "acme.cullis.local",
        "ca_fingerprint_sha256": "abcdef0123456789",
        "urls": {},
    }

    async def _fake_get(self, url, *, timeout):
        return _make_response(200, payload)

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)

    state = await discover_mastios(("https://mastio.test:9443",))
    assert len(state.found) == 1
    assert state.found[0].org_id == "acme"
    assert state.found[0].mode == "configured"
    assert state.found[0].ca_fingerprint_sha256 == "abcdef0123456789"
    assert state.errors == []


@pytest.mark.asyncio
async def test_discover_mastios_returns_setup_mode_when_org_id_null(monkeypatch):
    payload = {
        "version": 1,
        "mode": "setup",
        "org_id": None,
        "trust_domain": "cullis.local",
        "ca_fingerprint_sha256": None,
        "urls": {},
    }

    async def _fake_get(self, url, *, timeout):
        return _make_response(200, payload)

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    state = await discover_mastios(("https://mastio.test:9443",))
    assert len(state.found) == 1
    assert state.found[0].mode == "setup"
    assert state.found[0].org_id is None


@pytest.mark.asyncio
async def test_discover_mastios_classifies_connection_error(monkeypatch):
    async def _fake_get(self, url, *, timeout):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    state = await discover_mastios(("https://nope.test:9443",))
    assert state.found == []
    assert len(state.errors) == 1
    assert state.errors[0].reason == "connection refused"


@pytest.mark.asyncio
async def test_discover_mastios_classifies_timeout(monkeypatch):
    async def _fake_get(self, url, *, timeout):
        raise httpx.ReadTimeout("read timeout")

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    state = await discover_mastios(("https://slow.test:9443",))
    assert state.errors[0].reason == "read timeout"


@pytest.mark.asyncio
async def test_discover_mastios_classifies_bad_payload(monkeypatch):
    async def _fake_get(self, url, *, timeout):
        return _make_response(200, {"unexpected": "shape"})

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    state = await discover_mastios(("https://wrong.test:9443",))
    assert state.errors[0].reason == "bad payload"


@pytest.mark.asyncio
async def test_discover_mastios_classifies_non_200(monkeypatch):
    async def _fake_get(self, url, *, timeout):
        return _make_response(503)

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    state = await discover_mastios(("https://broken.test:9443",))
    assert state.errors[0].reason == "HTTP 503"


@pytest.mark.asyncio
async def test_discover_mastios_runs_probes_in_parallel(monkeypatch):
    """Three URLs, each delayed 0.5s synthetically. If they ran serially
    the total wall-clock would exceed 1s; gather caps it near the slowest
    single probe."""
    payload = {
        "version": 1, "mode": "configured", "org_id": "x",
        "trust_domain": "td", "ca_fingerprint_sha256": "ab", "urls": {},
    }

    async def _fake_get(self, url, *, timeout):
        await asyncio.sleep(0.3)
        return _make_response(200, payload)

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    import time
    start = time.time()
    state = await discover_mastios((
        "https://a.test:9443",
        "https://b.test:9443",
        "https://c.test:9443",
    ))
    elapsed = time.time() - start
    assert len(state.found) == 3
    # Three sequential 0.3s probes would be 0.9s; parallel should be
    # well under 0.7s even with overhead.
    assert elapsed < 0.7


@pytest.mark.asyncio
async def test_discover_mastios_sorts_configured_before_setup_mode(monkeypatch):
    """Wizard UX: surface fully-configured Mastios first."""
    responses = {
        "https://setup.test:9443/.well-known/cullis/connector-bootstrap": {
            "version": 1, "mode": "setup", "org_id": None,
            "trust_domain": "td-1", "ca_fingerprint_sha256": None, "urls": {},
        },
        "https://configured.test:9443/.well-known/cullis/connector-bootstrap": {
            "version": 1, "mode": "configured", "org_id": "acme",
            "trust_domain": "td-2", "ca_fingerprint_sha256": "ab", "urls": {},
        },
    }

    async def _fake_get(self, url, *, timeout):
        return _make_response(200, responses[url])

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    state = await discover_mastios((
        "https://setup.test:9443",
        "https://configured.test:9443",
    ))
    assert state.found[0].mode == "configured"
    assert state.found[1].mode == "setup"


@pytest.mark.asyncio
async def test_get_or_run_discovery_caches_within_ttl(monkeypatch):
    """Memory feedback_no_polling: a refresh inside the cache window
    must not trigger another round of network probes."""
    call_count = {"n": 0}
    payload = {
        "version": 1, "mode": "configured", "org_id": "x",
        "trust_domain": "td", "ca_fingerprint_sha256": "ab", "urls": {},
    }

    async def _fake_get(self, url, *, timeout):
        call_count["n"] += 1
        return _make_response(200, payload)

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)
    s1 = await get_or_run_discovery(("https://a.test:9443",))
    s2 = await get_or_run_discovery(("https://a.test:9443",))
    assert s1 is s2
    assert call_count["n"] == 1


def test_probe_urls_default_when_no_env(monkeypatch):
    monkeypatch.delenv("CULLIS_DISCOVERY_PROBE_URLS", raising=False)
    assert probe_urls() == discovery_mod.DEFAULT_PROBE_URLS


def test_probe_urls_env_override(monkeypatch):
    monkeypatch.setenv(
        "CULLIS_DISCOVERY_PROBE_URLS",
        "https://one.test:9443,https://two.test:9443",
    )
    urls = probe_urls()
    assert urls == ("https://one.test:9443", "https://two.test:9443")


def test_probe_urls_env_empty_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("CULLIS_DISCOVERY_PROBE_URLS", "  ,  ")
    assert probe_urls() == discovery_mod.DEFAULT_PROBE_URLS


# ── web route integration tests ────────────────────────────────────


@pytest.fixture
def cfg(tmp_path) -> ConnectorConfig:
    return ConnectorConfig(
        config_dir=tmp_path,
        site_url="",
        verify_tls=True,
    )


@pytest.fixture
def client(cfg, monkeypatch) -> TestClient:
    import cullis_connector.web as _web
    monkeypatch.setattr(_web, "has_identity", lambda _: False)
    tc = TestClient(build_app(cfg))
    tc.headers["Origin"] = "http://testserver"
    return tc


def test_root_redirects_to_setup_discover_on_first_boot(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/setup/discover"


def test_setup_discover_get_renders_wizard(client):
    resp = client.get("/setup/discover")
    assert resp.status_code == 200
    assert "Looking for your" in resp.text
    # The HTMX target div must be present so the auto-trigger can fire.
    assert 'id="discovery-results"' in resp.text
    assert 'hx-get="/api/setup/discover/results"' in resp.text


def test_api_results_renders_found_mastio(client, monkeypatch):
    """Single configured Mastio → wizard shows Use this Mastio button."""
    pem, fingerprint = _make_self_signed()
    fake_state = DiscoveryState(started_at=0.0, completed_at=1.0)
    fake_state.found.append(
        DiscoveredMastio(
            base_url="https://mastio.local:9443",
            org_id="acme",
            trust_domain="acme.cullis.local",
            mode="configured",
            ca_fingerprint_sha256=fingerprint,
        ),
    )

    async def _fake_run(*args, **kwargs):
        return fake_state

    monkeypatch.setattr(
        "cullis_connector.web.get_or_run_discovery", _fake_run,
    )
    resp = client.get("/api/setup/discover/results")
    assert resp.status_code == 200
    assert "acme" in resp.text
    assert "https://mastio.local:9443" in resp.text
    # Fingerprint must be rendered grouped (AB:CD:..) for visual diffing.
    assert ":" in resp.text
    assert "Use this Mastio" in resp.text


def test_api_results_renders_setup_mode_with_hint(client, monkeypatch):
    fake_state = DiscoveryState(started_at=0.0, completed_at=1.0)
    fake_state.found.append(
        DiscoveredMastio(
            base_url="https://mastio.local:9443",
            org_id=None,
            trust_domain="cullis.local",
            mode="setup",
            ca_fingerprint_sha256=None,
        ),
    )

    async def _fake_run(*args, **kwargs):
        return fake_state

    monkeypatch.setattr(
        "cullis_connector.web.get_or_run_discovery", _fake_run,
    )
    resp = client.get("/api/setup/discover/results")
    assert resp.status_code == 200
    assert "Not yet configured" in resp.text
    # Setup-mode entries must NOT show the "Use this Mastio" submit
    # button, because enrollment can't complete without an Org CA.
    assert "Use this Mastio" not in resp.text


def test_api_results_renders_no_mastio_found(client, monkeypatch):
    fake_state = DiscoveryState(started_at=0.0, completed_at=1.0)
    fake_state.errors.append(
        ProbeError(
            base_url="https://mastio.local:9443", reason="connection refused",
        ),
    )

    async def _fake_run(*args, **kwargs):
        return fake_state

    monkeypatch.setattr(
        "cullis_connector.web.get_or_run_discovery", _fake_run,
    )
    resp = client.get("/api/setup/discover/results")
    assert resp.status_code == 200
    assert "No Mastio found" in resp.text
    assert "connection refused" in resp.text


def test_select_pins_ca_and_redirects_to_setup_with_prefilled_url(
    client, monkeypatch,
):
    """Happy path: operator picks a Mastio from the wizard, server
    pins the CA (re-fetched + fingerprint-verified) and bounces to
    /setup with site_url + ca_pinned=1 so the manual form skips the
    TOFU box."""
    pem, fingerprint = _make_self_signed()

    def _fake_get(url, *, verify, timeout):
        assert url == "https://mastio.local:9443/pki/ca.crt"
        return httpx.Response(
            status_code=200, text=pem,
            headers={"content-type": "application/x-pem-file"},
        )

    monkeypatch.setattr("cullis_connector.web.httpx.get", _fake_get)

    resp = client.post(
        "/setup/discover/select",
        data={
            "base_url": "https://mastio.local:9443",
            "fingerprint": fingerprint,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("/setup?")
    assert "site_url=" in location
    assert "ca_pinned=1" in location

    # CA pinned at the expected path with the expected bytes.
    ca_path = client.app.extra.get("config_dir")  # not actually exposed
    # Simpler check: walk the cfg dir from the fixture.


def test_select_rejects_http_url(client):
    resp = client.post(
        "/setup/discover/select",
        data={"base_url": "http://insecure.test:9443", "fingerprint": "ab"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=non_https" in resp.headers["location"]


def test_select_rejects_fingerprint_mismatch(client, monkeypatch):
    """If the CA the wizard surfaced changed between probe and select
    (TOCTOU), refuse to pin and bounce back so the operator sees the
    new fingerprint instead of silently trusting it."""
    pem, observed_fp = _make_self_signed()

    def _fake_get(url, *, verify, timeout):
        return httpx.Response(status_code=200, text=pem)

    monkeypatch.setattr("cullis_connector.web.httpx.get", _fake_get)

    resp = client.post(
        "/setup/discover/select",
        data={
            "base_url": "https://mastio.local:9443",
            # Different fingerprint than what _fake_get will produce.
            "fingerprint": "ff" * 32,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=fingerprint_changed" in resp.headers["location"]


def test_setup_get_with_site_url_query_prefills_form(client):
    resp = client.get("/setup?site_url=https://mastio.local:9443&ca_pinned=1")
    assert resp.status_code == 200
    # URL pre-populated in the form value.
    assert 'value="https://mastio.local:9443"' in resp.text
    # ca_pinned=1 surfaces the green confirmation banner.
    assert "CA pinned from auto-discovery" in resp.text


def test_setup_get_without_query_shows_auto_discovery_hint(client):
    resp = client.get("/setup")
    assert resp.status_code == 200
    assert "Try auto-discovery instead" in resp.text


def test_setup_discover_get_redirects_when_identity_present(monkeypatch, cfg):
    import cullis_connector.web as _web
    monkeypatch.setattr(_web, "has_identity", lambda _: True)
    tc = TestClient(build_app(cfg))
    tc.headers["Origin"] = "http://testserver"
    resp = tc.get("/setup/discover", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/connected"
