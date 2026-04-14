"""Phase 2c — admin dashboard pages for pending Connector enrollments.

Covers the HTML routes under ``/proxy/enrollments``:

  - GET redirects to /proxy/login when unauthenticated
  - GET renders the list with one row per pending enrollment
  - POST approve wires through the service layer (cert issued, status flipped)
  - POST reject flips status and records the reason
  - CSRF hidden field is mandatory on both mutating endpoints

Complements ``tests/test_enrollment.py`` which exercises the JSON API.
"""
from __future__ import annotations

import json as _json
import time as _time
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient


# ── Helpers ──────────────────────────────────────────────────────


def _ec_pubkey_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _generate_self_signed_ca(org_id: str) -> tuple[str, str]:
    """Minimal self-signed CA. Returns (key_pem, cert_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id}-ca"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _admin_cookie(csrf_token: str = "test-csrf-token") -> tuple[str, str]:
    """Mint a signed session cookie + matching CSRF token."""
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign

    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf_token, "exp": int(_time.time()) + 3600}
    )
    return _COOKIE_NAME, _sign(payload)


# ── Fixture: proxy app with CA-equipped AgentManager ────────────────


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            # Attach a CA-loaded AgentManager so approval can sign certs.
            from mcp_proxy.egress.agent_manager import AgentManager

            mgr = AgentManager(org_id="acme", trust_domain="cullis.local")
            ca_key, ca_cert = _generate_self_signed_ca("acme")
            await mgr.load_org_ca(ca_key, ca_cert)
            app.state.agent_manager = mgr
            yield app, client
    get_settings.cache_clear()


async def _start_enrollment(client: AsyncClient, name: str = "Mario Rossi") -> str:
    resp = await client.post(
        "/v1/enrollment/start",
        json={
            "pubkey_pem": _ec_pubkey_pem(),
            "requester_name": name,
            "requester_email": "mario@acme.com",
            "reason": "Onboarding via dashboard test",
            "device_info": '{"os":"linux","host":"laptop-01"}',
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["session_id"]


# ── GET /proxy/enrollments ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_enrollments_requires_login(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/enrollments", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/proxy/login"


@pytest.mark.asyncio
async def test_get_enrollments_lists_pending(proxy_app):
    _, client = proxy_app
    session_id = await _start_enrollment(client, name="Mario Rossi")

    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/enrollments")
    assert resp.status_code == 200
    body = resp.text
    assert "Pending Enrollments" in body
    assert "Mario Rossi" in body
    assert "mario@acme.com" in body
    # Form actions for both mutations are rendered per-row.
    assert f"/proxy/enrollments/{session_id}/approve" in body
    assert f"/proxy/enrollments/{session_id}/reject" in body
    # CSRF hidden field is emitted.
    assert 'name="csrf_token"' in body


@pytest.mark.asyncio
async def test_get_enrollments_empty_state(proxy_app):
    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/enrollments")
    assert resp.status_code == 200
    assert "No pending enrollments" in resp.text


# ── POST /proxy/enrollments/{id}/approve ───────────────────────────


@pytest.mark.asyncio
async def test_approve_via_dashboard_issues_cert(proxy_app):
    app, client = proxy_app
    session_id = await _start_enrollment(client)

    csrf = "dashboard-csrf-approve"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        f"/proxy/enrollments/{session_id}/approve",
        data={
            "csrf_token": csrf,
            "agent_id": "agent-mrossi",
            "capabilities": "procurement.read, erp.query",
            "groups": "procurement",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    assert "/proxy/enrollments" in resp.headers["location"]

    # Verify the record flipped to approved and a cert was persisted.
    from mcp_proxy.db import get_db
    from mcp_proxy.enrollment import service

    async with get_db() as conn:
        record = await service.get_record(conn, session_id)
    assert record["status"] == "approved"
    assert record["agent_id_assigned"] == "agent-mrossi"
    assert record["cert_pem"]
    # Cert CN reflects org::agent_id binding (service-layer invariant).
    cert = x509.load_pem_x509_certificate(record["cert_pem"].encode())
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cns[0].value == "acme::agent-mrossi"
    # Capabilities persisted as JSON in assigned column.
    caps = _json.loads(record["capabilities_assigned"])
    assert caps == ["procurement.read", "erp.query"]


@pytest.mark.asyncio
async def test_approve_missing_csrf_is_403(proxy_app):
    _, client = proxy_app
    session_id = await _start_enrollment(client)
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        f"/proxy/enrollments/{session_id}/approve",
        data={"agent_id": "agent-x"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_approve_missing_agent_id_redirects_with_error(proxy_app):
    _, client = proxy_app
    session_id = await _start_enrollment(client)

    csrf = "dashboard-csrf-err"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        f"/proxy/enrollments/{session_id}/approve",
        data={"csrf_token": csrf, "agent_id": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]


# ── POST /proxy/enrollments/{id}/reject ────────────────────────────


@pytest.mark.asyncio
async def test_reject_via_dashboard_flips_status(proxy_app):
    _, client = proxy_app
    session_id = await _start_enrollment(client)

    csrf = "dashboard-csrf-reject"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        f"/proxy/enrollments/{session_id}/reject",
        data={"csrf_token": csrf, "reason": "No approval ticket on file."},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text

    from mcp_proxy.db import get_db
    from mcp_proxy.enrollment import service

    async with get_db() as conn:
        record = await service.get_record(conn, session_id)
    assert record["status"] == "rejected"
    assert record["rejection_reason"] == "No approval ticket on file."


@pytest.mark.asyncio
async def test_reject_missing_reason_redirects_with_error(proxy_app):
    _, client = proxy_app
    session_id = await _start_enrollment(client)
    csrf = "dashboard-csrf-reject-empty"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        f"/proxy/enrollments/{session_id}/reject",
        data={"csrf_token": csrf, "reason": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]


@pytest.mark.asyncio
async def test_reject_missing_csrf_is_403(proxy_app):
    _, client = proxy_app
    session_id = await _start_enrollment(client)
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        f"/proxy/enrollments/{session_id}/reject",
        data={"reason": "nope"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


# ── Nav badge ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_badge_enrollments_shows_count(proxy_app):
    _, client = proxy_app
    await _start_enrollment(client, name="A")
    await _start_enrollment(client, name="B")

    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/badge/enrollments")
    assert resp.status_code == 200
    assert ">2<" in resp.text


@pytest.mark.asyncio
async def test_badge_enrollments_empty_when_unauth(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/badge/enrollments")
    assert resp.status_code == 200
    assert resp.text == ""
