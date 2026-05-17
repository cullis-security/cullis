"""ADR-014 PR-B — unit tests for ``get_agent_from_client_cert``.

Drives the auth path that nginx in front of the Mastio feeds via
``X-SSL-Client-Cert`` + ``X-SSL-Client-Verify``. Most of the existing
egress / agents tests exercise this dep transitively via the FastAPI
routes; this file pins the contract directly so future refactors of
the parsing or pinning logic don't silently break.
"""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

from tests._mtls_helpers import (
    _build_test_ca,
    mint_agent_cert,
    mtls_headers,
    provision_internal_agent,
)


# ─────────────────────────────────────────────────────────────────────────────
# App fixture (matches the shape of the rest of the proxy unit tests)
# ─────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")
    monkeypatch.delenv("PROXY_TRANSPORT_INTRA_ORG", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


# ─────────────────────────────────────────────────────────────────────────────
# Direct dep tests — exercising ``get_agent_from_client_cert``
# ─────────────────────────────────────────────────────────────────────────────


def _request_with_headers(headers: dict[str, str]):
    """Stub a starlette Request with just ``.headers`` and ``.url`` — the
    cert dep only reads those, so we don't need the full ASGI surface."""
    request = MagicMock()
    request.headers = headers
    request.url.path = "/v1/egress/peers"
    return request


@pytest.mark.asyncio
async def test_happy_path_authenticates(proxy_app):
    headers = await provision_internal_agent("alice")
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_rejects_missing_verify_header(proxy_app):
    """Defence-in-depth: even with a parseable cert, a missing/wrong
    ``X-SSL-Client-Verify`` is rejected. nginx never reaches mcp-proxy
    without the SUCCESS marker on mTLS-required locations, but a caller
    that bypasses nginx (internal docker net) would skip it."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="alice")
    headers = {
        "X-SSL-Client-Cert": urllib.parse.quote(cert_pem, safe=""),
        # Verify header deliberately missing.
    }
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    body = resp.json()["detail"]
    assert isinstance(body, dict)
    assert body["reason"] == "client_cert_not_verified"


@pytest.mark.asyncio
async def test_rejects_missing_cert_header(proxy_app):
    headers = {"X-SSL-Client-Verify": "SUCCESS"}
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "client_cert_header_missing"


@pytest.mark.asyncio
async def test_rejects_garbage_pem(proxy_app):
    headers = {
        "X-SSL-Client-Cert": "not-a-pem",
        "X-SSL-Client-Verify": "SUCCESS",
    }
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "client_cert_invalid_pem"


@pytest.mark.asyncio
async def test_rejects_unknown_agent(proxy_app):
    """Cert parses fine, SAN says ``acme::stranger``, but no row exists."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="stranger")
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    body = resp.json()["detail"]
    assert body["reason"] == "agent_unknown_or_inactive"
    assert body["agent_id"] == "acme::stranger"


@pytest.mark.asyncio
async def test_rejects_inactive_agent(proxy_app):
    headers = await provision_internal_agent("retired", is_active=False)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rejects_org_mismatch(proxy_app):
    """Mastio's org_id is ``acme``; a cert claiming ``foreign`` is denied
    even if it parses cleanly. Closes the cross-tenant impersonation
    risk a future shared-CA deploy could open."""
    cert_pem, _ = mint_agent_cert(org_id="foreign", agent_name="alice")
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_org_mismatch_response_detail_carries_expected_and_presented(
    proxy_app,
):
    """P3 MAJOR-C — the org-mismatch 401 must surface both
    ``expected_org`` (this Mastio's config) and ``presented_org``
    (from the cert SAN) in a machine-readable JSON body so a
    customer admin / dashboard banner / SPA dispatches on the stable
    token instead of parsing prose. Both values are public-by-design
    (cert SAN, admin-derivable config) — disclosure is safe per the
    controlled-disclosure principle in
    ``feedback_sqlalchemy_exc_leaks_bound_params``.
    """
    cert_pem, _ = mint_agent_cert(org_id="foreign", agent_name="alice")
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401

    body = resp.json()["detail"]
    # MUST be parser-friendly JSON — not a bare string — otherwise
    # customer admins fall back to substring matching.
    assert isinstance(body, dict), (
        f"expected dict body, got {type(body).__name__}: {body!r}"
    )
    assert body["reason"] == "client_cert_org_mismatch"
    assert body["expected_org"] == "acme"
    assert body["presented_org"] == "foreign"
    assert body["agent_name"] == "alice"
    assert body["hint"]
    assert body["docs"].startswith("https://")


@pytest.mark.asyncio
async def test_rejects_cert_pin_mismatch(proxy_app):
    """A cert that chains to the Org CA but isn't the one stored in the
    DB row fails the leaf-DER pin even when the SPIFFE identity matches.
    Mirror of the rotated-cert / off-band-mint defence."""
    # Provision under one cert, then mint a NEW cert with the same SAN
    # but a different keypair — the row's stored cert_pem stays stale.
    real_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="alice")
    fake_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="alice")
    # Insert with the real cert so the row exists.
    from mcp_proxy.db import create_agent
    await create_agent(
        agent_id="acme::alice",
        display_name="alice",
        capabilities=["cap.read"],
        cert_pem=real_cert_pem,
    )
    # Authenticate with the second cert that was never stored.
    headers = mtls_headers(fake_cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    body = resp.json()["detail"]
    assert body["reason"] == "client_cert_pin_mismatch"
    assert body["agent_id"] == "acme::alice"
    assert "cert_serial" in body
    assert "cert_san" in body


@pytest.mark.asyncio
async def test_cn_fallback_when_san_missing(proxy_app, monkeypatch):
    """Legacy certs without the SPIFFE SAN extension fall back to the
    canonical CN ``<org>::<name>``. Exercise the CN-only branch by
    minting a cert without the SAN extension."""
    ca_key, ca_cert = _build_test_ca()
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "acme::legacy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        # No SubjectAlternativeName extension → forces the CN fallback.
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    # Insert the matching row.
    from mcp_proxy.db import create_agent
    await create_agent(
        agent_id="acme::legacy",
        display_name="legacy",
        capabilities=["cap.read"],
        cert_pem=cert_pem,
    )
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 200, resp.text


# ─────────────────────────────────────────────────────────────────────────────
# CRIT-1 (audit T2-C1, 2026-05-11) — typed principal lookup + pubkey pin
# ─────────────────────────────────────────────────────────────────────────────
#
# Before the CRIT-1 fix, the dep skipped registry lookup AND cert pin for
# user/workload principals on the rationale that the chain walk + SPIFFE
# SAN was sufficient. It was not: any Mastio-bound JWT could POST a CSR
# for ``<org>::user::<arbitrary>``, get the Org CA to sign a 1h cert
# bound to the attacker's keypair, then present that cert here and be
# accepted as that arbitrary user. The dep now requires the principal row
# to exist AND the cert's SPKI SHA-256 to match the row's
# ``pubkey_thumbprint`` (TOFU set on first CSR signature).
#
# These tests pin that contract.


async def _provision_typed_principal(
    canonical_id: str,
    *,
    cert_pem: str | None = None,
    pubkey_thumbprint: str | None = None,
    workload: bool = False,
) -> str | None:
    """Insert a row in ``local_user_principals`` / ``local_workload_principals``
    with the given pubkey thumbprint. If ``cert_pem`` is provided, derive
    the thumbprint from the cert's SPKI. If neither is provided, leaves
    pubkey_thumbprint NULL (legacy admin-pre-created row, before any CSR).

    Returns the stored thumbprint (or None when neither input given).
    """
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.db import get_db

    if pubkey_thumbprint is None and cert_pem is not None:
        from cryptography import x509
        from mcp_proxy.registry.principals_csr import pubkey_thumbprint_sha256
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        pubkey_thumbprint = pubkey_thumbprint_sha256(cert.public_key())

    name_part = canonical_id.split("::")[-1]
    now = datetime.now(timezone.utc).isoformat()
    table = "local_workload_principals" if workload else "local_user_principals"
    name_col = "workload_name" if workload else "user_name"

    async with get_db() as conn:
        if workload:
            await conn.execute(
                text(
                    f"INSERT INTO {table} "
                    f"(principal_id, {name_col}, runtime_status, "
                    f" pubkey_thumbprint, created_at) "
                    f"VALUES (:pid, :name, 'unknown', :pubkey, :now)"
                ),
                {
                    "pid": canonical_id, "name": name_part,
                    "pubkey": pubkey_thumbprint, "now": now,
                },
            )
        else:
            await conn.execute(
                text(
                    f"INSERT INTO {table} "
                    f"(principal_id, {name_col}, reach, surface, "
                    f" pubkey_thumbprint, created_at) "
                    f"VALUES (:pid, :name, 'intra', NULL, :pubkey, :now)"
                ),
                {
                    "pid": canonical_id, "name": name_part,
                    "pubkey": pubkey_thumbprint, "now": now,
                },
            )
    return pubkey_thumbprint


@pytest.mark.asyncio
async def test_typed_user_principal_pubkey_pinned_authenticates(proxy_app):
    """Happy path — user principal exists in ``local_user_principals``
    with pubkey_thumbprint matching the presented cert. Dep returns a
    user-typed InternalAgent without consulting ``internal_agents``."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::mario")
    await _provision_typed_principal("acme::user::mario", cert_pem=cert_pem)
    headers = mtls_headers(cert_pem)

    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    request.app = MagicMock()
    request.app.state = MagicMock()

    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    agent = await get_agent_from_client_cert(request)

    assert agent.agent_id == "acme::user::mario"
    assert agent.principal_type == "user"
    assert agent.cert_pem is None  # typed principals don't hold a cert in IAgent
    assert agent.reach == "intra"


@pytest.mark.asyncio
async def test_typed_user_principal_unknown_rejected(proxy_app):
    """CRIT-1 — cert chains to Org CA + SPIFFE SAN well-formed, but the
    user principal is not registered. Pre-fix this slipped through;
    post-fix this is 401 ``user principal unknown``."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::nobody")
    headers = mtls_headers(cert_pem)

    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from fastapi import HTTPException
    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    with pytest.raises(HTTPException) as exc_info:
        await get_agent_from_client_cert(request)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reason"] == "typed_principal_unknown"
    assert exc_info.value.detail["principal_kind"] == "user"
    assert exc_info.value.detail["principal_id"] == "acme::user::nobody"


@pytest.mark.asyncio
async def test_typed_user_principal_pubkey_unset_rejected(proxy_app):
    """CRIT-1 — admin pre-created the row via ``POST /v1/admin/users``
    but no CSR has been signed yet, so ``pubkey_thumbprint`` is NULL.
    The cert presented chains correctly but the pin column is empty —
    refuse rather than admit on the chain alone."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::pending")
    await _provision_typed_principal(
        "acme::user::pending",
        pubkey_thumbprint=None,  # explicit: pre-created, not yet enrolled
    )
    headers = mtls_headers(cert_pem)

    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from fastapi import HTTPException
    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    with pytest.raises(HTTPException) as exc_info:
        await get_agent_from_client_cert(request)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reason"] == "typed_principal_not_yet_enrolled"
    assert exc_info.value.detail["principal_id"] == "acme::user::pending"


@pytest.mark.asyncio
async def test_typed_user_principal_pubkey_mismatch_rejected(proxy_app):
    """CRIT-1 — the headline impersonation defence. Attacker mints a
    cert with their own keypair for ``acme::user::ceo``. The principal
    is registered (TOFU pinned to the legitimate user's keypair). The
    attacker's cert chains correctly, the SPIFFE SAN is well-formed,
    but the SPKI SHA-256 does not match the stored thumbprint. 401."""
    legit_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::ceo")
    await _provision_typed_principal(
        "acme::user::ceo", cert_pem=legit_cert_pem,
    )
    # Attacker's cert: same identity, different keypair.
    attacker_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::ceo")
    headers = mtls_headers(attacker_cert_pem)

    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from fastapi import HTTPException
    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    with pytest.raises(HTTPException) as exc_info:
        await get_agent_from_client_cert(request)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reason"] == "client_cert_pubkey_not_bound_to_principal"
    assert exc_info.value.detail["principal_id"] == "acme::user::ceo"


def _capture_warnings(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Patch ``mcp_proxy.auth.client_cert._log.warning`` and return the
    captured rendered messages.

    The ``mcp_proxy`` logger sets ``propagate=False`` (see
    ``feedback_mcp_proxy_logger_caplog`` in personal memory), so
    ``caplog`` never sees its records under pytest's default setup.
    Patching the module-level ``_log.warning`` is the established
    workaround across the rest of the test suite.
    """
    captured: list[str] = []
    from mcp_proxy.auth import client_cert as _client_cert_mod

    def _record(fmt: str, *args, **kwargs):  # noqa: ANN001
        try:
            captured.append(fmt % args if args else fmt)
        except (TypeError, ValueError):
            captured.append(fmt)

    monkeypatch.setattr(_client_cert_mod._log, "warning", _record)
    return captured


@pytest.mark.asyncio
async def test_pubkey_pin_mismatch_warning_carries_diagnostic_fields(
    proxy_app, monkeypatch,
):
    """Diagnostic regression guard for L3b.

    When the cert pubkey SPKI hash does not match the stored TOFU pin,
    the ``WARNING`` log must carry enough forensic detail to identify
    which cert was presented and which pin it failed against — without
    requiring an in-container ``pdb`` session on the next dogfood. The
    fields we lock in:

      * ``principal=``: which typed principal the cert claims.
      * ``presented_spki_sha256=``: full SHA-256 hex of the presented
        cert's SubjectPublicKeyInfo DER.
      * ``stored_spki_sha256=``: full SHA-256 hex of the pin row.
      * ``cert_serial=``: lowercase hex of the cert's serial number
        (cross-ref against ``/v1/principals/csr`` audit).
      * ``cert_san=``: first SPIFFE URI in the cert's SAN.

    Removing or renaming any of these fields breaks customer-path
    incident response. If a future change really must rename one,
    update this assert AND the corresponding ``imp/`` runbook entry.
    """
    from cryptography import x509

    captured = _capture_warnings(monkeypatch)

    legit_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::ceo")
    await _provision_typed_principal(
        "acme::user::ceo", cert_pem=legit_cert_pem,
    )
    attacker_cert_pem, _ = mint_agent_cert(
        org_id="acme", agent_name="user::ceo",
    )
    attacker_cert = x509.load_pem_x509_certificate(
        attacker_cert_pem.encode("utf-8"),
    )
    expected_serial_hex = f"{attacker_cert.serial_number:x}"

    headers = mtls_headers(attacker_cert_pem)
    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from fastapi import HTTPException
    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    with pytest.raises(HTTPException):
        await get_agent_from_client_cert(request)

    mismatch_msgs = [m for m in captured if "pubkey pin mismatch" in m]
    assert mismatch_msgs, (
        "expected a WARNING containing 'pubkey pin mismatch' so operators "
        "can grep the customer-path 401 in the next dogfood"
    )
    msg = mismatch_msgs[-1]
    assert "principal=acme::user::ceo" in msg
    assert "presented_spki_sha256=" in msg
    assert "stored_spki_sha256=" in msg
    # Different keypairs → different SPKI hashes. The full hashes appear
    # in the message — assert they're DISTINCT to lock in that we log
    # both sides (not e.g. presented twice).
    presented = msg.split("presented_spki_sha256=", 1)[1].split(" ", 1)[0]
    stored = msg.split("stored_spki_sha256=", 1)[1].split(" ", 1)[0]
    assert len(presented) == 64 and len(stored) == 64
    assert presented != stored
    assert f"cert_serial={expected_serial_hex}" in msg
    assert "cert_san=spiffe://" in msg


@pytest.mark.asyncio
async def test_pubkey_pin_unset_warning_carries_diagnostic_fields(
    proxy_app, monkeypatch,
):
    """Sibling regression guard — the "no pin" warning is the other
    arm of the diagnostic. An admin pre-created the principal row but
    no /v1/principals/csr has been signed; the WARNING needs to name
    that explicitly so the operator knows which retry to make."""
    captured = _capture_warnings(monkeypatch)

    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="user::pending")
    await _provision_typed_principal(
        "acme::user::pending", pubkey_thumbprint=None,
    )
    headers = mtls_headers(cert_pem)
    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from fastapi import HTTPException
    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    with pytest.raises(HTTPException):
        await get_agent_from_client_cert(request)

    no_pin_msgs = [m for m in captured if "has no pubkey pin" in m]
    assert no_pin_msgs
    msg = no_pin_msgs[-1]
    assert "principal=acme::user::pending" in msg
    assert "cert_serial=" in msg
    assert "cert_san=spiffe://" in msg


@pytest.mark.asyncio
async def test_typed_workload_principal_pubkey_pinned_authenticates(proxy_app):
    """Happy path workload — same contract as the user case via
    ``local_workload_principals``."""
    cert_pem, _ = mint_agent_cert(
        org_id="acme", agent_name="workload::etl-job",
    )
    await _provision_typed_principal(
        "acme::workload::etl-job", cert_pem=cert_pem, workload=True,
    )
    headers = mtls_headers(cert_pem)

    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    agent = await get_agent_from_client_cert(request)

    assert agent.agent_id == "acme::workload::etl-job"
    assert agent.principal_type == "workload"


@pytest.mark.asyncio
async def test_typed_workload_principal_unknown_rejected(proxy_app):
    """CRIT-1 mirror for workloads — unregistered workload principal
    cert is rejected even though the chain validates."""
    cert_pem, _ = mint_agent_cert(
        org_id="acme", agent_name="workload::stranger",
    )
    headers = mtls_headers(cert_pem)

    request = _request_with_headers(headers)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"

    from fastapi import HTTPException
    from mcp_proxy.auth.client_cert import get_agent_from_client_cert
    with pytest.raises(HTTPException) as exc_info:
        await get_agent_from_client_cert(request)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reason"] == "typed_principal_unknown"
    assert exc_info.value.detail["principal_kind"] == "workload"


# ── Diagnostic helper unit tests ─────────────────────────────────────


def test_strip_log_controls_escapes_cr_lf_drops_nul():
    """Defence-in-depth for log-line spoofing: any CR / LF / NUL
    sneaking through the cert SAN into a downstream plain-text log
    sink must be neutralised before emission. Locks the exact
    transformation so future tweaks (e.g. wider sanitisation) stay
    intentional."""
    from mcp_proxy.auth.client_cert import _strip_log_controls

    raw = "spiffe://td/org/user/alice\r\nfake_field=evil\x00trailing"
    assert _strip_log_controls(raw) == (
        "spiffe://td/org/user/alice\\r\\nfake_field=eviltrailing"
    )
    # Idempotent on already-clean input.
    clean = "spiffe://td/org/user/bob"
    assert _strip_log_controls(clean) == clean
    # Empty + "?" sentinel round-trip unchanged.
    assert _strip_log_controls("") == ""
    assert _strip_log_controls("?") == "?"


def test_cert_first_spiffe_returns_non_spiffe_uri_unchanged():
    """Docstring contract: the helper returns the FIRST URI in the
    cert's SAN regardless of scheme — operators want to SEE a
    wrong-scheme URI (``https://...``) rather than ``"?"`` so they
    can spot a cert that was issued under the wrong identity model."""
    from mcp_proxy.auth.client_cert import _cert_first_spiffe

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "weird"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "weird"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("https://attacker.example/"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    assert _cert_first_spiffe(cert) == "https://attacker.example/"


def test_cert_first_spiffe_no_san_returns_sentinel():
    """A cert without a SAN extension returns ``"?"`` so the log line
    stays structurally constant — downstream regex parsers can rely
    on the field always being present."""
    from mcp_proxy.auth.client_cert import _cert_first_spiffe

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "no-san"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "no-san"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    assert _cert_first_spiffe(cert) == "?"
