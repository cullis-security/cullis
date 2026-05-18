"""Connector enrollment — server-side API + service layer (Phase 2, #64).

Covers:
  - service.start_enrollment / get_record / list_pending / approve / reject
  - TTL lazy expiry and sweep
  - HTTP endpoints: /v1/enrollment/start, /v1/enrollment/{id}/status
  - Admin auth guard + CSRF header on /v1/admin/enrollments
  - AgentManager.sign_external_pubkey: cert bound to supplied pubkey
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from httpx import ASGITransport, AsyncClient

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.enrollment import service
from mcp_proxy.enrollment.service import EnrollmentError


# ── Helpers ────────────────────────────────────────────────────────


def _rsa_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return key, pem


def _ec_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return key, pem


def _rsa_pubkey_pem() -> str:
    return _rsa_keypair()[1]


def _ec_pubkey_pem() -> str:
    return _ec_keypair()[1]


def _sign_pop(priv, pub_pem: str) -> str:
    """Build a valid H-csr-pop signature over ``enrollment-pop:v1|<fp>``.

    Mirrors ``cullis_connector/enrollment.py:_build_pop_signature`` so
    the test calls match what the server's ``_verify_pop_signature``
    accepts.
    """
    pub = serialization.load_pem_public_key(pub_pem.encode())
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(der).hexdigest()
    canonical = f"enrollment-pop:v1|{fp}".encode("utf-8")
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        sig = priv.sign(canonical, ec.ECDSA(hashes.SHA256()))
    else:
        sig = priv.sign(
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def _rsa_pop_kwargs() -> dict[str, str]:
    """Returns ``{pubkey_pem, pop_signature}`` ready to splat into a call."""
    priv, pem = _rsa_keypair()
    return {"pubkey_pem": pem, "pop_signature": _sign_pop(priv, pem)}


def _ec_pop_kwargs() -> dict[str, str]:
    priv, pem = _ec_keypair()
    return {"pubkey_pem": pem, "pop_signature": _sign_pop(priv, pem)}


# ── Service layer tests (SQLite-backed, no HTTP) ───────────────────


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "enrollment.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_start_enrollment_persists_row(db_engine):
    _priv, pubkey = _ec_keypair()
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey,
            pop_signature=_sign_pop(_priv, pubkey),
            requester_name="Mario Rossi",
            requester_email="mario@acme.com",
            reason="Procurement Q2 project",
            device_info='{"os":"linux"}',
        )
    assert started.session_id
    assert started.expires_at > datetime.now(timezone.utc)

    async with get_db() as conn:
        record = await service.get_record(conn, started.session_id)
    assert record["requester_name"] == "Mario Rossi"
    assert record["status"] == "pending"
    assert len(record["pubkey_fingerprint"]) == 64  # sha256 hex


@pytest.mark.asyncio
async def test_start_rejects_malformed_pubkey(db_engine):
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem="not a real pem",
                pop_signature="noise",
                requester_name="Mario",
                requester_email="m@x.com",
                reason=None,
                device_info=None,
            )
    assert exc.value.http_status == 400


@pytest.mark.asyncio
async def test_get_record_not_found_raises_404(db_engine):
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.get_record(conn, "nonexistent")
    assert exc.value.http_status == 404


@pytest.mark.asyncio
async def test_expired_record_flips_on_read(db_engine):
    _priv, pubkey = _rsa_keypair()
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey,
            pop_signature=_sign_pop(_priv, pubkey),
            requester_name="N",
            requester_email="n@x.com",
            reason=None,
            device_info=None,
        )
        # Manually backdate expiry — simulate TTL elapsed.
        from sqlalchemy import text
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(
            timespec="seconds"
        )
        await conn.execute(
            text("UPDATE pending_enrollments SET expires_at = :t WHERE session_id = :s"),
            {"t": past, "s": started.session_id},
        )

    async with get_db() as conn:
        record = await service.get_record(conn, started.session_id)
    assert record["status"] == "expired"


@pytest.mark.asyncio
async def test_list_pending_skips_expired(db_engine):
    async with get_db() as conn:
        alive = await service.start_enrollment(
            conn,
            **_ec_pop_kwargs(),
            requester_name="Alive",
            requester_email="alive@x.com",
            reason=None,
            device_info=None,
        )
        stale = await service.start_enrollment(
            conn,
            **_ec_pop_kwargs(),
            requester_name="Stale",
            requester_email="stale@x.com",
            reason=None,
            device_info=None,
        )
        from sqlalchemy import text
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(
            timespec="seconds"
        )
        await conn.execute(
            text("UPDATE pending_enrollments SET expires_at = :t WHERE session_id = :s"),
            {"t": past, "s": stale.session_id},
        )

    async with get_db() as conn:
        pending = await service.list_pending(conn)
    ids = {r["session_id"] for r in pending}
    assert alive.session_id in ids
    assert stale.session_id not in ids


@pytest.mark.asyncio
async def test_reject_sets_status_and_reason(db_engine):
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            **_ec_pop_kwargs(),
            requester_name="R",
            requester_email="r@x.com",
            reason=None,
            device_info=None,
        )

    async with get_db() as conn:
        rejected = await service.reject(
            conn,
            session_id=started.session_id,
            reason="Not recognized",
            admin_name="admin",
        )
    assert rejected["status"] == "rejected"
    assert rejected["rejection_reason"] == "Not recognized"

    # Second reject must fail — can only act on pending.
    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.reject(
                conn,
                session_id=started.session_id,
                reason="again",
                admin_name="admin",
            )
    assert exc.value.http_status == 409


@pytest.mark.asyncio
async def test_approve_signs_cert_and_marks_approved(db_engine):
    from mcp_proxy.egress.agent_manager import AgentManager
    manager = AgentManager(org_id="acme", trust_domain="cullis.local")
    ca_key, ca_cert_pem = _generate_self_signed_ca("acme")
    await manager.load_org_ca(ca_key, ca_cert_pem)
    # Three-tier PKI hardening (audit 2026-05-18) — agent / external
    # pubkey signing now goes through the Mastio Intermediate, so the
    # identity must be loaded before service.approve() invokes
    # sign_external_pubkey.
    await manager.ensure_mastio_identity()

    _priv, pubkey = _rsa_keypair()
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey,
            pop_signature=_sign_pop(_priv, pubkey),
            requester_name="A",
            requester_email="a@x.com",
            reason=None,
            device_info=None,
        )

    async with get_db() as conn:
        record = await service.approve(
            conn,
            session_id=started.session_id,
            agent_id="agent-mrossi",
            capabilities=["procurement.read"],
            groups=["procurement"],
            admin_name="admin",
            agent_manager=manager,
        )

    assert record["status"] == "approved"
    assert record["agent_id_assigned"] == "acme::agent-mrossi"
    cert = x509.load_pem_x509_certificate(record["cert_pem"].encode())
    # CN contains the admin-chosen agent_id.
    cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    assert cns[0].value == "acme::agent-mrossi"
    # Cert binds to the *submitted* pubkey — requester keeps the private key.
    submitted_pub = serialization.load_pem_public_key(pubkey.encode())
    assert cert.public_key().public_numbers() == submitted_pub.public_numbers()


# ADR-014 PR-C: the api_key path is gone — the cert the Mastio signs at
# approval is the credential. The "connector-provided api_key_hash"
# round-trip test is removed; ``test_approve_registers_agent_in_internal_registry``
# below covers the cert-based round-trip.


@pytest.mark.asyncio
async def test_approve_registers_agent_in_internal_registry(db_engine):
    """Device-code approval must also land in internal_agents + audit_log.

    Without this, the connector receives a valid cert but the agent is
    invisible in the dashboard agents list — see the 2026-04-15 rc1 smoke
    bug report.
    """
    from sqlalchemy import text as _text
    from mcp_proxy.egress.agent_manager import AgentManager
    manager = AgentManager(org_id="acme", trust_domain="cullis.local")
    ca_key, ca_cert_pem = _generate_self_signed_ca("acme")
    await manager.load_org_ca(ca_key, ca_cert_pem)
    # Three-tier PKI hardening (audit 2026-05-18) — agent / external
    # pubkey signing now goes through the Mastio Intermediate, so the
    # identity must be loaded before service.approve() invokes
    # sign_external_pubkey.
    await manager.ensure_mastio_identity()

    _priv, pubkey = _rsa_keypair()
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey,
            pop_signature=_sign_pop(_priv, pubkey),
            requester_name="A",
            requester_email="a@x.com",
            reason=None,
            device_info=None,
        )

    async with get_db() as conn:
        await service.approve(
            conn,
            session_id=started.session_id,
            agent_id="claude-bot",
            capabilities=["test.read"],
            groups=[],
            admin_name="admin",
            agent_manager=manager,
        )

    # The agent must now be in internal_agents AND the audit_log.
    async with get_db() as conn:
        agents = (await conn.execute(
            _text("SELECT agent_id, cert_pem, is_active FROM internal_agents"),
        )).mappings().all()
        audits = (await conn.execute(
            _text(
                "SELECT agent_id, action, status FROM audit_log "
                "WHERE action = 'agent.create'",
            ),
        )).mappings().all()

    assert len(agents) == 1, "device-code approval must insert one agent"
    assert agents[0]["agent_id"] == "acme::claude-bot"
    assert bool(agents[0]["is_active"]) is True
    assert agents[0]["cert_pem"], "cert_pem must be persisted on the agent row"

    assert len(audits) == 1
    assert audits[0]["agent_id"] == "acme::claude-bot"
    assert audits[0]["status"] == "success"


@pytest.mark.asyncio
async def test_approve_re_enroll_same_agent_id_updates_cert(db_engine):
    """Re-approving the same ``agent_id`` with a fresh keypair MUST update
    ``internal_agents.cert_pem`` to the newly-signed cert.

    Recovery scenario: operator wipes ``connector_data/`` (or the disk
    dies), reinstalls the Connector, re-runs the enroll one-shot, and
    the admin re-approves the pending row with the same ``agent_id``.
    Without this, ``internal_agents.cert_pem`` keeps pinning the OLD
    cert from the first enrollment, and every mTLS call from the
    re-keyed Connector dies with ``client cert does not match the
    registered identity`` until ops manually patches the row.

    Asserts:
      - the row's ``cert_pem`` reflects the second sign
      - admin-managed columns (capabilities, federated, reach) are
        preserved across the re-enroll so a re-approval cannot reset
        operator decisions
      - audit_log carries an ``agent.cert_rotated`` event distinct from
        the original ``agent.create``
      - ``federation_revision`` is bumped so the publisher republishes
    """
    from sqlalchemy import text as _text
    from mcp_proxy.egress.agent_manager import AgentManager
    manager = AgentManager(org_id="acme", trust_domain="cullis.local")
    ca_key, ca_cert_pem = _generate_self_signed_ca("acme")
    await manager.load_org_ca(ca_key, ca_cert_pem)
    # Three-tier PKI hardening (audit 2026-05-18) — agent / external
    # pubkey signing now goes through the Mastio Intermediate, so the
    # identity must be loaded before service.approve() invokes
    # sign_external_pubkey.
    await manager.ensure_mastio_identity()

    # First enrollment + approval — establishes the baseline row.
    _priv_1, pubkey_1 = _rsa_keypair()
    async with get_db() as conn:
        s1 = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey_1,
            pop_signature=_sign_pop(_priv_1, pubkey_1),
            requester_name="A",
            requester_email="a@x.com",
            reason=None,
            device_info=None,
        )
    async with get_db() as conn:
        r1 = await service.approve(
            conn,
            session_id=s1.session_id,
            agent_id="frontdesk",
            capabilities=["procurement.read"],
            groups=["procurement"],
            admin_name="admin",
            agent_manager=manager,
        )
    cert_v1 = r1["cert_pem"]

    # Second enrollment + approval — fresh keypair, same agent_id (the
    # recovery flow). The admin's ``capabilities`` arg here is a stand-in
    # for a re-approval ritual; it should NOT overwrite the first
    # approval's stored caps because admin state is preserved.
    _priv_2, pubkey_2 = _rsa_keypair()
    assert pubkey_2 != pubkey_1, "test fixture sanity"
    async with get_db() as conn:
        s2 = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey_2,
            pop_signature=_sign_pop(_priv_2, pubkey_2),
            requester_name="A",
            requester_email="a@x.com",
            reason="reinstall",
            device_info=None,
        )
    async with get_db() as conn:
        r2 = await service.approve(
            conn,
            session_id=s2.session_id,
            agent_id="frontdesk",
            capabilities=["new.cap"],
            groups=["new"],
            admin_name="admin2",
            agent_manager=manager,
        )
    cert_v2 = r2["cert_pem"]

    assert cert_v2 != cert_v1, "re-approval must mint a fresh cert"

    async with get_db() as conn:
        agents = (await conn.execute(
            _text(
                "SELECT cert_pem, capabilities, federated, reach, "
                "federation_revision FROM internal_agents "
                "WHERE agent_id = 'acme::frontdesk'"
            ),
        )).mappings().all()
        audits = (await conn.execute(
            _text(
                "SELECT action FROM audit_log "
                "WHERE agent_id = 'acme::frontdesk' "
                "ORDER BY id"
            ),
        )).mappings().all()

    # Single row preserved (UPDATE, not duplicate INSERT).
    assert len(agents) == 1
    # cert_pem updated to the second-approval signature.
    assert agents[0]["cert_pem"] == cert_v2
    # Admin-managed columns held over from the first approval (the
    # second approve()'s capabilities argument MUST NOT overwrite them).
    import json as _json
    assert _json.loads(agents[0]["capabilities"]) == ["procurement.read"]
    assert agents[0]["reach"] == "both"
    assert int(agents[0]["federated"]) == 1
    # Revision bumped so the federation publisher pushes the new cert.
    assert int(agents[0]["federation_revision"]) >= 2

    # Audit chain: one create (first approve), one cert_renewed (second).
    actions = [row["action"] for row in audits]
    assert "agent.create" in actions
    assert "agent.cert_rotated" in actions


@pytest.mark.asyncio
async def test_approve_shared_mode_skips_auto_baseline_binding(
    db_engine, monkeypatch,
):
    """Frontdesk shared-mode workload must NOT get an auto-baseline binding.

    The proxy reads ``ambassador_mode=shared`` out of the ``device_info``
    JSON and skips ``_create_baseline_binding`` — capabilities scoped to
    MCP resources belong on user principals, not on the shared container
    (see memory/feedback_frontdesk_shared_mode_capability_model.md).
    """
    from mcp_proxy.egress.agent_manager import AgentManager
    manager = AgentManager(org_id="acme", trust_domain="cullis.local")
    ca_key, ca_cert_pem = _generate_self_signed_ca("acme")
    await manager.load_org_ca(ca_key, ca_cert_pem)
    # Three-tier PKI hardening (audit 2026-05-18) — agent / external
    # pubkey signing now goes through the Mastio Intermediate, so the
    # identity must be loaded before service.approve() invokes
    # sign_external_pubkey.
    await manager.ensure_mastio_identity()

    _priv, pubkey = _rsa_keypair()

    # Spy on the auto-baseline-binding scheduler so we can assert no task
    # is created for shared-mode enrollments. ``approve()`` calls
    # ``asyncio.create_task(_create_baseline_binding(...))`` directly, so
    # patching the helper at the service-module level is enough.
    called: list[dict] = []

    async def _spy(**kwargs):
        called.append(kwargs)

    monkeypatch.setattr(service, "_create_baseline_binding", _spy)

    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey,
            pop_signature=_sign_pop(_priv, pubkey),
            requester_name="Frontdesk",
            requester_email="frontdesk@acme.com",
            reason=None,
            device_info='{"ambassador_mode":"shared","host":"frontdesk-1"}',
        )

    async with get_db() as conn:
        await service.approve(
            conn,
            session_id=started.session_id,
            agent_id="frontdesk",
            capabilities=["principals.sign"],
            groups=[],
            admin_name="admin",
            agent_manager=manager,
        )

    # Give any (errantly-) scheduled task a turn to run.
    import asyncio as _asyncio
    await _asyncio.sleep(0)
    assert called == [], (
        "shared-mode enrollment must not schedule auto-baseline binding"
    )


@pytest.mark.asyncio
async def test_approve_single_mode_still_schedules_auto_baseline_binding(
    db_engine, monkeypatch,
):
    """Regression — patch must not break the single-mode default path."""
    from mcp_proxy.egress.agent_manager import AgentManager
    manager = AgentManager(org_id="acme", trust_domain="cullis.local")
    ca_key, ca_cert_pem = _generate_self_signed_ca("acme")
    await manager.load_org_ca(ca_key, ca_cert_pem)
    # Three-tier PKI hardening (audit 2026-05-18) — agent / external
    # pubkey signing now goes through the Mastio Intermediate, so the
    # identity must be loaded before service.approve() invokes
    # sign_external_pubkey.
    await manager.ensure_mastio_identity()

    _priv, pubkey = _rsa_keypair()

    called: list[dict] = []

    async def _spy(**kwargs):
        called.append(kwargs)

    monkeypatch.setattr(service, "_create_baseline_binding", _spy)

    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey,
            pop_signature=_sign_pop(_priv, pubkey),
            requester_name="Daniele",
            requester_email="d@acme.com",
            reason=None,
            device_info='{"host":"laptop-1"}',  # no ambassador_mode key
        )

    async with get_db() as conn:
        await service.approve(
            conn,
            session_id=started.session_id,
            agent_id="cullis",
            capabilities=["sql.read"],
            groups=[],
            admin_name="admin",
            agent_manager=manager,
        )

    import asyncio as _asyncio
    await _asyncio.sleep(0)
    assert len(called) == 1
    assert called[0]["agent_id"] == "acme::cullis"
    assert called[0]["capabilities"] == ["sql.read"]


def test_ambassador_mode_from_device_info_handles_garbage():
    """The parser must never raise on malformed ``device_info`` payloads."""
    f = service._ambassador_mode_from_device_info
    assert f(None) is None
    assert f("") is None
    assert f("not json") is None
    assert f("[1,2,3]") is None  # JSON but not an object
    assert f('{"ambassador_mode": 42}') is None  # non-string value
    assert f('{"ambassador_mode": "shared"}') == "shared"
    assert f('{"ambassador_mode": "single", "host": "x"}') == "single"


# ── HTTP endpoint tests ────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}"
    )
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
            yield app, client
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_http_start_returns_201_and_poll_url(proxy_app):
    _, client = proxy_app
    resp = await client.post(
        "/v1/enrollment/start",
        json={
            **_ec_pop_kwargs(),
            "requester_name": "Mario",
            "requester_email": "mario@acme.com",
            "reason": "Onboarding",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "pending"
    assert body["poll_url"].endswith(f"/v1/enrollment/{body['session_id']}/status")
    assert body["poll_interval_s"] >= 1


@pytest.mark.asyncio
async def test_http_status_pending_then_not_found(proxy_app):
    _, client = proxy_app
    start = await client.post(
        "/v1/enrollment/start",
        json={
            **_ec_pop_kwargs(),
            "requester_name": "X",
            "requester_email": "x@x.com",
        },
    )
    session_id = start.json()["session_id"]

    resp = await client.get(f"/v1/enrollment/{session_id}/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"

    missing = await client.get("/v1/enrollment/does-not-exist/status")
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_http_admin_list_requires_auth(proxy_app):
    _, client = proxy_app
    resp = await client.get("/v1/admin/enrollments")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_http_admin_approve_requires_csrf(proxy_app):
    app, client = proxy_app
    # Mint a valid session cookie + csrf token via the session helper.
    from mcp_proxy.dashboard.session import _sign, _COOKIE_NAME
    import json as _json
    import time as _time

    csrf = "test-csrf-token-abc"
    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf, "exp": int(_time.time()) + 3600}
    )
    cookie = _sign(payload)
    client.cookies.set(_COOKIE_NAME, cookie)

    # Missing header → 403.
    resp = await client.post(
        "/v1/admin/enrollments/bogus/approve",
        json={"agent_id": "x", "capabilities": [], "groups": []},
    )
    assert resp.status_code == 403

    # Wrong header → 403.
    resp = await client.post(
        "/v1/admin/enrollments/bogus/approve",
        headers={"X-CSRF-Token": "wrong"},
        json={"agent_id": "x", "capabilities": [], "groups": []},
    )
    assert resp.status_code == 403


# ── Test helpers ──────────────────────────────────────────────────


def _generate_self_signed_ca(org_id: str) -> tuple[str, str]:
    """Minimal self-signed CA for approve-path tests."""
    from cryptography.x509.oid import NameOID

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
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(key, __import__("cryptography").hazmat.primitives.hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


# ── Rate-limit tests (audit 2026-04-30 C2) ─────────────────────────


@pytest.mark.asyncio
async def test_http_start_rate_limits_after_budget(proxy_app, monkeypatch):
    """6th /v1/enrollment/start from the same IP within 60s returns 429."""
    _, client = proxy_app

    import importlib

    from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter

    enrollment_module = importlib.import_module("mcp_proxy.enrollment.router")
    reset_agent_rate_limiter()
    monkeypatch.setattr(enrollment_module, "_ENROLLMENT_START_PER_MINUTE", 5)

    for _ in range(5):
        resp = await client.post(
            "/v1/enrollment/start",
            json={
                **_ec_pop_kwargs(),
                "requester_name": "Mario",
                "requester_email": "mario@acme.com",
            },
        )
        assert resp.status_code == 201, resp.text

    blocked = await client.post(
        "/v1/enrollment/start",
        json={
            **_ec_pop_kwargs(),
            "requester_name": "Mario",
            "requester_email": "mario@acme.com",
        },
    )
    assert blocked.status_code == 429
    reset_agent_rate_limiter()


@pytest.mark.asyncio
async def test_http_status_rate_limits_after_budget(proxy_app, monkeypatch):
    """61st /v1/enrollment/{id}/status from the same IP within 60s returns 429."""
    _, client = proxy_app

    import importlib

    from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter

    enrollment_module = importlib.import_module("mcp_proxy.enrollment.router")
    reset_agent_rate_limiter()
    monkeypatch.setattr(enrollment_module, "_ENROLLMENT_STATUS_PER_MINUTE", 3)

    started = await client.post(
        "/v1/enrollment/start",
        json={
            **_ec_pop_kwargs(),
            "requester_name": "X",
            "requester_email": "x@x.com",
        },
    )
    session_id = started.json()["session_id"]

    for _ in range(3):
        resp = await client.get(f"/v1/enrollment/{session_id}/status")
        assert resp.status_code == 200

    blocked = await client.get(f"/v1/enrollment/{session_id}/status")
    assert blocked.status_code == 429
    reset_agent_rate_limiter()
