"""Boot-time detection + surface of legacy Org CAs with
``BasicConstraints(pathLen=0)``.

Issue #285 — proxies that bootstrapped before #280 kept an Org CA
with ``pathLen=0`` in ``proxy_config.org_ca_cert``. Their own
verifier (post-#284) now rejects the chain, but the silent
cross-org federation failure mode bites only at peer-verification
time. These tests pin the detection path + the surfaces operators
see: the WARNING log, the ``/health`` ``warnings`` array, the
Prometheus gauge, and the opt-in strict-PKI refuse-to-boot mode.

Fresh bootstraps (post-#280) emit ``pathLen=1`` and must NOT
trigger any of those signals — the regression-guard that keeps the
fix from becoming sticky.
"""
from __future__ import annotations

import datetime

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

from mcp_proxy.egress.agent_manager import AgentManager


def _mint_org_ca(path_length: int) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Mint a self-signed Org CA with the requested pathLen.

    Mirrors the dashboard setup wizard's emission shape so the
    detection path exercises exactly the cert shape a legacy /
    fresh proxy would carry in ``proxy_config.org_ca_cert``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "legacy-warn-test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "legacy-warn-test"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _pem_pair(key: rsa.RSAPrivateKey, cert: x509.Certificate) -> tuple[str, str]:
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """Isolated SQLite proxy DB + cleared settings cache per test."""
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_STRICT_PKI", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import dispose_db, init_db
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


# ── Detection + WARN log ─────────────────────────────────────────────


def _capture_warnings(monkeypatch) -> list[str]:
    """Monkeypatch ``mcp_proxy.egress.agent_manager.logger.warning`` to
    record invocations into a list.

    ``mcp_proxy.logging_setup`` sets ``propagate = False`` on the
    ``mcp_proxy`` parent logger (memory: ``feedback_mcp_proxy_logger_caplog``),
    so pytest's ``caplog`` — which hangs off the root — never sees
    records emitted under ``mcp_proxy.*``. Replacing the bound
    ``warning`` method with a capturing closure keeps the test
    independent of logger configuration.
    """
    captured: list[str] = []
    import mcp_proxy.egress.agent_manager as agent_mgr_mod

    def _fake_warning(msg, *args, **kwargs):
        # Match logging's ``%``-style formatting so the test sees the
        # fully-rendered string the real handler would emit.
        captured.append(msg % args if args else msg)

    monkeypatch.setattr(agent_mgr_mod.logger, "warning", _fake_warning)
    return captured


@pytest.mark.asyncio
async def test_legacy_ca_pathlen_zero_triggers_warning_and_flag(
    proxy_db, monkeypatch,
):
    """pathLen=0 Org CA → flag True, WARN log with the exact marker,
    Prometheus gauge goes to 1. The proxy still boots (no strict
    mode) so intra-org flows keep working.
    """
    key, cert = _mint_org_ca(path_length=0)
    key_pem, cert_pem = _pem_pair(key, cert)

    mgr = AgentManager(org_id="legacy-warn")
    await mgr.load_org_ca(key_pem, cert_pem)

    messages = _capture_warnings(monkeypatch)
    await mgr.ensure_mastio_identity()

    assert mgr.has_legacy_ca_pathlen_zero is True
    # Structured marker operators can grep for.
    assert any("org_ca_legacy_pathlen_zero" in m for m in messages), (
        f"expected WARN with marker, got: {messages}"
    )
    # Remediation hint present.
    assert any("/pki/rotate-ca" in m for m in messages), (
        "WARN must tell the operator how to fix"
    )

    from mcp_proxy.telemetry_metrics import LEGACY_CA_PATHLEN_ZERO
    # Gauge is 1 when the no-op shim is in place (set() returns None)
    # or when prometheus_client is installed. We probe the Gauge via
    # its private ``_value`` attribute when available; otherwise just
    # trust the shim behaviour.
    value = getattr(LEGACY_CA_PATHLEN_ZERO, "_value", None)
    if value is not None:
        # prometheus_client Gauge exposes ``_value.get()``.
        assert value.get() == 1.0


@pytest.mark.asyncio
async def test_fresh_ca_pathlen_one_does_not_trigger(proxy_db, monkeypatch):
    """Regression guard: post-#280 bootstraps emit ``pathLen=1``. The
    detection must NOT fire — no flag, no warning, gauge stays at 0.
    """
    key, cert = _mint_org_ca(path_length=1)
    key_pem, cert_pem = _pem_pair(key, cert)

    mgr = AgentManager(org_id="fresh-ok")
    await mgr.load_org_ca(key_pem, cert_pem)

    messages = _capture_warnings(monkeypatch)
    await mgr.ensure_mastio_identity()

    assert mgr.has_legacy_ca_pathlen_zero is False
    assert not any("org_ca_legacy_pathlen_zero" in m for m in messages)


# ── Strict mode (opt-in via env) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_strict_pki_mode_refuses_boot_on_legacy_ca(
    proxy_db, monkeypatch,
):
    """``MCP_PROXY_STRICT_PKI=1`` flips detection from warn-and-continue
    to refuse-to-boot. The WARN is still emitted (ops visibility),
    then ``ensure_mastio_identity`` raises with a message telling
    the operator how to recover.
    """
    monkeypatch.setenv("MCP_PROXY_STRICT_PKI", "1")

    key, cert = _mint_org_ca(path_length=0)
    key_pem, cert_pem = _pem_pair(key, cert)

    mgr = AgentManager(org_id="legacy-strict")
    await mgr.load_org_ca(key_pem, cert_pem)

    messages = _capture_warnings(monkeypatch)
    with pytest.raises(RuntimeError, match="MCP_PROXY_STRICT_PKI"):
        await mgr.ensure_mastio_identity()

    # WARN must still be emitted before the raise — ops need the log
    # marker regardless of whether boot proceeds.
    assert any("org_ca_legacy_pathlen_zero" in m for m in messages), messages


@pytest.mark.asyncio
async def test_strict_pki_mode_does_not_refuse_fresh_ca(
    proxy_db, monkeypatch,
):
    """``MCP_PROXY_STRICT_PKI=1`` does NOT refuse a healthy pathLen=1
    CA — the refuse-to-boot guard only fires on the legacy shape.
    """
    monkeypatch.setenv("MCP_PROXY_STRICT_PKI", "1")

    key, cert = _mint_org_ca(path_length=1)
    key_pem, cert_pem = _pem_pair(key, cert)

    mgr = AgentManager(org_id="fresh-strict")
    await mgr.load_org_ca(key_pem, cert_pem)

    # No raise — fresh CA boots cleanly even in strict mode.
    await mgr.ensure_mastio_identity()
    assert mgr.has_legacy_ca_pathlen_zero is False


@pytest.mark.asyncio
async def test_strict_pki_accepts_common_truthy_values(proxy_db, monkeypatch):
    """``MCP_PROXY_STRICT_PKI`` accepts ``1`` / ``true`` / ``yes``
    (case-insensitive). Other values behave as off — keeping a
    malformed env var from surprising the operator.
    """
    from mcp_proxy.egress.agent_manager import _strict_pki_enabled

    for value in ("1", "true", "TRUE", "yes", "YES"):
        monkeypatch.setenv("MCP_PROXY_STRICT_PKI", value)
        assert _strict_pki_enabled() is True, value

    for value in ("", "0", "false", "no", "maybe", "  "):
        monkeypatch.setenv("MCP_PROXY_STRICT_PKI", value)
        assert _strict_pki_enabled() is False, value


# ── /health surface ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_surfaces_legacy_ca_warning(tmp_path, monkeypatch):
    """End-to-end: boot a proxy with a legacy Org CA, hit ``/health``,
    assert the response carries ``warnings: ["org_ca_legacy_pathlen_zero"]``.
    Backward-compat: the ``warnings`` key is omitted entirely when
    the proxy is clean — consumers that assert ``status == "ok"``
    stay green.
    """
    # Seed proxy_config with a legacy Org CA before lifespan runs.
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "health-warn")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_STRICT_PKI", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import init_db, set_config, dispose_db
    await init_db(url)
    try:
        key, cert = _mint_org_ca(path_length=0)
        key_pem, cert_pem = _pem_pair(key, cert)
        await set_config("org_ca_key", key_pem)
        await set_config("org_ca_cert", cert_pem)
    finally:
        await dispose_db()

    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "ok"
            assert body.get("warnings") == ["org_ca_legacy_pathlen_zero"]

    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_health_omits_warnings_array_when_clean(tmp_path, monkeypatch):
    """Backward-compat: a clean proxy returns ``{"status": "ok",
    "version": ...}`` without a ``warnings`` key. Consumers that
    just check ``status`` don't see a new key appear.
    """
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "health-clean")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_STRICT_PKI", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import init_db, set_config, dispose_db
    await init_db(url)
    try:
        key, cert = _mint_org_ca(path_length=1)
        key_pem, cert_pem = _pem_pair(key, cert)
        await set_config("org_ca_key", key_pem)
        await set_config("org_ca_cert", cert_pem)
    finally:
        await dispose_db()

    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "ok"
            assert "warnings" not in body

    get_settings.cache_clear()
