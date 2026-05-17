"""P3 MAJOR-B (2026-05-17 dogfood) — boot-time self-check that the Org
CA loaded from ``proxy_config.org_ca_cert`` belongs to the
``proxy_config.org_id`` row.

The dogfood VM ``192.168.122.170`` had DB rows saying
``org_id=70e44ddd5d7b5a76`` but a ``nginx-certs/org-ca.crt`` bind
mount holding ``CN=9d5c940c49b8160f CA`` from a previous boot. Every
Connector client cert chain validation 400/401'd silently. The fix
makes :meth:`AgentManager.load_org_ca_from_config` log CRITICAL and
refuse the load when the subject CN doesn't line up with the
persisted ``org_id``.

Logger capture uses :func:`monkeypatch.setattr` on ``logger.<level>``
because ``mcp_proxy.logging_setup`` flips ``propagate=False`` and
``caplog`` is fragile across NixOS / pytest configurations (memory
``feedback_mcp_proxy_logger_caplog``).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcp_proxy.db import dispose_db, init_db, set_config
from mcp_proxy.egress import agent_manager as agent_manager_module
from mcp_proxy.egress.agent_manager import AgentManager


def _mint_unrelated_ca_pem(cn: str) -> bytes:
    """Self-signed CA cert in-memory only — used to stage a stale
    on-disk file without overwriting ``proxy_config.org_ca_cert`` via
    the KMS write path."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest_asyncio.fixture
async def fresh_db(tmp_path):
    db_file = tmp_path / "proxy.sqlite"
    await init_db(f"sqlite+aiosqlite:///{db_file}")
    yield
    await dispose_db()


@pytest.mark.asyncio
async def test_happy_path_cn_matches_persisted_org_id(fresh_db):
    """Standard boot: generate-derive seeds matching ``org_id`` + CA,
    second AgentManager reloads cleanly with ``ca_loaded=True``."""
    mgr1 = AgentManager(org_id="", trust_domain="cullis.local")
    await mgr1.generate_org_ca(derive_org_id=True)
    org_id = mgr1.org_id
    assert org_id

    mgr2 = AgentManager(org_id=org_id, trust_domain="cullis.local")
    ok = await mgr2.load_org_ca_from_config()

    assert ok is True
    assert mgr2.ca_loaded is True


@pytest.mark.asyncio
async def test_mismatch_cn_refuses_load_and_logs_critical(fresh_db, monkeypatch):
    """DB swap scenario: ``proxy_config.org_id`` was rewritten to A
    while ``proxy_config.org_ca_cert`` still holds a CA with CN
    ``B CA``. The load must return False, ``ca_loaded`` stays False,
    and CRITICAL is emitted with both expected and actual CN."""
    # Seed a CA whose CN is "{org_b} CA" (generate doesn't persist
    # org_id when derive=False).
    org_b = "bbbbbbbbbbbbbbbb"
    mgr_b = AgentManager(org_id=org_b, trust_domain="cullis.local")
    await mgr_b.generate_org_ca(derive_org_id=False)

    # Simulate the DB drift the dogfood VM exhibited.
    org_a = "aaaaaaaaaaaaaaaa"
    await set_config("org_id", org_a)

    captured: list[str] = []

    def _capture(msg, *args, **kwargs):
        try:
            captured.append(msg % args if args else msg)
        except TypeError:
            captured.append(str(msg))

    monkeypatch.setattr(agent_manager_module.logger, "critical", _capture)

    mgr_a = AgentManager(org_id=org_a, trust_domain="cullis.local")
    ok = await mgr_a.load_org_ca_from_config()

    assert ok is False, "mismatch path must return False"
    assert mgr_a.ca_loaded is False, "in-memory CA must be cleared on mismatch"
    assert any("Org CA subject mismatch" in m for m in captured), captured
    joined = " | ".join(captured)
    assert f"{org_a} CA" in joined
    assert f"{org_b} CA" in joined


@pytest.mark.asyncio
async def test_no_persisted_org_id_skips_check(fresh_db, monkeypatch):
    """Env-pinned org_id leaves ``proxy_config.org_id`` unset; the
    self-check is then a no-op and load succeeds without CRITICAL."""
    mgr_seed = AgentManager(org_id="env-pinned", trust_domain="cullis.local")
    await mgr_seed.generate_org_ca(derive_org_id=False)

    critical_calls: list[str] = []
    monkeypatch.setattr(
        agent_manager_module.logger,
        "critical",
        lambda msg, *a, **k: critical_calls.append(msg),
    )

    mgr2 = AgentManager(org_id="env-pinned", trust_domain="cullis.local")
    ok = await mgr2.load_org_ca_from_config()

    assert ok is True
    assert mgr2.ca_loaded is True
    assert critical_calls == [], critical_calls


@pytest.mark.asyncio
async def test_on_disk_ca_mismatch_logs_warning_but_loads(
    fresh_db, tmp_path, monkeypatch,
):
    """Secondary check: when ``nginx_cert_dir/org-ca.crt`` differs from
    the DB cert, log WARN but still return True —
    ``ensure_nginx_server_cert`` will rewrite the file later in the
    lifespan, so this is advisory only."""
    mgr_seed = AgentManager(org_id="", trust_domain="cullis.local")
    await mgr_seed.generate_org_ca(derive_org_id=True)

    stale_pem = _mint_unrelated_ca_pem(cn="9d5c940c49b8160f CA")
    nginx_dir = tmp_path / "nginx-certs"
    nginx_dir.mkdir()
    (nginx_dir / "org-ca.crt").write_bytes(stale_pem)

    class _StubSettings:
        nginx_cert_dir = str(nginx_dir)

    monkeypatch.setattr(
        agent_manager_module, "get_settings", lambda: _StubSettings(),
    )

    warnings: list[str] = []
    monkeypatch.setattr(
        agent_manager_module.logger,
        "warning",
        lambda msg, *a, **k: warnings.append(msg % a if a else msg),
    )

    mgr_reload = AgentManager(org_id=mgr_seed.org_id, trust_domain="cullis.local")
    ok = await mgr_reload.load_org_ca_from_config()

    assert ok is True
    assert mgr_reload.ca_loaded is True
    assert any("on-disk vs DB mismatch" in w for w in warnings), warnings


