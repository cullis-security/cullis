"""Tests for the nginx server cert runtime rotation watcher.

Wave 2 fix 6. The watcher closes the gap left by boot-time
``ensure_nginx_server_cert``: a Mastio container that stays up beyond
the 90-day cert validity would serve an expired leaf until restart.
The loop ticks daily, re-invokes the idempotent
``ensure_nginx_server_cert``, and audit-logs every actual rotation.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.egress.agent_manager import AgentManager
from mcp_proxy.lifespan.nginx_cert_watcher import (
    _check_once,
    nginx_cert_watcher_loop,
)


def _make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-org CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_manager_with_ca() -> AgentManager:
    mgr = AgentManager.__new__(AgentManager)
    key, cert = _make_ca()
    mgr._org_ca_key = key
    mgr._org_ca_cert = cert
    mgr._mastio_ca_key = key
    mgr._mastio_ca_cert = cert
    mgr._org_id = "test-org"
    return mgr


class _AuditCapture:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, **kwargs) -> None:
        self.calls.append(kwargs)


@pytest.mark.asyncio
async def test_check_once_rotates_when_cert_near_expiry(tmp_path: Path) -> None:
    mgr = _make_manager_with_ca()
    sans = ["mastio.local", "localhost"]
    rotated = await mgr.ensure_nginx_server_cert(
        out_dir=str(tmp_path), sans=sans, validity_days=5, renew_within_days=10,
    )
    assert rotated is True
    audit = _AuditCapture()
    with patch("mcp_proxy.db.log_audit", new=audit):
        await _check_once(
            mgr, out_dir=str(tmp_path), sans=sans, renew_within_days=10,
        )
    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["action"] == "pki.nginx_server_cert_rotated"
    assert call["status"] == "success"
    assert call["agent_id"] == "system"
    assert "new_expiry=" in call["detail"]
    assert "mastio.local" in call["detail"]


@pytest.mark.asyncio
async def test_check_once_noop_when_cert_fresh(tmp_path: Path) -> None:
    mgr = _make_manager_with_ca()
    sans = ["mastio.local"]
    rotated = await mgr.ensure_nginx_server_cert(
        out_dir=str(tmp_path), sans=sans, validity_days=90, renew_within_days=30,
    )
    assert rotated is True
    audit = _AuditCapture()
    with patch("mcp_proxy.db.log_audit", new=audit):
        await _check_once(
            mgr, out_dir=str(tmp_path), sans=sans, renew_within_days=30,
        )
    assert audit.calls == []


@pytest.mark.asyncio
async def test_check_once_skips_when_intermediate_missing(tmp_path: Path) -> None:
    mgr = _make_manager_with_ca()
    mgr._mastio_ca_cert = None
    audit = _AuditCapture()
    with patch("mcp_proxy.db.log_audit", new=audit):
        await _check_once(
            mgr, out_dir=str(tmp_path), sans=["mastio.local"], renew_within_days=30,
        )
    assert audit.calls == []
    assert not (tmp_path / "mastio-server.crt").exists()


@pytest.mark.asyncio
async def test_check_once_audits_on_ensure_exception(tmp_path: Path) -> None:
    mgr = _make_manager_with_ca()

    async def _raise(**_kw):
        raise RuntimeError("kms unreachable")

    audit = _AuditCapture()
    with patch.object(mgr, "ensure_nginx_server_cert", new=_raise), \
            patch("mcp_proxy.db.log_audit", new=audit):
        await _check_once(
            mgr, out_dir=str(tmp_path), sans=["mastio.local"], renew_within_days=30,
        )
    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["action"] == "pki.nginx_server_cert_rotation_failed"
    assert call["status"] == "error"
    assert "RuntimeError" in call["detail"]


@pytest.mark.asyncio
async def test_loop_exits_promptly_on_stop_event(tmp_path: Path) -> None:
    mgr = _make_manager_with_ca()
    stop = asyncio.Event()

    async def _stop_later() -> None:
        await asyncio.sleep(0.2)
        stop.set()

    audit = _AuditCapture()
    with patch("mcp_proxy.db.log_audit", new=audit):
        await asyncio.gather(
            nginx_cert_watcher_loop(
                mgr,
                out_dir=str(tmp_path),
                sans=["mastio.local"],
                tick_seconds=60,
                renew_within_days=30,
                stop_event=stop,
            ),
            _stop_later(),
        )
    assert any(
        c["action"] == "pki.nginx_server_cert_rotated" for c in audit.calls
    ), "first tick should have emitted seed cert + audit"


@pytest.mark.asyncio
async def test_loop_continues_when_check_raises(tmp_path: Path) -> None:
    mgr = _make_manager_with_ca()
    stop = asyncio.Event()
    ticks_seen = 0

    async def _flaky_check(*_a, **_kw) -> None:
        nonlocal ticks_seen
        ticks_seen += 1
        if ticks_seen <= 2:
            raise RuntimeError(f"transient failure #{ticks_seen}")
        stop.set()

    with patch(
        "mcp_proxy.lifespan.nginx_cert_watcher._check_once",
        new=_flaky_check,
    ):
        await asyncio.wait_for(
            nginx_cert_watcher_loop(
                mgr,
                out_dir=str(tmp_path),
                sans=["mastio.local"],
                tick_seconds=0.01,
                renew_within_days=30,
                stop_event=stop,
            ),
            timeout=5.0,
        )
    assert ticks_seen >= 3, "loop must have survived 2 raising ticks"
