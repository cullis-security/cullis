"""
H-xff + H-kms-perms regression: rate-limit IP attribution can no
longer be spoofed via ``X-Forwarded-For``, and ``LocalKMSProvider``
refuses to load an Org CA private key with loose POSIX perms in
production.

Three audit findings closed in one batch:

* ``mcp_proxy/pki/public.py:_client_ip`` — used to read the first
  hop of ``X-Forwarded-For`` directly. Attacker-controlled when
  nginx is bypassed (host port exposed) or forwards upstream XFF
  unchecked. Now reads ``request.client.host`` only.
* ``mcp_proxy/auth/jwks_local.py:_client_ip`` — same shape.
* ``app/kms/local.py:LocalKMSProvider`` — used to read the Org CA
  private key without checking file mode. A world-readable key on
  a shared host let any local process steal the trust anchor of
  every Org cert. Now refuses ``0o077`` mode bits in production
  unless the operator opts out.
"""
from __future__ import annotations

import os
import stat as _stat

import pytest


# ── XFF spoof: pki/public.py ─────────────────────────────────────────


def test_pki_public_client_ip_ignores_xff_header() -> None:
    """Crafted XFF header must NOT be the rate-limit subject."""
    from mcp_proxy.pki.public import _client_ip

    class _Client:
        host = "10.0.0.1"

    class _Req:
        headers = {"x-forwarded-for": "203.0.113.5"}
        client = _Client()

    assert _client_ip(_Req()) == "10.0.0.1"


def test_pki_public_client_ip_returns_unknown_without_client() -> None:
    from mcp_proxy.pki.public import _client_ip

    class _Req:
        headers = {"x-forwarded-for": "203.0.113.5"}
        client = None

    assert _client_ip(_Req()) == "unknown"


# ── XFF spoof: auth/jwks_local.py ────────────────────────────────────


def test_jwks_local_client_ip_ignores_xff_header() -> None:
    from mcp_proxy.auth.jwks_local import _client_ip

    class _Client:
        host = "10.0.0.7"

    class _Req:
        headers = {"x-forwarded-for": "203.0.113.99"}
        client = _Client()

    assert _client_ip(_Req()) == "10.0.0.7"


# ── LocalKMSProvider perm check ──────────────────────────────────────


def _write_key_file(path, mode: int) -> None:
    path.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"
    )
    os.chmod(path, mode)


@pytest.mark.asyncio
async def test_local_kms_accepts_0600(tmp_path) -> None:
    """The happy path: 0600 perms load without complaint."""
    from app.kms.local import LocalKMSProvider

    key = tmp_path / "ca.key"
    cert = tmp_path / "ca.crt"
    cert.write_text(
        "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
    )
    _write_key_file(key, 0o600)

    kms = LocalKMSProvider(
        key_path=str(key), cert_path=str(cert),
        secret_encryption_key_path=str(tmp_path / "se.key"),
    )
    pem = await kms.get_broker_private_key_pem()
    assert "BEGIN RSA PRIVATE KEY" in pem


@pytest.mark.asyncio
async def test_local_kms_warns_on_loose_perms_in_dev(
    tmp_path, monkeypatch,
) -> None:
    """Development mode: warn loudly but still load. Capture via a
    monkeypatch on ``_log.warning`` because caplog's logger
    propagation depends on root config that the conftest may
    override; the direct patch is robust regardless."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS", raising=False)
    from app.config import get_settings
    get_settings.cache_clear()

    from app.kms import local as local_kms

    captured: list[str] = []

    def _capture(msg, *args, **kwargs):
        try:
            captured.append(msg % args if args else msg)
        except TypeError:
            captured.append(str(msg))

    monkeypatch.setattr(local_kms._log, "warning", _capture)

    key = tmp_path / "ca.key"
    cert = tmp_path / "ca.crt"
    cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    _write_key_file(key, 0o644)

    kms = local_kms.LocalKMSProvider(
        key_path=str(key), cert_path=str(cert),
        secret_encryption_key_path=str(tmp_path / "se.key"),
    )
    pem = await kms.get_broker_private_key_pem()
    assert "BEGIN RSA PRIVATE KEY" in pem
    assert any("loose POSIX perms" in m for m in captured), captured
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_local_kms_refuses_loose_perms_in_production(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ADMIN_SECRET", "test-secret-not-default")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "x" * 32)
    monkeypatch.delenv("MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS", raising=False)
    from app.config import get_settings
    get_settings.cache_clear()

    from app.kms.local import LocalKMSProvider

    key = tmp_path / "ca.key"
    cert = tmp_path / "ca.crt"
    cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    _write_key_file(key, 0o644)

    kms = LocalKMSProvider(
        key_path=str(key), cert_path=str(cert),
        secret_encryption_key_path=str(tmp_path / "se.key"),
    )
    with pytest.raises(RuntimeError, match="loose perms"):
        await kms.get_broker_private_key_pem()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_local_kms_env_override_skips_check(
    tmp_path, monkeypatch,
) -> None:
    """Operators who knowingly run on a shared filesystem can opt
    out via the env override even in production."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ADMIN_SECRET", "test-secret-not-default")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "x" * 32)
    monkeypatch.setenv("MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS", "1")
    from app.config import get_settings
    get_settings.cache_clear()

    from app.kms.local import LocalKMSProvider

    key = tmp_path / "ca.key"
    cert = tmp_path / "ca.crt"
    cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    _write_key_file(key, 0o644)

    kms = LocalKMSProvider(
        key_path=str(key), cert_path=str(cert),
        secret_encryption_key_path=str(tmp_path / "se.key"),
    )
    pem = await kms.get_broker_private_key_pem()
    assert "BEGIN RSA PRIVATE KEY" in pem
    get_settings.cache_clear()


def test_loose_perm_bit_predicate() -> None:
    """Sanity check on the bitmask used to detect group/world access."""
    assert (0o600 & 0o077) == 0
    assert (0o640 & 0o077) != 0  # group readable
    assert (0o604 & 0o077) != 0  # world readable
    assert (0o644 & 0o077) != 0  # both
    assert _stat.S_IRGRP & 0o077
    assert _stat.S_IROTH & 0o077
