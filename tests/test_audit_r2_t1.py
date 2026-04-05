"""
Tests for security audit Round 2 findings #17, #23, #35, #37, #42, #43.

Covers:
  - #17: CSRF enforcement on /dashboard/audit/verify
  - #23: Exception detail leak in message signature verification
  - #35: Constant-time cert thumbprint comparison
  - #37: KMS backend unknown value raises RuntimeError
  - #42: Revoked binding cannot be re-approved
  - #43: Logout requires POST + CSRF (GET rejected)
"""
import json
import pytest
from unittest.mock import patch
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings

pytestmark = pytest.mark.asyncio


# ── Helpers ��─────────────────────────────────────────────────────────────────

def _extract_csrf(cookies: dict) -> str:
    """Extract CSRF token from the signed session cookie."""
    import codecs
    cookie = cookies.get("atn_session", "")
    if not cookie:
        return ""
    if cookie.startswith('"') and cookie.endswith('"'):
        cookie = cookie[1:-1]
    try:
        cookie = codecs.decode(cookie, "unicode_escape")
    except Exception:
        pass
    if "." not in cookie:
        return ""
    payload_str = cookie.rsplit(".", 1)[0]
    try:
        data = json.loads(payload_str)
        return data.get("csrf_token", "")
    except (json.JSONDecodeError, TypeError):
        return ""


async def _admin_login(client: AsyncClient) -> tuple[dict, str]:
    """Login as admin, return (cookies, csrf_token)."""
    resp = await client.post("/dashboard/login", data={
        "login_type": "admin", "admin_secret": get_settings().admin_secret,
    }, follow_redirects=False)
    assert resp.status_code == 303
    cookies = dict(resp.cookies)
    return cookies, _extract_csrf(cookies)


# ── #17: CSRF enforcement on /dashboard/audit/verify ─────────────────────────

async def test_audit_verify_rejects_missing_csrf(client: AsyncClient):
    """#17: POST /dashboard/audit/verify without CSRF token must be rejected."""
    cookies, _ = await _admin_login(client)
    resp = await client.post(
        "/dashboard/audit/verify",
        cookies=cookies,
        data={},  # no csrf_token
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_audit_verify_rejects_wrong_csrf(client: AsyncClient):
    """#17: POST /dashboard/audit/verify with wrong CSRF token must be rejected."""
    cookies, _ = await _admin_login(client)
    resp = await client.post(
        "/dashboard/audit/verify",
        cookies=cookies,
        data={"csrf_token": "wrong-token"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_audit_verify_accepts_valid_csrf(client: AsyncClient):
    """#17: POST /dashboard/audit/verify with valid CSRF token succeeds."""
    cookies, csrf = await _admin_login(client)
    resp = await client.post(
        "/dashboard/audit/verify",
        cookies=cookies,
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 200


# ── #23: Exception detail leak in message_signer ─���───────────────────────────

def test_signature_error_does_not_leak_details():
    """#23: Generic exceptions in verify_message_signature must not leak internals."""
    from app.auth.message_signer import verify_message_signature
    from fastapi import HTTPException

    # Pass garbage cert to trigger a generic Exception (not InvalidSignature)
    with pytest.raises(HTTPException) as exc_info:
        verify_message_signature(
            cert_pem="not-a-valid-cert",
            signature_b64="AAAA",
            session_id="s1",
            sender_agent_id="a1",
            nonce="n1",
            timestamp=0,
            payload={"test": True},
        )
    # Must NOT contain internal exception details
    detail = exc_info.value.detail
    assert "Signature verification failed" == detail
    assert "not-a-valid-cert" not in detail
    assert "PEM" not in detail.upper() or detail == "Signature verification failed"


def test_invalid_signature_still_reports_correctly():
    """#23: InvalidSignature specifically still returns clear message."""
    from app.auth.message_signer import verify_message_signature, sign_message
    from fastapi import HTTPException
    from tests.cert_factory import make_agent_cert
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    # Create a valid cert + key pair
    agent_key_obj, agent_cert_obj = make_agent_cert("org1::agent1", "org1")
    agent_key_pem = agent_key_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    agent_cert_pem = agent_cert_obj.public_bytes(Encoding.PEM).decode()

    sig = sign_message(
        private_key_pem=agent_key_pem,
        session_id="s1",
        sender_agent_id="agent1",
        nonce="n1",
        timestamp=1000,
        payload={"msg": "hello"},
    )

    # Tamper with payload to trigger InvalidSignature
    with pytest.raises(HTTPException) as exc_info:
        verify_message_signature(
            cert_pem=agent_cert_pem,
            signature_b64=sig,
            session_id="s1",
            sender_agent_id="agent1",
            nonce="n1",
            timestamp=1000,
            payload={"msg": "tampered"},
        )
    assert exc_info.value.status_code == 401
    assert "sender" in exc_info.value.detail.lower() or "signature" in exc_info.value.detail.lower()


# ── #35: Constant-time cert thumbprint comparison ────────────────────────────

def test_thumbprint_uses_constant_time_comparison():
    """#35: update_agent_cert must use hmac.compare_digest, not ==."""
    import inspect
    from app.registry import store
    source = inspect.getsource(store.update_agent_cert)
    assert "hmac.compare_digest" in source
    # Ensure no plain == on thumbprint
    assert "cert_thumbprint ==" not in source


# ── #37: KMS backend unknown value ───────────────────────────────────────────

def test_kms_unknown_backend_raises():
    """#37: Unknown KMS_BACKEND must raise RuntimeError, not fall back silently."""
    from app.kms.factory import _build_provider
    with patch("app.config.get_settings") as mock_settings:
        mock_settings.return_value.kms_backend = "banana"
        with pytest.raises(RuntimeError, match="Unknown KMS_BACKEND 'banana'"):
            _build_provider()


def test_kms_local_backend_still_works():
    """#37: KMS_BACKEND=local must still work after the fix."""
    from app.kms.factory import _build_provider
    from app.kms.local import LocalKMSProvider
    with patch("app.config.get_settings") as mock_settings:
        mock_settings.return_value.kms_backend = "local"
        mock_settings.return_value.broker_ca_key_path = "/dev/null"
        mock_settings.return_value.broker_ca_cert_path = "/dev/null"
        provider = _build_provider()
        assert isinstance(provider, LocalKMSProvider)


# ── #42: Revoked binding cannot be re-approved ─────��─────────────────────────

async def test_revoked_binding_cannot_be_reapproved(db_session: AsyncSession):
    """#42: approve_binding must reject bindings that are not in 'pending' status."""
    from app.registry.binding_store import create_binding, approve_binding, revoke_binding

    binding = await create_binding(db_session, "org-r2", "agent-r2", ["cap1"])
    assert binding.status == "pending"

    # Approve it
    approved = await approve_binding(db_session, binding.id, "admin")
    assert approved is not None
    assert approved.status == "approved"

    # Revoke it
    revoked = await revoke_binding(db_session, binding.id)
    assert revoked is not None
    assert revoked.status == "revoked"

    # Try to re-approve — must return None
    result = await approve_binding(db_session, binding.id, "admin")
    assert result is None


async def test_approved_binding_cannot_be_reapproved(db_session: AsyncSession):
    """#42: Already approved binding cannot be approved again."""
    from app.registry.binding_store import create_binding, approve_binding

    binding = await create_binding(db_session, "org-r2b", "agent-r2b", ["cap1"])
    approved = await approve_binding(db_session, binding.id, "admin")
    assert approved is not None

    # Double-approve must return None
    result = await approve_binding(db_session, binding.id, "admin")
    assert result is None


# ── #43: Logout requires POST + CSRF ──���─────────────────────────────��────────

async def test_logout_get_not_allowed(client: AsyncClient):
    """#43: GET /dashboard/logout must return 405 (method not allowed)."""
    cookies, _ = await _admin_login(client)
    resp = await client.get("/dashboard/logout", cookies=cookies, follow_redirects=False)
    assert resp.status_code == 405


async def test_logout_post_without_csrf_rejected(client: AsyncClient):
    """#43: POST /dashboard/logout without CSRF token must be rejected."""
    cookies, _ = await _admin_login(client)
    resp = await client.post(
        "/dashboard/logout",
        cookies=cookies,
        data={},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_logout_post_with_valid_csrf_succeeds(client: AsyncClient):
    """#43: POST /dashboard/logout with valid CSRF token clears session."""
    cookies, csrf = await _admin_login(client)
    resp = await client.post(
        "/dashboard/logout",
        cookies=cookies,
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/dashboard/login" in resp.headers.get("location", "")
