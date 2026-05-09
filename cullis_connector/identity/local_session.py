"""Local-mode session cookie for Cullis Connector — ADR-025 Phase 2.

When ``AUTH_MODE=local`` (the Frontdesk SMB scenario without a
corporate IdP) the Connector authenticates end users directly against
``users.db`` and issues a short-lived HMAC-signed session cookie. This
module owns the encode/decode of that cookie. Conceptually the same
shape as ``cullis_connector/ambassador/shared/cookie.py`` but with a
distinct payload schema: it carries the local user_name, a
must-change-password flag, and a per-session CSRF token.

Format: ``<base64url(payload_json)>.<base64url(hmac_sha256(payload, secret))>``

The payload is canonical JSON (sorted keys, separators ``(",", ":")``).
``parse_local_cookie`` collapses every failure mode (bad encoding, bad
signature, expired, malformed JSON) to ``None`` so callers cannot leak
the failure reason via timing or exception type.

The HMAC primitives are intentionally duplicated from
``cullis_connector.ambassador.shared.cookie`` rather than imported, so
local-mode does not pull the shared-mode credential cache + provisioner
graph into the boot path. Both modules use the same HMAC-SHA256 with
``hmac.compare_digest`` so behaviour is byte-identical.
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

_log = logging.getLogger("cullis_connector.identity.local_session")

# Cookie name for the local-mode session. Distinct from the shared-mode
# cookie name (``cullis_session``) so a Frontdesk container that gets
# reconfigured between modes does not present a stale cookie of the
# wrong shape and silently authenticate.
LOCAL_SESSION_COOKIE_NAME = "cullis_local_session"

# 8-hour TTL — same as ``mcp_proxy/dashboard/session.py`` admin cookie.
# Long enough to cover a full work session, short enough that a stolen
# cookie has a bounded blast radius.
LOCAL_SESSION_TTL_SEC = 8 * 3600

# Minimum signing-secret length. 16 bytes is the floor we require so a
# misconfigured operator cannot ship a 4-byte HMAC key. The Frontdesk
# bootstrap (`bootstrap_cookie_secret`) generates 32 bytes.
_MIN_SECRET_BYTES = 16

# Caps on cookie payload size — keep cookies well under the 4KiB browser
# limit and refuse anything larger than would be reasonable.
_MAX_PAYLOAD_BYTES = 1024
_MAX_COOKIE_BYTES = 2048


@dataclass(frozen=True)
class LocalSessionPayload:
    """Structured contents of a local-mode session cookie."""

    user_name: str               # 'mario'
    principal_name: str          # initially same as user_name; Phase 3 SPIFFE
    must_change_password: bool
    csrf_token: str              # 16 bytes hex
    iat: int                     # issued-at, unix seconds
    exp: int                     # expiry, unix seconds

    def as_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "user_name": self.user_name,
                "principal_name": self.principal_name,
                "must_change_password": bool(self.must_change_password),
                "csrf_token": self.csrf_token,
                "iat": int(self.iat),
                "exp": int(self.exp),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "LocalSessionPayload":
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("payload must be a JSON object")
        for k in (
            "user_name",
            "principal_name",
            "must_change_password",
            "csrf_token",
            "iat",
            "exp",
        ):
            if k not in obj:
                raise ValueError(f"payload missing required key {k!r}")
        return cls(
            user_name=str(obj["user_name"]),
            principal_name=str(obj["principal_name"]),
            must_change_password=bool(obj["must_change_password"]),
            csrf_token=str(obj["csrf_token"]),
            iat=int(obj["iat"]),
            exp=int(obj["exp"]),
        )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _hmac(secret: bytes, payload: bytes) -> bytes:
    return hmac.new(secret, payload, sha256).digest()


def new_csrf_token() -> str:
    """Return a fresh 16-byte hex CSRF token (32 hex chars)."""
    return secrets.token_hex(16)


def issue_local_cookie(
    payload: LocalSessionPayload, secret: bytes,
) -> str:
    """HMAC-sign + base64url-encode a local session payload.

    Raises ``ValueError`` if the payload exceeds the soft cap or if the
    secret is too short.
    """
    if len(secret) < _MIN_SECRET_BYTES:
        raise ValueError(
            f"secret must be at least {_MIN_SECRET_BYTES} bytes",
        )
    raw = payload.as_json_bytes()
    if len(raw) > _MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"cookie payload too large ({len(raw)} bytes "
            f"> {_MAX_PAYLOAD_BYTES})",
        )
    sig = _hmac(secret, raw)
    return f"{_b64url_encode(raw)}.{_b64url_encode(sig)}"


def parse_local_cookie(
    cookie_value: str,
    secret: bytes,
    *,
    now: Optional[int] = None,
) -> Optional[LocalSessionPayload]:
    """Verify + decode a local session cookie. Returns ``None`` on any failure.

    Failure modes collapse to ``None`` on purpose so callers cannot
    leak via timing or exception type which check failed (bad sig vs
    expired vs malformed).
    """
    if not cookie_value or len(cookie_value) > _MAX_COOKIE_BYTES:
        return None
    try:
        encoded_payload, encoded_sig = cookie_value.split(".", 1)
    except ValueError:
        return None
    try:
        raw_payload = _b64url_decode(encoded_payload)
        raw_sig = _b64url_decode(encoded_sig)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    if len(secret) < _MIN_SECRET_BYTES:
        # Caller bug: never accept a too-short secret on parse either.
        return None
    expected_sig = _hmac(secret, raw_payload)
    if not hmac.compare_digest(raw_sig, expected_sig):
        return None
    try:
        payload = LocalSessionPayload.from_json_bytes(raw_payload)
    except (ValueError, json.JSONDecodeError, TypeError):
        return None
    cur = int(now if now is not None else time.time())
    if cur >= payload.exp:
        return None
    if cur < payload.iat:
        # Issued in the future — refuse rather than accept, something
        # is wrong with the issuer's clock.
        return None
    return payload


def build_payload(
    *,
    user_name: str,
    must_change_password: bool,
    principal_name: str = "",
    csrf_token: Optional[str] = None,
    ttl_seconds: int = LOCAL_SESSION_TTL_SEC,
    now: Optional[int] = None,
) -> LocalSessionPayload:
    """Convenience constructor — fills iat/exp + a fresh CSRF token.

    ``principal_name`` defaults to the bare user_name (Phase 2). Phase 3
    replaces it with the full SPIFFE form once user-principal CSR
    issuance lands.
    """
    if ttl_seconds <= 0 or ttl_seconds > 24 * 3600:
        raise ValueError("ttl_seconds must be in (0, 86400]")
    cur = int(now if now is not None else time.time())
    return LocalSessionPayload(
        user_name=user_name,
        principal_name=principal_name or user_name,
        must_change_password=bool(must_change_password),
        csrf_token=csrf_token or new_csrf_token(),
        iat=cur,
        exp=cur + ttl_seconds,
    )


__all__ = [
    "LOCAL_SESSION_COOKIE_NAME",
    "LOCAL_SESSION_TTL_SEC",
    "LocalSessionPayload",
    "build_payload",
    "issue_local_cookie",
    "new_csrf_token",
    "parse_local_cookie",
]
