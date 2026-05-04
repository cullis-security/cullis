"""HMAC-signed session cookie for Cullis Frontdesk shared mode.

Format: ``<base64url(payload_json)>.<base64url(hmac_sha256(payload, secret))>``

Self-validating: the payload carries ``iat`` + ``exp`` so we can
detect tampering and expiry without a server-side session table.
``parse_cookie`` returns ``None`` on any failure (bad encoding, bad
signature, expired, malformed JSON) so callers cannot accidentally
distinguish "absent" from "invalid" in their control flow.

Why not ``itsdangerous``: stdlib ``hmac`` + ``base64`` + ``json`` are
enough for this footprint and keep the Frontdesk container's
dependency tree minimal. Constant-time comparison via
``hmac.compare_digest``.
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

_log = logging.getLogger("cullis_connector.ambassador.shared.cookie")

# Caps on cookie payload size — keep cookies well under the 4KiB browser
# limit and refuse anything larger than would be reasonable.
_MAX_PAYLOAD_BYTES = 1024
_MAX_COOKIE_BYTES = 2048


@dataclass(frozen=True)
class SessionPayload:
    """The structured contents of a shared-mode session cookie."""

    sub: str               # SSO subject (e.g. 'mario@acme.it')
    org: str               # tenant org id
    principal_id: str      # 'acme.test/acme/user/mario'
    iat: int               # issued at (unix seconds)
    exp: int               # expiry (unix seconds)

    def as_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "sub": self.sub,
                "org": self.org,
                "principal_id": self.principal_id,
                "iat": int(self.iat),
                "exp": int(self.exp),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "SessionPayload":
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("payload must be a JSON object")
        for k in ("sub", "org", "principal_id", "iat", "exp"):
            if k not in obj:
                raise ValueError(f"payload missing required key {k!r}")
        return cls(
            sub=str(obj["sub"]),
            org=str(obj["org"]),
            principal_id=str(obj["principal_id"]),
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


def make_cookie(payload: SessionPayload, secret: bytes) -> str:
    """Encode + HMAC-sign a session payload.

    Raises ``ValueError`` if the payload exceeds the soft cap.
    """
    if len(secret) < 16:
        raise ValueError("secret must be at least 16 bytes")
    raw = payload.as_json_bytes()
    if len(raw) > _MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"cookie payload too large ({len(raw)} bytes > {_MAX_PAYLOAD_BYTES})",
        )
    sig = _hmac(secret, raw)
    return f"{_b64url_encode(raw)}.{_b64url_encode(sig)}"


def parse_cookie(
    cookie: str,
    secret: bytes,
    *,
    now: Optional[int] = None,
) -> Optional[SessionPayload]:
    """Verify + decode a session cookie. Returns ``None`` on any failure.

    Failure modes collapse to ``None`` on purpose so callers cannot
    leak via timing or exception type which check failed (bad sig vs
    expired vs malformed).
    """
    if not cookie or len(cookie) > _MAX_COOKIE_BYTES:
        return None
    try:
        encoded_payload, encoded_sig = cookie.split(".", 1)
    except ValueError:
        return None
    try:
        raw_payload = _b64url_decode(encoded_payload)
        raw_sig = _b64url_decode(encoded_sig)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    expected_sig = _hmac(secret, raw_payload)
    if not hmac.compare_digest(raw_sig, expected_sig):
        return None
    try:
        payload = SessionPayload.from_json_bytes(raw_payload)
    except (ValueError, json.JSONDecodeError, TypeError):
        return None
    cur = int(now if now is not None else time.time())
    if cur >= payload.exp:
        return None
    if cur < payload.iat:
        # Issued in the future — refuse rather than gracefully accept,
        # something is very wrong with the issuer's clock.
        return None
    return payload


def issue(
    *,
    sub: str,
    org: str,
    principal_id: str,
    secret: bytes,
    ttl_seconds: int = 3600,
    now: Optional[int] = None,
) -> tuple[str, SessionPayload]:
    """Build + sign a fresh session cookie. Convenience over ``make_cookie``."""
    if ttl_seconds <= 0 or ttl_seconds > 24 * 3600:
        raise ValueError("ttl_seconds must be in (0, 86400]")
    cur = int(now if now is not None else time.time())
    payload = SessionPayload(
        sub=sub,
        org=org,
        principal_id=principal_id,
        iat=cur,
        exp=cur + ttl_seconds,
    )
    return make_cookie(payload, secret), payload


__all__ = [
    "SessionPayload",
    "issue",
    "make_cookie",
    "parse_cookie",
]
