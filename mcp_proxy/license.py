"""Mastio license verifier — offline JWT (RS256) gate for paid features.

Validates an offline-signed license token and exposes ``has_feature`` /
``require_feature`` for the plugin layer + protected endpoints.

Design choices:
  * RS256 with a public key embedded in the binary — no phone-home, no
    network call to validate. Operators can supply their own pubkey via
    ``CULLIS_LICENSE_PUBKEY_PATH`` (typical for staging or self-issued
    test keys; production deals will swap the embedded key with the
    customer-distribution one before the first contract).
  * Token is read from ``CULLIS_LICENSE_KEY`` (raw JWT) or from the file
    pointed to by ``CULLIS_LICENSE_PATH``. Missing or invalid token =
    community tier (no paid features).
  * ``has_feature`` is the non-blocking accessor (returns False on
    community); ``require_feature(name)`` is a FastAPI dependency
    factory that raises HTTPException(402) when a paid feature is hit
    without entitlement.

The placeholder embedded key never matches a real-world signature; the
public repo deliberately ships in "community-only" mode until an
operator points the override env at a real key.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt as jose_jwt
from fastapi import HTTPException

_log = logging.getLogger("mcp_proxy.license")


_PLACEHOLDER_MARKER = "CULLIS_PLACEHOLDER_PUBKEY"
_DEV_PUBKEY_PEM = (
    f"-----BEGIN PUBLIC KEY-----\n{_PLACEHOLDER_MARKER}\n-----END PUBLIC KEY-----\n"
).encode()


@dataclass(frozen=True)
class LicenseClaims:
    tier: str = "community"
    org: str = ""
    exp: int = 0
    features: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_community(self) -> bool:
        return self.tier == "community"

    def has(self, feature: str) -> bool:
        return feature in self.features


_COMMUNITY = LicenseClaims()
_cached: LicenseClaims | None = None


def _load_pubkey() -> bytes | None:
    override = os.environ.get("CULLIS_LICENSE_PUBKEY_PATH")
    if override:
        try:
            return Path(override).read_bytes()
        except OSError as exc:
            _log.warning("license pubkey override %s unreadable: %s", override, exc)
            return None

    if _PLACEHOLDER_MARKER in _DEV_PUBKEY_PEM.decode("ascii", errors="replace"):
        # Public repo ships without a real key. Any submitted license
        # would fail signature verification anyway; short-circuit so the
        # log line is honest about why we are running community.
        return None
    return _DEV_PUBKEY_PEM


def _read_token() -> str | None:
    raw = os.environ.get("CULLIS_LICENSE_KEY")
    if raw and raw.strip():
        return raw.strip()
    path = os.environ.get("CULLIS_LICENSE_PATH")
    if path:
        try:
            return Path(path).read_text().strip() or None
        except OSError as exc:
            _log.warning("license file %s unreadable: %s", path, exc)
    return None


def _verify(token: str, pubkey: bytes) -> LicenseClaims | None:
    try:
        payload: dict[str, Any] = jose_jwt.decode(
            token,
            pubkey,
            algorithms=["RS256"],
            options={"require": ["exp"]},
        )
    except jose_jwt.ExpiredSignatureError:
        _log.error("license expired")
        return None
    except jose_jwt.InvalidTokenError as exc:
        _log.error("license invalid: %s", exc)
        return None

    raw_features = payload.get("features", [])
    if not isinstance(raw_features, list):
        raw_features = []
    return LicenseClaims(
        tier=str(payload.get("tier", "enterprise")),
        org=str(payload.get("org", "")),
        exp=int(payload.get("exp", 0)),
        features=frozenset(str(f) for f in raw_features),
    )


def load_license() -> LicenseClaims:
    """Read + verify the license; cached after the first successful call."""
    global _cached
    if _cached is not None:
        return _cached

    token = _read_token()
    if not token:
        _cached = _COMMUNITY
        _log.info("license: community (no token configured)")
        return _cached

    pubkey = _load_pubkey()
    if not pubkey:
        _log.warning(
            "license token present but no real pubkey configured "
            "(set CULLIS_LICENSE_PUBKEY_PATH) — falling back to community",
        )
        _cached = _COMMUNITY
        return _cached

    claims = _verify(token, pubkey)
    if claims is None:
        _cached = _COMMUNITY
        return _cached

    _cached = claims
    _log.info(
        "license: tier=%s org=%s features=%d exp=%s",
        claims.tier,
        claims.org,
        len(claims.features),
        time.strftime("%Y-%m-%d", time.gmtime(claims.exp)) if claims.exp else "unset",
    )
    return _cached


def reset_cache() -> None:
    """Test-only: drop cached claims so the next ``load_license`` re-reads env."""
    global _cached
    _cached = None


def has_feature(feature: str) -> bool:
    return load_license().has(feature)


def require_feature(feature: str):
    """FastAPI dependency factory that 402s when ``feature`` is not licensed."""

    def _dep() -> None:
        if not has_feature(feature):
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "license_required",
                    "feature": feature,
                    "tier": load_license().tier,
                },
            )

    return _dep
