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
# Production RS256 public key for Cullis Enterprise license JWTs.
# The matching private key is held offline by Cullis Security and is
# never committed. Operators can override with CULLIS_LICENSE_PUBKEY_PATH
# for self-issued test/staging tokens.
_DEV_PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokKvv5ycc25CZGAy34G0
yMn7O5+kgWjC4s87OC7kvPw9rsrLrN+CItLI16DNf5UwPL0lvuPQCfgHKif0i2+R
W2yzWwMktQcbf5SoFNI8381rjQ/JARaeJdanA59ZQS5+jjJbDD2OrCc27e42GVNR
ka2hK4I76lm3xqaLVHCCMJ5KwlDlg8JlqwYFyBXYh/44hjVUGimF9WaUbF4gDK5/
xiB1pKLkyyl/Alhg7dIVQk5e7zP6pUW65Sz7CIapqUY8PqPUwjE9izMTdcFkoRIW
0QYRC6cFVjO5vKWAB0I9P4f31NAGcZzRbWduPhApykCy4RCnuGRoDyTn01032eEj
fQIDAQAB
-----END PUBLIC KEY-----
"""


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


class LicenseSwapError(Exception):
    """Raised by :func:`swap_token` when a candidate token is rejected.

    The cached license remains unchanged so a bad swap (operator paste
    error, expired JWT, wrong-tenant token) cannot accidentally
    downgrade a running deployment to community.
    """


def swap_token(new_token: str) -> LicenseClaims:
    """Hot-swap the in-process license without a restart (H3 P0.2).

    Validates ``new_token`` against the same baked / overridden public
    key used at boot. On success the cached :class:`LicenseClaims` is
    replaced atomically and the plugin registry is invalidated so the
    feature gate re-applies on the next call. On failure the cache
    stays unchanged and :class:`LicenseSwapError` is raised with a
    short reason the dashboard can show to the operator.

    Pubkey rotation (i.e. swapping the verifier itself, not just the
    license token) still requires a container rebuild — that's
    intentional, the pubkey is part of the supply-chain attestation.
    """
    global _cached

    candidate = (new_token or "").strip()
    if not candidate:
        raise LicenseSwapError("license token is empty")

    pubkey = _load_pubkey()
    if not pubkey:
        # Public-repo placeholder build: refuse to claim a swap
        # succeeded when verification is impossible.
        raise LicenseSwapError(
            "no real license pubkey configured (set CULLIS_LICENSE_PUBKEY_PATH)",
        )

    claims = _verify(candidate, pubkey)
    if claims is None:
        # _verify already logged the underlying reason (expired /
        # invalid signature). Surface a stable short message.
        raise LicenseSwapError(
            "license token failed verification (expired or wrong signature)",
        )

    # Atomic replace. Tier downgrades + entitlement narrowing are
    # legitimate operator actions (e.g. a customer downsizing their
    # plan); the dashboard surfaces the new tier so this is visible.
    _cached = claims
    _log.info(
        "license hot-swap: tier=%s org=%s features=%d exp=%s",
        claims.tier,
        claims.org,
        len(claims.features),
        time.strftime("%Y-%m-%d", time.gmtime(claims.exp)) if claims.exp else "unset",
    )

    # The plugin registry caches its feature-filtered view at first
    # use; force it to re-evaluate against the new claims so paid
    # plugins that were dark before this swap come online (and vice
    # versa for a downgrade).
    try:
        from mcp_proxy.plugins import reset_registry
        reset_registry()
    except Exception:  # defensive — never fail the swap on a side-effect
        _log.exception("plugin registry reset after license swap failed")

    return claims


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
