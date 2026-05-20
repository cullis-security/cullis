"""Bootstrap helpers for Cullis Frontdesk shared mode (ADR-021 PR4c).

Two responsibilities:

  - ``bootstrap_cookie_secret(config_dir)`` — generate a 32-byte secret
    on first start and persist it at ``<config_dir>/cookie.secret`` mode
    0600. Subsequent runs reuse the same file.
  - ``shared_mode_settings_from_env()`` — read the shared-mode env vars
    into a typed dataclass so ``_maybe_install_shared_ambassador`` in
    ``cullis_connector/web.py`` can validate them once at boot.

Env contract (documented in ADR-021 §5+§6):

  AMBASSADOR_MODE                  "single" (default) | "shared"
  CULLIS_TRUSTED_PROXIES           CIDR list, default "127.0.0.1/32,::1/128"
  CULLIS_FRONTDESK_ORG_ID          required for shared
  CULLIS_FRONTDESK_TRUST_DOMAIN    required for shared
  CULLIS_FRONTDESK_COOKIE_TTL_S    int seconds, default 3600
  CULLIS_FRONTDESK_MASTIO_URL      where the Mastio CSR endpoint lives

The Mastio URL falls back to the Connector ``site_url`` when not set,
because in single-tenant Frontdesk deployments they are the same host.
"""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_log = logging.getLogger("cullis_connector.ambassador.shared.wire")

COOKIE_SECRET_FILENAME = "cookie.secret"
SECRET_LEN_BYTES = 32

# Env var names — kept in one place so docs and tests can import them.
ENV_MODE = "AMBASSADOR_MODE"
ENV_TRUSTED_PROXIES = "CULLIS_TRUSTED_PROXIES"
ENV_ORG_ID = "CULLIS_FRONTDESK_ORG_ID"
ENV_TRUST_DOMAIN = "CULLIS_FRONTDESK_TRUST_DOMAIN"
ENV_COOKIE_TTL = "CULLIS_FRONTDESK_COOKIE_TTL_S"
ENV_MASTIO_URL = "CULLIS_FRONTDESK_MASTIO_URL"

DEFAULT_TRUSTED_PROXIES = "127.0.0.1/32,::1/128"
DEFAULT_COOKIE_TTL = 3600


@dataclass(frozen=True)
class SharedModeSettings:
    """Validated env-driven shared-mode configuration."""

    enabled: bool
    org_id: str
    trust_domain: str
    trusted_proxies_cidrs: tuple[str, ...]
    cookie_ttl_seconds: int
    mastio_url: str  # may be empty → caller falls back to site_url


def bootstrap_cookie_secret(config_dir: Path) -> bytes:
    """Return the cookie secret, generating it on first call.

    File mode 0600. The secret is the cryptographic root for every
    session cookie issued by this Frontdesk container. Backup
    alongside the broker CA private key — losing it forces every
    user's browser to re-init their session (no security incident,
    just UX churn).
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / COOKIE_SECRET_FILENAME
    if path.exists():
        raw = path.read_bytes()
        if len(raw) == SECRET_LEN_BYTES:
            return raw
        _log.warning(
            "shared cookie secret at %s has unexpected length %d; "
            "regenerating", path, len(raw),
        )
    secret = secrets.token_bytes(SECRET_LEN_BYTES)
    # Audit F-B-401 — the cookie secret is the HMAC key for every
    # Frontdesk shared-mode session cookie. Atomic 0600 write so the
    # 64 random bytes don't sit on disk world-readable for the chmod
    # window.
    from cullis_connector._atomic_write import write_with_mode
    write_with_mode(path, data=secret, mode=0o600)
    _log.info("shared cookie secret generated at %s (0600)", path)
    return secret


def _coerce_int(raw: Optional[str], default: int, *, name: str) -> int:
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer; got {raw!r}") from exc


def shared_mode_settings_from_env(
    env: Optional[dict[str, str]] = None,
) -> SharedModeSettings:
    """Read + validate shared-mode env vars.

    Returns ``enabled=False`` (and other fields zeroed) when
    ``AMBASSADOR_MODE`` is anything other than ``"shared"``. Raises
    ``ValueError`` only when the operator opted into shared mode but
    a required field is missing or malformed.
    """
    e = env if env is not None else os.environ
    mode = (e.get(ENV_MODE) or "single").strip().lower()
    if mode != "shared":
        return SharedModeSettings(
            enabled=False,
            org_id="",
            trust_domain="",
            trusted_proxies_cidrs=(),
            cookie_ttl_seconds=DEFAULT_COOKIE_TTL,
            mastio_url="",
        )

    org_id = (e.get(ENV_ORG_ID) or "").strip()
    if not org_id:
        raise ValueError(
            f"{ENV_ORG_ID} is required when {ENV_MODE}=shared",
        )
    trust_domain = (e.get(ENV_TRUST_DOMAIN) or "").strip()
    if not trust_domain:
        raise ValueError(
            f"{ENV_TRUST_DOMAIN} is required when {ENV_MODE}=shared",
        )

    raw_cidrs = (e.get(ENV_TRUSTED_PROXIES) or DEFAULT_TRUSTED_PROXIES)
    cidrs = tuple(c.strip() for c in raw_cidrs.split(",") if c.strip())
    if not cidrs:
        raise ValueError(
            f"{ENV_TRUSTED_PROXIES} must contain at least one CIDR",
        )

    cookie_ttl = _coerce_int(
        e.get(ENV_COOKIE_TTL), DEFAULT_COOKIE_TTL, name=ENV_COOKIE_TTL,
    )
    if cookie_ttl <= 0 or cookie_ttl > 24 * 3600:
        raise ValueError(
            f"{ENV_COOKIE_TTL} must be in (0, 86400]; got {cookie_ttl}",
        )

    mastio_url = (e.get(ENV_MASTIO_URL) or "").rstrip("/")

    return SharedModeSettings(
        enabled=True,
        org_id=org_id,
        trust_domain=trust_domain,
        trusted_proxies_cidrs=cidrs,
        cookie_ttl_seconds=cookie_ttl,
        mastio_url=mastio_url,
    )


__all__ = [
    "COOKIE_SECRET_FILENAME",
    "DEFAULT_COOKIE_TTL",
    "DEFAULT_TRUSTED_PROXIES",
    "ENV_COOKIE_TTL",
    "ENV_MASTIO_URL",
    "ENV_MODE",
    "ENV_ORG_ID",
    "ENV_TRUST_DOMAIN",
    "ENV_TRUSTED_PROXIES",
    "SECRET_LEN_BYTES",
    "SharedModeSettings",
    "bootstrap_cookie_secret",
    "shared_mode_settings_from_env",
]
