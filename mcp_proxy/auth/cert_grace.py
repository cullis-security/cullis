"""Grace-period helpers for agent leaf cert + DPoP jkt rotation.

Wave 2 fix 7+8. Shared by:

* ``mcp_proxy.enrollment.service.approve_enrollment`` (re-enrollment
  flow that overwrites ``internal_agents.cert_pem`` + ``dpop_jkt``).
* ``mcp_proxy.admin.agents.register_agent_dpop_jwk`` (admin endpoint
  that rotates ``dpop_jkt`` alone).
* ``mcp_proxy.auth.client_cert.get_agent_from_client_cert`` (fall back
  to ``previous_cert_pem`` on pin mismatch during the grace window).
* ``mcp_proxy.auth.dpop_client_cert.get_agent_from_dpop_client_cert``
  (fall back to ``previous_dpop_jkt`` on jkt mismatch during the
  grace window).
* ``mcp_proxy.lifespan.agent_cert_grace_cleanup`` (sweep expired rows).

Kept here (not inlined into each call site) so changing the grace
window or the thumbprint format is a single-file edit and the
verifier-vs-writer surfaces never drift.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_log = logging.getLogger("mcp_proxy.auth.cert_grace")


def now_utc_iso() -> str:
    """ISO-8601 UTC timestamp matching the format the rest of the
    Mastio writes into ``internal_agents.created_at`` /
    ``enrolled_at``. Centralised so the rotation writer + the cleanup
    task use exactly the same shape (string comparison vs the cleanup
    SQL ``WHERE previous_grace_period_expires_at < :now``)."""
    return datetime.now(timezone.utc).isoformat()


def compute_grace_expiry(grace_hours: int) -> str:
    """``now() + grace_hours`` as an ISO-8601 UTC string.

    ``grace_hours`` <= 0 returns ``now()``, which the verifier reads
    as "grace expired the instant we set it" — i.e. effectively
    disables grace. The writers still stash the previous values so
    operators can inspect a recently-rotated row, but the pinning
    fallback never activates.
    """
    expiry = datetime.now(timezone.utc) + timedelta(hours=max(grace_hours, 0))
    return expiry.isoformat()


def is_grace_active(expires_at: Optional[str]) -> bool:
    """Return True iff ``expires_at`` is in the future.

    Tolerates ``None`` / empty string (no grace window active) and
    malformed timestamps (logs at debug, returns False — fail closed
    so a corrupted DB row can't widen the trust boundary).
    """
    if not expires_at:
        return False
    try:
        expiry = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError) as exc:
        _log.debug(
            "agent_cert_grace: unparseable previous_grace_period_expires_at "
            "%r (%s) — treating as expired",
            expires_at, exc,
        )
        return False
    if expiry.tzinfo is None:
        # The writers always emit ``isoformat()`` on tz-aware datetimes,
        # but legacy rows / hand-seeded fixtures may carry naive values.
        # Treat them as UTC to match the writer contract.
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > datetime.now(timezone.utc)


def cert_thumbprint_hex(pem: Optional[str]) -> Optional[str]:
    """SHA-256 hex digest of the cert DER, or ``None`` on parse error.

    Mirrors the ``_pem_der_digest`` helper in
    :mod:`mcp_proxy.auth.client_cert` but returns hex (string) instead
    of bytes so audit rows + log lines can embed it directly. Used in
    audit detail bodies so operators can correlate
    ``agent.cert_rotated`` rows to specific certs.
    """
    if not pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return None
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


__all__ = [
    "now_utc_iso",
    "compute_grace_expiry",
    "is_grace_active",
    "cert_thumbprint_hex",
]
