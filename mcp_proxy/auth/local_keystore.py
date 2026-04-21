"""ADR-012 Phase 2.0 — multi-key store for the Mastio ES256 identity.

Backing table: ``mastio_keys`` (see ``mcp_proxy/db_models.py`` +
migration ``0018_mastio_keys``). The invariant maintained by callers:
*exactly one* row has ``activated_at IS NOT NULL AND deprecated_at IS
NULL`` at any time — that is the current signer used by
``LocalIssuer`` and by the ADR-009 counter-signature path.

Phase 2.0 ships the primitive only; rotation is Phase 2.1, grace-period
verification is Phase 2.2. The keystore is deliberately oblivious to
those flows: callers orchestrate the activate/deprecate transitions
and the keystore just exposes read views (``current_signer``,
``find_by_kid``, ``all_valid_keys``).

``kid`` convention (carried over from the pre-2.0 ``LocalIssuer``):
    ``mastio-<sha256(pubkey_pem)[:16]>``
deterministic per-key, stable across restarts, unique across orgs
(assuming no ES256 collisions — cryptographically safe).
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.db import (
    get_mastio_key_by_kid,
    get_mastio_keys_active,
    get_mastio_keys_valid,
)


def compute_kid(pubkey_pem: str) -> str:
    """Derive the ``kid`` from an ES256 public-key PEM.

    Matches the legacy ``LocalIssuer._compute_kid`` so rows migrated
    from ``proxy_config.mastio_leaf_cert`` keep the same kid that any
    previously-issued JWT already references.
    """
    digest = hashlib.sha256(pubkey_pem.encode()).hexdigest()[:16]
    return f"mastio-{digest}"


@dataclass(frozen=True)
class MastioKey:
    """Materialised row from ``mastio_keys``.

    All timestamps are timezone-aware (UTC). ``privkey_pem`` is
    always present — the table stores keys we own, not foreign keys
    we only verify against (that is what ``mastio_pubkey`` pinned on
    the Court side is for, a different trust store).

    ``cert_pem`` carries the X.509 leaf currently chained under this
    key. It can be None in principle (the CA may re-issue without
    churning the key material), but the normal path keeps them
    together.
    """
    kid: str
    pubkey_pem: str
    privkey_pem: str
    cert_pem: str | None
    created_at: datetime
    activated_at: datetime | None
    deprecated_at: datetime | None
    expires_at: datetime | None

    @property
    def is_active(self) -> bool:
        """True iff this row is the current signer."""
        return self.activated_at is not None and self.deprecated_at is None

    @property
    def is_valid_for_verification(self) -> bool:
        """True while the verifier should still accept tokens with this kid."""
        if self.activated_at is None:
            return False
        if self.expires_at is None:
            return True
        return datetime.now(timezone.utc) < self.expires_at

    def load_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Deserialise ``privkey_pem`` into a ``cryptography`` EC key."""
        key = serialization.load_pem_private_key(
            self.privkey_pem.encode(), password=None,
        )
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                f"expected EC P-256 private key, got {type(key).__name__}"
            )
        return key

    def jwk(self) -> dict[str, Any]:
        """Return the JWK representation for a JWKS endpoint."""
        pub = serialization.load_pem_public_key(self.pubkey_pem.encode())
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise TypeError("expected EC P-256 public key")
        numbers = pub.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u_int(numbers.x, 32),
            "y": _b64u_int(numbers.y, 32),
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid,
        }


class LocalKeyStore:
    """Read view over ``mastio_keys``.

    Stateless: every call hits the DB. The proxy caches the current
    signer in its issuer instance, so ``current_signer`` is only read
    on boot / after a rotation event — there is no hot-path contention.
    """

    async def current_signer(self) -> MastioKey:
        """Return the single active key.

        Raises:
            RuntimeError: if no active key exists (Mastio identity not
                yet ensured) or if more than one is marked active
                (rotation bug — the invariant was violated and the
                caller must refuse to sign until it is restored).
        """
        rows = await get_mastio_keys_active()
        if len(rows) == 0:
            raise RuntimeError(
                "no active mastio key — "
                "AgentManager.ensure_mastio_identity() must run first"
            )
        if len(rows) > 1:
            kids = ", ".join(row["kid"] for row in rows)
            raise RuntimeError(
                f"{len(rows)} active mastio keys ({kids}) — "
                "rotation invariant violated"
            )
        return _row_to_key(rows[0])

    async def find_by_kid(self, kid: str) -> MastioKey | None:
        """Look up a key by ``kid``.

        Returns None if the kid is unknown. The caller still has to
        check :attr:`MastioKey.is_valid_for_verification` before
        accepting a token — an expired row is a known-but-rejected kid.
        """
        row = await get_mastio_key_by_kid(kid)
        return _row_to_key(row) if row else None

    async def all_valid_keys(self) -> list[MastioKey]:
        """Every key currently accepted for verification.

        Used by the JWKS endpoint so JWT validators outside the proxy
        (Phase 2.2) can pick the right key by ``kid``.
        """
        rows = await get_mastio_keys_valid()
        return [_row_to_key(row) for row in rows]


def _row_to_key(row: dict[str, Any]) -> MastioKey:
    return MastioKey(
        kid=row["kid"],
        pubkey_pem=row["pubkey_pem"],
        privkey_pem=row["privkey_pem"],
        cert_pem=row.get("cert_pem"),
        created_at=_parse_iso(row["created_at"]),
        activated_at=_parse_iso(row["activated_at"]) if row["activated_at"] else None,
        deprecated_at=_parse_iso(row["deprecated_at"]) if row["deprecated_at"] else None,
        expires_at=_parse_iso(row["expires_at"]) if row["expires_at"] else None,
    )


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 string into a timezone-aware UTC datetime.

    Python 3.11's ``datetime.fromisoformat`` already accepts the
    ``+00:00`` suffix; the ``Z`` fallback keeps us compatible with
    anything that has emitted the shorter form.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _b64u_int(value: int, length: int) -> str:
    return (
        base64.urlsafe_b64encode(value.to_bytes(length, "big"))
        .rstrip(b"=")
        .decode()
    )
