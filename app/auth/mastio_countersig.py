"""ADR-009 Phase 1 — mastio counter-signature verification.

When an organization has pinned its mastio/proxy ES256 public key at
onboarding (``organizations.mastio_pubkey``), the Court requires every
``/v1/auth/token`` call for that org to carry an
``X-Cullis-Mastio-Signature`` header. The header is the ES256 signature
over the raw ``client_assertion`` JWT string (the exact bytes the agent
submitted), base64url-encoded without padding.

This proves the login flowed through the organization's mastio — an agent
with a stolen or self-issued cert cannot bypass the gateway and authenticate
to the Court directly, because only the mastio holds the pinned private key.

Leaving ``mastio_pubkey`` NULL disables enforcement for that org, which is
the legacy behavior used by orgs that have not yet been rolled onto the
ADR-009 flow. Phase 3 flips this to NOT NULL.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException, status


COUNTERSIG_HEADER = "X-Cullis-Mastio-Signature"


def _b64url_decode_nopad(data: str) -> bytes:
    """Decode base64url with or without padding (see feedback_base64url_nopad)."""
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def verify_mastio_countersig(
    *,
    client_assertion: str,
    signature_b64: str | None,
    mastio_pubkey_pem: str,
) -> None:
    """Verify the mastio counter-signature or raise 403.

    ``signature_b64`` is the header value as received; ``None`` means the
    client didn't send it at all. ``mastio_pubkey_pem`` must be a pinned
    EC P-256 SubjectPublicKeyInfo PEM (the format that onboarding accepts).
    The signed message is the raw UTF-8 bytes of ``client_assertion`` —
    the ``cryptography`` library applies SHA-256 internally as part of
    ``ec.ECDSA(hashes.SHA256())``.
    """
    if signature_b64 is None or not signature_b64.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "organization requires mastio counter-signature but the "
                f"{COUNTERSIG_HEADER} header is missing"
            ),
        )

    try:
        pubkey = serialization.load_pem_public_key(mastio_pubkey_pem.encode())
    except Exception as exc:
        # Defensive: onboarding validates the PEM before pinning, so a
        # malformed column means operator tampering. Fail closed.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="pinned mastio_pubkey is unreadable — contact the admin",
        ) from exc

    if not isinstance(pubkey, ec.EllipticCurvePublicKey) or not isinstance(
        pubkey.curve, ec.SECP256R1,
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="pinned mastio_pubkey is not EC P-256",
        )

    try:
        signature = _b64url_decode_nopad(signature_b64.strip())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{COUNTERSIG_HEADER} is not valid base64url",
        ) from exc

    try:
        pubkey.verify(
            signature, client_assertion.encode(), ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="mastio counter-signature verification failed",
        )
