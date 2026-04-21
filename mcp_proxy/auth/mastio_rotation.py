"""ADR-012 Phase 2.1 — key-continuity proof for Mastio key rotation.

The Mastio proves it is legitimately the same operator during a key
rotation by signing a canonical statement with the *old* private key.
The Court verifies the signature against the currently-pinned pubkey
(the old one, pre-rotation) and — on success — updates the pin to the
new pubkey.

Proof shape (canonical JSON, sort_keys, no whitespace)::

    {
      "issued_at":      "2026-04-21T21:00:00+00:00",
      "new_kid":        "mastio-<sha256(new_pubkey_pem)[:16]>",
      "new_pubkey_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END...",
      "old_kid":        "mastio-<sha256(old_pubkey_pem)[:16]>"
    }

The signature is ES256 over the UTF-8-encoded canonical JSON,
base64url-encoded with no padding — the same shape already used by
the ADR-009 counter-signature path.

The proof carries ``old_kid`` so the verifier can refuse a mismatch
between the signature's key and the key that was intended to sign
(anti-substitution). ``issued_at`` bounds replay: the verifier
rejects proofs whose timestamp is outside a small freshness window.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

PROOF_FRESHNESS_SECONDS = 600  # 10 minutes


@dataclass(frozen=True)
class ContinuityProof:
    old_kid: str
    new_kid: str
    new_pubkey_pem: str
    issued_at: str
    signature_b64u: str

    def to_dict(self) -> dict[str, str]:
        return {
            "old_kid": self.old_kid,
            "new_kid": self.new_kid,
            "new_pubkey_pem": self.new_pubkey_pem,
            "issued_at": self.issued_at,
            "signature_b64u": self.signature_b64u,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContinuityProof":
        required = {"old_kid", "new_kid", "new_pubkey_pem", "issued_at", "signature_b64u"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"continuity proof missing fields: {sorted(missing)}")
        for key in required:
            if not isinstance(data[key], str) or not data[key]:
                raise ValueError(f"continuity proof field {key!r} must be a non-empty string")
        return cls(
            old_kid=data["old_kid"],
            new_kid=data["new_kid"],
            new_pubkey_pem=data["new_pubkey_pem"],
            issued_at=data["issued_at"],
            signature_b64u=data["signature_b64u"],
        )


class ContinuityProofError(Exception):
    """Raised when a continuity proof fails any validation step."""


def _canonical_payload(
    *, old_kid: str, new_kid: str, new_pubkey_pem: str, issued_at: str,
) -> bytes:
    """Canonical JSON body over which the proof signature is computed."""
    return json.dumps(
        {
            "issued_at": issued_at,
            "new_kid": new_kid,
            "new_pubkey_pem": new_pubkey_pem,
            "old_kid": old_kid,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def build_proof(
    *,
    old_priv_key: ec.EllipticCurvePrivateKey,
    old_kid: str,
    new_kid: str,
    new_pubkey_pem: str,
    issued_at: datetime | None = None,
) -> ContinuityProof:
    """Produce a signed continuity proof.

    ``old_priv_key`` is the current-signer key whose corresponding
    public key is currently pinned at the Court. ``new_kid`` /
    ``new_pubkey_pem`` describe the key we want the Court to pin next.

    The resulting ``ContinuityProof`` is JSON-serialisable via
    :meth:`ContinuityProof.to_dict` and is what gets POSTed to the
    Court rotation endpoint.
    """
    now = issued_at or datetime.now(timezone.utc)
    issued_at_iso = now.isoformat()
    payload = _canonical_payload(
        old_kid=old_kid,
        new_kid=new_kid,
        new_pubkey_pem=new_pubkey_pem,
        issued_at=issued_at_iso,
    )
    der_signature = old_priv_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    sig_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return ContinuityProof(
        old_kid=old_kid,
        new_kid=new_kid,
        new_pubkey_pem=new_pubkey_pem,
        issued_at=issued_at_iso,
        signature_b64u=sig_b64,
    )


def verify_proof(
    proof: ContinuityProof,
    *,
    expected_old_pubkey_pem: str,
    expected_old_kid: str | None = None,
    now: datetime | None = None,
    freshness_seconds: int = PROOF_FRESHNESS_SECONDS,
) -> None:
    """Verify a continuity proof against the currently-pinned old pubkey.

    Raises :class:`ContinuityProofError` on any validation failure —
    stale timestamp, wrong ``old_kid``, malformed signature, bad
    signature. Succeeds silently on a valid proof.

    ``expected_old_kid`` lets the caller assert the proof is signed by
    the kid they think is currently pinned (anti-substitution); if
    omitted, only the signature is checked.
    """
    if expected_old_kid is not None and proof.old_kid != expected_old_kid:
        raise ContinuityProofError(
            f"old_kid mismatch: proof carries {proof.old_kid!r}, "
            f"Court has {expected_old_kid!r} pinned"
        )

    try:
        issued = datetime.fromisoformat(proof.issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityProofError(f"invalid issued_at: {exc}") from exc
    if issued.tzinfo is None:
        raise ContinuityProofError("issued_at is not timezone-aware")
    reference = now or datetime.now(timezone.utc)
    delta = abs((reference - issued).total_seconds())
    if delta > freshness_seconds:
        raise ContinuityProofError(
            f"issued_at is outside the freshness window "
            f"({int(delta)}s > {freshness_seconds}s)"
        )

    try:
        pub_key = serialization.load_pem_public_key(expected_old_pubkey_pem.encode())
    except ValueError as exc:
        raise ContinuityProofError(f"malformed expected_old_pubkey_pem: {exc}") from exc
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise ContinuityProofError("expected_old_pubkey is not an EC key")

    try:
        raw_sig = base64.urlsafe_b64decode(
            proof.signature_b64u + "=" * (-len(proof.signature_b64u) % 4)
        )
    except (ValueError, binascii.Error) as exc:
        raise ContinuityProofError(f"malformed signature_b64u: {exc}") from exc
    if len(raw_sig) != 64:
        raise ContinuityProofError(
            f"signature must be 64 bytes (r||s), got {len(raw_sig)}"
        )
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der_sig = encode_dss_signature(r, s)

    payload = _canonical_payload(
        old_kid=proof.old_kid,
        new_kid=proof.new_kid,
        new_pubkey_pem=proof.new_pubkey_pem,
        issued_at=proof.issued_at,
    )
    try:
        pub_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ContinuityProofError("signature verification failed") from exc


__all__ = [
    "ContinuityProof",
    "ContinuityProofError",
    "PROOF_FRESHNESS_SECONDS",
    "build_proof",
    "verify_proof",
]
