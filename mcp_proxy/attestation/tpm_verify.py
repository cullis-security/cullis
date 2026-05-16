"""Server-side TPM 2.0 quote verifier (ADR-032 F3 Phase 1).

Pure-Python: imports only ``cryptography``. The Connector ships a quote
envelope packed by ``cullis_connector.keystore.tpm_linux._pack_quote_envelope``
which we unpack and verify against the PEM public key submitted in the
same enrollment request.

Phase 1 limits (explicit in ``imp/c2-f3-linux-tpm-spike-prompt.md``):

* EK CA chain verify DEFERRED (Decision Q8). Manufacturer trust is by
  literal whitelist; an unknown vendor downgrades strength to
  ``hw_isolated`` rather than refusing the claim.
* No PCR allowlist; the quote attests to PCR 0..7 (the static-root
  measured-boot range) but we do not pin a known-good digest. The
  ``policy.tier_evaluated`` audit row preserves the digest so a future
  F5 release can compare.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

_log = logging.getLogger("mcp_proxy.attestation.tpm_verify")

# Mirrors the Connector-side set in
# ``cullis_connector/keystore/tpm_linux.py``. The two must stay in sync;
# a future ADR will move both to a refreshable remote bundle. Order is
# alphabetical to make diffs reviewer-friendly.
TPM_MANUFACTURER_WHITELIST: frozenset[str] = frozenset(
    {"Infineon", "Intel", "Microsoft", "Nuvoton", "ST"},
)

class TpmQuoteVerificationError(Exception):
    """Raised when the quote envelope is malformed, the signature fails,
    or the embedded nonce does not match the server-issued challenge."""


_QUOTE_MAGIC = b"CULLIS-Q1"


def _unpack_envelope(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Inverse of the Connector packer. Server-local copy so this module
    does not depend on ``tpm2-pytss`` being installed on the Mastio host."""
    if len(blob) < len(_QUOTE_MAGIC) + 2 + 4 + 4:
        raise TpmQuoteVerificationError("quote envelope truncated")
    if blob[: len(_QUOTE_MAGIC)] != _QUOTE_MAGIC:
        raise TpmQuoteVerificationError("quote envelope magic mismatch")
    pos = len(_QUOTE_MAGIC)
    nonce_len = int.from_bytes(blob[pos : pos + 2], "big")
    pos += 2
    nonce = blob[pos : pos + nonce_len]
    pos += nonce_len
    quote_len = int.from_bytes(blob[pos : pos + 4], "big")
    pos += 4
    quote = blob[pos : pos + quote_len]
    pos += quote_len
    if len(quote) != quote_len:
        raise TpmQuoteVerificationError("quote body truncated")
    sig_len = int.from_bytes(blob[pos : pos + 4], "big")
    pos += 4
    sig = blob[pos : pos + sig_len]
    if len(sig) != sig_len:
        raise TpmQuoteVerificationError("quote signature truncated")
    return nonce, quote, sig


def _load_pub(public_key_pem: str) -> PublicKeyTypes:
    try:
        return serialization.load_pem_public_key(public_key_pem.encode())
    except Exception as exc:
        raise TpmQuoteVerificationError(f"invalid public key PEM: {exc}") from exc


def verify_tpm_quote(
    quote_blob: bytes,
    public_key_pem: str,
    expected_nonce: bytes,
    *,
    manufacturer: str | None = None,
    manufacturer_whitelist: frozenset[str] | None = None,
    ek_cert_present: bool = False,
) -> tuple[bool, dict[str, object]]:
    """Verify ``quote_blob`` and derive the hardware-side attestation claim.

    Returns ``(valid, claim_partial)``. ``valid`` is ``False`` only when
    cryptographic verification fails or the nonce is wrong; an unknown
    manufacturer still counts as ``valid`` but downgrades ``strength`` to
    ``hw_isolated`` (Phase 1 EK CA gap, ADR-032 Q8).

    ``claim_partial`` has the shape locked in
    ``imp/attestation-claim-schema.md`` sez. 1 for the hardware fields:

    * ``hardware`` ; always ``"tpm_2.0"`` (Phase 1 owns no other backend)
    * ``strength`` ; ``hw_attested`` / ``hw_isolated`` / ``soft_only``
    * ``manufacturer``; passthrough or ``None``
    * ``pcr_digest_sha256``; hex of the quote digest, for audit replay
    """
    whitelist = manufacturer_whitelist or TPM_MANUFACTURER_WHITELIST
    try:
        nonce, quote_bytes, sig_bytes = _unpack_envelope(quote_blob)
    except TpmQuoteVerificationError as exc:
        _log.warning("tpm_quote_envelope_error", extra={"err": str(exc)})
        return False, _claim_soft_only()

    if nonce != expected_nonce:
        _log.warning(
            "tpm_quote_nonce_mismatch",
            extra={
                "expected_sha256": hashlib.sha256(expected_nonce).hexdigest(),
                "got_sha256": hashlib.sha256(nonce).hexdigest(),
            },
        )
        return False, _claim_soft_only()

    pub = _load_pub(public_key_pem)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        _log.warning(
            "tpm_quote_unsupported_key",
            extra={"key_type": type(pub).__name__},
        )
        return False, _claim_soft_only()

    digest = hashlib.sha256(quote_bytes).digest()
    try:
        # tpm2-pytss exports an ECDSA-SHA256 signature; we verify the
        # signature over the quote bytes the TPM signed (the TPMS_ATTEST
        # marshalled form). Verifying with ``ec.ECDSA(Prehashed)`` lets
        # us pass the SHA-256 digest we already computed.
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
        )

        pub.verify(sig_bytes, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        _log.warning("tpm_quote_invalid_signature")
        return False, _claim_soft_only()

    # Quote is valid. Derive strength from manufacturer/EK posture.
    strength: Literal["hw_attested", "hw_isolated"]
    if ek_cert_present and manufacturer in whitelist:
        strength = "hw_attested"
    else:
        strength = "hw_isolated"

    claim: dict[str, object] = {
        "hardware": "tpm_2.0",
        "strength": strength,
        "manufacturer": manufacturer,
        "pcr_digest_sha256": digest.hex(),
    }
    return True, claim


def _claim_soft_only() -> dict[str, object]:
    return {
        "hardware": "soft",
        "strength": "soft_only",
        "manufacturer": None,
    }


# Tier algorithm lives in :mod:`mcp_proxy.attestation.tier` (F2). The
# F3 verifier returns the hardware-side fields; the enrollment hook
# combines them with the MDM half and calls :func:`tier.compute_effective_tier`.
