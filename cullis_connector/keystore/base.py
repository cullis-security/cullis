"""Abstract :class:`KeyStore` and the on-the-wire attestation claim shape.

The claim mirrors ``imp/attestation-claim-schema.md`` sez. 1. Only the
hardware-related subset is owned by the keystore; the MDM/compliance half
is filled in by F2 (Intune polling). The Mastio enrollment endpoint merges
the two halves before persisting ``device_attestation``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

HardwareKind = Literal["tpm_2.0", "secure_enclave", "soft"]
AttestationStrength = Literal["hw_attested", "hw_isolated", "soft_only"]


class KeyStoreUnavailable(Exception):
    """Raised when a hardware backend cannot be initialised.

    Callers (notably :func:`detect_best_keystore`) catch this to fall back
    to the soft keystore. A bare ``ImportError`` from the optional
    ``tpm2-pytss`` dependency, a missing ``/dev/tpmrm0`` device node, or
    an EACCES on the TCTI socket all surface as this exception so the
    enrollment flow sees a single, semantically meaningful failure type.
    """


@dataclass(frozen=True)
class AttestationClaim:
    """Hardware-side half of the device attestation claim.

    Field names + value vocabularies match the lock in
    ``imp/attestation-claim-schema.md`` sez. 1. ``hardware`` and
    ``strength`` are required; ``manufacturer`` may be ``None`` when the
    TPM advertises a vendor outside the Phase 1 whitelist or when no EK
    cert was parsed.
    """

    hardware: HardwareKind
    strength: AttestationStrength
    manufacturer: str | None = None
    # Free-form telemetry consumed by audit (not by the schema contract).
    extras: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "hardware": self.hardware,
            "strength": self.strength,
        }
        if self.manufacturer is not None:
            out["manufacturer"] = self.manufacturer
        return out


class KeyStore(ABC):
    """DPoP / CSR key backend.

    Implementations must produce a stable public key across calls (the
    enrollment flow submits the PEM once at ``/v1/enrollment/start`` and
    later DPoP proofs must verify against it) and must guarantee that
    :meth:`sign` cannot be forged without on-device material. The soft
    backend stores a PKCS#8 PEM under ``chmod 600``; the TPM backend
    keeps the private half inside the chip and only exposes signatures.
    """

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Return a signature over ``message``.

        Signature encoding is keystore-defined but must verify against the
        algorithm implied by :meth:`public_key_pem` (ECDSA-SHA256 for the
        EC P-256 backends used in Phase 1, DER-encoded ``r,s``).
        """

    @abstractmethod
    def public_key_pem(self) -> str:
        """Return the SubjectPublicKeyInfo PEM of the stored key."""

    @abstractmethod
    def attestation_strength(self) -> AttestationStrength:
        """Return ``hw_attested`` / ``hw_isolated`` / ``soft_only``.

        ``hw_attested`` requires that the backend can produce a quote the
        server can verify (TPM AIK quote + EK chain or manufacturer match
        Phase 1). ``hw_isolated`` means the key lives in hardware but the
        attestation surface is unavailable (no EK cert, vTPM, etc).
        ``soft_only`` is the file-on-disk backend.
        """

    @abstractmethod
    def attestation_claim(self) -> AttestationClaim | None:
        """Return the hardware-side claim, or ``None`` for soft backends."""

    def generate_aik_quote(self, nonce: bytes) -> bytes | None:
        """Produce an AIK quote bound to ``nonce``.

        Default implementation returns ``None``; only hardware backends
        that own an Attestation Identity Key override this. The enrollment
        flow uses ``hasattr(self, "generate_aik_quote")``-style branching
        with the return value: ``None`` means "no quote to ship", a bytes
        blob is forwarded server-side for verification.
        """
        return None
