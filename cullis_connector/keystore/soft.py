"""Soft (file-on-disk) :class:`KeyStore`; existing default.

Wraps an in-memory ``cryptography`` EC P-256 private key so the enrollment
flow can treat soft and TPM backends uniformly. No attestation claim is
emitted: the server resolves ``effective_tier`` to ``untrusted`` /
``byod_isolated`` depending on what the rest of the envelope ships.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from cullis_connector.identity.keypair import (
    generate_keypair,
    public_key_to_pem,
)
from cullis_connector.keystore.base import (
    AttestationClaim,
    AttestationStrength,
    KeyStore,
)


class SoftKeyStore(KeyStore):
    """In-process EC P-256 key, optionally persisted to a PKCS#8 PEM file.

    Three modes:

    * ``private_key_path`` is ``None`` → generate ephemeral key (tests, dev)
    * ``private_key_path`` exists       → load from disk
    * ``private_key_path`` missing      → generate and persist (chmod 600)
    """

    def __init__(
        self,
        *,
        private_key_path: Path | str | None = None,
        private_key: PrivateKeyTypes | None = None,
    ) -> None:
        if private_key is not None:
            self._key = private_key
            self._path: Path | None = (
                Path(private_key_path) if private_key_path else None
            )
            return

        if private_key_path is None:
            self._key = generate_keypair()
            self._path = None
            return

        path = Path(private_key_path)
        self._path = path
        if path.exists():
            self._key = serialization.load_pem_private_key(
                path.read_bytes(), password=None,
            )
            return

        self._key = generate_keypair()
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        try:
            path.chmod(0o600)
        except OSError:
            # Best-effort; POSIX-only, Windows is out of scope for Phase 1.
            pass

    # ── KeyStore interface ───────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            return self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        raise NotImplementedError(
            f"SoftKeyStore.sign does not support {type(self._key).__name__}"
            "; Phase 1 uses EC P-256 only",
        )

    def public_key_pem(self) -> str:
        return public_key_to_pem(self._key.public_key()).decode()

    def attestation_strength(self) -> AttestationStrength:
        return "soft_only"

    def attestation_claim(self) -> AttestationClaim | None:
        return None

    # ── Soft-only helpers (used by tests + legacy callers) ──────────────

    @property
    def private_key(self) -> PrivateKeyTypes:
        """Escape hatch for code paths that still need the raw key.

        New code should use :meth:`sign` instead so it stays portable to
        the TPM backend. Kept available because the enrollment + DPoP key
        material currently lives in two separate stores (cert key vs DPoP
        JWK) and refactoring both is out of scope for F3 Phase 1.
        """
        return self._key
