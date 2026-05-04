"""UserPrincipalKMS abstraction — key material for human users.

Distinct from the existing ``KMSProvider`` (``app/kms/provider.py``)
which manages the broker's own CA and at-rest secret encryption.
This Protocol manages per-user key material for ADR-020 user
principals (``spiffe://<td>/<org>/user/<name>``).

Lifecycle expected by callers:

    1. ``has_principal(id)`` — if True, principal already provisioned;
       proceed straight to ``sign``.
    2. ``create_keypair(id, alg)`` — backend generates the keypair
       internally (in-process for the embedded backend, server-side
       for Vault Transit / AWS KMS / Azure KV). Returns the public
       key so the caller can build a CSR from it.
    3. Caller hands the CSR to Mastio (or any CA) for signing.
    4. ``attach_certificate(id, cert_pem)`` — backend stores the cert
       alongside the key material. The caller can now drop the cert
       from its own working memory.
    5. ``sign(id, payload)`` — backend signs ``payload`` with the
       private key. For KMS-backed implementations the key never
       leaves the KMS; for the embedded backend it is decrypted in
       process for the duration of the call.
    6. ``get_certificate(id)`` — returns the stored cert PEM (used
       for cert thumbprint pinning, x5c headers, etc.).
    7. ``revoke_principal(id)`` — marks the principal revoked; future
       ``sign`` calls raise. The row remains for audit replay.

The Protocol is deliberately narrow. There is no ``get_private_key``
method, by design — even the embedded backend is structured so
callers cannot accidentally exfiltrate private key material.

This refines the API sketched in ``imp/adr-021-shared-mode-multi-user-kms.md``
§1, which originally combined keypair generation and CSR-to-cert
into a single ``provision_principal(csr_pem)`` call. The two-step
split (``create_keypair`` then ``attach_certificate``) is cleaner
because it puts the CA dependency (Mastio) outside the KMS contract:
the KMS handles keys, Mastio handles certs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


# Algorithm identifiers accepted by ``create_keypair`` and ``sign``.
# v0.1 ships only ES256 (ECC P-256). RS256 will arrive in v0.2 if a
# customer KMS only exposes RSA.
ALG_ES256 = "ES256"
SUPPORTED_ALGS = frozenset({ALG_ES256})


class PrincipalNotFoundError(KeyError):
    """Raised when an operation references an unknown ``principal_id``."""


class PrincipalAlreadyExistsError(ValueError):
    """Raised when ``create_keypair`` is called for an existing principal.

    Re-provisioning requires an explicit ``revoke_principal`` first —
    silent overwrite would mask key-rotation bugs.
    """


class PrincipalRevokedError(PermissionError):
    """Raised when ``sign`` is invoked on a revoked principal."""


class CertificateNotAttachedError(LookupError):
    """Raised when ``get_certificate`` runs before ``attach_certificate``."""


@dataclass(frozen=True)
class ProvisioningResult:
    """Outcome of ``create_keypair``.

    Attributes:
        public_key_pem: SubjectPublicKeyInfo PEM. Caller embeds this
            in a CSR and ships it to the CA.
        key_handle: Opaque backend-specific reference (e.g.
            ``"embedded:acme/acme/user/mario"`` for the embedded
            backend, ``"vault:transit/keys/cullis-user-..."`` for
            Vault). Returned for log correlation only; callers must
            not parse it.
        alg: The algorithm identifier the backend used. Echoes back
            what the caller asked for, for paranoia.
    """

    public_key_pem: str
    key_handle: str
    alg: str


@runtime_checkable
class UserPrincipalKMS(Protocol):
    """Backend-agnostic key management for user principals."""

    async def has_principal(self, principal_id: str) -> bool:
        """Return True if this principal already has key material.

        Returns True for both active and revoked principals — use
        ``sign`` failure or a separate ``is_revoked`` check (future)
        to distinguish.
        """
        ...

    async def create_keypair(
        self,
        principal_id: str,
        *,
        alg: str = ALG_ES256,
    ) -> ProvisioningResult:
        """Generate a fresh keypair for ``principal_id``.

        Raises:
            PrincipalAlreadyExistsError: principal already provisioned.
            ValueError: ``alg`` not in ``SUPPORTED_ALGS``.
        """
        ...

    async def attach_certificate(
        self,
        principal_id: str,
        cert_pem: str,
    ) -> None:
        """Store the CA-signed cert for ``principal_id``.

        Re-attaching overrides the prior cert (cert rotation is a
        normal operation). Raises ``PrincipalNotFoundError`` if
        ``create_keypair`` has not run.
        """
        ...

    async def get_certificate(self, principal_id: str) -> str:
        """Return the stored cert PEM.

        Raises:
            PrincipalNotFoundError: no key material at all.
            CertificateNotAttachedError: keys exist but no cert yet.
        """
        ...

    async def sign(self, principal_id: str, payload: bytes) -> bytes:
        """Sign ``payload`` with the principal's private key.

        Returns raw signature bytes (DER for ECDSA, PKCS#1 v1.5 for
        RSA — alg-dependent). DPoP / JWS callers re-encode as needed.

        Raises:
            PrincipalNotFoundError
            PrincipalRevokedError
        """
        ...

    async def revoke_principal(self, principal_id: str) -> None:
        """Mark the principal revoked. Future ``sign`` raises.

        Idempotent: revoking an already-revoked principal is a no-op.
        Raises ``PrincipalNotFoundError`` if no key material exists.
        """
        ...


__all__ = [
    "ALG_ES256",
    "SUPPORTED_ALGS",
    "CertificateNotAttachedError",
    "PrincipalAlreadyExistsError",
    "PrincipalNotFoundError",
    "PrincipalRevokedError",
    "ProvisioningResult",
    "UserPrincipalKMS",
]
