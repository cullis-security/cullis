"""Per-user provisioning flow (ADR-021 PR4b).

Orchestrates the steps that turn a fresh SSO subject into a usable
credential the Ambassador can sign DPoP+x509 proofs with:

    1. Cache hit? → return cached ``UserCredentials``.
    2. Generate an ECC P-256 keypair in process memory.
    3. Build a CSR around the public key, with a SPIFFE SAN matching
       the principal_id (``spiffe://<td>/<org>/user/<name>``).
    4. POST the CSR to Mastio's ``/v1/principals/csr`` endpoint
       (PR4a) and get back a 1h cert.
    5. Populate the in-process ``UserCredentialCache`` so subsequent
       Ambassador requests skip the whole roundtrip.

v0.1 simplification: the keypair lives in process memory for the
TTL of the cache entry (1h, matches the cert lifetime). v0.2 will
plug the embedded KMS (PR1) and refactor ``CullisClient`` to take
a signer callable so the private key never leaves the KMS. The
cross-package boundary stays clean: this module talks to Mastio
via HTTPS only.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cullis_connector.ambassador.shared.credentials import (
    UserCredentialCache,
    UserCredentials,
)

_log = logging.getLogger("cullis_connector.ambassador.shared.provisioning")


class MastioCsrError(RuntimeError):
    """Raised when Mastio refuses to sign the CSR for any reason."""


class MastioCsrTransport(Protocol):
    """The CSR-signing surface the provisioner needs from Mastio.

    Implementations wrap an ``httpx.AsyncClient`` carrying the
    Ambassador's own DPoP-bound credentials.
    """

    async def sign_csr(
        self,
        *,
        principal_id: str,
        csr_pem: str,
    ) -> tuple[str, datetime]:
        """POST /v1/principals/csr → (cert_pem, not_after).

        Raises ``MastioCsrError`` on non-201 responses.
        """
        ...


@dataclass(frozen=True)
class HttpxMastioCsrTransport:
    """Default Mastio transport built on an ``httpx.AsyncClient``.

    The client is supplied externally so the caller controls auth
    headers (DPoP token + cert), TLS settings, and base URL. We do
    not own its lifecycle.
    """

    http: httpx.AsyncClient
    base_url: str

    async def sign_csr(
        self,
        *,
        principal_id: str,
        csr_pem: str,
    ) -> tuple[str, datetime]:
        url = f"{self.base_url.rstrip('/')}/v1/principals/csr"
        try:
            resp = await self.http.post(
                url,
                json={"principal_id": principal_id, "csr_pem": csr_pem},
            )
        except httpx.HTTPError as exc:
            raise MastioCsrError(
                f"transport failure calling Mastio /v1/principals/csr: {exc}",
            ) from exc

        if resp.status_code != 201:
            raise MastioCsrError(
                f"Mastio /v1/principals/csr returned {resp.status_code}: "
                f"{resp.text[:512]}",
            )
        body = resp.json()
        try:
            cert_pem = body["cert_pem"]
            not_after_iso = body["cert_not_after"]
        except (KeyError, TypeError) as exc:
            raise MastioCsrError(
                f"Mastio CSR response missing required fields: {body!r}",
            ) from exc
        try:
            not_after = datetime.fromisoformat(not_after_iso)
        except ValueError as exc:
            raise MastioCsrError(
                f"Mastio CSR response has invalid not_after: {not_after_iso!r}",
            ) from exc
        return cert_pem, not_after


def _generate_keypair_pem() -> tuple[str, ec.EllipticCurvePrivateKey]:
    """Build an ECC P-256 keypair. Returns (key_pem, key_object).

    The PEM is what the SDK consumes; the key object is used to
    sign the CSR locally before being discarded.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    key_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return key_pem, priv


def _build_csr_pem(
    priv: ec.EllipticCurvePrivateKey,
    *,
    principal_id: str,
    spiffe_uri: str,
) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, principal_id[:64]),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_uri),
            ]),
            critical=False,
        )
        .sign(priv, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class UserProvisioner:
    """Compose keypair + Mastio CSR + cache to obtain user credentials."""

    def __init__(
        self,
        *,
        mastio: MastioCsrTransport,
        cache: UserCredentialCache,
    ) -> None:
        self._mastio = mastio
        self._cache = cache

    async def get_or_provision(
        self,
        *,
        principal_id: str,
        sso_subject: str,
    ) -> UserCredentials:
        """Return a fresh ``UserCredentials`` for this principal.

        Cache hit → return cached. Cache miss → run the full
        provisioning chain and populate the cache.
        """
        cached = await self._cache.get(principal_id)
        if cached is not None:
            return cached
        cred = await self._provision(
            principal_id=principal_id, sso_subject=sso_subject,
        )
        await self._cache.put(cred)
        return cred

    async def _provision(
        self, *, principal_id: str, sso_subject: str,
    ) -> UserCredentials:
        spiffe_uri = f"spiffe://{principal_id}"

        key_pem, priv = _generate_keypair_pem()
        csr_pem = _build_csr_pem(
            priv, principal_id=principal_id, spiffe_uri=spiffe_uri,
        )

        cert_pem, not_after = await self._mastio.sign_csr(
            principal_id=principal_id, csr_pem=csr_pem,
        )

        cred = UserCredentials(
            principal_id=principal_id,
            cert_pem=cert_pem,
            key_pem=key_pem,
            cert_not_after=not_after,
        )
        _log.info(
            "ambassador provisioned principal=%s sso=%s not_after=%s",
            principal_id, sso_subject, not_after.isoformat(),
        )
        return cred


__all__ = [
    "HttpxMastioCsrTransport",
    "MastioCsrError",
    "MastioCsrTransport",
    "UserProvisioner",
]
