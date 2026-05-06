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

import asyncio
import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

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
    """Legacy mTLS-only transport.

    Kept for tests + early-bring-up where the proxy still accepts
    mTLS-only on /v1/principals/csr. ADR-021 PR4a tightened the
    Court (and the proxy via reverse-proxy forwarding) to require
    DPoP-bound JWT — production deployments must use
    :class:`SdkMastioCsrTransport`.
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
        return _parse_csr_response(body)


class SdkMastioCsrTransport:
    """Production CSR transport using the cullis-sdk ``CullisClient``.

    Authenticates the Frontdesk Connector against the broker (via the
    Mastio reverse-proxy) with ``login_via_proxy_with_local_key``, the
    device-code-friendly login that keeps the agent's private key on
    the Connector and asks the Mastio to counter-sign the assertion
    before the broker mints a DPoP-bound access token. The CSR call
    then rides ``CullisClient._authed_request`` so every POST carries
    ``Authorization: DPoP <token>`` + a fresh DPoP proof — exactly what
    the Court's ADR-021 PR4a auth dependency requires.

    Why not ``login_from_pem``: that path goes through the Mastio's
    ADR-012 local issuer when ``MCP_PROXY_LOCAL_AUTH_ENABLED=true``;
    its tokens are signed by the Mastio key and the Court rejects them
    on /v1/principals/csr ("Token invalid or expired"). The
    ``login_via_proxy_with_local_key`` path always rounds through the
    Court so the token is broker-issued.

    Lazy login: the first ``sign_csr`` call triggers a login. The token
    is cached for ``RELOGIN_INTERVAL_S`` (10 min by default — below
    Mastio's 30-min default ``jwt_access_token_expire_minutes``). On a
    401 the transport invalidates the cached client and retries once.
    """

    RELOGIN_INTERVAL_S: float = 10 * 60

    def __init__(
        self,
        *,
        config_dir: Any,
        base_url: str,
        verify_tls: bool | str = True,
    ) -> None:
        self._config_dir = config_dir
        self._base_url = base_url.rstrip("/")
        self._verify_tls = verify_tls
        self._client: Any = None
        self._created_at: float = 0.0
        self._lock = threading.Lock()

    def _build(self) -> Any:
        from cullis_sdk import CullisClient
        import time

        # ``from_connector`` reads cert + key + metadata.json from
        # ``<config_dir>/identity/``; the SDK uses the metadata.site_url
        # as the broker base. We override here so the Frontdesk
        # ``CULLIS_FRONTDESK_MASTIO_URL`` (which may differ from the
        # site_url written at enrollment) wins.
        client = CullisClient.from_connector(
            self._config_dir, verify_tls=self._verify_tls,
        )
        client.base = self._base_url
        client.login_via_proxy_with_local_key()
        self._client = client
        self._created_at = time.monotonic()
        _log.info(
            "ambassador SDK login_via_proxy_with_local_key ok agent=%s site=%s",
            getattr(client, "_proxy_agent_id", "?"), self._base_url,
        )
        return client

    def _get(self) -> Any:
        import time

        with self._lock:
            now = time.monotonic()
            if (
                self._client is None
                or (now - self._created_at) > self.RELOGIN_INTERVAL_S
            ):
                self._build()
            return self._client

    def _invalidate(self) -> None:
        with self._lock:
            self._client = None
            self._created_at = 0.0

    def _post_csr_sync(self, principal_id: str, csr_pem: str) -> dict:
        client = self._get()
        resp = client._authed_request(
            "POST", "/v1/principals/csr",
            json={"principal_id": principal_id, "csr_pem": csr_pem},
        )
        if resp.status_code == 401:
            # TOCTOU: token expired between cache check and request.
            # Re-login once, retry.
            self._invalidate()
            client = self._get()
            resp = client._authed_request(
                "POST", "/v1/principals/csr",
                json={"principal_id": principal_id, "csr_pem": csr_pem},
            )
        if resp.status_code != 201:
            raise MastioCsrError(
                f"Mastio /v1/principals/csr returned {resp.status_code}: "
                f"{resp.text[:512]}",
            )
        return resp.json()

    async def sign_csr(
        self,
        *,
        principal_id: str,
        csr_pem: str,
    ) -> tuple[str, datetime]:
        try:
            body = await asyncio.to_thread(
                self._post_csr_sync, principal_id, csr_pem,
            )
        except MastioCsrError:
            raise
        except Exception as exc:
            raise MastioCsrError(
                f"transport failure calling Mastio /v1/principals/csr: {exc}",
            ) from exc
        return _parse_csr_response(body)


def _parse_csr_response(body: dict) -> tuple[str, datetime]:
    """Decode the JSON body of /v1/principals/csr into (cert_pem, not_after)."""
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
    "SdkMastioCsrTransport",
    "UserProvisioner",
]
