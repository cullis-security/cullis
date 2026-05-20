"""TSA client abstraction for audit chain anchoring (issue #75 Slice 2).

Two backends:

- `MockTsaClient` — default; produces a deterministic token that embeds
  the digest + current broker time. Useful for dev, CI, and demo. NOT
  dispute-grade: a dispute verifier who only trusts a real RFC 3161 TSA
  must reject these anchors.
- `Rfc3161TsaClient` — production; round-trips a TimeStampReq to a real
  RFC 3161 TSA (DigiCert, SwissSign, own TSA). Requires the optional
  `rfc3161-client` runtime dependency — import is lazy so the broker
  keeps booting on a minimal install.

`get_tsa_client(settings)` is the factory used by the worker; tests
inject a mock directly.

Audit F-A-405 (2026-05-20): the production `verify` path delegates to
`app.audit.tsa_verify.verify_rfc3161_token` which performs full CMS
signature verification + cert chain walk to a trust anchor + EKU check
+ genTime skew bound. Before this rewrite, `verify` only compared the
``message_imprint`` field against the row hash, which any holder of the
hash could forge.
"""
from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import NamedTuple

from app.audit.tsa_verify import TsaVerifyDependencyError, verify_rfc3161_token

_log = logging.getLogger("audit.tsa")

# Anchor tokens have a 2-byte magic prefix so a verifier can reject
# unknown formats fast instead of feeding garbage to an ASN.1 parser.
_MOCK_MAGIC = b"MK"
_RFC3161_MAGIC = b"T1"  # we wrap the raw DER TimeStampToken so the
                        # verifier always sees a framed payload


class TimestampedAnchor(NamedTuple):
    """Result of a timestamp operation.

    `token` is opaque bytes the backend understands for later verify.
    `tsa_url` is recorded for auditability (which authority signed).
    `created_at` is the broker-side wall clock; the authoritative time
    is inside the token itself, but recording local time helps detect
    clock skew on verify.
    `cert_chain_pem` is the PEM-encoded signing cert (+ any intermediates
    bundled in the TSA response). Persisted alongside the token so an
    offline dispute verifier can walk the chain without re-fetching from
    the TSA. ``None`` for the mock backend.
    """
    token: bytes
    tsa_url: str
    created_at: datetime
    cert_chain_pem: str | None = None


class TsaClient(ABC):
    """Protocol for TSA backends."""

    @abstractmethod
    async def timestamp(self, digest_hex: str) -> TimestampedAnchor:
        """Return a TimestampedAnchor for the given sha256 hex digest."""

    @abstractmethod
    def verify(
        self,
        token: bytes,
        digest_hex: str,
        *,
        cert_chain_pem: str | None = None,
        created_at: datetime | None = None,
    ) -> bool:
        """Return True if the token was issued for this digest. The
        verify is *cryptographic*, not network — the CLI uses it in
        offline mode on exported bundles."""


class MockTsaClient(TsaClient):
    """Deterministic backend for dev/CI/demo.

    Token layout (bytes):
      _MOCK_MAGIC (2) || "|" || digest_hex (64) || "|" || created_iso

    Verify simply re-encodes the digest and checks the prefix. There is
    NO cryptographic signing here — the mock is trust-equivalent to the
    broker database itself. Anyone serious about disputes must use the
    rfc3161 backend.
    """

    def __init__(self, url: str = "mock://broker-internal-tsa") -> None:
        self.url = url

    async def timestamp(self, digest_hex: str) -> TimestampedAnchor:
        now = datetime.now(timezone.utc)
        payload = f"|{digest_hex}|{now.isoformat()}".encode("utf-8")
        token = _MOCK_MAGIC + payload
        return TimestampedAnchor(
            token=token,
            tsa_url=self.url,
            created_at=now,
            cert_chain_pem=None,
        )

    def verify(
        self,
        token: bytes,
        digest_hex: str,
        *,
        cert_chain_pem: str | None = None,
        created_at: datetime | None = None,
    ) -> bool:
        if not token.startswith(_MOCK_MAGIC + b"|"):
            return False
        try:
            # strip magic + leading "|", split "digest|iso"
            remainder = token[len(_MOCK_MAGIC) + 1:].decode("utf-8")
        except UnicodeDecodeError:
            return False
        parts = remainder.split("|", 1)
        if len(parts) != 2:
            return False
        token_digest, _iso = parts
        return token_digest == digest_hex


class Rfc3161TsaClient(TsaClient):
    """RFC 3161 Time-Stamp Protocol client using `rfc3161-client`.

    The dep is imported lazily so a broker image without rfc3161-client
    can still boot (and default to the mock backend). An operator who
    sets AUDIT_TSA_BACKEND=rfc3161 without installing the lib will get
    a clear error at first timestamp() / verify() call — preferable to
    failing at startup because the worker is not in the boot-critical
    path.

    Audit F-A-405 wired ``trust_anchor_pem`` + ``max_clock_skew_seconds``
    so an offline verifier can establish a real cert chain. Without a
    trust anchor configured, ``verify`` refuses to declare a token
    valid (returns False with a WARNING log) — silent True on
    "imprint matches" was the pre-2026-05-20 forgery surface.
    """

    def __init__(
        self,
        url: str,
        *,
        trust_anchor_pem: bytes | None = None,
        max_clock_skew_seconds: int = 86400,
    ) -> None:
        self.url = url
        self._trust_anchor_pem = trust_anchor_pem
        self._max_clock_skew_seconds = max_clock_skew_seconds

    async def timestamp(self, digest_hex: str) -> TimestampedAnchor:
        # Lazy import — see class docstring.
        try:
            from rfc3161_client import (  # type: ignore[import-not-found]
                TimestampRequestBuilder,
                decode_timestamp_response,
            )
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "rfc3161-client + httpx required for AUDIT_TSA_BACKEND=rfc3161 — "
                "install with `pip install rfc3161-client httpx`"
            ) from exc

        digest = bytes.fromhex(digest_hex)
        # cert_req=True asks the TSA to embed the signing certificate
        # (+ any intermediates) into the response so an offline verifier
        # has a chain to walk without re-contacting the TSA. Without
        # this flag the TST has no ``certificates`` field and
        # verify_rfc3161_token returns False (audit F-A-405).
        builder = (
            TimestampRequestBuilder()
            .data(digest)  # builder hashes if we pass raw; we already have digest
            .nonce(True)
        )
        if hasattr(builder, "cert_req"):
            builder = builder.cert_req(True)
        req = builder.build()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                self.url,
                content=req.as_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
            )
            resp.raise_for_status()
        tsa_resp = decode_timestamp_response(resp.content)
        token_bytes = tsa_resp.time_stamp_token
        now = datetime.now(timezone.utc)
        cert_chain_pem = _extract_cert_chain_pem(token_bytes)
        return TimestampedAnchor(
            token=_RFC3161_MAGIC + b"|" + token_bytes,
            tsa_url=self.url,
            created_at=now,
            cert_chain_pem=cert_chain_pem,
        )

    def verify(
        self,
        token: bytes,
        digest_hex: str,
        *,
        cert_chain_pem: str | None = None,
        created_at: datetime | None = None,
    ) -> bool:
        if not token.startswith(_RFC3161_MAGIC + b"|"):
            return False
        raw = token[len(_RFC3161_MAGIC) + 1:]
        try:
            return verify_rfc3161_token(
                raw,
                expected_digest_hex=digest_hex,
                trust_anchor_pem=self._trust_anchor_pem,
                max_clock_skew_seconds=self._max_clock_skew_seconds,
                expected_created_at=created_at,
            )
        except TsaVerifyDependencyError:
            # The optional crypto deps are missing AND the operator
            # configured AUDIT_TSA_BACKEND=rfc3161. Silent False here
            # would let a dispute verifier swallow the missing-lib
            # signal and return "anchor invalid" — operationally
            # identical to a real forgery. Re-raise so the caller (CLI,
            # admin endpoint, test) sees the dependency problem
            # directly. Audit F-A-405 recommendation 4.
            raise


def _extract_cert_chain_pem(token_der: bytes) -> str | None:
    """Pull the signing cert (+ embedded intermediates) out of a raw
    DER TimeStampToken and return them as a concatenated PEM bundle.

    Returns ``None`` if asn1crypto isn't installed or the token has no
    ``certificates`` field (the TSA was not asked for cert_req=True or
    chose not to honour it).
    """
    try:
        from asn1crypto import tsp  # type: ignore[import-not-found]
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
    except ImportError:
        return None
    try:
        token = tsp.TimeStampToken.load(token_der)
        signed_data = token["content"]
        if "certificates" not in signed_data:
            return None
        certs_field = signed_data["certificates"]
        if certs_field is None:
            return None
        pems: list[str] = []
        for cert_choice in certs_field:
            if cert_choice.name != "certificate":
                continue
            der = cert_choice.chosen.dump()
            cert = x509.load_der_x509_certificate(der)
            pems.append(cert.public_bytes(Encoding.PEM).decode("ascii"))
        if not pems:
            return None
        return "".join(pems)
    except Exception as exc:  # noqa: BLE001 — best-effort extract
        _log.warning("failed to extract cert chain from TSA response: %s", exc)
        return None


def get_tsa_client(settings) -> TsaClient:
    """Factory: pick backend from settings.

    Unknown values fall back to MockTsaClient with a warning so a
    typo'd env var doesn't crash the worker.
    """
    backend = (getattr(settings, "audit_tsa_backend", "mock") or "mock").lower()
    url = getattr(settings, "audit_tsa_url", "") or "mock://broker-internal-tsa"
    if backend == "rfc3161":
        trust_anchor_pem: bytes | None = None
        anchor_path = getattr(settings, "audit_tsa_trust_anchor_path", "") or ""
        if anchor_path:
            try:
                with open(anchor_path, "rb") as f:
                    trust_anchor_pem = f.read()
            except OSError as exc:
                _log.warning(
                    "audit_tsa_trust_anchor_path=%r could not be read: %s",
                    anchor_path,
                    exc,
                )
        max_skew = int(getattr(settings, "audit_tsa_max_clock_skew_seconds", 86400))
        return Rfc3161TsaClient(
            url=url,
            trust_anchor_pem=trust_anchor_pem,
            max_clock_skew_seconds=max_skew,
        )
    if backend != "mock":
        _log.warning("unknown audit_tsa_backend=%r, falling back to mock", backend)
    return MockTsaClient(url=url)


def digest_hex_from_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
