"""Wave 3 U4 — bidirectional mTLS verification on Mastio→Court calls.

Layer on top of the existing JWT counter-signature (ADR-009): when the
calling Mastio also presents a TLS client certificate during the handshake,
verify that the certificate's public key matches the org's pinned
``mastio_pubkey``. Today the JWT counter-sig alone proves possession of
the org's signing key, but a leaked countersig (replayed from an audit
log, for instance) would still authorize the request. With mTLS bound to
the same key, an attacker would need both the leaked sig AND a TLS
session terminated with that key — a strict superset of the assumption.

Phase 1 (this PR) — verify-if-present:
  * If the connection terminates at Court with a peer cert, extract it.
  * If a peer cert is present, its SubjectPublicKeyInfo MUST match the
    pinned ``mastio_pubkey``; mismatch raises 403.
  * If no peer cert is present, this is a no-op (legacy path) — the
    JWT countersig remains the sole proof.
  * Future Phase 2 will add a per-org ``require_mtls`` flag that flips
    "missing cert" from "no-op" to "403". Deploy/nginx config for cert
    pass-through is also Phase 2.

Cert extraction sources (tried in order):
  1. ``request.scope["transport"]`` — uvicorn termination with
     ``ssl_cert_reqs=ssl.CERT_OPTIONAL``. Returns the peercert dict via
     the asyncio transport. Used by the sandbox/demo Court.
  2. Header ``X-Cullis-Mastio-Cert`` — nginx pass-through (Phase 2).
     Format: URL-encoded PEM (``$ssl_client_escaped_cert``). Trusted only
     because the front layer is the deployment boundary.

The two paths converge on a parsed ``x509.Certificate`` so the verify
function doesn't care which path produced it.
"""
from __future__ import annotations

import logging
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Request, status

_log = logging.getLogger("app.auth.mastio_mtls")

PASS_THROUGH_HEADER = "X-Cullis-Mastio-Cert"


def extract_mastio_cert(request: Request) -> x509.Certificate | None:
    """Return the peer cert from the TLS handshake if available, else None.

    Tries the uvicorn ASGI transport first, then the nginx pass-through
    header. Logs at debug if neither path produced a cert; logs at warning
    if a path produced bytes that didn't parse as a certificate (operator
    misconfiguration is more likely than active attack at this layer, but
    we still refuse the cert rather than ignoring silently).
    """
    # Path 1: uvicorn ssl_cert_reqs=optional → peercert in transport.
    transport = request.scope.get("transport")
    if transport is not None:
        peercert_der = None
        try:
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj is not None:
                peercert_der = ssl_obj.getpeercert(binary_form=True)
        except Exception as exc:  # pragma: no cover — defensive
            _log.debug("mastio mTLS: transport.get_extra_info failed: %s", exc)
        if peercert_der:
            try:
                return x509.load_der_x509_certificate(peercert_der)
            except ValueError as exc:
                _log.warning(
                    "mastio mTLS: peer cert from transport is not parseable: %s",
                    exc,
                )
                return None

    # Path 2: nginx pass-through header (Phase 2 wiring).
    header_val = request.headers.get(PASS_THROUGH_HEADER)
    if header_val:
        # nginx ssl_client_escaped_cert → URL-encoded PEM with newlines as %0A
        pem = unquote(header_val).strip()
        if pem.startswith("-----BEGIN CERTIFICATE-----"):
            try:
                return x509.load_pem_x509_certificate(pem.encode())
            except ValueError as exc:
                _log.warning(
                    "mastio mTLS: header cert is not parseable: %s", exc,
                )
                return None
        else:
            _log.warning(
                "mastio mTLS: %s present but not PEM (got %d chars)",
                PASS_THROUGH_HEADER, len(pem),
            )
            return None

    return None


def verify_mastio_cert_pubkey(
    cert: x509.Certificate,
    mastio_pubkey_pem: str,
) -> None:
    """Raise 403 unless ``cert``'s SubjectPublicKeyInfo matches the pinned PEM.

    The comparison is byte-equality on the SubjectPublicKeyInfo DER form,
    which is what ``mastio_pubkey`` already stores (loaded as PEM, but the
    underlying key bytes are stable across PEM/DER round-trips).
    """
    try:
        pinned = serialization.load_pem_public_key(mastio_pubkey_pem.encode())
    except Exception as exc:
        # Onboarding validates the PEM before pinning, so a malformed
        # column at this point means operator tampering. Fail closed.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="pinned mastio_pubkey is unreadable",
        ) from exc

    pinned_der = pinned.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if pinned_der != cert_der:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "mastio mTLS: peer cert public key does not match the "
                "pinned organizations.mastio_pubkey"
            ),
        )


def enforce_if_present(request: Request, mastio_pubkey_pem: str) -> bool:
    """Phase 1 helper: verify cert if present, no-op if absent.

    Returns True if a cert was presented and verified, False if no cert
    was presented (legacy path). Raises 403 on mismatch.
    """
    cert = extract_mastio_cert(request)
    if cert is None:
        return False
    verify_mastio_cert_pubkey(cert, mastio_pubkey_pem)
    return True
