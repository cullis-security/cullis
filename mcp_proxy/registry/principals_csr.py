"""Mastio CSR signing for user principals (ADR-021 PR4a, proxy-side).

This is the proxy-side signer. The original implementation lived on
the broker (``app/registry/principals_csr.py``) and signed with
``broker_private_key_pem`` — the broker root CA. The Court then
verifies user certs against ``organizations.ca_certificate``, the
**org** CA the proxy attached, so the broker-signed user cert
``certificate chain broken at position 0``'d on every login. The
fix is to sign with the org-CA private key, which only ever lives on
the proxy. Same module here, swapped signing source.

The Cullis Frontdesk Ambassador (PR4b) generates a keypair locally,
builds a CSR around the public key, and POSTs it here to obtain a
proxy-signed cert chained to the org CA the Court already trusts.

v0.1 scope:
  - Signs with the proxy's loaded org CA (``AgentManager._org_ca_key``).
  - TTL 1 hour, refreshed at the next SSO touch.
  - Issuer name preserved (``CN=Cullis Mastio Broker CA, O=<org>``)
    for back-compat with existing chain validators.
  - Validates the CSR's SPIFFE SAN matches the requested principal_id
    so callers cannot smuggle a CSR for a different principal.

Auth: ``Depends(get_authenticated_agent)``. RBAC: caller may only
request signing for principals in its own org.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from mcp_proxy.egress.agent_manager import AgentManager

_log = logging.getLogger("mcp_proxy.registry.principals_csr")


# Cert lifetime for user principals. Short on purpose — the Ambassador
# refreshes via a fresh signing call whenever the user's session
# rolls over. Production may shorten this further (e.g. 15min) once
# the rollover path is exercised.
USER_CERT_TTL = timedelta(hours=1)

# Allowed clock skew either direction.
CLOCK_SKEW = timedelta(minutes=5)


class CsrValidationError(ValueError):
    """Raised when the submitted CSR fails any structural check."""


def parse_principal_id_to_spiffe(principal_id: str) -> tuple[str, str]:
    """Translate ``<td>/<org>/<type>/<name>`` into the full SPIFFE URI
    + a normalised internal id.

    Returns ``(spiffe_uri, expected_org_id)``. Raises ``ValueError``
    when the path is malformed.
    """
    parts = principal_id.split("/")
    if len(parts) != 4:
        raise ValueError(
            "principal_id must have 4 path components "
            "(<trust-domain>/<org>/<principal-type>/<name>); got "
            f"{len(parts)}: {principal_id!r}",
        )
    td, org, ptype, name = parts
    if not all((td, org, ptype, name)):
        raise ValueError(
            f"principal_id contains an empty component: {principal_id!r}",
        )
    if ptype not in ("user", "agent", "workload"):
        raise ValueError(
            f"principal_id principal-type must be one of "
            f"user/agent/workload; got {ptype!r}",
        )
    spiffe_uri = f"spiffe://{td}/{org}/{ptype}/{name}"
    return spiffe_uri, org


def _extract_csr_spiffe_uri(csr: x509.CertificateSigningRequest) -> str:
    """Return the single SPIFFE URI SAN in the CSR.

    Raises ``CsrValidationError`` if the CSR has zero or multiple URI
    SANs, or if the URI is not a SPIFFE id.
    """
    try:
        san_ext = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
    except x509.ExtensionNotFound as exc:
        raise CsrValidationError(
            "CSR is missing the SubjectAlternativeName extension",
        ) from exc

    sans = san_ext.value
    uris = [u.value for u in sans if isinstance(u, x509.UniformResourceIdentifier)]
    if len(uris) == 0:
        raise CsrValidationError("CSR SAN has no URI entries")
    if len(uris) > 1:
        raise CsrValidationError(
            f"CSR SAN must have exactly one URI; got {len(uris)}",
        )
    uri = uris[0]
    if not uri.startswith("spiffe://"):
        raise CsrValidationError(
            f"CSR SAN URI must be a SPIFFE id; got {uri!r}",
        )
    return uri


def _verify_csr_signature(csr: x509.CertificateSigningRequest) -> None:
    """``x509.CertificateSigningRequest`` exposes ``is_signature_valid``
    on cryptography>=41 — we use it as the canonical check that the
    requester actually held the matching private key.
    """
    if not csr.is_signature_valid:
        raise CsrValidationError("CSR signature does not verify")


def _validate_public_key(csr: x509.CertificateSigningRequest) -> None:
    """Refuse weak keys. EC P-256/384/521 ok, RSA >= 2048 ok."""
    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            raise CsrValidationError(
                f"RSA key too small ({pub.key_size} bits); minimum 2048",
            )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        if pub.curve.key_size < 256:
            raise CsrValidationError(
                f"EC curve too small ({pub.curve.key_size} bits); minimum 256",
            )
    else:
        raise CsrValidationError(
            f"Unsupported public key type: {type(pub).__name__}",
        )


def _build_subject(principal_id: str, org_id: str) -> x509.Name:
    """ADR-020 — typed-principal certs ship as SVID-style (empty subject,
    identity in the SPIFFE SAN URI only).

    Putting the 4-component principal_id in CN/O sends the broker's
    ``x509_verifier`` down the legacy CN/O parse branch which then tries
    to coerce ``orga.test/orga/user/daniele`` into the
    ``org::agent-name`` internal format and 500s. The SPIFFE SAN we add
    later carries the full identity, and the verifier's SVID branch
    parses it cleanly via ``spiffe_to_principal`` (PR #443). Agent certs
    keep CN/O via the ``sign_external_pubkey`` path; this helper is
    user / workload only.
    """
    return x509.Name([])


def _build_issuer(org_id: str) -> x509.Name:
    """Fallback issuer name when the proxy can't read the Org CA cert.

    Real signing path uses the actual Org CA cert's subject (see
    ``sign_user_csr``) so the cert's ``Issuer`` field rfc4514-equals
    the CA's ``Subject`` and nginx ``ssl_verify_client`` walks the
    chain cleanly. This helper is only kept for the test fakes that
    construct certs without an AgentManager around.
    """
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Mastio Broker CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])


def _cert_thumbprint_sha256(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


async def sign_user_csr(
    csr_pem: str,
    principal_id: str,
    *,
    agent_manager: "AgentManager",
    ttl: timedelta = USER_CERT_TTL,
) -> tuple[str, str, datetime]:
    """Sign a user-principal CSR with the proxy's loaded Org CA.

    Returns ``(cert_pem, cert_thumbprint_sha256, cert_not_after)``.

    Raises:
        ValueError: principal_id malformed.
        CsrValidationError: CSR malformed, weak key, missing SAN,
            wrong SPIFFE URI, signature invalid.
        RuntimeError: Org CA not loaded on this proxy yet.
    """
    spiffe_expected, expected_org = parse_principal_id_to_spiffe(principal_id)

    if expected_org != agent_manager.org_id:
        raise CsrValidationError(
            f"principal_id org {expected_org!r} does not match this "
            f"proxy's org {agent_manager.org_id!r}",
        )

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise CsrValidationError(f"could not parse CSR PEM: {exc}") from exc

    _verify_csr_signature(csr)
    _validate_public_key(csr)

    spiffe_in_csr = _extract_csr_spiffe_uri(csr)
    if spiffe_in_csr != spiffe_expected:
        raise CsrValidationError(
            f"CSR SPIFFE id {spiffe_in_csr!r} does not match requested "
            f"principal_id {principal_id!r} (expected {spiffe_expected!r})",
        )

    if not agent_manager.ca_loaded:
        raise RuntimeError(
            "Org CA not loaded on this proxy — cannot sign principal CSRs",
        )
    ca_key = agent_manager._org_ca_key  # type: ignore[attr-defined]
    if ca_key is None:
        raise RuntimeError("Org CA key missing despite ca_loaded=True")
    # Use the *real* Org CA cert subject as the issuer so the resulting
    # cert chains cleanly through nginx's ``ssl_verify_client``. The
    # fallback ``_build_issuer`` would emit a synthetic
    # ``CN=Cullis Mastio Broker CA, O=<org>`` Name that does NOT match
    # the registered org_ca subject; OpenSSL then refuses the chain
    # with "unable to get issuer cert" and nginx returns the generic
    # 400 SSL certificate error page. Caught dogfooding 2026-05-06.
    ca_cert = agent_manager._org_ca_cert  # type: ignore[attr-defined]
    issuer_name = ca_cert.subject if ca_cert is not None else _build_issuer(
        expected_org,
    )

    now = datetime.now(timezone.utc)
    not_before = now - CLOCK_SKEW
    not_after = now + ttl

    cert = (
        x509.CertificateBuilder()
        .subject_name(_build_subject(principal_id, expected_org))
        .issuer_name(issuer_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_expected),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    thumbprint = _cert_thumbprint_sha256(cert)
    return cert_pem, thumbprint, not_after


__all__ = [
    "CLOCK_SKEW",
    "CsrValidationError",
    "USER_CERT_TTL",
    "parse_principal_id_to_spiffe",
    "sign_user_csr",
]
