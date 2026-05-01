"""
Cert-side trust helpers shared by message_signer and e2e verifiers.

H7 closed three gaps in the SDK verify path:

1. ``verify_signature`` and ``verify_oneshot_envelope_signature`` used to
   accept a bare SPKI public key when the PEM had no ``CERTIFICATE``
   marker. A bare SPKI carries no identity, so an attacker who could
   substitute the public key for one they control would forge messages
   without any identity binding catching it. The new entry points
   refuse anything that isn't a full X.509 cert.

2. The verifying key was never bound to ``sender_agent_id``: a valid
   signature from any cert was accepted as proof the claimed agent
   sent the message. The cert subject — CN (classic mode) or a SPIFFE
   URI SAN (SPIRE mode) — now has to match the claimed sender.

3. Chain validation is now optional via ``trust_anchors_pem``: when
   the caller supplies the Org CA bundle (e.g. via the operator-pinned
   TOFU path on ``CullisClient``), the leaf cert must chain to one of
   the anchors. Without anchors the verifier still does (1) + (2),
   which is enough to stop the substitution attacks the audit
   flagged; chain validation upgrades it to "the issuing CA is the
   one we trust".
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as ec_alg
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_alg
from cryptography.x509.oid import NameOID


class CertTrustError(ValueError):
    """Raised when a cert cannot be loaded, bound, or chained."""


def load_cert_strict(cert_pem: str) -> crypto_x509.Certificate:
    """Load a PEM-encoded X.509 certificate.

    Rejects bare SPKI public keys (the silent-fallback the audit
    flagged): the cert subject is what binds the verifying key to a
    sender_agent_id, and a bare SPKI has none.
    """
    if cert_pem is None:
        raise CertTrustError("cert_pem is None")
    pem_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    if b"-----BEGIN CERTIFICATE-----" not in pem_bytes:
        raise CertTrustError(
            "expected an X.509 CERTIFICATE PEM; bare SPKI public keys "
            "are no longer accepted (H7 audit fix)",
        )
    try:
        return crypto_x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:
        raise CertTrustError(f"could not parse certificate PEM: {exc}") from exc


def cert_binds_agent_id(cert: crypto_x509.Certificate, expected_agent_id: str) -> bool:
    """Return True iff the cert subject identifies ``expected_agent_id``.

    Matching rules mirror ``app/auth/x509_verifier.py``:

    * Classic mode — cert has CN: the CN must equal the full
      ``{org}::{name}`` agent_id.
    * SPIRE mode — cert has no CN, identity in a SPIFFE URI SAN: the
      path tail (last segment after ``/``) must equal the agent's
      short name (``expected_agent_id`` after the ``::`` split).
    """
    if not expected_agent_id:
        return False
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        return cn_attrs[0].value == expected_agent_id
    try:
        san_ext = cert.extensions.get_extension_for_class(
            crypto_x509.SubjectAlternativeName,
        )
    except crypto_x509.ExtensionNotFound:
        return False
    uris = san_ext.value.get_values_for_type(crypto_x509.UniformResourceIdentifier)
    expected_tail = expected_agent_id.split("::", 1)[-1]
    for uri in uris:
        if not uri.startswith("spiffe://"):
            continue
        tail = uri.rsplit("/", 1)[-1]
        if tail == expected_tail:
            return True
    return False


def _load_anchors(trust_anchors_pem: Sequence[str]) -> list[crypto_x509.Certificate]:
    anchors: list[crypto_x509.Certificate] = []
    for pem in trust_anchors_pem:
        if not pem:
            continue
        pem_bytes = pem.encode() if isinstance(pem, str) else pem
        try:
            anchors.extend(crypto_x509.load_pem_x509_certificates(pem_bytes))
        except Exception:
            continue
    return anchors


def cert_chains_to_anchor(
    leaf: crypto_x509.Certificate,
    trust_anchors_pem: Sequence[str],
    *,
    now: datetime | None = None,
) -> bool:
    """Return True iff ``leaf`` is signed by one of the anchors and not expired.

    Single-level chain check (leaf → Org CA). Cullis agent certs are
    issued directly by the Org CA, no intermediates, so this matches
    the deployment topology. Expanding to multi-level chains would
    require ``cryptography.x509.verification.PolicyBuilder`` (>=42),
    which we can adopt when the SDK's lower bound moves up.
    """
    anchors = _load_anchors(trust_anchors_pem)
    if not anchors:
        return False

    when = now if now is not None else datetime.now(timezone.utc)
    if leaf.not_valid_before_utc > when or leaf.not_valid_after_utc < when:
        return False

    leaf_tbs = leaf.tbs_certificate_bytes
    leaf_sig = leaf.signature
    leaf_alg = leaf.signature_hash_algorithm
    if leaf_alg is None:
        return False

    for anchor in anchors:
        if anchor.subject != leaf.issuer:
            continue
        if anchor.not_valid_before_utc > when or anchor.not_valid_after_utc < when:
            continue
        anchor_pub = anchor.public_key()
        try:
            if isinstance(anchor_pub, rsa_alg.RSAPublicKey):
                anchor_pub.verify(leaf_sig, leaf_tbs, asym_padding.PKCS1v15(), leaf_alg)
            elif isinstance(anchor_pub, ec_alg.EllipticCurvePublicKey):
                anchor_pub.verify(leaf_sig, leaf_tbs, ec_alg.ECDSA(leaf_alg))
            else:
                continue
            return True
        except InvalidSignature:
            continue
        except Exception:
            continue
    return False


def verify_cert_for_sender(
    cert_pem: str,
    sender_agent_id: str,
    trust_anchors_pem: Sequence[str] | None = None,
) -> crypto_x509.Certificate | None:
    """One-shot helper: parse cert, verify it binds ``sender_agent_id``,
    optionally verify it chains to a trust anchor.

    Returns the parsed cert when every check passes, ``None`` otherwise.
    Callers use the returned cert's public key to verify the signature
    so the binding result stays welded to the same cert object.
    """
    try:
        cert = load_cert_strict(cert_pem)
    except CertTrustError:
        return None
    if not cert_binds_agent_id(cert, sender_agent_id):
        return None
    if trust_anchors_pem is not None:
        if not cert_chains_to_anchor(cert, trust_anchors_pem):
            return None
    return cert


__all__ = [
    "CertTrustError",
    "cert_binds_agent_id",
    "cert_chains_to_anchor",
    "load_cert_strict",
    "verify_cert_for_sender",
]


# Public verification helpers (hashes + asym primitives) re-exported so
# verify_signature implementations stay DRY.
PSS_PADDING = asym_padding.PSS(
    mgf=asym_padding.MGF1(hashes.SHA256()),
    salt_length=asym_padding.PSS.MAX_LENGTH,
)
SHA256 = hashes.SHA256
ECDSA = ec_alg.ECDSA
RSAPublicKey = rsa_alg.RSAPublicKey
ECPublicKey = ec_alg.EllipticCurvePublicKey
