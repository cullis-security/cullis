"""
H7 regression: SDK verify helpers reject bare SPKI, bind cert ↔ sender_agent_id,
and chain-validate against operator-pinned trust anchors when supplied.
"""
from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from cullis_sdk.crypto._cert_trust import (
    cert_binds_agent_id,
    cert_chains_to_anchor,
    load_cert_strict,
    verify_cert_for_sender,
)
from cullis_sdk.crypto.message_signer import (
    sign_message,
    sign_oneshot_envelope,
    verify_oneshot_envelope_signature,
    verify_signature,
)


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _priv_pem(priv) -> str:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _spki_pem(priv) -> str:
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _ca_pair(org_id: str = "acme") -> tuple[_x509.Certificate, "rsa.RSAPrivateKey"]:
    ca_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} Test CA"),
        _x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    ca_cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_priv.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_priv, hashes.SHA256())
    )
    return ca_cert, ca_priv


def _agent_cert(
    agent_priv,
    agent_id: str,
    org_id: str,
    issuer_priv=None,
    issuer_cert=None,
    self_signed: bool = False,
) -> _x509.Certificate:
    subject = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        _x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    if self_signed or issuer_priv is None:
        issuer_priv = agent_priv
        issuer_subject = subject
    else:
        issuer_subject = issuer_cert.subject
    now = _dt.datetime.now(_dt.timezone.utc)
    return (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_subject)
        .public_key(agent_priv.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(hours=1))
        .sign(issuer_priv, hashes.SHA256())
    )


def _pem(cert: _x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ── load_cert_strict ────────────────────────────────────────────────────


def test_load_cert_strict_rejects_bare_spki() -> None:
    priv = _ec_key()
    with pytest.raises(Exception):
        load_cert_strict(_spki_pem(priv))


def test_load_cert_strict_accepts_certificate() -> None:
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    parsed = load_cert_strict(_pem(cert))
    assert parsed.subject == cert.subject


# ── cert_binds_agent_id ─────────────────────────────────────────────────


def test_binding_cn_matches() -> None:
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    assert cert_binds_agent_id(cert, "acme::alice") is True


def test_binding_cn_mismatch_rejects() -> None:
    """Substitution attack: cert has CN=acme::alice but caller claims bob."""
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    assert cert_binds_agent_id(cert, "acme::bob") is False


# ── cert_chains_to_anchor ───────────────────────────────────────────────


def test_chain_signed_by_anchor_accepted() -> None:
    ca_cert, ca_priv = _ca_pair("acme")
    agent_priv = _ec_key()
    agent_cert = _agent_cert(
        agent_priv, "acme::alice", "acme",
        issuer_priv=ca_priv, issuer_cert=ca_cert,
    )
    assert cert_chains_to_anchor(agent_cert, [_pem(ca_cert)]) is True


def test_chain_self_signed_rejected_when_anchor_supplied() -> None:
    """Self-signed cert masquerading as agent cert: chain check rejects."""
    _, real_ca_priv = _ca_pair("acme")
    real_ca_cert, _ = _ca_pair("acme")  # different CA
    fake_priv = _ec_key()
    fake_cert = _agent_cert(fake_priv, "acme::alice", "acme", self_signed=True)
    assert cert_chains_to_anchor(fake_cert, [_pem(real_ca_cert)]) is False


def test_chain_expired_cert_rejected() -> None:
    ca_cert, ca_priv = _ca_pair("acme")
    agent_priv = _ec_key()
    subject = _x509.Name([
        _x509.NameAttribute(NameOID.COMMON_NAME, "acme::alice"),
        _x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    expired_cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_priv.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=10))
        .not_valid_after(now - _dt.timedelta(days=1))
        .sign(ca_priv, hashes.SHA256())
    )
    assert cert_chains_to_anchor(expired_cert, [_pem(ca_cert)]) is False


# ── verify_cert_for_sender (composite) ──────────────────────────────────


def test_verify_cert_for_sender_returns_cert_when_valid() -> None:
    ca_cert, ca_priv = _ca_pair("acme")
    agent_priv = _ec_key()
    agent_cert = _agent_cert(
        agent_priv, "acme::alice", "acme",
        issuer_priv=ca_priv, issuer_cert=ca_cert,
    )
    out = verify_cert_for_sender(_pem(agent_cert), "acme::alice", [_pem(ca_cert)])
    assert out is not None
    assert out.subject == agent_cert.subject


def test_verify_cert_for_sender_returns_none_on_binding_mismatch() -> None:
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    assert verify_cert_for_sender(_pem(cert), "acme::bob", None) is None


def test_verify_cert_for_sender_skips_chain_when_anchors_none() -> None:
    """Identity binding alone is enough when no anchors are supplied —
    SDK consumers without a TOFU-pinned Org CA still get cert+binding."""
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    assert verify_cert_for_sender(_pem(cert), "acme::alice", None) is not None


# ── End-to-end through verify_signature ────────────────────────────────


def test_verify_signature_rejects_spki() -> None:
    priv = _ec_key()
    sig = sign_message(_priv_pem(priv), "s1", "acme::alice", "n", 1700000000, {"x": 1})
    assert verify_signature(
        _spki_pem(priv), sig, "s1", "acme::alice", "n", 1700000000, {"x": 1},
    ) is False


def test_verify_signature_rejects_cn_mismatch() -> None:
    """Attacker holds a valid cert for acme::alice and tries to use it to
    forge a message claiming to be from acme::bob — binding check stops it."""
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    sig = sign_message(_priv_pem(priv), "s1", "acme::bob", "n", 1700000000, {"x": 1})
    assert verify_signature(
        _pem(cert), sig, "s1", "acme::bob", "n", 1700000000, {"x": 1},
    ) is False


def test_verify_signature_rejects_untrusted_chain() -> None:
    """Chain validation: a self-signed cert with the right CN is rejected
    when a real Org CA is supplied as the trust anchor."""
    real_ca_cert, _ = _ca_pair("acme")
    fake_priv = _ec_key()
    fake_cert = _agent_cert(fake_priv, "acme::alice", "acme", self_signed=True)
    sig = sign_message(_priv_pem(fake_priv), "s1", "acme::alice", "n", 1700000000, {"x": 1})
    assert verify_signature(
        _pem(fake_cert), sig, "s1", "acme::alice", "n", 1700000000, {"x": 1},
        trust_anchors_pem=[_pem(real_ca_cert)],
    ) is False


def test_verify_signature_accepts_legit_chain() -> None:
    ca_cert, ca_priv = _ca_pair("acme")
    agent_priv = _ec_key()
    agent_cert = _agent_cert(
        agent_priv, "acme::alice", "acme",
        issuer_priv=ca_priv, issuer_cert=ca_cert,
    )
    sig = sign_message(
        _priv_pem(agent_priv), "s1", "acme::alice", "n", 1700000000, {"x": 1},
    )
    assert verify_signature(
        _pem(agent_cert), sig, "s1", "acme::alice", "n", 1700000000, {"x": 1},
        trust_anchors_pem=[_pem(ca_cert)],
    ) is True


# ── End-to-end through verify_oneshot_envelope_signature ───────────────


def test_oneshot_verify_rejects_spki() -> None:
    priv = _ec_key()
    sig = sign_oneshot_envelope(
        _priv_pem(priv),
        correlation_id="c1", sender_agent_id="acme::alice",
        nonce="n", timestamp=1700000000, mode="envelope",
        reply_to=None, payload={"x": 1},
    )
    assert verify_oneshot_envelope_signature(
        _spki_pem(priv), sig,
        correlation_id="c1", sender_agent_id="acme::alice",
        nonce="n", timestamp=1700000000, mode="envelope",
        reply_to=None, payload={"x": 1},
    ) is False


def test_oneshot_verify_rejects_cn_mismatch() -> None:
    priv = _ec_key()
    cert = _agent_cert(priv, "acme::alice", "acme", self_signed=True)
    sig = sign_oneshot_envelope(
        _priv_pem(priv),
        correlation_id="c1", sender_agent_id="acme::bob",
        nonce="n", timestamp=1700000000, mode="envelope",
        reply_to=None, payload={"x": 1},
    )
    assert verify_oneshot_envelope_signature(
        _pem(cert), sig,
        correlation_id="c1", sender_agent_id="acme::bob",
        nonce="n", timestamp=1700000000, mode="envelope",
        reply_to=None, payload={"x": 1},
    ) is False
