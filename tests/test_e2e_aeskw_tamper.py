"""
H6 regression: ECDH key wrap is AES-KW (RFC 3394), not malleable XOR.

The pre-fix scheme XOR'd the AES data key with an HKDF-derived key per
message. Single-bit tampering of ``encrypted_key`` produced a different
AES key on the recipient side and the outer AES-GCM tag rejected the
ciphertext, so end-to-end confidentiality was preserved by accident, but
the wrap step itself had no integrity. AES-KW provides authenticated
key wrap and rejects tampering during unwrap with ``InvalidUnwrap``.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from app.e2e_crypto import decrypt_from_agent, encrypt_for_agent


def _ec_keypair() -> tuple[str, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def test_ecdh_wrapped_key_is_40_bytes() -> None:
    _, pub_pem = _ec_keypair()
    blob = encrypt_for_agent(
        pub_pem, {"hello": "world"}, "inner-sig", "sess", "orgA::sender",
    )
    assert "ephemeral_pubkey" in blob, "EC wrap must include ephemeral pubkey"
    wrapped = base64.urlsafe_b64decode(blob["encrypted_key"] + "==")
    assert len(wrapped) == 40, (
        "AES-KW wrap of a 32-byte key must be 40 bytes (RFC 3394). "
        "32 bytes would mean XOR wrap is back."
    )


def test_ecdh_tampered_wrapped_key_raises_invalid_unwrap() -> None:
    priv_pem, pub_pem = _ec_keypair()
    blob = encrypt_for_agent(
        pub_pem, {"x": 1}, "inner-sig", "sess", "orgA::sender",
    )
    # Flip one bit of the wrapped key.
    raw = bytearray(base64.urlsafe_b64decode(blob["encrypted_key"] + "=="))
    raw[0] ^= 0x01
    blob["encrypted_key"] = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    with pytest.raises(InvalidUnwrap):
        decrypt_from_agent(priv_pem, blob, "sess", "orgA::sender")


def test_ecdh_roundtrip_preserves_payload() -> None:
    priv_pem, pub_pem = _ec_keypair()
    payload = {"order_id": 42, "items": ["a", "b"]}
    blob = encrypt_for_agent(
        pub_pem, payload, "inner-sig", "sess-roundtrip", "orgA::sender",
        client_seq=7,
    )
    decoded, sig = decrypt_from_agent(
        priv_pem, blob, "sess-roundtrip", "orgA::sender", client_seq=7,
    )
    assert decoded == payload
    assert sig == "inner-sig"
