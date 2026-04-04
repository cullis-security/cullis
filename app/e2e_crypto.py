"""
End-to-end encryption for inter-agent messages.

Schema:
  sender:    sign(plaintext) -> encrypt({payload, inner_sig}) with recipient pubkey -> sign(ciphertext)
  broker:    verify outer signature on ciphertext (transport integrity), forward opaque blob
  recipient: decrypt -> verify inner signature on plaintext (non-repudiation)
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_for_agent(
    recipient_pubkey_pem: str,
    plaintext_dict: dict,
    inner_signature: str,
    session_id: str,
    sender_agent_id: str,
) -> dict:
    """
    Cifra payload e firma interna con la chiave pubblica del destinatario.

    Schema ibrido: AES-256-GCM per i dati, RSA-OAEP-SHA256 per la chiave AES.
    L'AAD (Additional Authenticated Data) lega il ciphertext al contesto di sessione,
    impedendo che un blob cifrato valido venga reindirizzato a un'altra sessione o mittente.

    Ritorna: {ciphertext: base64, encrypted_key: base64, iv: base64}
    Il tag GCM è incluso nel ciphertext (ultimi 16 byte).
    """
    pubkey = serialization.load_pem_public_key(recipient_pubkey_pem.encode())

    plaintext = json.dumps(
        {"payload": plaintext_dict, "inner_signature": inner_signature},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    aad = f"{session_id}|{sender_agent_id}".encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)  # include GCM tag (16 byte)

    encrypted_key = pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
        "encrypted_key": base64.urlsafe_b64encode(encrypted_key).decode(),
        "iv": base64.urlsafe_b64encode(iv).decode(),
    }


def decrypt_from_agent(
    recipient_privkey_pem: str,
    cipher_blob: dict,
    session_id: str,
    sender_agent_id: str,
) -> tuple[dict, str]:
    """
    Decifra un blob cifrato. Ritorna (payload_dict, inner_signature).

    session_id e sender_agent_id devono corrispondere a quelli usati in encrypt_for_agent:
    vengono usati come AAD per verificare l'integrità del contesto di sessione.

    Raises:
        KeyError: se cipher_blob non ha i campi attesi
        ValueError: se la decifrazione fallisce (chiave sbagliata, blob corrotto o AAD mismatch)
    """
    privkey = serialization.load_pem_private_key(
        recipient_privkey_pem.encode(), password=None
    )

    encrypted_key = base64.urlsafe_b64decode(cipher_blob["encrypted_key"])
    iv = base64.urlsafe_b64decode(cipher_blob["iv"])
    ciphertext = base64.urlsafe_b64decode(cipher_blob["ciphertext"])

    aes_key = privkey.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    aad = f"{session_id}|{sender_agent_id}".encode()
    plaintext = aesgcm.decrypt(iv, ciphertext, aad)
    data = json.loads(plaintext)

    return data["payload"], data["inner_signature"]


def verify_inner_signature(
    sender_cert_pem: str,
    inner_signature_b64: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
) -> bool:
    """
    Verify the inner (plaintext) signature after E2E decryption.

    This provides non-repudiation: the recipient can prove the sender
    signed the plaintext, not just the ciphertext. Returns True if valid,
    raises ValueError if invalid.
    """
    import base64
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding as asym_pad

    cert = crypto_x509.load_pem_x509_certificate(sender_cert_pem.encode())
    pub_key = cert.public_key()
    sig = base64.urlsafe_b64decode(inner_signature_b64)

    # Canonical format must match sign_message() in message_signer.py
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")

    pss_padding = asym_pad.PSS(
        mgf=asym_pad.MGF1(hashes.SHA256()),
        salt_length=asym_pad.PSS.MAX_LENGTH,
    )
    try:
        pub_key.verify(sig, canonical, pss_padding, hashes.SHA256())
        return True
    except InvalidSignature:
        raise ValueError("Inner signature verification failed — message may have been tampered with")
