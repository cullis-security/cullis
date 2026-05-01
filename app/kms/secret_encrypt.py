"""
Symmetric secret encryption for at-rest values (OIDC client secrets, etc.).

Two on-wire formats coexist:

* ``enc:v1:`` (legacy) — KEK derived via HKDF-SHA256 from the broker
  CA private key PEM. Audit H8 flagged this for tying secret
  encryption to the issuing CA's private key, so a CA key rotation
  invalidates every stored secret and a CA compromise discloses every
  stored secret. Reads still work for back-compat.
* ``enc:v2:`` (new) — KEK derived via HKDF-SHA256 from a dedicated
  32-byte master key the KMS provider manages. The master key has its
  own lifecycle separate from the Org CA. Format:
  ``enc:v2:<salt_hex>:<fernet_token>``.

Both formats are Fernet-wrapped (AES-128-CBC + HMAC-SHA256). The
``is_encrypted`` helper matches either prefix; ``decrypt_secret`` only
handles the v1 path because callers without a master key can still
read legacy values; ``decrypt_secret_v2`` handles the new path.
"""
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

_ENC_PREFIX = "enc:v1:"
_ENC_PREFIX_V2 = "enc:v2:"
_HKDF_INFO = b"atn-secret-encryption-v1"
_HKDF_INFO_V2 = b"atn-secret-encryption-v2"
_SALT_LENGTH = 16


def _derive_fernet_key(private_key_pem: str, salt: bytes | None = None) -> bytes:
    """Derive a 32-byte Fernet key from the broker private key PEM via HKDF.

    Legacy v1 path. Retained so existing ``enc:v1:`` ciphertexts decrypt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO,
    )
    derived = hkdf.derive(private_key_pem.encode())
    return base64.urlsafe_b64encode(derived)


def _derive_fernet_key_v2(master_key: bytes, salt: bytes) -> bytes:
    """Derive a Fernet key from the dedicated secret-encryption master key.

    H8 audit fix: ``master_key`` is a 32-byte secret managed by the KMS
    backend, decoupled from the Org CA private key. Its compromise
    surface is limited to at-rest secrets, and rotating it does not
    require re-issuing the CA.
    """
    if len(master_key) < 16:
        raise ValueError(
            "Secret-encryption master key must be at least 16 bytes "
            "(got %d). Re-generate with `openssl rand 32`." % len(master_key),
        )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_HKDF_INFO_V2,
    )
    derived = hkdf.derive(master_key)
    return base64.urlsafe_b64encode(derived)


def encrypt_secret(private_key_pem: str, plaintext: str) -> str:
    """Encrypt with the legacy v1 KEK (CA-derived). Use ``encrypt_secret_v2``
    for new code — the v1 path is kept only for tests that still feed a PEM.
    """
    salt = os.urandom(_SALT_LENGTH)
    key = _derive_fernet_key(private_key_pem, salt=salt)
    token = Fernet(key).encrypt(plaintext.encode()).decode()
    return f"{_ENC_PREFIX}{salt.hex()}:{token}"


def encrypt_secret_v2(master_key: bytes, plaintext: str) -> str:
    """Encrypt with the dedicated secret-encryption master key (H8).

    Returns ``enc:v2:<salt_hex>:<fernet_token>``. The 16-byte salt
    randomises the per-secret KEK so two ciphertexts of the same
    plaintext don't share the same KEK.
    """
    salt = os.urandom(_SALT_LENGTH)
    key = _derive_fernet_key_v2(master_key, salt=salt)
    token = Fernet(key).encrypt(plaintext.encode()).decode()
    return f"{_ENC_PREFIX_V2}{salt.hex()}:{token}"


def decrypt_secret(private_key_pem: str, stored: str) -> str:
    """Decrypt a v1 stored secret (legacy CA-derived KEK).

    If the value does not carry the ``enc:v1:`` prefix it is assumed
    to be legacy plaintext and returned as-is (transparent migration).
    Refuses ``enc:v2:`` values — those require ``decrypt_secret_v2``.

    Supports both v1 sub-formats:
      - ``enc:v1:<salt_hex>:<fernet_token>`` (salted)
      - ``enc:v1:<fernet_token>`` (pre-salt legacy)
    """
    if stored.startswith(_ENC_PREFIX_V2):
        raise ValueError(
            "decrypt_secret() only handles enc:v1; use decrypt_secret_v2() "
            "with the secret-encryption master key for enc:v2 values",
        )
    if not stored.startswith(_ENC_PREFIX):
        return stored  # legacy plaintext — return unchanged
    payload = stored[len(_ENC_PREFIX):]

    # Detect salted vs legacy format: salted has exactly 32 hex chars then ':'
    parts = payload.split(":", 1)
    if len(parts) == 2 and len(parts[0]) == _SALT_LENGTH * 2:
        try:
            salt = bytes.fromhex(parts[0])
            token = parts[1]
            key = _derive_fernet_key(private_key_pem, salt=salt)
            return Fernet(key).decrypt(token.encode()).decode()
        except (ValueError, InvalidToken) as exc:
            raise ValueError("Failed to decrypt secret — wrong key or corrupted data") from exc
    else:
        # Legacy format: enc:v1:<fernet_token> (no salt)
        key = _derive_fernet_key(private_key_pem, salt=None)
        try:
            return Fernet(key).decrypt(payload.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("Failed to decrypt secret — wrong key or corrupted data") from exc


def decrypt_secret_v2(master_key: bytes, stored: str) -> str:
    """Decrypt an ``enc:v2:`` secret with the dedicated master key (H8).

    Refuses values without the v2 prefix so a typo doesn't silently
    feed legacy v1 ciphertexts to the wrong key.
    """
    if not stored.startswith(_ENC_PREFIX_V2):
        raise ValueError(
            "decrypt_secret_v2() requires enc:v2 input; "
            "got prefix-stripped value or legacy enc:v1",
        )
    payload = stored[len(_ENC_PREFIX_V2):]
    parts = payload.split(":", 1)
    if len(parts) != 2 or len(parts[0]) != _SALT_LENGTH * 2:
        raise ValueError("malformed enc:v2 secret — expected <salt_hex>:<fernet_token>")
    try:
        salt = bytes.fromhex(parts[0])
        token = parts[1]
        key = _derive_fernet_key_v2(master_key, salt=salt)
        return Fernet(key).decrypt(token.encode()).decode()
    except (ValueError, InvalidToken) as exc:
        raise ValueError("Failed to decrypt secret — wrong key or corrupted data") from exc


def is_encrypted(stored: str) -> bool:
    """Check if a stored value is encrypted (either v1 or v2 prefix)."""
    return stored.startswith(_ENC_PREFIX) or stored.startswith(_ENC_PREFIX_V2)
