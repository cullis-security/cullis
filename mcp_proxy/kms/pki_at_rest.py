"""Fernet-at-rest envelope for the ``pki_key_store`` table.

Three-tier PKI hardening (audit 2026-05-18). Pre-fix the Org Root +
Mastio Intermediate private keys lived as plaintext PEM in
``proxy_config`` rows; a DB-only leak (Postgres backup, SQLite file
copy, stolen volume snapshot) handed the attacker root-of-trust
material outright. Post-fix, every private PEM in ``pki_key_store``
is wrapped in a Fernet envelope keyed off
``MCP_PROXY_DB_ENCRYPTION_KEY`` (passphrase, derived via
PBKDF2-HMAC-SHA256 600k iterations, salt ``b"cullis-mastio-pki-v1"``).

Why a separate helper from :mod:`mcp_proxy.tools.secret_encrypt`:

* That module derives its master key from
  ``MCP_PROXY_SECRET_ENCRYPTION_KEY_B64`` (urlsafe-base64 raw 32 bytes)
  or auto-generates one and persists into ``proxy_config``.
  Convenient for AI provider creds but unsafe for the root-of-trust:
  the auto-generated value lives in the same DB row we are trying to
  defend, so a DB-only leak compromises both.
* PKI hardening insists on an operator-supplied passphrase
  (``MCP_PROXY_DB_ENCRYPTION_KEY``) with no DB fallback. Production
  ``validate_config`` refuses to start without it. Dev / sandbox
  callers pass an explicit env value (``./sandbox/demo.sh`` exports a
  fixed dev passphrase so the demo keeps booting).
* PBKDF2 600k matches OWASP 2023 guidance for HMAC-SHA256 and matches
  the iteration count cullis-enterprise uses for its KMS bootstrap.

Public surface:

* :func:`derive_master_key` — PBKDF2 → 32 raw bytes → urlsafe-base64
  (the form Fernet expects).
* :func:`encrypt_pki_payload` / :func:`decrypt_pki_payload` — JSON
  bundle (`{"key_pem": ..., "cert_pem": ...}`) wrapped in the
  ``enc:pki:v1:`` envelope.
* :func:`pki_master_key_configured` — boolean predicate the lifespan
  uses to gate the Phase 0 wipe + Phase 1 store routing.

This module is sync-only — the Fernet calls are pure CPU and the
caller already holds an event loop. We avoid pulling in
``await``/``asyncio`` boilerplate so the KMS provider implementations
that wrap us can stay drop-in compatible with sync libraries
(``boto3``, ``azure-keyvault-keys`` synchronous client, etc.).
"""
from __future__ import annotations

import base64
import json
import logging
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_log = logging.getLogger("mcp_proxy.kms.pki_at_rest")

_ENV_VAR = "MCP_PROXY_DB_ENCRYPTION_KEY"
_SALT = b"cullis-mastio-pki-v1"
_ITERATIONS = 600_000
_ENVELOPE_PREFIX = "enc:pki:v1:"


class PKIKeyMissingError(RuntimeError):
    """Raised when the PKI master passphrase is required but not set.

    Production callers should treat this as fatal (refuse to start),
    dev callers may catch and fall back to a sandbox-only path with a
    loud warning. ``validate_config`` does the production gate at boot.
    """


def pki_master_key_configured() -> bool:
    """Return True when ``MCP_PROXY_DB_ENCRYPTION_KEY`` is set non-empty."""
    raw = os.environ.get(_ENV_VAR, "").strip()
    return bool(raw)


def _passphrase() -> bytes:
    raw = os.environ.get(_ENV_VAR, "").strip()
    if not raw:
        raise PKIKeyMissingError(
            f"{_ENV_VAR} is not set. The PKI at-rest envelope cannot "
            "decrypt or encrypt without it. Set it to a strong random "
            "value (e.g. ``openssl rand -hex 48``). In production "
            "validate_config refuses to start when this is missing; "
            "in dev / sandbox set the value explicitly (see "
            "sandbox/demo.sh for the canonical dev default).",
        )
    if len(raw) < 16:
        # Defensive: a 16-char minimum keeps an absent-minded operator
        # from typing ``MCP_PROXY_DB_ENCRYPTION_KEY=x`` and walking away
        # with what looks like at-rest encryption. The production gate
        # in validate_config also enforces 32+ for full strength.
        raise PKIKeyMissingError(
            f"{_ENV_VAR} must be at least 16 characters "
            f"(got {len(raw)}). Generate one with ``openssl rand -hex 48``."
        )
    return raw.encode("utf-8")


@lru_cache(maxsize=1)
def _derive_cached(passphrase: bytes) -> bytes:
    """PBKDF2 is expensive on purpose; cache the derived key per process.

    Cache keyed on the passphrase bytes so a test that monkeypatches
    the env var and then re-invokes :func:`derive_master_key` will see
    the new value. Production callers don't rotate the env mid-process,
    so the cache hit is the common path.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=_ITERATIONS,
    )
    raw = kdf.derive(passphrase)
    return base64.urlsafe_b64encode(raw)


def derive_master_key() -> bytes:
    """Derive the Fernet master key from ``MCP_PROXY_DB_ENCRYPTION_KEY``.

    Returns the urlsafe-base64 form Fernet expects. Raises
    :class:`PKIKeyMissingError` when the env var is absent or too short.
    """
    return _derive_cached(_passphrase())


def encrypt_pki_payload(*, key_pem: str, cert_pem: str) -> str:
    """Wrap a ``(key_pem, cert_pem)`` pair in the ``enc:pki:v1:`` envelope.

    Returns the prefixed envelope string ready for ``pki_key_store.
    ciphertext``. The cert PEM is bundled into the encrypted payload so
    a single decrypt round-trips both halves; the ``cert_pem`` column
    on the table holds an additional public copy for the verification-
    only path that should not require the master key.
    """
    if not key_pem or not cert_pem:
        raise ValueError("encrypt_pki_payload: both key_pem and cert_pem must be non-empty")
    master = derive_master_key()
    payload = json.dumps({"key_pem": key_pem, "cert_pem": cert_pem})
    token = Fernet(master).encrypt(payload.encode("utf-8")).decode("utf-8")
    return _ENVELOPE_PREFIX + token


def decrypt_pki_payload(envelope: str) -> tuple[str, str]:
    """Reverse of :func:`encrypt_pki_payload`. Returns ``(key_pem, cert_pem)``.

    Raises :class:`PKIKeyMissingError` when the master key is missing.
    Raises ``RuntimeError`` when the envelope was minted under a
    different master key (operator rotated ``MCP_PROXY_DB_ENCRYPTION_KEY``
    without re-encrypting) — falling back to whatever is in the
    ciphertext column as plaintext would be worse than failing loudly.
    """
    if not envelope.startswith(_ENVELOPE_PREFIX):
        raise ValueError(
            f"decrypt_pki_payload: envelope does not start with "
            f"{_ENVELOPE_PREFIX!r}; refusing to interpret as plaintext."
        )
    master = derive_master_key()
    token = envelope[len(_ENVELOPE_PREFIX):]
    try:
        decoded = Fernet(master).decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "pki_key_store row cannot be decrypted with the current "
            f"{_ENV_VAR}. Either the env var was rotated without "
            "re-encrypting the existing rows, or the DB came from a "
            "different deploy. Restore the original passphrase or "
            "re-issue PKI material from scratch.",
        ) from exc
    try:
        bundle = json.loads(decoded)
        return bundle["key_pem"], bundle["cert_pem"]
    except (ValueError, KeyError) as exc:
        raise RuntimeError(
            "pki_key_store payload is malformed (decrypted JSON missing "
            "key_pem/cert_pem). DB tampering or version skew.",
        ) from exc


def _reset_cache_for_tests() -> None:
    """Test hook: drop the PBKDF2 cache so monkeypatched env vars apply."""
    _derive_cached.cache_clear()


__all__ = [
    "PKIKeyMissingError",
    "decrypt_pki_payload",
    "derive_master_key",
    "encrypt_pki_payload",
    "pki_master_key_configured",
]
