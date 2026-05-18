"""``LocalKMSProvider`` — Org Root + Mastio Intermediate persisted in
``pki_key_store`` with Fernet at-rest encryption.

Pre-three-tier-hardening this provider wrote plaintext PEMs into
``proxy_config.org_ca_key`` / ``proxy_config.org_ca_cert``, and the
Mastio Intermediate bypassed the provider entirely (direct
``set_config`` from ``agent_manager``). Post-fix:

* Org Root keypair → ``pki_key_store`` row with ``key_type='org_ca'``,
  ciphertext column wraps the PEM in :mod:`mcp_proxy.kms.pki_at_rest`.
* Mastio Intermediate keypair → ``pki_key_store`` row with
  ``key_type='intermediate_ca'``, same envelope.
* Public cert PEMs are also stored unwrapped on each row so the CA
  bundle / chain endpoint can serve them without touching the master
  key (cert PEMs are public material — leaking them is not a risk).

The provider stays sync at the boundary: the underlying DB helpers are
async (``insert_pki_key``, ``activate_staged_pki_and_deprecate_old``,
etc.) and the Fernet calls are sync; we glue them with ``await`` in
the provider methods. The KMSProvider protocol is async-typed so
plugin implementations can do whatever they need (cloud KMS round-
trips, ``boto3`` over ``asyncio.to_thread``, etc.).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from mcp_proxy.db import (
    activate_staged_pki_and_deprecate_old,
    get_active_pki_key,
    get_config,
    insert_pki_key,
    set_config,
)
from mcp_proxy.kms.pki_at_rest import (
    decrypt_pki_payload,
    encrypt_pki_payload,
    pki_master_key_configured,
)

_log = logging.getLogger("mcp_proxy.kms.local")

_ORG_CA = "org_ca"
_INTERMEDIATE_CA = "intermediate_ca"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_key_id(cert_pem: str, prefix: str) -> str:
    """Derive a stable key_id from the cert public key.

    Mirrors :meth:`AgentManager.derive_org_id_from_ca` for Org CA so the
    same id stays consistent across the Mastio lifecycle. For
    Intermediate we prefix with ``intermediate-`` to keep the namespace
    obvious in ``pki_key_store``.
    """
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    pubkey_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(pubkey_der).hexdigest()[:16]
    return f"{prefix}-{fp}" if prefix else fp


class LocalKMSProvider:
    """Default Mastio KMS provider, ``pki_key_store`` + Fernet at-rest."""

    name = "local"

    async def load_org_ca(self) -> tuple[str, str] | None:
        return await self._load(
            _ORG_CA,
            legacy_key="org_ca_key",
            legacy_cert="org_ca_cert",
        )

    async def store_org_ca(self, key_pem: str, cert_pem: str) -> None:
        await self._store(
            _ORG_CA, key_pem, cert_pem,
            id_prefix="",
            legacy_key="org_ca_key",
            legacy_cert="org_ca_cert",
        )

    async def load_intermediate_ca(self) -> tuple[str, str] | None:
        return await self._load(
            _INTERMEDIATE_CA,
            legacy_key="mastio_ca_key",
            legacy_cert="mastio_ca_cert",
        )

    async def store_intermediate_ca(self, key_pem: str, cert_pem: str) -> None:
        await self._store(
            _INTERMEDIATE_CA, key_pem, cert_pem,
            id_prefix="intermediate",
            legacy_key="mastio_ca_key",
            legacy_cert="mastio_ca_cert",
        )

    async def _load(
        self, key_type: str, *, legacy_key: str, legacy_cert: str,
    ) -> tuple[str, str] | None:
        # Encrypted path requires the master passphrase. When absent,
        # fall back to the legacy plaintext rows in ``proxy_config``
        # (matches pre-three-tier-hardening behavior so existing
        # tests + dev sandbox keep booting without the env var).
        if not pki_master_key_configured():
            key_pem = await get_config(legacy_key)
            cert_pem = await get_config(legacy_cert)
            if key_pem and cert_pem:
                return key_pem, cert_pem
            return None
        row = await get_active_pki_key(key_type)
        if row is None:
            # Encrypted store empty, fall back to legacy rows once so
            # boot can still find a freshly-generated CA the dev path
            # may have written via the back-compat branch below.
            key_pem = await get_config(legacy_key)
            cert_pem = await get_config(legacy_cert)
            if key_pem and cert_pem:
                return key_pem, cert_pem
            return None
        try:
            key_pem, cert_pem = decrypt_pki_payload(row["ciphertext"])
        except RuntimeError:
            _log.error(
                "LocalKMSProvider: failed to decrypt %s (key_id=%s) — "
                "MCP_PROXY_DB_ENCRYPTION_KEY may have been rotated "
                "without re-encryption",
                key_type, row.get("key_id"),
            )
            raise
        # ``cert_pem`` is duplicated in the row (unencrypted) and in the
        # decrypted payload; both should match. We prefer the
        # unencrypted column so consumers that only need public
        # material can bypass the decrypt path later.
        return key_pem, row.get("cert_pem") or cert_pem

    async def _store(
        self, key_type: str, key_pem: str, cert_pem: str, *,
        id_prefix: str, legacy_key: str, legacy_cert: str,
    ) -> None:
        # Dev / test fallback: when the at-rest master passphrase is
        # absent, write the legacy plaintext rows in ``proxy_config``
        # so existing fixtures keep working. validate_config refuses
        # this in production.
        if not pki_master_key_configured():
            _log.warning(
                "LocalKMSProvider: MCP_PROXY_DB_ENCRYPTION_KEY not "
                "set, falling back to legacy plaintext proxy_config "
                "rows for %s (dev/test only).", key_type,
            )
            await set_config(legacy_key, key_pem)
            await set_config(legacy_cert, cert_pem)
            return

        envelope = encrypt_pki_payload(key_pem=key_pem, cert_pem=cert_pem)
        key_id = _stable_key_id(cert_pem, id_prefix)
        now = _now_iso()

        # Replace-by-rotation semantics: if a current active row exists,
        # deprecate it and activate the new one in the same swap. This
        # mirrors the historic LocalKMSProvider behavior (idempotent on
        # identical inputs, atomic replace otherwise) but keeps a full
        # history in the table so the audit log can trace key changes.
        current = await get_active_pki_key(key_type)
        if current is not None and current["key_id"] == key_id:
            # Identical material already active — idempotent fast path.
            return

        await insert_pki_key(
            key_id=key_id,
            key_type=key_type,
            ciphertext=envelope,
            cert_pem=cert_pem,
            created_at=now,
            activated_at=None,  # staged, then atomic-swap below
        )
        await activate_staged_pki_and_deprecate_old(
            key_type=key_type,
            new_key_id=key_id,
            new_activated_at=now,
            old_key_id=current["key_id"] if current is not None else None,
            old_deprecated_at=now,
            # Default grace for the deprecated row: 1 day. This is the
            # store path, not the operator-driven rotation path — store
            # is called on fresh-mint, not rotation. The deprecated row
            # exists only for forensic continuity, never for verification.
            old_expires_at=now,
        )
        _log.info(
            "LocalKMSProvider: stored %s (key_id=%s) under Fernet at-rest",
            key_type, key_id,
        )
